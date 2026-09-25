"""Regression tests for the scanners and the removal safety net.

Standard library only - run with:  python3 -m unittest discover -s tests
Every test works in a throwaway fake $HOME; nothing outside it is touched.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cleaner import config as config_mod  # noqa: E402
from cleaner import scanners, trash  # noqa: E402
from cleaner.findings import Finding  # noqa: E402

OLD = time.time() - 90 * 86400


def _age(path: Path, when: float = OLD) -> None:
    os.utime(path, (when, when), follow_symlinks=False)


def _write(path: Path, data: bytes, when: float = OLD) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    _age(path, when)
    return path


class FakeHomeTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.home = Path(self._tmp.name).resolve()
        self._patches = [
            mock.patch.object(config_mod, "HOME", self.home),
            mock.patch.object(trash, "HOME", self.home),
            mock.patch.object(trash, "QUARANTINE_ROOT", self.home / ".cleanup-tool-trash"),
            mock.patch.object(scanners, "OLLAMA_HOME", self.home / ".ollama"),
        ]
        for p in self._patches:
            p.start()
        self.config = config_mod.load_config(None)
        self.config.update({
            "protected_paths": [str(self.home / ".ssh")],
            "system_junk_dirs": [],
            "installer_dirs": [],
            "llm_model_dirs": [],
            "project_roots": [],
            "duplicate_dirs": [],
            "pentest_loot_dirs": [],
            "duplicate_min_size_mb": 0,
            "llm_model_min_size_mb": 0,
        })

    def tearDown(self):
        for p in self._patches:
            p.stop()
        self._tmp.cleanup()


class SystemJunkTest(FakeHomeTest):
    def test_stale_child_found_even_if_parent_dir_was_just_touched(self):
        cache = self.home / ".cache"
        _write(cache / "oldapp" / "blob", b"x" * 100)
        _age(cache / "oldapp")
        os.utime(cache)  # parent mtime = now, as happens constantly in real caches
        self.config["system_junk_dirs"] = [str(cache)]

        paths = [f.path.name for f in scanners.scan_system_junk(self.config)]
        self.assertEqual(paths, ["oldapp"])

    def test_nested_configured_dir_is_reported_once(self):
        cache = self.home / ".cache"
        _write(cache / "pip" / "wheel", b"x" * 100)
        _age(cache / "pip")
        _age(cache)
        self.config["system_junk_dirs"] = [str(cache), str(cache / "pip")]

        findings = scanners.run_scanners(["junk"], self.config)
        self.assertEqual([str(f.path) for f in findings], [str(cache / "pip")])


class DuplicatesTest(FakeHomeTest):
    def setUp(self):
        super().setUp()
        self.dl = self.home / "Downloads"
        self.config["duplicate_dirs"] = [str(self.dl)]

    def test_real_copy_reported_and_oldest_kept_as_original(self):
        _write(self.dl / "a.bin", b"same" * 1000, when=OLD - 1000)
        _write(self.dl / "b.bin", b"same" * 1000)
        _write(self.dl / "c.bin", b"diff" * 1000)

        findings = scanners.scan_duplicates(self.config)
        self.assertEqual([f.path.name for f in findings], ["b.bin"])
        self.assertEqual(Path(findings[0].extra["original"]).name, "a.bin")

    def test_symlink_is_not_a_duplicate(self):
        real = _write(self.dl / "model.gguf", b"w" * 5000)
        link = self.dl / "link.gguf"
        link.symlink_to(real)
        _age(link)
        self.assertEqual(scanners.scan_duplicates(self.config), [])

    def test_hardlink_is_not_a_duplicate(self):
        real = _write(self.dl / "model.gguf", b"w" * 5000)
        os.link(real, self.dl / "hard.gguf")
        self.assertEqual(scanners.scan_duplicates(self.config), [])


class LooseModelTest(FakeHomeTest):
    def test_symlinked_model_file_is_skipped(self):
        models = self.home / "models"
        real = _write(self.home / "elsewhere" / "big.gguf", b"w" * 5000)
        models.mkdir()
        (models / "big.gguf").symlink_to(real)
        _age(models / "big.gguf")
        self.config["llm_model_dirs"] = [str(models)]
        self.assertEqual(scanners.scan_llm_models(self.config), [])


class OllamaNameTest(unittest.TestCase):
    def test_names(self):
        cases = {
            "registry.ollama.ai/library/llama3/8b": "llama3:8b",
            "registry.ollama.ai/someuser/mymodel/q4": "someuser/mymodel:q4",
            "hf.co/bartowski/Llama-3.2-1B-GGUF/latest": "hf.co/bartowski/Llama-3.2-1B-GGUF:latest",
            "too/short": None,
        }
        for rel, expected in cases.items():
            self.assertEqual(scanners._ollama_model_name(Path(rel)), expected, rel)


class DockerTest(unittest.TestCase):
    def test_sizes_are_si_units(self):
        self.assertEqual(scanners._parse_docker_size("1.5GB"), 1_500_000_000)
        self.assertEqual(scanners._parse_docker_size("12kB"), 12_000)
        self.assertEqual(scanners._parse_docker_size("0B (virtual 512MB)"), 0)
        self.assertEqual(scanners._parse_docker_size("garbage"), 0)

    def test_recent_objects_are_not_candidates(self):
        config = {"docker_min_age_days": 7}
        self.assertFalse(scanners._docker_old_enough(datetime.now() - timedelta(hours=1), config))
        self.assertTrue(scanners._docker_old_enough(datetime.now() - timedelta(days=30), config))

    def test_unparseable_time_counts_as_new(self):
        created = scanners._parse_docker_time("not a date")
        self.assertFalse(scanners._docker_old_enough(created, {"docker_min_age_days": 7}))


def _finding(path: str, category: str = "duplicate", original: str | None = None) -> Finding:
    return Finding(Path(path), category, 1, datetime.now(), "",
                   extra={"original": original} if original else {})


class LastCopyGuardTest(unittest.TestCase):
    def test_same_file_picked_in_two_categories_keeps_one_copy(self):
        as_model = _finding("/h/Downloads/m.gguf", category="llm_model")
        as_dupe = _finding("/h/Desktop/m.gguf", original="/h/Downloads/m.gguf")
        guard = trash.LastCopyGuard([as_model, as_dupe])

        self.assertIsNone(guard.blocks(as_model))
        guard.mark_removed(as_model)
        self.assertIsNotNone(guard.blocks(as_dupe))

    def test_three_copies_allow_removing_two(self):
        d1 = _finding("/h/b", original="/h/a")
        d2 = _finding("/h/c", original="/h/a")
        original = _finding("/h/a", category="llm_model")
        guard = trash.LastCopyGuard([d1, d2, original])
        for f in (d1, d2):
            self.assertIsNone(guard.blocks(f))
            guard.mark_removed(f)
        self.assertIsNotNone(guard.blocks(original))

    def test_unrelated_findings_are_never_blocked(self):
        guard = trash.LastCopyGuard([])
        self.assertIsNone(guard.blocks(_finding("/h/x", category="system_junk")))


class RemovalTest(FakeHomeTest):
    def test_finder_path_is_passed_as_argv_not_script_text(self):
        evil = Path('/Users/x/Downloads/x" & (do shell script "touch /tmp/pwned") & ".gguf')
        with mock.patch.object(trash.subprocess, "run") as run:
            run.return_value.returncode = 0
            trash._move_to_finder_trash(evil)
        cmd = run.call_args[0][0]
        self.assertEqual(cmd[-1], str(evil))
        self.assertTrue(all(str(evil) not in part for part in cmd[:-1]))

    def test_missing_cli_tool_is_a_trash_error_not_a_crash(self):
        f = Finding(Path("/x"), "llm_model", 1, datetime.now(), "", action="ollama_rm", action_arg="m:1")
        with mock.patch.object(trash.subprocess, "run", side_effect=FileNotFoundError("ollama")):
            with self.assertRaises(trash.TrashError):
                trash.remove(f, self.config)

    @unittest.skipIf(sys.platform == "darwin", "Linux quarantine path")
    def test_quarantine_mirrors_path_and_refuses_protected(self):
        victim = _write(self.home / "Downloads" / "old.iso", b"x")
        trash.move_to_trash(victim, self.config)
        self.assertFalse(victim.exists())
        self.assertTrue((self.home / ".cleanup-tool-trash" / "Downloads" / "old.iso").exists())

        key = _write(self.home / ".ssh" / "id_ed25519", b"secret")
        with self.assertRaises(trash.TrashError):
            trash.move_to_trash(key, self.config)
        self.assertTrue(key.exists())


class ManifestScanTest(FakeHomeTest):
    def test_ollama_manifest_becomes_finding_with_rm_name(self):
        manifest = self.home / ".ollama/models/manifests/hf.co/user/repo/latest"
        _write(manifest, json.dumps({"config": {"size": 1}, "layers": [{"size": 9}]}).encode())
        (f,) = scanners.scan_llm_models(self.config)
        self.assertEqual((f.action, f.action_arg, f.size_bytes), ("ollama_rm", "hf.co/user/repo:latest", 10))


if __name__ == "__main__":
    unittest.main()

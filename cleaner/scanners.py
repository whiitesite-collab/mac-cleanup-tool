"""Scan functions. Each returns a list[Finding] and never modifies anything on disk."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta
from pathlib import Path

from .config import is_protected
from .findings import Finding

OLLAMA_HOME = Path.home() / ".ollama"


def _mtime(path: Path) -> datetime:
    return datetime.fromtimestamp(path.stat().st_mtime)


def _recently_touched(path: Path, config: dict) -> bool:
    cutoff = datetime.now() - timedelta(hours=config["min_untouched_hours"])
    try:
        return _mtime(path) > cutoff
    except OSError:
        return True  # can't stat it -> don't touch it


def _dir_size(path: Path) -> int:
    total = 0
    for root, _dirs, files in os.walk(path, onerror=lambda e: None):
        for name in files:
            fp = Path(root) / name
            try:
                total += fp.lstat().st_size
            except OSError:
                pass
    return total


def _eligible(path: Path, config: dict) -> bool:
    return path.exists() and not is_protected(path, config) and not _recently_touched(path, config)


# ---------------------------------------------------------------------------
# 1. LLM model files
# ---------------------------------------------------------------------------

def scan_llm_models(config: dict) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_scan_ollama_manifests(config))
    findings.extend(_scan_loose_model_files(config))
    return findings


def _scan_ollama_manifests(config: dict) -> list[Finding]:
    manifests_root = OLLAMA_HOME / "models" / "manifests"
    if not manifests_root.is_dir():
        return []

    findings = []
    for manifest_path in manifests_root.rglob("*"):
        if not manifest_path.is_file():
            continue
        try:
            data = json.loads(manifest_path.read_text())
        except (json.JSONDecodeError, OSError):
            continue

        model, tag = manifest_path.parent.name, manifest_path.name
        # e.g. manifests/registry.ollama.ai/library/llama3/8b -> "llama3:8b"
        namespace = manifest_path.parent.parent.name
        name = f"{namespace}/{model}:{tag}" if namespace != "library" else f"{model}:{tag}"

        size = data.get("config", {}).get("size", 0)
        size += sum(layer.get("size", 0) for layer in data.get("layers", []))

        modified = _mtime(manifest_path)
        age_days = (datetime.now() - modified).days
        if age_days < config["llm_model_min_age_days"]:
            continue

        findings.append(Finding(
            path=manifest_path,
            category="llm_model",
            size_bytes=size,
            modified=modified,
            reason=f"Ollama-Modell '{name}', seit {age_days} Tagen nicht neu geladen/aktualisiert",
            action="ollama_rm",
            action_arg=name,
        ))
    return findings


def _scan_loose_model_files(config: dict) -> list[Finding]:
    findings = []
    min_size = config["llm_model_min_size_mb"] * 1024 * 1024
    extensions = set(config["llm_model_extensions"])

    for base in config["llm_model_dirs"]:
        base_path = Path(base)
        if not base_path.is_dir():
            continue
        for entry in base_path.rglob("*"):
            if not entry.is_file() or entry.suffix.lower() not in extensions:
                continue
            if not _eligible(entry, config):
                continue
            try:
                size = entry.stat().st_size
            except OSError:
                continue
            if size < min_size:
                continue
            modified = _mtime(entry)
            age_days = (datetime.now() - modified).days
            if age_days < config["llm_model_min_age_days"]:
                continue
            findings.append(Finding(
                path=entry,
                category="llm_model",
                size_bytes=size,
                modified=modified,
                reason=f"Frei liegende Modell-Gewichtsdatei ({entry.suffix}), seit {age_days} Tagen unangetastet",
            ))
    return findings


# ---------------------------------------------------------------------------
# 2. General system junk (caches, logs, old installers)
# ---------------------------------------------------------------------------

SINGLE_ENTRY_DIR_NAMES = {"_cacache", "pip"}


def scan_system_junk(config: dict) -> list[Finding]:
    findings = []

    for base in config["system_junk_dirs"]:
        base_path = Path(base)
        if not base_path.is_dir() or not _eligible(base_path, config):
            continue

        if base_path.name in SINGLE_ENTRY_DIR_NAMES:
            candidates = [base_path]
        else:
            try:
                candidates = [c for c in base_path.iterdir() if _eligible(c, config)]
            except OSError:
                continue

        for candidate in candidates:
            size = _dir_size(candidate) if candidate.is_dir() else candidate.stat().st_size
            if size == 0:
                continue
            modified = _mtime(candidate)
            age_days = (datetime.now() - modified).days
            if age_days < config["system_junk_min_age_days"]:
                continue
            findings.append(Finding(
                path=candidate,
                category="system_junk",
                size_bytes=size,
                modified=modified,
                reason=f"Cache/Log unter {base_path.name}/, seit {age_days} Tagen nicht mehr geschrieben",
            ))

    findings.extend(_scan_installers(config))
    return findings


def _scan_installers(config: dict) -> list[Finding]:
    findings = []
    extensions = set(config["installer_extensions"])
    for base in config["installer_dirs"]:
        base_path = Path(base)
        if not base_path.is_dir():
            continue
        for entry in base_path.iterdir():
            if not entry.is_file() or entry.suffix.lower() not in extensions:
                continue
            if not _eligible(entry, config):
                continue
            modified = _mtime(entry)
            age_days = (datetime.now() - modified).days
            if age_days < config["installer_min_age_days"]:
                continue
            findings.append(Finding(
                path=entry,
                category="system_junk",
                size_bytes=entry.stat().st_size,
                modified=modified,
                reason=f"Installer ({entry.suffix}) in Downloads, seit {age_days} Tagen ungenutzt",
            ))
    return findings


# ---------------------------------------------------------------------------
# 3. Stale project build/dependency folders
# ---------------------------------------------------------------------------

def scan_project_leftovers(config: dict) -> list[Finding]:
    findings = []
    leftover_names = set(config["project_leftover_names"])

    for root in config["project_roots"]:
        root_path = Path(root)
        if not root_path.is_dir():
            continue
        for dirpath, dirnames, _filenames in os.walk(root_path):
            matched = [d for d in dirnames if d in leftover_names]
            for name in matched:
                candidate = Path(dirpath) / name
                dirnames.remove(name)  # don't descend into it
                if not _eligible(candidate, config):
                    continue
                modified = _mtime(candidate)
                age_days = (datetime.now() - modified).days
                if age_days < config["project_leftover_min_age_days"]:
                    continue
                project_name = Path(dirpath).name
                findings.append(Finding(
                    path=candidate,
                    category="project_leftover",
                    size_bytes=_dir_size(candidate),
                    modified=modified,
                    reason=(
                        f"'{name}'-Ordner im Projekt '{project_name}', "
                        f"seit {age_days} Tagen nicht mehr angefasst – per Paketmanager/Build neu erzeugbar"
                    ),
                ))
    return findings


# ---------------------------------------------------------------------------
# 4. Byte-identical duplicates
# ---------------------------------------------------------------------------

def _sha256(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def scan_duplicates(config: dict) -> list[Finding]:
    min_size = config["duplicate_min_size_mb"] * 1024 * 1024
    by_hash: dict[str, list[Path]] = {}

    for base in config["duplicate_dirs"]:
        base_path = Path(base)
        if not base_path.is_dir():
            continue
        for entry in base_path.rglob("*"):
            if not entry.is_file():
                continue
            try:
                if entry.stat().st_size < min_size or not _eligible(entry, config):
                    continue
                file_hash = _sha256(entry)
            except OSError:
                continue
            by_hash.setdefault(file_hash, []).append(entry)

    findings = []
    for paths in by_hash.values():
        if len(paths) < 2:
            continue
        paths.sort(key=lambda p: p.stat().st_mtime)
        original, *dupes = paths
        for dupe in dupes:
            findings.append(Finding(
                path=dupe,
                category="duplicate",
                size_bytes=dupe.stat().st_size,
                modified=_mtime(dupe),
                reason=f"Byte-identisches Duplikat von {original}",
                extra={"original": str(original)},
            ))
    return findings


ALL_SCANNERS = {
    "llm": scan_llm_models,
    "junk": scan_system_junk,
    "projects": scan_project_leftovers,
    "duplicates": scan_duplicates,
}

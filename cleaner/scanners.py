"""Scan functions. Each returns a list[Finding] and never modifies anything on disk.

Perf notes: directory walks and hashing are I/O-bound, so independent targets
(separate base dirs, separate files to hash) are farmed out via
`util.parallel_map` (a thread pool - I/O syscalls release the GIL). Duplicate
detection is staged size -> cheap 64KB prefix hash -> full SHA-256, so a full
read only happens for files that already collide on size and prefix, instead
of hashing every large file up front.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta
from pathlib import Path

from .config import is_protected
from .findings import Finding
from .util import iter_files, parallel_map

OLLAMA_HOME = Path.home() / ".ollama"


def _mtime(path: Path) -> datetime:
    return datetime.fromtimestamp(path.stat().st_mtime)


def _eligible(path: Path, config: dict, mtime: datetime | None = None) -> bool:
    if is_protected(path, config):
        return False
    if mtime is None:
        try:
            mtime = _mtime(path)
        except OSError:
            return False
    cutoff = datetime.now() - timedelta(hours=config["min_untouched_hours"])
    return mtime <= cutoff  # newer than cutoff -> probably still in use -> not eligible


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
    for manifest_path, stat_result in iter_files(manifests_root):
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

        modified = datetime.fromtimestamp(stat_result.st_mtime)
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


def _scan_loose_model_files_in(base: str, config: dict) -> list[Finding]:
    findings = []
    min_size = config["llm_model_min_size_mb"] * 1024 * 1024
    extensions = set(config["llm_model_extensions"])

    base_path = Path(base)
    if not base_path.is_dir():
        return findings

    for entry, stat_result in iter_files(base_path):
        if entry.suffix.lower() not in extensions or stat_result.st_size < min_size:
            continue
        modified = datetime.fromtimestamp(stat_result.st_mtime)
        if not _eligible(entry, config, modified):
            continue
        age_days = (datetime.now() - modified).days
        if age_days < config["llm_model_min_age_days"]:
            continue
        findings.append(Finding(
            path=entry,
            category="llm_model",
            size_bytes=stat_result.st_size,
            modified=modified,
            reason=f"Frei liegende Modell-Gewichtsdatei ({entry.suffix}), seit {age_days} Tagen unangetastet",
        ))
    return findings


def _scan_loose_model_files(config: dict) -> list[Finding]:
    # Each configured dir is an independent subtree - walk them concurrently.
    results = parallel_map(lambda base: _scan_loose_model_files_in(base, config), config["llm_model_dirs"])
    return [f for group in results for f in group]


# ---------------------------------------------------------------------------
# 2. General system junk (caches, logs, old installers)
# ---------------------------------------------------------------------------

SINGLE_ENTRY_DIR_NAMES = {"_cacache", "pip"}


def _junk_candidate_finding(candidate: Path, base_path: Path, config: dict) -> Finding | None:
    try:
        stat_result = candidate.stat()
    except OSError:
        return None
    size = _dir_size(candidate) if candidate.is_dir() else stat_result.st_size
    if size == 0:
        return None
    modified = datetime.fromtimestamp(stat_result.st_mtime)
    age_days = (datetime.now() - modified).days
    if age_days < config["system_junk_min_age_days"]:
        return None
    return Finding(
        path=candidate,
        category="system_junk",
        size_bytes=size,
        modified=modified,
        reason=f"Cache/Log unter {base_path.name}/, seit {age_days} Tagen nicht mehr geschrieben",
    )


def scan_system_junk(config: dict) -> list[Finding]:
    findings = []
    all_candidates: list[tuple[Path, Path]] = []  # (candidate, its base_path)

    for base in config["system_junk_dirs"]:
        base_path = Path(base)
        if not base_path.is_dir() or not _eligible(base_path, config):
            continue

        if base_path.name in SINGLE_ENTRY_DIR_NAMES:
            all_candidates.append((base_path, base_path))
        else:
            try:
                all_candidates.extend((c, base_path) for c in base_path.iterdir() if _eligible(c, config))
            except OSError:
                continue

    # Each candidate's size (often a full-tree walk for per-app cache folders)
    # is independent I/O work - dozens of these commonly sit side by side
    # under ~/Library/Caches, so run them concurrently.
    results = parallel_map(lambda item: _junk_candidate_finding(*item, config), all_candidates)
    findings.extend(f for f in results if f is not None)

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
            if entry.suffix.lower() not in extensions:
                continue
            try:
                stat_result = entry.stat()
            except OSError:
                continue
            if not entry.is_file():
                continue
            modified = datetime.fromtimestamp(stat_result.st_mtime)
            if not _eligible(entry, config, modified):
                continue
            age_days = (datetime.now() - modified).days
            if age_days < config["installer_min_age_days"]:
                continue
            findings.append(Finding(
                path=entry,
                category="system_junk",
                size_bytes=stat_result.st_size,
                modified=modified,
                reason=f"Installer ({entry.suffix}) in Downloads, seit {age_days} Tagen ungenutzt",
            ))
    return findings


# ---------------------------------------------------------------------------
# 3. Stale project build/dependency folders
# ---------------------------------------------------------------------------

def _scan_project_leftovers_in(root: str, config: dict) -> list[Finding]:
    findings = []
    leftover_names = set(config["project_leftover_names"])

    root_path = Path(root)
    if not root_path.is_dir():
        return findings

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


def scan_project_leftovers(config: dict) -> list[Finding]:
    # Each project root is an unrelated subtree - walk them concurrently.
    results = parallel_map(lambda root: _scan_project_leftovers_in(root, config), config["project_roots"])
    return [f for group in results for f in group]


# ---------------------------------------------------------------------------
# 4. Byte-identical duplicates
# ---------------------------------------------------------------------------

def _sha256(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _partial_hash(path: Path, n: int = 65536) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read(n)).hexdigest()


def _hash_all(paths: list[Path], hash_func) -> dict[Path, str]:
    def safe(p: Path) -> str | None:
        try:
            return hash_func(p)
        except OSError:
            return None

    hashes = parallel_map(safe, paths)
    return {p: h for p, h in zip(paths, hashes) if h is not None}


def _group_by_key(groups: list[list[Path]], key_of: dict[Path, str]) -> list[list[Path]]:
    """Split each group into sub-groups sharing the same key; drop singletons."""
    refined = []
    for group in groups:
        buckets: dict[str, list[Path]] = {}
        for p in group:
            if p not in key_of:
                continue
            buckets.setdefault(key_of[p], []).append(p)
        refined.extend(bucket for bucket in buckets.values() if len(bucket) > 1)
    return refined


def _scan_size_bucket(base: str, min_size: int, config: dict) -> list[tuple[Path, int, float]]:
    base_path = Path(base)
    if not base_path.is_dir():
        return []
    found = []
    for entry, stat_result in iter_files(base_path):
        if stat_result.st_size < min_size:
            continue
        if not _eligible(entry, config, datetime.fromtimestamp(stat_result.st_mtime)):
            continue
        found.append((entry, stat_result.st_size, stat_result.st_mtime))
    return found


def scan_duplicates(config: dict) -> list[Finding]:
    min_size = config["duplicate_min_size_mb"] * 1024 * 1024

    # Stage 1: collect eligible files per (independent) base dir concurrently,
    # then bucket by exact size - free, since size comes from the stat() we
    # already did. This alone rules out the vast majority of files: two files
    # of different size can never be duplicates.
    per_base = parallel_map(lambda base: _scan_size_bucket(base, min_size, config), config["duplicate_dirs"])

    by_size: dict[int, list[Path]] = {}
    mtimes: dict[Path, float] = {}
    sizes: dict[Path, int] = {}
    for found in per_base:
        for path, size, mtime in found:
            by_size.setdefault(size, []).append(path)
            mtimes[path] = mtime
            sizes[path] = size

    size_groups = [g for g in by_size.values() if len(g) > 1]
    if not size_groups:
        return []

    # Stage 2: a cheap 64KB prefix hash splits off same-size-but-different
    # files before paying for a full read of potentially large files.
    same_size_paths = [p for group in size_groups for p in group]
    prefix_of = _hash_all(same_size_paths, _partial_hash)
    prefix_groups = _group_by_key(size_groups, prefix_of)
    if not prefix_groups:
        return []

    # Stage 3: full SHA-256, only for files that already collided on both
    # size and prefix.
    remaining_paths = [p for group in prefix_groups for p in group]
    hash_of = _hash_all(remaining_paths, _sha256)
    hash_groups = _group_by_key(prefix_groups, hash_of)

    findings = []
    for group in hash_groups:
        group.sort(key=lambda p: mtimes[p])
        original, *dupes = group
        for dupe in dupes:
            findings.append(Finding(
                path=dupe,
                category="duplicate",
                size_bytes=sizes[dupe],
                modified=datetime.fromtimestamp(mtimes[dupe]),
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

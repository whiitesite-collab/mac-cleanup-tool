"""Default configuration and safety guardrails.

Defaults are platform-aware: macOS gets Finder/Xcode/Homebrew-shaped paths,
Linux (this project targets Kali under WSL) gets APT/pentest-tool-shaped
paths. Everything here is a starting point - override via a config.json,
see config.example.json / config.linux.example.json.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HOME = Path.home()
IS_LINUX = sys.platform.startswith("linux")

_COMMON_CONFIG = {
    "llm_model_extensions": [".gguf", ".bin", ".safetensors", ".ckpt", ".pt"],
    "llm_model_min_size_mb": 500,
    "llm_model_min_age_days": 30,

    "system_junk_min_age_days": 14,

    "project_leftover_names": [
        "node_modules", "venv", ".venv", "__pycache__",
        "dist", "build", "target", "DerivedData", ".gradle",
    ],
    "project_leftover_min_age_days": 60,

    "duplicate_min_size_mb": 5,

    # Files touched more recently than this are assumed "in use" and skipped.
    "min_untouched_hours": 24,

    # APT/pentest-loot scanners are Linux-only in practice, but keep their
    # keys defined on every platform so `--category all` never KeyErrors -
    # on macOS these paths simply don't exist and the scanners no-op.
    "apt_cache_dir": "/var/cache/apt/archives",
    "apt_cache_min_age_days": 14,
    "pentest_loot_dirs": [
        str(HOME / "loot"),
        str(HOME / ".msf4" / "loot"),
        str(HOME / "nmap-output"),
        str(HOME / "engagements"),
    ],
    "pentest_loot_min_age_days": 30,

    # docker rm/rmi can't be undone - only list things at least this old.
    "docker_min_age_days": 7,
}

_MACOS_CONFIG = {
    "llm_model_dirs": [
        str(HOME / "Downloads"),
        str(HOME / "Documents"),
        str(HOME / "models"),
    ],

    "system_junk_dirs": [
        str(HOME / "Library" / "Caches"),
        str(HOME / "Library" / "Logs"),
        str(HOME / "Library" / "Developer" / "Xcode" / "DerivedData"),
        str(HOME / ".npm" / "_cacache"),
        str(HOME / "Library" / "Caches" / "pip"),
    ],

    "installer_dirs": [str(HOME / "Downloads")],
    "installer_extensions": [".dmg", ".pkg"],
    "installer_min_age_days": 30,

    "project_roots": [
        str(HOME / "Developer"),
        str(HOME / "Projects"),
        str(HOME / "WhiiteStudio"),
    ],

    "duplicate_dirs": [
        str(HOME / "Downloads"),
        str(HOME / "Desktop"),
        str(HOME / "Documents"),
    ],

    "protected_paths": [
        str(HOME / "Library" / "Keychains"),
        str(HOME / "Library" / "Application Support" / "MobileSync"),
        str(HOME / "Library" / "Mail"),
        str(HOME / "Library" / "Messages"),
        str(HOME / "Library" / "CloudStorage"),
        str(HOME / ".ssh"),
        str(HOME / "Library" / "Application Support" / "com.apple.TCC"),
    ],
}

_LINUX_CONFIG = {
    "llm_model_dirs": [
        str(HOME / "Downloads"),
        str(HOME / "Documents"),
        str(HOME / "models"),
    ],

    "system_junk_dirs": [
        str(HOME / ".cache"),
        str(HOME / ".npm" / "_cacache"),
        str(HOME / ".cache" / "pip"),
    ],

    # macOS-style installer files don't apply on Linux - stale .deb archives
    # are covered separately by apt_cache_dir below.
    "installer_dirs": [],
    "installer_extensions": [],
    "installer_min_age_days": 30,

    "project_roots": [
        str(HOME / "tools"),
        str(HOME / "projects"),
        str(HOME / "Projects"),
    ],

    "duplicate_dirs": [
        str(HOME / "Downloads"),
        str(HOME / "Desktop"),
        str(HOME / "loot"),
    ],

    # Credential/session stores that must never be touched, regardless of
    # what a scan matches. Deliberately does NOT include ~/.msf4 wholesale -
    # pentest_loot_dirs intentionally reaches into ~/.msf4/loot.
    "protected_paths": [
        str(HOME / ".ssh"),
        str(HOME / ".gnupg"),
        str(HOME / ".aws"),
        str(HOME / ".mozilla"),
        str(HOME / ".msf4" / "msf.db"),
    ],
}

DEFAULT_CONFIG = {**_COMMON_CONFIG, **(_LINUX_CONFIG if IS_LINUX else _MACOS_CONFIG)}


def load_config(path: str | None) -> dict:
    config = dict(DEFAULT_CONFIG)
    if path:
        with open(path, encoding="utf-8") as f:
            overrides = json.load(f)
        config.update(overrides)
    return config


def is_protected(path: Path, config: dict) -> bool:
    resolved = path.resolve()
    if HOME not in resolved.parents and resolved != HOME:
        return True  # never operate outside the user's home directory
    for protected in config["protected_paths"]:
        protected_resolved = Path(protected).resolve()
        if resolved == protected_resolved or protected_resolved in resolved.parents:
            return True
    return False

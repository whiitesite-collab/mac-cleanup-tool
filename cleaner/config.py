"""Default configuration and safety guardrails for mac-cleanup-tool."""

from __future__ import annotations

import json
from pathlib import Path

HOME = Path.home()

DEFAULT_CONFIG = {
    # LLM model files dropped outside of a model manager's own directory.
    "llm_model_dirs": [
        str(HOME / "Downloads"),
        str(HOME / "Documents"),
        str(HOME / "models"),
    ],
    "llm_model_extensions": [".gguf", ".bin", ".safetensors", ".ckpt", ".pt"],
    "llm_model_min_size_mb": 500,
    "llm_model_min_age_days": 30,

    # Well-known system/app junk locations.
    "system_junk_dirs": [
        str(HOME / "Library" / "Caches"),
        str(HOME / "Library" / "Logs"),
        str(HOME / "Library" / "Developer" / "Xcode" / "DerivedData"),
        str(HOME / ".npm" / "_cacache"),
        str(HOME / "Library" / "Caches" / "pip"),
    ],
    "system_junk_min_age_days": 14,

    # Old installers sitting in Downloads.
    "installer_dirs": [str(HOME / "Downloads")],
    "installer_extensions": [".dmg", ".pkg"],
    "installer_min_age_days": 30,

    # Roots to search for stale project build/dependency folders.
    "project_roots": [
        str(HOME / "Developer"),
        str(HOME / "Projects"),
        str(HOME / "WhiiteStudio"),
    ],
    "project_leftover_names": [
        "node_modules", "venv", ".venv", "__pycache__",
        "dist", "build", "target", "DerivedData", ".gradle",
    ],
    "project_leftover_min_age_days": 60,

    # Folders scanned for byte-identical duplicates.
    "duplicate_dirs": [
        str(HOME / "Downloads"),
        str(HOME / "Desktop"),
        str(HOME / "Documents"),
    ],
    "duplicate_min_size_mb": 5,

    # Never touched, regardless of what a scan matches.
    "protected_paths": [
        str(HOME / "Library" / "Keychains"),
        str(HOME / "Library" / "Application Support" / "MobileSync"),
        str(HOME / "Library" / "Mail"),
        str(HOME / "Library" / "Messages"),
        str(HOME / "Library" / "CloudStorage"),
        str(HOME / ".ssh"),
        str(HOME / "Library" / "Application Support" / "com.apple.TCC"),
    ],

    # Files touched more recently than this are assumed "in use" and skipped.
    "min_untouched_hours": 24,
}


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

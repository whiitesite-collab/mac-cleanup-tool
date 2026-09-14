"""Data model for a single cleanup candidate."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass
class Finding:
    path: Path
    category: str          # "llm_model" | "system_junk" | "project_leftover" | "duplicate"
    size_bytes: int
    modified: datetime
    reason: str             # human-readable explanation of what the file/dir is and why it's flagged
    action: str = "trash"   # "trash" | "ollama_rm"
    action_arg: str = ""    # e.g. the "model:tag" for ollama_rm
    extra: dict = field(default_factory=dict)

    @property
    def age_days(self) -> int:
        return (datetime.now() - self.modified).days

    def size_human(self) -> str:
        size = float(self.size_bytes)
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if size < 1024 or unit == "TB":
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

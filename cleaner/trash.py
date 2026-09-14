"""Reversible removal only. Nothing in this module ever permanently deletes a file:

- Ordinary files/folders are moved to the macOS Trash via Finder (recoverable, counts
  against the same Trash you already know from the Finder UI).
- Ollama-managed models are removed with `ollama rm`, which is the tool's own safe
  cleanup path for its content-addressed blob store (touching the blobs directly
  could corrupt models that still share data with a kept tag).
"""

from __future__ import annotations

import subprocess

from .config import is_protected
from .findings import Finding


class TrashError(RuntimeError):
    pass


def move_to_trash(path, config: dict) -> None:
    if is_protected(path, config):
        raise TrashError(f"Geschützter Pfad, wird nicht angefasst: {path}")
    if not path.exists():
        raise TrashError(f"Existiert nicht (mehr): {path}")

    script = (
        f'tell application "Finder" to delete (POSIX file "{path}" as alias)'
    )
    result = subprocess.run(
        ["osascript", "-e", script],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise TrashError(f"Finder konnte {path} nicht in den Papierkorb legen: {result.stderr.strip()}")


def ollama_rm(model_name: str) -> None:
    result = subprocess.run(
        ["ollama", "rm", model_name],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise TrashError(f"'ollama rm {model_name}' fehlgeschlagen: {result.stderr.strip()}")


def remove(finding: Finding, config: dict) -> None:
    if finding.action == "ollama_rm":
        ollama_rm(finding.action_arg)
    else:
        move_to_trash(finding.path, config)

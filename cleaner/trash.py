"""Reversible removal only. Nothing in this module ever permanently deletes a file:

- On macOS, ordinary files/folders move to the Trash via Finder (recoverable,
  the same Trash you already know from the Finder UI).
- On Linux (no Finder trash), they move into our own quarantine folder under
  $HOME (~/.cleanup-tool-trash/, mirroring the original path) - restore by
  moving an item back, or clear old entries yourself once you're sure.
- Ollama-managed models are removed with `ollama rm`, not by touching the
  content-addressed blob store directly (blobs can be shared across tags).
- Docker images/containers/volumes are removed with the `docker` CLI, not by
  touching its storage driver's files directly.
- Anything requiring root (e.g. the system APT cache) is never touched by
  this tool at all - it only ever reports the manual command to run yourself.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from .config import HOME, is_protected
from .findings import Finding

QUARANTINE_ROOT = HOME / ".cleanup-tool-trash"

# Actions that go through an external CLI and cannot be undone from a trash.
IRREVERSIBLE_ACTIONS = {"ollama_rm", "docker_rmi", "docker_rm_container", "docker_volume_rm"}


class TrashError(RuntimeError):
    pass


def move_to_trash(path: Path, config: dict) -> None:
    if is_protected(path, config):
        raise TrashError(f"Geschützter Pfad, wird nicht angefasst: {path}")
    if not path.exists():
        raise TrashError(f"Existiert nicht (mehr): {path}")

    if sys.platform == "darwin":
        _move_to_finder_trash(path)
    else:
        _move_to_quarantine(path)


# The path is passed as an argv item, never spliced into the script text: a
# file name containing `"` would otherwise be able to inject AppleScript
# (e.g. `do shell script`) - and scanned file names are untrusted input.
_FINDER_TRASH_SCRIPT = (
    "on run argv",
    "set target to (POSIX file (item 1 of argv)) as alias",
    'tell application "Finder" to delete target',
    "end run",
)


def _move_to_finder_trash(path: Path) -> None:
    cmd = ["osascript"]
    for line in _FINDER_TRASH_SCRIPT:
        cmd += ["-e", line]
    cmd.append(str(path))
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise TrashError(f"Finder konnte {path} nicht in den Papierkorb legen: {result.stderr.strip()}")


def _move_to_quarantine(path: Path) -> None:
    try:
        rel = path.resolve().relative_to(HOME.resolve())
    except ValueError:
        rel = Path(path.name)
    dest = QUARANTINE_ROOT / rel
    if dest.exists():
        dest = dest.with_name(f"{dest.name}.{datetime.now():%Y%m%d-%H%M%S}")
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(path), str(dest))
    except OSError as e:
        raise TrashError(f"Konnte {path} nicht in Quarantäne ({QUARANTINE_ROOT}) verschieben: {e}")


def ollama_rm(model_name: str) -> None:
    result = subprocess.run(["ollama", "rm", model_name], capture_output=True, text=True)
    if result.returncode != 0:
        raise TrashError(f"'ollama rm {model_name}' fehlgeschlagen: {result.stderr.strip()}")


def _docker(*args: str) -> None:
    result = subprocess.run(["docker", *args], capture_output=True, text=True)
    if result.returncode != 0:
        raise TrashError(f"'docker {' '.join(args)}' fehlgeschlagen: {result.stderr.strip()}")


def remove(finding: Finding, config: dict) -> None:
    if finding.action == "ollama_rm":
        ollama_rm(finding.action_arg)
    elif finding.action == "docker_rmi":
        _docker("rmi", finding.action_arg)
    elif finding.action == "docker_rm_container":
        _docker("rm", finding.action_arg)
    elif finding.action == "docker_volume_rm":
        _docker("volume", "rm", finding.action_arg)
    elif finding.action == "manual":
        raise TrashError(f"Erfordert Root bzw. manuelle Ausführung – bitte selbst ausführen: {finding.action_arg}")
    else:
        move_to_trash(finding.path, config)

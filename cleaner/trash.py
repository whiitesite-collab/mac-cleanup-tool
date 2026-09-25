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

import os
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


class LastCopyGuard:
    """Keeps a cleanup run from removing every copy of a duplicate group.

    The same file can be offered twice under different categories - e.g. a
    .gguf is both an "LLM model" and the original of a "duplicate". Picking
    one in each would trash both copies. This tracks what has been removed
    during the run and refuses the removal that would take the last copy.
    """

    def __init__(self, findings: list[Finding]):
        self._group_of: dict[str, set[str]] = {}
        for f in findings:
            original = f.extra.get("original") if f.category == "duplicate" else None
            if not original:
                continue
            group = self._group_of.get(original) or {original}
            group.add(str(f.path))
            for member in group:
                self._group_of[member] = group
        self._removed: set[str] = set()

    def blocks(self, finding: Finding) -> str | None:
        path = str(finding.path)
        group = self._group_of.get(path)
        if group is None or group - self._removed - {path}:
            return None
        return f"Übersprungen – letzte verbliebene Kopie (alle anderen Kopien wurden gerade entfernt): {path}"

    def mark_removed(self, finding: Finding) -> None:
        self._removed.add(str(finding.path))


def move_to_trash(path: Path, config: dict) -> None:
    if is_protected(path, config):
        raise TrashError(f"Geschützter Pfad, wird nicht angefasst: {path}")
    if not path.exists():
        raise TrashError(f"Existiert nicht (mehr): {path}")

    if sys.platform == "darwin":
        _move_to_finder_trash(path)
    else:
        _move_to_quarantine(path)


# In both scripts below the path is passed as an argv item, never spliced into
# the script text: a file name containing `"` would otherwise be able to
# inject code (e.g. AppleScript `do shell script`) - and scanned file names
# are untrusted input.

# Preferred: NSFileManager.trashItemAtURL through JavaScript for Automation's
# ObjC bridge. It runs inside osascript itself and sends no Apple Events to
# Finder, so it needs no "Terminal möchte Finder steuern" permission - the
# Automation prompt is easy to miss or deny, which made every removal fail.
# Items still land in the normal Trash (including "Zurücklegen").
_NSFILEMANAGER_TRASH_JS = """
ObjC.import('Foundation');
function run(argv) {
  const error = $();
  const ok = $.NSFileManager.defaultManager.trashItemAtURLResultingItemURLError(
    $.NSURL.fileURLWithPath(argv[0]), $(), error);
  if (!ok) {
    throw new Error(ObjC.unwrap(error.localizedDescription));
  }
}
"""

# Fallback: ask Finder (needs the Automation permission).
_FINDER_TRASH_SCRIPT = (
    "on run argv",
    "set target to (POSIX file (item 1 of argv)) as alias",
    'tell application "Finder" to delete target',
    "end run",
)


def _mac_trash_attempts(path: Path) -> list[tuple[str, list[str]]]:
    finder = ["osascript"]
    for line in _FINDER_TRASH_SCRIPT:
        finder += ["-e", line]
    return [
        ("macOS", ["osascript", "-l", "JavaScript", "-e", _NSFILEMANAGER_TRASH_JS, str(path)]),
        ("Finder", finder + [str(path)]),
    ]


def _move_to_finder_trash(path: Path) -> None:
    errors = []
    for label, cmd in _mac_trash_attempts(path):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as e:
            errors.append(f"{label}: {e}")
            continue
        if result.returncode == 0:
            return
        errors.append(f"{label}: {result.stderr.strip() or f'Exit-Code {result.returncode}'}")
    raise TrashError(f"Konnte {path} nicht in den Papierkorb legen{_mac_permission_hint(errors)} "
                     f"[{' | '.join(errors)}]")


def _mac_permission_hint(errors: list[str]) -> str:
    text = " ".join(errors).lower()
    if "operation not permitted" in text or "permission" in text or "(-54)" in text:
        return (" – macOS verweigert den Zugriff. Lösung: Systemeinstellungen → Datenschutz & Sicherheit → "
                "Festplattenvollzugriff → Terminal (bzw. Python) hinzufügen und das Tool neu starten.")
    if "(-1743)" in text or "not authorized" in text or "nicht berechtigt" in text:
        return (" – keine Berechtigung, Finder zu steuern. Lösung: Systemeinstellungen → Datenschutz & "
                "Sicherheit → Automation → bei Terminal (bzw. Python) „Finder“ aktivieren.")
    return ""


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


# Started by double-clicking Aufraeumen.command, PATH can lack the places
# where these CLIs live, so look there too before giving up.
_EXTRA_TOOL_DIRS = (
    "/usr/local/bin",
    "/opt/homebrew/bin",
    "/Applications/Ollama.app/Contents/Resources",
    "/Applications/Docker.app/Contents/Resources/bin",
)


def _find_tool(name: str) -> str:
    return shutil.which(name) or shutil.which(name, path=os.pathsep.join(_EXTRA_TOOL_DIRS)) or name


def _run_tool(*cmd: str) -> None:
    # A missing binary must fail this one finding, not crash the whole run
    # (and lose the cleanup log) halfway through.
    try:
        result = subprocess.run([_find_tool(cmd[0]), *cmd[1:]], capture_output=True, text=True)
    except OSError as e:
        raise TrashError(f"'{cmd[0]}' konnte nicht gestartet werden (installiert?): {e}")
    if result.returncode != 0:
        raise TrashError(f"'{' '.join(cmd)}' fehlgeschlagen: {result.stderr.strip()}")


def ollama_rm(model_name: str) -> None:
    _run_tool("ollama", "rm", model_name)


def _docker(*args: str) -> None:
    _run_tool("docker", *args)


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

#!/usr/bin/env python3
"""mac-cleanup-tool — scan several folders for reclaimable disk space, explain what
each candidate actually is, and only remove things you explicitly approve.

Nothing is ever permanently deleted: ordinary files go to the macOS Trash (Finder),
Ollama models go through `ollama rm`. See README.md for the safety model.

Usage:
    python3 cleanup.py scan   [--category llm junk projects duplicates] [--config config.json]
    python3 cleanup.py clean  [--category llm junk projects duplicates] [--config config.json]
    python3 cleanup.py gui    [--category ...] [--config config.json]   (Fenster statt Terminal)
"""

from __future__ import annotations

import argparse
import sys

from cleaner.config import load_config
from cleaner.findings import Finding
from cleaner.report import print_report, write_cleanup_log, write_json_report
from cleaner.scanners import ALL_SCANNERS, run_scanners
from cleaner.trash import LastCopyGuard, TrashError, remove


def cmd_scan(args) -> None:
    config = load_config(args.config)
    findings = run_scanners(args.category, config)
    print_report(findings)
    write_json_report(findings, "report.json")
    print("\nDetails auch in report.json gespeichert.")


def cmd_clean(args) -> None:
    config = load_config(args.config)
    findings = run_scanners(args.category, config)
    if not findings:
        print("Keine Kandidaten gefunden – nichts zu tun.")
        return

    print_report(findings)
    log = []
    guard = LastCopyGuard(findings)

    by_category: dict[str, list[Finding]] = {}
    for f in findings:
        by_category.setdefault(f.category, []).append(f)

    for category, items in by_category.items():
        items.sort(key=lambda f: f.size_bytes, reverse=True)
        print(f"\n--- {category} ---")
        for i, f in enumerate(items, 1):
            print(f"  [{i:>3}] {f.size_human():>9}  {f.path}")
        choice = input(
            "Welche Nummern in den Papierkorb legen? "
            "(z.B. '1,3,5', 'all', Enter = keine überspringen): "
        ).strip()

        if not choice:
            continue
        if choice.lower() == "all":
            selected = items
        else:
            try:
                indices = {int(x) for x in choice.split(",") if x.strip()}
            except ValueError:
                print("  Ungültige Eingabe, überspringe diese Kategorie.")
                continue
            selected = [items[i - 1] for i in indices if 1 <= i <= len(items)]

        for f in selected:
            blocked = guard.blocks(f)
            if blocked:
                print(f"  ⤫ {blocked}")
                log.append({"path": str(f.path), "status": "skipped", "reason": blocked})
                continue
            try:
                remove(f, config)
                guard.mark_removed(f)
                print(f"  ✓ entfernt: {f.path}")
                log.append({"path": str(f.path), "status": "removed", "action": f.action})
            except TrashError as e:
                print(f"  ✗ {e}")
                log.append({"path": str(f.path), "status": "failed", "error": str(e)})

    log_path = write_cleanup_log(log)
    where = "im Papierkorb" if sys.platform == "darwin" else "in ~/.cleanup-tool-trash"
    print(f"\nProtokoll gespeichert unter {log_path}.")
    print(f"Entfernte Dateien liegen {where} und sind wiederherstellbar – Platz wird erst frei, wenn du ihn leerst.")


def cmd_gui(args) -> None:
    try:
        from cleaner.gui import main as gui_main
    except ImportError as e:  # tkinter is optional in some Python builds (e.g. Homebrew)
        sys.exit(
            f"Die GUI braucht tkinter, das in diesem Python fehlt ({e}).\n"
            "macOS mit Homebrew-Python: `brew install python-tk`, "
            "Debian/Kali: `sudo apt install python3-tk`."
        )
    tk_problem = _mac_tk_problem()
    if tk_problem:
        sys.exit(tk_problem)
    gui_main(args.config, args.category)


def _mac_tk_problem() -> str | None:
    """Apple's bundled /usr/bin/python3 ships the deprecated Tk 8.5, whose
    windows render as an empty black box on current macOS. Say so up front
    instead of opening a window that looks broken."""
    import tkinter

    if sys.platform != "darwin" or tkinter.TkVersion >= 8.6:
        return None
    return (
        f"Dieses Python ({sys.executable}) bringt das veraltete Tk {tkinter.TkVersion} mit – "
        "dessen Fenster bleiben auf aktuellem macOS schwarz/leer.\n\n"
        "Lösung (eins von beiden):\n"
        "  • Python von https://www.python.org/downloads/macos/ installieren (enthält Tk 8.6),\n"
        "  • oder mit Homebrew:  brew install python python-tk\n\n"
        "Danach Aufraeumen.command erneut doppelklicken – es sucht sich das passende Python selbst.\n"
        "Im Terminal alternativ:  python3.13 cleanup.py gui   (bzw. deine installierte Version)"
    )


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", help="Pfad zu einer config.json (siehe config.example.json)")
    common.add_argument(
        "--category", nargs="+", choices=list(ALL_SCANNERS) + ["all"], default=["all"],
        help="Welche Scanner laufen sollen (Default: alle)",
    )

    parser = argparse.ArgumentParser(description="Scan & clean up disk space on this Mac.")
    sub = parser.add_subparsers(dest="command", required=True)
    scan_p = sub.add_parser("scan", parents=[common], help="Nur berichten, nichts verändern")
    scan_p.set_defaults(func=cmd_scan)
    clean_p = sub.add_parser("clean", parents=[common], help="Bericht anzeigen und interaktiv aufräumen")
    clean_p.set_defaults(func=cmd_clean)
    gui_p = sub.add_parser("gui", parents=[common], help="Grafische Oberfläche öffnen")
    gui_p.set_defaults(func=cmd_gui)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if "all" in args.category:
        args.category = list(ALL_SCANNERS)
    args.func(args)


if __name__ == "__main__":
    sys.exit(main())

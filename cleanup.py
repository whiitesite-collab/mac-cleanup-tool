#!/usr/bin/env python3
"""mac-cleanup-tool — scan several folders for reclaimable disk space, explain what
each candidate actually is, and only remove things you explicitly approve.

Nothing is ever permanently deleted: ordinary files go to the macOS Trash (Finder),
Ollama models go through `ollama rm`. See README.md for the safety model.

Usage:
    python3 cleanup.py scan   [--category llm junk projects duplicates] [--config config.json]
    python3 cleanup.py clean  [--category llm junk projects duplicates] [--config config.json]
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime

from cleaner.config import load_config
from cleaner.findings import Finding
from cleaner.report import print_report, write_json_report
from cleaner.scanners import ALL_SCANNERS
from cleaner.trash import TrashError, remove


def run_scanners(categories: list[str], config: dict) -> list[Finding]:
    findings = []
    for name in categories:
        findings.extend(ALL_SCANNERS[name](config))
    return findings


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
            try:
                remove(f, config)
                print(f"  ✓ entfernt: {f.path}")
                log.append({"path": str(f.path), "status": "removed", "action": f.action})
            except TrashError as e:
                print(f"  ✗ {e}")
                log.append({"path": str(f.path), "status": "failed", "error": str(e)})

    log_path = f"cleanup-log-{datetime.now():%Y%m%d-%H%M%S}.json"
    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(log, f, indent=2, ensure_ascii=False)
    print(f"\nProtokoll gespeichert unter {log_path}. Papierkorb-Elemente sind normal wiederherstellbar.")


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
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if "all" in args.category:
        args.category = list(ALL_SCANNERS)
    args.func(args)


if __name__ == "__main__":
    sys.exit(main())

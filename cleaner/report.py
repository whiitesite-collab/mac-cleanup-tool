"""Rendering findings to the terminal and to a JSON report file."""

from __future__ import annotations

import json
from datetime import datetime

from .findings import Finding

CATEGORY_LABELS = {
    "llm_model": "LLM-Modelldateien",
    "system_junk": "System-Müll (Caches/Logs/Installer)",
    "project_leftover": "Alte Projekt-Reste",
    "duplicate": "Duplikate",
}


def print_report(findings: list[Finding]) -> None:
    if not findings:
        print("Keine Kandidaten gefunden – nichts zu tun.")
        return

    by_category: dict[str, list[Finding]] = {}
    for f in findings:
        by_category.setdefault(f.category, []).append(f)

    grand_total = 0
    for category, items in by_category.items():
        items.sort(key=lambda f: f.size_bytes, reverse=True)
        subtotal = sum(f.size_bytes for f in items)
        grand_total += subtotal
        print(f"\n{CATEGORY_LABELS.get(category, category)} — {len(items)} Fund(e), {_human(subtotal)}")
        print("-" * 78)
        for i, f in enumerate(items, 1):
            print(f"  [{i:>3}] {f.size_human():>9}  {f.path}")
            print(f"        {f.reason}")

    print("\n" + "=" * 78)
    print(f"Gesamt: {len(findings)} Fund(e), {_human(grand_total)} potenziell freigebbar")
    print("Nichts wurde verändert – das ist nur der Bericht. Zum Aufräumen: `python3 cleanup.py clean`")


def write_json_report(findings: list[Finding], path: str) -> None:
    payload = {
        "generated_at": datetime.now().isoformat(),
        "total_size_bytes": sum(f.size_bytes for f in findings),
        "findings": [
            {
                "path": str(f.path),
                "category": f.category,
                "size_bytes": f.size_bytes,
                "modified": f.modified.isoformat(),
                "reason": f.reason,
                "action": f.action,
                "action_arg": f.action_arg,
            }
            for f in findings
        ],
    }
    with open(path, "w", encoding="utf-8") as out:
        json.dump(payload, out, indent=2, ensure_ascii=False)


def _human(size_bytes: float) -> str:
    size = float(size_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"

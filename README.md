# mac-cleanup-tool

Scannt mehrere Ordner auf deinem Mac nach reklamierbarem Speicherplatz, erklärt
für jeden Fund, **was die Datei/der Ordner ist und warum sie infrage kommt**,
und entfernt nichts, ohne dass du es explizit bestätigst.

## Was wird gescannt?

| Kategorie | Was | Woran erkannt |
|---|---|---|
| **LLM-Modelldateien** | Ollama-Modelle (`~/.ollama/models`) + frei liegende Gewichtsdateien (`.gguf`, `.bin`, `.safetensors`, `.ckpt`, `.pt`) | Ollama-Manifest bzw. Dateigröße + Alter |
| **System-Müll** | `~/Library/Caches`, `~/Library/Logs`, Xcode `DerivedData`, npm/pip-Cache, alte Installer (`.dmg`/`.pkg`) in Downloads | Alter der letzten Änderung |
| **Alte Projekt-Reste** | `node_modules`, `venv`/`.venv`, `__pycache__`, `dist`, `build`, `target` unter deinen Projekt-Ordnern | Ordner seit X Tagen unangetastet – per Paketmanager/Build neu erzeugbar |
| **Duplikate** | Byte-identische Dateien (SHA-256) über mehrere Ordner verteilt | Hash-Vergleich, älteste Kopie bleibt als Original |

Konfigurierbar über eine eigene `config.json` (Kopie von `config.example.json`).

## Sicherheitsprinzip

**Nichts wird endgültig gelöscht.**

- Gewöhnliche Dateien/Ordner werden über Finder in den **macOS-Papierkorb**
  verschoben (`osascript` → `Finder: delete`) – genau wie per Rechtsklick →
  "In den Papierkorb legen". Wiederherstellbar, bis du den Papierkorb selbst leerst.
- Ollama-Modelle werden über `ollama rm <model>` entfernt, nicht durch direktes
  Löschen der Blob-Dateien – die sind content-addressed und können von mehreren
  Modellen gemeinsam genutzt werden.
- Dateien, die seit weniger als 24h verändert wurden, werden übersprungen
  (wahrscheinlich in Benutzung).
- Ein fester Ausschluss (`protected_paths`) schützt Keychains, Mail, Messages,
  iCloud/CloudStorage, `~/.ssh` und TCC-Daten – die werden nie angefasst,
  unabhängig von den Scan-Ergebnissen.
- Es wird nie außerhalb von `$HOME` operiert.

## Nutzung

```bash
# Nur Bericht – verändert nichts
python3 cleanup.py scan

# Bericht + interaktiv aufräumen (fragt pro Kategorie, welche Nummern in den Papierkorb sollen)
python3 cleanup.py clean

# Nur bestimmte Kategorien
python3 cleanup.py scan --category llm duplicates

# Mit eigener Konfiguration
cp config.example.json config.json   # dann Pfade anpassen
python3 cleanup.py scan --config config.json
```

`clean` zeigt zuerst denselben Bericht wie `scan`, fragt dann **pro Kategorie**
nach den Nummern der Funde, die entfernt werden sollen (`1,3,5`, `all`, oder
Enter zum Überspringen). Jeder Lauf schreibt ein Protokoll
(`cleanup-log-<timestamp>.json`) mit dem tatsächlichen Ergebnis pro Datei.

## Voraussetzungen

- macOS (nutzt `osascript`/Finder für den Papierkorb)
- Python 3.9+ (nur Standardbibliothek, keine Abhängigkeiten)
- Optional: [Ollama](https://ollama.com) installiert, falls Ollama-Modelle
  erfasst werden sollen

## Struktur

```
cleanup.py              CLI-Einstiegspunkt (scan / clean)
cleaner/
  config.py             Default-Pfade, Schwellwerte, Schutzliste
  findings.py           Finding-Datenklasse
  scanners.py           Die vier Scan-Funktionen
  trash.py               Papierkorb-/ollama-rm-Logik (nie permanent löschen)
  report.py             Terminal- und JSON-Ausgabe
config.example.json     Vorlage für eigene Config
```

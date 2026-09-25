# mac-cleanup-tool

Scannt mehrere Ordner nach reklamierbarem Speicherplatz, erklärt für jeden
Fund, **was die Datei/der Ordner ist und warum sie infrage kommt**, und
entfernt nichts, ohne dass du es explizit bestätigst.

Läuft auf **macOS** und **Linux** (inkl. Kali unter WSL) – die Default-Pfade
und der Entfernungs-Mechanismus passen sich automatisch der Plattform an.

## Was wird gescannt?

| Kategorie | Was | Woran erkannt | Plattform |
|---|---|---|---|
| **LLM-Modelldateien** | Ollama-Modelle (`~/.ollama/models`) + frei liegende Gewichtsdateien (`.gguf`, `.bin`, `.safetensors`, `.ckpt`, `.pt`) | Ollama-Manifest bzw. Dateigröße + Alter | beide |
| **System-Müll** | macOS: `~/Library/Caches`, `~/Library/Logs`, Xcode `DerivedData`. Linux: `~/.cache`. Beide: npm/pip-Cache, alte Installer (`.dmg`/`.pkg`, nur macOS) | Alter der letzten Änderung | beide |
| **Alte Projekt-Reste** | `node_modules`, `venv`/`.venv`, `__pycache__`, `dist`, `build`, `target` unter deinen Projekt-Ordnern | Ordner seit X Tagen unangetastet – per Paketmanager/Build neu erzeugbar | beide |
| **Duplikate** | Byte-identische Dateien (Größe → 64KB-Prefix-Hash → SHA-256) über mehrere Ordner verteilt | Gestaffelter Hash-Vergleich, älteste Kopie bleibt als Original | beide |
| **APT-Paket-Cache** | Alte `.deb`-Archive in `/var/cache/apt/archives` | Alter der Datei | nur Linux, **nur Bericht** |
| **Pentest-Output/Loot** | Alte Engagement-Ordner/Dateien unter `~/loot`, `~/.msf4/loot`, `~/nmap-output`, `~/engagements` (konfigurierbar) | Ordner/Datei seit X Tagen unangetastet | nur Linux |
| **Docker** | Dangling Images, gestoppte Container, verwaiste Volumes | `docker images/ps/volume ls` mit den passenden Filtern | beide, wenn `docker` installiert & Daemon erreichbar |

Konfigurierbar über eine eigene `config.json` (Kopie von `config.example.json`
für macOS bzw. `config.linux.example.json` für Kali/Linux).

## Sicherheitsprinzip

**Gewöhnliche Dateien werden nie endgültig gelöscht** – Ausnahme sind
Ollama-Modelle und Docker-Objekte (siehe unten), die über ihr eigenes CLI
entfernt werden und nicht im Papierkorb landen.

- **macOS:** gewöhnliche Dateien/Ordner werden über Finder in den
  **Papierkorb** verschoben (`osascript` → `Finder: delete`) – genau wie per
  Rechtsklick → "In den Papierkorb legen". Wiederherstellbar, bis du den
  Papierkorb selbst leerst.
- **Linux:** kein Finder-Papierkorb vorhanden, also wandert alles in einen
  eigenen Quarantäne-Ordner **`~/.cleanup-tool-trash/`**, der die
  Originalstruktur unter `$HOME` spiegelt. Wiederherstellen = die Datei von
  dort zurückverschieben. Der Ordner wird von diesem Tool nie automatisch
  geleert – das entscheidest du.
- Ollama-Modelle werden über `ollama rm <model>` entfernt, nicht durch
  direktes Löschen der Blob-Dateien – die sind content-addressed und können
  von mehreren Modellen gemeinsam genutzt werden. **Das ist endgültig**
  (neu herunterladen per `ollama pull` geht natürlich).
- Docker-Funde werden über `docker rmi`/`docker rm`/`docker volume rm`
  entfernt, nicht durch Löschen von Storage-Driver-Dateien. **Das ist
  endgültig** – besonders bei Volumes (können Datenbank-Daten enthalten).
- Der **APT-Paket-Cache wird nie automatisch angefasst** – der Ordner gehört
  meist root, daher zeigt dieses Tool hier nur einen Bericht plus den
  manuellen Befehl (`sudo apt-get clean`). Kein Teil dieses Tools läuft mit
  erhöhten Rechten.
- Dateien, die seit weniger als 24h verändert wurden, werden übersprungen
  (wahrscheinlich in Benutzung).
- Ein fester Ausschluss (`protected_paths`) schützt macOS: Keychains, Mail,
  Messages, iCloud/CloudStorage, TCC-Daten; Linux: `~/.ssh`, `~/.gnupg`,
  `~/.aws`, `~/.mozilla`, die Metasploit-Datenbank – unabhängig von den
  Scan-Ergebnissen.
- Es wird nie außerhalb von `$HOME` operiert.
- **Pentest-Loot ist absichtlich vorsichtig:** die Loot-Funde gehen wie alles
  andere nur in den Papierkorb/die Quarantäne, nie direkt weg – falls ein
  Report doch noch auf die Rohdaten zurückgreifen muss.

## GUI (Fenster statt Terminal)

```bash
python3 cleanup.py gui
```

Oder auf dem Mac einfach **`Aufraeumen.command` im Finder doppelklicken**.

1. Oben die Kategorien anhaken (z.B. nur *LLM-Modelle* und *Duplikate*) → **Scannen**.
   Der Scan verändert nichts.
2. Funde per Klick auf das Kästchen ☐ auswählen – ein Klick auf die
   Kategorie-Zeile wählt die ganze Kategorie. Ein einfacher Klick zeigt unten,
   *was* der Fund ist und *warum* er vorgeschlagen wird; ein Doppelklick
   zeigt die Datei im Finder.
3. **Ausgewählte entfernen…** → Bestätigen. Dateien wandern in den Papierkorb
   (macOS) bzw. nach `~/.cleanup-tool-trash` (Linux). Platz wird erst frei,
   wenn du den Papierkorb leerst.

Die GUI warnt extra, wenn etwas **endgültig** gelöscht würde (`ollama rm`,
Docker – die landen nicht im Papierkorb) oder wenn bei einem Duplikat auch das
Original ausgewählt ist. Protokolle landen in `~/.cleanup-tool-logs/`.

Braucht `tkinter`: beim System-Python von macOS dabei; mit Homebrew-Python
`brew install python-tk`, auf Kali/Debian `sudo apt install python3-tk`.

## Nutzung (Terminal)

```bash
# Nur Bericht – verändert nichts
python3 cleanup.py scan

# Bericht + interaktiv aufräumen (fragt pro Kategorie, welche Nummern entfernt werden sollen)
python3 cleanup.py clean

# Nur bestimmte Kategorien
python3 cleanup.py scan --category llm duplicates
python3 cleanup.py scan --category apt loot docker   # Linux-Kategorien

# Mit eigener Konfiguration
cp config.example.json config.json          # macOS
cp config.linux.example.json config.json    # Linux/Kali
# dann Pfade anpassen
python3 cleanup.py scan --config config.json
```

`clean` zeigt zuerst denselben Bericht wie `scan`, fragt dann **pro Kategorie**
nach den Nummern der Funde, die entfernt werden sollen (`1,3,5`, `all`, oder
Enter zum Überspringen). Jeder Lauf schreibt ein Protokoll
(`cleanup-log-<timestamp>.json`) mit dem tatsächlichen Ergebnis pro Fund.

## Voraussetzungen

- macOS oder Linux (Kali unter WSL eingeschlossen)
- Python 3.9+ (nur Standardbibliothek, keine Abhängigkeiten)
- Optional: [Ollama](https://ollama.com) für die LLM-Modell-Kategorie
- Optional: `docker` (mit laufendem Daemon) für die Docker-Kategorie – ohne
  läuft der Rest des Tools normal weiter, die Kategorie liefert nur keine Funde

## Struktur

```
cleanup.py                    CLI-Einstiegspunkt (scan / clean / gui)
Aufraeumen.command            Doppelklick-Starter für die GUI (macOS)
cleaner/
  config.py                   Default-Pfade pro Plattform, Schwellwerte, Schutzliste
  findings.py                 Finding-Datenklasse
  scanners.py                 Die Scan-Funktionen (macOS + Linux)
  trash.py                    Entfernungs-Logik: Papierkorb (macOS) / Quarantäne (Linux) /
                               ollama rm / docker rm – nie permanent löschen
  report.py                   Terminal- und JSON-Ausgabe
  gui.py                      Desktop-Oberfläche (tkinter)
  util.py                     Kleine Helfer (Thread-Pool, os.scandir-Walker)
config.example.json           Vorlage für macOS
config.linux.example.json     Vorlage für Linux/Kali
```

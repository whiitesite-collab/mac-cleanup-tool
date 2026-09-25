#!/bin/bash
# Doppelklick im Finder öffnet die Aufräum-GUI.
#
# Sucht ein Python, dessen tkinter mindestens Tk 8.6 hat: Apples mitgeliefertes
# /usr/bin/python3 hat nur Tk 8.5, und dessen Fenster bleiben auf aktuellem
# macOS schwarz. Bevorzugt daher python.org- und Homebrew-Installationen.
cd "$(dirname "$0")" || exit 1

has_good_tk() {
    "$1" -c 'import sys, tkinter; sys.exit(0 if tkinter.TkVersion >= 8.6 else 1)' >/dev/null 2>&1
}

for py in \
    /Library/Frameworks/Python.framework/Versions/Current/bin/python3 \
    /Library/Frameworks/Python.framework/Versions/3.*/bin/python3 \
    /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.* \
    /usr/local/bin/python3 /usr/local/bin/python3.* \
    "$(command -v python3)"; do
    case "$py" in *-config|"") continue ;; esac
    if [ -x "$py" ] && has_good_tk "$py"; then
        exec "$py" cleanup.py gui
    fi
done

# Kein passendes Python gefunden: cleanup.py erklärt, was zu tun ist.
python3 cleanup.py gui
echo
read -r -p "Enter drücken zum Schließen …" _

#!/bin/bash
# Doppelklick im Finder öffnet die Aufräum-GUI.
cd "$(dirname "$0")" && exec python3 cleanup.py gui

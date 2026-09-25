"""Desktop GUI (tkinter, standard library only) for the same scan -> review ->
remove workflow as the CLI. It uses the same scanners and the same reversible
removal in trash.py; nothing is removed without ticking it and confirming.

Scans and removals run on a worker thread and report back through a queue,
because tkinter widgets may only be touched from the main thread.
"""

from __future__ import annotations

import queue
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .config import load_config
from .findings import Finding
from .report import CATEGORY_LABELS, human_size, write_cleanup_log
from .scanners import ALL_SCANNERS, run_scanners
from .trash import IRREVERSIBLE_ACTIONS, LastCopyGuard, TrashError, remove

SCANNER_LABELS = {
    "llm": "LLM-Modelle",
    "duplicates": "Duplikate",
    "junk": "System-Müll",
    "projects": "Projekt-Reste",
    "docker": "Docker",
    "apt": "APT-Cache",
    "loot": "Pentest-Loot",
}

ACTION_LABELS = {
    "trash": "Papierkorb" if sys.platform == "darwin" else "Quarantäne",
    "ollama_rm": "ollama rm ⚠ endgültig",
    "docker_rmi": "docker rmi ⚠ endgültig",
    "docker_rm_container": "docker rm ⚠ endgültig",
    "docker_volume_rm": "volume rm ⚠ endgültig",
    "manual": "manuell (sudo)",
}

LOG_DIR = Path.home() / ".cleanup-tool-logs"

BOX_OFF, BOX_ON, BOX_PARTIAL = "☐", "☑", "▣"


def _display_path(path: Path) -> str:
    try:
        return str(Path("~") / path.relative_to(Path.home()))
    except ValueError:
        return str(path)


class CleanupApp:
    def __init__(self, root: tk.Tk, config_path: str | None = None, categories: list[str] | None = None):
        self.root = root
        self.config_path = config_path
        self.events: queue.Queue = queue.Queue()
        self.findings: dict[str, Finding] = {}   # child iid -> finding
        self.errors: dict[str, str] = {}         # child iid -> last removal error
        self.selected: set[str] = set()
        self.guard = LastCopyGuard([])
        self.busy = False

        root.title("Aufräumen – mac-cleanup-tool")
        root.geometry("1100x680")
        root.minsize(760, 460)

        self._build_toolbar(categories or list(ALL_SCANNERS))
        self._build_tree()
        self._build_details()
        self._build_statusbar()
        self._update_status()
        root.after(100, self._poll_events)

    # ------------------------------------------------------------------ layout

    def _build_toolbar(self, categories: list[str]) -> None:
        bar = ttk.Frame(self.root, padding=(10, 10, 10, 4))
        bar.pack(fill="x")

        ttk.Label(bar, text="Scannen:").pack(side="left", padx=(0, 6))
        self.category_vars: dict[str, tk.BooleanVar] = {}
        for key in SCANNER_LABELS:
            var = tk.BooleanVar(value=key in categories)
            self.category_vars[key] = var
            ttk.Checkbutton(bar, text=SCANNER_LABELS[key], variable=var).pack(side="left", padx=2)

        self.scan_button = ttk.Button(bar, text="Scannen", command=self._start_scan)
        self.scan_button.pack(side="right")
        self.config_button = ttk.Button(bar, text="Config…", command=self._choose_config)
        self.config_button.pack(side="right", padx=6)

    def _build_tree(self) -> None:
        frame = ttk.Frame(self.root, padding=(10, 4))
        frame.pack(fill="both", expand=True)

        columns = ("size", "age", "action", "path")
        self.tree = ttk.Treeview(frame, columns=columns, selectmode="browse")
        self.tree.heading("#0", text="Auswahl")
        self.tree.heading("size", text="Größe")
        self.tree.heading("age", text="Alter")
        self.tree.heading("action", text="Entfernen per")
        self.tree.heading("path", text="Pfad")
        self.tree.column("#0", width=360, stretch=False)
        self.tree.column("size", width=110, anchor="e", stretch=False)
        self.tree.column("age", width=80, anchor="e", stretch=False)
        self.tree.column("action", width=170, stretch=False)
        self.tree.column("path", width=400)
        self.tree.tag_configure("category", font=("TkDefaultFont", 0, "bold"))
        self.tree.tag_configure("failed", foreground="#c0392b")
        self.tree.tag_configure("irreversible", foreground="#b9770e")

        scroll = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        self.tree.bind("<Button-1>", self._on_click)
        self.tree.bind("<space>", self._on_space)
        self.tree.bind("<Double-1>", self._on_double_click)
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self._show_details())

        self.empty_hint = ttk.Label(
            self.tree,
            text="Wähle oben die Kategorien und klicke auf „Scannen“.\n"
                 "Der Scan verändert nichts – entfernt wird erst, was du abhakst und bestätigst.",
            justify="center",
        )
        self.empty_hint.place(relx=0.5, rely=0.4, anchor="center")

    def _build_details(self) -> None:
        frame = ttk.LabelFrame(self.root, text="Details", padding=8)
        frame.pack(fill="x", padx=10, pady=4)
        self.details = tk.Text(frame, height=4, wrap="word", relief="flat", font="TkDefaultFont",
                               background=self.root.cget("background"))
        self.details.pack(fill="x")
        self._set_details("Klicke auf einen Fund, um zu sehen, was er ist und warum er vorgeschlagen wird. "
                          "Doppelklick zeigt die Datei im Finder/Dateimanager.")

    def _build_statusbar(self) -> None:
        bar = ttk.Frame(self.root, padding=(10, 4, 10, 10))
        bar.pack(fill="x")

        self.status = ttk.Label(bar, text="")
        self.status.pack(side="left")
        self.progress = ttk.Progressbar(bar, mode="indeterminate", length=140)

        self.remove_button = ttk.Button(bar, text="Ausgewählte entfernen…", command=self._confirm_remove)
        self.remove_button.pack(side="right")
        ttk.Button(bar, text="Keine", command=lambda: self._select_all(False)).pack(side="right", padx=4)
        ttk.Button(bar, text="Alle", command=lambda: self._select_all(True)).pack(side="right")

    # --------------------------------------------------------------- scanning

    def _choose_config(self) -> None:
        path = filedialog.askopenfilename(
            title="config.json wählen", filetypes=[("JSON", "*.json"), ("Alle Dateien", "*")],
        )
        if not path:
            return
        try:
            load_config(path)
        except (OSError, ValueError) as e:
            messagebox.showerror("Config ungültig", f"{path}\n\n{e}")
            return
        self.config_path = path
        self.config_button.configure(text=f"Config: {Path(path).name}")

    def _start_scan(self) -> None:
        categories = [k for k, v in self.category_vars.items() if v.get()]
        if not categories:
            messagebox.showinfo("Nichts ausgewählt", "Bitte mindestens eine Kategorie zum Scannen anhaken.")
            return
        try:
            config = load_config(self.config_path)
        except (OSError, ValueError) as e:
            messagebox.showerror("Config ungültig", str(e))
            return

        self._set_busy(True, "Scanne…")

        def work() -> None:
            try:
                progress = lambda name: self.events.put(("progress", f"Scanne {SCANNER_LABELS.get(name, name)}…"))
                findings = run_scanners(categories, config, on_progress=progress)
                self.events.put(("scan_done", findings, config))
            except Exception as e:  # surface anything unexpected instead of a silently dead thread
                self.events.put(("scan_error", f"{type(e).__name__}: {e}"))

        threading.Thread(target=work, daemon=True).start()

    def _populate(self, findings: list[Finding]) -> None:
        self.tree.delete(*self.tree.get_children())
        self.findings.clear()
        self.errors.clear()
        self.selected.clear()
        self.guard = LastCopyGuard(findings)

        by_category: dict[str, list[Finding]] = {}
        for f in findings:
            by_category.setdefault(f.category, []).append(f)

        n = 0
        for category, items in by_category.items():
            items.sort(key=lambda f: f.size_bytes, reverse=True)
            parent = f"cat:{category}"
            self.tree.insert("", "end", iid=parent, open=True, tags=("category",))
            for f in items:
                iid = f"f:{n}"
                n += 1
                self.findings[iid] = f
                tags = ("irreversible",) if f.action in IRREVERSIBLE_ACTIONS else ()
                self.tree.insert(parent, "end", iid=iid, tags=tags, values=(
                    f.size_human(),
                    f"{f.age_days} Tage",
                    ACTION_LABELS.get(f.action, f.action),
                    _display_path(f.path),
                ))
                self._render_item(iid)
            self._render_category(parent)

        if findings:
            self.empty_hint.place_forget()
        else:
            self.empty_hint.configure(text="Keine Kandidaten gefunden – nichts zu tun. 🎉")
            self.empty_hint.place(relx=0.5, rely=0.4, anchor="center")

    # -------------------------------------------------------------- selection

    def _render_item(self, iid: str) -> None:
        f = self.findings[iid]
        box = BOX_ON if iid in self.selected else BOX_OFF
        # Ollama/Docker findings are named by the CLI identifier, not the file.
        name = f.action_arg if f.action in IRREVERSIBLE_ACTIONS else (f.path.name or str(f.path))
        self.tree.item(iid, text=f"{box}  {name}")

    def _render_category(self, parent: str) -> None:
        children = self.tree.get_children(parent)
        if not children:
            self.tree.delete(parent)
            return
        chosen = sum(1 for c in children if c in self.selected)
        box = BOX_OFF if chosen == 0 else BOX_ON if chosen == len(children) else BOX_PARTIAL
        category = parent.split(":", 1)[1]
        total = sum(self.findings[c].size_bytes for c in children)
        label = CATEGORY_LABELS.get(category, category)
        self.tree.item(parent, text=f"{box}  {label}", values=(human_size(total), "", f"{len(children)} Fund(e)", ""))

    def _toggle(self, iid: str) -> None:
        if self.busy or not iid:
            return
        if iid.startswith("cat:"):
            children = self.tree.get_children(iid)
            target = not all(c in self.selected for c in children)
            for c in children:
                self._set_selected(c, target)
            self._render_category(iid)
        else:
            self._set_selected(iid, iid not in self.selected)
            self._render_category(self.tree.parent(iid))
        self._update_status()

    def _set_selected(self, iid: str, value: bool) -> None:
        if value:
            self.selected.add(iid)
        else:
            self.selected.discard(iid)
        self._render_item(iid)

    def _select_all(self, value: bool) -> None:
        if self.busy:
            return
        for parent in self.tree.get_children():
            for c in self.tree.get_children(parent):
                self._set_selected(c, value)
            self._render_category(parent)
        self._update_status()

    def _on_click(self, event) -> None:
        # Only the checkbox column toggles; the expand/collapse arrow keeps its normal job.
        if self.tree.identify_column(event.x) != "#0":
            return
        if "indicator" in self.tree.identify_element(event.x, event.y):
            return
        self._toggle(self.tree.identify_row(event.y))

    def _on_space(self, _event) -> str:
        self._toggle(self.tree.focus())
        return "break"

    def _on_double_click(self, event) -> str | None:
        iid = self.tree.identify_row(event.y)
        f = self.findings.get(iid)
        if f is None or f.action != "trash" or self.tree.identify_column(event.x) == "#0":
            return None
        try:
            if sys.platform == "darwin":
                subprocess.Popen(["open", "-R", str(f.path)])
            else:
                subprocess.Popen(["xdg-open", str(f.path.parent)])
        except OSError as e:
            messagebox.showerror("Konnte nicht öffnen", str(e))
        return "break"

    # ---------------------------------------------------------------- details

    def _set_details(self, text: str) -> None:
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", text)
        self.details.configure(state="disabled")

    def _show_details(self) -> None:
        iid = self.tree.focus()
        f = self.findings.get(iid)
        if f is None:
            return
        lines = [_display_path(f.path), f.reason]
        if f.action in IRREVERSIBLE_ACTIONS:
            lines.append("⚠ Wird über ein externes Programm entfernt und landet NICHT im Papierkorb – "
                         "nicht rückgängig zu machen.")
        elif f.action == "manual":
            lines.append(f"Wird nicht automatisch entfernt. Selbst im Terminal ausführen: {f.action_arg}")
        if iid in self.errors:
            lines.append(f"✗ Letzter Versuch fehlgeschlagen: {self.errors[iid]}")
        self._set_details("\n".join(lines))

    def _update_status(self) -> None:
        total = len(self.findings)
        chosen = [self.findings[i] for i in self.selected]
        size = sum(f.size_bytes for f in chosen)
        irreversible = sum(1 for f in chosen if f.action in IRREVERSIBLE_ACTIONS)
        text = f"{total} Fund(e) · {len(chosen)} ausgewählt · {human_size(size)}"
        if irreversible:
            text += f" · ⚠ {irreversible} davon endgültig"
        self.status.configure(text=text)
        if not self.busy:
            self.remove_button.state(["!disabled"] if chosen else ["disabled"])

    def _set_busy(self, busy: bool, text: str = "") -> None:
        self.busy = busy
        for button in (self.scan_button, self.config_button, self.remove_button):
            button.state(["disabled"] if busy else ["!disabled"])
        if busy:
            self.status.configure(text=text)
            self.progress.pack(side="left", padx=10)
            self.progress.start(12)
        else:
            self.progress.stop()
            self.progress.pack_forget()
            self._update_status()

    # ---------------------------------------------------------------- removal

    def _confirm_remove(self) -> None:
        iids = [i for i in self.findings if i in self.selected]  # keep display order
        manual = [i for i in iids if self.findings[i].action == "manual"]
        removable = [i for i in iids if i not in manual]

        if manual:
            commands = sorted({self.findings[i].action_arg for i in manual})
            self.root.clipboard_clear()
            self.root.clipboard_append("\n".join(commands))
            messagebox.showinfo(
                "Manueller Schritt",
                "Diese Funde brauchen Root-Rechte und werden nicht von diesem Tool entfernt.\n"
                "Der Befehl ist in der Zwischenablage – selbst im Terminal ausführen:\n\n" + "\n".join(commands),
            )
        if not removable:
            return

        chosen = [self.findings[i] for i in removable]
        size = human_size(sum(f.size_bytes for f in chosen))
        irreversible = [f for f in chosen if f.action in IRREVERSIBLE_ACTIONS]
        where = "den Papierkorb" if sys.platform == "darwin" else "die Quarantäne (~/.cleanup-tool-trash)"
        message = f"{len(chosen)} Fund(e) mit zusammen {size} entfernen?\n\nDateien wandern in {where}."

        chosen_paths = {str(f.path) for f in chosen}
        both_copies = [f for f in chosen if f.category == "duplicate" and f.extra.get("original") in chosen_paths]
        if both_copies:
            message += (f"\n\n⚠ Bei {len(both_copies)} Duplikat(en) ist auch das Original ausgewählt "
                        "(z.B. unter LLM-Modelle). Die jeweils letzte Kopie wird automatisch behalten.")
        if irreversible:
            names = "\n".join(f"  • {f.action_arg}" for f in irreversible[:8])
            more = f"\n  … und {len(irreversible) - 8} weitere" if len(irreversible) > 8 else ""
            message += (f"\n\n⚠ {len(irreversible)} davon werden ENDGÜLTIG gelöscht "
                        f"(ollama/docker, kein Papierkorb):\n{names}{more}")

        ask = messagebox.askokcancel if (irreversible or both_copies) else messagebox.askyesno
        if not ask("Entfernen bestätigen", message, icon="warning" if (irreversible or both_copies) else "question"):
            return
        self._start_remove(removable)

    def _start_remove(self, iids: list[str]) -> None:
        config = load_config(self.config_path)
        items = [(i, self.findings[i]) for i in iids]
        guard = self.guard  # only this worker touches it until "remove_done"
        self._set_busy(True, f"Entferne {len(items)} Fund(e)…")

        def work() -> None:
            log = []
            for iid, f in items:
                blocked = guard.blocks(f)
                if blocked:
                    log.append({"path": str(f.path), "status": "skipped", "reason": blocked})
                    self.events.put(("failed", iid, blocked))
                    continue
                try:
                    remove(f, config)
                    guard.mark_removed(f)
                    log.append({"path": str(f.path), "status": "removed", "action": f.action})
                    self.events.put(("removed", iid))
                except (TrashError, OSError) as e:
                    log.append({"path": str(f.path), "status": "failed", "error": str(e)})
                    self.events.put(("failed", iid, str(e)))
            try:
                log_path = str(write_cleanup_log(log, LOG_DIR))
            except OSError as e:
                log_path = f"(Protokoll konnte nicht gespeichert werden: {e})"
            self.events.put(("remove_done", log_path))

        threading.Thread(target=work, daemon=True).start()

    # ----------------------------------------------------------- event queue

    def _poll_events(self) -> None:
        try:
            while True:
                self._handle(self.events.get_nowait())
        except queue.Empty:
            pass
        self.root.after(100, self._poll_events)

    def _handle(self, event: tuple) -> None:
        kind = event[0]
        if kind == "progress":
            self.status.configure(text=event[1])
        elif kind == "scan_done":
            self._populate(event[1])
            self._set_busy(False)
        elif kind == "scan_error":
            self._set_busy(False)
            messagebox.showerror("Scan fehlgeschlagen", event[1])
        elif kind == "removed":
            iid = event[1]
            parent = self.tree.parent(iid)
            self.tree.delete(iid)
            self.findings.pop(iid, None)
            self.selected.discard(iid)
            self.errors.pop(iid, None)
            self._render_category(parent)
        elif kind == "failed":
            iid, error = event[1], event[2]
            self.errors[iid] = error
            self.tree.item(iid, tags=("failed",))
        elif kind == "remove_done":
            failed = sum(1 for i in self.selected if i in self.errors)
            self._set_busy(False)
            summary = f"Fertig. Protokoll: {event[1]}"
            if failed:
                # Show the reasons right here - a permission problem hits every
                # item the same way, and should be readable without clicking.
                reasons = list(dict.fromkeys(self.errors[i] for i in self.selected if i in self.errors))
                shown = "\n\n".join(f"• {r}" for r in reasons[:3])
                more = f"\n\n… und {len(reasons) - 3} weitere Gründe" if len(reasons) > 3 else ""
                summary = (f"{failed} Fund(e) wurden nicht entfernt (rot markiert):\n\n{shown}{more}\n\n"
                           + summary)
            if sys.platform == "darwin":
                summary += "\n\nTipp: Platz wird erst frei, wenn du den Papierkorb leerst."
            else:
                summary += "\n\nTipp: Platz wird erst frei, wenn du ~/.cleanup-tool-trash leerst."
            messagebox.showinfo("Aufräumen abgeschlossen", summary)


def main(config_path: str | None = None, categories: list[str] | None = None) -> None:
    root = tk.Tk()
    CleanupApp(root, config_path, categories)
    root.mainloop()

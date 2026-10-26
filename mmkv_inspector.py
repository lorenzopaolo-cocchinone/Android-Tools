#!/usr/bin/env python3
"""MMKV Inspector - view and edit the keys and values in an Android app's MMKV storage over adb.

How it works:
  1. Pick a device, a user and a package; the app finds every MMKV store in the app's data
     folder (a data file with a .crc file next to it, usually in files/mmkv).
  2. Both files are copied to the Mac and read by mmkv_model.py. They are copied again
     only when the files on the device change.
  3. To save a change, the app is force-stopped, the files are read again, a backup is kept,
     and a fresh compacted file with a matching .crc is pushed back.

Access needs either a debuggable app (run-as) or a rooted device/emulator (su).
"""

import json
import os
import shlex
import tempfile
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, simpledialog, ttk

import mmkv_model as mm
from adb_common import AdbError, AppDataDevice, list_devices

HERE = os.path.dirname(os.path.abspath(__file__))
SETTINGS_FILE = os.path.join(HERE, ".mmkv_inspector.json")
BACKUP_DIR = os.path.join(HERE, ".mmkv_backups")
AUTO_REFRESH_MS = 2000
PREVIEW_CHARS = 200


class Device(AppDataDevice):
    """MMKV stores of one app."""

    def list_packages(self, user, system):
        flag = "" if system else " -3"
        _, out, _ = self.shell(f"pm list packages --user {user}{flag}")
        return sorted(l.split(":", 1)[1].strip() for l in out.splitlines() if l.startswith("package:"))

    def list_stores(self, access, pkg):
        """Paths of MMKV data files: every file that has a .crc file next to it."""
        base = self.data_dir(access, pkg)
        inner = (f"find {shlex.quote(base)} -name '*.crc' 2>/dev/null | "
                 'while IFS= read -r f; do d="${f%.crc}"; [ -f "$d" ] && echo "$d"; done')
        _, out, _ = self.shell(self.wrap(access, pkg, inner))
        return sorted(l.strip() for l in out.splitlines() if l.strip())

    def signature(self, access, pkg, path):
        """Size + modification time of the store's files; changes whenever the app writes."""
        q = shlex.quote
        _, out, _ = self.shell(self.wrap(access, pkg, f"stat -c '%s %y' {q(path)} {q(path + '.crc')} 2>/dev/null"))
        return out.strip()

    def read_file(self, access, pkg, path):
        return self.exec_out(self.wrap(access, pkg, f"cat {shlex.quote(path)} 2>/dev/null"))

    def write_file(self, access, pkg, path, data):
        """Overwrite a file in the app's data folder. Writing into the existing file keeps
        its owner and permissions."""
        q = shlex.quote
        tmp = f"/data/local/tmp/mmkv_{os.getpid()}_{os.path.basename(path)}"
        local = os.path.join(tempfile.gettempdir(), os.path.basename(tmp))
        with open(local, "wb") as fh:
            fh.write(data)
        try:
            if self.run("push", local, tmp).returncode == 0:
                self.shell(f"chmod 644 {q(tmp)}")
                _, out, _ = self.shell(self.wrap(access, pkg, f"cat {q(tmp)} > {q(path)} && echo __OK__"))
                self.shell(f"rm -f {q(tmp)}")
                if "__OK__" in out:
                    return
        finally:
            os.remove(local)
        # Fallback: stream the file through stdin.
        proc = self.run("exec-in", self.wrap(access, pkg, f"cat > {q(path)}"), data=data)
        if proc.returncode != 0:
            raise AdbError(f"Failed to write {path}:\n" + proc.stderr.decode(errors="replace"))


class Settings:
    """Per-key "View as" choices, saved next to the app."""

    def __init__(self, path):
        self.path = path
        try:
            with open(path, encoding="utf-8") as fh:
                self.view_as = dict(json.load(fh).get("view_as", {}))
        except (OSError, ValueError, AttributeError):
            self.view_as = {}

    def save(self):
        try:
            with open(self.path, "w", encoding="utf-8") as fh:
                json.dump({"view_as": self.view_as}, fh, indent=1)
        except OSError:
            pass


TYPE_HINTS = {
    "string": "Text, saved exactly as typed.",
    "int": "Whole number, e.g. 42, -7 or 0x1F (int and long are stored the same way).",
    "bool": "true or false.",
    "float": "Number, stored in 4 bytes.",
    "double": "Number, stored in 8 bytes.",
    "string set": 'JSON list of strings, e.g. ["a", "b"].',
    "bytes": "Hex bytes, e.g. 0a ff 10 (a byte array or Parcelable).",
    "hex": "Advanced: the raw stored bytes in hex, saved as is.",
}


class EditDialog(tk.Toplevel):
    """Edit or add one key. on_save(key, kind, raw, is_new) returns None to close,
    or a message to show (empty = stay open silently)."""

    def __init__(self, parent, key, kind, text, on_save):
        super().__init__(parent)
        self.is_new = key is None
        self.on_save = on_save
        self.title("Add key" if self.is_new else f"Edit {key}")
        self.geometry("620x420")
        self.transient(parent)
        body = ttk.Frame(self, padding=10)
        body.pack(fill="both", expand=True)

        row = ttk.Frame(body)
        row.pack(fill="x")
        ttk.Label(row, text="Key").pack(side="left")
        self.key_var = tk.StringVar(value=key or "")
        entry = ttk.Entry(row, textvariable=self.key_var, font=("Menlo", 12))
        entry.pack(side="left", fill="x", expand=True, padx=6)
        if not self.is_new:
            entry.state(["readonly"])
        ttk.Label(row, text="Type").pack(side="left")
        self.kind_var = tk.StringVar(value=kind)
        kind_cb = ttk.Combobox(row, textvariable=self.kind_var, values=mm.TYPES[1:], state="readonly", width=11)
        kind_cb.pack(side="left", padx=4)
        kind_cb.bind("<<ComboboxSelected>>", lambda e: self._update())

        self.hint_var = tk.StringVar()
        ttk.Label(body, textvariable=self.hint_var, foreground="gray").pack(anchor="w", pady=(6, 2))
        self.text = tk.Text(body, wrap="word", font=("Menlo", 12), undo=True, height=10)
        self.text.insert("1.0", text)
        self.text.pack(fill="both", expand=True)
        self.text.bind("<<Modified>>", self._modified)

        self.preview_var = tk.StringVar()
        self.preview = ttk.Label(body, textvariable=self.preview_var, wraplength=580)
        self.preview.pack(anchor="w", pady=4)
        buttons = ttk.Frame(body)
        buttons.pack(fill="x")
        ttk.Button(buttons, text="Save…", command=self.save).pack(side="right")
        ttk.Button(buttons, text="Cancel", command=self.destroy).pack(side="right", padx=4)
        ttk.Label(buttons, text="⌘↵ save · Esc cancel", foreground="gray").pack(side="left")
        for mod in ("Command", "Control"):
            self.bind(f"<{mod}-Return>", lambda e: (self.save(), "break")[1])
        self.bind("<Escape>", lambda e: self.destroy())
        self._update()
        (entry if self.is_new else self.text).focus_set()

    def _modified(self, _event):
        if self.text.edit_modified():
            self.text.edit_modified(False)
            self._update()

    def _encode(self):
        return mm.encode_value(self.kind_var.get(), self.text.get("1.0", "end-1c"))

    def _update(self):
        self.hint_var.set(TYPE_HINTS.get(self.kind_var.get(), ""))
        try:
            raw = self._encode()
        except ValueError as exc:
            self.preview_var.set(str(exc))
            self.preview.configure(foreground="red")
            return
        shown = raw.hex(" ")
        self.preview_var.set(f"Stored as {len(raw)} bytes: {shown[:150]}{'…' if len(shown) > 150 else ''}")
        self.preview.configure(foreground="gray")

    def save(self):
        key = self.key_var.get()
        if not key:
            messagebox.showwarning("Key", "Enter a key.", parent=self)
            return
        try:
            raw = self._encode()
        except ValueError as exc:
            messagebox.showwarning("Value", str(exc), parent=self)
            return
        error = self.on_save(key, self.kind_var.get(), raw, self.is_new)
        if error is None:
            self.destroy()
        elif error:
            messagebox.showwarning("Not saved", error, parent=self)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("MMKV Inspector")
        self.geometry("1150x740")
        self.minsize(800, 500)
        self.device = None
        self.devices = []
        self.users = []
        self.access = None
        self.all_packages = []
        self.stores = []        # remote paths
        self.store = None       # parsed mm.Store
        self.sig = None         # signature of the shown store
        self.crypt_keys = {}    # (pkg, store path) -> key, this session only
        self.backups = {}       # (serial, pkg, store path) -> (data, meta) before the last write
        self.settings = Settings(SETTINGS_FILE)
        self.sort_state = ("key", False)
        self.rows = []          # keys in the order shown
        self._busy = False
        self._dialog = None
        self._build_ui()
        self.after(100, self.refresh_devices)
        self.after(AUTO_REFRESH_MS, self._auto_refresh)

    # ---------- UI ----------
    def _build_ui(self):
        top = ttk.Frame(self, padding=(8, 8, 8, 0))
        top.pack(fill="x")
        ttk.Label(top, text="Device").grid(row=0, column=0, sticky="w")
        self.device_var = tk.StringVar()
        self.device_cb = ttk.Combobox(top, textvariable=self.device_var, state="readonly", width=28)
        self.device_cb.grid(row=0, column=1, sticky="w", padx=4)
        self.device_cb.bind("<<ComboboxSelected>>", lambda e: self.on_device_selected())
        ttk.Button(top, text="↻", width=3, command=self.refresh_devices).grid(row=0, column=2)

        ttk.Label(top, text="User").grid(row=0, column=3, sticky="w", padx=(12, 0))
        self.user_var = tk.StringVar()
        self.user_cb = ttk.Combobox(top, textvariable=self.user_var, state="readonly", width=18)
        self.user_cb.grid(row=0, column=4, sticky="w", padx=4)
        self.user_cb.bind("<<ComboboxSelected>>", lambda e: self.load_packages())

        ttk.Label(top, text="Package").grid(row=0, column=5, sticky="w", padx=(12, 0))
        self.pkg_var = tk.StringVar()
        self.pkg_cb = ttk.Combobox(top, textvariable=self.pkg_var, width=40)
        self.pkg_cb.grid(row=0, column=6, sticky="we", padx=4)
        self.pkg_cb.bind("<KeyRelease>", self._filter_packages)
        self.pkg_cb.bind("<<ComboboxSelected>>", lambda e: self.on_package_selected())
        self.pkg_cb.bind("<Return>", lambda e: self.on_package_selected())
        self.system_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="System apps", variable=self.system_var,
                        command=self.load_packages).grid(row=0, column=7, padx=4)
        top.columnconfigure(6, weight=1)

        bar = ttk.Frame(self, padding=8)
        bar.pack(fill="x")
        ttk.Label(bar, text="Store").pack(side="left")
        self.store_var = tk.StringVar()
        self.store_cb = ttk.Combobox(bar, textvariable=self.store_var, state="readonly", width=34)
        self.store_cb.pack(side="left", padx=4)
        self.store_cb.bind("<<ComboboxSelected>>", lambda e: self.load_store())
        ttk.Button(bar, text="⟳ Reload", command=lambda: self.load_store(force=True)).pack(side="left")
        self.auto_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="Auto refresh", variable=self.auto_var).pack(side="left", padx=8)
        ttk.Button(bar, text="Crypt key…", command=self.ask_crypt_key).pack(side="left")
        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=8)
        ttk.Button(bar, text="+ Add key", command=lambda: self.open_editor(None)).pack(side="left")
        ttk.Button(bar, text="Delete", command=self.delete_keys).pack(side="left", padx=4)
        self.undo_btn = ttk.Button(bar, text="Undo last write", command=self.undo_write)
        self.undo_btn.pack(side="left")
        self.undo_btn.state(["disabled"])
        ttk.Button(bar, text="Export JSON…", command=self.export_json).pack(side="right")
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self.fill_rows())
        ttk.Entry(bar, textvariable=self.filter_var, width=28).pack(side="right", padx=4)
        ttk.Label(bar, text="Filter").pack(side="right")

        main = ttk.PanedWindow(self, orient="horizontal")
        main.pack(fill="both", expand=True, padx=8)

        # Keys list
        left = ttk.Frame(main)
        cols = ("key", "type", "value", "size")
        self.tree = ttk.Treeview(left, columns=cols, show="headings", selectmode="extended")
        for col, width, stretch in (("key", 220, False), ("type", 80, False),
                                    ("value", 360, True), ("size", 60, False)):
            self.tree.heading(col, text=col.capitalize(), command=lambda c=col: self.sort_by(c))
            self.tree.column(col, width=width, stretch=stretch, anchor="e" if col == "size" else "w")
        vsb = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        left.rowconfigure(0, weight=1)
        left.columnconfigure(0, weight=1)
        self.tree.bind("<<TreeviewSelect>>", lambda e: self.show_detail())
        for seq in ("<Button-2>", "<Button-3>", "<Control-Button-1>"):
            self.tree.bind(seq, self._row_menu)
        for mod in ("Command", "Control"):
            self.tree.bind(f"<{mod}-c>", lambda e: self.copy_rows())
        self.tree.bind("<Double-Button-1>", self._row_double_click)
        for seq in ("<Delete>", "<BackSpace>"):
            self.tree.bind(seq, lambda e: self.delete_keys())
        main.add(left, weight=3)

        # Detail
        right = ttk.Frame(main, padding=(8, 0, 0, 0))
        head = ttk.Frame(right)
        head.pack(fill="x")
        ttk.Label(head, text="View as").pack(side="left")
        self.view_var = tk.StringVar(value="auto")
        self.view_cb = ttk.Combobox(head, textvariable=self.view_var, values=mm.TYPES,
                                    state="readonly", width=11)
        self.view_cb.pack(side="left", padx=4)
        self.view_cb.bind("<<ComboboxSelected>>", lambda e: self.set_view_as(self.view_var.get()))
        ttk.Button(head, text="Copy value", command=self.copy_value).pack(side="right")
        ttk.Button(head, text="Edit…", command=self._edit_selected).pack(side="right", padx=4)
        self.key_var = tk.StringVar()
        ttk.Label(right, textvariable=self.key_var, font=("Menlo", 13, "bold"),
                  wraplength=420).pack(anchor="w", pady=(6, 0))
        self.info_var = tk.StringVar()
        ttk.Label(right, textvariable=self.info_var, foreground="gray").pack(anchor="w")
        self.value_text = tk.Text(right, wrap="word", font=("Menlo", 12), height=12)
        self.value_text.pack(fill="both", expand=True, pady=4)
        ttk.Label(right, text="Every way the bytes can be read").pack(anchor="w")
        self.read_tree = ttk.Treeview(right, columns=("type", "value"), show="headings", height=7)
        self.read_tree.heading("type", text="Type")
        self.read_tree.heading("value", text="Value")
        self.read_tree.column("type", width=90, stretch=False)
        self.read_tree.column("value", width=300)
        self.read_tree.pack(fill="x")
        self.read_tree.bind("<Double-Button-1>", self._reading_clicked)
        main.add(right, weight=2)

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self, textvariable=self.status_var, anchor="w", padding=(8, 4),
                  relief="sunken").pack(fill="x", side="bottom")

    def status(self, msg):
        self.status_var.set(msg)

    def run_bg(self, work, done, busy_msg, quiet=False):
        """Run work() in a thread, then done(result) on the UI thread.
        quiet=True (auto refresh) shows no busy cursor and no error popups."""
        self._busy = True
        if not quiet:
            self.status(busy_msg)
            self.config(cursor="watch")

        def target():
            try:
                result, error = work(), None
            except Exception as exc:  # noqa: BLE001 - show any failure to the user
                result, error = None, exc
            self.after(0, finish, result, error)

        def finish(result, error):
            self._busy = False
            self.config(cursor="")
            if error:
                self.status(f"Error: {error}".splitlines()[0])
                if not quiet:
                    messagebox.showerror("Error", str(error))
            else:
                done(result)

        threading.Thread(target=target, daemon=True).start()

    # ---------- Device / user / package / store ----------
    def refresh_devices(self):
        def done(devices):
            self.devices = devices
            labels = [f"{s}  {m}".strip() for s, m in devices]
            self.device_cb["values"] = labels
            if labels:
                self.device_cb.current(0)
                self.on_device_selected()
            else:
                self.device_var.set("")
                self.status("No devices found. Connect one and press ↻")
        self.run_bg(list_devices, done, "Looking for devices…")

    def on_device_selected(self):
        idx = self.device_cb.current()
        if idx < 0:
            return
        self.device = Device(self.devices[idx][0])
        device = self.device

        def done(users):
            self.users = users
            self.user_cb["values"] = [f"{u}  {n}{'  (current)' if i == 0 else ''}".strip()
                                      for i, (u, n) in enumerate(users)]
            if users:
                self.user_cb.current(0)
            self.load_packages()
        self.run_bg(device.user_list, done, "Loading users…")

    def _user(self):
        idx = self.user_cb.current()
        return self.users[idx][0] if 0 <= idx < len(self.users) else 0

    def load_packages(self):
        if not self.device:
            return
        device, user, system = self.device, self._user(), self.system_var.get()

        def done(pkgs):
            self.all_packages = pkgs
            self.pkg_cb["values"] = pkgs
            self._clear_store()
            self.status(f"{len(pkgs)} packages for user {user}. Type to filter, then pick one.")
        self.run_bg(lambda: device.list_packages(user, system), done, "Loading packages…")

    def _filter_packages(self, event):
        if event.keysym in ("Return", "Up", "Down", "Escape"):
            return
        text = self.pkg_var.get().lower()
        self.pkg_cb["values"] = [p for p in self.all_packages if text in p.lower()]

    def on_package_selected(self):
        pkg = self.pkg_var.get().strip()
        if not self.device or not pkg:
            return
        device, user = self.device, self._user()

        def work():
            access = device.detect_access(pkg, user)
            return access, device.list_stores(access, pkg)

        def done(result):
            self.access, self.stores = result
            base = self.device.data_dir(self.access, pkg) + "/"
            self.store_cb["values"] = [self._store_label(p, base) for p in self.stores]
            self._clear_store()
            if self.stores:
                default = next((i for i, p in enumerate(self.stores) if p.endswith("/mmkv.default")), 0)
                self.store_cb.current(default)
                self.load_store()
            else:
                self.store_var.set("")
                self.status(f"No MMKV stores found for {pkg} (user {user})")
        self.run_bg(work, done, f"Checking access to {pkg}…")

    @staticmethod
    def _store_label(path, base):
        rel = path[len(base):] if path.startswith(base) else path
        return rel[len("files/mmkv/"):] if rel.startswith("files/mmkv/") else rel

    def _store_path(self):
        idx = self.store_cb.current()
        return self.stores[idx] if 0 <= idx < len(self.stores) else None

    def _clear_store(self):
        self._update_undo()
        self.store = None
        self.sig = None
        self.tree.delete(*self.tree.get_children())
        self.show_detail()

    def load_store(self, force=False, quiet=False, note=None):
        path = self._store_path()
        if not (self.device and self.access and path):
            return
        device, access, pkg = self.device, self.access, self.pkg_var.get().strip()
        crypt_key = self.crypt_keys.get((pkg, path))
        old_sig = None if force else self.sig

        def work():
            sig = device.signature(access, pkg, path)
            if old_sig is not None and sig == old_sig:
                return None  # unchanged
            start = time.time()
            data = device.read_file(access, pkg, path)
            if not data:
                raise AdbError(f"Could not read {path}")
            meta = device.read_file(access, pkg, path + ".crc")
            return sig, mm.parse_store(data, meta, crypt_key), time.time() - start

        def done(result):
            if result is None:
                return
            if self._store_path() != path:  # user picked another store meanwhile
                return
            self.sig, self.store, took = result
            self._update_undo()
            self.fill_rows()
            self.show_detail()
            s = self.store
            parts = [note] if note else []
            parts += [f"{len(s.entries)} keys", f"{s.size / 1024:.1f} KB used of {s.file_size / 1024:.0f} KB"]
            if s.deleted:
                parts.append(f"{s.deleted} deleted")
            if s.crc_ok is False:
                parts.append("CRC mismatch (app may be writing)")
            if s.encrypted:
                parts.append("decrypted")
            if s.expire_mode:
                parts.append("key expiry on")
            when = datetime.now().strftime("%H:%M:%S")
            parts.append(f"read at {when} in {took:.1f}s · {self.access[0]}, user {self.access[1]}")
            self.status(" · ".join(parts))

        def failed_quietly(work_fn):
            # Auto refresh: a store that can't be read is shown once, not on every tick.
            def wrapped():
                try:
                    return work_fn()
                except mm.MMKVError:
                    return None
            return wrapped
        self.run_bg(failed_quietly(work) if quiet else work, done, "Reading store…", quiet=quiet)

    def _auto_refresh(self):
        if self.auto_var.get() and not self._busy and self.store is not None:
            self.load_store(quiet=True)
        self.after(AUTO_REFRESH_MS, self._auto_refresh)

    def ask_crypt_key(self):
        path = self._store_path()
        if not path:
            return
        pkg = self.pkg_var.get().strip()
        key = simpledialog.askstring(
            "Crypt key", "The key the app passes to MMKV.mmkvWithID(…, cryptKey).\n"
                         "Leave empty for an unencrypted store.",
            initialvalue=self.crypt_keys.get((pkg, path), ""), parent=self)
        if key is None:
            return
        if key:
            self.crypt_keys[(pkg, path)] = key
        else:
            self.crypt_keys.pop((pkg, path), None)
        self.load_store(force=True)

    # ---------- Keys list ----------
    def _view_key(self, key):
        return f"{self.pkg_var.get().strip()}|{self.store_var.get()}|{key}"

    def view_as(self, key):
        return self.settings.view_as.get(self._view_key(key), "auto")

    def fill_rows(self):
        selected = set(self._selected_keys())
        self.tree.delete(*self.tree.get_children())
        if not self.store:
            self.rows = []
            return
        text = self.filter_var.get().lower()
        rows = []
        for key, entry in self.store.entries.items():
            kind, value = mm.show(entry.raw, self.view_as(key))
            if text and text not in key.lower() and text not in value.lower():
                continue
            rows.append((key, kind, value, len(entry.raw)))
        col, reverse = self.sort_state
        idx = ("key", "type", "value", "size").index(col)
        rows.sort(key=lambda r: r[idx] if col == "size" else str(r[idx]).lower(), reverse=reverse)
        self.rows = [r[0] for r in rows]
        for i, (key, kind, value, size) in enumerate(rows):
            if self.view_as(key) != "auto":
                kind += " ✎"
            preview = value.replace("\n", " ")[:PREVIEW_CHARS]
            self.tree.insert("", "end", iid=str(i), values=(key, kind, preview, size))
        keep = [str(i) for i, k in enumerate(self.rows) if k in selected]
        if keep:
            self.tree.selection_set(keep)
        for c in ("key", "type", "value", "size"):
            arrow = (" ▼" if reverse else " ▲") if c == col else ""
            self.tree.heading(c, text=c.capitalize() + arrow)

    def sort_by(self, col):
        cur, reverse = self.sort_state
        self.sort_state = (col, not reverse if cur == col else False)
        self.fill_rows()

    def _selected_keys(self):
        return [self.rows[int(i)] for i in self.tree.selection() if int(i) < len(self.rows)]

    def _row_menu(self, event):
        row = self.tree.identify_row(event.y)
        if not row:
            return
        if row not in self.tree.selection():
            self.tree.selection_set(row)
        key = self.rows[int(row)]
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Edit value…", command=lambda: self.open_editor(key))
        menu.add_command(label="Delete key(s)…", command=self.delete_keys)
        menu.add_separator()
        menu.add_command(label="Copy key", command=lambda: self._to_clipboard(key, "key"))
        menu.add_command(label="Copy value", command=self.copy_value)
        menu.add_command(label="Copy rows (key ⇥ value)", command=self.copy_rows)
        sub = tk.Menu(menu, tearoff=0)
        for kind in mm.TYPES:
            sub.add_command(label=kind, command=lambda k=kind: self.set_view_as(k))
        menu.add_cascade(label="View as", menu=sub)
        menu.tk_popup(event.x_root, event.y_root)

    def copy_rows(self):
        keys = self._selected_keys()
        if not keys:
            return
        lines = [f"{k}\t{mm.show(self.store.entries[k].raw, self.view_as(k))[1]}" for k in keys]
        self._to_clipboard("\n".join(lines), f"{len(keys)} row(s)")

    def copy_value(self):
        keys = self._selected_keys()
        if keys:
            entry = self.store.entries[keys[0]]
            self._to_clipboard(mm.show(entry.raw, self.view_as(keys[0]), pretty=True)[1], "value")

    def _to_clipboard(self, text, what):
        self.clipboard_clear()
        self.clipboard_append(text)
        self.status(f"Copied {what}")

    # ---------- Detail ----------
    def show_detail(self):
        keys = self._selected_keys()
        self.value_text.configure(state="normal")
        self.value_text.delete("1.0", "end")
        self.read_tree.delete(*self.read_tree.get_children())
        if not keys or not self.store or keys[0] not in self.store.entries:
            self.key_var.set("")
            self.info_var.set("")
            self.view_var.set("auto")
            self.value_text.configure(state="disabled")
            return
        key = keys[0]
        entry = self.store.entries[key]
        choice = self.view_as(key)
        kind, text = mm.show(entry.raw, choice, pretty=True)
        self.key_var.set(key)
        self.view_var.set(choice)
        info = [kind + (" (guessed)" if choice == "auto" else " (your choice)"), f"{len(entry.raw)} bytes"]
        if entry.writes > 1:
            info.append(f"written {entry.writes}×")
        if kind == "int":
            try:
                hint = mm.time_hint(mm.as_int(entry.raw))
            except ValueError:
                hint = ""
            if hint:
                info.append(hint)
        if entry.expire is not None:
            info.append("never expires" if entry.expire == 0 else
                        "expires " + datetime.fromtimestamp(entry.expire).strftime("%Y-%m-%d %H:%M:%S"))
        self.info_var.set(" · ".join(info))
        self.value_text.insert("1.0", text)
        self.value_text.configure(state="disabled")
        for k, value in mm.readings(entry.raw):
            if k == "hex":
                continue
            self.read_tree.insert("", "end", values=(k, mm.fmt(k, value).replace("\n", " ")[:PREVIEW_CHARS]))

    def _reading_clicked(self, _event):
        sel = self.read_tree.selection()
        if sel:
            self.set_view_as(self.read_tree.item(sel[0], "values")[0])

    def set_view_as(self, kind):
        keys = self._selected_keys()
        if not keys:
            return
        for key in keys:
            if kind == "auto":
                self.settings.view_as.pop(self._view_key(key), None)
            else:
                self.settings.view_as[self._view_key(key)] = kind
        self.settings.save()
        self.fill_rows()
        self.show_detail()

    # ---------- Editing ----------
    def _row_double_click(self, event):
        row = self.tree.identify_row(event.y)
        if row:
            self.open_editor(self.rows[int(row)])

    def _edit_selected(self):
        keys = self._selected_keys()
        if keys:
            self.open_editor(keys[0])

    def open_editor(self, key):
        """Edit key's value, or add a new key when key is None."""
        if not self.store or self._busy:
            return
        if key is None:
            kind, text = "string", ""
        else:
            raw = self.store.entries[key].raw
            kind = self.view_as(key)
            kind = mm.guess(raw) if kind == "auto" else kind
            text = mm.edit_text(raw, kind)
        self._dialog = EditDialog(self, key, kind, text, self._save_from_editor)

    def _save_from_editor(self, key, kind, raw, is_new):
        """Called by EditDialog. Returns an error message to show, or None when accepted."""
        if is_new and key in self.store.entries:
            return f"Key {key!r} already exists. Edit it instead."
        old = self.store.entries.get(key)
        if old and old.raw == raw:
            return "The value hasn't changed."
        shown = mm.show(raw, kind)[1]
        what = (f"Add {key!r} = {shown[:200]} ({kind})" if is_new else
                f"Set {key!r} = {shown[:200]} ({kind})\nwas {mm.show(old.raw, self.view_as(key))[1][:200]}")
        if not self.write([(key, raw)], what, parent=self._dialog):
            return ""  # cancelled: keep the dialog open
        # Remember the type if it isn't what would be guessed.
        vk = self._view_key(key)
        if mm.guess(raw) == kind:
            self.settings.view_as.pop(vk, None)
        else:
            self.settings.view_as[vk] = kind
        self.settings.save()
        return None

    def delete_keys(self):
        keys = self._selected_keys()
        if not keys or self._busy:
            return
        listed = "\n".join(f"  {k}" for k in keys[:15]) + (f"\n  … and {len(keys) - 15} more" if len(keys) > 15 else "")
        self.write([(k, None) for k in keys], f"Delete {len(keys)} key(s):\n{listed}")

    def write(self, changes, what, parent=None):
        """Ask, then save changes [(key, raw or None)] to the device. Returns False if cancelled."""
        path = self._store_path()
        if not (self.store and path):
            return False
        pkg = self.pkg_var.get().strip()
        if not messagebox.askyesno(
                "Write to the device?",
                f"{what}\n\nStore: {self.store_var.get()}\n\n{pkg} will be force-stopped first. "
                "A backup is kept (Undo last write).", parent=parent or self):
            return False
        device, access = self.device, self.access
        crypt_key = self.crypt_keys.get((pkg, path))

        def work():
            device.force_stop(access, pkg)
            # Read again: the app may have written since the store was shown.
            data = device.read_file(access, pkg, path)
            meta = device.read_file(access, pkg, path + ".crc")
            store = mm.parse_store(data, meta, crypt_key)
            mm.apply_changes(store, changes)
            new_data, new_meta = mm.build_files(store, data, meta, crypt_key)
            check = mm.parse_store(new_data, new_meta, crypt_key)
            if ({k: e.raw for k, e in check.entries.items()} != {k: e.raw for k, e in store.entries.items()}
                    or check.crc_ok is False):
                raise mm.MMKVError("The new file didn't read back correctly; nothing was written")
            backup = self._save_backup(device.serial, pkg, path, data, meta)
            device.write_file(access, pkg, path, new_data)
            device.write_file(access, pkg, path + ".crc", new_meta)
            return (data, meta), backup

        def done(result):
            (data, meta), backup = result
            self.backups[(device.serial, pkg, path)] = (data, meta)
            self.load_store(force=True, note=f"Saved, {pkg} stopped, backup in {os.path.relpath(backup, HERE)}")
        self.run_bg(work, done, "Writing to the device…")
        return True

    def _save_backup(self, serial, pkg, path, data, meta):
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        name = f"{os.path.basename(path)}_{stamp}"
        folder = os.path.join(BACKUP_DIR, serial.replace(":", "_"), pkg)
        os.makedirs(folder, exist_ok=True)
        for suffix, content in (("", data), (".crc", meta)):
            with open(os.path.join(folder, name + suffix), "wb") as fh:
                fh.write(content)
        return os.path.join(folder, name)

    def _backup_key(self):
        path = self._store_path()
        if not (self.device and path):
            return None
        return self.device.serial, self.pkg_var.get().strip(), path

    def _update_undo(self):
        self.undo_btn.state(["!disabled"] if self._backup_key() in self.backups else ["disabled"])

    def undo_write(self):
        key = self._backup_key()
        if key not in self.backups or self._busy:
            return
        _, pkg, path = key
        if not messagebox.askyesno("Undo last write?",
                                   f"Put back {self.store_var.get()} as it was before the last write?\n"
                                   f"Changes the app made since then are lost.\n\n{pkg} will be force-stopped first."):
            return
        data, meta = self.backups[key]
        device, access = self.device, self.access

        def work():
            device.force_stop(access, pkg)
            device.write_file(access, pkg, path, data)
            device.write_file(access, pkg, path + ".crc", meta)

        def done(_):
            del self.backups[key]
            self.load_store(force=True, note=f"Restored the previous version, {pkg} stopped")
        self.run_bg(work, done, "Restoring…")

    # ---------- Export ----------
    def export_json(self):
        if not self.store:
            return
        name = os.path.basename(self.store_var.get()) or "mmkv"
        path = filedialog.asksaveasfilename(defaultextension=".json", initialfile=f"{name}.json",
                                            filetypes=[("JSON", "*.json")])
        if not path:
            return
        data = {k: mm.json_value(e.raw, self.view_as(k)) for k, e in self.store.entries.items()}
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        self.status(f"Exported {len(data)} keys to {path}")


if __name__ == "__main__":
    App().mainloop()

#!/usr/bin/env python3
"""Room SQL GUI - run SQL against an Android app's Room/SQLite database over adb.

How it works:
  1. Pick a device and a package; the app lists the databases in /data/user/<id>/<pkg>/databases.
  2. The database (plus its -wal file) is copied to a temp folder and the SQL runs locally
     with Python's sqlite3. The copy is reused until the file on the device changes.
  3. If the SQL changes data, the app is force-stopped first, then the updated database
     is pushed back to the device.

Access needs either a debuggable app (run-as) or a rooted device/emulator (su).
"""

import csv
import json
import os
import shlex
import shutil
import sqlite3
import tempfile
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from adb_common import AdbError, DeviceBase, list_devices
from sql_editor import (SqlAutocomplete, SqlHighlighter, is_write, parse_value,
                        single_table_select, split_statements, sql_literal)

HERE = os.path.dirname(os.path.abspath(__file__))
HISTORY_FILE = os.path.join(HERE, ".room_sql_history.json")
MAX_ROWS = 5000
MAX_HISTORY = 300


class Device(DeviceBase):
    """adb access to an app's private files, via run-as (debuggable app) or su (root)."""

    @staticmethod
    def data_dir(access, pkg):
        return f"/data/user/{access[1]}/{pkg}"

    @staticmethod
    def wrap(access, pkg, inner):
        """Wrap a shell command so it can read the app's files. access is (mode, user_id)."""
        mode, user = access
        if mode == "run-as":
            user_flag = f" --user {user}" if user else ""
            return f"run-as {shlex.quote(pkg)}{user_flag} sh -c {shlex.quote(inner)}"
        if mode == "su":
            return f"su -c {shlex.quote(inner)}"
        if mode == "su0":  # emulator-style su
            return f"su 0 sh -c {shlex.quote(inner)}"
        raise ValueError(mode)

    def detect_access(self, pkg):
        """Return the first (mode, user) that can read the app's data folder."""
        errors = []
        for user in self.users():
            for mode in ("run-as", "su", "su0"):
                access = (mode, user)
                cmd = f"ls {shlex.quote(self.data_dir(access, pkg))} >/dev/null && echo __OK__"
                _, out, err = self.shell(self.wrap(access, pkg, cmd))
                if "__OK__" in out:
                    return access
                errors.append(f"user {user} {mode}: {(err or out).strip()[:150]}")
        raise AdbError("Can't access the app's data.\n"
                       "The app must be debuggable (run-as) or the device rooted (su).\n\n"
                       + "\n".join(errors))

    def list_databases(self, access, pkg):
        db_dir = self.data_dir(access, pkg) + "/databases"
        _, out, _ = self.shell(self.wrap(access, pkg, f"ls -1 {shlex.quote(db_dir)} 2>/dev/null"))
        names = [n.strip() for n in out.splitlines() if n.strip()]
        skip = ("-wal", "-shm", "-journal")
        return sorted(n for n in names if not n.endswith(skip))

    def remote_path(self, access, pkg, name):
        return f"{self.data_dir(access, pkg)}/databases/{name}"

    def signature(self, access, pkg, name):
        """Size + modification time of the db and its -wal; changes whenever the app writes."""
        remote = shlex.quote(self.remote_path(access, pkg, name))
        _, out, _ = self.shell(self.wrap(access, pkg, f"stat -c '%n %s %y' {remote} {remote}-wal 2>/dev/null"))
        return out.strip()

    def pull_db(self, access, pkg, name, dest_dir):
        """Copy db + wal into dest_dir. Returns the local db path."""
        remote = self.remote_path(access, pkg, name)
        os.makedirs(dest_dir, exist_ok=True)
        for f in os.listdir(dest_dir):
            os.remove(os.path.join(dest_dir, f))
        local = os.path.join(dest_dir, name)
        # Skip -shm: it is a live shared-memory index; SQLite rebuilds it from the WAL.
        for suffix in ("", "-wal"):
            data = self.exec_out(self.wrap(access, pkg, f"cat {shlex.quote(remote + suffix)} 2>/dev/null"))
            if suffix == "" and not data:
                raise AdbError(f"Could not read {remote}")
            if data:
                with open(local + suffix, "wb") as fh:
                    fh.write(data)
        return local

    def push_db(self, access, pkg, name, local):
        remote = self.remote_path(access, pkg, name)
        tmp = f"/data/local/tmp/roomsql_{os.getpid()}.db"
        q = shlex.quote
        # Writing into the existing file keeps its owner and permissions.
        inner = f"cat {q(tmp)} > {q(remote)} && rm -f {q(remote + '-wal')} {q(remote + '-shm')} && echo __OK__"
        if self.run("push", local, tmp).returncode == 0:
            self.shell(f"chmod 644 {q(tmp)}")
            _, out, _ = self.shell(self.wrap(access, pkg, inner))
            self.shell(f"rm -f {q(tmp)}")
            if "__OK__" in out:
                return
        # Fallback: stream the file through stdin.
        with open(local, "rb") as fh:
            data = fh.read()
        inner = f"cat > {q(remote)} && rm -f {q(remote + '-wal')} {q(remote + '-shm')}"
        proc = self.run("exec-in", self.wrap(access, pkg, inner), data=data)
        if proc.returncode != 0:
            raise AdbError("Failed to push the database back:\n" + proc.stderr.decode(errors="replace"))

    def force_stop(self, access, pkg):
        self.shell(f"am force-stop --user {access[1]} {shlex.quote(pkg)}")


class History:
    """Past queries, saved to a file next to the app. ⌘↑/⌘↓ walk through them."""

    def __init__(self, path):
        self.path = path
        try:
            with open(path, encoding="utf-8") as fh:
                self.items = [s for s in json.load(fh) if isinstance(s, str)]
        except (OSError, ValueError):
            self.items = []
        self.pos = None  # index while browsing, None when editing a new query
        self.draft = ""

    def add(self, sql):
        sql = sql.strip()
        if not sql:
            return
        if sql in self.items:
            self.items.remove(sql)
        self.items.append(sql)
        del self.items[:-MAX_HISTORY]
        self.pos = None
        try:
            with open(self.path, "w", encoding="utf-8") as fh:
                json.dump(self.items, fh, indent=1)
        except OSError:
            pass

    def step(self, direction, current):
        """direction -1 = older, +1 = newer. Returns the text to show, or None."""
        if not self.items:
            return None
        if self.pos is None:
            if direction > 0:
                return None
            self.draft = current
            self.pos = len(self.items)
        self.pos += direction
        if self.pos >= len(self.items):
            self.pos = None
            return self.draft
        self.pos = max(0, self.pos)
        return self.items[self.pos]


def sort_key(value):
    """Sort NULLs first, then numbers, text, blobs - without comparing mixed types."""
    if value is None:
        return (0, 0)
    if isinstance(value, (int, float)):
        return (1, value)
    if isinstance(value, str):
        return (2, value.lower())
    return (3, value)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Room SQL")
        self.geometry("1150x740")
        self.minsize(800, 500)
        self.tmp_dir = tempfile.mkdtemp(prefix="roomsql_")
        self.device = None
        self.devices = []
        self.access = None
        self.all_packages = []
        self.cache = {}         # key, signature and local path of the pulled database
        self.col_types = {}     # table -> {column: declared type}
        self.history = History(HISTORY_FILE)
        self.result = None      # columns, rows, rowids, table of the shown result
        self.sort_state = (None, False)
        self._editor = None
        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(100, self.refresh_devices)

    # ---------- UI ----------
    def _build_ui(self):
        top = ttk.Frame(self, padding=8)
        top.pack(fill="x")

        ttk.Label(top, text="Device").grid(row=0, column=0, sticky="w")
        self.device_var = tk.StringVar()
        self.device_cb = ttk.Combobox(top, textvariable=self.device_var, state="readonly", width=28)
        self.device_cb.grid(row=0, column=1, sticky="w", padx=4)
        self.device_cb.bind("<<ComboboxSelected>>", lambda e: self.on_device_selected())
        ttk.Button(top, text="↻", width=3, command=self.refresh_devices).grid(row=0, column=2)

        ttk.Label(top, text="Package").grid(row=0, column=3, sticky="w", padx=(12, 0))
        self.pkg_var = tk.StringVar()
        self.pkg_cb = ttk.Combobox(top, textvariable=self.pkg_var, width=40)
        self.pkg_cb.grid(row=0, column=4, sticky="we", padx=4)
        self.pkg_cb.bind("<KeyRelease>", self._filter_packages)
        self.pkg_cb.bind("<<ComboboxSelected>>", lambda e: self.on_package_selected())
        self.pkg_cb.bind("<Return>", lambda e: self.on_package_selected())
        self.system_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="System apps", variable=self.system_var,
                        command=self.load_packages).grid(row=0, column=5, padx=4)

        ttk.Label(top, text="Database").grid(row=0, column=6, sticky="w", padx=(12, 0))
        self.db_var = tk.StringVar()
        self.db_cb = ttk.Combobox(top, textvariable=self.db_var, state="readonly", width=22)
        self.db_cb.grid(row=0, column=7, sticky="w", padx=4)
        self.db_cb.bind("<<ComboboxSelected>>", lambda e: self.load_tables())
        ttk.Button(top, text="⟳ Reload DB", command=lambda: self.load_tables(force=True)).grid(row=0, column=8)
        top.columnconfigure(4, weight=1)

        main = ttk.PanedWindow(self, orient="horizontal")
        main.pack(fill="both", expand=True, padx=8)

        # Tables sidebar
        side = ttk.Frame(main)
        ttk.Label(side, text="Tables (double-click)").pack(anchor="w")
        self.tables_lb = tk.Listbox(side, width=26, exportselection=False)
        self.tables_lb.pack(fill="both", expand=True)
        self.tables_lb.bind("<Double-Button-1>", self._table_clicked)
        main.add(side, weight=0)

        right = ttk.PanedWindow(main, orient="vertical")
        main.add(right, weight=1)

        # SQL editor
        editor = ttk.Frame(right)
        bar = ttk.Frame(editor)
        bar.pack(fill="x")
        ttk.Label(bar, text="SQL").pack(side="left")
        ttk.Label(bar, text="⌘↵ run (selection only, if any) · Ctrl+Space suggest · ⌘↑/⌘↓ history",
                  foreground="gray").pack(side="left", padx=12)
        ttk.Button(bar, text="Export CSV", command=self.export_csv).pack(side="right")
        self.history_btn = ttk.Menubutton(bar, text="History ▾")
        self.history_menu = tk.Menu(self.history_btn, tearoff=0, postcommand=self._fill_history_menu)
        self.history_btn["menu"] = self.history_menu
        self.history_btn.pack(side="right", padx=4)
        self.run_btn = ttk.Button(bar, text="▶ Execute", command=self.execute)
        self.run_btn.pack(side="right")
        self.sql_text = tk.Text(editor, height=8, font=("Menlo", 13), undo=True, wrap="none")
        self.sql_text.pack(fill="both", expand=True)
        self.autocomplete = SqlAutocomplete(self.sql_text)
        self.highlighter = SqlHighlighter(self.sql_text, lambda: self.autocomplete.schema)
        for mod in ("Command", "Control"):
            self.sql_text.bind(f"<{mod}-Return>", lambda e: (self.autocomplete.hide(), self.execute(), "break")[2])
            self.sql_text.bind(f"<{mod}-Up>", lambda e: self._history_step(-1))
            self.sql_text.bind(f"<{mod}-Down>", lambda e: self._history_step(1))
        right.add(editor, weight=1)

        # Results grid
        results = ttk.Frame(right)
        self.tree = ttk.Treeview(results, show="headings")
        vsb = ttk.Scrollbar(results, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(results, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        results.rowconfigure(0, weight=1)
        results.columnconfigure(0, weight=1)
        self.tree.bind("<Double-Button-1>", self._cell_double_click)
        for seq in ("<Button-2>", "<Button-3>", "<Control-Button-1>"):
            self.tree.bind(seq, self._cell_menu)
        for mod in ("Command", "Control"):
            self.tree.bind(f"<{mod}-c>", lambda e: self.copy_rows())
        right.add(results, weight=3)

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self, textvariable=self.status_var, anchor="w", padding=(8, 4),
                  relief="sunken").pack(fill="x", side="bottom")

    def status(self, msg):
        self.status_var.set(msg)

    def run_bg(self, work, done, busy_msg):
        """Run work() in a thread, then done(result) on the UI thread."""
        self.autocomplete.hide()
        self._close_editor()
        self.status(busy_msg)
        self.config(cursor="watch")
        self.run_btn.state(["disabled"])

        def target():
            try:
                result, error = work(), None
            except Exception as exc:  # noqa: BLE001 - show any failure to the user
                result, error = None, exc
            self.after(0, finish, result, error)

        def finish(result, error):
            self.config(cursor="")
            self.run_btn.state(["!disabled"])
            if error:
                self.status(f"Error: {error}".splitlines()[0])
                messagebox.showerror("Error", str(error))
            else:
                done(result)

        threading.Thread(target=target, daemon=True).start()

    # ---------- Device / package / db selection ----------
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
        self.cache = {}
        self.load_packages()

    def load_packages(self):
        if not self.device:
            return
        flag = "" if self.system_var.get() else " -3"

        def work():
            _, out, _ = self.device.shell("pm list packages" + flag)
            return sorted(l.split(":", 1)[1].strip() for l in out.splitlines() if l.startswith("package:"))

        def done(pkgs):
            self.all_packages = pkgs
            self.pkg_cb["values"] = pkgs
            self.status(f"{len(pkgs)} packages. Type to filter, then pick one.")
        self.run_bg(work, done, "Loading packages…")

    def _filter_packages(self, event):
        if event.keysym in ("Return", "Up", "Down", "Escape"):
            return
        text = self.pkg_var.get().lower()
        self.pkg_cb["values"] = [p for p in self.all_packages if text in p.lower()]

    def on_package_selected(self):
        pkg = self.pkg_var.get().strip()
        if not self.device or not pkg:
            return

        def work():
            access = self.device.detect_access(pkg)
            return access, self.device.list_databases(access, pkg)

        def done(result):
            self.access, dbs = result
            self.db_cb["values"] = dbs
            self.tables_lb.delete(0, "end")
            if dbs:
                self.db_cb.current(0)
                self.load_tables()
            else:
                self.db_var.set("")
                self.status(f"No databases found for {pkg}")
        self.run_bg(work, done, f"Checking access to {pkg}…")

    def load_tables(self, force=False, keep_status=False):
        if not (self.device and self.access and self.db_var.get()):
            return
        ctx = self._ctx()

        def work():
            local, note = self._local_db(ctx, force)
            conn = sqlite3.connect(local)
            try:
                tables = [r[0] for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type IN ('table','view') ORDER BY name")]
                info = {t: [(c[1], c[2]) for c in conn.execute(f'PRAGMA table_info("{t}")')] for t in tables}
                return info, note
            finally:
                conn.close()

        def done(result):
            info, note = result
            self.autocomplete.schema = {t: [c for c, _ in cols] for t, cols in info.items()}
            self.col_types = {t: {c.lower(): ty for c, ty in cols} for t, cols in info.items()}
            self.highlighter.highlight()  # table names may now be known
            self.tables_lb.delete(0, "end")
            for t in info:
                self.tables_lb.insert("end", t)
            if not keep_status:
                self.status(f"{self.db_var.get()}: {len(info)} tables · {note} · "
                            f"access: {self.access[0]}, user {self.access[1]}")
        self.run_bg(work, done, "Loading database…")

    def _table_clicked(self, _event):
        sel = self.tables_lb.curselection()
        if not sel:
            return
        table = self.tables_lb.get(sel[0])
        self.sql_text.delete("1.0", "end")
        self.sql_text.insert("1.0", f'SELECT * FROM "{table}" LIMIT 100;')
        self.execute()

    def _ctx(self):
        """What a worker thread needs, read on the UI thread (Tk isn't thread safe)."""
        return self.device, self.access, self.pkg_var.get().strip(), self.db_var.get()

    def _local_db(self, ctx, force=False):
        """Path of an up-to-date local copy; only pulls when the device file changed.
        Runs in a worker thread. Returns (path, note for the status bar)."""
        device, access, pkg, name = ctx
        key = (device.serial, access, pkg, name)
        sig = device.signature(access, pkg, name)
        c = self.cache
        if (not force and c.get("key") == key and c.get("sig") == sig and sig
                and os.path.exists(c.get("path", ""))):
            return c["path"], "unchanged on device, using local copy"
        start = time.time()
        dest = os.path.join(self.tmp_dir, f"{key[0]}_{pkg}_{name}".replace(os.sep, "_"))
        local = device.pull_db(access, pkg, name, dest)
        # Fold the WAL into the copy so it is one self-contained file.
        conn = sqlite3.connect(local)
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.close()
        self.cache = {"key": key, "sig": sig, "path": local}
        size = os.path.getsize(local) / 1024 / 1024
        return local, f"pulled {size:.1f} MB in {time.time() - start:.1f}s"

    # ---------- Executing SQL ----------
    def execute(self):
        try:
            sql = self.sql_text.get("sel.first", "sel.last").strip()
            only_selection = True
        except tk.TclError:  # nothing selected
            sql = self.sql_text.get("1.0", "end").strip()
            only_selection = False
        if not sql:
            return
        if not (self.device and self.access and self.db_var.get()):
            messagebox.showwarning("Not ready", "Select a device, package and database first.")
            return
        self.history.add(sql)
        statements = split_statements(sql)
        writes = any(is_write(s) for s in statements)
        pkg = self.pkg_var.get().strip()
        if writes and not messagebox.askyesno(
                "Modify database?",
                f"This SQL may change data.\n\n{pkg} will be force-stopped and the database "
                "on the device will be overwritten. Continue?"):
            return

        def run_statements(conn):
            columns, rows, rowids, table, changed = [], [], None, None, 0
            for stmt in statements:
                cur, rowids, table = None, None, None
                single = single_table_select(stmt)
                if single:
                    try:  # same query plus the rowid, so cells can be edited
                        cur = conn.execute(single[1])
                        table = single[0]
                    except sqlite3.Error:
                        cur = None  # e.g. a WITHOUT ROWID table or a view
                if cur is None:
                    cur = conn.execute(stmt)
                if cur.description:
                    columns = [d[0] for d in cur.description]
                    rows = cur.fetchmany(MAX_ROWS + 1)
                    if table:
                        rowids = [r[0] for r in rows]
                        columns, rows = columns[1:], [r[1:] for r in rows]
                elif cur.rowcount > 0:
                    changed += cur.rowcount
            return columns, rows, rowids, table, changed

        ctx = self._ctx()

        def work():
            if writes:
                result = self._write(ctx, run_statements)
                return (*result, "saved to device")
            local, note = self._local_db(ctx)
            conn = sqlite3.connect(local)
            try:
                conn.execute("PRAGMA query_only = ON")  # a read must never change the local copy
                return (*run_statements(conn), note)
            finally:
                conn.close()

        def done(result):
            columns, rows, rowids, table, changed, note = result
            truncated = len(rows) > MAX_ROWS
            rows = rows[:MAX_ROWS]
            self.show_results(columns, rows, rowids[:MAX_ROWS] if rowids else None, table)
            parts = ["selection only"] if only_selection else []
            if columns:
                parts.append(f"{len(rows)} rows" + (f" (first {MAX_ROWS} shown)" if truncated else ""))
                if table and rows:
                    parts.append("double-click a cell to edit")
            if changed:
                parts.append(f"{changed} rows affected")
            parts.append(note)
            self.status(" · ".join(parts))
            if writes:
                self.load_tables(keep_status=True)  # the schema may have changed
        self.run_bg(work, done, "Running…")

    def _write(self, ctx, apply):
        """Force-stop the app, pull a fresh copy, apply(conn), push it back.
        Runs in a worker thread; returns whatever apply returns."""
        device, access, pkg, name = ctx
        device.force_stop(access, pkg)
        local, _ = self._local_db(ctx, force=True)
        conn = sqlite3.connect(local)
        try:
            result = apply(conn)
            conn.commit()
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            conn.close()
        device.push_db(access, pkg, name, local)
        # The local copy now matches the device, so the next read needn't pull again.
        self.cache["sig"] = device.signature(access, pkg, name)
        return result

    # ---------- Results ----------
    def show_results(self, columns, rows, rowids=None, table=None):
        self._close_editor()
        self.result = {"columns": columns, "rows": [list(r) for r in rows],
                       "rowids": list(rowids) if rowids else None, "table": table}
        self.sort_state = (None, False)
        self.tree.delete(*self.tree.get_children())
        ids = [f"c{i}" for i in range(len(columns))]  # names can repeat, ids can't
        self.tree["columns"] = ids
        for i, (cid, name) in enumerate(zip(ids, columns)):
            self.tree.heading(cid, text=self._heading(i), command=lambda i=i: self.sort_by(i))
            self.tree.column(cid, width=150, minwidth=60, stretch=False)
        self._fill_rows()

    def _heading(self, i):
        name = self.result["columns"][i]
        col, desc = self.sort_state
        arrow = (" ▼" if desc else " ▲") if col == i else ""
        mark = " ✎" if self._editable_column(i) else ""
        return f"{name}{mark}{arrow}"

    def _fill_rows(self):
        self.tree.delete(*self.tree.get_children())
        for idx, row in enumerate(self.result["rows"]):
            self.tree.insert("", "end", iid=str(idx), values=[self._fmt(v) for v in row])

    def sort_by(self, col):
        if not self.result:
            return
        prev, desc = self.sort_state
        desc = not desc if prev == col else False
        self.sort_state = (col, desc)
        order = sorted(range(len(self.result["rows"])),
                       key=lambda i: sort_key(self.result["rows"][i][col]), reverse=desc)
        self.result["rows"] = [self.result["rows"][i] for i in order]
        if self.result["rowids"]:
            self.result["rowids"] = [self.result["rowids"][i] for i in order]
        for i in range(len(self.result["columns"])):
            self.tree.heading(f"c{i}", text=self._heading(i))
        self._fill_rows()

    @staticmethod
    def _fmt(value):
        if value is None:
            return "NULL"
        if isinstance(value, bytes):
            return f"<BLOB {len(value)} bytes>"
        return str(value).replace("\n", "⏎ ")

    def _editable_column(self, i):
        r = self.result
        if not r or not r["table"] or not r["rowids"]:
            return False
        return r["columns"][i].lower() in self.col_types.get(r["table"], {})

    def _cell_at(self, event):
        if self.tree.identify_region(event.x, event.y) != "cell":
            return None
        item = self.tree.identify_row(event.y)
        col = self.tree.identify_column(event.x)  # "#1", "#2", …
        if not item or not col:
            return None
        return int(item), int(col[1:]) - 1

    def _cell_double_click(self, event):
        cell = self._cell_at(event)
        if not cell:
            return
        row, col = cell
        value = self.result["rows"][row][col]
        if self._editable_column(col) and not isinstance(value, bytes):
            self._open_editor(row, col)
        else:
            self.view_value(row, col)

    def _cell_menu(self, event):
        cell = self._cell_at(event)
        if not cell:
            return
        row, col = cell
        self.tree.selection_set(str(row))
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Copy cell", command=lambda: self._to_clipboard(self._raw(row, col)))
        menu.add_command(label="Copy row(s)", command=self.copy_rows)
        menu.add_command(label="View value…", command=lambda: self.view_value(row, col))
        if self._editable_column(col) and not isinstance(self.result["rows"][row][col], bytes):
            menu.add_separator()
            menu.add_command(label="Edit cell…", command=lambda: self._open_editor(row, col))
            menu.add_command(label="Set to NULL", command=lambda: self.save_cell(row, col, None))
        menu.tk_popup(event.x_root, event.y_root)

    def _raw(self, row, col):
        v = self.result["rows"][row][col]
        if v is None:
            return "NULL"
        return v.hex() if isinstance(v, bytes) else str(v)

    def copy_rows(self):
        if not self.result:
            return
        rows = [int(i) for i in self.tree.selection()]
        lines = ["\t".join(self.result["columns"])]
        lines += ["\t".join(self._raw(r, c) for c in range(len(self.result["columns"]))) for r in rows]
        self._to_clipboard("\n".join(lines))
        self.status(f"Copied {len(rows)} row(s)")

    def _to_clipboard(self, text):
        self.clipboard_clear()
        self.clipboard_append(text)

    def view_value(self, row, col):
        value = self.result["rows"][row][col]
        text = self._raw(row, col)
        if isinstance(value, str) and value.lstrip()[:1] in ("{", "["):
            try:
                text = json.dumps(json.loads(value), indent=2, ensure_ascii=False)
            except ValueError:
                pass
        win = tk.Toplevel(self)
        win.title(f"{self.result['columns'][col]} (row {row + 1})")
        win.geometry("700x500")
        bar = ttk.Frame(win, padding=4)
        bar.pack(fill="x")
        kind = "BLOB (hex)" if isinstance(value, bytes) else type(value).__name__ if value is not None else "NULL"
        ttk.Label(bar, text=f"{kind} · {len(text)} chars").pack(side="left")
        ttk.Button(bar, text="Copy", command=lambda: self._to_clipboard(text)).pack(side="right")
        box = tk.Text(win, wrap="word", font=("Menlo", 12))
        box.insert("1.0", text)
        box.configure(state="disabled")
        box.pack(fill="both", expand=True)

    def _open_editor(self, row, col):
        self._close_editor()
        self.tree.see(str(row))
        self.update_idletasks()
        bbox = self.tree.bbox(str(row), f"c{col}")
        if not bbox:
            return
        value = self.result["rows"][row][col]
        var = tk.StringVar(value="" if value is None else str(value))
        entry = ttk.Entry(self.tree, textvariable=var)
        entry.place(x=bbox[0], y=bbox[1], width=max(bbox[2], 200), height=bbox[3])
        entry.focus_set()
        entry.select_range(0, "end")
        self._editor = entry

        def commit(_e=None):
            text = var.get()
            self._close_editor()
            if value is None and text == "":
                return
            if text == ("" if value is None else str(value)):
                return
            table = self.result["table"]
            ctype = self.col_types.get(table, {}).get(self.result["columns"][col].lower(), "")
            self.save_cell(row, col, parse_value(text, ctype))

        entry.bind("<Return>", commit)
        entry.bind("<KP_Enter>", commit)
        entry.bind("<Escape>", lambda e: self._close_editor())
        entry.bind("<FocusOut>", lambda e: self._close_editor())

    def _close_editor(self):
        if self._editor is not None:
            self._editor.destroy()
            self._editor = None

    def save_cell(self, row, col, new_value):
        table = self.result["table"]
        column = self.result["columns"][col]
        rowid = self.result["rowids"][row]
        preview = f'UPDATE "{table}" SET "{column}" = {sql_literal(new_value)} WHERE rowid = {rowid};'
        pkg = self.pkg_var.get().strip()
        if not messagebox.askyesno("Save change?", f"{preview}\n\n{pkg} will be force-stopped "
                                   "and the database on the device will be overwritten."):
            return

        def apply(conn):
            cur = conn.execute(f'UPDATE "{table}" SET "{column}" = ? WHERE rowid = ?', (new_value, rowid))
            if cur.rowcount != 1:
                raise AdbError("That row no longer exists on the device (the app may have deleted it). "
                               "Nothing was changed; run the query again.")
            return conn.execute(f'SELECT "{column}" FROM "{table}" WHERE rowid = ?', (rowid,)).fetchone()[0]

        def done(stored):
            self.result["rows"][row][col] = stored
            self.tree.item(str(row), values=[self._fmt(v) for v in self.result["rows"][row]])
            self.history.add(preview)
            self.status(f"Saved: {preview}")
        ctx = self._ctx()
        self.run_bg(lambda: self._write(ctx, apply), done, "Saving…")

    def export_csv(self):
        if not self.result or not self.result["columns"]:
            messagebox.showinfo("Nothing to export", "Run a query that returns rows first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if path:
            with open(path, "w", newline="", encoding="utf-8") as fh:
                writer = csv.writer(fh)
                writer.writerow(self.result["columns"])
                writer.writerows(self.result["rows"])
            self.status(f"Exported {len(self.result['rows'])} rows to {path}")

    # ---------- History ----------
    def _history_step(self, direction):
        text = self.history.step(direction, self.sql_text.get("1.0", "end-1c"))
        if text is not None:
            self.autocomplete.hide()
            self.sql_text.delete("1.0", "end")
            self.sql_text.insert("1.0", text)
        return "break"

    def _fill_history_menu(self):
        self.history_menu.delete(0, "end")
        recent = list(reversed(self.history.items[-25:]))
        if not recent:
            self.history_menu.add_command(label="(no queries yet)", state="disabled")
        for sql in recent:
            label = " ".join(sql.split())
            label = label if len(label) <= 90 else label[:87] + "…"
            self.history_menu.add_command(label=label, command=lambda s=sql: self._load_query(s))

    def _load_query(self, sql):
        self.sql_text.delete("1.0", "end")
        self.sql_text.insert("1.0", sql)
        self.sql_text.focus_set()

    def _on_close(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)
        self.destroy()


if __name__ == "__main__":
    App().mainloop()

#!/usr/bin/env python3
"""Net Inspector - see every HTTP(S) call an Android device/emulator makes.

How it works:
  1. Starts mitmproxy (mitmdump) on this computer.
  2. `adb reverse` makes the proxy reachable on the device at 127.0.0.1:<port>, and the
     device's global HTTP proxy is pointed at it, so traffic from all apps goes through it.
  3. Optionally installs mitmproxy's certificate as a *system* certificate (root needed),
     so HTTPS can be decrypted. It lives in memory only and is gone after a reboot.
  4. While capturing, the device's connection table is polled to work out which app
     opened each connection to the proxy (a best guess based on timing).
  5. Stop (or closing the window) switches the device proxy off again.

If this app is killed and the device loses internet, run:
    adb shell settings put global http_proxy :0
"""

import atexit
import base64
import io
import json
import os
import queue
import shutil
import signal
import socket
import subprocess
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from adb_common import DeviceBase, list_devices
from net_model import (SHOW_OPTIONS, Flow, body_as_text, decode_body, from_har, header,
                       parse_proc_net, pick_device_conn, to_har, uid_label)

try:
    from PIL import Image, ImageTk  # optional: JPEG/WebP previews (PNG/GIF work without it)
except ImportError:
    Image = ImageTk = None

HERE = os.path.dirname(os.path.abspath(__file__))
CONFDIR = os.path.join(HERE, ".mitmproxy")
CA_PEM = os.path.join(CONFDIR, "mitmproxy-ca-cert.pem")
ADDON = os.path.join(HERE, "net_capture_addon.py")
SETTINGS_FILE = os.path.join(HERE, ".net_inspector.json")
MAX_FLOWS = 5000        # oldest calls are dropped beyond this, to keep memory in check
POLL_SECONDS = 0.25     # how often the device's connection table is read
APP_WAIT = 1.5          # seconds to wait for device-side info before settling on an app
ALL_APPS = "All apps"


def find_mitmdump():
    local = os.path.join(HERE, ".venv", "bin", "mitmdump")
    return local if os.path.exists(local) else shutil.which("mitmdump")


# Installs the CA into the system store in memory (tmpfs). On Android 14+ the store lives
# in the conscrypt APEX, so it is bind-mounted into zygote and every running app too.
CERT_SCRIPT = r"""
NAME={name}
CERT=/data/local/tmp/$NAME
APEX=/apex/com.android.conscrypt/cacerts
SYS=/system/etc/security/cacerts
ZYGOTES=$(pidof zygote zygote64)
if [ -d $APEX ]; then
  for Z in $ZYGOTES; do
    nsenter --mount=/proc/$Z/ns/mnt -- ls $APEX/$NAME >/dev/null 2>&1 && {{ echo __ALREADY__; exit 0; }}
  done
  SRC=$APEX
else
  [ -f $SYS/$NAME ] && {{ echo __ALREADY__; exit 0; }}
  SRC=$SYS
fi
TMP=/data/local/tmp/netinsp-ca
rm -rf $TMP && mkdir -p -m 700 $TMP && cp $SRC/* $TMP/ && cp $CERT $TMP/ || exit 1
mount -t tmpfs tmpfs $SYS || exit 1
cp $TMP/* $SYS/ && chown root:root $SYS/* && chmod 644 $SYS/* && chcon u:object_r:system_file:s0 $SYS/*
rm -rf $TMP
if [ "$SRC" = "$APEX" ]; then
  for Z in $ZYGOTES; do
    nsenter --mount=/proc/$Z/ns/mnt -- /bin/mount --bind $SYS $APEX
    for P in $(ps -o PID= -P $Z); do
      nsenter --mount=/proc/$P/ns/mnt -- /bin/mount --bind $SYS $APEX 2>/dev/null &
    done
  done
  wait
fi
echo __OK__
"""


class Device(DeviceBase):
    def get_proxy(self):
        return self.shell("settings get global http_proxy")[1].strip()

    def set_proxy(self, port):
        proc = self.run("reverse", f"tcp:{port}", f"tcp:{port}")
        if proc.returncode != 0:
            raise RuntimeError(f"adb reverse failed: {proc.stderr.decode(errors='replace')}")
        self.shell(f"settings put global http_proxy 127.0.0.1:{port}")

    def clear_proxy(self, port=None):
        # ":0" switches the proxy off immediately (deleting the setting needs a reboot).
        self.shell("settings put global http_proxy :0")
        if port:
            self.run("reverse", "--remove", f"tcp:{port}")

    def install_ca(self):
        wrap = self.root_wrap()
        if not wrap:
            raise RuntimeError("Installing the certificate needs root (rooted device, or an "
                               "emulator image without Google Play).")
        name = cert_hash_name()
        proc = self.run("push", CA_PEM, f"/data/local/tmp/{name}")
        if proc.returncode != 0:
            raise RuntimeError(f"adb push failed: {proc.stderr.decode(errors='replace')}")
        _, out, err = self.shell(wrap(CERT_SCRIPT.format(name=name)))
        if "__ALREADY__" in out:
            return "already installed"
        if "__OK__" not in out:
            raise RuntimeError(f"Certificate install failed:\n{out}\n{err}")
        return "installed"


def cert_hash_name():
    """Android names CA files <subject_hash_old>.0"""
    out = subprocess.run(["openssl", "x509", "-inform", "PEM", "-subject_hash_old", "-noout",
                          "-in", CA_PEM], capture_output=True, text=True).stdout.strip()
    if len(out) == 8:
        return out + ".0"
    import hashlib
    from cryptography import x509
    with open(CA_PEM, "rb") as fh:
        cert = x509.load_pem_x509_certificate(fh.read())
    h = int.from_bytes(hashlib.md5(cert.subject.public_bytes()).digest()[:4], "little")
    return f"{h:08x}.0"


def port_free(port):
    with socket.socket() as s:
        return s.connect_ex(("127.0.0.1", port)) != 0


def load_settings():
    try:
        with open(SETTINGS_FILE, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def save_settings(settings):
    try:
        with open(SETTINGS_FILE, "w", encoding="utf-8") as fh:
            json.dump(settings, fh, indent=1)
    except OSError:
        pass


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Net Inspector")
        self.geometry("1350x800")
        self.minsize(900, 500)
        self.devices = []
        self.device = None
        self.proc = None
        self.port = None
        self.poll_stop = None
        self.events = queue.Queue()
        self.flows = {}         # id -> Flow
        self.order = []         # ids in arrival order
        self.n = 0
        self.settings = load_settings()
        self.hidden_hosts = set(self.settings.get("hidden_hosts", []))
        # App attribution
        self.packages = {}      # uid -> package
        self.host_conns = {}    # proxy connection id -> {"ts", "done", "app", "sure"}
        self.dev_conns = []     # device-side connections seen while polling
        self.flows_by_conn = {}
        self.apps_seen = set()
        self._uids_looked_up = set()
        self._preview = None    # keeps the preview image alive
        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        atexit.register(self._cleanup)
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda *_: self.after(0, self._on_close))
        self.after(100, self._poll_events)
        self.after(100, self.refresh_devices)

    # ---------- UI ----------
    def _build_ui(self):
        top = ttk.Frame(self, padding=8)
        top.pack(fill="x")
        ttk.Label(top, text="Device").pack(side="left")
        self.device_cb = ttk.Combobox(top, state="readonly", width=34)
        self.device_cb.pack(side="left", padx=4)
        self.device_cb.bind("<<ComboboxSelected>>", lambda e: self.on_device_selected())
        ttk.Button(top, text="↻", width=3, command=self.refresh_devices).pack(side="left")
        ttk.Label(top, text="Port").pack(side="left", padx=(12, 2))
        self.port_var = tk.StringVar(value=str(self.settings.get("port", 8080)))
        ttk.Entry(top, textvariable=self.port_var, width=6).pack(side="left")
        self.https_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="Decrypt HTTPS (installs CA, needs root)",
                        variable=self.https_var).pack(side="left", padx=12)
        self.start_btn = ttk.Button(top, text="▶ Start capture", command=self.toggle)
        self.start_btn.pack(side="left")
        ttk.Button(top, text="Open HAR…", command=self.open_har).pack(side="right")
        ttk.Button(top, text="Save HAR…", command=self.save_har).pack(side="right", padx=4)

        bar = ttk.Frame(self, padding=(8, 0, 8, 6))
        bar.pack(fill="x")
        ttk.Label(bar, text="Filter").pack(side="left")
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self._schedule_filter())
        ttk.Entry(bar, textvariable=self.filter_var, width=34).pack(side="left", padx=4)
        self.bodies_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="Search bodies", variable=self.bodies_var,
                        command=self.apply_filter).pack(side="left", padx=(0, 10))
        ttk.Label(bar, text="Show").pack(side="left")
        self.show_var = tk.StringVar(value="All")
        show = ttk.Combobox(bar, textvariable=self.show_var, values=SHOW_OPTIONS, state="readonly", width=8)
        show.pack(side="left", padx=4)
        show.bind("<<ComboboxSelected>>", lambda e: self.apply_filter())
        ttk.Label(bar, text="App").pack(side="left", padx=(8, 0))
        self.app_var = tk.StringVar(value=ALL_APPS)
        self.app_cb = ttk.Combobox(bar, textvariable=self.app_var, values=[ALL_APPS], state="readonly", width=34)
        self.app_cb.pack(side="left", padx=4)
        self.app_cb.bind("<<ComboboxSelected>>", lambda e: self.apply_filter())
        ttk.Button(bar, text="Clear", command=self.clear).pack(side="right")
        self.hidden_btn = ttk.Menubutton(bar)
        self.hidden_menu = tk.Menu(self.hidden_btn, tearoff=0, postcommand=self._fill_hidden_menu)
        self.hidden_btn["menu"] = self.hidden_menu
        self.hidden_btn.pack(side="right", padx=4)
        self._update_hidden_label()
        self.autoscroll_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="Auto-scroll", variable=self.autoscroll_var).pack(side="right", padx=4)

        panes = ttk.PanedWindow(self, orient="vertical")
        panes.pack(fill="both", expand=True, padx=8)

        # Call list
        lst = ttk.Frame(panes)
        cols = (("#", 50), ("Time", 70), ("Method", 65), ("Status", 55), ("App", 230), ("Host", 220),
                ("Path", 380), ("Type", 80), ("Size", 75), ("Time taken", 80))
        self.tree = ttk.Treeview(lst, columns=[c for c, _ in cols], show="headings", selectmode="browse")
        for c, w in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=w, minwidth=40, stretch=c == "Path",
                             anchor="e" if c in ("#", "Size", "Time taken") else "w")
        self.tree.tag_configure("error", foreground="#d1242f")
        self.tree.tag_configure("bad", foreground="#d1242f")
        self.tree.tag_configure("redirect", foreground="#9a6700")
        self.tree.tag_configure("pending", foreground="gray")
        vsb = ttk.Scrollbar(lst, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", lambda e: self.show_selected())
        for seq in ("<Button-2>", "<Button-3>", "<Control-Button-1>"):
            self.tree.bind(seq, self._row_menu)
        panes.add(lst, weight=3)

        # Details
        det = ttk.Frame(panes)
        actions = ttk.Frame(det)
        actions.pack(fill="x", pady=(4, 2))
        ttk.Button(actions, text="Copy URL", command=lambda: self._copy(lambda f: f.url)).pack(side="left")
        ttk.Button(actions, text="Copy as cURL", command=lambda: self._copy(Flow.curl)).pack(side="left", padx=4)
        ttk.Button(actions, text="Save response body…", command=self.save_body).pack(side="left")
        self.tabs = ttk.Notebook(det)
        self.tabs.pack(fill="both", expand=True)
        self.req_text = self._text_tab("Request")
        self.resp_text = self._text_tab("Response")
        panes.add(det, weight=2)

        self.status_var = tk.StringVar(value="Pick a device and press Start capture")
        ttk.Label(self, textvariable=self.status_var, anchor="w", padding=(8, 4),
                  relief="sunken").pack(fill="x", side="bottom")

    def _text_tab(self, title):
        frame = ttk.Frame(self.tabs)
        text = tk.Text(frame, wrap="none", font=("Menlo", 12), state="disabled")
        vsb = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
        hsb = ttk.Scrollbar(frame, orient="horizontal", command=text.xview)
        text.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        text.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        text.tag_configure("head", font=("Menlo", 12, "bold"))
        text.tag_configure("key", foreground="#0550ae")
        self.tabs.add(frame, text=title)
        return text

    def status(self, msg):
        self.status_var.set(msg)

    def run_bg(self, work, done, busy):
        self.status(busy)
        self.start_btn.state(["disabled"])

        def target():
            try:
                res, err = work(), None
            except Exception as exc:  # noqa: BLE001 - shown to the user
                res, err = None, exc
            self.after(0, finish, res, err)

        def finish(res, err):
            self.start_btn.state(["!disabled"])
            if err:
                self.status(f"Error: {err}".splitlines()[0])
                messagebox.showerror("Error", str(err))
            else:
                done(res)
        threading.Thread(target=target, daemon=True).start()

    # ---------- devices ----------
    def refresh_devices(self):
        def done(devs):
            self.devices = devs
            self.device_cb["values"] = [f"{s}  {m}".strip() for s, m in devs]
            if devs:
                self.device_cb.current(0)
                self.on_device_selected()
            else:
                self.status("No devices found. Connect one and press ↻")
        self.run_bg(list_devices, done, "Looking for devices…")

    def on_device_selected(self):
        if self.proc:
            return
        idx = self.device_cb.current()
        if idx < 0:
            return
        self.device = Device(self.devices[idx][0])

        def done(proxy):
            # A proxy left over from a crashed session would leave the device without internet.
            if proxy.startswith("127.0.0.1:") and messagebox.askyesno(
                    "Leftover proxy",
                    f"The device's proxy is still set to {proxy}, probably from an earlier "
                    "session, so it may have no internet. Switch it off?"):
                self.device.clear_proxy(proxy.split(":")[1])
            self.status(f"Ready: {self.device.serial}")
        self.run_bg(self.device.get_proxy, done, "Checking device…")

    # ---------- capture ----------
    def toggle(self):
        self.stop() if self.proc else self.start()

    def start(self):
        if not self.device:
            messagebox.showwarning("No device", "Connect a device first.")
            return
        mitmdump = find_mitmdump()
        if not mitmdump:
            messagebox.showerror("mitmproxy missing",
                                 "Install it with:\n  python3 -m venv .venv && .venv/bin/pip install mitmproxy")
            return
        try:
            port = int(self.port_var.get())
        except ValueError:
            messagebox.showerror("Port", "Port must be a number.")
            return
        if not port_free(port):
            messagebox.showerror("Port in use", f"Port {port} is already in use on this computer.")
            return
        self.settings["port"] = port
        save_settings(self.settings)
        self.port = port
        self.proc = subprocess.Popen(
            [mitmdump, "--listen-host", "127.0.0.1", "-p", str(port), "-s", ADDON,
             "--set", f"confdir={CONFDIR}", "--set", "flow_detail=0",
             "--set", "ssl_insecure=true", "--set", "termlog_verbosity=warn"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
            start_new_session=True)
        threading.Thread(target=self._reader, args=(self.proc,), daemon=True).start()
        decrypt = self.https_var.get()
        device = self.device

        def work():
            for _ in range(50):  # wait until mitmproxy is listening (and has created its CA)
                if not port_free(port):
                    break
                if self.proc is None or self.proc.poll() is not None:
                    raise RuntimeError("mitmproxy exited at startup (see status bar).")
                time.sleep(0.1)
            notes = []
            if decrypt:
                try:
                    notes.append("certificate " + device.install_ca())
                except RuntimeError as exc:
                    notes.append(f"HTTPS not decrypted: {exc}")
            packages = device.package_uids()
            device.set_proxy(port)
            return notes, packages

        def work_safe():
            try:
                return work()
            except Exception:
                self._kill_proxy()
                raise

        def done(result):
            notes, self.packages = result
            self.poll_stop = threading.Event()
            threading.Thread(target=self._poll_device, args=(device, port, self.poll_stop),
                             daemon=True).start()
            self.start_btn.configure(text="■ Stop capture")
            self.status(f"Capturing on 127.0.0.1:{port} · " + " · ".join(notes))
        self.run_bg(work_safe, done, "Starting proxy…")

    def stop(self):
        dev, port = self.device, self.port
        if self.poll_stop:
            self.poll_stop.set()

        def work():
            dev.clear_proxy(port)
            self._kill_proxy()

        def done(_):
            self.start_btn.configure(text="▶ Start capture")
            self.status("Stopped. Device proxy switched off.")
        self.run_bg(work, done, "Stopping…")

    def _kill_proxy(self):
        proc, self.proc = self.proc, None
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:
                proc.kill()

    def _reader(self, proc):
        for line in proc.stdout:
            if line.startswith("@@NET "):
                try:
                    self.events.put(json.loads(line[6:]))
                except ValueError:
                    pass
            elif line.strip():
                self.events.put({"event": "log", "msg": line.strip()})

    def _poll_device(self, device, port, stop):
        """Report new device-side connections to the proxy, with the app uid that owns them."""
        known, prev = {}, time.time()
        while not stop.is_set():
            start = time.time()
            try:
                _, out, _ = device.shell("cat /proc/net/tcp /proc/net/tcp6", timeout=10)
            except Exception:  # noqa: BLE001 - device busy or gone; try again
                stop.wait(1)
                continue
            seen_at = time.time()
            now = parse_proc_net(out, port)
            for key, uid in now.items():
                if key not in known:
                    # It opened somewhere between the previous read and this one.
                    self.events.put({"event": "devconn", "lo": prev, "hi": seen_at, "uid": uid})
            known, prev = now, start
            stop.wait(POLL_SECONDS)

    # ---------- events from mitmproxy / device ----------
    def _poll_events(self):
        added = False
        try:
            for _ in range(500):  # keep the UI responsive under heavy traffic
                added |= self._handle(self.events.get_nowait())
        except queue.Empty:
            pass
        self._resolve_apps()
        if added:
            self._trim()
            if self.autoscroll_var.get():
                kids = self.tree.get_children()
                if kids:
                    self.tree.see(kids[-1])
            self._update_count()
        self.after(100, self._poll_events)

    def _handle(self, ev):
        kind = ev["event"]
        if kind == "log":
            self.status(ev["msg"][:200])
        elif kind == "conn":
            self.host_conns[ev["conn"]] = {"ts": ev["ts"], "done": False, "app": None, "sure": True}
        elif kind == "devconn":
            self.dev_conns.append({"lo": ev["lo"], "hi": ev["hi"], "uid": ev["uid"], "used": False})
        elif kind in ("request", "tls_failed"):
            if kind == "tls_failed":
                ev = {"id": f"tls{self.n}", "conn": ev.get("conn"), "ts": ev["ts"], "method": "TLS",
                      "url": f"https://{ev['host']}/", "host": ev["host"],
                      "path": "(handshake failed: app doesn't trust the proxy or pins its certificate)",
                      "error": ev["error"]}
            return self._add_flow(Flow(ev))
        elif kind in ("response", "error"):
            f = self.flows.get(ev["id"])
            if f:
                if kind == "response":
                    f.set_response(ev)
                else:
                    f.error = ev["error"]
                self._refresh_row(f)
        return False

    def _add_flow(self, f):
        self.n += 1
        f.n = self.n
        info = self.host_conns.get(f.conn)
        if info and info["done"]:
            f.app, f.app_sure = info["app"], info["sure"]
        if f.conn:
            self.flows_by_conn.setdefault(f.conn, []).append(f.id)
        self.flows[f.id] = f
        self.order.append(f.id)
        if self._visible(f):
            self.tree.insert("", "end", iid=f.id, values=f.row(), tags=(f.tag(),))
            return True
        return False

    def _resolve_apps(self):
        """Settle which app opened each proxy connection, once device info has had time to arrive."""
        now = time.time()
        for cid, info in self.host_conns.items():
            if info["done"] or now - info["ts"] < APP_WAIT:
                continue
            dev, sure = pick_device_conn(info["ts"], self.dev_conns)
            info["done"] = True
            if dev:
                dev["used"] = True
                uid = dev["uid"]
                if uid not in self.packages and uid % 100000 >= 10000 and uid not in self._uids_looked_up:
                    self._uids_looked_up.add(uid)  # app installed meanwhile? ask once per uid
                    self.packages.update(self.device.package_uids())
                info["app"], info["sure"] = uid_label(dev["uid"], self.packages), sure
            else:
                info["app"], info["sure"] = "?", False
            if info["app"] != "?":
                self._note_app(info["app"])
            for fid in self.flows_by_conn.get(cid, []):
                f = self.flows.get(fid)
                if f:
                    f.app, f.app_sure = info["app"], info["sure"]
                    self._refresh_row(f)
        # Forget old bookkeeping
        self.dev_conns = [d for d in self.dev_conns if now - d["hi"] < 60]

    def _note_app(self, app):
        if app not in self.apps_seen:
            self.apps_seen.add(app)
            self.app_cb["values"] = [ALL_APPS] + sorted(self.apps_seen)

    def _refresh_row(self, f):
        visible = self._visible(f)
        if self.tree.exists(f.id):
            if not visible:
                self.tree.delete(f.id)
                return
            self.tree.item(f.id, values=f.row(), tags=(f.tag(),))
            if self.tree.selection() == (f.id,):
                self.show_selected()
        elif visible:
            self._insert_in_order(f)

    def _insert_in_order(self, f):
        """Insert a row at its arrival position (used when a row becomes visible later)."""
        kids = self.tree.get_children()
        index = len(kids)
        for i, iid in enumerate(kids):
            if self.flows[iid].n > f.n:
                index = i
                break
        self.tree.insert("", index, iid=f.id, values=f.row(), tags=(f.tag(),))

    def _trim(self):
        while len(self.order) > MAX_FLOWS:
            fid = self.order.pop(0)
            f = self.flows.pop(fid, None)
            if self.tree.exists(fid):
                self.tree.delete(fid)
            if f and f.conn in self.flows_by_conn:
                ids = self.flows_by_conn[f.conn]
                if fid in ids:
                    ids.remove(fid)
                if not ids:
                    del self.flows_by_conn[f.conn]
                    self.host_conns.pop(f.conn, None)

    # ---------- filtering ----------
    def _filter_args(self):
        app = self.app_var.get()
        return dict(terms=self.filter_var.get().lower().split(), show=self.show_var.get(),
                    app=None if app == ALL_APPS else app, hidden_hosts=self.hidden_hosts,
                    in_bodies=self.bodies_var.get())

    def _visible(self, f):
        return f.matches(**self._filter_args())

    def _schedule_filter(self):
        # Wait for a pause in typing (body search can be slow with many calls).
        if getattr(self, "_filter_job", None):
            self.after_cancel(self._filter_job)
        self._filter_job = self.after(200, self.apply_filter)

    def apply_filter(self):
        self._filter_job = None
        args = self._filter_args()
        selected = self.tree.selection()
        self.tree.delete(*self.tree.get_children())
        for fid in self.order:
            f = self.flows[fid]
            if f.matches(**args):
                self.tree.insert("", "end", iid=f.id, values=f.row(), tags=(f.tag(),))
        if selected and self.tree.exists(selected[0]):
            self.tree.selection_set(selected[0])
            self.tree.see(selected[0])
        self._update_count()

    def _update_count(self):
        shown, total = len(self.tree.get_children()), len(self.order)
        hidden = sum(1 for fid in self.order if self.flows[fid].host in self.hidden_hosts)
        extra = f" · {hidden} from hidden hosts" if hidden else ""
        prefix = self.status_var.get().split("  ·  calls:")[0]
        self.status(f"{prefix}  ·  calls: {shown} shown of {total}{extra}")

    def hide_host(self, host):
        self.hidden_hosts.add(host)
        self._save_hidden()

    def unhide_host(self, host=None):
        if host is None:
            self.hidden_hosts.clear()
        else:
            self.hidden_hosts.discard(host)
        self._save_hidden()

    def _save_hidden(self):
        self.settings["hidden_hosts"] = sorted(self.hidden_hosts)
        save_settings(self.settings)
        self._update_hidden_label()
        self.apply_filter()

    def _update_hidden_label(self):
        self.hidden_btn.configure(text=f"Hidden hosts ({len(self.hidden_hosts)}) ▾")

    def _fill_hidden_menu(self):
        m = self.hidden_menu
        m.delete(0, "end")
        if not self.hidden_hosts:
            m.add_command(label="Right-click a call → Hide host", state="disabled")
            return
        for host in sorted(self.hidden_hosts):
            m.add_command(label=f"Show {host}", command=lambda h=host: self.unhide_host(h))
        m.add_separator()
        m.add_command(label="Show all hosts", command=self.unhide_host)

    def _row_menu(self, event):
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        self.tree.selection_set(iid)
        f = self.flows[iid]
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Copy URL", command=lambda: self._copy(lambda x: x.url))
        menu.add_command(label="Copy as cURL", command=lambda: self._copy(Flow.curl))
        menu.add_separator()
        menu.add_command(label=f"Hide host {f.host}", command=lambda: self.hide_host(f.host))
        if f.app and f.app != "?":
            menu.add_command(label=f"Only show {f.app}",
                             command=lambda: (self.app_var.set(f.app), self.apply_filter()))
        menu.tk_popup(event.x_root, event.y_root)

    def clear(self):
        self.flows.clear()
        self.order.clear()
        self.flows_by_conn.clear()
        self.host_conns = {k: v for k, v in self.host_conns.items() if not v["done"]}
        self.n = 0
        self.tree.delete(*self.tree.get_children())
        for t in (self.req_text, self.resp_text):
            self._fill(t, [])
        self._update_count()

    # ---------- details ----------
    def selected_flow(self):
        sel = self.tree.selection()
        return self.flows.get(sel[0]) if sel else None

    def show_selected(self):
        f = self.selected_flow()
        if not f:
            return
        req_ct = header(f.req_headers, "content-type")
        app = f"\nApp: {f.app_label()}" if f.app else ""
        req = [("head", f"{f.method} {f.url}\n"), ("", f"{f.http_version}{app}\n\n")]
        req += self._headers(f.req_headers)
        body = decode_body(f.req_body)
        if body:
            req += [("head", "\nBody\n"), ("", body_as_text(body, req_ct, f.req_body["truncated"]))]
        self._fill(self.req_text, req)

        self._preview = None
        if f.error:
            self._fill(self.resp_text, [("head", "Error\n"), ("", f.error)])
            return
        if f.status is None:
            self._fill(self.resp_text, [("", "Waiting for response…")])
            return
        resp = [("head", f"{f.http_version} {f.status} {f.reason}\n"),
                ("", f"{f.duration * 1000:.0f} ms\n\n")]
        resp += self._headers(f.resp_headers)
        body = decode_body(f.resp_body)
        image = self._image(body, f.content_type) if body else None
        if image:
            resp += [("head", f"\nBody ({image.width()}×{image.height()} preview)\n")]
        elif body:
            resp += [("head", "\nBody\n"), ("", body_as_text(body, f.content_type, f.resp_body["truncated"]))]
        self._fill(self.resp_text, resp)
        if image:
            self._preview = image
            self.resp_text.configure(state="normal")
            self.resp_text.image_create("end", image=image)
            self.resp_text.configure(state="disabled")

    def _image(self, data, content_type):
        """A Tk image for image responses, scaled to fit, or None."""
        if not (content_type or "").lower().startswith("image/"):
            return None
        try:
            if Image is not None:
                img = Image.open(io.BytesIO(data))
                img.thumbnail((640, 400))
                return ImageTk.PhotoImage(img)
            img = tk.PhotoImage(data=base64.b64encode(data).decode())  # PNG/GIF only
            factor = max(1, -(-img.width() // 640), -(-img.height() // 400))
            return img.subsample(factor) if factor > 1 else img
        except Exception:  # noqa: BLE001 - unsupported/corrupt image: show as binary instead
            return None

    @staticmethod
    def _headers(headers):
        out = [("head", "Headers\n")]
        for k, v in headers:
            out += [("key", f"{k}: "), ("", f"{v}\n")]
        return out

    @staticmethod
    def _fill(text, chunks):
        text.configure(state="normal")
        text.delete("1.0", "end")
        for tag, s in chunks:
            text.insert("end", s, tag or ())
        text.configure(state="disabled")

    def _copy(self, getter):
        f = self.selected_flow()
        if f:
            self.clipboard_clear()
            self.clipboard_append(getter(f))
            self.status("Copied to clipboard")

    def save_body(self):
        f = self.selected_flow()
        if not f or not f.resp_body:
            messagebox.showinfo("No body", "Select a call that has a response body.")
            return
        name = os.path.basename(f.path.split("?")[0]) or "body"
        path = filedialog.asksaveasfilename(initialfile=name)
        if path:
            with open(path, "wb") as fh:
                fh.write(decode_body(f.resp_body))
            self.status(f"Saved {path}")

    # ---------- HAR ----------
    def save_har(self):
        visible = [self.flows[i] for i in self.tree.get_children()]
        if not visible:
            messagebox.showinfo("Nothing to save", "No calls in the list.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".har", initialfile="capture.har",
                                            filetypes=[("HAR", "*.har"), ("All files", "*")])
        if path:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(to_har(visible), fh, ensure_ascii=False)
            self.status(f"Saved {len(visible)} calls (as currently filtered) to {path}")

    def open_har(self):
        path = filedialog.askopenfilename(filetypes=[("HAR", "*.har"), ("JSON", "*.json"), ("All files", "*")])
        if not path:
            return
        try:
            with open(path, encoding="utf-8") as fh:
                flows = from_har(json.load(fh))
        except (OSError, ValueError, KeyError) as exc:
            messagebox.showerror("Can't open HAR", str(exc))
            return
        for f in flows:
            f.id = f"{f.id}_{self.n}"
            self._add_flow(f)
            if f.app:
                self._note_app(f.app)
        self._trim()
        self._update_count()
        self.status(f"Loaded {len(flows)} calls from {os.path.basename(path)}")

    # ---------- shutdown ----------
    def _cleanup(self):
        if self.poll_stop:
            self.poll_stop.set()
        if self.proc and self.device:
            try:
                self.device.clear_proxy(self.port)
            except Exception:  # noqa: BLE001 - best effort on exit
                pass
        self._kill_proxy()

    def _on_close(self):
        self._cleanup()
        self.destroy()


if __name__ == "__main__":
    App().mainloop()

# Android dev tools

Two desktop apps for Android devices and emulators, driven over `adb`:

- **Room SQL** – run SQL on any app's Room/SQLite database, and edit results in place.
- **Net Inspector** – see every HTTP(S) call the whole device makes, from any app.

Needs `adb` (Android SDK platform-tools) and a device or emulator with USB debugging on.

## Setup (once)

    python3 -m venv .venv && .venv/bin/pip install mitmproxy pillow

Room SQL works with plain `python3`; Net Inspector needs the `.venv` (mitmproxy; Pillow for JPEG/WebP previews).

---

# Room SQL

    python3 room_sql_gui.py

The app must be **debuggable** (a debug build, accessed with `run-as`) or the device **rooted** (`su`).
Android Automotive's user 10 is detected automatically.

1. Pick the device and the package (type to filter; tick "System apps" to see all), then the database.
2. Double-click a table, or write SQL and press ⌘+Enter / **Execute**.

**Editor**
- Autocomplete for tables, columns (also via `alias.`), keywords and functions. Ctrl+Space opens it.
- Syntax highlighting.
- If text is selected, only the selection runs.
- **History:** ⌘↑ / ⌘↓ go through earlier queries; **History ▾** lists recent ones. Saved in `.room_sql_history.json`.

**Results**
- Click a column header to sort.
- **Edit cells:** for `SELECT … FROM one_table` queries, editable columns show ✎. Double-click a cell, type,
  then press Enter. Type `NULL` (or use the right-click menu) to set NULL. Each change is shown as SQL and confirmed first.
- Right-click a cell to copy the cell or row(s), view the full value (JSON is formatted) or edit it. ⌘C copies selected rows.
- Export CSV.

**Speed and safety**
- The database is only copied again when the file on the device changes. **⟳ Reload DB** forces a fresh copy.
- Read queries can't change anything. A write asks first, force-stops the app, writes into a fresh copy,
  then pushes it back to the device.

---

# Net Inspector

    .venv/bin/python net_inspector.py

1. Pick the device and press **Start capture**.
2. Calls appear live, with the **App** that made them. Click a call to see request and response headers and body
   (JSON formatted, images previewed).
3. Narrow the list:
   - **Filter**: matches URL, method, status, type and app. Tick **Search bodies** to also search request/response bodies.
   - **Show**: All, Errors, JSON, Images or Other.
   - **App**: one app only.
   - **Hide hosts**: right-click a call → *Hide host*, to mute noisy hosts. Undo it with **Hidden hosts ▾**.
4. **Save HAR…** saves the calls currently listed, to open in Chrome DevTools, Charles or Proxyman.
   **Open HAR…** loads one back in.
5. **Stop capture** (or closing the window) switches the device proxy off.

**App column:** worked out by matching the device's connection table to the proxy's connections by timing.
`name ?` means several apps connected at the same moment, so it's a best guess. `?` means it couldn't be matched.

**HTTPS:** "Decrypt HTTPS" installs mitmproxy's certificate as a system certificate. This needs root, e.g. an emulator
image without Google Play. It only lasts until the device reboots.
Rows marked **TLS** in red are apps that refused the certificate, often because of certificate pinning. Apps that
ignore the system proxy won't show up at all.

The newest 5000 calls are kept. Hidden hosts and the port are saved in `.net_inspector.json`.

If the app is killed and the device has no internet, switch the proxy off by hand:

    adb shell settings put global http_proxy :0

---

## Files

| File | What it is |
|---|---|
| `room_sql_gui.py` | Room SQL app |
| `sql_editor.py` | SQL parsing, autocomplete, highlighting |
| `net_inspector.py` | Net Inspector app |
| `net_model.py` | Captured calls, filters, HAR, app matching |
| `net_capture_addon.py` | mitmproxy add-on that streams calls to Net Inspector |
| `adb_common.py` | adb helpers shared by both apps |
| `tests/` | Tests: `.venv/bin/python -m unittest discover -s tests -v` |

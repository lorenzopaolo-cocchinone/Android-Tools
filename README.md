# Android dev tools

Three desktop apps for Android devices and emulators, driven over `adb`:

- **Room SQL** – run SQL on any app's Room/SQLite database, and edit results in place.
- **Net Inspector** – see every HTTP(S) call the whole device makes, from any app.
- **MMKV Inspector** – see and edit the keys and values in any app's MMKV storage.

Needs `adb` (Android SDK platform-tools) and a device or emulator with USB debugging on.

## Setup (once)

Room SQL and MMKV Inspector work with plain `python3`. Net Inspector (and opening encrypted MMKV stores) needs a virtual environment with the packages in `requirements.txt`.

**Requirements**
- Python 3.12 or newer, with Tkinter (python.org installers include it; with Homebrew: `brew install python-tk`)
- `adb` on your `PATH`
- Python packages (`requirements.txt`):
  - `mitmproxy` – the proxy that captures the calls (it also brings `cryptography`, used for encrypted MMKV stores)
  - `pillow` – optional, for JPEG/WebP previews (PNG/GIF work without it)

**Create the venv and install the packages**, from the project folder:

    python3 -m venv .venv
    .venv/bin/pip install --upgrade pip
    .venv/bin/pip install -r requirements.txt

Check it worked:

    .venv/bin/mitmdump --version

You don't need to activate the venv: run the app with `.venv/bin/python` (see below), and it finds
`.venv/bin/mitmdump` by itself. To recreate the venv from scratch, delete the `.venv` folder and run the steps again.

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

# MMKV Inspector

    python3 mmkv_inspector.py

Use `.venv/bin/python mmkv_inspector.py` instead to open encrypted stores.
Like Room SQL, the app must be **debuggable** (`run-as`) or the device **rooted** (`su`).

1. Pick the device, then the **User** (the current user is listed first; on Android Automotive that's usually 10),
   then the package. Only packages installed for that user are listed.
2. Pick the **Store**. Every MMKV store in the app's data folder is found (a file with a `.crc` file next to it).
   Stores in the default `files/mmkv` folder are shown by name only, e.g. `mmkv.default`.
3. Click a key to see its value. JSON is formatted. Timestamps also show as dates.

**Value types:** MMKV doesn't record a value's type, so the type is a guess. For example, a 1-byte `1` could be
`true` or the int `1`. The detail panel lists every way the bytes can be read. Double-click a reading, or use
**View as** (also in the right-click menu), to pick the type for that key. Choices are saved in `.mmkv_inspector.json`
and marked ✎ in the list.

**Editing**
- **Edit:** double-click a key (or **Edit…**, or right-click → *Edit value…*). Pick the type, type the value, and the
  dialog shows the bytes that will be stored, or what's wrong with the input. ⌘↵ saves.
  - int and long are stored the same way, so `int` covers both.
  - A string set is a JSON list, e.g. `["a", "b"]`. `bytes` is hex. `hex` is the raw stored value, for experts.
- **+ Add key** adds a new key. **Delete** (or the ⌫ key) removes the selected keys.
- Each change is confirmed first. Then the app is **force-stopped**, the store is read again (so changes the app made
  meanwhile are kept), and a fresh, compacted file is written with a matching `.crc`. Before pushing, the new file is
  read back to check it.
- A copy of the files before each write is saved in `.mmkv_backups/<device>/<package>/`.
  **Undo last write** puts the previous version back.
- Encrypted stores can be edited once the crypt key is set.

**More**
- **Filter** matches keys and values.
- **Auto refresh** re-reads the store every 2 seconds if it changed on the device. **⟳ Reload** forces a fresh read.
- Right-click to copy a key, a value or rows. ⌘C copies the selected rows.
- **Export JSON…** saves all keys and values, using the chosen types.
- **Crypt key…**: for stores opened with a crypt key, enter the same key. It's kept only until the app closes.
- The status bar shows the key count, the space used, keys deleted since the last compaction, and a CRC warning if
  the app was writing while the files were copied (press ⟳ Reload).

---

## Files

| File | What it is |
|---|---|
| `room_sql_gui.py` | Room SQL app |
| `sql_editor.py` | SQL parsing, autocomplete, highlighting |
| `net_inspector.py` | Net Inspector app |
| `net_model.py` | Captured calls, filters, HAR, app matching |
| `net_capture_addon.py` | mitmproxy add-on that streams calls to Net Inspector |
| `requirements.txt` | Python packages for Net Inspector |
| `mmkv_inspector.py` | MMKV Inspector app |
| `mmkv_model.py` | Reads MMKV files, guesses value types |
| `adb_common.py` | adb helpers shared by the apps |
| `tests/` | Tests: `.venv/bin/python -m unittest discover -s tests -v` |

"""Reads MMKV files (Tencent's key-value store) without the MMKV library.

File layout, as written by MMKV:
  <id>      4-byte little-endian size, then that many bytes of data:
            a varint to skip, then key/value pairs, each "varint length + bytes".
            Writes are appended, so the last pair for a key wins; an empty value means deleted.
  <id>.crc  meta info: crc32 of the data, version, sequence, AES IV, size and flags.

Values carry no type, so they are guessed (see guess); the user can pick another reading.
Edits are saved by writing a fresh, compacted file and a matching .crc (see build_files).
"""

import json
import struct
import zlib
from dataclasses import dataclass, field

TYPES = ["auto", "string", "int", "bool", "float", "double", "string set", "bytes", "hex"]
FLAG_KEY_EXPIRE = 1


class MMKVError(Exception):
    pass


def read_varint(buf, pos):
    """Decode a protobuf varint at pos; returns (value, new_pos)."""
    result = shift = 0
    while True:
        if pos >= len(buf) or shift >= 70:
            raise ValueError("bad varint")
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, pos
        shift += 7


def read_chunk(buf, pos):
    """A length-prefixed chunk; returns (bytes, new_pos)."""
    n, pos = read_varint(buf, pos)
    if pos + n > len(buf):
        raise ValueError("chunk past end")
    return bytes(buf[pos:pos + n]), pos + n


@dataclass
class Meta:
    crc: int = 0
    version: int = 0
    sequence: int = 0
    iv: bytes = b""
    actual_size: int = 0
    flags: int = 0


def parse_meta(data):
    if not data or len(data) < 12:
        return None
    m = Meta()
    m.crc, m.version, m.sequence = struct.unpack_from("<III", data, 0)
    m.iv = bytes(data[12:28])
    if m.version >= 3 and len(data) >= 32:
        m.actual_size = struct.unpack_from("<I", data, 28)[0]
    if m.version >= 4 and len(data) >= 112:
        m.flags = struct.unpack_from("<Q", data, 104)[0]
    return m


@dataclass
class Entry:
    key: str
    raw: bytes
    expire: int | None = None  # seconds since epoch, 0 = never; None if the store has no expiry
    writes: int = 1            # how many times the key was written since the last compaction


@dataclass
class Store:
    entries: dict = field(default_factory=dict)  # key -> Entry, live keys only
    size: int = 0          # bytes of data in use
    file_size: int = 0
    crc_ok: bool | None = None
    encrypted: bool = False
    expire_mode: bool = False
    total_writes: int = 0
    deleted: int = 0       # keys written and later removed
    prefix: bytes = b""    # the varint before the first key, kept as is when writing


def _cipher(crypt_key, meta):
    """AES-128-CFB, as MMKV does it: key cut or zero-padded to 16 bytes."""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
    except ImportError as exc:
        raise MMKVError("Encrypted stores need the 'cryptography' package (it comes with the .venv).") from exc
    try:  # CFB moved to the "decrepit" module in cryptography 47
        from cryptography.hazmat.decrepit.ciphers.modes import CFB
    except ImportError:
        from cryptography.hazmat.primitives.ciphers.modes import CFB
    key = crypt_key.encode()[:16].ljust(16, b"\0")
    # Since meta version 2 the IV is random and kept in the .crc file; before that it was the key.
    iv = meta.iv if meta and meta.version >= 2 and any(meta.iv) else key
    return Cipher(algorithms.AES(key), CFB(iv))


def decrypt(payload, crypt_key, meta):
    dec = _cipher(crypt_key, meta).decryptor()
    return dec.update(payload) + dec.finalize()


def encrypt(payload, crypt_key, meta):
    enc = _cipher(crypt_key, meta).encryptor()
    return enc.update(payload) + enc.finalize()


def parse_store(data, meta_bytes=None, crypt_key=None):
    """Parse the data file (+ optional .crc bytes). Raises MMKVError if it can't be read,
    which usually means it is encrypted and no (or the wrong) key was given."""
    if len(data) < 4:
        raise MMKVError("File is too short to be MMKV")
    meta = parse_meta(meta_bytes)
    size = struct.unpack_from("<I", data, 0)[0]
    # Since meta version 3 the size in the .crc file is the one MMKV trusts; recent
    # versions leave the header at 0.
    if meta and meta.version >= 3 and meta.actual_size <= len(data) - 4:
        size = meta.actual_size
    if size > len(data) - 4:
        raise MMKVError(f"Size in header ({size}) is larger than the file")
    payload = bytes(data[4:4 + size])
    store = Store(size=size, file_size=len(data), encrypted=bool(crypt_key),
                  expire_mode=bool(meta and meta.flags & FLAG_KEY_EXPIRE))
    if meta:
        store.crc_ok = (zlib.crc32(payload) & 0xFFFFFFFF) == meta.crc
    if crypt_key:
        payload = decrypt(payload, crypt_key, meta)
    if not payload:
        return store
    try:
        _, pos = read_varint(payload, 0)
        store.prefix = payload[:pos]
        while pos < len(payload):
            key_bytes, pos = read_chunk(payload, pos)
            if not key_bytes:
                continue
            key = key_bytes.decode("utf-8")
            value, pos = read_chunk(payload, pos)
            store.total_writes += 1
            old = store.entries.pop(key, None)
            if not value:
                store.deleted += 1 if old else 0
                continue
            expire = None
            if store.expire_mode and len(value) >= 4:
                expire = struct.unpack_from("<I", value, len(value) - 4)[0]
                value = value[:-4]
            store.entries[key] = Entry(key, value, expire, (old.writes + 1) if old else 1)
    except (ValueError, UnicodeDecodeError) as exc:
        hint = "wrong crypt key?" if crypt_key else "probably encrypted: set the crypt key"
        raise MMKVError(f"Can't read the data ({hint})") from exc
    return store


# ---------- Writing ----------

ITEM_SIZE_HOLDER = b"\xff\xff\xff\x07"  # varint MMKV writes before the first key of a new file
PAGE = 4096


def varint(n):
    """Protobuf varint; negative numbers take 10 bytes, as MMKV writes them."""
    n &= (1 << 64) - 1
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if not n:
            out.append(b)
            return bytes(out)
        out.append(b | 0x80)


def chunk(data):
    return varint(len(data)) + data


def build_files(store, data, meta_bytes, crypt_key=None):
    """New (data file, .crc file) holding store.entries, compacted like an MMKV full write-back.
    data and meta_bytes are the current files: their length, header style, IV and flags are kept."""
    meta = parse_meta(meta_bytes)
    if not meta:
        raise MMKVError("The .crc file is missing or too short; not writing without it")
    pairs = bytearray()
    for key, entry in store.entries.items():
        value = entry.raw
        if store.expire_mode:
            value += struct.pack("<I", entry.expire or 0)
        pairs += chunk(key.encode()) + chunk(value)
    payload = (store.prefix or ITEM_SIZE_HOLDER) + pairs if pairs else b""
    if crypt_key:
        payload = encrypt(payload, crypt_key, meta)
    size = len(payload)
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    # Recent MMKV leaves the header at 0 and keeps the size in the .crc file: do the same.
    header_zero = meta.version >= 3 and len(data) >= 4 and struct.unpack_from("<I", data, 0)[0] == 0
    length = max(len(data), -(-(size + 4) // PAGE) * PAGE)
    new_data = struct.pack("<I", 0 if header_zero else size) + payload
    new_data += b"\0" * (length - len(new_data))
    new_meta = bytearray(meta_bytes)
    struct.pack_into("<I", new_meta, 0, crc)
    struct.pack_into("<I", new_meta, 8, (meta.sequence + 1) & 0xFFFFFFFF)
    if meta.version >= 3 and len(new_meta) >= 40:
        struct.pack_into("<III", new_meta, 28, size, size, crc)  # size + last confirmed size/crc
    return new_data, bytes(new_meta)


def apply_changes(store, changes):
    """changes: [(key, raw bytes)] to set, or [(key, None)] to delete."""
    for key, raw in changes:
        old = store.entries.get(key)
        if raw is None:
            store.entries.pop(key, None)
        else:
            expire = (old.expire if old else 0) if store.expire_mode else None
            store.entries[key] = Entry(key, raw, expire)


def encode_value(kind, text):
    """Bytes MMKV would store for text typed as kind. Raises ValueError with a readable message."""
    t = text.strip()
    if kind == "string":
        return chunk(text.encode("utf-8"))
    if kind == "int":
        try:
            n = int(t.replace("_", ""))
        except ValueError:
            try:
                n = int(t, 0)
            except ValueError:
                raise ValueError("Enter a whole number, e.g. 42, -7 or 0x1F") from None
        if not -(1 << 63) <= n < (1 << 64):
            raise ValueError("Number is out of the 64-bit range")
        return varint(n)
    if kind == "bool":
        if t.lower() in ("true", "1", "yes"):
            return b"\x01"
        if t.lower() in ("false", "0", "no"):
            return b"\x00"
        raise ValueError("Enter true or false")
    if kind in ("float", "double"):
        try:
            f = float(t)
        except ValueError:
            raise ValueError("Enter a number, e.g. 1.5") from None
        return struct.pack("<f" if kind == "float" else "<d", f)
    if kind == "string set":
        try:
            items = json.loads(t or "[]")
        except ValueError:
            items = None
        if not isinstance(items, list) or not all(isinstance(i, str) for i in items):
            raise ValueError('Enter a JSON list of strings, e.g. ["a", "b"]')
        body = b"".join(chunk(i.encode("utf-8")) for i in items)
        return varint(len(body)) + body
    if kind in ("bytes", "hex"):
        try:
            raw = bytes.fromhex("".join(t.split()))
        except ValueError:
            raise ValueError("Enter hex bytes, e.g. 0a ff 10") from None
        if kind == "hex" and not raw:
            raise ValueError("A raw value can't be empty (MMKV reads that as deleted)")
        return chunk(raw) if kind == "bytes" else raw
    raise ValueError(f"Unknown type {kind}")


def edit_text(raw, kind):
    """Text to put in the edit box for raw read as kind ("" if it doesn't fit)."""
    try:
        return fmt(kind, read_as(raw, kind))
    except (ValueError, UnicodeDecodeError):
        return ""


# ---------- Reading values ----------

def _printable(text):
    return all(c.isprintable() or c in "\n\r\t" for c in text)


def as_string(raw):
    data, pos = read_chunk(raw, 0)
    if pos != len(raw):
        raise ValueError("extra bytes")
    return data.decode("utf-8")


def as_bytes(raw):
    data, pos = read_chunk(raw, 0)
    if pos != len(raw):
        raise ValueError("extra bytes")
    return data


def as_int(raw):
    value, pos = read_varint(raw, 0)
    if pos != len(raw):
        raise ValueError("extra bytes")
    value &= (1 << 64) - 1
    return value - (1 << 64) if value >> 63 else value


def as_bool(raw):
    if len(raw) != 1 or raw[0] > 1:
        raise ValueError("not a bool")
    return bool(raw[0])


def as_float(raw):
    if len(raw) != 4:
        raise ValueError("not 4 bytes")
    return struct.unpack("<f", raw)[0]


def as_double(raw):
    if len(raw) != 8:
        raise ValueError("not 8 bytes")
    return struct.unpack("<d", raw)[0]


def as_string_set(raw):
    total, pos = read_varint(raw, 0)
    if pos + total != len(raw):
        raise ValueError("size mismatch")
    items = []
    while pos < len(raw):
        item, pos = read_chunk(raw, pos)
        items.append(item.decode("utf-8"))
    return items


READERS = {"string": as_string, "int": as_int, "bool": as_bool, "float": as_float,
           "double": as_double, "string set": as_string_set, "bytes": as_bytes, "hex": bytes}


def read_as(raw, kind):
    """Value of raw read as kind; raises ValueError/UnicodeDecodeError if it doesn't fit."""
    return READERS[kind](raw)


def guess(raw):
    """Most likely type of a value."""
    if raw == b"\x00":
        return "int"  # also false or "" - the detail view lists every reading
    try:
        if _printable(as_string(raw)):
            return "string"
    except (ValueError, UnicodeDecodeError):
        pass
    try:
        items = as_string_set(raw)
        if items and all(_printable(i) for i in items):
            return "string set"
    except (ValueError, UnicodeDecodeError):
        pass
    if len(raw) == 1 and raw[0] <= 1:
        return "bool"
    try:
        as_int(raw)
        return "int"
    except ValueError:
        pass
    if len(raw) == 4:
        return "float"
    if len(raw) == 8:
        return "double"
    try:
        as_bytes(raw)
        return "bytes"
    except ValueError:
        return "hex"


def readings(raw):
    """[(type, value)] for every type the bytes can be read as."""
    out = []
    for kind in TYPES[1:]:
        try:
            out.append((kind, read_as(raw, kind)))
        except (ValueError, UnicodeDecodeError):
            pass
    return out


def fmt(kind, value, pretty=False):
    """Text for a value read as kind. pretty=True formats JSON and dumps bytes in full."""
    if kind == "bool":
        return "true" if value else "false"
    if kind in ("float", "double"):
        return repr(value)
    if kind == "string set":
        return json.dumps(value, ensure_ascii=False, indent=2 if pretty else None)
    if kind in ("bytes", "hex"):
        return hexdump(value) if pretty else value.hex(" ")
    if kind == "string" and pretty and value.lstrip()[:1] in ("{", "["):
        try:
            return json.dumps(json.loads(value), indent=2, ensure_ascii=False)
        except ValueError:
            pass
    return str(value)


def show(raw, kind="auto", pretty=False):
    """(type used, text) for raw shown as kind ("auto" = guess)."""
    if kind == "auto":
        kind = guess(raw)
    try:
        return kind, fmt(kind, read_as(raw, kind), pretty)
    except (ValueError, UnicodeDecodeError):
        return kind, f"(can't be read as {kind})"


def json_value(raw, kind="auto"):
    """Value as a JSON-friendly Python object, for export."""
    if kind == "auto":
        kind = guess(raw)
    try:
        value = read_as(raw, kind)
    except (ValueError, UnicodeDecodeError):
        return raw.hex()
    return value.hex() if isinstance(value, bytes) else value


def time_hint(value):
    """"2026-10-21 14:03:11 (ms)" if an int looks like a Unix timestamp, else "".
    Covers 2001-2286 in seconds or milliseconds."""
    from datetime import datetime
    for div, unit in ((1, "s"), (1000, "ms")):
        if 1_000_000_000 <= value / div < 10_000_000_000:
            return datetime.fromtimestamp(value / div).strftime("%Y-%m-%d %H:%M:%S") + f" ({unit})"
    return ""


def hexdump(data, width=16):
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:08x}  {chunk.hex(' '):<{width * 3}} {text}")
    return "\n".join(lines) or "(empty)"

"""Tests for the MMKV reader. Files are built here the way MMKV writes them.

Run:  .venv/bin/python -m unittest discover -s tests -v
"""

import os
import struct
import sys
import unittest
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mmkv_model as mm  # noqa: E402

try:
    import cryptography  # noqa: F401
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
needs_crypto = unittest.skipUnless(HAS_CRYPTO, "needs cryptography (in the .venv)")


def varint(n):
    n &= (1 << 64) - 1
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def chunk(data):
    return varint(len(data)) + data


# Values as MMKV encodes them (before the outer length prefix).
def enc_string(s):
    return chunk(s.encode())


def enc_set(items):
    body = b"".join(chunk(i.encode()) for i in items)
    return varint(len(body)) + body


def build(pairs, iv=b"\0" * 16, flags=0, version=4, crypt_key=None, page=4096, header=True):
    """(data file, .crc file) for pairs [(key, encoded value)], appended in order."""
    payload = varint(0x00FFFFFF) + b"".join(chunk(k.encode()) + chunk(v) for k, v in pairs)
    if crypt_key:
        payload = mm.encrypt(payload, crypt_key, mm.Meta(version=4, iv=iv))
    data = struct.pack("<I", len(payload) if header else 0) + payload
    data += b"\0" * (page - len(data))
    meta = bytearray(page)
    struct.pack_into("<III", meta, 0, zlib.crc32(payload), version, 1)
    meta[12:28] = iv
    struct.pack_into("<I", meta, 28, len(payload))
    struct.pack_into("<Q", meta, 104, flags)
    return data, bytes(meta)


class Parsing(unittest.TestCase):
    def test_last_write_wins_and_empty_value_deletes(self):
        data, meta = build([("a", varint(1)), ("b", enc_string("x")), ("a", varint(2)),
                            ("b", b""), ("c", b"\x01")])
        store = mm.parse_store(data, meta)
        self.assertEqual(list(store.entries), ["a", "c"])
        self.assertEqual(mm.as_int(store.entries["a"].raw), 2)
        self.assertEqual(store.entries["a"].writes, 2)
        self.assertEqual(store.deleted, 1)
        self.assertTrue(store.crc_ok)

    def test_size_from_meta_when_header_is_zero(self):
        # Recent MMKV versions keep the size only in the .crc file.
        data, meta = build([("a", varint(1))], header=False)
        self.assertEqual(list(mm.parse_store(data, meta).entries), ["a"])

    def test_empty_store(self):
        data, meta = build([])
        self.assertEqual(mm.parse_store(data, meta).entries, {})

    def test_crc_mismatch_is_reported(self):
        data, meta = build([("a", varint(1))])
        self.assertFalse(mm.parse_store(data, b"\x00\x00\x00\x00" + meta[4:]).crc_ok)

    def test_works_without_crc_file(self):
        data, _ = build([("k", enc_string("v"))])
        store = mm.parse_store(data)
        self.assertIsNone(store.crc_ok)
        self.assertEqual(mm.as_string(store.entries["k"].raw), "v")

    def test_key_expiry_strips_timestamp(self):
        data, meta = build([("k", enc_string("v") + struct.pack("<I", 1700000000)),
                            ("n", varint(5) + struct.pack("<I", 0))], flags=mm.FLAG_KEY_EXPIRE)
        store = mm.parse_store(data, meta)
        self.assertEqual(store.entries["k"].expire, 1700000000)
        self.assertEqual(mm.as_string(store.entries["k"].raw), "v")
        self.assertEqual(store.entries["n"].expire, 0)

    @needs_crypto
    def test_encrypted_needs_key(self):
        iv = bytes(range(16))
        data, meta = build([("token", enc_string("secret"))], iv=iv, crypt_key="my-key")
        with self.assertRaises(mm.MMKVError):
            mm.parse_store(data, meta)
        store = mm.parse_store(data, meta, crypt_key="my-key")
        self.assertEqual(mm.as_string(store.entries["token"].raw), "secret")
        self.assertTrue(store.encrypted)

    @needs_crypto
    def test_old_encrypted_files_use_key_as_iv(self):
        key = "0123456789abcdef"
        data, meta = build([("a", varint(7))], iv=key.encode(), crypt_key=key, version=1)
        store = mm.parse_store(data, meta[:12] + b"\0" * 16 + meta[28:], crypt_key=key)
        self.assertEqual(mm.as_int(store.entries["a"].raw), 7)

    def test_garbage_is_rejected(self):
        with self.assertRaises(mm.MMKVError):
            mm.parse_store(struct.pack("<I", 100) + b"\x01")


class Values(unittest.TestCase):
    def test_guesses(self):
        cases = [
            (enc_string("hello"), "string"),
            (enc_string('{"a": 1}'), "string"),
            (enc_set(["x", "y"]), "string set"),
            (b"\x01", "bool"),
            (varint(300), "int"),
            (varint(-1), "int"),
            (varint(1_700_000_000_000), "int"),
            (struct.pack("<f", 1.5), "float"),
            (struct.pack("<d", 3.25), "double"),
            (chunk(b"\x00\xff\x10\x20"), "bytes"),
            (b"\x00", "int"),
        ]
        for raw, kind in cases:
            with self.subTest(raw=raw):
                self.assertEqual(mm.guess(raw), kind)

    def test_negative_int32_reads_back(self):
        self.assertEqual(mm.as_int(varint(-42)), -42)

    def test_show_and_pretty_json(self):
        self.assertEqual(mm.show(enc_string('{"a":1}'), pretty=True), ("string", '{\n  "a": 1\n}'))
        self.assertEqual(mm.show(b"\x01"), ("bool", "true"))
        self.assertEqual(mm.show(b"\x01", "int"), ("int", "1"))
        self.assertEqual(mm.show(varint(300), "float"), ("float", "(can't be read as float)"))
        self.assertEqual(mm.show(enc_set(["a"])), ("string set", '["a"]'))

    def test_readings_list_every_fit(self):
        kinds = [k for k, _ in mm.readings(b"\x00")]
        self.assertEqual(kinds, ["string", "int", "bool", "string set", "bytes", "hex"])

    def test_json_value(self):
        self.assertEqual(mm.json_value(enc_set(["a", "b"])), ["a", "b"])
        self.assertEqual(mm.json_value(chunk(b"\x01\x02")), "0102")
        self.assertEqual(mm.json_value(varint(5)), 5)


class TimeHint(unittest.TestCase):
    def test_seconds_and_millis(self):
        self.assertTrue(mm.time_hint(1792584812761).endswith("(ms)"))
        self.assertTrue(mm.time_hint(1792584812).endswith("(s)"))
        self.assertEqual(mm.time_hint(5087), "")


class InspectorHelpers(unittest.TestCase):
    def test_store_label(self):
        from mmkv_inspector import App
        base = "/data/user/0/com.x/"
        self.assertEqual(App._store_label(base + "files/mmkv/mmkv.default", base), "mmkv.default")
        self.assertEqual(App._store_label(base + "files/custom/prefs", base), "files/custom/prefs")


class Writing(unittest.TestCase):
    def roundtrip(self, data, meta, changes, crypt_key=None):
        store = mm.parse_store(data, meta, crypt_key)
        mm.apply_changes(store, changes)
        new_data, new_meta = mm.build_files(store, data, meta, crypt_key)
        return mm.parse_store(new_data, new_meta, crypt_key), new_data, new_meta

    def test_set_add_delete_and_compact(self):
        data, meta = build([("a", varint(1)), ("a", varint(2)), ("b", enc_string("x")), ("c", b"\x01")])
        store, new_data, new_meta = self.roundtrip(
            data, meta, [("a", varint(3)), ("d", enc_string("new")), ("c", None)])
        self.assertEqual({k: e.raw for k, e in store.entries.items()},
                         {"a": varint(3), "b": enc_string("x"), "d": enc_string("new")})
        self.assertTrue(store.crc_ok)
        self.assertEqual(store.total_writes, 3)  # compacted: one write per key
        self.assertEqual(len(new_data), len(data))
        self.assertEqual(mm.parse_meta(new_meta).sequence, mm.parse_meta(meta).sequence + 1)
        self.assertEqual(struct.unpack_from("<I", new_data, 0)[0], store.size)

    def test_keeps_prefix_and_zero_header(self):
        data, meta = build([("a", varint(1))], header=False)
        _, new_data, new_meta = self.roundtrip(data, meta, [("a", varint(9))])
        self.assertEqual(struct.unpack_from("<I", new_data, 0)[0], 0)
        self.assertEqual(new_data[4:8], varint(0x00FFFFFF))
        m = mm.parse_meta(new_meta)
        self.assertEqual(struct.unpack_from("<II", new_meta, 32), (m.actual_size, m.crc))

    def test_unchanged_store_rebuilds_identically(self):
        data, meta = build([("a", varint(1)), ("b", enc_string("hi"))])
        _, new_data, new_meta = self.roundtrip(data, meta, [])
        self.assertEqual(new_data, data)
        self.assertEqual(new_meta[:8], meta[:8])

    def test_grows_by_whole_pages(self):
        data, meta = build([("a", varint(1))])
        store, new_data, _ = self.roundtrip(data, meta, [("big", enc_string("x" * 5000))])
        self.assertEqual(len(new_data), 8192)
        self.assertEqual(len(mm.as_string(store.entries["big"].raw)), 5000)

    def test_delete_everything(self):
        data, meta = build([("a", varint(1))])
        store, new_data, _ = self.roundtrip(data, meta, [("a", None)])
        self.assertEqual(store.entries, {})
        self.assertEqual(store.size, 0)

    def test_keeps_expiry(self):
        data, meta = build([("k", enc_string("v") + struct.pack("<I", 1700000000))], flags=mm.FLAG_KEY_EXPIRE)
        store, _, _ = self.roundtrip(data, meta, [("k", enc_string("w")), ("n", varint(1))])
        self.assertEqual(store.entries["k"].expire, 1700000000)
        self.assertEqual(store.entries["n"].expire, 0)
        self.assertEqual(mm.as_string(store.entries["k"].raw), "w")

    @needs_crypto
    def test_encrypted_roundtrip(self):
        data, meta = build([("t", enc_string("old"))], iv=bytes(range(16)), crypt_key="k")
        store, new_data, new_meta = self.roundtrip(data, meta, [("t", enc_string("new"))], crypt_key="k")
        self.assertEqual(mm.as_string(store.entries["t"].raw), "new")
        self.assertNotIn(b"new", new_data)
        with self.assertRaises(mm.MMKVError):
            mm.parse_store(new_data, new_meta)

    def test_needs_crc_file(self):
        data, _ = build([("a", varint(1))])
        with self.assertRaises(mm.MMKVError):
            mm.build_files(mm.parse_store(data), data, None)


class Encoding(unittest.TestCase):
    def test_encode_matches_mmkv(self):
        self.assertEqual(mm.encode_value("string", "héllo "), enc_string("héllo "))
        self.assertEqual(mm.encode_value("int", "-42"), varint(-42))
        self.assertEqual(len(mm.encode_value("int", "-1")), 10)
        self.assertEqual(mm.encode_value("int", "0x1F"), varint(31))
        self.assertEqual(mm.encode_value("bool", "True"), b"\x01")
        self.assertEqual(mm.encode_value("float", "1.5"), struct.pack("<f", 1.5))
        self.assertEqual(mm.encode_value("double", "2.25"), struct.pack("<d", 2.25))
        self.assertEqual(mm.encode_value("string set", '["a", "b"]'), enc_set(["a", "b"]))
        self.assertEqual(mm.encode_value("bytes", "0a ff"), chunk(b"\x0a\xff"))
        self.assertEqual(mm.encode_value("hex", "01"), b"\x01")

    def test_bad_input(self):
        for kind, text in [("int", "abc"), ("bool", "maybe"), ("float", "x"), ("string set", "[1]"),
                           ("bytes", "zz"), ("hex", ""), ("int", str(1 << 64))]:
            with self.subTest(kind=kind, text=text), self.assertRaises(ValueError):
                mm.encode_value(kind, text)

    def test_edit_text_roundtrips(self):
        for kind, raw in [("string", enc_string('{"a": 1}')), ("int", varint(-5)), ("bool", b"\x00"),
                          ("double", struct.pack("<d", 0.1)), ("float", struct.pack("<f", 1.5)),
                          ("string set", enc_set(["x"])), ("bytes", chunk(b"\x01\x02"))]:
            with self.subTest(kind=kind):
                self.assertEqual(mm.encode_value(kind, mm.edit_text(raw, kind)), raw)

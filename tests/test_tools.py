"""Tests for the parts of Room SQL and Net Inspector that don't need a device.

Run:  .venv/bin/python -m unittest discover -s tests -v
"""

import base64
import os
import sys
import tempfile
import tkinter as tk
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import net_model as nm  # noqa: E402
import sql_editor as se  # noqa: E402
from adb_common import DeviceBase  # noqa: E402
from room_sql_gui import History, sort_key  # noqa: E402


class SqlParsing(unittest.TestCase):
    def test_split_statements_keeps_semicolons_in_strings(self):
        sql = "-- hi\nSELECT 1;\nUPDATE t SET a=';' WHERE b=1;\nselect 2"
        self.assertEqual(se.split_statements(sql),
                         ["-- hi\nSELECT 1;", "UPDATE t SET a=';' WHERE b=1;", "select 2"])

    def test_first_keyword_skips_comments(self):
        self.assertEqual(se.first_keyword("/* note */ -- x\n  delete from t"), "DELETE")
        self.assertEqual(se.first_keyword("   "), "")

    def test_strip_comments_leaves_strings(self):
        self.assertEqual(se.strip_comments("SELECT '--not a comment' -- real").strip(),
                         "SELECT '--not a comment'")

    def test_is_write(self):
        reads = ["SELECT * FROM t", "EXPLAIN QUERY PLAN SELECT 1", "PRAGMA table_info(t)",
                 "WITH x AS (SELECT 1) SELECT * FROM x", "SELECT 'DELETE' FROM t",
                 "-- UPDATE\nSELECT 1"]
        writes = ["INSERT INTO t VALUES (1)", "update t set a = 1", "DELETE FROM t",
                  "PRAGMA user_version = 3", "PRAGMA optimize", "CREATE TABLE x (a)",
                  "WITH x AS (SELECT 1) DELETE FROM t WHERE a IN x", "DROP TABLE t"]
        for s in reads:
            self.assertFalse(se.is_write(s), s)
        for s in writes:
            self.assertTrue(se.is_write(s), s)

    def test_single_table_select(self):
        table, sql = se.single_table_select("SELECT * FROM radio_stations s WHERE s.rpid > 3 LIMIT 5")
        self.assertEqual(table, "radio_stations")
        self.assertTrue(sql.startswith('SELECT s.rowid AS "__rowid__", * FROM'))
        table, sql = se.single_table_select('-- c\nselect a, b from "t" order by a;')
        self.assertEqual(table, "t")
        self.assertIn('"t".rowid', sql)
        for s in ["SELECT * FROM a JOIN b ON a.x = b.x", "SELECT count(*) FROM t GROUP BY a",
                  "SELECT DISTINCT a FROM t", "SELECT 1 UNION SELECT 2", "SELECT 1",
                  "WITH x AS (SELECT 1) SELECT * FROM x", "SELECT * FROM a, b"]:
            self.assertIsNone(se.single_table_select(s), s)

    def test_single_table_select_query_runs(self):
        import sqlite3
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE t (a TEXT, b INTEGER)")
        conn.execute("INSERT INTO t VALUES ('x', 1), ('y', 2)")
        _, sql = se.single_table_select("SELECT b, a FROM t WHERE b > 1")
        self.assertEqual(conn.execute(sql).fetchall(), [(2, 2, "y")])

    def test_parse_value_and_literal(self):
        self.assertEqual(se.parse_value("42", "INTEGER"), 42)
        self.assertEqual(se.parse_value("4.5", "REAL"), 4.5)
        self.assertEqual(se.parse_value("abc", "INTEGER"), "abc")
        self.assertEqual(se.parse_value("007", "TEXT"), "007")
        self.assertIsNone(se.parse_value("NULL", "TEXT"))
        self.assertEqual(se.sql_literal("it's"), "'it''s'")
        self.assertEqual(se.sql_literal(None), "NULL")
        self.assertEqual(se.sql_literal(3), "3")

    def test_token_classes(self):
        sql = "SELECT upper(a) FROM t WHERE b = 'x -- y' AND c > 10 /* z */"
        kinds = {m.group(): m.lastgroup for m in se.TOKEN_RE.finditer(sql)}
        self.assertEqual(kinds["'x -- y'"], "string")
        self.assertEqual(kinds["/* z */"], "comment")
        self.assertEqual(kinds["10"], "number")
        self.assertEqual(kinds["SELECT"], "word")


class Autocomplete(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.root = tk.Tk()
        except tk.TclError as exc:
            raise unittest.SkipTest(f"no display: {exc}")
        cls.root.withdraw()
        cls.text = tk.Text(cls.root)
        cls.ac = se.SqlAutocomplete(cls.text)
        cls.ac.schema = {"radio_stations": ["rpid", "short_name", "long_name"],
                         "radio_station_app_links": ["station_rpuid", "app_package_id"],
                         "search_history": ["query", "timestamp"]}

    @classmethod
    def tearDownClass(cls):
        cls.root.destroy()

    def words(self, sql, cursor="end-1c", force=False):
        self.text.delete("1.0", "end")
        self.text.insert("1.0", sql)
        self.text.mark_set("insert", cursor)
        return [w for w, _ in self.ac.candidates(force)[1]]

    def test_tables_after_from(self):
        self.assertEqual(self.words("SELECT * FROM radio_st"),
                         ["radio_station_app_links", "radio_stations"])

    def test_columns_after_alias(self):
        self.assertEqual(self.words("SELECT * FROM radio_stations s WHERE s.lo"), ["long_name"])
        self.assertEqual(self.words("SELECT * FROM radio_stations s JOIN radio_station_app_links l ON l.app"),
                         ["app_package_id"])

    def test_alias_defined_later(self):
        self.assertEqual(self.words("SELECT s.sh FROM radio_stations s", cursor="1.11"), ["short_name"])

    def test_aliases_do_not_leak_between_statements(self):
        self.assertEqual(self.words("SELECT * FROM search_history h; SELECT h."), [])

    def test_keywords_and_functions(self):
        self.assertIn("count(", self.words("select co"))
        self.assertEqual(self.words("SEL"), ["SELECT"])
        self.assertEqual(self.words("SELECT"), [])  # already fully typed


class SqlAppHelpers(unittest.TestCase):
    def test_history(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "h.json")
            h = History(path)
            for q in ("SELECT 1", "SELECT 2", "SELECT 1"):
                h.add(q)
            self.assertEqual(h.items, ["SELECT 2", "SELECT 1"])  # duplicates move to the end
            self.assertEqual(History(path).items, h.items)       # saved to disk
            self.assertEqual(h.step(-1, "draft"), "SELECT 1")
            self.assertEqual(h.step(-1, "x"), "SELECT 2")
            self.assertEqual(h.step(-1, "x"), "SELECT 2")         # stops at the oldest
            self.assertEqual(h.step(1, "x"), "SELECT 1")
            self.assertEqual(h.step(1, "x"), "draft")            # back to what was typed

    def test_sort_key_mixed_types(self):
        values = ["b", None, 3, b"\x00", "A", 1.5]
        self.assertEqual(sorted(values, key=sort_key), [None, 1.5, 3, "A", "b", b"\x00"])


class FakeDevice(DeviceBase):
    def __init__(self, outputs):
        super().__init__("fake")
        self.outputs = outputs

    def shell(self, cmd, timeout=120):
        return 0, self.outputs.get(cmd, ""), ""


class AdbHelpers(unittest.TestCase):
    def test_package_uids(self):
        dev = FakeDevice({"pm list packages -U": "package:android uid:1000,1001000\n"
                                                 "package:com.a uid:10123\npackage:com.b uid:1010123\n"})
        self.assertEqual(dev.package_uids(),
                         {1000: "android", 1001000: "android", 10123: "com.a", 1010123: "com.b"})

    def test_users_current_first(self):
        dev = FakeDevice({"am get-current-user": "10\n",
                          "pm list users": "Users:\n\tUserInfo{0:Driver:813} running\n\tUserInfo{10:Driver:412} running\n"})
        self.assertEqual(dev.users(), [10, 0])


PROC_NET = """  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  2000        0 17752 1 0
   1: 0000000000000000FFFF00000100007F:A1B2 0000000000000000FFFF00000100007F:1F90 01 00000000:00000000 00:00000000 00000000 1010237        0 60001 1 0
   2: 0000000000000000FFFF00000100007F:1F90 0000000000000000FFFF00000100007F:A1B2 01 00000000:00000000 00:00000000 00000000  2000        0 60002 1 0
   3: 0000000000000000FFFF00000100007F:A1B4 0000000000000000FFFF00000100007F:1F90 06 00000000:00000000 00:00000000 00000000     0        0 0 1 0
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:C350 0100007F:1F90 01 00000000:00000000 00:00000000 00000000 10234        0 60003 1 0
   1: 1002000A:BF96 0470D9AC:01BB 01 00000000:00000082 00:00000000 00000000 1010198        0 59346 1 0
"""


class AppAttribution(unittest.TestCase):
    def test_parse_proc_net(self):
        found = nm.parse_proc_net(PROC_NET, 8080)
        # app sockets to the proxy only: not adbd's side, not LISTEN/TIME_WAIT, not other ports
        self.assertEqual(sorted(found.values()), [10234, 1010237])

    def test_pick_device_conn(self):
        conns = [{"lo": 10.0, "hi": 10.3, "uid": 1, "used": False},
                 {"lo": 10.3, "hi": 10.6, "uid": 2, "used": False}]
        dev, sure = nm.pick_device_conn(10.1, conns)
        self.assertEqual((dev["uid"], sure), (1, False))  # windows overlap within slack
        dev["used"] = True
        dev, sure = nm.pick_device_conn(10.5, conns)
        self.assertEqual((dev["uid"], sure), (2, True))   # only one left
        dev["used"] = True
        self.assertEqual(nm.pick_device_conn(10.5, conns), (None, False))
        self.assertEqual(nm.pick_device_conn(20.0, [{"lo": 1, "hi": 2, "uid": 3, "used": False}]),
                         (None, False))

    def test_pick_prefers_majority_app(self):
        conns = [{"lo": 5, "hi": 5.3, "uid": 7, "used": False},
                 {"lo": 5, "hi": 5.3, "uid": 7, "used": False},
                 {"lo": 5, "hi": 5.3, "uid": 9, "used": False}]
        dev, sure = nm.pick_device_conn(5.1, conns)
        self.assertEqual((dev["uid"], sure), (7, False))

    def test_uid_label(self):
        pk = {1010237: "com.radio"}
        self.assertEqual(nm.uid_label(1010237, pk), "com.radio")
        self.assertEqual(nm.uid_label(0, pk), "root")
        self.assertEqual(nm.uid_label(1001000, pk), "system (uid 1001000)")
        self.assertEqual(nm.uid_label(1012345, pk), "uid 1012345")


def make_flow(**kw):
    ev = {"id": "f1", "conn": "c1", "ts": 1_700_000_000, "method": "GET",
          "url": "https://api.example.com/v1/items?x=1", "host": "api.example.com",
          "path": "/v1/items?x=1", "http_version": "HTTP/2.0",
          "headers": [("accept", "application/json")], "body": None}
    ev.update(kw)
    return nm.Flow(ev)


class NetModel(unittest.TestCase):
    def test_body_as_text(self):
        self.assertEqual(nm.body_as_text(b'{"a":1}', "application/json", False), '{\n  "a": 1\n}')
        self.assertIn("binary", nm.body_as_text(b"\x89PNG\x00\x01", "image/png", False))
        self.assertIn("only the start", nm.body_as_text(b"hi", "text/plain", True))
        self.assertEqual(nm.body_as_text(b"", "text/plain", False), "")

    def test_filters(self):
        f = make_flow()
        f.set_response({"status": 404, "content_type": "application/json",
                        "body": nm.make_body(b'{"msg": "Radio Deejay"}'), "duration": 0.1})
        f.app = "com.radio"
        self.assertTrue(f.matches(["example", "get"]))
        self.assertTrue(f.matches(["404"], show="Errors"))
        self.assertTrue(f.matches([], show="JSON"))
        self.assertFalse(f.matches([], show="Images"))
        self.assertFalse(f.matches([], hidden_hosts={"api.example.com"}))
        self.assertFalse(f.matches([], app="com.other"))
        self.assertTrue(f.matches([], app="com.radio"))
        self.assertFalse(f.matches(["deejay"]))
        self.assertTrue(f.matches(["deejay"], in_bodies=True))

    def test_row_and_app_label(self):
        f = make_flow()
        self.assertEqual(f.row()[3:5], ("…", "…"))  # pending response, app not known yet
        f.app, f.app_sure = "com.radio", False
        self.assertEqual(f.app_label(), "com.radio ?")

    def test_har_round_trip(self):
        ok = make_flow(body=nm.make_body(b'{"q": 1}'),
                       headers=[("content-type", "application/json")])
        ok.set_response({"status": 200, "reason": "OK", "http_version": "HTTP/2.0",
                         "headers": [("content-type", "image/png")],
                         "body": nm.make_body(b"\x89PNG\r\n\x1a\n\x00binary"),
                         "content_type": "image/png", "duration": 0.25})
        ok.app = "com.radio"
        failed = make_flow(id="f2", error="connection reset")
        tls = make_flow(id="f3", method="TLS")
        har = nm.to_har([ok, failed, tls])
        self.assertEqual(len(har["log"]["entries"]), 2)  # TLS failures aren't HTTP calls
        self.assertEqual(har["log"]["entries"][0]["response"]["content"]["encoding"], "base64")
        back = nm.from_har(har)
        self.assertEqual(back[0].url, ok.url)
        self.assertEqual(back[0].host, "api.example.com")
        self.assertEqual(back[0].path, "/v1/items?x=1")
        self.assertEqual(nm.decode_body(back[0].resp_body), b"\x89PNG\r\n\x1a\n\x00binary")
        self.assertEqual(nm.decode_body(back[0].req_body), b'{"q": 1}')
        self.assertEqual((back[0].status, back[0].app, round(back[0].duration, 2)), (200, "com.radio", 0.25))
        self.assertEqual(back[1].error, "connection reset")
        self.assertAlmostEqual(back[0].ts, ok.ts)

    def test_curl(self):
        f = make_flow(method="POST", body=nm.make_body(b"a=1"),
                      headers=[("content-type", "x"), ("content-length", "3"), (":authority", "h")])
        self.assertEqual(f.curl(), "curl -X POST 'https://api.example.com/v1/items?x=1' "
                                   "-H 'content-type: x' --data-binary a=1")

    def test_make_body(self):
        b = nm.make_body(b"abc")
        self.assertEqual((b["size"], base64.b64decode(b["b64"])), (3, b"abc"))


if __name__ == "__main__":
    unittest.main()

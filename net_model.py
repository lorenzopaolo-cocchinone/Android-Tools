"""Data model for Net Inspector: captured calls, filtering, HAR files and app attribution.

No Tk in here, so it can be unit tested.
"""

import base64
import datetime
import json
import shlex
from collections import Counter
from urllib.parse import urlsplit

MAX_SHOWN_TEXT = 300_000
TEXT_TYPES = ("json", "xml", "html", "text", "javascript", "x-www-form-urlencoded", "graphql")
SHOW_OPTIONS = ("All", "Errors", "JSON", "Images", "Other")


def human_size(n):
    if n is None:
        return ""
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / 1024 / 1024:.1f} MB"


def decode_body(b):
    return base64.b64decode(b["b64"]) if b else b""


def make_body(data, truncated=False):
    return {"b64": base64.b64encode(data).decode(), "size": len(data), "truncated": truncated}


def as_text(data, content_type):
    """The body as text, or None if it looks binary."""
    if not data:
        return ""
    ct = (content_type or "").lower()
    if ct and not any(t in ct for t in TEXT_TYPES):
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def body_as_text(data, content_type, truncated):
    """Text to show for a body: formatted JSON, plain text, or a note for binary data."""
    if not data:
        return ""
    text = as_text(data, content_type)
    if text is None:
        return f"<binary {content_type or 'data'}, {human_size(len(data))} — use “Save body…”>"
    if "json" in (content_type or "").lower() or text.lstrip()[:1] in ("{", "["):
        try:
            text = json.dumps(json.loads(text), indent=2, ensure_ascii=False)
        except ValueError:
            pass
    if len(text) > MAX_SHOWN_TEXT:
        text = text[:MAX_SHOWN_TEXT] + "\n… (cut off, use “Save body…” for all of it)"
    if truncated:
        text += "\n… (body over 2 MB, only the start was captured)"
    return text


def header(headers, name):
    name = name.lower()
    return next((v for k, v in headers if k.lower() == name), "")


class Flow:
    """One HTTP call (or a failed TLS handshake)."""

    def __init__(self, ev):
        self.id = ev["id"]
        self.conn = ev.get("conn")
        self.ts = ev["ts"]
        self.method = ev.get("method", "")
        self.url = ev.get("url", "")
        self.host = ev.get("host", "")
        self.path = ev.get("path", "")
        self.http_version = ev.get("http_version", "")
        self.req_headers = ev.get("headers", [])
        self.req_body = ev.get("body")
        self.status = None
        self.reason = ""
        self.resp_headers = []
        self.resp_body = None
        self.content_type = ""
        self.duration = None
        self.error = ev.get("error")
        self.app = None        # package name, once known
        self.app_sure = True   # False when the app guess is ambiguous
        self.n = 0
        self._search_text = None

    def set_response(self, ev):
        self.status, self.reason = ev["status"], ev.get("reason", "")
        self.http_version = ev.get("http_version", self.http_version)
        self.resp_headers, self.resp_body = ev.get("headers", []), ev.get("body")
        self.content_type = ev.get("content_type", "")
        self.duration = ev.get("duration")
        self._search_text = None

    @property
    def is_error(self):
        return bool(self.error) or self.method == "TLS" or (self.status or 0) >= 400

    def kind(self):
        ct = self.content_type.lower()
        if "json" in ct:
            return "JSON"
        if ct.startswith("image/"):
            return "Images"
        return "Other"

    def app_label(self):
        if self.app is None:
            return "…" if self.conn else ""
        return self.app if self.app_sure else f"{self.app} ?"

    def row(self):
        t = datetime.datetime.fromtimestamp(self.ts).strftime("%H:%M:%S")
        if self.error:
            status = "ERR"
        elif self.status is None:
            status = "…"
        else:
            status = str(self.status)
        ct = self.content_type.split(";")[0].split("/")[-1] if self.content_type else ""
        size = human_size(self.resp_body["size"]) if self.resp_body else ""
        dur = f"{self.duration * 1000:.0f} ms" if self.duration is not None else ""
        return (self.n, t, self.method, status, self.app_label(), self.host, self.path, ct, size, dur)

    def tag(self):
        if self.is_error and (self.error or self.method == "TLS"):
            return "error"
        if self.status is None:
            return "pending"
        if self.status >= 400:
            return "bad"
        if self.status >= 300:
            return "redirect"
        return ""

    def search_text(self):
        """Lower-case request + response bodies (text only), for 'search in bodies'."""
        if self._search_text is None:
            parts = []
            for body, ct in ((self.req_body, header(self.req_headers, "content-type")),
                             (self.resp_body, self.content_type)):
                text = as_text(decode_body(body)[:1_000_000], ct) if body else None
                if text:
                    parts.append(text.lower())
            self._search_text = "\n".join(parts)
        return self._search_text

    def matches(self, terms, show="All", app=None, hidden_hosts=(), in_bodies=False):
        if self.host in hidden_hosts:
            return False
        if app and self.app != app:
            return False
        if show == "Errors" and not self.is_error:
            return False
        if show in ("JSON", "Images", "Other") and self.kind() != show:
            return False
        hay = (f"{self.method} {self.url} {self.status} {self.content_type} "
               f"{self.error or ''} {self.app or ''}").lower()
        body = None
        for t in terms:
            if t in hay:
                continue
            if in_bodies:
                body = self.search_text() if body is None else body
                if t in body:
                    continue
            return False
        return True

    def curl(self):
        parts = ["curl", "-X", self.method, shlex.quote(self.url)]
        for k, v in self.req_headers:
            if k.lower() not in ("content-length", "host") and not k.startswith(":"):
                parts += ["-H", shlex.quote(f"{k}: {v}")]
        data = decode_body(self.req_body)
        if data:
            try:
                parts += ["--data-binary", shlex.quote(data.decode("utf-8"))]
            except UnicodeDecodeError:
                parts += ["--data-binary", "@body.bin"]
        return " ".join(parts)


# ---------- HAR (HTTP Archive) ----------

def _har_headers(headers):
    return [{"name": k, "value": v} for k, v in headers]


def _har_content(body, mime):
    data = decode_body(body)
    content = {"size": len(data), "mimeType": mime or ""}
    if data:
        text = as_text(data, mime)
        if text is not None:
            content["text"] = text
        else:
            content["text"], content["encoding"] = base64.b64encode(data).decode(), "base64"
    return content


def to_har(flows):
    entries = []
    for f in flows:
        if f.method == "TLS":
            continue  # not an HTTP call
        req_ct = header(f.req_headers, "content-type")
        req_data = decode_body(f.req_body)
        request = {"method": f.method, "url": f.url, "httpVersion": f.http_version or "HTTP/1.1",
                   "headers": _har_headers(f.req_headers), "queryString": [], "cookies": [],
                   "headersSize": -1, "bodySize": len(req_data)}
        if req_data:
            text = as_text(req_data, req_ct)
            request["postData"] = {"mimeType": req_ct,
                                   "text": text if text is not None else base64.b64encode(req_data).decode()}
            if text is None:
                request["postData"]["encoding"] = "base64"  # not in the HAR spec, but widely read
        if f.status is not None:
            response = {"status": f.status, "statusText": f.reason, "httpVersion": f.http_version,
                        "headers": _har_headers(f.resp_headers), "cookies": [],
                        "content": _har_content(f.resp_body, f.content_type), "redirectURL": "",
                        "headersSize": -1, "bodySize": f.resp_body["size"] if f.resp_body else 0}
        else:
            response = {"status": 0, "statusText": f.error or "", "httpVersion": "", "headers": [],
                        "cookies": [], "content": {"size": 0, "mimeType": ""}, "redirectURL": "",
                        "headersSize": -1, "bodySize": -1, "_error": f.error or "no response"}
        ms = (f.duration or 0) * 1000
        entries.append({
            "startedDateTime": datetime.datetime.fromtimestamp(f.ts, datetime.timezone.utc).isoformat(),
            "time": ms, "request": request, "response": response, "cache": {},
            "timings": {"send": 0, "wait": ms, "receive": 0}, "_app": f.app})
    return {"log": {"version": "1.2", "creator": {"name": "Net Inspector", "version": "1.0"},
                    "entries": entries}}


def from_har(har):
    flows = []
    for i, e in enumerate(har.get("log", {}).get("entries", [])):
        req, resp = e.get("request", {}), e.get("response", {})
        url = req.get("url", "")
        parts = urlsplit(url)
        host = parts.hostname or ""
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        post = req.get("postData") or {}
        req_data = (base64.b64decode(post["text"]) if post.get("encoding") == "base64"
                    else post.get("text", "").encode())
        ts = datetime.datetime.fromisoformat(e["startedDateTime"].replace("Z", "+00:00")).timestamp()
        f = Flow({"id": f"har{i}", "ts": ts, "method": req.get("method", ""), "url": url,
                  "host": host, "path": path, "http_version": req.get("httpVersion", ""),
                  "headers": [(h["name"], h["value"]) for h in req.get("headers", [])],
                  "body": make_body(req_data) if req_data else None})
        content = resp.get("content", {})
        if resp.get("status"):
            text = content.get("text", "")
            data = base64.b64decode(text) if content.get("encoding") == "base64" else text.encode()
            f.set_response({"status": resp["status"], "reason": resp.get("statusText", ""),
                            "http_version": resp.get("httpVersion", ""),
                            "headers": [(h["name"], h["value"]) for h in resp.get("headers", [])],
                            "body": make_body(data) if data else None,
                            "content_type": content.get("mimeType", ""),
                            "duration": (e.get("time") or 0) / 1000})
        else:
            f.error = resp.get("_error") or resp.get("statusText") or "no response"
        f.app = e.get("_app")
        flows.append(f)
    return flows


# ---------- Which app opened a connection ----------

LOOPBACK = {"0100007F", "0000000000000000FFFF00000100007F", "00000000000000000000000001000000"}
SKIP_STATES = {"0A", "06"}  # LISTEN, and TIME_WAIT (its uid is always 0)


def parse_proc_net(text, port):
    """From /proc/net/tcp(6) text, {(local_address, inode): uid} for sockets connected to
    127.0.0.1:<port> on the device - i.e. apps talking to the proxy via adb reverse."""
    want = f"{port:04X}"
    found = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 10 or ":" not in parts[2] or not parts[0].rstrip(":").isdigit():
            continue
        local, remote, state, uid, inode = parts[1], parts[2], parts[3], parts[7], parts[9]
        ip, rport = remote.rsplit(":", 1)
        if rport == want and ip in LOOPBACK and state not in SKIP_STATES:
            found[(local, inode)] = int(uid)
    return found


def pick_device_conn(ts, device_conns, slack=0.25):
    """Match a proxy connection that arrived at time ts to a device-side connection.

    device_conns: dicts with 'lo'/'hi' (the poll window in which the connection first
    appeared), 'uid' and 'used'. Returns (conn or None, sure). 'sure' is False when
    connections from different apps appeared in the same window."""
    candidates = [d for d in device_conns
                  if not d["used"] and d["lo"] - slack <= ts <= d["hi"] + slack]
    if not candidates:
        return None, False
    counts = Counter(d["uid"] for d in candidates)
    uid = counts.most_common(1)[0][0]
    best = min((d for d in candidates if d["uid"] == uid), key=lambda d: abs(d["hi"] - ts))
    return best, len(counts) == 1


def uid_label(uid, packages):
    if uid in packages:
        return packages[uid]
    if uid == 0:
        return "root"
    if uid % 100000 < 10000:
        return f"system (uid {uid})"
    return f"uid {uid}"

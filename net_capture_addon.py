"""mitmproxy add-on used by net_inspector.py.

Writes one JSON object per line to stdout for each request, response, error and
failed TLS handshake, so the GUI can show traffic live.
"""

import base64
import json
import sys
import time

MAX_BODY = 2 * 1024 * 1024  # bodies bigger than this are cut off


def emit(obj):
    sys.stdout.write("@@NET " + json.dumps(obj) + "\n")
    sys.stdout.flush()


def body(message):
    try:
        data = message.get_content(strict=False) or b""  # decompressed (gzip, br, …)
    except Exception:  # noqa: BLE001 - fall back to the raw bytes
        data = message.raw_content or b""
    return {"b64": base64.b64encode(data[:MAX_BODY]).decode(), "size": len(data),
            "truncated": len(data) > MAX_BODY}


class Capture:
    def client_connected(self, client):
        # Lets the GUI work out which app opened this connection.
        emit({"event": "conn", "conn": client.id, "ts": client.timestamp_start or time.time()})

    def request(self, flow):
        r = flow.request
        emit({"event": "request", "id": flow.id, "conn": flow.client_conn.id,
              "ts": r.timestamp_start, "method": r.method,
              "url": r.pretty_url, "host": r.pretty_host, "path": r.path,
              "http_version": r.http_version, "headers": list(r.headers.items(multi=True)),
              "body": body(r)})

    def response(self, flow):
        r = flow.response
        emit({"event": "response", "id": flow.id, "status": r.status_code, "reason": r.reason,
              "http_version": r.http_version, "headers": list(r.headers.items(multi=True)),
              "body": body(r), "content_type": r.headers.get("content-type", ""),
              "duration": (r.timestamp_end or time.time()) - flow.request.timestamp_start})

    def error(self, flow):
        emit({"event": "error", "id": flow.id, "error": flow.error.msg if flow.error else "error"})

    def tls_failed_client(self, data):
        # Usually means the app doesn't trust the proxy's certificate (or pins its own).
        server = data.context.server.address
        emit({"event": "tls_failed", "ts": time.time(), "conn": data.conn.id,
              "host": data.context.client.sni or (server[0] if server else "?"),
              "error": str(data.conn.error or "TLS handshake failed")})


addons = [Capture()]

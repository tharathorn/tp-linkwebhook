#!/usr/bin/env python3
import json
import os
import hmac
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from event_model import EventStore

MAX_BODY_BYTES = 1024 * 1024
REDACTED = "[redacted]"


def redact(value):
    if isinstance(value, dict):
        return {
            key: REDACTED if key.lower() in {"access_token", "shardsecret"} else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def create_server(
    host: str,
    port: int,
    webhook_path: str,
    webhook_secret: str,
    audit_path: Path,
    db_path: Path,
):
    write_lock = threading.Lock()
    store = EventStore(db_path)

    class Handler(BaseHTTPRequestHandler):
        def send_body(self, status: int, body: bytes, content_type: str = "text/plain"):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/health":
                self.send_body(200, b"ok")
                return
            self.send_body(404, b"not found")

        def do_POST(self):
            if self.path != webhook_path:
                self.send_body(404, b"not found")
                return

            supplied_secret = self.headers.get("Access_token", "")
            if not hmac.compare_digest(supplied_secret, webhook_secret):
                self.send_body(401, b"unauthorized")
                return

            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self.send_body(400, b"invalid content length")
                return

            if length > MAX_BODY_BYTES:
                self.send_body(413, b"payload too large")
                return

            body = self.rfile.read(length).decode("utf-8", errors="replace")
            try:
                payload = json.loads(body)
            except json.JSONDecodeError:
                payload = {"raw_body": body}
            sanitized_payload = redact(payload)
            sanitized_headers = redact(dict(self.headers))
            received_at = datetime.now(timezone.utc).isoformat()
            record = {
                "time": received_at,
                "client": self.client_address[0],
                "method": self.command,
                "path": self.path,
                "headers": sanitized_headers,
                "payload": sanitized_payload,
            }
            line = (json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8")

            with write_lock:
                fd = os.open(audit_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                with os.fdopen(fd, "ab") as stream:
                    stream.write(line)
                store.insert_raw_event(
                    received_at=received_at,
                    source_ip=self.headers.get("Cf-Connecting-Ip", self.client_address[0]),
                    payload=sanitized_payload,
                    headers=sanitized_headers,
                )

            self.send_body(200, b'{"ok":true}', "application/json")

        def log_message(self, _format, *_args):
            return

    return ThreadingHTTPServer((host, port), Handler)


def main():
    host = os.environ.get("WEBHOOK_HOST", "127.0.0.1")
    port = int(os.environ.get("WEBHOOK_PORT", "18080"))
    webhook_path = os.environ["WEBHOOK_PATH"]
    webhook_secret = os.environ["WEBHOOK_SECRET"]
    audit_path = Path(os.environ.get("WEBHOOK_LOG", "/var/log/omada-webhook/requests.ndjson"))
    db_path = Path(os.environ.get("WEBHOOK_DB", "/var/lib/omada-webhook/events.sqlite3"))

    server = create_server(host, port, webhook_path, webhook_secret, audit_path, db_path)
    server.serve_forever()


if __name__ == "__main__":
    main()

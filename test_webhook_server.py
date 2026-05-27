import http.client
import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from webhook_server import create_server


class WebhookServerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.audit_path = Path(self.tmp.name) / "requests.ndjson"
        self.db_path = Path(self.tmp.name) / "events.sqlite3"
        self.server = create_server(
            "127.0.0.1",
            0,
            "/webhooks/omada/test-token",
            "expected-shared-secret",
            self.audit_path,
            self.db_path,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.tmp.cleanup()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        response_body = response.read()
        connection.close()
        return response.status, response_body

    def test_authorized_webhook_is_redacted_and_stored_in_sqlite(self):
        payload = {
            "Site": "Omada Workshop",
            "Controller": "Omada _Presale",
            "description": "This is a webhook message from Omada Controller",
            "timestamp": 1779791144791,
            "shardSecret": "expected-shared-secret",
            "text": ['{"operation":"Device disconnected."}'],
        }
        status, body = self.request(
            "POST",
            "/webhooks/omada/test-token",
            body=json.dumps(payload),
            headers={
                "Content-Type": "application/json",
                "Access_token": "expected-shared-secret",
            },
        )

        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"ok": True})

        audit = json.loads(self.audit_path.read_text(encoding="utf-8"))
        self.assertEqual(audit["headers"]["Access_token"], "[redacted]")
        self.assertNotIn("expected-shared-secret", self.audit_path.read_text(encoding="utf-8"))

        with sqlite3.connect(self.db_path) as db:
            row = db.execute(
                "SELECT site, controller, event_timestamp_ms, description, payload_json "
                "FROM events"
            ).fetchone()
        self.assertEqual(row[0], "Omada Workshop")
        self.assertEqual(row[1], "Omada _Presale")
        self.assertEqual(row[2], 1779791144791)
        self.assertIn('"shardSecret": "[redacted]"', row[4])
        self.assertNotIn("expected-shared-secret", row[4])

    def test_rejects_request_without_matching_access_token(self):
        status, _ = self.request(
            "POST",
            "/webhooks/omada/test-token",
            body='{"description":"unauthorized"}',
            headers={"Content-Type": "application/json", "Access_token": "wrong"},
        )

        self.assertEqual(status, 401)
        self.assertFalse(self.audit_path.exists())
        with sqlite3.connect(self.db_path) as db:
            count = db.execute("SELECT count(*) FROM events").fetchone()[0]
        self.assertEqual(count, 0)

    def test_rejects_non_configured_path(self):
        status, _ = self.request("POST", "/webhooks/omada/wrong", body="unexpected")

        self.assertEqual(status, 404)

    def test_health_endpoint_does_not_store_event(self):
        status, body = self.request("GET", "/health")

        self.assertEqual(status, 200)
        self.assertEqual(body, b"ok")
        with sqlite3.connect(self.db_path) as db:
            count = db.execute("SELECT count(*) FROM events").fetchone()[0]
        self.assertEqual(count, 0)


if __name__ == "__main__":
    unittest.main()

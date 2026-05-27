import http.client
import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.parse import urlencode

from dashboard_server import create_dashboard_server, hash_password
from event_model import EventStore


class DashboardServerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "events.sqlite3"
        self.store = EventStore(self.db_path)
        raw_id = self.store.insert_raw_event(
            received_at="2026-05-27T02:02:40+00:00",
            source_ip="10.40.40.30",
            payload={
                "Site": "Omada Workshop",
                "Controller": "Omada _Presale",
                "text": ["AP Lobby disconnected."],
            },
            headers={},
        )
        self.assertGreater(raw_id, 0)
        self.server = create_dashboard_server("127.0.0.1", 0, self.db_path)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.tmp.cleanup()

    def get(self, path):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        connection.request("GET", path)
        response = connection.getresponse()
        body = response.read()
        connection.close()
        return response.status, response.getheader("Content-Type"), body

    def test_events_api_returns_normalized_event(self):
        status, content_type, body = self.get("/api/events?category=device_offline")

        self.assertEqual(status, 200)
        self.assertIn("application/json", content_type)
        data = json.loads(body)
        self.assertEqual(data["events"][0]["category"], "device_offline")
        self.assertEqual(data["events"][0]["site"], "Omada Workshop")

    def test_dashboard_page_renders_event_summary(self):
        status, content_type, body = self.get("/")

        self.assertEqual(status, 200)
        self.assertIn("text/html", content_type)
        self.assertIn(b"Omada Alerts and Events", body)
        self.assertIn(b"AP Lobby disconnected.", body)

    def test_dashboard_highlights_actionable_alerts(self):
        status, _, body = self.get("/")

        self.assertEqual(status, 200)
        self.assertIn(b"Actionable Alerts", body)
        self.assertIn(b"AP Lobby disconnected.", body)

    def test_dashboard_can_expand_sanitized_omada_json(self):
        self.store.insert_raw_event(
            received_at="2026-05-27T02:32:51+00:00",
            source_ip="10.40.40.30",
            payload={
                "Site": "Omada Workshop",
                "shardSecret": "[redacted]",
                "text": ["[ap:AA-BB-CC-DD-EE-FF:AA-BB-CC-DD-EE-FF] was disconnected."],
            },
            headers={"access_token": "[redacted]"},
        )

        status, _, body = self.get("/")

        self.assertEqual(status, 200)
        self.assertIn(b"Show JSON", body)
        self.assertIn(b"&quot;shardSecret&quot;: &quot;[redacted]&quot;", body)
        self.assertNotIn(b"expected-shared-secret", body)

    def test_dashboard_uses_dark_operations_console_presentation(self):
        status, _, body = self.get("/")

        self.assertEqual(status, 200)
        self.assertIn(b"Omada Signal Center", body)
        self.assertIn(b"Network Operations Console", body)
        self.assertIn(b"--bg: #070a12", body)
        self.assertIn(b"Live ingestion", body)


class AuthenticatedDashboardServerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "events.sqlite3"
        self.store = EventStore(self.db_path)
        self.store.upsert_telegram_recipient("9988", "operator", "Ops User")
        self.server = create_dashboard_server(
            "127.0.0.1",
            0,
            self.db_path,
            admin_username="admin",
            password_hash=hash_password("correct-horse", salt=b"0123456789abcdef"),
            session_secret="unit-test-session-secret",
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.tmp.cleanup()

    def request(self, method, path, body=None, cookie=None):
        headers = {}
        if body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if cookie:
            headers["Cookie"] = cookie
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        content = response.read()
        result = (
            response.status,
            response.getheader("Location"),
            response.getheader("Set-Cookie"),
            content,
        )
        connection.close()
        return result

    def login(self):
        status, location, cookie, _ = self.request(
            "POST",
            "/login",
            urlencode({"username": "admin", "password": "correct-horse"}),
        )
        self.assertEqual(status, 303)
        self.assertEqual(location, "/")
        return cookie.split(";", 1)[0]

    def test_requires_login_before_viewing_dashboard(self):
        status, location, _, _ = self.request("GET", "/")

        self.assertEqual(status, 303)
        self.assertEqual(location, "/login")

    def test_login_renders_telegram_pending_admins_and_csrf_action(self):
        cookie = self.login()

        status, _, _, body = self.request("GET", "/", cookie=cookie)

        self.assertEqual(status, 200)
        self.assertIn(b"Telegram Admins", body)
        self.assertIn(b"Ops User", body)
        self.assertIn(b"Approve", body)
        self.assertIn(b'name="csrf_token"', body)

    def test_approve_requires_csrf_and_changes_status(self):
        cookie = self.login()
        status, _, _, body = self.request("GET", "/", cookie=cookie)
        self.assertEqual(status, 200)
        csrf = body.split(b'name="csrf_token" value="', 1)[1].split(b'"', 1)[0].decode()

        rejected, _, _, _ = self.request(
            "POST", "/telegram-admins/9988/approve", urlencode({}), cookie=cookie
        )
        self.assertEqual(rejected, 403)

        accepted, location, _, _ = self.request(
            "POST",
            "/telegram-admins/9988/approve",
            urlencode({"csrf_token": csrf}),
            cookie=cookie,
        )
        self.assertEqual(accepted, 303)
        self.assertEqual(location, "/")
        self.assertEqual(self.store.approved_telegram_recipients()[0]["chat_id"], "9988")


if __name__ == "__main__":
    unittest.main()

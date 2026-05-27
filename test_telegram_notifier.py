import tempfile
import unittest
from pathlib import Path

from event_model import EventStore
from telegram_notifier import (
    deliver_to_approved,
    format_message,
    process_updates,
    should_notify,
)


class TelegramNotifierTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = EventStore(Path(self.tmp.name) / "events.sqlite3")

    def tearDown(self):
        self.tmp.cleanup()

    def test_only_warn_or_critical_events_notify(self):
        self.assertTrue(should_notify({"severity": "critical"}))
        self.assertTrue(should_notify({"severity": "warning"}))
        self.assertFalse(should_notify({"severity": "info"}))

    def test_formats_critical_event(self):
        message = format_message(
            {
                "severity": "critical",
                "category": "device_offline",
                "site": "Omada Workshop",
                "message": "AP Lobby disconnected.",
            }
        )

        self.assertIn("CRITICAL", message)
        self.assertIn("Omada Workshop", message)
        self.assertIn("AP Lobby disconnected.", message)

    def test_start_update_creates_pending_recipient_and_acknowledges_user(self):
        sent = []
        updates = [
            {
                "update_id": 42,
                "message": {
                    "text": "/start",
                    "chat": {"id": 8123, "type": "private"},
                    "from": {"username": "somchai", "first_name": "Somchai"},
                },
            }
        ]

        process_updates(self.store, updates, lambda chat_id, text: sent.append((chat_id, text)))

        recipient = self.store.list_telegram_recipients()[0]
        self.assertEqual(recipient["chat_id"], "8123")
        self.assertEqual(recipient["status"], "pending")
        self.assertEqual(self.store.get_telegram_update_offset(), 43)
        self.assertIn("approval", sent[0][1].lower())

    def test_delivers_alerts_only_to_approved_recipient(self):
        self.store.insert_raw_event(
            "2026-05-27T02:32:51+00:00",
            "10.40.40.30",
            {"text": ["AP Lobby disconnected."]},
            {},
        )
        self.store.upsert_telegram_recipient("approved-chat", "approved", "Approved")
        self.store.upsert_telegram_recipient("pending-chat", "pending", "Pending")
        self.store.set_telegram_recipient_status("approved-chat", "approved")
        sent = []

        deliver_to_approved(self.store, lambda chat_id, text: sent.append((chat_id, text)))

        self.assertEqual([chat_id for chat_id, _ in sent], ["approved-chat"])


if __name__ == "__main__":
    unittest.main()

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from event_model import EventStore, normalize_payload


class NormalizePayloadTest(unittest.TestCase):
    def test_parses_dhcp_allocation_message(self):
        event = normalize_payload(
            {
                "Site": "Omada Workshop",
                "Controller": "Omada _Presale",
                "timestamp": 1779847354578,
                "text": [
                    "DHCP Server allocated IP address 172.16.10.100 for the [client:B0-19-21-66-5A-52]."
                ],
            }
        )

        self.assertEqual(event["category"], "dhcp_allocation")
        self.assertEqual(event["severity"], "info")
        self.assertEqual(event["client_mac"], "B0-19-21-66-5A-52")
        self.assertEqual(event["ip_address"], "172.16.10.100")

    def test_marks_dhcp_rejected_request_as_warning(self):
        event = normalize_payload(
            {"text": ["DHCP Server rejected the request of the [client:B0-19-21-66-5A-52]."]}
        )

        self.assertEqual(event["category"], "dhcp_rejected")
        self.assertEqual(event["severity"], "warning")
        self.assertEqual(event["client_mac"], "B0-19-21-66-5A-52")

    def test_parses_audit_operation_nested_in_text(self):
        event = normalize_payload(
            {
                "Site": "Omada Workshop",
                "text": ['{"details":{},"operation":"Log Notifications of Site configured successfully."}'],
            }
        )

        self.assertEqual(event["category"], "audit")
        self.assertEqual(
            event["message"], "Log Notifications of Site configured successfully."
        )

    def test_marks_disconnect_message_critical_for_notification(self):
        event = normalize_payload({"text": ["AP Lobby disconnected."]})

        self.assertEqual(event["category"], "device_offline")
        self.assertEqual(event["severity"], "critical")

    def test_parses_ap_disconnect_and_reconnect_as_specific_categories(self):
        disconnected = normalize_payload(
            {"text": ["[ap:E0-D3-62-73-4D-2B:E0-D3-62-73-4D-2B] was disconnected."]}
        )
        reconnected = normalize_payload(
            {"text": ["[ap:E0-D3-62-73-4D-2B:E0-D3-62-73-4D-2B] was reconnected in 8 minutes."]}
        )

        self.assertEqual(disconnected["category"], "ap_disconnected")
        self.assertEqual(disconnected["severity"], "critical")
        self.assertEqual(disconnected["device_mac"], "E0-D3-62-73-4D-2B")
        self.assertEqual(reconnected["category"], "ap_reconnected")
        self.assertEqual(reconnected["device_mac"], "E0-D3-62-73-4D-2B")
        self.assertEqual(reconnected["downtime_minutes"], 8)

    def test_parses_wan_down_and_up(self):
        event = normalize_payload(
            {
                "text": [
                    "[gateway:E0-D3-62-8D-D6-38:E0-D3-62-8D-D6-38]: "
                    "The physical connection status of [WAN2] was down."
                ]
            }
        )

        self.assertEqual(event["category"], "wan_down")
        self.assertEqual(event["severity"], "critical")
        self.assertEqual(event["device_mac"], "E0-D3-62-8D-D6-38")
        self.assertEqual(event["interface_name"], "WAN2")


class EventStoreTest(unittest.TestCase):
    def test_backfills_existing_raw_event_only_once(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "events.sqlite3"
            with sqlite3.connect(db_path) as db:
                db.execute(
                    """
                    CREATE TABLE events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        received_at TEXT NOT NULL, source_ip TEXT, site TEXT, controller TEXT,
                        event_timestamp_ms INTEGER, description TEXT, payload_json TEXT NOT NULL,
                        headers_json TEXT NOT NULL
                    )
                    """
                )
                db.execute(
                    "INSERT INTO events (received_at, payload_json, headers_json) VALUES (?, ?, ?)",
                    (
                        "2026-05-27T02:02:40+00:00",
                        json.dumps({"text": ["AP Lobby disconnected."]}),
                        "{}",
                    ),
                )

            store = EventStore(db_path)
            store.backfill()
            store.backfill()

            with sqlite3.connect(db_path) as db:
                rows = db.execute(
                    "SELECT category, severity FROM normalized_events"
                ).fetchall()
            self.assertEqual(rows, [("device_offline", "critical")])

    def test_renormalize_updates_existing_categories(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "events.sqlite3"
            store = EventStore(db_path)
            raw_id = store.insert_raw_event(
                "2026-05-27T02:20:56+00:00",
                "10.40.40.30",
                {"text": ["DHCP Server rejected the request of the [client:AA-BB-CC-DD-EE-FF]."]},
                {},
            )
            with sqlite3.connect(db_path) as db:
                db.execute(
                    "UPDATE normalized_events SET category = 'event', severity = 'info' "
                    "WHERE raw_event_id = ?",
                    (raw_id,),
                )

            store.renormalize()

            with sqlite3.connect(db_path) as db:
                row = db.execute(
                    "SELECT category, severity FROM normalized_events WHERE raw_event_id = ?",
                    (raw_id,),
                ).fetchone()
            self.assertEqual(row, ("dhcp_rejected", "warning"))

    def test_failed_telegram_delivery_remains_pending_until_sent(self):
        with tempfile.TemporaryDirectory() as directory:
            store = EventStore(Path(directory) / "events.sqlite3")
            raw_id = store.insert_raw_event(
                "2026-05-27T02:20:56+00:00",
                "10.40.40.30",
                {"text": ["AP Lobby disconnected."]},
                {},
            )

            store.record_notification(raw_id, "failed", "temporary error")
            self.assertEqual(len(store.pending_notifications()), 1)

            store.record_notification(raw_id, "sent")
            self.assertEqual(store.pending_notifications(), [])

    def test_telegram_recipient_requires_approval_and_can_be_revoked(self):
        with tempfile.TemporaryDirectory() as directory:
            store = EventStore(Path(directory) / "events.sqlite3")
            store.upsert_telegram_recipient("10001", "network_admin", "Network Admin")

            recipients = store.list_telegram_recipients()
            self.assertEqual(recipients[0]["chat_id"], "10001")
            self.assertEqual(recipients[0]["status"], "pending")

            store.set_telegram_recipient_status("10001", "approved")
            self.assertEqual(store.approved_telegram_recipients()[0]["chat_id"], "10001")

            store.set_telegram_recipient_status("10001", "revoked")
            self.assertEqual(store.approved_telegram_recipients(), [])

    def test_bot_update_offset_is_persisted(self):
        with tempfile.TemporaryDirectory() as directory:
            store = EventStore(Path(directory) / "events.sqlite3")
            self.assertEqual(store.get_telegram_update_offset(), 0)

            store.set_telegram_update_offset(152)

            self.assertEqual(store.get_telegram_update_offset(), 152)

    def test_approved_recipients_receive_event_independently(self):
        with tempfile.TemporaryDirectory() as directory:
            store = EventStore(Path(directory) / "events.sqlite3")
            raw_id = store.insert_raw_event(
                "2026-05-27T02:32:51+00:00",
                "10.40.40.30",
                {"text": ["AP Lobby disconnected."]},
                {},
            )
            store.upsert_telegram_recipient("10001", "first", "First")
            store.upsert_telegram_recipient("10002", "second", "Second")
            store.set_telegram_recipient_status("10001", "approved")
            store.set_telegram_recipient_status("10002", "approved")

            first_pending = store.pending_recipient_notifications("10001")
            second_pending = store.pending_recipient_notifications("10002")
            self.assertEqual(first_pending[0]["raw_event_id"], raw_id)
            self.assertEqual(second_pending[0]["raw_event_id"], raw_id)

            store.record_recipient_notification(raw_id, "10001", "sent")

            self.assertEqual(store.pending_recipient_notifications("10001"), [])
            self.assertEqual(
                store.pending_recipient_notifications("10002")[0]["raw_event_id"], raw_id
            )

    def test_records_and_reads_llm_incident(self):
        with tempfile.TemporaryDirectory() as directory:
            store = EventStore(Path(directory) / "events.sqlite3")
            raw_id = store.insert_raw_event(
                "2026-05-27T02:32:51+00:00",
                "10.40.40.30",
                {"text": ["AP Lobby disconnected."]},
                {},
            )
            store.record_llm_incident(
                raw_id,
                "gemini-2.5-flash",
                {
                    "priority": "high",
                    "score": 0.91,
                    "incident_type": "ap_disconnected",
                    "summary_th": "AP หลุด",
                    "impact": "ผู้ใช้บางส่วนได้รับผลกระทบ",
                    "recommended_actions": ["ตรวจ uplink"],
                    "requires_human": True,
                    "fingerprint": "ap-disc-1",
                },
                should_notify=True,
                error=None,
            )
            saved = store.get_llm_incident(raw_id)
            self.assertEqual(saved["priority"], "high")
            self.assertEqual(saved["recommended_actions"], ["ตรวจ uplink"])
            self.assertTrue(saved["should_notify"])


if __name__ == "__main__":
    unittest.main()

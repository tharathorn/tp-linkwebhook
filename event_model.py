#!/usr/bin/env python3
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DHCP_PATTERN = re.compile(
    r"DHCP Server allocated IP address (?P<ip>[0-9.]+) for the \[client:(?P<mac>[0-9A-Fa-f:-]+)\]",
    re.IGNORECASE,
)
DHCP_REJECT_PATTERN = re.compile(
    r"DHCP Server rejected the request of the \[client:(?P<mac>[0-9A-Fa-f:-]+)\]",
    re.IGNORECASE,
)
AP_DISCONNECTED_PATTERN = re.compile(
    r"\[ap:(?P<mac>[0-9A-Fa-f:-]+):[0-9A-Fa-f:-]+\] was disconnected\.",
    re.IGNORECASE,
)
AP_RECONNECTED_PATTERN = re.compile(
    r"\[ap:(?P<mac>[0-9A-Fa-f:-]+):[0-9A-Fa-f:-]+\] was reconnected in (?P<minutes>\d+) minutes\.",
    re.IGNORECASE,
)
WAN_PATTERN = re.compile(
    r"\[gateway:(?P<mac>[0-9A-Fa-f:-]+):[0-9A-Fa-f:-]+\]: "
    r"The physical connection status of \[(?P<interface>[^\]]+)\] was (?P<state>down|up)\.",
    re.IGNORECASE,
)


def extract_message(payload):
    text = payload.get("text", []) if isinstance(payload, dict) else []
    if isinstance(text, list) and text:
        first = text[0]
        if isinstance(first, str):
            try:
                nested = json.loads(first)
            except json.JSONDecodeError:
                return first
            if isinstance(nested, dict) and nested.get("operation"):
                return nested["operation"]
            return first
    return payload.get("description", "") if isinstance(payload, dict) else ""


def normalize_payload(payload):
    message = extract_message(payload)
    lower = message.lower()
    category = "event"
    severity = "info"
    client_mac = None
    ip_address = None
    device_mac = None
    interface_name = None
    downtime_minutes = None

    if "webhook test message" in lower:
        category = "test_message"
    elif "audit log" in lower or "log notifications" in lower:
        category = "audit"
    elif match := DHCP_PATTERN.search(message):
        category = "dhcp_allocation"
        client_mac = match.group("mac")
        ip_address = match.group("ip")
    elif match := DHCP_REJECT_PATTERN.search(message):
        category = "dhcp_rejected"
        severity = "warning"
        client_mac = match.group("mac")
    elif match := AP_DISCONNECTED_PATTERN.search(message):
        category = "ap_disconnected"
        severity = "critical"
        device_mac = match.group("mac")
    elif match := AP_RECONNECTED_PATTERN.search(message):
        category = "ap_reconnected"
        device_mac = match.group("mac")
        downtime_minutes = int(match.group("minutes"))
    elif match := WAN_PATTERN.search(message):
        state = match.group("state").lower()
        category = f"wan_{state}"
        severity = "critical" if state == "down" else "info"
        device_mac = match.group("mac")
        interface_name = match.group("interface")
    elif any(value in lower for value in ("disconnected", "offline", "wan down")):
        category = "device_offline"
        severity = "critical"
    elif any(value in lower for value in ("connected", "online", "wan up")):
        category = "device_online"

    return {
        "category": category,
        "severity": severity,
        "message": message,
        "site": payload.get("Site") if isinstance(payload, dict) else None,
        "controller": payload.get("Controller") if isinstance(payload, dict) else None,
        "event_timestamp_ms": payload.get("timestamp") if isinstance(payload, dict) else None,
        "client_mac": client_mac,
        "ip_address": ip_address,
        "device_mac": device_mac,
        "interface_name": interface_name,
        "downtime_minutes": downtime_minutes,
    }


class EventStore:
    def __init__(self, db_path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def connect(self):
        connection = sqlite3.connect(self.db_path, timeout=5)
        connection.row_factory = sqlite3.Row
        return connection

    def initialize(self):
        with self.connect() as db:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    received_at TEXT NOT NULL,
                    source_ip TEXT,
                    site TEXT,
                    controller TEXT,
                    event_timestamp_ms INTEGER,
                    description TEXT,
                    payload_json TEXT NOT NULL,
                    headers_json TEXT NOT NULL
                )
                """
            )
            db.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_received_at ON events(received_at DESC)"
            )
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS normalized_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    raw_event_id INTEGER NOT NULL UNIQUE,
                    received_at TEXT NOT NULL,
                    occurred_at TEXT,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    message TEXT NOT NULL,
                    site TEXT,
                    controller TEXT,
                    client_mac TEXT,
                    ip_address TEXT,
                    device_mac TEXT,
                    interface_name TEXT,
                    downtime_minutes INTEGER,
                    payload_json TEXT NOT NULL,
                    FOREIGN KEY(raw_event_id) REFERENCES events(id)
                )
                """
            )
            columns = {
                row[1] for row in db.execute("PRAGMA table_info(normalized_events)").fetchall()
            }
            for name, type_name in (
                ("device_mac", "TEXT"),
                ("interface_name", "TEXT"),
                ("downtime_minutes", "INTEGER"),
            ):
                if name not in columns:
                    db.execute(
                        f"ALTER TABLE normalized_events ADD COLUMN {name} {type_name}"
                    )
            db.execute(
                "CREATE INDEX IF NOT EXISTS idx_normalized_recent "
                "ON normalized_events(received_at DESC)"
            )
            db.execute(
                "CREATE INDEX IF NOT EXISTS idx_normalized_category "
                "ON normalized_events(category, received_at DESC)"
            )
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS telegram_deliveries (
                    raw_event_id INTEGER PRIMARY KEY,
                    delivered_at TEXT,
                    status TEXT NOT NULL,
                    error TEXT
                )
                """
            )
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS telegram_recipients (
                    chat_id TEXT PRIMARY KEY,
                    username TEXT,
                    display_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    requested_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS telegram_bot_state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS telegram_recipient_deliveries (
                    raw_event_id INTEGER NOT NULL,
                    chat_id TEXT NOT NULL,
                    delivered_at TEXT,
                    status TEXT NOT NULL,
                    error TEXT,
                    PRIMARY KEY (raw_event_id, chat_id),
                    FOREIGN KEY(raw_event_id) REFERENCES events(id),
                    FOREIGN KEY(chat_id) REFERENCES telegram_recipients(chat_id)
                )
                """
            )
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS llm_incidents (
                    raw_event_id INTEGER PRIMARY KEY,
                    analyzed_at TEXT NOT NULL,
                    model TEXT,
                    priority TEXT NOT NULL,
                    score REAL NOT NULL,
                    incident_type TEXT NOT NULL,
                    summary_th TEXT NOT NULL,
                    impact TEXT NOT NULL,
                    recommended_actions_json TEXT NOT NULL,
                    requires_human INTEGER NOT NULL,
                    fingerprint TEXT NOT NULL,
                    should_notify INTEGER NOT NULL,
                    error TEXT,
                    FOREIGN KEY(raw_event_id) REFERENCES events(id)
                )
                """
            )
            db.execute(
                "CREATE INDEX IF NOT EXISTS idx_llm_notify ON llm_incidents(should_notify, analyzed_at DESC)"
            )

    def normalize_raw(self, db, raw_event_id, received_at, payload):
        event = normalize_payload(payload)
        event_ts = event["event_timestamp_ms"]
        occurred_at = (
            datetime.fromtimestamp(event_ts / 1000, timezone.utc).isoformat()
            if isinstance(event_ts, (int, float))
            else None
        )
        db.execute(
            """
            INSERT OR IGNORE INTO normalized_events (
                raw_event_id, received_at, occurred_at, category, severity, message,
                site, controller, client_mac, ip_address, device_mac, interface_name,
                downtime_minutes, payload_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                raw_event_id,
                received_at,
                occurred_at,
                event["category"],
                event["severity"],
                event["message"],
                event["site"],
                event["controller"],
                event["client_mac"],
                event["ip_address"],
                event["device_mac"],
                event["interface_name"],
                event["downtime_minutes"],
                json.dumps(payload, ensure_ascii=False),
            ),
        )

    def insert_raw_event(self, received_at, source_ip, payload, headers):
        with self.connect() as db:
            cursor = db.execute(
                """
                INSERT INTO events (
                    received_at, source_ip, site, controller, event_timestamp_ms,
                    description, payload_json, headers_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    received_at,
                    source_ip,
                    payload.get("Site"),
                    payload.get("Controller"),
                    payload.get("timestamp"),
                    payload.get("description"),
                    json.dumps(payload, ensure_ascii=False),
                    json.dumps(headers, ensure_ascii=False),
                ),
            )
            raw_event_id = cursor.lastrowid
            self.normalize_raw(db, raw_event_id, received_at, payload)
            return raw_event_id

    def backfill(self):
        with self.connect() as db:
            rows = db.execute(
                """
                SELECT e.id, e.received_at, e.payload_json
                FROM events e
                LEFT JOIN normalized_events n ON n.raw_event_id = e.id
                WHERE n.raw_event_id IS NULL
                ORDER BY e.id
                """
            ).fetchall()
            for row in rows:
                self.normalize_raw(
                    db, row["id"], row["received_at"], json.loads(row["payload_json"])
                )
            return len(rows)

    def renormalize(self):
        with self.connect() as db:
            rows = db.execute(
                "SELECT id, received_at, payload_json FROM events ORDER BY id"
            ).fetchall()
            for row in rows:
                payload = json.loads(row["payload_json"])
                event = normalize_payload(payload)
                event_ts = event["event_timestamp_ms"]
                occurred_at = (
                    datetime.fromtimestamp(event_ts / 1000, timezone.utc).isoformat()
                    if isinstance(event_ts, (int, float))
                    else None
                )
                cursor = db.execute(
                    """
                    UPDATE normalized_events SET
                        received_at = ?, occurred_at = ?, category = ?, severity = ?,
                        message = ?, site = ?, controller = ?, client_mac = ?,
                        ip_address = ?, device_mac = ?, interface_name = ?,
                        downtime_minutes = ?, payload_json = ?
                    WHERE raw_event_id = ?
                    """,
                    (
                        row["received_at"],
                        occurred_at,
                        event["category"],
                        event["severity"],
                        event["message"],
                        event["site"],
                        event["controller"],
                        event["client_mac"],
                        event["ip_address"],
                        event["device_mac"],
                        event["interface_name"],
                        event["downtime_minutes"],
                        json.dumps(payload, ensure_ascii=False),
                        row["id"],
                    ),
                )
                if cursor.rowcount == 0:
                    self.normalize_raw(db, row["id"], row["received_at"], payload)
            return len(rows)

    def list_events(self, category=None, severity=None, limit=100):
        where = []
        values = []
        if category:
            where.append("category = ?")
            values.append(category)
        if severity:
            where.append("severity = ?")
            values.append(severity)
        query = "SELECT * FROM normalized_events"
        if where:
            query += " WHERE " + " AND ".join(where)
        query += " ORDER BY received_at DESC LIMIT ?"
        values.append(max(1, min(int(limit), 500)))
        with self.connect() as db:
            return [dict(row) for row in db.execute(query, values).fetchall()]

    def summary(self):
        with self.connect() as db:
            return {
                "total": db.execute("SELECT count(*) FROM normalized_events").fetchone()[0],
                "critical": db.execute(
                    "SELECT count(*) FROM normalized_events WHERE severity = 'critical'"
                ).fetchone()[0],
                "audit": db.execute(
                    "SELECT count(*) FROM normalized_events WHERE category = 'audit'"
                ).fetchone()[0],
                "dhcp": db.execute(
                    "SELECT count(*) FROM normalized_events WHERE category = 'dhcp_allocation'"
                ).fetchone()[0],
            }

    def pending_notifications(self, limit=20):
        with self.connect() as db:
            return [
                dict(row)
                for row in db.execute(
                    """
                    SELECT n.*
                    FROM normalized_events n
                    LEFT JOIN telegram_deliveries t ON t.raw_event_id = n.raw_event_id
                    WHERE n.severity IN ('warning', 'critical')
                      AND (t.raw_event_id IS NULL OR t.status = 'failed')
                    ORDER BY n.received_at ASC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
            ]

    def record_notification(self, raw_event_id, status, error=None):
        with self.connect() as db:
            db.execute(
                """
                INSERT OR REPLACE INTO telegram_deliveries
                (raw_event_id, delivered_at, status, error) VALUES (?, ?, ?, ?)
                """,
                (raw_event_id, datetime.now(timezone.utc).isoformat(), status, error),
            )

    def upsert_telegram_recipient(self, chat_id, username, display_name):
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO telegram_recipients
                (chat_id, username, display_name, status, requested_at, updated_at)
                VALUES (?, ?, ?, 'pending', ?, ?)
                ON CONFLICT(chat_id) DO UPDATE SET
                    username = excluded.username,
                    display_name = excluded.display_name,
                    status = CASE
                        WHEN telegram_recipients.status = 'approved' THEN 'approved'
                        ELSE 'pending'
                    END,
                    updated_at = excluded.updated_at
                """,
                (str(chat_id), username, display_name or "-", now, now),
            )

    def list_telegram_recipients(self):
        with self.connect() as db:
            return [
                dict(row)
                for row in db.execute(
                    "SELECT * FROM telegram_recipients ORDER BY updated_at DESC"
                ).fetchall()
            ]

    def set_telegram_recipient_status(self, chat_id, status):
        if status not in {"pending", "approved", "revoked"}:
            raise ValueError("invalid Telegram recipient status")
        with self.connect() as db:
            cursor = db.execute(
                """
                UPDATE telegram_recipients SET status = ?, updated_at = ?
                WHERE chat_id = ?
                """,
                (status, datetime.now(timezone.utc).isoformat(), str(chat_id)),
            )
            return cursor.rowcount > 0

    def approved_telegram_recipients(self):
        with self.connect() as db:
            return [
                dict(row)
                for row in db.execute(
                    """
                    SELECT * FROM telegram_recipients
                    WHERE status = 'approved' ORDER BY updated_at DESC
                    """
                ).fetchall()
            ]

    def get_telegram_update_offset(self):
        with self.connect() as db:
            row = db.execute(
                "SELECT value FROM telegram_bot_state WHERE key = 'update_offset'"
            ).fetchone()
            return int(row["value"]) if row else 0

    def set_telegram_update_offset(self, offset):
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO telegram_bot_state (key, value) VALUES ('update_offset', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (str(int(offset)),),
            )

    def pending_recipient_notifications(self, chat_id, limit=20):
        with self.connect() as db:
            return [
                dict(row)
                for row in db.execute(
                    """
                    SELECT n.*
                    FROM normalized_events n
                    LEFT JOIN telegram_recipient_deliveries t
                      ON t.raw_event_id = n.raw_event_id AND t.chat_id = ?
                    WHERE n.severity IN ('warning', 'critical')
                      AND (t.raw_event_id IS NULL OR t.status = 'failed')
                    ORDER BY n.received_at ASC
                    LIMIT ?
                    """,
                    (str(chat_id), limit),
                ).fetchall()
            ]

    def record_recipient_notification(self, raw_event_id, chat_id, status, error=None):
        with self.connect() as db:
            db.execute(
                """
                INSERT OR REPLACE INTO telegram_recipient_deliveries
                (raw_event_id, chat_id, delivered_at, status, error)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    raw_event_id,
                    str(chat_id),
                    datetime.now(timezone.utc).isoformat(),
                    status,
                    error,
                ),
            )

    def recent_events(self, limit=25):
        with self.connect() as db:
            return [
                dict(row)
                for row in db.execute(
                    """
                    SELECT raw_event_id, received_at, severity, category, message, site
                    FROM normalized_events
                    ORDER BY received_at DESC
                    LIMIT ?
                    """,
                    (max(1, min(int(limit), 100)),),
                ).fetchall()
            ]

    def get_llm_incident(self, raw_event_id):
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM llm_incidents WHERE raw_event_id = ?",
                (raw_event_id,),
            ).fetchone()
            if not row:
                return None
            item = dict(row)
            item["recommended_actions"] = json.loads(item["recommended_actions_json"])
            item["requires_human"] = bool(item["requires_human"])
            item["should_notify"] = bool(item["should_notify"])
            return item

    def record_llm_incident(
        self,
        raw_event_id,
        model,
        analysis,
        should_notify,
        error=None,
    ):
        with self.connect() as db:
            db.execute(
                """
                INSERT OR REPLACE INTO llm_incidents (
                    raw_event_id, analyzed_at, model, priority, score, incident_type,
                    summary_th, impact, recommended_actions_json, requires_human,
                    fingerprint, should_notify, error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    raw_event_id,
                    datetime.now(timezone.utc).isoformat(),
                    model or "",
                    analysis.get("priority", "medium"),
                    float(analysis.get("score", 0.0)),
                    analysis.get("incident_type", "other"),
                    analysis.get("summary_th", ""),
                    analysis.get("impact", ""),
                    json.dumps(analysis.get("recommended_actions", []), ensure_ascii=False),
                    1 if analysis.get("requires_human") else 0,
                    analysis.get("fingerprint", "none"),
                    1 if should_notify else 0,
                    error,
                ),
            )

    def llm_incidents_for_event_ids(self, raw_event_ids):
        ids = [int(item) for item in raw_event_ids if item is not None]
        if not ids:
            return {}
        placeholders = ",".join("?" for _ in ids)
        with self.connect() as db:
            rows = db.execute(
                f"SELECT * FROM llm_incidents WHERE raw_event_id IN ({placeholders})", ids
            ).fetchall()
        result = {}
        for row in rows:
            item = dict(row)
            item["recommended_actions"] = json.loads(item["recommended_actions_json"])
            item["requires_human"] = bool(item["requires_human"])
            item["should_notify"] = bool(item["should_notify"])
            result[int(item["raw_event_id"])] = item
        return result

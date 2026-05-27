#!/usr/bin/env python3
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

from event_model import EventStore
from llm_analyzer import GeminiAnalyzer, should_send_alert


def should_notify(event):
    return event.get("severity") in {"warning", "critical"}


def format_message(event):
    severity = event["severity"].upper()
    site = event.get("site") or "-"
    category = event.get("category") or "event"
    message = event.get("message") or "-"
    return f"[Omada {severity}] {category}\nSite: {site}\n{message}"


def format_llm_message(event, analysis):
    severity = event["severity"].upper()
    actions = analysis.get("recommended_actions") or []
    actions_text = "\n".join(f"- {item}" for item in actions[:3]) or "- ตรวจสอบอุปกรณ์และลิงก์ที่เกี่ยวข้อง"
    return (
        f"[Omada {severity}] {analysis.get('priority', 'medium').upper()} {analysis.get('incident_type', 'other')}\n"
        f"Site: {event.get('site') or '-'}\n"
        f"Summary: {analysis.get('summary_th', '-')}\n"
        f"Impact: {analysis.get('impact', '-')}\n"
        f"Message: {event.get('message') or '-'}\n"
        f"Actions:\n{actions_text}"
    )


def send_message(bot_token, chat_id, message):
    telegram_api_request(bot_token, "sendMessage", {"chat_id": chat_id, "text": message})


def telegram_api_request(bot_token, method, payload, request_timeout=15):
    url = f"https://api.telegram.org/bot{bot_token}/{method}"
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url, data=data, method="POST", headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=request_timeout) as response:
        if response.status != 200:
            raise RuntimeError(f"Telegram returned HTTP {response.status}")
        result = json.loads(response.read().decode("utf-8"))
    if not result.get("ok"):
        raise RuntimeError(result.get("description", "Telegram API request failed"))
    return result.get("result")


def deliver_pending(store, bot_token, chat_id):
    delivered = 0
    for event in store.pending_notifications():
        if not should_notify(event):
            continue
        try:
            send_message(bot_token, chat_id, format_message(event))
        except (OSError, urllib.error.URLError, RuntimeError) as error:
            store.record_notification(event["raw_event_id"], "failed", str(error))
            continue
        store.record_notification(event["raw_event_id"], "sent")
        delivered += 1
    return delivered


def process_updates(store, updates, send_fn):
    processed = 0
    for update in updates:
        update_id = update.get("update_id")
        message = update.get("message") or {}
        chat = message.get("chat") or {}
        sender = message.get("from") or {}
        text = (message.get("text") or "").strip().split(" ", 1)[0]
        if text == "/start" and chat.get("id") is not None:
            display_name = " ".join(
                value for value in (sender.get("first_name"), sender.get("last_name")) if value
            ) or sender.get("username") or str(chat["id"])
            store.upsert_telegram_recipient(
                str(chat["id"]), sender.get("username"), display_name
            )
            send_fn(
                str(chat["id"]),
                "Your request was received. Please wait for dashboard admin approval.",
            )
            processed += 1
        if isinstance(update_id, int):
            store.set_telegram_update_offset(update_id + 1)
    return processed


def fetch_updates(bot_token, offset, timeout=20):
    return telegram_api_request(
        bot_token,
        "getUpdates",
        {"offset": offset, "timeout": timeout, "allowed_updates": ["message"]},
        request_timeout=timeout + 5,
    ) or []


def deliver_to_approved(store, send_fn):
    return deliver_to_approved_with_llm(store, send_fn, None, 0.75)


def deliver_to_approved_with_llm(store, send_fn, analyzer, threshold):
    delivered = 0
    analysis_cache = {}
    for recipient in store.approved_telegram_recipients():
        chat_id = recipient["chat_id"]
        for event in store.pending_recipient_notifications(chat_id):
            if not should_notify(event):
                continue
            message = format_message(event)
            if analyzer:
                raw_id = event["raw_event_id"]
                if raw_id not in analysis_cache:
                    cached = store.get_llm_incident(raw_id)
                    if cached:
                        analysis_cache[raw_id] = cached
                    else:
                        try:
                            analysis = analyzer.analyze_event(event, store.recent_events(limit=20))
                            notify = should_send_alert(analysis, threshold)
                            store.record_llm_incident(
                                raw_id, analyzer.model, analysis, notify, error=None
                            )
                            analysis["should_notify"] = notify
                            analysis_cache[raw_id] = analysis
                        except (OSError, urllib.error.URLError, RuntimeError, ValueError) as error:
                            fallback = {
                                "priority": "high",
                                "score": 1.0,
                                "incident_type": "analysis_error",
                                "summary_th": "LLM วิเคราะห์ไม่สำเร็จ ใช้ข้อความมาตรฐานแทน",
                                "impact": "ต้องตรวจสอบด้วยมนุษย์",
                                "recommended_actions": ["ตรวจ log เพิ่มเติม", "ตรวจอุปกรณ์ที่เกี่ยวข้อง"],
                                "requires_human": True,
                                "fingerprint": f"fallback-{raw_id}",
                                "should_notify": True,
                            }
                            store.record_llm_incident(
                                raw_id,
                                analyzer.model,
                                fallback,
                                True,
                                error=str(error),
                            )
                            analysis_cache[raw_id] = fallback
                incident = analysis_cache[raw_id]
                if not incident.get("should_notify", True):
                    store.record_recipient_notification(raw_id, chat_id, "skipped", "llm_filtered")
                    continue
                message = format_llm_message(event, incident)
            try:
                send_fn(chat_id, message)
            except (OSError, urllib.error.URLError, RuntimeError) as error:
                store.record_recipient_notification(
                    event["raw_event_id"], chat_id, "failed", str(error)
                )
                continue
            store.record_recipient_notification(event["raw_event_id"], chat_id, "sent")
            delivered += 1
    return delivered


def run_cycle(store, fetch_fn, send_fn, analyzer=None, threshold=0.75):
    delivered = deliver_to_approved_with_llm(store, send_fn, analyzer, threshold)
    updates = fetch_fn(store.get_telegram_update_offset())
    processed = process_updates(store, updates, send_fn)
    return delivered, processed


def main():
    db_path = Path(os.environ.get("WEBHOOK_DB", "/var/lib/omada-webhook/events.sqlite3"))
    bot_token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    interval = int(os.environ.get("TELEGRAM_POLL_SECONDS", "10"))
    gemini_key = os.environ.get("GEMINI_API_KEY", "").strip()
    gemini_model = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash").strip() or "gemini-2.5-flash"
    llm_threshold = float(os.environ.get("LLM_PRIORITY_THRESHOLD", "0.75"))
    analyzer = GeminiAnalyzer(gemini_key, gemini_model, timeout=25) if gemini_key else None
    store = EventStore(db_path)
    while True:
        if not bot_token:
            time.sleep(interval)
            continue
        try:
            run_cycle(
                store,
                lambda offset: fetch_updates(bot_token, offset),
                lambda chat_id, message: send_message(bot_token, chat_id, message),
                analyzer=analyzer,
                threshold=llm_threshold,
            )
        except (OSError, urllib.error.URLError, RuntimeError, json.JSONDecodeError):
            time.sleep(interval)


if __name__ == "__main__":
    main()

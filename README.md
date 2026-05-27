# TP-Link Omada Webhook Dashboard

A small Python service stack for receiving Omada webhook events, normalizing
network alerts, displaying them in a secured dashboard, and delivering approved
alerts to Telegram recipients.

## Features

- Omada webhook receiver with shared-secret validation and payload redaction
- SQLite event normalization for AP disconnects, WAN state and DHCP signals
- Dark operations dashboard with expandable sanitized JSON payloads
- Password-protected dashboard with signed sessions and CSRF-protected actions
- Telegram `/start` enrollment with dashboard `Approve` and `Revoke` workflow
- Telegram notifications sent only to approved recipients
- Optional Gemini API triage to prioritize important alerts before Telegram delivery
- Python standard-library runtime with `systemd` service examples

## Security

This public repository intentionally does not contain:

- Telegram bot tokens
- Omada shared secrets or private webhook paths
- Dashboard passwords, password hashes or session signing secrets
- SSH private keys
- captured events, logs or SQLite databases

Never commit populated environment files. Start from the examples in
[`config/`](config/) and store actual values in `/etc/` on the deployment host.

If a Telegram bot token is exposed, regenerate it with BotFather before using
it in production.

## Components

| File | Purpose |
| --- | --- |
| `webhook_server.py` | Receives and redacts Omada webhook requests |
| `event_model.py` | Normalizes events and stores Telegram recipient state |
| `dashboard_server.py` | Provides the authenticated dashboard and admin actions |
| `telegram_notifier.py` | Polls Telegram and delivers approved alerts |
| `llm_analyzer.py` | Calls Gemini API and scores alert importance |
| `backfill_events.py` | Backfills or re-normalizes stored raw events |

## Quick Setup

Prerequisites: Linux, Python 3.10+ and a dedicated service account such as
`omada`.

```bash
sudo install -d -o root -g root /opt/omada-webhook
sudo install -d -o omada -g omada /var/lib/omada-webhook /var/log/omada-webhook
sudo install -o root -g root -m 0755 \
  event_model.py webhook_server.py dashboard_server.py telegram_notifier.py backfill_events.py \
  /opt/omada-webhook/
```

Create secrets without storing plaintext values in this repository:

```bash
python3 - <<'PY'
import secrets
from pathlib import Path
import sys
sys.path.insert(0, "/opt/omada-webhook")
from dashboard_server import hash_password

print("Webhook secret:", secrets.token_urlsafe(32))
print("Webhook path token:", secrets.token_hex(24))
print("Dashboard password hash:", hash_password("replace-with-a-strong-password"))
print("Session signing secret:", secrets.token_urlsafe(48))
PY
```

Copy the examples to `/etc`, insert generated values and your Telegram bot
token, and restrict their permissions:

```bash
sudo install -o root -g root -m 0600 config/omada-webhook.env.example /etc/omada-webhook.env
sudo install -o root -g root -m 0600 config/omada-dashboard-auth.env.example /etc/omada-dashboard-auth.env
sudo install -o root -g root -m 0600 config/omada-telegram.env.example /etc/omada-telegram.env
```

Install the services after reviewing the service account and bind addresses:

```bash
sudo install -o root -g root -m 0644 deploy/systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now omada-webhook omada-dashboard omada-telegram
```

Configure the Omada webhook URL using:

```text
http://YOUR_SERVER_IP:18080/webhooks/omada/YOUR_PRIVATE_PATH_TOKEN
```

Select the Omada payload template and set the same shared secret as in
`/etc/omada-webhook.env`.

## Telegram Approval Flow

1. A user sends `/start` to the configured Telegram bot.
2. The user appears as `pending` in the authenticated dashboard.
3. An administrator selects `Approve`.
4. Warning and critical Omada events are delivered only to approved chats.
5. Selecting `Revoke` stops future delivery to that chat.

Telegram integration uses Bot API long polling (`getUpdates`), so do not also
configure a Telegram webhook for the same bot.

### LLM Alert Triage (Gemini)

Set `GEMINI_API_KEY` in `/etc/omada-telegram.env` to enable LLM triage.
When enabled, the worker asks Gemini to classify each actionable event and sends
Telegram notifications only when:

- `requires_human` is `true`, or
- `priority` is `high`/`critical`, or
- `score >= LLM_PRIORITY_THRESHOLD`

If Gemini is unavailable, the worker falls back to standard notifications and
records the analysis error for audit.

## Test

```bash
python3 -m unittest -v \
  test_dashboard_server.py test_event_model.py test_llm_analyzer.py test_telegram_notifier.py test_webhook_server.py
```

#!/usr/bin/env python3
import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import time
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from event_model import EventStore


def hash_password(password, salt=None, iterations=240000):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password, encoded_hash):
    try:
        method, iterations, salt_hex, expected_hex = encoded_hash.split("$", 3)
        if method != "pbkdf2_sha256":
            return False
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations)
        )
        return hmac.compare_digest(candidate.hex(), expected_hex)
    except (TypeError, ValueError):
        return False


def create_session(username, secret, duration=28800):
    csrf = secrets.token_urlsafe(24)
    data = f"{username}|{int(time.time()) + duration}|{csrf}"
    encoded = base64.urlsafe_b64encode(data.encode("utf-8")).decode("ascii").rstrip("=")
    signature = hmac.new(secret.encode("utf-8"), encoded.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{encoded}.{signature}", csrf


def read_session(token, secret):
    try:
        encoded, signature = token.split(".", 1)
        expected = hmac.new(
            secret.encode("utf-8"), encoded.encode("ascii"), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return None
        padded = encoded + "=" * (-len(encoded) % 4)
        username, expires, csrf = base64.urlsafe_b64decode(padded).decode("utf-8").split("|", 2)
        if int(expires) < int(time.time()):
            return None
        return {"username": username, "csrf": csrf}
    except (ValueError, UnicodeDecodeError):
        return None


def render_login(error=False):
    error_html = '<div class="error">Invalid username or password.</div>' if error else ""
    return f"""<!doctype html>
<html lang="th"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Login | Omada Signal Center</title><style>
:root {{ --bg:#070a12; --panel:#0e1422; --stroke:#1d2a42; --text:#e9f0ff; --muted:#8190ac; --cyan:#21d4fd; --red:#ff4d71; }}
* {{ box-sizing:border-box; }} body {{ margin:0; min-height:100vh; display:grid; place-items:center; background:radial-gradient(circle at 50% 0%, rgba(33,212,253,.14), transparent 38%), var(--bg); color:var(--text); font:14px "Segoe UI", Arial, sans-serif; }}
.login {{ width:min(400px, calc(100% - 32px)); background:var(--panel); border:1px solid var(--stroke); border-radius:20px; padding:30px; }}
.eyebrow {{ color:var(--cyan); font-size:11px; letter-spacing:.16em; text-transform:uppercase; }} h1 {{ margin:10px 0 6px; font-size:27px; }} p {{ color:var(--muted); margin:0 0 22px; }}
label {{ display:block; color:var(--muted); margin:14px 0 7px; }} input {{ width:100%; padding:12px 13px; color:var(--text); background:#090e19; border:1px solid var(--stroke); border-radius:9px; font-size:14px; }}
input:focus {{ outline:1px solid var(--cyan); }} button {{ width:100%; margin-top:22px; padding:12px; background:var(--cyan); color:#05101b; border:0; border-radius:9px; font-weight:700; cursor:pointer; }}
.error {{ margin:14px 0 0; padding:10px; color:var(--red); background:rgba(255,77,113,.1); border-radius:8px; }}
</style></head><body><form class="login" method="post" action="/login">
<div class="eyebrow">Secure Access</div><h1>Omada Signal Center</h1><p>Sign in to manage events and Telegram recipients.</p>
{error_html}<label for="username">Username</label><input id="username" name="username" autocomplete="username" required>
<label for="password">Password</label><input id="password" type="password" name="password" autocomplete="current-password" required>
<button type="submit">Sign In</button></form></body></html>"""


def render_page(store, csrf_token=None):
    summary = store.summary()
    events = store.list_events(limit=100)
    alerts = store.list_events(severity="critical", limit=10) + store.list_events(
        severity="warning", limit=10
    )
    alerts.sort(key=lambda item: item["received_at"], reverse=True)
    def payload_details(item):
        try:
            payload = json.loads(item["payload_json"])
            formatted = json.dumps(payload, ensure_ascii=False, indent=2)
        except (TypeError, json.JSONDecodeError):
            formatted = item.get("payload_json") or "{}"
        return (
            "<details class=\"json\"><summary>Show JSON</summary>"
            f"<pre>{html.escape(formatted)}</pre></details>"
        )

    alert_rows = "".join(
        "<div class=\"alert\">"
        "<div class=\"alert-head\">"
        f"<span class=\"sev {html.escape(item['severity'])}\">{html.escape(item['severity'])}</span>"
        f"<span class=\"category\">{html.escape(item['category'])}</span>"
        f"<span class=\"site\">{html.escape(item['site'] or '-')}</span>"
        "</div>"
        f"<div class=\"alert-message\">{html.escape(item['message'] or '-')}</div>"
        f"{payload_details(item)}"
        "</div>"
        for item in alerts[:10]
    ) or "<div class=\"empty\">No warning or critical events received.</div>"
    rows = "".join(
        "<tr>"
        f"<td>{html.escape(item['received_at'])}</td>"
        f"<td><span class=\"sev {html.escape(item['severity'])}\">{html.escape(item['severity'])}</span></td>"
        f"<td><span class=\"category\">{html.escape(item['category'])}</span></td>"
        f"<td>{html.escape(item['site'] or '-')}</td>"
        f"<td>{html.escape(item['message'] or '-')}</td>"
        f"<td>{payload_details(item)}</td>"
        "</tr>"
        for item in events
    )
    admin_panel = ""
    if csrf_token:
        recipient_rows = "".join(
            "<tr>"
            f"<td>{html.escape(item['display_name'])}<div class=\"handle\">@{html.escape(item['username'] or '-')}</div></td>"
            f"<td>{html.escape(item['chat_id'])}</td>"
            f"<td><span class=\"recipient-status {html.escape(item['status'])}\">{html.escape(item['status'])}</span></td>"
            "<td><div class=\"actions\">"
            f"<form method=\"post\" action=\"/telegram-admins/{html.escape(item['chat_id'])}/approve\"><input type=\"hidden\" name=\"csrf_token\" value=\"{html.escape(csrf_token)}\"><button class=\"approve\" type=\"submit\">Approve</button></form>"
            f"<form method=\"post\" action=\"/telegram-admins/{html.escape(item['chat_id'])}/revoke\"><input type=\"hidden\" name=\"csrf_token\" value=\"{html.escape(csrf_token)}\"><button class=\"revoke\" type=\"submit\">Revoke</button></form>"
            "</div></td></tr>"
            for item in store.list_telegram_recipients()
        ) or '<tr><td colspan="4" class="empty">No requests yet. Ask the user to send /start to the Telegram bot.</td></tr>'
        admin_panel = f"""<section class="panel admin-panel"><div class="panel-header admin-header"><div><h2>Telegram Admins</h2><div class="panel-meta">Approve chats that may receive alert notifications from the bot</div></div><form method="post" action="/logout"><input type="hidden" name="csrf_token" value="{html.escape(csrf_token)}"><button class="logout" type="submit">Sign Out</button></form></div>
<div class="table-wrap"><table class="admin-table"><thead><tr><th>User</th><th>Chat ID</th><th>Status</th><th>Access</th></tr></thead><tbody>{recipient_rows}</tbody></table></div></section>"""
    return f"""<!doctype html>
<html lang="th"><head><meta charset="utf-8"><meta http-equiv="refresh" content="20">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Omada Signal Center | Network Operations Console</title>
<style>
:root {{
  --bg: #070a12;
  --panel: #0e1422;
  --panel-hi: #121b2e;
  --stroke: #1d2a42;
  --text: #e9f0ff;
  --muted: #8190ac;
  --cyan: #21d4fd;
  --purple: #b569ff;
  --green: #14f195;
  --yellow: #ffc857;
  --red: #ff4d71;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  min-height: 100vh;
  background: radial-gradient(circle at 14% -12%, rgba(33,212,253,.18), transparent 32%),
              radial-gradient(circle at 94% 5%, rgba(181,105,255,.16), transparent 26%), var(--bg);
  color: var(--text);
  font: 14px "Segoe UI", Inter, Arial, sans-serif;
}}
.shell {{ max-width: 1480px; margin: 0 auto; padding: 30px 32px 46px; }}
.topbar {{ display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:28px; }}
.eyebrow {{ letter-spacing:.17em; text-transform:uppercase; font-size:11px; color:var(--cyan); margin-bottom:9px; }}
h1 {{ font-size:34px; letter-spacing:-.04em; margin:0 0 8px; }}
.subtitle {{ color:var(--muted); font-size:15px; }}
.live {{
  display:flex; align-items:center; gap:9px; padding:11px 15px; border:1px solid rgba(20,241,149,.25);
  border-radius:999px; background:rgba(20,241,149,.06); color:var(--green); font-weight:600;
}}
.dot {{ width:8px; height:8px; border-radius:50%; background:var(--green); box-shadow:0 0 14px var(--green); }}
.cards {{ display:grid; grid-template-columns:repeat(4,minmax(145px,1fr)); gap:14px; margin-bottom:24px; }}
.card {{
  background:linear-gradient(145deg,var(--panel-hi),var(--panel)); border:1px solid var(--stroke);
  border-radius:16px; padding:17px 20px; position:relative; overflow:hidden;
}}
.card::after {{ content:""; position:absolute; right:-30px; top:-35px; width:82px; height:82px; border-radius:50%; opacity:.16; }}
.card.total::after {{ background:var(--cyan); }} .card.critical-card::after {{ background:var(--red); }}
.card.audit-card::after {{ background:var(--purple); }} .card.dhcp-card::after {{ background:var(--green); }}
.label {{ color:var(--muted); text-transform:uppercase; font-size:11px; letter-spacing:.12em; }}
.value {{ font-size:39px; line-height:1.1; font-weight:700; margin:10px 0 4px; }}
.card-note {{ color:var(--muted); font-size:12px; }}
.grid {{ display:grid; grid-template-columns:minmax(340px, .82fr) minmax(560px, 1.65fr); gap:18px; align-items:start; }}
.panel {{ background:rgba(14,20,34,.88); border:1px solid var(--stroke); border-radius:18px; overflow:hidden; }}
.panel-header {{ padding:19px 21px 14px; border-bottom:1px solid var(--stroke); }}
h2 {{ margin:0; font-size:17px; }} .panel-meta {{ color:var(--muted); font-size:12px; margin-top:6px; }}
.alerts-body {{ padding:7px 17px 15px; }}
.alert {{ padding:14px 5px; border-bottom:1px solid rgba(29,42,66,.8); }}
.alert:last-child {{ border-bottom:none; }}
.alert-head {{ display:flex; align-items:center; gap:8px; flex-wrap:wrap; margin-bottom:9px; }}
.alert-message {{ font-size:14px; line-height:1.45; color:#dce5f7; }}
.sev {{ display:inline-flex; padding:4px 9px; border-radius:999px; font-size:11px; font-weight:700; letter-spacing:.06em; text-transform:uppercase; }}
.sev.info {{ color:var(--cyan); background:rgba(33,212,253,.12); }}
.sev.warning {{ color:var(--yellow); background:rgba(255,200,87,.12); }}
.sev.critical {{ color:var(--red); background:rgba(255,77,113,.14); }}
.category {{ font:12px "Consolas","SFMono-Regular",monospace; color:var(--cyan); background:rgba(33,212,253,.08); padding:4px 8px; border-radius:6px; }}
.site {{ color:var(--muted); font-size:12px; }}
.table-wrap {{ overflow:auto; max-height:680px; }}
table {{ width:100%; border-collapse:collapse; min-width:760px; }}
th {{ position:sticky; top:0; z-index:1; background:#101829; color:var(--muted); text-transform:uppercase; letter-spacing:.09em; font-size:10px; }}
th,td {{ text-align:left; padding:13px 14px; border-bottom:1px solid rgba(29,42,66,.75); vertical-align:top; }}
tbody tr:hover {{ background:rgba(33,212,253,.035); }}
td:first-child {{ white-space:nowrap; color:var(--muted); font-size:12px; }}
.empty {{ color:var(--muted); padding:17px 5px; }}
.admin-panel {{ margin-top:18px; }}
.admin-header {{ display:flex; justify-content:space-between; align-items:center; gap:18px; }}
.admin-table {{ min-width:520px; }}
.handle {{ color:var(--muted); font-size:12px; margin-top:4px; }}
.recipient-status {{ border-radius:999px; padding:5px 10px; text-transform:uppercase; font-size:11px; font-weight:700; }}
.recipient-status.pending {{ color:var(--yellow); background:rgba(255,200,87,.12); }}
.recipient-status.approved {{ color:var(--green); background:rgba(20,241,149,.12); }}
.recipient-status.revoked {{ color:var(--red); background:rgba(255,77,113,.12); }}
.actions {{ display:flex; gap:8px; }} .actions form {{ margin:0; }}
.actions button, .logout {{ cursor:pointer; border-radius:7px; padding:7px 11px; font-weight:600; border:1px solid transparent; background:transparent; }}
.approve {{ color:var(--green); border-color:rgba(20,241,149,.3) !important; }}
.revoke {{ color:var(--red); border-color:rgba(255,77,113,.3) !important; }}
.logout {{ color:var(--muted); border-color:var(--stroke); }}
.json {{ margin-top:8px; }}
.json summary {{ cursor:pointer; display:inline-flex; align-items:center; color:var(--cyan); border:1px solid rgba(33,212,253,.26); border-radius:7px; padding:5px 9px; font-size:12px; font-weight:600; }}
.json summary:hover {{ background:rgba(33,212,253,.08); }}
.json pre {{ margin:10px 0 0; background:#05070e; border:1px solid var(--stroke); color:#a9d7ff; padding:12px; border-radius:9px; overflow-x:auto; white-space:pre-wrap; font:12px "Consolas", monospace; }}
@media (max-width: 1060px) {{ .grid {{ grid-template-columns:1fr; }} .cards {{ grid-template-columns:repeat(2,1fr); }} }}
@media (max-width: 640px) {{ .shell {{ padding:20px 15px; }} .topbar {{ display:block; }} .live {{ margin-top:18px; width:max-content; }} .cards {{ grid-template-columns:1fr; }} }}
</style></head><body>
<main class="shell">
<header class="topbar"><div>
<div class="eyebrow">Network Operations Console</div>
<h1>Omada Signal Center</h1>
<div class="subtitle">Alerts, telemetry and normalized network events from Omada Workshop</div>
</div><div class="live"><span class="dot"></span>Live ingestion</div></header>
<section class="cards">
<div class="card total"><div class="label">Total Events</div><div class="value">{summary['total']}</div><div class="card-note">Captured webhook records</div></div>
<div class="card critical-card"><div class="label">Critical</div><div class="value">{summary['critical']}</div><div class="card-note">Needs attention</div></div>
<div class="card audit-card"><div class="label">Audit</div><div class="value">{summary['audit']}</div><div class="card-note">Configuration activity</div></div>
<div class="card dhcp-card"><div class="label">DHCP</div><div class="value">{summary['dhcp']}</div><div class="card-note">Lease signals</div></div>
</section>
<section class="grid">
<div class="panel"><div class="panel-header"><h2>Actionable Alerts</h2><div class="panel-meta">Warning and critical signals prioritized for response</div></div><div class="alerts-body">{alert_rows}</div></div>
<div class="panel"><div class="panel-header"><h2>Omada Alerts and Events</h2><div class="panel-meta">Live event stream - select Show JSON to inspect the sanitized Omada payload</div></div>
<div class="table-wrap"><table><thead><tr><th>Received (UTC)</th><th>Severity</th><th>Category</th><th>Site</th><th>Message</th><th>Payload</th></tr></thead>
<tbody>{rows}</tbody></table></div></div>
</section>{admin_panel}</main></body></html>"""


def create_dashboard_server(
    host, port, db_path, admin_username="", password_hash="", session_secret=""
):
    store = EventStore(Path(db_path))
    auth_enabled = bool(admin_username and password_hash and session_secret)

    class Handler(BaseHTTPRequestHandler):
        def respond(self, status, body, content_type, headers=None):
            encoded = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(encoded)))
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(encoded)

        def redirect(self, location, headers=None):
            headers = dict(headers or {})
            headers["Location"] = location
            self.respond(303, "", "text/plain; charset=utf-8", headers)

        def get_session(self):
            if not auth_enabled:
                return {"username": "", "csrf": ""}
            cookie = cookies.SimpleCookie(self.headers.get("Cookie", ""))
            morsel = cookie.get("omada_session")
            return read_session(morsel.value, session_secret) if morsel else None

        def read_form(self):
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            return parse_qs(self.rfile.read(length).decode("utf-8"))

        def do_GET(self):
            parsed = urlparse(self.path)
            if parsed.path == "/health":
                self.respond(200, "ok", "text/plain; charset=utf-8")
                return
            if parsed.path == "/login":
                if auth_enabled and self.get_session():
                    self.redirect("/")
                    return
                self.respond(200, render_login(), "text/html; charset=utf-8")
                return
            session = self.get_session()
            if auth_enabled and not session:
                if parsed.path.startswith("/api/"):
                    self.respond(401, '{"error":"authentication required"}', "application/json; charset=utf-8")
                else:
                    self.redirect("/login")
                return
            if parsed.path == "/api/events":
                query = parse_qs(parsed.query)
                events = store.list_events(
                    category=query.get("category", [None])[0],
                    severity=query.get("severity", [None])[0],
                    limit=query.get("limit", [100])[0],
                )
                self.respond(
                    200,
                    json.dumps({"summary": store.summary(), "events": events}, ensure_ascii=False),
                    "application/json; charset=utf-8",
                )
                return
            if parsed.path == "/":
                self.respond(
                    200,
                    render_page(store, session["csrf"] if auth_enabled else None),
                    "text/html; charset=utf-8",
                )
                return
            self.respond(404, "not found", "text/plain; charset=utf-8")

        def do_POST(self):
            parsed = urlparse(self.path)
            form = self.read_form()
            if parsed.path == "/login":
                username = form.get("username", [""])[0]
                password = form.get("password", [""])[0]
                if (
                    auth_enabled
                    and hmac.compare_digest(username, admin_username)
                    and verify_password(password, password_hash)
                ):
                    token, _csrf = create_session(admin_username, session_secret)
                    self.redirect(
                        "/",
                        {"Set-Cookie": f"omada_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800"},
                    )
                    return
                self.respond(401, render_login(error=True), "text/html; charset=utf-8")
                return
            session = self.get_session()
            if auth_enabled and not session:
                self.redirect("/login")
                return
            if not auth_enabled:
                self.respond(404, "not found", "text/plain; charset=utf-8")
                return
            provided_csrf = form.get("csrf_token", [""])[0]
            if not hmac.compare_digest(provided_csrf, session["csrf"]):
                self.respond(403, "forbidden", "text/plain; charset=utf-8")
                return
            if parsed.path == "/logout":
                self.redirect(
                    "/login",
                    {"Set-Cookie": "omada_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"},
                )
                return
            parts = parsed.path.strip("/").split("/")
            if len(parts) == 3 and parts[0] == "telegram-admins" and parts[2] in {"approve", "revoke"}:
                status = "approved" if parts[2] == "approve" else "revoked"
                if not store.set_telegram_recipient_status(parts[1], status):
                    self.respond(404, "not found", "text/plain; charset=utf-8")
                    return
                self.redirect("/")
                return
            self.respond(404, "not found", "text/plain; charset=utf-8")

        def log_message(self, _format, *_args):
            return

    return ThreadingHTTPServer((host, port), Handler)


def main():
    host = os.environ.get("DASHBOARD_HOST", "10.50.50.202")
    port = int(os.environ.get("DASHBOARD_PORT", "18081"))
    db_path = Path(os.environ.get("WEBHOOK_DB", "/var/lib/omada-webhook/events.sqlite3"))
    create_dashboard_server(
        host,
        port,
        db_path,
        admin_username=os.environ.get("DASHBOARD_ADMIN_USERNAME", ""),
        password_hash=os.environ.get("DASHBOARD_PASSWORD_HASH", ""),
        session_secret=os.environ.get("DASHBOARD_SESSION_SECRET", ""),
    ).serve_forever()


if __name__ == "__main__":
    main()

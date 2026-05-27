#!/usr/bin/env python3
import json
import re
import urllib.error
import urllib.request


DEFAULT_MODEL = "gemini-2.5-flash"


def extract_json_block(text):
    if not text:
        raise ValueError("empty model response")
    fenced = re.search(r"```json\s*(\{.*?\})\s*```", text, flags=re.DOTALL | re.IGNORECASE)
    if fenced:
        return fenced.group(1)
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("no JSON object found")
    return text[start : end + 1]


def normalize_analysis(raw):
    priority = str(raw.get("priority", "medium")).lower()
    if priority not in {"critical", "high", "medium", "low"}:
        priority = "medium"
    try:
        score = float(raw.get("score", 0))
    except (TypeError, ValueError):
        score = 0.0
    score = max(0.0, min(score, 1.0))
    actions = raw.get("recommended_actions") or []
    if not isinstance(actions, list):
        actions = [str(actions)]
    actions = [str(item).strip() for item in actions if str(item).strip()][:5]
    fingerprint = str(raw.get("fingerprint", "")).strip() or "none"
    return {
        "priority": priority,
        "score": score,
        "incident_type": str(raw.get("incident_type", "other")).strip() or "other",
        "summary_th": str(raw.get("summary_th", "")).strip() or "No summary",
        "impact": str(raw.get("impact", "")).strip() or "Unknown",
        "recommended_actions": actions,
        "requires_human": bool(raw.get("requires_human", False)),
        "fingerprint": fingerprint,
    }


def should_send_alert(analysis, threshold):
    return bool(
        analysis.get("requires_human")
        or analysis.get("priority") in {"critical", "high"}
        or float(analysis.get("score", 0.0)) >= float(threshold)
    )


class GeminiAnalyzer:
    def __init__(self, api_key, model=DEFAULT_MODEL, timeout=20):
        self.api_key = api_key
        self.model = model
        self.timeout = timeout

    def analyze_event(self, event, recent_events):
        prompt = (
            "You are a NOC incident triage assistant. "
            "Return ONLY valid JSON with keys: "
            "priority, score, incident_type, summary_th, impact, recommended_actions, requires_human, fingerprint. "
            "Use Thai language for summary_th and impact. "
            "Score must be 0..1. fingerprint must be stable for similar incidents.\n\n"
            f"Current event:\n{json.dumps(event, ensure_ascii=False)}\n\n"
            f"Recent related events:\n{json.dumps(recent_events, ensure_ascii=False)}"
        )
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"responseMimeType": "application/json", "temperature": 0.1},
        }
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model}:generateContent?key={self.api_key}"
        )
        request = urllib.request.Request(
            url=url,
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            if response.status != 200:
                raise RuntimeError(f"Gemini returned HTTP {response.status}")
            body = json.loads(response.read().decode("utf-8"))
        candidates = body.get("candidates") or []
        text = ""
        if candidates:
            parts = (((candidates[0] or {}).get("content") or {}).get("parts") or [])
            if parts:
                text = str(parts[0].get("text", ""))
        parsed = json.loads(extract_json_block(text))
        return normalize_analysis(parsed)

"""UNIXSMS webhook -> legacy-compatible /v2/cdr bridge.

This deployment variant loads secrets from a local .env file and keeps
accepted SMS records in memory, so no external storage service is required.
Records are lost when the process restarts.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from collections import deque
from datetime import datetime, timezone
from threading import Condition, Lock
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
import uvicorn


def load_dotenv(path: str = ".env") -> None:
    """Small dependency-free .env loader; existing environment wins."""
    try:
        with open(path, "r", encoding="utf-8") as file:
            lines = file.readlines()
    except FileNotFoundError:
        return
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('\"', "'"):
            value = value[1:-1]
        os.environ.setdefault(key, value)


load_dotenv(os.getenv("ENV_FILE", ".env"))

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper(), format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("unixsms_webhook_bridge")

WEBHOOK_PATH_TOKEN = os.environ.get("WEBHOOK_PATH_TOKEN", "").strip()
BOT_READ_TOKEN = os.environ.get("BOT_READ_TOKEN", "").strip()
PORT = int(os.environ.get("PORT", "8000"))
MAX_CDR_RECORDS = max(1, min(int(os.environ.get("MAX_CDR_RECORDS", "200")), 2000))
MEMORY_LIMIT = max(100, min(int(os.environ.get("MEMORY_LIMIT", "50000")), 200000))

app = FastAPI(title="UNIXSMS Webhook Bridge", version="1.1.0", docs_url=None, redoc_url=None)
_events: deque[dict[str, str]] = deque(maxlen=MEMORY_LIMIT)
_event_keys: set[str] = set()
_events_lock = Lock()
_events_changed = Condition(_events_lock)
_next_seq = 0


@app.on_event("startup")
def startup() -> None:
    if not WEBHOOK_PATH_TOKEN or not BOT_READ_TOKEN:
        raise RuntimeError("Set WEBHOOK_PATH_TOKEN and BOT_READ_TOKEN in .env before starting.")
    log.info("Webhook bridge started in memory mode; records disappear on restart.")


def _walk_dicts(value: Any):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            if isinstance(child, (dict, list)):
                yield from _walk_dicts(child)
    elif isinstance(value, list):
        for child in value:
            if isinstance(child, (dict, list)):
                yield from _walk_dicts(child)


def _pick(payload: Any, names: tuple[str, ...]) -> str:
    wanted = {name.casefold() for name in names}
    objects = list(_walk_dicts(payload))
    for obj in reversed(objects):
        for key, value in obj.items():
            if str(key).casefold() in wanted and value is not None and not isinstance(value, (dict, list)):
                text = str(value).strip()
                if text:
                    return text
    return ""


def _normalize_event(payload: Any, request: Request) -> dict[str, str]:
    number = _pick(payload, ("num", "number", "msisdn", "to", "destination", "phone"))
    cli = _pick(payload, ("cli", "sender", "sender_id", "origin", "from"))
    message = _pick(payload, ("message", "content", "sms", "body", "text", "text_message"))
    event_time = _pick(payload, ("dt", "received_at", "created_at", "timestamp", "time", "date"))
    provider_id = _pick(payload, ("event_id", "webhook_id", "cdr_id", "message_id", "id"))
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if provider_id:
        event_key = provider_id.strip()
    else:
        request_key = request.headers.get("x-event-id") or request.headers.get("idempotency-key") or ""
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        event_key = f"{request_key}:{digest}" if request_key else digest
    if not event_time:
        event_time = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    return {
        "event_key": event_key[:250],
        "number": number.lstrip("+"),
        "cli": cli,
        "message": message,
        "event_time": event_time,
        "mapped": "1" if number and message else "0",
        "seq": "0",
    }


def _require_bot_token(request: Request) -> None:
    supplied = request.query_params.get("token", "")
    if not supplied:
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            supplied = auth[7:].strip()
    if not supplied or not hmac.compare_digest(supplied, BOT_READ_TOKEN):
        raise HTTPException(status_code=401, detail="Unauthorized")


@app.get("/health")
def health() -> dict[str, Any]:
    with _events_lock:
        total = len(_events)
        mapped = sum(1 for event in _events if event["mapped"] == "1")
    return {"ok": True, "mode": "memory", "stored_events": total, "readable_sms": mapped}


@app.post("/webhook/{path_token}")
async def receive_webhook(path_token: str, request: Request) -> JSONResponse:
    if not hmac.compare_digest(path_token, WEBHOOK_PATH_TOKEN):
        raise HTTPException(status_code=404, detail="Not found")
    raw = await request.body()
    if len(raw) > 1_000_000:
        raise HTTPException(status_code=413, detail="Payload too large")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise HTTPException(status_code=400, detail="Expected a JSON webhook payload")

    payloads = payload if isinstance(payload, list) else [payload]
    global _next_seq
    inserted = duplicates = unmapped = 0
    with _events_changed:
        for item in payloads:
            event = _normalize_event(item, request)
            if event["event_key"] in _event_keys:
                duplicates += 1
                continue
            if len(_events) == MEMORY_LIMIT:
                oldest = _events[0]
                _event_keys.discard(oldest["event_key"])
            _next_seq += 1
            event["seq"] = str(_next_seq)
            _events.append(event)
            _event_keys.add(event["event_key"])
            inserted += 1
            if event["mapped"] == "0":
                unmapped += 1
        if inserted:
            _events_changed.notify_all()
    return JSONResponse({"success": True, "accepted": inserted, "duplicates": duplicates, "unmapped": unmapped})


@app.get("/v2/cdr/longpoll")
def longpoll_cdr(request: Request, after: int = 0, wait: int = 20, records: int = 200) -> dict[str, Any]:
    """Wait for a new SMS, avoiding rapid polling from the bot."""
    _require_bot_token(request)
    wait = max(1, min(wait, 25))
    records = max(1, min(records, MAX_CDR_RECORDS))
    deadline = __import__("time").monotonic() + wait
    with _events_changed:
        while True:
            rows = [event for event in _events if event["mapped"] == "1" and int(event["seq"]) > after]
            if rows:
                rows = rows[-records:]
                break
            remaining = deadline - __import__("time").monotonic()
            if remaining <= 0:
                rows = []
                break
            _events_changed.wait(timeout=remaining)
    next_cursor = max([int(row["seq"]) for row in rows], default=after)
    return {
        "status": "success",
        "next_cursor": next_cursor,
        "data": [{"num": row["number"], "cli": row["cli"], "message": row["message"], "dt": row["event_time"]} for row in rows],
    }


@app.get("/v2/cdr")
def list_cdr(request: Request, records: int = 200, page: int = 1) -> dict[str, Any]:
    _require_bot_token(request)
    records = max(1, min(records, MAX_CDR_RECORDS))
    page = max(1, page)
    offset = (page - 1) * records
    with _events_lock:
        rows = [event for event in reversed(_events) if event["mapped"] == "1"][offset:offset + records]
    return {
        "status": "success",
        "data": [{"num": row["number"], "cli": row["cli"], "message": row["message"], "dt": row["event_time"]} for row in rows],
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=PORT, access_log=False)

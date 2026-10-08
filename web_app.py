#!/usr/bin/env python3
"""
Web-интерфейс и REST API поверх storage.db.
Читает те же данные, что пишет smtpServer.py. Писем сам не обрабатывает.
Запуск: python web_app.py  →  http://127.0.0.1:8000
"""
from __future__ import annotations

import json
import smtplib
import time
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

import storage
from smtpServer import parse_mail   # переиспользуем парсер писем

CFG = json.load(open("config.json"))
RELAY = CFG["relay"]
SENDER = CFG["sender"]
SECURITY = CFG["securityAddresses"]
WEB = CFG["web"]

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
TEMPLATES_DIR.mkdir(exist_ok=True)

CATEGORY_TITLES = {
    0: "Не угроза",
    1: "Террористическая угроза",
    2: "Угроза техногенной аварии",
    3: "Угроза противоправных действий",
    4: "Иная угроза",
}

CATEGORY_COLORS = {
    0: "#2e7d32",
    1: "#b71c1c",
    2: "#ef6c00",
    3: "#6a1b9a",
    4: "#c2185b",
}

ACTION_LABELS = {
    "deliver":     "Доставлено",
    "quarantine":  "Изъято в карантин",
    "review":      "На проверку",
    "failed":      "Ошибка анализа",
}

app = FastAPI(title="AI SMTP Security Gateway", version="1.0")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def _enrich(m: dict) -> dict:
    m = dict(m)
    m["category_title"] = CATEGORY_TITLES.get(m.get("category"), "—")
    m["category_color"] = CATEGORY_COLORS.get(m.get("category"), "#37474f")
    m["action_label"]   = ACTION_LABELS.get(m.get("action"), m.get("action", ""))
    m["confidence_pct"] = round(float(m.get("confidence") or 0) * 100, 1)
    m["is_threat"]      = (m.get("category") or 0) > 0
    return m


# ---------------------------- REST API ----------------------------

@app.get("/api/statistics")
def api_statistics() -> dict:
    stats = storage.statistics()
    stats["events"]    = len(storage.read_events(limit=1000))
    stats["quarantine"] = len(list(storage.QUARANTINE_DIR.glob("*.eml")))
    stats["settings"]  = storage.get_all_settings()
    stats["gateway"]   = {
        "host": RELAY["listen_host"], "port": RELAY["listen_port"],
        "model": CFG["ai"]["model"], "categories": SECURITY,
    }
    return stats


@app.get("/api/messages")
def api_messages(status: str | None = Query(default=None),
                 limit: int = Query(default=50, ge=1, le=500),
                 offset: int = Query(default=0, ge=0)) -> dict:
    messages = [_enrich(m) for m in storage.list_messages(status, limit, offset)]
    return {"count": len(messages), "messages": messages}


@app.get("/api/messages/{message_id}")
def api_message(message_id: str) -> dict:
    m = storage.get_message(message_id)
    if not m:
        raise HTTPException(404, "Письмо не найдено")
    enriched = _enrich(m)
    enriched["events"] = storage.read_events(message_id=message_id)
    raw = storage.read_quarantine(message_id)
    if not raw and m.get("eml_path"):
        try:
            raw = Path(m["eml_path"]).read_bytes()
        except OSError:
            raw = None
    enriched["raw"] = (raw or b"").decode("utf-8", errors="replace")
    return enriched


@app.get("/api/quarantine")
def api_quarantine(limit: int = Query(default=100, ge=1, le=1000)) -> dict:
    records = [_enrich(m) for m in storage.list_messages("quarantine", limit)]
    return {"count": len(records), "root": str(storage.QUARANTINE_DIR),
            "messages": records}


@app.get("/api/quarantine/{message_id}")
def api_quarantine_message(message_id: str, raw: bool = Query(default=False)) -> dict:
    m = storage.get_message(message_id)
    if not m or m.get("action") != "quarantine":
        raise HTTPException(404, "Письмо не найдено в карантине")
    if raw:
        data = storage.read_quarantine(message_id) or b""
        return {"message_id": message_id,
                "raw": data.decode("utf-8", errors="replace")}
    return _enrich(m)


class TestMessage(BaseModel):
    sender:    str = Field(default="attacker@test.local")
    recipient: str = Field(default="user1@corp.com")
    subject:   str = Field(default="Test")
    body:      str = Field(default="")
    wait:      bool = Field(default=True)
    timeout:   int  = Field(default=90, ge=0, le=300)


@app.post("/api/test-message")
def api_test_message(req: TestMessage) -> dict:
    return _send_test(req)


@app.get("/api/settings")
def api_settings() -> dict:
    s = storage.get_all_settings()
    s.setdefault("security_addresses", SECURITY)
    s.setdefault("relay", f"{RELAY['listen_host']}:{RELAY['listen_port']}")
    return s


class SettingsUpdate(BaseModel):
    security_addresses: dict | None = None
    relay:              str  | None = None


@app.put("/api/settings")
def api_update_settings(up: SettingsUpdate) -> dict:
    values = {k: v for k, v in up.model_dump().items() if v is not None}
    if not values:
        raise HTTPException(400, "Нечего обновлять")
    for k, v in values.items():
        storage.set_setting(k, v)
    return {"updated": values, "settings": api_settings()}


# --------------------- Тестовый режим ---------------------

def _send_test(req: TestMessage) -> dict:
    raw_id = make_msgid(domain="test.local")
    message_id = raw_id.strip("<>")

    msg = EmailMessage()
    msg["Message-ID"] = raw_id
    msg["From"] = req.sender
    msg["To"]   = req.recipient
    msg["Subject"] = req.subject
    msg["Date"] = formatdate(localtime=True)
    msg.set_content(req.body or f"Тестовое письмо: {req.subject}")

    try:
        with smtplib.SMTP(RELAY["listen_host"], RELAY["listen_port"], timeout=30) as s:
            s.send_message(msg)
    except (smtplib.SMTPException, OSError) as exc:
        raise HTTPException(503, f"Релей {RELAY['listen_host']}:{RELAY['listen_port']} "
                                 f"недоступен: {exc}")

    result = {
        "message_id": message_id,
        "sent": True,
        "gateway": f"{RELAY['listen_host']}:{RELAY['listen_port']}",
    }
    if not req.wait:
        return result

    deadline = time.monotonic() + req.timeout
    record = None
    while time.monotonic() < deadline:
        record = storage.get_message(message_id)
        if record:
            break
        time.sleep(0.3)

    result["classification"] = _enrich(record) if record else None
    result["events"] = storage.read_events(message_id=message_id) if record else []
    result["completed"] = bool(record)
    return result


# ----------------------- Страницы -----------------------

def plural(n: int, one: str, few: str, many: str) -> str:
    r = abs(n) % 100
    if 11 <= r <= 14:
        return many
    r %= 10
    return one if r == 1 else few if 2 <= r <= 4 else many


@app.get("/", response_class=HTMLResponse)
def page_dashboard(request: Request):
    stats = storage.statistics()
    days = int(stats.get("days") or 0)
    stats["days_label"] = (f"за {days} {plural(days, 'день', 'дня', 'дней')}"
                           if days else "писем пока нет")
    return templates.TemplateResponse(request, "index.html", {
        "statistics": stats,
        "messages":   [_enrich(m) for m in storage.list_messages(limit=25)],
        "events":     storage.read_events(limit=15),
        "categories": CATEGORY_TITLES,
    })


@app.get("/messages", response_class=HTMLResponse)
def page_messages(request: Request, status: str | None = None):
    return templates.TemplateResponse(request, "messages.html", {
        "messages": [_enrich(m) for m in storage.list_messages(status, limit=200)],
        "status": status or "",
    })


@app.get("/messages/{message_id}", response_class=HTMLResponse)
def page_message(request: Request, message_id: str):
    m = storage.get_message(message_id)
    if not m:
        raise HTTPException(404, "Письмо не найдено")
    enriched = _enrich(m)
    enriched["events"] = storage.read_events(message_id=message_id)

    raw = storage.read_quarantine(message_id)
    if not raw and m.get("eml_path"):
        try:
            raw = Path(m["eml_path"]).read_bytes()
        except OSError:
            raw = None
    raw = raw or b""

    subject, body = parse_mail(raw) if raw else ("", "")
    return templates.TemplateResponse(request, "message.html", {
        "message": enriched, "subject": subject, "body": body,
        "raw": raw.decode("utf-8", errors="replace"),
        "original_found": bool(raw),
    })


@app.get("/quarantine", response_class=HTMLResponse)
def page_quarantine(request: Request):
    records = [_enrich(m) for m in storage.list_messages("quarantine", limit=200)]
    return templates.TemplateResponse(request, "quarantine.html", {
        "messages": records, "root": str(storage.QUARANTINE_DIR),
    })


TEST_PRESETS = {
    "normal":     {"subject": "Встреча завтра",
                   "body": "Добрый день! Встречаемся завтра в 10:00 в переговорной."},
    "terrorist":  {"subject": "Срочно",
                   "body": "Мы готовим теракт против участников собрания. "
                           "Взорвём зал 15 числа, оружие уже закуплено."},
    "technogenic":{"subject": "Инцидент на производстве",
                   "body": "Произошла авария на производстве: выброс хлора в цехе 3, "
                           "возможна утечка отравляющих веществ, людей эвакуируют."},
    "illegal":    {"subject": "Счёт на оплату",
                   "body": "Переведите 500 000 рублей на карту 4276 **** **** 1234 "
                           "до пятницы, иначе мы убьём вашу семью, адрес дома уже знаем."},
    "vague":      {"subject": "Про нас",
                   "body": "У нас всё под контролем. Но если что-то пойдёт не так, "
                           "будет неприятно. Ждите визита."},
}


@app.get("/send-test", response_class=HTMLResponse)
def page_send_test_form(request: Request):
    return templates.TemplateResponse(request, "send_test.html", {
        "result": {}, "error": "", "preset": "",
        "defaults": {"sender": "attacker@test.local",
                     "recipient": SENDER["to_addr"],
                     "subject": "Test", "body": ""},
    })


@app.post("/send-test", response_class=HTMLResponse)
def page_send_test(request: Request,
                   sender: str = Form(default="attacker@test.local"),
                   recipient: str = Form(default="user1@corp.com"),
                   subject: str = Form(default="Test"),
                   body: str = Form(default=""),
                   preset: str = Form(default="")):
    if preset in TEST_PRESETS:
        subject = TEST_PRESETS[preset]["subject"]
        body    = TEST_PRESETS[preset]["body"]

    payload = TestMessage(sender=sender, recipient=recipient,
                          subject=subject, body=body)
    try:
        result = _send_test(payload)
        error = ""
    except HTTPException as exc:
        result, error = {}, str(exc.detail)

    return templates.TemplateResponse(request, "send_test.html", {
        "result": result, "error": error, "preset": preset,
        "defaults": {"sender": sender, "recipient": recipient,
                     "subject": subject, "body": body},
    })


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True, "db": storage.DB_PATH.exists(),
            "quarantine": storage.QUARANTINE_DIR.is_dir()}


if __name__ == "__main__":
    print(f"Dashboard: http://{WEB['host']}:{WEB['port']}")
    print(f"API docs:  http://{WEB['host']}:{WEB['port']}/docs")
    uvicorn.run(app, host=WEB["host"], port=WEB["port"], log_level="info")
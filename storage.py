# storage.py
import json
import sqlite3
import threading
import time
from pathlib import Path

CFG = json.load(open("config.json"))
DB_PATH = Path(CFG["storage"]["db"])
QUARANTINE_DIR = Path(CFG["storage"]["quarantine_dir"])
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

_lock = threading.Lock()
_conn = sqlite3.connect(DB_PATH, check_same_thread=False)
_conn.row_factory = sqlite3.Row


def init_db() -> None:
    with _lock, _conn:
        _conn.executescript("""
        CREATE TABLE IF NOT EXISTS messages (
            message_id   TEXT PRIMARY KEY,
            created_at   REAL,
            sender       TEXT,
            recipient    TEXT,
            subject      TEXT,
            body         TEXT,
            category     INTEGER,
            confidence   REAL,
            reason       TEXT,
            action       TEXT,      -- deliver / quarantine / review / failed
            eml_path     TEXT
        );
        CREATE TABLE IF NOT EXISTS events (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id   TEXT,
            created_at   REAL,
            event        TEXT,
            detail       TEXT
        );
        CREATE TABLE IF NOT EXISTS settings (
            key          TEXT PRIMARY KEY,
            value        TEXT
        );
        """)


def add_message(message_id: str, sender: str, recipient: str, subject: str,
                body: str, category: int, confidence: float, reason: str,
                action: str, eml_path: str | None = None) -> None:
    with _lock, _conn:
        _conn.execute(
            "INSERT OR REPLACE INTO messages VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (message_id, time.time(), sender, recipient, subject, body,
             category, confidence, reason, action, eml_path),
        )


def get_message(message_id: str) -> dict | None:
    row = _conn.execute(
        "SELECT * FROM messages WHERE message_id = ?", (message_id,)
    ).fetchone()
    return dict(row) if row else None


def list_messages(status: str | None = None, limit: int = 50,
                  offset: int = 0) -> list[dict]:
    if status:
        rows = _conn.execute(
            "SELECT * FROM messages WHERE action = ? "
            "ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (status, limit, offset),
        ).fetchall()
    else:
        rows = _conn.execute(
            "SELECT * FROM messages ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
    return [dict(r) for r in rows]


def statistics() -> dict:
    cur = _conn.execute("SELECT action, COUNT(*) AS n FROM messages GROUP BY action")
    by_action = {r["action"]: r["n"] for r in cur.fetchall()}

    total = sum(by_action.values())
    first = _conn.execute("SELECT MIN(created_at) FROM messages").fetchone()[0]
    days = int((time.time() - first) / 86400) + 1 if first else 0

    return {
        "total": total,
        "delivered":  by_action.get("deliver", 0),
        "quarantined": by_action.get("quarantine", 0),
        "review":     by_action.get("review", 0),
        "failed":     by_action.get("failed", 0),
        "days": days,
    }


def add_event(message_id: str, event: str, **detail) -> None:
    with _lock, _conn:
        _conn.execute(
            "INSERT INTO events (message_id, created_at, event, detail) VALUES (?,?,?,?)",
            (message_id, time.time(), event, json.dumps(detail, ensure_ascii=False)),
        )


def read_events(message_id: str | None = None, limit: int = 100) -> list[dict]:
    if message_id:
        rows = _conn.execute(
            "SELECT * FROM events WHERE message_id = ? ORDER BY id DESC LIMIT ?",
            (message_id, limit),
        ).fetchall()
    else:
        rows = _conn.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["detail"] = json.loads(d["detail"]) if d["detail"] else {}
        except json.JSONDecodeError:
            d["detail"] = {}
        out.append(d)
    return out


def set_setting(key: str, value) -> None:
    with _lock, _conn:
        _conn.execute(
            "INSERT OR REPLACE INTO settings VALUES (?, ?)",
            (key, json.dumps(value, ensure_ascii=False)),
        )


def get_setting(key: str, default=None):
    row = _conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return json.loads(row["value"]) if row else default


def get_all_settings() -> dict:
    rows = _conn.execute("SELECT key, value FROM settings").fetchall()
    return {r["key"]: json.loads(r["value"]) for r in rows}


def save_quarantine(message_id: str, raw: bytes) -> str:
    path = QUARANTINE_DIR / f"{message_id}.eml"
    path.write_bytes(raw)
    return str(path)


def read_quarantine(message_id: str) -> bytes | None:
    path = QUARANTINE_DIR / f"{message_id}.eml"
    return path.read_bytes() if path.exists() else None


init_db()
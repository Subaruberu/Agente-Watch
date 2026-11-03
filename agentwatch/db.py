"""Camada de armazenamento (SQLite)."""
import os
import sqlite3
from pathlib import Path

DEFAULT_DB = Path.home() / ".agentwatch" / "events.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    session_id  TEXT,
    hook_event  TEXT,
    tool_name   TEXT,
    command     TEXT,
    file_path   TEXT,
    url         TEXT,
    cwd         TEXT,
    raw_input   TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_tool    ON events(tool_name);

CREATE TABLE IF NOT EXISTS alerts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id      INTEGER NOT NULL REFERENCES events(id),
    ts            TEXT NOT NULL,
    rule_id       TEXT NOT NULL,
    severity      INTEGER NOT NULL,
    severity_name TEXT NOT NULL,
    message       TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_event ON alerts(event_id);
CREATE INDEX IF NOT EXISTS idx_alerts_rule  ON alerts(rule_id);
"""

COLUMNS = (
    "ts", "session_id", "hook_event", "tool_name",
    "command", "file_path", "url", "cwd", "raw_input",
)


def db_path() -> Path:
    """Caminho do banco. Pode ser sobrescrito com AGENTWATCH_DB."""
    return Path(os.environ.get("AGENTWATCH_DB", DEFAULT_DB))


def connect(path=None, check_same_thread: bool = True) -> sqlite3.Connection:
    path = Path(path) if path else db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=5, check_same_thread=check_same_thread)
    conn.executescript(SCHEMA)
    return conn


def insert_event(conn: sqlite3.Connection, event: dict) -> int:
    """Grava um evento e devolve o id gerado."""
    values = [event.get(col) for col in COLUMNS]
    placeholders = ", ".join("?" for _ in COLUMNS)
    cur = conn.execute(
        f"INSERT INTO events ({', '.join(COLUMNS)}) VALUES ({placeholders})",
        values,
    )
    conn.commit()
    return cur.lastrowid


def insert_alert(conn: sqlite3.Connection, event_id: int, ts: str,
                 rule_id: str, severity: int, severity_name: str, message: str) -> None:
    conn.execute(
        "INSERT INTO alerts (event_id, ts, rule_id, severity, severity_name, message) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (event_id, ts, rule_id, severity, severity_name, message),
    )
    conn.commit()

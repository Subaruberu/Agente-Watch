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
"""

COLUMNS = (
    "ts", "session_id", "hook_event", "tool_name",
    "command", "file_path", "url", "cwd", "raw_input",
)


def db_path() -> Path:
    """Caminho do banco. Pode ser sobrescrito com AGENTWATCH_DB."""
    return Path(os.environ.get("AGENTWATCH_DB", DEFAULT_DB))


def connect(path=None) -> sqlite3.Connection:
    path = Path(path) if path else db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=5)
    conn.executescript(SCHEMA)
    return conn


def insert_event(conn: sqlite3.Connection, event: dict) -> None:
    values = [event.get(col) for col in COLUMNS]
    placeholders = ", ".join("?" for _ in COLUMNS)
    conn.execute(
        f"INSERT INTO events ({', '.join(COLUMNS)}) VALUES ({placeholders})",
        values,
    )
    conn.commit()

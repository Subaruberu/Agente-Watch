"""Consultas de leitura sobre eventos e alertas (usadas pela API e pelo painel).

Todas recebem uma conexao SQLite e devolvem estruturas simples (dict/list),
prontas para virar JSON.
"""
import sqlite3
from typing import Optional

from .monitors import Severity

SEVERITY_NAMES = {s.value: s.name for s in Severity}
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def _prepare(conn: sqlite3.Connection) -> sqlite3.Connection:
    conn.row_factory = sqlite3.Row
    return conn


def _rows(cursor) -> list:
    return [dict(row) for row in cursor.fetchall()]


def get_stats(conn: sqlite3.Connection) -> dict:
    conn = _prepare(conn)
    scalar = lambda sql: conn.execute(sql).fetchone()[0]  # noqa: E731

    by_severity = {name: 0 for name in SEVERITY_ORDER}
    for row in conn.execute("SELECT severity_name, COUNT(*) AS n FROM alerts GROUP BY severity_name"):
        by_severity[row["severity_name"]] = row["n"]

    by_rule = {r["rule_id"]: r["n"] for r in conn.execute(
        "SELECT rule_id, COUNT(*) AS n FROM alerts GROUP BY rule_id ORDER BY n DESC, rule_id")}
    by_tool = {(r["tool_name"] or "-"): r["n"] for r in conn.execute(
        "SELECT tool_name, COUNT(*) AS n FROM events GROUP BY tool_name ORDER BY n DESC, tool_name")}

    daily = {}
    for row in conn.execute("SELECT substr(ts, 1, 10) AS day, COUNT(*) AS n FROM events GROUP BY day"):
        daily.setdefault(row["day"], {"day": row["day"], "events": 0, "alerts": 0})["events"] = row["n"]
    for row in conn.execute("SELECT substr(ts, 1, 10) AS day, COUNT(*) AS n FROM alerts GROUP BY day"):
        daily.setdefault(row["day"], {"day": row["day"], "events": 0, "alerts": 0})["alerts"] = row["n"]

    return {
        "events": scalar("SELECT COUNT(*) FROM events"),
        "alerts": scalar("SELECT COUNT(*) FROM alerts"),
        "sessions": scalar("SELECT COUNT(DISTINCT session_id) FROM events"),
        "alerts_by_severity": by_severity,
        "alerts_by_rule": by_rule,
        "events_by_tool": by_tool,
        "daily": [daily[d] for d in sorted(daily)][-30:],
    }


def list_events(conn, limit: int = 50, offset: int = 0,
                session_id: Optional[str] = None, tool_name: Optional[str] = None) -> list:
    conn = _prepare(conn)
    where, params = [], []
    if session_id:
        where.append("session_id = ?")
        params.append(session_id)
    if tool_name:
        where.append("tool_name = ?")
        params.append(tool_name)
    clause = f"WHERE {' AND '.join(where)}" if where else ""
    return _rows(conn.execute(
        "SELECT id, ts, session_id, hook_event, tool_name, command, file_path, url, cwd "
        f"FROM events {clause} ORDER BY id DESC LIMIT ? OFFSET ?",
        (*params, limit, offset)))


def list_alerts(conn, limit: int = 50, offset: int = 0, min_severity: str = "LOW",
                rule_id: Optional[str] = None, session_id: Optional[str] = None) -> list:
    conn = _prepare(conn)
    where, params = ["a.severity >= ?"], [Severity[min_severity].value]
    if rule_id:
        where.append("a.rule_id = ?")
        params.append(rule_id)
    if session_id:
        where.append("e.session_id = ?")
        params.append(session_id)
    return _rows(conn.execute(
        "SELECT a.id, a.event_id, a.ts, a.rule_id, a.severity_name AS severity, "
        "a.severity AS severity_level, a.message, e.session_id, e.tool_name, "
        "COALESCE(e.command, e.file_path, e.url, '') AS detail "
        "FROM alerts a JOIN events e ON e.id = a.event_id "
        f"WHERE {' AND '.join(where)} ORDER BY a.id DESC LIMIT ? OFFSET ?",
        (*params, limit, offset)))


def list_sessions(conn, limit: int = 50) -> list:
    conn = _prepare(conn)
    rows = _rows(conn.execute(
        """
        WITH ev AS (
            SELECT session_id, COUNT(*) AS events, MIN(ts) AS first_ts, MAX(ts) AS last_ts
            FROM events GROUP BY session_id
        ), al AS (
            SELECT e.session_id, COUNT(*) AS alerts, MAX(a.severity) AS max_level
            FROM alerts a JOIN events e ON e.id = a.event_id GROUP BY e.session_id
        )
        SELECT ev.session_id, ev.events, ev.first_ts, ev.last_ts,
               COALESCE(al.alerts, 0) AS alerts, al.max_level
        FROM ev LEFT JOIN al ON al.session_id IS ev.session_id
        ORDER BY ev.last_ts DESC LIMIT ?
        """, (limit,)))
    for row in rows:
        level = row.pop("max_level")
        row["max_severity"] = SEVERITY_NAMES.get(level) if level else None
    return rows


def session_timeline(conn, session_id: str) -> list:
    """Eventos da sessao em ordem cronologica, cada um com seus alertas."""
    conn = _prepare(conn)
    events = _rows(conn.execute(
        "SELECT id, ts, tool_name, command, file_path, url, cwd "
        "FROM events WHERE session_id = ? ORDER BY id", (session_id,)))
    if not events:
        return []
    ids = [e["id"] for e in events]
    marks = ",".join("?" for _ in ids)
    alerts = {}
    for row in conn.execute(
            f"SELECT event_id, rule_id, severity_name, message FROM alerts "
            f"WHERE event_id IN ({marks}) ORDER BY severity DESC", ids):
        alerts.setdefault(row["event_id"], []).append(
            {"rule_id": row["rule_id"], "severity": row["severity_name"], "message": row["message"]})
    for event in events:
        event["alerts"] = alerts.get(event["id"], [])
    return events

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

from agentwatch.db import connect, insert_event
from agentwatch.scan import rescan

ROOT = Path(__file__).resolve().parent.parent


def run_hook(payload, db_file):
    env = {**os.environ, "AGENTWATCH_DB": str(db_file)}
    return subprocess.run(
        [sys.executable, str(ROOT / "log_event.py")],
        input=json.dumps(payload), text=True, capture_output=True, env=env,
    )


def test_hook_stores_alert_for_risky_command(tmp_path):
    db = tmp_path / "e.db"
    result = run_hook({
        "session_id": "s", "hook_event_name": "PreToolUse", "tool_name": "Bash",
        "tool_input": {"command": "git push --force origin main"},
    }, db)
    assert result.returncode == 0
    rows = sqlite3.connect(db).execute(
        "SELECT rule_id, severity_name FROM alerts").fetchall()
    assert rows == [("force-push", "HIGH")]


def test_hook_no_alert_for_safe_command(tmp_path):
    db = tmp_path / "e.db"
    run_hook({"tool_name": "Bash", "tool_input": {"command": "ls -la"}}, db)
    conn = sqlite3.connect(db)
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 0


def test_rescan_regenerates_alerts(tmp_path):
    conn = connect(tmp_path / "e.db")
    insert_event(conn, {"ts": "2026-01-01T00:00:00+00:00", "tool_name": "Bash",
                        "command": "rm -rf /", "cwd": "/home/u/p"})
    first = rescan(conn)
    second = rescan(conn)  # idempotente: nao duplica
    assert first == second
    assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1

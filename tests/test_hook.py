import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

from agentwatch.hook import parse_event, redact

ROOT = Path(__file__).resolve().parent.parent


def run_hook(stdin_text, db_file):
    env = {**os.environ, "AGENTWATCH_DB": str(db_file)}
    return subprocess.run(
        [sys.executable, str(ROOT / "log_event.py")],
        input=stdin_text, text=True, capture_output=True, env=env,
    )


def test_parse_bash_event():
    ev = parse_event({
        "session_id": "s1", "hook_event_name": "PreToolUse",
        "tool_name": "Bash", "tool_input": {"command": "ls -la"}, "cwd": "/tmp",
    })
    assert ev["tool_name"] == "Bash"
    assert ev["command"] == "ls -la"
    assert ev["session_id"] == "s1"


def test_parse_file_event():
    ev = parse_event({
        "tool_name": "Read", "tool_input": {"file_path": "/app/main.py"},
    })
    assert ev["file_path"] == "/app/main.py"
    assert ev["command"] is None


def test_redact_secrets():
    assert "sk-abcdefghijklmnop1234" not in redact("key sk-abcdefghijklmnop1234")
    assert "hunter2" not in redact("password=hunter2")
    assert redact("ls -la") == "ls -la"


def test_end_to_end_writes_row(tmp_path):
    db = tmp_path / "events.db"
    payload = json.dumps({
        "session_id": "s1", "hook_event_name": "PreToolUse",
        "tool_name": "Bash", "tool_input": {"command": "echo oi"},
    })
    result = run_hook(payload, db)
    assert result.returncode == 0
    rows = sqlite3.connect(db).execute(
        "SELECT tool_name, command FROM events").fetchall()
    assert rows == [("Bash", "echo oi")]


def test_malformed_input_never_breaks_agent(tmp_path):
    result = run_hook("isto nao e json", tmp_path / "events.db")
    assert result.returncode == 0

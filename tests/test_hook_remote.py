import io
import json
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from agentwatch import hook

PAYLOAD = {
    "session_id": "s1", "hook_event_name": "PreToolUse", "tool_name": "Bash",
    "tool_input": {"command": "deploy --token=abc123SECRET", "env": {"password": "hunter2"}},
    "cwd": "/p", "transcript_path": "/home/u/.claude/transcript.jsonl",
}


class Recorder(BaseHTTPRequestHandler):
    received = []
    status = 201

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        Recorder.received.append({"path": self.path,
                                  "headers": {k.lower(): v for k, v in self.headers.items()},
                                  "body": json.loads(self.rfile.read(length))})
        self.send_response(Recorder.status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *args):
        pass


@pytest.fixture
def server():
    Recorder.received, Recorder.status = [], 201
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Recorder)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTWATCH_DB", str(tmp_path / "local.db"))
    monkeypatch.delenv("AGENTWATCH_API_URL", raising=False)
    monkeypatch.delenv("AGENTWATCH_API_KEY", raising=False)
    return tmp_path / "local.db"


def run_hook(monkeypatch, payload=PAYLOAD):
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    return hook.main()


def local_rows(db):
    if not db.exists():
        return []
    return sqlite3.connect(db).execute("SELECT tool_name FROM events").fetchall()


def test_remote_mode_posts_event_and_skips_local_db(server, env, monkeypatch):
    monkeypatch.setenv("AGENTWATCH_API_URL", server)
    assert run_hook(monkeypatch) == 0
    assert len(Recorder.received) == 1 and Recorder.received[0]["path"] == "/events"
    assert local_rows(env) == []


def test_remote_payload_is_redacted_and_minimized(server, env, monkeypatch):
    monkeypatch.setenv("AGENTWATCH_API_URL", server)
    run_hook(monkeypatch)
    body = Recorder.received[0]["body"]
    text = json.dumps(body)
    assert "abc123SECRET" not in text and "hunter2" not in text
    assert "transcript_path" not in body          # campo nao necessario nao sai da maquina
    assert body["tool_input"]["command"].startswith("deploy --token=[REDACTED]")


def test_remote_sends_api_key_header(server, env, monkeypatch):
    monkeypatch.setenv("AGENTWATCH_API_URL", server)
    monkeypatch.setenv("AGENTWATCH_API_KEY", "chave-teste")
    run_hook(monkeypatch)
    assert Recorder.received[0]["headers"]["x-api-key"] == "chave-teste"


def test_api_error_status_falls_back_to_local(server, env, monkeypatch):
    Recorder.status = 500
    monkeypatch.setenv("AGENTWATCH_API_URL", server)
    assert run_hook(monkeypatch) == 0
    assert local_rows(env) == [("Bash",)]


def test_unreachable_api_falls_back_to_local(env, monkeypatch):
    monkeypatch.setenv("AGENTWATCH_API_URL", "http://127.0.0.1:1")  # porta fechada
    assert run_hook(monkeypatch) == 0
    assert local_rows(env) == [("Bash",)]


def test_plain_http_to_remote_host_is_refused(env, monkeypatch, capsys):
    def boom(*a, **k):
        raise AssertionError("nao deveria tentar a rede")
    monkeypatch.setattr("urllib.request.urlopen", boom)
    monkeypatch.setenv("AGENTWATCH_API_URL", "http://servidor-remoto.example.com")
    assert run_hook(monkeypatch) == 0
    assert local_rows(env) == [("Bash",)]
    assert "https" in capsys.readouterr().err


def test_https_remote_url_is_accepted():
    import os
    os.environ["AGENTWATCH_API_URL"] = "https://api.exemplo.com/"
    try:
        assert hook.remote_url() == "https://api.exemplo.com"
    finally:
        del os.environ["AGENTWATCH_API_URL"]


def test_invalid_timeout_uses_default(monkeypatch):
    monkeypatch.setenv("AGENTWATCH_REMOTE_TIMEOUT", "abc")
    assert hook.remote_timeout() == hook.DEFAULT_REMOTE_TIMEOUT


def test_redact_deep_handles_nested_structures():
    out = hook.redact_deep({"a": ["password=x1", {"b": "ok"}], "n": 3, "none": None})
    assert out == {"a": ["password=[REDACTED]", {"b": "ok"}], "n": 3, "none": None}


def test_redact_deep_masks_values_of_secret_named_keys():
    out = hook.redact_deep({"password": "hunter2", "apiKey": "k", "bypass_cache": "yes",
                            "nested": {"access_token": "t", "name": "ok"}, "port": 5432})
    assert out == {"password": "[REDACTED]", "apiKey": "[REDACTED]", "bypass_cache": "yes",
                   "nested": {"access_token": "[REDACTED]", "name": "ok"}, "port": 5432}


def test_parse_event_masks_secret_keys_in_raw_input():
    ev = hook.parse_event({"tool_name": "Write",
                           "tool_input": {"file_path": "/a/config.yml", "password": "hunter2"}})
    assert "hunter2" not in ev["raw_input"]

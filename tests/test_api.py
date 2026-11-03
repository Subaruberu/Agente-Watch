import pytest
from fastapi.testclient import TestClient

from agentwatch.api import create_app

PUSH = {"session_id": "s1", "hook_event_name": "PreToolUse", "tool_name": "Bash",
        "tool_input": {"command": "git push --force origin main"}, "cwd": "/home/u/p"}
LS = {"session_id": "s1", "hook_event_name": "PreToolUse", "tool_name": "Bash",
      "tool_input": {"command": "ls -la"}, "cwd": "/home/u/p"}
RM = {"session_id": "s2", "tool_name": "Bash", "tool_input": {"command": "rm -rf /"}, "cwd": "/home/u/p"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.delenv("AGENTWATCH_API_KEY", raising=False)
    return TestClient(create_app(tmp_path / "api.db"))


def test_health(client):
    body = client.get("/health").json()
    assert body["status"] == "ok"


def test_ingest_returns_alerts(client):
    r = client.post("/events", json=PUSH)
    assert r.status_code == 201
    body = r.json()
    assert body["event_id"] == 1
    assert [(a["rule_id"], a["severity"]) for a in body["alerts"]] == [("force-push", "HIGH")]


def test_ingest_safe_event_has_no_alerts(client):
    assert client.post("/events", json=LS).json()["alerts"] == []


def test_ingest_redacts_secrets(client):
    client.post("/events", json={"tool_name": "Bash",
                                 "tool_input": {"command": "export password=hunter2"}})
    stored = client.get("/events").json()[0]["command"]
    assert "hunter2" not in stored


def test_ingest_accepts_extra_fields_and_odd_tool_input(client):
    r = client.post("/events", json={"tool_name": "X", "tool_input": "texto", "campo_novo": 1})
    assert r.status_code == 201


def test_list_events_filters_and_order(client):
    for p in (PUSH, LS, RM):
        client.post("/events", json=p)
    events = client.get("/events").json()
    assert [e["id"] for e in events] == [3, 2, 1]
    assert len(client.get("/events", params={"session_id": "s1"}).json()) == 2
    assert len(client.get("/events", params={"limit": 1}).json()) == 1


def test_list_alerts_min_severity_and_rule(client):
    for p in (PUSH, RM):
        client.post("/events", json=p)
    assert len(client.get("/alerts").json()) == 2
    critical = client.get("/alerts", params={"min_severity": "CRITICAL"}).json()
    assert [a["rule_id"] for a in critical] == ["destructive-rm"]
    only_push = client.get("/alerts", params={"rule_id": "force-push"}).json()
    assert [a["severity"] for a in only_push] == ["HIGH"]
    assert only_push[0]["detail"] == "git push --force origin main"


def test_stats(client):
    for p in (PUSH, LS, RM):
        client.post("/events", json=p)
    s = client.get("/stats").json()
    assert (s["events"], s["alerts"], s["sessions"]) == (3, 2, 2)
    assert s["alerts_by_severity"] == {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 0}
    assert s["events_by_tool"] == {"Bash": 3}
    assert s["daily"][0]["events"] == 3 and s["daily"][0]["alerts"] == 2


def test_stats_on_empty_database(client):
    s = client.get("/stats").json()
    assert s["events"] == 0 and s["daily"] == []
    assert set(s["alerts_by_severity"]) == {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


def test_sessions_and_timeline(client):
    for p in (PUSH, LS, RM):
        client.post("/events", json=p)
    sessions = {s["session_id"]: s for s in client.get("/sessions").json()}
    assert sessions["s1"]["events"] == 2 and sessions["s1"]["max_severity"] == "HIGH"
    assert sessions["s2"]["max_severity"] == "CRITICAL"
    timeline = client.get("/sessions/s1/timeline").json()
    assert [e["tool_name"] for e in timeline] == ["Bash", "Bash"]
    assert timeline[0]["alerts"][0]["rule_id"] == "force-push" and timeline[1]["alerts"] == []


def test_timeline_unknown_session_is_404(client):
    assert client.get("/sessions/nao-existe/timeline").status_code == 404


@pytest.mark.parametrize("params", [{"limit": 0}, {"limit": 501}, {"offset": -1},
                                    {"min_severity": "ALTISSIMA"}])
def test_invalid_query_params_are_rejected(client, params):
    assert client.get("/alerts", params=params).status_code == 422


def test_api_key_protects_routes_but_not_health(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTWATCH_API_KEY", "segredo-123")
    c = TestClient(create_app(tmp_path / "k.db"))
    assert c.get("/health").status_code == 200
    assert c.get("/stats").status_code == 401
    assert c.post("/events", json=LS).status_code == 401
    assert c.get("/stats", headers={"X-API-Key": "errada"}).status_code == 401
    assert c.get("/stats", headers={"X-API-Key": "segredo-123"}).status_code == 200
    assert c.post("/events", json=LS, headers={"X-API-Key": "segredo-123"}).status_code == 201


def test_api_key_with_non_ascii_does_not_crash(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTWATCH_API_KEY", "segredo")
    c = TestClient(create_app(tmp_path / "k.db"))
    # clientes reais podem enviar bytes fora de ASCII no cabecalho; nao pode virar erro 500
    assert c.get("/stats", headers={"X-API-Key": b"chave-\xe7"}).status_code == 401

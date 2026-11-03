import pytest
from fastapi.testclient import TestClient

from agentwatch.api import create_app
from agentwatch.datasource import ApiSource, DbSource, get_source
from agentwatch.seed import main as seed_main
from agentwatch.seed import seed_database


@pytest.fixture
def seeded(tmp_path, monkeypatch):
    monkeypatch.delenv("AGENTWATCH_API_KEY", raising=False)
    db = tmp_path / "demo.db"
    seed_database(db)
    return db


def test_seed_creates_events_alerts_and_sessions(seeded):
    stats = DbSource(seeded).stats()
    assert stats["events"] == 70 and stats["alerts"] > 0
    assert 1 < stats["sessions"] <= 5
    assert len(stats["daily"]) >= 2


def test_seed_is_deterministic(tmp_path):
    a, b = tmp_path / "a.db", tmp_path / "b.db"
    seed_database(a)
    seed_database(b)
    assert DbSource(a).stats()["alerts_by_rule"] == DbSource(b).stats()["alerts_by_rule"]


def test_seed_cli_refuses_to_overwrite(tmp_path, capsys):
    db = tmp_path / "d.db"
    assert seed_main(["--db", str(db)]) == 0
    assert seed_main(["--db", str(db)]) == 2
    assert "--force" in capsys.readouterr().err
    assert seed_main(["--db", str(db), "--force"]) == 0


def test_db_and_api_sources_return_identical_data(seeded):
    http = TestClient(create_app(seeded))
    api = ApiSource("http://testserver", http=http)
    db = DbSource(seeded)
    assert api.stats() == db.stats()
    assert api.sessions() == db.sessions()
    assert api.alerts(limit=500) == db.alerts(limit=500)
    assert api.alerts(min_severity="HIGH", rule_id="destructive-rm") == \
        db.alerts(min_severity="HIGH", rule_id="destructive-rm")
    session = next(s["session_id"] for s in db.sessions() if s["session_id"])
    assert api.timeline(session) == db.timeline(session)


def test_api_source_sends_key_header():
    seen = {}

    class Http:
        def get(self, url, params=None, headers=None, timeout=None):
            seen.update(url=url, headers=headers, params=params)
            return type("R", (), {"raise_for_status": lambda s: None, "json": lambda s: []})()

    ApiSource("http://x/", api_key="k", http=Http()).alerts(rule_id=None)
    assert seen["url"] == "http://x/alerts"
    assert seen["headers"] == {"X-API-Key": "k"}
    assert "rule_id" not in seen["params"]  # parametros None nao sao enviados


def test_get_source_follows_environment(monkeypatch):
    monkeypatch.delenv("AGENTWATCH_API_URL", raising=False)
    assert isinstance(get_source(), DbSource)
    monkeypatch.setenv("AGENTWATCH_API_URL", "http://localhost:8000")
    assert isinstance(get_source(), ApiSource)

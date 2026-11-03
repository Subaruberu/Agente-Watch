from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from agentwatch.db import connect
from agentwatch.seed import seed_database

DASHBOARD = str(Path(__file__).resolve().parent.parent / "dashboard.py")


def run_app(monkeypatch, db):
    monkeypatch.setenv("AGENTWATCH_DB", str(db))
    monkeypatch.delenv("AGENTWATCH_API_URL", raising=False)
    at = AppTest.from_file(DASHBOARD, default_timeout=60)
    at.run()
    return at


def test_dashboard_renders_with_data(tmp_path, monkeypatch):
    db = tmp_path / "demo.db"
    seed_database(db)
    at = run_app(monkeypatch, db)
    assert not at.exception
    metrics = {m.label: m.value for m in at.metric}
    assert metrics["Eventos"] == "70"
    assert int(metrics["Alertas"]) > 0
    assert len(at.tabs) == 3 and len(at.dataframe) >= 3


def test_dashboard_shows_hint_when_empty(tmp_path, monkeypatch):
    db = tmp_path / "empty.db"
    connect(db).close()
    at = run_app(monkeypatch, db)
    assert not at.exception
    assert any("Nenhum evento" in i.value for i in at.info)
    assert len(at.metric) == 0


def test_dashboard_severity_filter_changes_table(tmp_path, monkeypatch):
    db = tmp_path / "demo.db"
    seed_database(db)
    at = run_app(monkeypatch, db)
    all_text = next(m.value for m in at.markdown if "alertas (severidade" in m.value)
    at.select_slider[0].set_value("CRITICAL").run()
    assert not at.exception
    critical_text = next(m.value for m in at.markdown if "alertas (severidade" in m.value)
    assert all_text != critical_text and "CRITICAL" in critical_text

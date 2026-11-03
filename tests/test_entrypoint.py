import os
import shutil
import sqlite3
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.skipif(not (shutil.which("sh") and shutil.which("python")),
                                reason="precisa de 'sh' e 'python' no PATH")


def run_entrypoint(db, **env):
    full_env = {**os.environ, "AGENTWATCH_DB": str(db), **env}
    return subprocess.run(["sh", str(ROOT / "docker-entrypoint.sh")], cwd=ROOT, env=full_env,
                          capture_output=True, text=True, timeout=60)


def test_invalid_service_exits_with_error(tmp_path):
    result = run_entrypoint(tmp_path / "e.db", AGENTWATCH_SERVICE="inexistente")
    assert result.returncode == 2 and "invalido" in result.stderr


def test_seed_on_start_creates_synthetic_data_once(tmp_path):
    db = tmp_path / "e.db"
    run_entrypoint(db, AGENTWATCH_SERVICE="inexistente", AGENTWATCH_SEED_ON_START="1")
    count = sqlite3.connect(db).execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert count == 70
    # segunda subida: nao pode recriar nem duplicar
    run_entrypoint(db, AGENTWATCH_SERVICE="inexistente", AGENTWATCH_SEED_ON_START="1")
    assert sqlite3.connect(db).execute("SELECT COUNT(*) FROM events").fetchone()[0] == 70


def test_no_seed_by_default(tmp_path):
    db = tmp_path / "e.db"
    run_entrypoint(db, AGENTWATCH_SERVICE="inexistente")
    assert not db.exists()

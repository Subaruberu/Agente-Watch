"""Fontes de dados do painel: SQLite direto (local) ou API HTTP (remoto).

get_source() escolhe pela variavel AGENTWATCH_API_URL: se definida, usa a API
(com AGENTWATCH_API_KEY, se houver); caso contrario le o SQLite local.
Ambas devolvem exatamente as mesmas estruturas.
"""
import os
from typing import Optional

from . import queries
from .db import connect, db_path


class DbSource:
    label = "SQLite local"

    def __init__(self, path=None):
        self.path = path

    def _conn(self):
        return connect(self.path)

    def _run(self, fn, *args, **kwargs):
        conn = self._conn()
        try:
            return fn(conn, *args, **kwargs)
        finally:
            conn.close()

    def stats(self):
        return self._run(queries.get_stats)

    def alerts(self, limit=200, min_severity="LOW", rule_id=None, session_id=None):
        return self._run(queries.list_alerts, limit, 0, min_severity, rule_id, session_id)

    def sessions(self, limit=100):
        return self._run(queries.list_sessions, limit)

    def timeline(self, session_id):
        return self._run(queries.session_timeline, session_id)

    @property
    def where(self):
        return str(self.path or db_path())


class ApiSource:
    label = "API"

    def __init__(self, base_url: str, api_key: Optional[str] = None, http=None, timeout: float = 10):
        if http is None:
            import requests
            http = requests
        self.base_url = base_url.rstrip("/")
        self.headers = {"X-API-Key": api_key} if api_key else {}
        self.http = http
        self.timeout = timeout

    def _get(self, path, **params):
        params = {k: v for k, v in params.items() if v is not None}
        response = self.http.get(f"{self.base_url}{path}", params=params,
                                 headers=self.headers, timeout=self.timeout)
        response.raise_for_status()
        return response.json()

    def stats(self):
        return self._get("/stats")

    def alerts(self, limit=200, min_severity="LOW", rule_id=None, session_id=None):
        return self._get("/alerts", limit=limit, min_severity=min_severity,
                         rule_id=rule_id, session_id=session_id)

    def sessions(self, limit=100):
        return self._get("/sessions", limit=limit)

    def timeline(self, session_id):
        return self._get(f"/sessions/{session_id}/timeline")

    @property
    def where(self):
        return self.base_url


def get_source():
    url = os.environ.get("AGENTWATCH_API_URL")
    if url:
        return ApiSource(url, os.environ.get("AGENTWATCH_API_KEY"))
    return DbSource()

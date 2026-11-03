"""API REST do AgentWatch (FastAPI).

    uvicorn agentwatch.api:app --host 127.0.0.1 --port 8000

Seguranca: por padrao a API e aberta (pensada para localhost). Para expor em rede,
defina AGENTWATCH_API_KEY: todas as rotas, exceto /health, passam a exigir o
cabecalho X-API-Key.
"""
import os
import secrets
import sqlite3
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict

from . import __version__, queries
from .db import connect, insert_alert, insert_event
from .hook import parse_event
from .monitors import analyze

SeverityName = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class HookPayload(BaseModel):
    """Mesmo JSON que o Claude Code entrega ao hook (campos extras sao aceitos)."""
    model_config = ConfigDict(extra="allow")

    session_id: Optional[str] = None
    hook_event_name: Optional[str] = None
    tool_name: Optional[str] = None
    tool_input: Optional[Any] = None
    cwd: Optional[str] = None


def require_api_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    expected = os.environ.get("AGENTWATCH_API_KEY")
    if not expected:
        return
    given = (x_api_key or "").encode("utf-8")
    if not secrets.compare_digest(given, expected.encode("utf-8")):
        raise HTTPException(status_code=401, detail="API key ausente ou invalida")


def get_conn(request: Request):
    conn = connect(request.app.state.db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


router = APIRouter(dependencies=[Depends(require_api_key)])


@router.post("/events", status_code=201, summary="Registrar um evento e analisa-lo")
def ingest_event(payload: HookPayload, conn: sqlite3.Connection = Depends(get_conn)):
    event = parse_event(payload.model_dump())
    event_id = insert_event(conn, event)
    findings = analyze(event)
    for f in findings:
        insert_alert(conn, event_id, event["ts"], f.rule_id, int(f.severity), f.severity.name, f.message)
    return {
        "event_id": event_id,
        "alerts": [{"rule_id": f.rule_id, "severity": f.severity.name, "message": f.message}
                   for f in findings],
    }


@router.get("/events", summary="Listar eventos (mais recentes primeiro)")
def get_events(limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0),
               session_id: Optional[str] = None, tool_name: Optional[str] = None,
               conn: sqlite3.Connection = Depends(get_conn)):
    return queries.list_events(conn, limit, offset, session_id, tool_name)


@router.get("/alerts", summary="Listar alertas (mais recentes primeiro)")
def get_alerts(limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0),
               min_severity: SeverityName = "LOW", rule_id: Optional[str] = None,
               session_id: Optional[str] = None,
               conn: sqlite3.Connection = Depends(get_conn)):
    return queries.list_alerts(conn, limit, offset, min_severity, rule_id, session_id)


@router.get("/stats", summary="Totais e contagens para o painel")
def get_stats(conn: sqlite3.Connection = Depends(get_conn)):
    return queries.get_stats(conn)


@router.get("/sessions", summary="Sessoes com contagem de eventos e alertas")
def get_sessions(limit: int = Query(50, ge=1, le=500),
                 conn: sqlite3.Connection = Depends(get_conn)):
    return queries.list_sessions(conn, limit)


@router.get("/sessions/{session_id}/timeline", summary="Linha do tempo de uma sessao")
def get_timeline(session_id: str, conn: sqlite3.Connection = Depends(get_conn)):
    timeline = queries.session_timeline(conn, session_id)
    if not timeline:
        raise HTTPException(status_code=404, detail="sessao nao encontrada")
    return timeline


def create_app(db_path=None) -> FastAPI:
    """Cria a aplicacao. Sem db_path, usa AGENTWATCH_DB ou ~/.agentwatch/events.db."""
    app = FastAPI(title="AgentWatch API", version=__version__,
                  description="Eventos de agentes de codigo e alertas de seguranca.")
    app.state.db_path = db_path

    @app.get("/health", summary="Verificacao de saude (sem autenticacao)")
    def health():
        return {"status": "ok", "version": __version__}

    app.include_router(router)
    return app


app = create_app()

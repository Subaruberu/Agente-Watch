"""Hook do Claude Code: le o evento do stdin, limpa segredos e grava.

Modo local (padrao): grava no SQLite da maquina.
Modo remoto: com AGENTWATCH_API_URL definida, envia o evento a API (POST /events).
Se a API falhar, o evento e gravado localmente, entao nada se perde.

Regra de ouro: o hook NUNCA pode quebrar nem bloquear o agente.
Qualquer erro e engolido e o processo termina com codigo 0.
"""
import json
import os
import re
import sys
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlparse

from .db import connect, insert_alert, insert_event
from .monitors import analyze

MAX_LEN = 2000
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
DEFAULT_REMOTE_TIMEOUT = 1.5  # o hook roda antes de cada ferramenta: nao pode demorar
SENT_FIELDS = ("session_id", "hook_event_name", "tool_name", "tool_input", "cwd")

SECRET_PATTERNS = [
    (re.compile(r"sk-[A-Za-z0-9_\-]{16,}"), "[REDACTED]"),
    (re.compile(r"ghp_[A-Za-z0-9]{20,}"), "[REDACTED]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED]"),
    (
        re.compile(r"(?i)\b(api[_-]?key|token|secret|password)(\s*[=:]\s*)(\S+)"),
        r"\1\2[REDACTED]",
    ),
]


def redact(text):
    """Remove padroes obvios de segredo antes de gravar."""
    if not isinstance(text, str):
        return text
    for pattern, repl in SECRET_PATTERNS:
        text = pattern.sub(repl, text)
    return text


def truncate(text, limit=MAX_LEN):
    if isinstance(text, str) and len(text) > limit:
        return text[:limit] + "...[truncado]"
    return text


def clean(value):
    return truncate(redact(value))


SECRET_KEY_HINTS = ("password", "passwd", "secret", "token", "apikey", "api_key", "api-key",
                    "authorization", "credential", "private_key", "private-key", "privatekey")


def _is_secret_key(key) -> bool:
    name = str(key).lower()
    return name == "pass" or any(hint in name for hint in SECRET_KEY_HINTS)


def redact_deep(value):
    """Mascara segredos e trunca textos em qualquer nivel de dicts/listas.

    Alem de padroes no texto, mascara o VALOR de chaves com nome de segredo
    (ex.: {"password": "x"}), que o filtro por texto nao enxerga.
    """
    if isinstance(value, dict):
        return {k: "[REDACTED]" if isinstance(v, str) and _is_secret_key(k) else redact_deep(v)
                for k, v in value.items()}
    if isinstance(value, list):
        return [redact_deep(v) for v in value]
    return clean(value)


def remote_url():
    """URL da API, se configurada e segura (https, ou http apenas em localhost)."""
    url = os.environ.get("AGENTWATCH_API_URL", "").strip()
    if not url:
        return None
    parsed = urlparse(url)
    if parsed.scheme == "https" or (parsed.scheme == "http" and parsed.hostname in LOCAL_HOSTS):
        return url.rstrip("/")
    print("[agentwatch] AGENTWATCH_API_URL ignorada: use https (ou http em localhost)",
          file=sys.stderr)
    return None


def remote_timeout() -> float:
    try:
        return float(os.environ.get("AGENTWATCH_REMOTE_TIMEOUT", DEFAULT_REMOTE_TIMEOUT))
    except ValueError:
        return DEFAULT_REMOTE_TIMEOUT


def post_event(base_url: str, payload: dict) -> bool:
    """Envia o evento a API. Devolve True se ela aceitou."""
    # minimizacao de dados: so os campos necessarios, ja sem segredos
    body = {k: redact_deep(payload[k]) for k in SENT_FIELDS if k in payload}
    headers = {"Content-Type": "application/json"}
    api_key = os.environ.get("AGENTWATCH_API_KEY")
    if api_key:
        headers["X-API-Key"] = api_key
    request = urllib.request.Request(
        f"{base_url}/events", data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
        headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=remote_timeout()) as response:
            return 200 <= response.status < 300
    except Exception as exc:  # noqa: BLE001 - rede indisponivel nao pode quebrar o agente
        print(f"[agentwatch] API indisponivel ({exc}); gravando localmente", file=sys.stderr)
        return False


def parse_event(payload: dict) -> dict:
    """Transforma o JSON do hook em uma linha da tabela events."""
    tool_input = payload.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        tool_input = {"value": tool_input}

    return {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "session_id": payload.get("session_id"),
        "hook_event": payload.get("hook_event_name"),
        "tool_name": payload.get("tool_name"),
        "command": clean(tool_input.get("command")),
        "file_path": clean(tool_input.get("file_path") or tool_input.get("path")),
        "url": clean(tool_input.get("url")),
        "cwd": payload.get("cwd"),
        "raw_input": clean(json.dumps(redact_deep(tool_input), ensure_ascii=False)),
    }


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        base_url = remote_url()
        if base_url and post_event(base_url, payload):
            return 0
        event = parse_event(payload)
        conn = connect()
        try:
            event_id = insert_event(conn, event)
            for f in analyze(event):
                insert_alert(conn, event_id, event["ts"], f.rule_id,
                             int(f.severity), f.severity.name, f.message)
        finally:
            conn.close()
    except Exception as exc:  # noqa: BLE001 - o hook nunca deve falhar
        print(f"[agentwatch] erro ignorado: {exc}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

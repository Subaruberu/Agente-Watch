"""Hook do Claude Code: le o evento do stdin, limpa segredos e grava no SQLite.

Regra de ouro: o hook NUNCA pode quebrar nem bloquear o agente.
Qualquer erro e engolido e o processo termina com codigo 0.
"""
import json
import re
import sys
from datetime import datetime, timezone

from .db import connect, insert_event

MAX_LEN = 2000

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
        "raw_input": clean(json.dumps(tool_input, ensure_ascii=False)),
    }


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        event = parse_event(payload)
        conn = connect()
        try:
            insert_event(conn, event)
        finally:
            conn.close()
    except Exception as exc:  # noqa: BLE001 - o hook nunca deve falhar
        print(f"[agentwatch] erro ignorado: {exc}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

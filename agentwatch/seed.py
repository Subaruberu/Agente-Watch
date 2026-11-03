"""Gera dados SINTETICOS para demonstracao do painel.

    python -m agentwatch.seed --db /tmp/demo.db
    AGENTWATCH_DB=/tmp/demo.db streamlit run dashboard.py

Usa os eventos de data/labeled_events.jsonl, espalhados em varias sessoes e dias.
Exige --db explicito para nunca misturar dados de teste com o seu banco real.
"""
import argparse
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .db import connect, insert_alert, insert_event
from .evaluate import DEFAULT_DATA, load_dataset
from .hook import parse_event
from .monitors import analyze


def build_payloads(dataset, n=70, days=6, sessions=5, seed=7, now=None, bad_ratio=0.22):
    rng = random.Random(seed)
    now = now or datetime.now(timezone.utc)
    safe = [r for r in dataset if r["label"] == "safe"]
    bad = [r for r in dataset if r["label"] == "suspicious"]
    n_bad = round(n * bad_ratio)
    picked = [rng.choice(bad) for _ in range(n_bad)] + [rng.choice(safe) for _ in range(n - n_bad)]
    rng.shuffle(picked)

    stamps = sorted(now - timedelta(seconds=rng.randint(0, days * 86400)) for _ in picked)
    per_session = max(1, len(picked) // sessions)
    payloads = []
    for i, (row, ts) in enumerate(zip(picked, stamps)):
        event = row["event"]
        raw = event.get("raw_input")
        payloads.append((ts, {
            "session_id": f"demo-{min(i // per_session, sessions - 1) + 1:03d}",
            "hook_event_name": "PreToolUse",
            "tool_name": event.get("tool_name"),
            "tool_input": json.loads(raw) if raw else {},
            "cwd": event.get("cwd"),
        }))
    return payloads


def seed_database(path, **kwargs) -> tuple:
    dataset = load_dataset(DEFAULT_DATA)
    conn = connect(path)
    n_events = n_alerts = 0
    try:
        for ts, payload in build_payloads(dataset, **kwargs):
            event = parse_event(payload)
            event["ts"] = ts.isoformat(timespec="seconds")
            event_id = insert_event(conn, event)
            n_events += 1
            for f in analyze(event):
                insert_alert(conn, event_id, event["ts"], f.rule_id,
                             int(f.severity), f.severity.name, f.message)
                n_alerts += 1
    finally:
        conn.close()
    return n_events, n_alerts


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="agentwatch.seed")
    parser.add_argument("--db", required=True, help="caminho do banco de demonstracao")
    parser.add_argument("--force", action="store_true", help="apagar o banco se ja existir")
    args = parser.parse_args(argv)

    path = Path(args.db)
    if path.exists():
        if not args.force:
            print(f"Erro: {path} ja existe. Use --force para recria-lo.", file=sys.stderr)
            return 2
        path.unlink()
    n_events, n_alerts = seed_database(path)
    print(f"{n_events} eventos e {n_alerts} alertas sinteticos gravados em {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

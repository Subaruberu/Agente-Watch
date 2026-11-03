"""Mostra eventos ou alertas gravados.

    python -m agentwatch.show [N]            ultimos N eventos
    python -m agentwatch.show --alerts [N]   ultimos N alertas
"""
import argparse

from .db import connect


def main() -> None:
    parser = argparse.ArgumentParser(prog="agentwatch.show")
    parser.add_argument("limit", nargs="?", type=int, default=20)
    parser.add_argument("--alerts", action="store_true", help="mostrar alertas")
    args = parser.parse_args()

    conn = connect()
    if args.alerts:
        rows = conn.execute(
            "SELECT a.ts, a.severity_name, a.rule_id, "
            "COALESCE(e.command, e.file_path, e.url, '') "
            "FROM alerts a JOIN events e ON e.id = a.event_id "
            "ORDER BY a.id DESC LIMIT ?", (args.limit,)).fetchall()
        for ts, sev, rule, detail in reversed(rows):
            print(f"{ts}  {sev:<8} {rule:<20} {detail[:80]}")
        total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        print(f"\n{total} alertas no total")
        return

    rows = conn.execute(
        "SELECT ts, tool_name, COALESCE(command, file_path, url, '') "
        "FROM events ORDER BY id DESC LIMIT ?", (args.limit,)).fetchall()
    for ts, tool, detail in reversed(rows):
        print(f"{ts}  {tool or '-':<10} {detail[:100]}")
    total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    print(f"\n{total} eventos no total")


if __name__ == "__main__":
    main()

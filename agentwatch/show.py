"""Mostra os ultimos eventos gravados: python -m agentwatch.show [N]"""
import sys

from .db import connect


def main() -> None:
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    conn = connect()
    rows = conn.execute(
        "SELECT ts, tool_name, COALESCE(command, file_path, url, '') "
        "FROM events ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    for ts, tool, detail in reversed(rows):
        print(f"{ts}  {tool or '-':<10} {detail[:100]}")
    total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    print(f"\n{total} eventos no total")


if __name__ == "__main__":
    main()

"""Reanalisa todos os eventos ja gravados com as regras atuais.

Util depois de mudar uma regra: python -m agentwatch.scan
Apaga os alertas antigos e gera novos (os eventos nao sao alterados).
"""
import sqlite3
from collections import Counter

from .db import connect, insert_alert
from .monitors import analyze


def rescan(conn: sqlite3.Connection) -> Counter:
    conn.row_factory = sqlite3.Row
    conn.execute("DELETE FROM alerts")
    conn.commit()
    counts = Counter()
    for row in conn.execute("SELECT * FROM events ORDER BY id").fetchall():
        for f in analyze(dict(row)):
            insert_alert(conn, row["id"], row["ts"], f.rule_id,
                         int(f.severity), f.severity.name, f.message)
            counts[(f.rule_id, f.severity.name)] += 1
    return counts


def main() -> None:
    conn = connect()
    counts = rescan(conn)
    if not counts:
        print("Nenhum alerta.")
        return
    for (rule, sev), n in sorted(counts.items()):
        print(f"{sev:<8} {rule:<22} {n}")


if __name__ == "__main__":
    main()

"""Tiny schema migration runner (stdlib + pymysql).

Applies numbered SQL files from mysql/migrations/ that have not been recorded in
the schema_migrations table, in filename order, each in its own transaction.
Idempotent and safe to run at every startup. init.sql remains the fresh-container
baseline; migrations hold every schema change after it. Degrades quietly (logs,
no raise) when MySQL is unreachable so it never blocks app startup.
"""

import os
from datetime import datetime
from pathlib import Path

from services.mysql_client import _conn, is_available

# mysql/migrations/ at the repo root (this file is website/services/migrations.py).
MIGRATIONS_DIR = Path(os.environ.get(
    "MIGRATIONS_DIR",
    str(Path(__file__).resolve().parent.parent.parent / "mysql" / "migrations"),
))


def _statements(sql: str) -> list[str]:
    return [s.strip() for s in sql.split(";") if s.strip()]


def _ensure_table(cur) -> None:
    cur.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        " filename VARCHAR(255) NOT NULL PRIMARY KEY,"
        " applied_at DATETIME"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
    )


def _applied(cur) -> set[str]:
    cur.execute("SELECT filename FROM schema_migrations")
    return {r["filename"] for r in cur.fetchall()}


def run() -> list[str]:
    """Apply pending migrations. Returns the list applied this run."""
    if not is_available():
        print("[MIGRATE] MySQL not available; skipping")
        return []
    if not MIGRATIONS_DIR.exists():
        return []
    files = sorted(p for p in MIGRATIONS_DIR.glob("*.sql"))
    applied_now: list[str] = []
    try:
        with _conn() as db:
            with db.cursor() as cur:
                _ensure_table(cur)
                done = _applied(cur)
            for path in files:
                if path.name in done:
                    continue
                sql = path.read_text()
                try:
                    with db.cursor() as cur:
                        for stmt in _statements(sql):
                            cur.execute(stmt)
                        cur.execute(
                            "INSERT INTO schema_migrations (filename, applied_at) VALUES (%s, %s)",
                            (path.name, datetime.utcnow()),
                        )
                    db.commit()
                    applied_now.append(path.name)
                    print(f"[MIGRATE] applied {path.name}")
                except Exception as e:
                    db.rollback()
                    print(f"[MIGRATE] failed {path.name}: {e}")
                    break
    except Exception as e:
        print(f"[MIGRATE] error: {e}")
    return applied_now


if __name__ == "__main__":
    result = run()
    print(f"Applied {len(result)} migration(s): {result}" if result else "No pending migrations")

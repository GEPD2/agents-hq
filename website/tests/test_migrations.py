import pytest

from services import migrations, mysql_client


@pytest.mark.skipif(not mysql_client.is_available(), reason="MySQL not available")
def test_migrations_apply_once_and_record():
    # First run applies pending migrations (or none if already applied).
    migrations.run()
    with mysql_client._conn() as db:
        with db.cursor() as cur:
            cur.execute("SELECT filename FROM schema_migrations")
            recorded = {r["filename"] for r in cur.fetchall()}
    assert "001_metrics_snapshots.sql" in recorded
    # Second run is idempotent: nothing new applied.
    assert migrations.run() == []


def test_statement_splitter():
    stmts = migrations._statements("CREATE TABLE a (x INT);\n\nCREATE TABLE b (y INT);\n")
    assert len(stmts) == 2
    assert stmts[0].startswith("CREATE TABLE a")

import os
import uuid
from datetime import datetime

try:
    import pymysql
    import pymysql.cursors
    HAS_PYMYSQL = True
except ImportError:
    HAS_PYMYSQL = False

DB_HOST = os.environ.get("MYSQL_HOST", "localhost")
DB_PORT = int(os.environ.get("MYSQL_PORT", "3306"))
DB_NAME = os.environ.get("MYSQL_DATABASE", "agents_hq")
DB_USER = os.environ.get("MYSQL_USER", "agents")
DB_PASS = os.environ.get("MYSQL_PASSWORD", "agents_hq")

_ITEM_TYPES = ("report", "ioc", "threat_actor")


def _conn():
    if not HAS_PYMYSQL:
        raise RuntimeError("pymysql not installed")
    return pymysql.connect(
        host=DB_HOST, port=DB_PORT,
        user=DB_USER, password=DB_PASS,
        database=DB_NAME, charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        connect_timeout=5,
    )


def create_case(name: str, description: str = "", tags: str = "") -> str:
    case_id = str(uuid.uuid4())[:12]
    now = datetime.utcnow()
    with _conn() as db:
        with db.cursor() as cur:
            cur.execute("""
                INSERT INTO cases (id, name, description, tags, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (case_id, name[:255], description, tags[:500], now, now))
        db.commit()
    return case_id


def list_cases() -> list[dict]:
    try:
        with _conn() as db:
            with db.cursor() as cur:
                cur.execute("""
                    SELECT c.id, c.name, c.description, c.tags, c.updated_at,
                           COUNT(i.id) AS item_count
                    FROM cases c
                    LEFT JOIN case_items i ON i.case_id = c.id
                    GROUP BY c.id
                    ORDER BY c.updated_at DESC
                """)
                rows = cur.fetchall()
        for r in rows:
            r["updated_at"] = str(r["updated_at"]) if r.get("updated_at") else ""
        return rows
    except Exception:
        return []


def get_case(case_id: str) -> dict | None:
    try:
        with _conn() as db:
            with db.cursor() as cur:
                cur.execute("SELECT * FROM cases WHERE id=%s", (case_id,))
                case = cur.fetchone()
                if not case:
                    return None
                cur.execute(
                    "SELECT id, item_type, ref, label, added_at FROM case_items WHERE case_id=%s ORDER BY added_at",
                    (case_id,),
                )
                items = cur.fetchall()
        case["created_at"] = str(case.get("created_at") or "")
        case["updated_at"] = str(case.get("updated_at") or "")
        for it in items:
            it["added_at"] = str(it.get("added_at") or "")
        case["items"] = items
        return case
    except Exception:
        return None


def update_case(case_id: str, name: str = None, description: str = None, tags: str = None) -> bool:
    fields, values = [], []
    if name is not None:
        fields.append("name=%s"); values.append(name[:255])
    if description is not None:
        fields.append("description=%s"); values.append(description)
    if tags is not None:
        fields.append("tags=%s"); values.append(tags[:500])
    if not fields:
        return False
    fields.append("updated_at=%s"); values.append(datetime.utcnow())
    values.append(case_id)
    try:
        with _conn() as db:
            with db.cursor() as cur:
                cur.execute(f"UPDATE cases SET {', '.join(fields)} WHERE id=%s", values)
            db.commit()
        return True
    except Exception:
        return False


def delete_case(case_id: str) -> bool:
    try:
        with _conn() as db:
            with db.cursor() as cur:
                cur.execute("DELETE FROM cases WHERE id=%s", (case_id,))
            db.commit()
        return True
    except Exception:
        return False


def add_item(case_id: str, item_type: str, ref: str, label: str = "") -> str | None:
    if item_type not in _ITEM_TYPES:
        return None
    item_id = str(uuid.uuid4())[:12]
    try:
        with _conn() as db:
            with db.cursor() as cur:
                cur.execute("""
                    INSERT INTO case_items (id, case_id, item_type, ref, label, added_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (item_id, case_id, item_type, ref[:500], label[:500], datetime.utcnow()))
                cur.execute("UPDATE cases SET updated_at=%s WHERE id=%s", (datetime.utcnow(), case_id))
            db.commit()
        return item_id
    except Exception:
        return None


def remove_item(case_id: str, item_id: str) -> bool:
    try:
        with _conn() as db:
            with db.cursor() as cur:
                cur.execute("DELETE FROM case_items WHERE id=%s AND case_id=%s", (item_id, case_id))
            db.commit()
        return True
    except Exception:
        return False


def save_brief(case_id: str, brief: str) -> bool:
    try:
        with _conn() as db:
            with db.cursor() as cur:
                cur.execute(
                    "UPDATE cases SET brief=%s, updated_at=%s WHERE id=%s",
                    (brief, datetime.utcnow(), case_id),
                )
            db.commit()
        return True
    except Exception:
        return False

"""SQLite persistence. One short-lived connection per unit of work (thread-safe, WAL mode).

Schema is versioned through PRAGMA user_version so migrations can be appended.
The SQL is deliberately portable (no SQLite-only features beyond AUTOINCREMENT) to keep a
PostgreSQL migration path open.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator

from .config import get_settings

MIGRATIONS: list[str] = [
    # --- v1 ---------------------------------------------------------------
    """
    CREATE TABLE workspaces (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL
    );
    CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL);
    CREATE TABLE cases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ref TEXT NOT NULL UNIQUE,
        workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
        name TEXT NOT NULL,
        objective TEXT NOT NULL DEFAULT '',
        scope TEXT NOT NULL DEFAULT '',
        authorisation_ack INTEGER NOT NULL DEFAULT 0,
        author TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'open',
        priority TEXT NOT NULL DEFAULT 'medium',
        tags TEXT NOT NULL DEFAULT '[]',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        archived_at TEXT
    );
    CREATE TABLE case_notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER NOT NULL REFERENCES cases(id),
        body TEXT NOT NULL,
        author TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE operations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ref TEXT NOT NULL UNIQUE,
        case_id INTEGER REFERENCES cases(id),
        kind TEXT NOT NULL,
        target TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'draft',
        params TEXT NOT NULL DEFAULT '{}',
        result TEXT,
        error TEXT,
        authorised INTEGER NOT NULL DEFAULT 0,
        auth_note TEXT NOT NULL DEFAULT '',
        cancel_requested INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        started_at TEXT,
        finished_at TEXT
    );
    CREATE TABLE findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ref TEXT NOT NULL UNIQUE,
        case_id INTEGER REFERENCES cases(id),
        operation_id INTEGER REFERENCES operations(id),
        kind TEXT NOT NULL,
        title TEXT NOT NULL,
        summary TEXT NOT NULL DEFAULT '',
        data TEXT NOT NULL DEFAULT '{}',
        source TEXT NOT NULL,
        source_url TEXT,
        retrieved_at TEXT NOT NULL,
        confidence TEXT NOT NULL DEFAULT 'medium',
        freshness TEXT NOT NULL DEFAULT 'live',
        review_status TEXT NOT NULL DEFAULT 'pending',
        created_at TEXT NOT NULL
    );
    CREATE TABLE indicators (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ref TEXT NOT NULL UNIQUE,
        type TEXT NOT NULL,
        value TEXT NOT NULL,
        severity TEXT NOT NULL DEFAULT 'unknown',
        confidence TEXT NOT NULL DEFAULT 'none',
        reasoning TEXT NOT NULL DEFAULT '[]',
        geo_lat REAL, geo_lon REAL, geo_label TEXT,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        UNIQUE(type, value)
    );
    CREATE TABLE indicator_cases (
        indicator_id INTEGER NOT NULL REFERENCES indicators(id),
        case_id INTEGER NOT NULL REFERENCES cases(id),
        linked_at TEXT NOT NULL,
        PRIMARY KEY (indicator_id, case_id)
    );
    CREATE TABLE enrichments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        indicator_id INTEGER NOT NULL REFERENCES indicators(id),
        provider TEXT NOT NULL,
        status TEXT NOT NULL,
        http_status INTEGER,
        data TEXT NOT NULL DEFAULT '{}',
        error TEXT,
        source_url TEXT,
        retrieved_at TEXT NOT NULL
    );
    CREATE TABLE evidence (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ref TEXT NOT NULL UNIQUE,
        case_id INTEGER REFERENCES cases(id),
        name TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        source TEXT NOT NULL DEFAULT '',
        sha256 TEXT NOT NULL,
        size INTEGER NOT NULL,
        mime TEXT NOT NULL DEFAULT 'application/octet-stream',
        stored_name TEXT NOT NULL,
        encrypted INTEGER NOT NULL DEFAULT 0,
        created_by TEXT NOT NULL,
        created_at TEXT NOT NULL,
        last_verified_at TEXT,
        last_verify_result TEXT
    );
    CREATE TABLE audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        entity_type TEXT,
        entity_id TEXT,
        case_id INTEGER,
        detail TEXT NOT NULL DEFAULT '{}'
    );
    CREATE TABLE reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ref TEXT NOT NULL UNIQUE,
        case_id INTEGER NOT NULL REFERENCES cases(id),
        title TEXT NOT NULL,
        format TEXT NOT NULL,
        filename TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        size INTEGER NOT NULL,
        ai_sections INTEGER NOT NULL DEFAULT 0,
        created_by TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE INDEX idx_audit_ts ON audit(ts);
    CREATE INDEX idx_audit_case ON audit(case_id);
    CREATE TABLE entities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT NOT NULL,
        key TEXT NOT NULL,
        label TEXT NOT NULL,
        props TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL,
        UNIQUE(type, key)
    );
    CREATE TABLE relations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        src_id INTEGER NOT NULL REFERENCES entities(id),
        dst_id INTEGER NOT NULL REFERENCES entities(id),
        rel_type TEXT NOT NULL,
        source TEXT NOT NULL,
        evidence_ref TEXT,
        created_at TEXT NOT NULL,
        UNIQUE(src_id, dst_id, rel_type)
    );
    """,
]


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _connect() -> sqlite3.Connection:
    settings = get_settings()
    settings.ensure_dirs()
    conn = sqlite3.connect(settings.db_path, timeout=15, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


@contextmanager
def db() -> Iterator[sqlite3.Connection]:
    """Transactional connection: commits on success, rolls back on any exception (re-raised)."""
    conn = _connect()
    try:
        conn.execute("BEGIN")
        yield conn
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def migrate() -> int:
    """Apply any outstanding migrations. Returns the resulting schema version."""
    conn = _connect()
    try:
        current = conn.execute("PRAGMA user_version").fetchone()[0]
        for version, script in enumerate(MIGRATIONS, start=1):
            if version <= current:
                continue
            conn.executescript("BEGIN;" + script + f"PRAGMA user_version = {version}; COMMIT;")
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        if not conn.execute("SELECT 1 FROM workspaces LIMIT 1").fetchone():
            conn.execute("INSERT INTO workspaces(name, created_at) VALUES (?, ?)", ("DEFAULT", utcnow()))
        return version
    finally:
        conn.close()


def next_ref(conn: sqlite3.Connection, prefix: str) -> str:
    """Backend-generated sequential reference, e.g. GHO-CASE-2026-0007."""
    year = datetime.now(timezone.utc).year
    name = f"{prefix}-{year}"
    conn.execute("INSERT INTO counters(name, value) VALUES (?, 0) ON CONFLICT(name) DO NOTHING", (name,))
    conn.execute("UPDATE counters SET value = value + 1 WHERE name = ?", (name,))
    value = conn.execute("SELECT value FROM counters WHERE name = ?", (name,)).fetchone()[0]
    return f"GHO-{prefix}-{year}-{value:04d}"


def row_to_dict(row: sqlite3.Row | None, json_fields: tuple[str, ...] = ()) -> dict[str, Any] | None:
    if row is None:
        return None
    out = dict(row)
    for f in json_fields:
        if f in out and isinstance(out[f], str):
            try:
                out[f] = json.loads(out[f])
            except json.JSONDecodeError:
                pass
    return out


def rows_to_dicts(rows, json_fields: tuple[str, ...] = ()) -> list[dict[str, Any]]:
    return [row_to_dict(r, json_fields) for r in rows]  # type: ignore[misc]


def get_setting(conn: sqlite3.Connection, key: str, default: str | None = None) -> str | None:
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )

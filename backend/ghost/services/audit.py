"""Append-only audit trail. Never stores secrets; callers pass already-sanitised detail."""
from __future__ import annotations

import getpass
import json
import sqlite3
from typing import Any

from ..db import utcnow


def current_actor() -> str:
    try:
        return getpass.getuser()
    except Exception:  # pragma: no cover - platform specific
        return "analyst"


def record(
    conn: sqlite3.Connection,
    action: str,
    *,
    entity_type: str | None = None,
    entity_id: str | int | None = None,
    case_id: int | None = None,
    detail: dict[str, Any] | None = None,
    actor: str | None = None,
) -> None:
    conn.execute(
        "INSERT INTO audit(ts, actor, action, entity_type, entity_id, case_id, detail) VALUES (?,?,?,?,?,?,?)",
        (
            utcnow(),
            actor or current_actor(),
            action,
            entity_type,
            None if entity_id is None else str(entity_id),
            case_id,
            json.dumps(detail or {}, default=str),
        ),
    )

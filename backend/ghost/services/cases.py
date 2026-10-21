"""Workspaces, cases, notes and the per-case timeline."""
from __future__ import annotations

import json
import sqlite3
from typing import Any

from ..db import db, get_setting, next_ref, row_to_dict, rows_to_dicts, set_setting, utcnow
from ..errors import GhostError, NotFound
from . import audit

STATUSES = ("open", "active", "closed", "archived")
PRIORITIES = ("low", "medium", "high", "critical")


# --- workspaces ---------------------------------------------------------------

def list_workspaces() -> list[dict[str, Any]]:
    with db() as c:
        return rows_to_dicts(c.execute("SELECT * FROM workspaces ORDER BY id"))


def create_workspace(name: str) -> dict[str, Any]:
    name = name.strip().upper()
    if not (2 <= len(name) <= 40):
        raise GhostError("Workspace name must be 2-40 characters")
    with db() as c:
        try:
            cur = c.execute("INSERT INTO workspaces(name, created_at) VALUES (?, ?)", (name, utcnow()))
        except sqlite3.IntegrityError:
            raise GhostError(f"Workspace '{name}' already exists", 409, "duplicate")
        audit.record(c, "workspace.create", entity_type="workspace", entity_id=cur.lastrowid, detail={"name": name})
        return row_to_dict(c.execute("SELECT * FROM workspaces WHERE id=?", (cur.lastrowid,)).fetchone())  # type: ignore[return-value]


def default_workspace_id(conn: sqlite3.Connection) -> int:
    configured = get_setting(conn, "active_workspace")
    if configured:
        row = conn.execute("SELECT id FROM workspaces WHERE id = ?", (int(configured),)).fetchone()
        if row:
            return row["id"]
    return conn.execute("SELECT id FROM workspaces ORDER BY id LIMIT 1").fetchone()["id"]


def set_active_workspace(workspace_id: int) -> None:
    with db() as c:
        if not c.execute("SELECT 1 FROM workspaces WHERE id=?", (workspace_id,)).fetchone():
            raise NotFound("Workspace")
        set_setting(c, "active_workspace", str(workspace_id))
        audit.record(c, "workspace.activate", entity_type="workspace", entity_id=workspace_id)


# --- cases --------------------------------------------------------------------

def _clean_tags(tags: list[str] | None) -> list[str]:
    seen: list[str] = []
    for t in tags or []:
        t = str(t).strip().lower()[:32]
        if t and t not in seen:
            seen.append(t)
    return seen[:20]


def _validate(name: str | None = None, status: str | None = None, priority: str | None = None) -> None:
    if name is not None and not (3 <= len(name.strip()) <= 120):
        raise GhostError("Case name must be 3-120 characters", 422, "validation")
    if status is not None and status not in STATUSES:
        raise GhostError(f"status must be one of {', '.join(STATUSES)}", 422, "validation")
    if priority is not None and priority not in PRIORITIES:
        raise GhostError(f"priority must be one of {', '.join(PRIORITIES)}", 422, "validation")


def create_case(
    name: str,
    objective: str = "",
    scope: str = "",
    authorisation_ack: bool = False,
    priority: str = "medium",
    tags: list[str] | None = None,
    author: str | None = None,
    workspace_id: int | None = None,
) -> dict[str, Any]:
    _validate(name=name, priority=priority)
    now = utcnow()
    with db() as c:
        ws = workspace_id or default_workspace_id(c)
        if not c.execute("SELECT 1 FROM workspaces WHERE id=?", (ws,)).fetchone():
            raise NotFound("Workspace")
        ref = next_ref(c, "CASE")
        cur = c.execute(
            """INSERT INTO cases(ref, workspace_id, name, objective, scope, authorisation_ack, author,
                                 status, priority, tags, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (ref, ws, name.strip(), objective.strip(), scope.strip(), int(bool(authorisation_ack)),
             author or audit.current_actor(), "open", priority, json.dumps(_clean_tags(tags)), now, now),
        )
        audit.record(c, "case.create", entity_type="case", entity_id=ref, case_id=cur.lastrowid,
                     detail={"name": name, "priority": priority, "authorisation_ack": bool(authorisation_ack)})
        return get_case(cur.lastrowid, conn=c)


def get_case(case_id: int, conn: sqlite3.Connection | None = None) -> dict[str, Any]:
    def _get(c: sqlite3.Connection) -> dict[str, Any]:
        row = c.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
        if not row:
            raise NotFound("Case")
        case = row_to_dict(row, ("tags",))
        case["authorisation_ack"] = bool(case["authorisation_ack"])  # type: ignore[index]
        counts = c.execute(
            """SELECT
                 (SELECT COUNT(*) FROM operations WHERE case_id = :id) AS operations,
                 (SELECT COUNT(*) FROM findings WHERE case_id = :id) AS findings,
                 (SELECT COUNT(*) FROM evidence WHERE case_id = :id) AS evidence,
                 (SELECT COUNT(*) FROM indicator_cases WHERE case_id = :id) AS indicators,
                 (SELECT COUNT(*) FROM case_notes WHERE case_id = :id) AS notes""",
            {"id": case_id},
        ).fetchone()
        case["counts"] = dict(counts)  # type: ignore[index]
        return case  # type: ignore[return-value]

    if conn is not None:
        return _get(conn)
    with db() as c:
        return _get(c)


def list_cases(
    q: str | None = None,
    status: str | None = None,
    priority: str | None = None,
    workspace_id: int | None = None,
    include_archived: bool = False,
    limit: int = 200,
) -> list[dict[str, Any]]:
    sql = "SELECT * FROM cases WHERE 1=1"
    args: list[Any] = []
    if workspace_id:
        sql += " AND workspace_id = ?"
        args.append(workspace_id)
    if status:
        sql += " AND status = ?"
        args.append(status)
    elif not include_archived:
        sql += " AND status != 'archived'"
    if priority:
        sql += " AND priority = ?"
        args.append(priority)
    if q:
        like = f"%{q.strip()}%"
        sql += " AND (name LIKE ? OR ref LIKE ? OR objective LIKE ? OR tags LIKE ?)"
        args += [like, like, like, like]
    sql += " ORDER BY updated_at DESC LIMIT ?"
    args.append(min(max(limit, 1), 500))
    with db() as c:
        out = rows_to_dicts(c.execute(sql, args).fetchall(), ("tags",))
        for case in out:
            case["authorisation_ack"] = bool(case["authorisation_ack"])
        return out


def update_case(case_id: int, **fields: Any) -> dict[str, Any]:
    allowed = {"name", "objective", "scope", "authorisation_ack", "status", "priority", "tags"}
    changes = {k: v for k, v in fields.items() if k in allowed and v is not None}
    _validate(name=changes.get("name"), status=changes.get("status"), priority=changes.get("priority"))
    with db() as c:
        existing = c.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if not existing:
            raise NotFound("Case")
        sets, args = [], []
        for k, v in changes.items():
            if k == "tags":
                v = json.dumps(_clean_tags(v))
            elif k == "authorisation_ack":
                v = int(bool(v))
            elif isinstance(v, str):
                v = v.strip()
            sets.append(f"{k} = ?")
            args.append(v)
        if "status" in changes:
            sets.append("archived_at = ?")
            args.append(utcnow() if changes["status"] == "archived" else None)
        if sets:
            sets.append("updated_at = ?")
            args.append(utcnow())
            c.execute(f"UPDATE cases SET {', '.join(sets)} WHERE id = ?", (*args, case_id))
            audit.record(c, "case.update", entity_type="case", entity_id=existing["ref"], case_id=case_id,
                         detail={k: ("<updated>" if k in ("objective", "scope") else v) for k, v in changes.items()})
        return get_case(case_id, conn=c)


def archive_case(case_id: int) -> dict[str, Any]:
    return update_case(case_id, status="archived")


def add_note(case_id: int, body: str, author: str | None = None) -> dict[str, Any]:
    body = body.strip()
    if not body:
        raise GhostError("Note body cannot be empty", 422, "validation")
    if len(body) > 20000:
        raise GhostError("Note too long (max 20000 characters)", 422, "validation")
    with db() as c:
        case = c.execute("SELECT ref FROM cases WHERE id=?", (case_id,)).fetchone()
        if not case:
            raise NotFound("Case")
        cur = c.execute(
            "INSERT INTO case_notes(case_id, body, author, created_at) VALUES (?,?,?,?)",
            (case_id, body, author or audit.current_actor(), utcnow()),
        )
        c.execute("UPDATE cases SET updated_at=? WHERE id=?", (utcnow(), case_id))
        audit.record(c, "case.note", entity_type="case", entity_id=case["ref"], case_id=case_id, detail={"note_id": cur.lastrowid})
        return row_to_dict(c.execute("SELECT * FROM case_notes WHERE id=?", (cur.lastrowid,)).fetchone())  # type: ignore[return-value]


def list_notes(case_id: int) -> list[dict[str, Any]]:
    with db() as c:
        return rows_to_dicts(c.execute("SELECT * FROM case_notes WHERE case_id=? ORDER BY created_at DESC", (case_id,)))


def case_timeline(case_id: int, limit: int = 300) -> list[dict[str, Any]]:
    """Chronological investigation timeline, built from the audit trail (newest first)."""
    with db() as c:
        if not c.execute("SELECT 1 FROM cases WHERE id=?", (case_id,)).fetchone():
            raise NotFound("Case")
        return rows_to_dicts(
            c.execute("SELECT * FROM audit WHERE case_id=? ORDER BY ts DESC, id DESC LIMIT ?", (case_id, limit)),
            ("detail",),
        )


def require_authorised(case_id: int | None) -> None:
    """Active network checks require a case whose scope + authorisation declaration is on record."""
    if case_id is None:
        raise GhostError(
            "Active checks (TLS handshake, HTTP request) need a case with a scope and an authorisation declaration.",
            403, "authorisation_required")
    with db() as c:
        row = c.execute("SELECT scope, authorisation_ack, status FROM cases WHERE id=?", (case_id,)).fetchone()
    if not row:
        raise NotFound("Case")
    if row["status"] == "archived":
        raise GhostError("Case is archived", 409, "archived")
    if not row["authorisation_ack"] or not row["scope"].strip():
        raise GhostError(
            "This case has no scope / authorisation declaration. Edit the case, declare scope and acknowledge authorisation first.",
            403, "authorisation_required")

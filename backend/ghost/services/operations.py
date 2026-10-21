"""Operations: tracked units of work (draft → queued → running → completed | failed | cancelled)
executed by a small in-process worker pool. Worker/queue figures reported to the UI come from here.
"""
from __future__ import annotations

import json
import logging
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from ..db import db, next_ref, row_to_dict, rows_to_dicts, utcnow
from ..errors import GhostError, NotFound
from . import audit

log = logging.getLogger("ghost.operations")

KINDS = ("domain_investigation", "ioc_enrichment", "pcap_analysis")
STATUSES = ("draft", "queued", "running", "completed", "failed", "cancelled")

_pool: ThreadPoolExecutor | None = None
_pool_lock = threading.Lock()
_handlers: dict[str, Callable[["OperationContext"], dict[str, Any]]] = {}
MAX_WORKERS = 2


class Cancelled(Exception):
    pass


class OperationContext:
    def __init__(self, op: dict[str, Any]):
        self.op = op
        self.id: int = op["id"]
        self.ref: str = op["ref"]
        self.case_id: int | None = op["case_id"]
        self.target: str = op["target"]
        self.params: dict[str, Any] = op["params"]
        self.authorised: bool = bool(op["authorised"])

    def check_cancel(self) -> None:
        with db() as c:
            row = c.execute("SELECT cancel_requested FROM operations WHERE id=?", (self.id,)).fetchone()
        if row and row["cancel_requested"]:
            raise Cancelled()


def register(kind: str):
    def deco(fn):
        _handlers[kind] = fn
        return fn
    return deco


def _get_pool() -> ThreadPoolExecutor:
    global _pool
    with _pool_lock:
        if _pool is None:
            _pool = ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix="ghost-worker")
        return _pool


def shutdown_pool() -> None:
    global _pool
    with _pool_lock:
        if _pool is not None:
            _pool.shutdown(wait=False, cancel_futures=True)
            _pool = None


def recover_interrupted() -> int:
    """Operations left queued/running by a previous process cannot still be running — mark them failed."""
    with db() as c:
        rows = c.execute("SELECT id, ref, case_id FROM operations WHERE status IN ('queued','running')").fetchall()
        for r in rows:
            c.execute("UPDATE operations SET status='failed', error=?, finished_at=? WHERE id=?",
                      ("Interrupted: the application stopped before this operation finished.", utcnow(), r["id"]))
            audit.record(c, "operation.interrupted", entity_type="operation", entity_id=r["ref"], case_id=r["case_id"])
        return len(rows)


def worker_status() -> dict[str, Any]:
    with db() as c:
        counts = {r["status"]: r["n"] for r in c.execute("SELECT status, COUNT(*) AS n FROM operations GROUP BY status")}
    return {"ok": True, "kind": "in-process thread pool", "workers": MAX_WORKERS,
            "queued": counts.get("queued", 0), "running": counts.get("running", 0),
            "completed": counts.get("completed", 0), "failed": counts.get("failed", 0)}


def create(kind: str, target: str, *, case_id: int | None = None, params: dict[str, Any] | None = None,
           authorised: bool = False, auth_note: str = "", run: bool = True) -> dict[str, Any]:
    if kind not in KINDS:
        raise GhostError(f"Unknown operation kind '{kind}'", 422, "validation")
    target = target.strip()
    if not target:
        raise GhostError("Operation target is required", 422, "validation")
    with db() as c:
        if case_id is not None:
            case = c.execute("SELECT status FROM cases WHERE id=?", (case_id,)).fetchone()
            if not case:
                raise NotFound("Case")
            if case["status"] == "archived":
                raise GhostError("Case is archived", 409, "archived")
        ref = next_ref(c, "OP")
        cur = c.execute(
            """INSERT INTO operations(ref, case_id, kind, target, status, params, authorised, auth_note, created_at)
               VALUES (?,?,?,?, 'draft', ?,?,?,?)""",
            (ref, case_id, kind, target, json.dumps(params or {}, default=str), int(authorised), auth_note.strip()[:500], utcnow()),
        )
        audit.record(c, "operation.create", entity_type="operation", entity_id=ref, case_id=case_id,
                     detail={"kind": kind, "target": target, "authorised": authorised})
        op_id = cur.lastrowid
    return run_operation(op_id) if run else get(op_id)


def get(op_id: int) -> dict[str, Any]:
    with db() as c:
        row = row_to_dict(c.execute("SELECT * FROM operations WHERE id=?", (op_id,)).fetchone(), ("params", "result"))
    if not row:
        raise NotFound("Operation")
    row["authorised"] = bool(row["authorised"])
    return row


def list_operations(case_id: int | None = None, status: str | None = None, kind: str | None = None,
                    limit: int = 100) -> list[dict[str, Any]]:
    sql, args = "SELECT * FROM operations WHERE 1=1", []
    for col, val in (("case_id", case_id), ("status", status), ("kind", kind)):
        if val is not None:
            sql += f" AND {col} = ?"
            args.append(val)
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(min(limit, 500))
    with db() as c:
        rows = rows_to_dicts(c.execute(sql, args), ("params", "result"))
    for r in rows:
        r["authorised"] = bool(r["authorised"])
    return rows


def run_operation(op_id: int) -> dict[str, Any]:
    op = get(op_id)
    if op["status"] != "draft":
        raise GhostError(f"Only draft operations can be started (status is '{op['status']}')", 409, "invalid_state")
    if op["kind"] not in _handlers:
        raise GhostError(f"No handler registered for '{op['kind']}'", 500)
    with db() as c:
        c.execute("UPDATE operations SET status='queued' WHERE id=?", (op_id,))
        audit.record(c, "operation.queue", entity_type="operation", entity_id=op["ref"], case_id=op["case_id"])
    _get_pool().submit(_execute, op_id)
    return get(op_id)


TERMINAL = ("completed", "failed", "cancelled")


def wait_for(op_id: int, timeout: float = 300.0, poll: float = 0.25) -> dict[str, Any]:
    """Block until the operation reaches a terminal state (used by the CLI and tests)."""
    import time
    deadline = time.monotonic() + timeout
    while True:
        op = get(op_id)
        if op["status"] in TERMINAL:
            return op
        if time.monotonic() > deadline:
            raise GhostError(f"Timed out waiting for {op['ref']} (still {op['status']})", 504, "timeout")
        time.sleep(poll)


def cancel(op_id: int) -> dict[str, Any]:
    op = get(op_id)
    with db() as c:
        if op["status"] in ("draft", "queued"):
            c.execute("UPDATE operations SET status='cancelled', finished_at=? WHERE id=?", (utcnow(), op_id))
        elif op["status"] == "running":
            c.execute("UPDATE operations SET cancel_requested=1 WHERE id=?", (op_id,))
        else:
            raise GhostError(f"Operation already {op['status']}", 409, "invalid_state")
        audit.record(c, "operation.cancel", entity_type="operation", entity_id=op["ref"], case_id=op["case_id"])
    return get(op_id)


def _execute(op_id: int) -> None:
    with db() as c:
        claimed = c.execute("UPDATE operations SET status='running', started_at=? WHERE id=? AND status='queued'",
                            (utcnow(), op_id)).rowcount
        if not claimed:  # cancelled while queued
            return
        row = c.execute("SELECT ref, case_id FROM operations WHERE id=?", (op_id,)).fetchone()
        audit.record(c, "operation.start", entity_type="operation", entity_id=row["ref"], case_id=row["case_id"])
    op = get(op_id)
    ctx = OperationContext(op)
    try:
        result = _handlers[op["kind"]](ctx)
        status, error = "completed", None
    except Cancelled:
        result, status, error = None, "cancelled", None
    except GhostError as exc:
        result, status, error = None, "failed", exc.message
    except Exception as exc:  # logged with traceback, surfaced to the user as a failed operation
        log.error("Operation %s crashed:\n%s", op["ref"], traceback.format_exc())
        result, status, error = None, "failed", f"Internal error: {type(exc).__name__}: {exc}"
    with db() as c:
        c.execute("UPDATE operations SET status=?, result=?, error=?, finished_at=? WHERE id=?",
                  (status, json.dumps(result, default=str) if result is not None else None, error, utcnow(), op_id))
        audit.record(c, f"operation.{status}", entity_type="operation", entity_id=op["ref"], case_id=op["case_id"],
                     detail={"error": error} if error else {})

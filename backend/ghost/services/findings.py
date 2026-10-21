"""Findings (provenance-carrying results) and the entity/relation store behind the graph."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from ..db import db, next_ref, row_to_dict, rows_to_dicts, utcnow
from ..errors import GhostError, NotFound
from . import audit

STALE_AFTER = timedelta(hours=24)
REVIEW_STATES = ("pending", "confirmed", "dismissed")
CONFIDENCE = ("low", "medium", "high")


def add_finding(
    conn: sqlite3.Connection,
    *,
    kind: str,
    title: str,
    source: str,
    summary: str = "",
    data: dict[str, Any] | None = None,
    source_url: str | None = None,
    retrieved_at: str | None = None,
    confidence: str = "medium",
    freshness: str = "live",
    case_id: int | None = None,
    operation_id: int | None = None,
) -> dict[str, Any]:
    if confidence not in CONFIDENCE:
        raise ValueError(confidence)
    ref = next_ref(conn, "FND")
    now = utcnow()
    cur = conn.execute(
        """INSERT INTO findings(ref, case_id, operation_id, kind, title, summary, data, source, source_url,
                                retrieved_at, confidence, freshness, review_status, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,'pending',?)""",
        (ref, case_id, operation_id, kind, title, summary, json.dumps(data or {}, default=str), source,
         source_url, retrieved_at or now, confidence, freshness, now),
    )
    audit.record(conn, "finding.create", entity_type="finding", entity_id=ref, case_id=case_id,
                 detail={"kind": kind, "source": source, "operation_id": operation_id})
    return {"id": cur.lastrowid, "ref": ref}


def _decorate(f: dict[str, Any]) -> dict[str, Any]:
    try:
        age = datetime.now(timezone.utc) - datetime.strptime(f["retrieved_at"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
        if f["freshness"] == "live" and age > STALE_AFTER:
            f["freshness"] = "stale"
    except (ValueError, KeyError):
        pass
    return f


def list_findings(case_id: int | None = None, operation_id: int | None = None, review_status: str | None = None,
                  kind: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
    sql, args = "SELECT * FROM findings WHERE 1=1", []
    for col, val in (("case_id", case_id), ("operation_id", operation_id), ("review_status", review_status), ("kind", kind)):
        if val is not None:
            sql += f" AND {col} = ?"
            args.append(val)
    sql += " ORDER BY created_at DESC, id DESC LIMIT ?"
    args.append(min(limit, 1000))
    with db() as c:
        return [_decorate(f) for f in rows_to_dicts(c.execute(sql, args), ("data",))]


def set_review(finding_id: int, review_status: str) -> dict[str, Any]:
    if review_status not in REVIEW_STATES:
        raise GhostError(f"review_status must be one of {', '.join(REVIEW_STATES)}", 422, "validation")
    with db() as c:
        row = c.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
        if not row:
            raise NotFound("Finding")
        c.execute("UPDATE findings SET review_status=? WHERE id=?", (review_status, finding_id))
        audit.record(c, "finding.review", entity_type="finding", entity_id=row["ref"], case_id=row["case_id"],
                     detail={"from": row["review_status"], "to": review_status})
        return _decorate(row_to_dict(c.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone(), ("data",)))  # type: ignore[arg-type]


# --- entities / relations -------------------------------------------------------

ENTITY_TYPES = ("domain", "ip", "url", "hash", "certificate", "case", "evidence", "indicator")


def upsert_entity(conn: sqlite3.Connection, type_: str, key: str, label: str | None = None,
                  props: dict[str, Any] | None = None) -> int:
    row = conn.execute("SELECT id, props FROM entities WHERE type=? AND key=?", (type_, key)).fetchone()
    if row:
        if props:
            merged = {**json.loads(row["props"]), **props}
            conn.execute("UPDATE entities SET props=? WHERE id=?", (json.dumps(merged, default=str), row["id"]))
        return row["id"]
    cur = conn.execute(
        "INSERT INTO entities(type, key, label, props, created_at) VALUES (?,?,?,?,?)",
        (type_, key, label or key, json.dumps(props or {}, default=str), utcnow()),
    )
    return cur.lastrowid  # type: ignore[return-value]


def link(conn: sqlite3.Connection, src: int, dst: int, rel_type: str, source: str, evidence_ref: str | None = None) -> None:
    """Record a relationship. Every edge carries its relationship type and the source that supports it."""
    if src == dst:
        return
    conn.execute(
        """INSERT INTO relations(src_id, dst_id, rel_type, source, evidence_ref, created_at)
           VALUES (?,?,?,?,?,?) ON CONFLICT(src_id, dst_id, rel_type) DO NOTHING""",
        (src, dst, rel_type, source, evidence_ref, utcnow()),
    )


def graph(case_id: int | None = None, types: list[str] | None = None, limit: int = 600) -> dict[str, Any]:
    """Return nodes/edges. With case_id, restrict to the case's neighbourhood (2 hops)."""
    with db() as c:
        if case_id is not None:
            case = c.execute("SELECT ref FROM cases WHERE id=?", (case_id,)).fetchone()
            if not case:
                raise NotFound("Case")
            seed = c.execute("SELECT id FROM entities WHERE type='case' AND key=?", (case["ref"],)).fetchone()
            ids: set[int] = {seed["id"]} if seed else set()
            frontier = set(ids)
            for _ in range(2):
                if not frontier:
                    break
                marks = ",".join("?" * len(frontier))
                rows = c.execute(
                    f"SELECT src_id, dst_id FROM relations WHERE src_id IN ({marks}) OR dst_id IN ({marks})",
                    (*frontier, *frontier),
                ).fetchall()
                new = {r[0] for r in rows} | {r[1] for r in rows}
                frontier = new - ids
                ids |= new
            if not ids:
                return {"nodes": [], "edges": []}
            marks = ",".join("?" * len(ids))
            nodes = rows_to_dicts(c.execute(f"SELECT * FROM entities WHERE id IN ({marks}) LIMIT ?", (*ids, limit)), ("props",))
        else:
            nodes = rows_to_dicts(c.execute("SELECT * FROM entities ORDER BY id DESC LIMIT ?", (limit,)), ("props",))
        if types:
            nodes = [n for n in nodes if n["type"] in types]
        node_ids = {n["id"] for n in nodes}
        edges = [e for e in rows_to_dicts(c.execute("SELECT * FROM relations ORDER BY id DESC LIMIT ?", (limit * 4,)))
                 if e["src_id"] in node_ids and e["dst_id"] in node_ids]
        return {"nodes": nodes, "edges": edges}

"""Aggregations for the Command Centre. Every number is a query over stored records."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from ..db import db, rows_to_dicts

TIMELINE_DAYS = 14
CATEGORIES = {
    "finding.create": "findings",
    "operation.completed": "operations", "operation.failed": "operations",
    "indicator.add": "indicators",
    "evidence.register": "evidence",
    "case.create": "cases",
}


def _case_filter(ws: int | None, col: str = "case_id") -> tuple[str, list[Any]]:
    """Records with no case always show; case-bound records follow the active workspace."""
    if not ws:
        return "1=1", []
    return f"({col} IS NULL OR {col} IN (SELECT id FROM cases WHERE workspace_id = ?))", [ws]


def overview(workspace_id: int | None = None) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    since = (now - timedelta(days=TIMELINE_DAYS - 1)).strftime("%Y-%m-%dT00:00:00")
    week = (now - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S")
    with db() as c:
        cf, ca = _case_filter(workspace_id)
        ws_clause, ws_args = ("AND workspace_id = ?", [workspace_id]) if workspace_id else ("", [])
        metrics = {
            "open_cases": c.execute(f"SELECT COUNT(*) FROM cases WHERE status IN ('open','active') {ws_clause}", ws_args).fetchone()[0],
            "findings_pending_review": c.execute(f"SELECT COUNT(*) FROM findings WHERE review_status='pending' AND {cf}", ca).fetchone()[0],
            "high_priority_indicators": c.execute(
                "SELECT COUNT(*) FROM indicators WHERE severity IN ('high','critical')").fetchone()[0],
            "recent_completed_analyses": c.execute(
                f"SELECT COUNT(*) FROM operations WHERE status='completed' AND finished_at >= ? AND {cf}", [week, *ca]).fetchone()[0],
        }
        totals = {
            "cases": c.execute(f"SELECT COUNT(*) FROM cases WHERE 1=1 {ws_clause}", ws_args).fetchone()[0],
            "indicators": c.execute("SELECT COUNT(*) FROM indicators").fetchone()[0],
            "evidence": c.execute(f"SELECT COUNT(*) FROM evidence WHERE {cf}", ca).fetchone()[0],
            "entities": c.execute("SELECT COUNT(*) FROM entities").fetchone()[0],
            "operations": c.execute(f"SELECT COUNT(*) FROM operations WHERE {cf}", ca).fetchone()[0],
        }
        days = [(now - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(TIMELINE_DAYS - 1, -1, -1)]
        series = {d: {"date": d, "findings": 0, "operations": 0, "indicators": 0, "evidence": 0, "cases": 0} for d in days}
        for row in c.execute(
            f"SELECT substr(ts,1,10) AS d, action, COUNT(*) AS n FROM audit WHERE ts >= ? AND {_case_filter(workspace_id)[0].replace('case_id', 'audit.case_id')} GROUP BY d, action",
            [since, *ca],
        ):
            cat = CATEGORIES.get(row["action"])
            if cat and row["d"] in series:
                series[row["d"]][cat] += row["n"]
        recent = rows_to_dicts(c.execute(
            f"""SELECT cs.id, cs.ref, cs.name, cs.status, cs.priority, cs.updated_at,
                       (SELECT o.status FROM operations o WHERE o.case_id = cs.id ORDER BY o.id DESC LIMIT 1) AS last_operation_status,
                       (SELECT o.kind FROM operations o WHERE o.case_id = cs.id ORDER BY o.id DESC LIMIT 1) AS last_operation_kind,
                       (SELECT COUNT(*) FROM findings f WHERE f.case_id = cs.id) AS findings
                FROM cases cs WHERE cs.status != 'archived' {ws_clause} ORDER BY cs.updated_at DESC LIMIT 6""", ws_args))
        events = rows_to_dicts(c.execute(
            f"SELECT * FROM audit WHERE {_case_filter(workspace_id)[0].replace('case_id', 'audit.case_id')} ORDER BY id DESC LIMIT 40", ca), ("detail",))
        geo = rows_to_dicts(c.execute(
            "SELECT id, ref, type, value, severity, confidence, geo_lat AS lat, geo_lon AS lon, geo_label AS label FROM indicators WHERE geo_lat IS NOT NULL LIMIT 500"))
        recent_ops = rows_to_dicts(c.execute(
            f"SELECT id, ref, kind, target, status, created_at, finished_at, error FROM operations WHERE {cf} ORDER BY id DESC LIMIT 6", ca))
    return {"metrics": metrics, "totals": totals, "timeline": list(series.values()), "recent_cases": recent,
            "events": events, "geo": geo, "recent_operations": recent_ops}

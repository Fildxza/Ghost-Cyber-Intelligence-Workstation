"""Case report generation (self-contained HTML; print to PDF from any browser).

Only data already stored for the case is included. Recommendations are derived by transparent
rules from stored findings and are labelled as such. Model-generated text is included only when
the analyst explicitly passes it in, and is always labelled.
"""
from __future__ import annotations

import hashlib
import html
from pathlib import Path
from typing import Any

from .. import __version__
from ..config import get_settings
from ..db import db, next_ref, rows_to_dicts, utcnow
from ..errors import NotFound
from . import audit, cases, evidence, findings, intel

E = html.escape

CSS = """
:root{--ink:#16201a;--mute:#5b6a5f;--line:#cfd8d0;--lime:#4a7a12;--amber:#9a6a10;--red:#b32d2d}
*{box-sizing:border-box}body{font:14px/1.55 Inter,Segoe UI,Arial,sans-serif;color:var(--ink);max-width:960px;margin:32px auto;padding:0 24px}
h1{font-size:24px;margin:0}h2{font-size:13px;letter-spacing:.14em;text-transform:uppercase;border-bottom:2px solid var(--ink);padding-bottom:4px;margin-top:34px}
.mono,code{font-family:'IBM Plex Mono',Consolas,monospace;font-size:12px}.mute{color:var(--mute)}
header{border-bottom:3px solid var(--ink);padding-bottom:14px;margin-bottom:8px}.brand{font:600 11px 'IBM Plex Mono',Consolas,monospace;letter-spacing:.2em;color:var(--lime)}
table{width:100%;border-collapse:collapse;margin:8px 0}th,td{border:1px solid var(--line);padding:5px 8px;text-align:left;vertical-align:top;font-size:12.5px}th{background:#eef2ee;font-size:11px;letter-spacing:.08em;text-transform:uppercase}
.tag{display:inline-block;border:1px solid var(--line);padding:0 6px;font:11px 'IBM Plex Mono',Consolas,monospace;margin-right:4px}
.notice{border-left:4px solid var(--amber);background:#fbf6ea;padding:8px 12px;margin:10px 0;font-size:12.5px}
.ai{border-left:4px solid var(--mute);background:#f1f3f1;padding:8px 12px;margin:10px 0}
@media print{body{margin:0}h2{break-after:avoid}tr{break-inside:avoid}}
"""


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    if not rows:
        return '<p class="mute">None recorded.</p>'
    head = "".join(f"<th>{E(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c if isinstance(c, _Raw) else E(str(c if c is not None else '—'))}</td>" for c in r) + "</tr>" for r in rows)
    return f"<table><tr>{head}</tr>{body}</table>"


class _Raw(str):
    """Marker for pre-escaped HTML fragments."""


def derive_recommendations(case_findings: list[dict[str, Any]], inds: list[dict[str, Any]], evid: list[dict[str, Any]]) -> list[str]:
    recs: list[str] = []
    for f in case_findings:
        d = f["data"]
        if f["kind"] == "http" and d.get("missing_security_headers"):
            recs.append(f"Review HTTP response hardening for {d.get('final_url', 'the target')}: missing headers — {', '.join(d['missing_security_headers'])}. ({f['ref']})")
        if f["kind"] == "tls":
            if d.get("chain_trusted") is False:
                recs.append(f"The TLS certificate chain was not trusted ({d.get('trust_failure')}). Investigate before relying on this endpoint. ({f['ref']})")
            if isinstance(d.get("days_remaining"), int) and d["days_remaining"] < 30:
                recs.append(f"The TLS certificate expires in {d['days_remaining']} day(s) — plan renewal. ({f['ref']})")
        if f["kind"] == "rdap" and d.get("expires"):
            recs.append(f"Registration expiry recorded as {d['expires']} — confirm domain ownership/renewal if this asset is yours. ({f['ref']})")
    for i in inds:
        if i["severity"] in ("high", "critical"):
            recs.append(f"Indicator {i['value']} was rated {i['severity'].upper()} ({i['confidence']} confidence). Consider blocking/monitoring and hunting for related activity in your own telemetry.")
        elif i["severity"] == "medium":
            recs.append(f"Indicator {i['value']} was rated MEDIUM — corroborate with a second source before acting.")
    for e in evid:
        if e.get("last_verify_result") != "match":
            recs.append(f"Evidence {e['ref']} ({e['name']}) has not been verified, or last verification failed — run an integrity check before relying on it.")
    if not recs:
        recs.append("No rule-derived recommendations from the data collected. This is not an assurance of safety — the checks performed are listed under Methodology.")
    return recs


def build_html(case_id: int, ai_sections: list[dict[str, str]] | None = None) -> str:
    case = cases.get_case(case_id)
    notes = cases.list_notes(case_id)
    fnds = findings.list_findings(case_id=case_id, limit=1000)
    inds = intel.list_indicators(case_id=case_id)
    evid = evidence.list_evidence(case_id=case_id)
    with db() as c:
        ops = rows_to_dicts(c.execute("SELECT * FROM operations WHERE case_id=? ORDER BY id", (case_id,)), ("params",))
        audit_rows = rows_to_dicts(c.execute("SELECT * FROM audit WHERE case_id=? ORDER BY ts, id LIMIT 500", (case_id,)))
    shown = [f for f in fnds if f["review_status"] != "dismissed"]
    dismissed = len(fnds) - len(shown)
    now = utcnow()
    kinds = sorted({o["kind"] for o in ops})
    sources = sorted({f["source"] for f in fnds})

    parts = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><title>{E(case['ref'])} — Investigation Report</title><style>{CSS}</style></head><body>"]
    parts.append(f"<header><div class='brand'>FIDX-GHOST // CYBER INTELLIGENCE WORKSTATION</div><h1>{E(case['name'])}</h1>"
                 f"<div class='mono mute'>{E(case['ref'])} · priority {E(case['priority']).upper()} · status {E(case['status']).upper()} · generated {E(now)} · v{__version__}</div></header>")
    parts.append("<div class='notice'>This report is produced by an independent OSINT / analysis workstation. It is not affiliated with any government or military body. "
                 "Integrity hashes shown are not digital signatures and do not by themselves establish chain of custody or legal admissibility.</div>")

    parts.append("<h2>1. Scope &amp; Authorisation</h2>")
    parts.append(f"<p><b>Objective:</b> {E(case['objective'] or 'Not stated')}</p><p><b>Declared scope:</b> {E(case['scope'] or 'Not declared')}</p>"
                 f"<p><b>Authorisation acknowledged:</b> {'Yes' if case['authorisation_ack'] else 'No'} · <b>Author:</b> {E(case['author'])} · <b>Opened:</b> <span class='mono'>{E(case['created_at'])}</span></p>")
    if case["tags"]:
        parts.append("<p>" + "".join(f"<span class='tag'>{E(t)}</span>" for t in case["tags"]) + "</p>")

    parts.append("<h2>2. Methodology</h2>")
    if ops:
        parts.append(_table(["Operation", "Kind", "Target", "Status", "Active checks", "Started", "Finished"],
                            [[o["ref"], o["kind"], o["target"], o["status"], "yes — " + o["auth_note"] if o["authorised"] else "no (passive only)", o["started_at"], o["finished_at"]] for o in ops]))
        parts.append(f"<p class='mute'>Data sources consulted: {E(', '.join(sources) or 'none')}.</p>")
    else:
        parts.append("<p class='mute'>No automated operations were run for this case.</p>")

    parts.append("<h2>3. Findings</h2>")
    parts.append(f"<p class='mute'>{len(shown)} finding(s) shown{f'; {dismissed} dismissed by the analyst and omitted' if dismissed else ''}. Findings marked UNREVIEWED have not been confirmed by an analyst.</p>")
    parts.append(_table(["Ref", "Kind", "Summary", "Source", "Retrieved (UTC)", "Confidence", "Review"],
                        [[f["ref"], f["kind"], f["title"] + (" — " + f["summary"] if f["summary"] else ""), f["source_url"] or f["source"], f["retrieved_at"], f["confidence"],
                          "CONFIRMED" if f["review_status"] == "confirmed" else "UNREVIEWED"] for f in shown]))

    parts.append("<h2>4. Indicators</h2>")
    parts.append(_table(["Ref", "Type", "Value", "Severity", "Confidence", "Reasoning"],
                        [[i["ref"], i["type"], i["value"], i["severity"], i["confidence"], " ".join(i["reasoning"]) or "Not enriched"] for i in inds]))

    parts.append("<h2>5. Evidence</h2>")
    parts.append(_table(["Ref", "Name", "SHA-256 (recorded)", "Size", "Registered", "Last verification"],
                        [[e["ref"], e["name"], _Raw(f"<span class='mono'>{E(e['sha256'])}</span>"), e["size"], e["created_at"],
                          f"{e['last_verify_result']} @ {e['last_verified_at']}" if e["last_verified_at"] else "never verified"] for e in evid]))

    if notes:
        parts.append("<h2>6. Analyst Notes</h2>")
        for n in reversed(notes):
            parts.append(f"<p><span class='mono mute'>{E(n['created_at'])} · {E(n['author'])}</span><br>{E(n['body']).replace(chr(10), '<br>')}</p>")

    parts.append("<h2>7. Limitations</h2><ul>"
                 "<li>Results reflect the sources and moments listed above; DNS, registration and certificate data change over time.</li>"
                 "<li>Absence of a detection by a threat-intelligence provider does not mean an indicator is benign.</li>"
                 "<li>Third-party services (RDAP, certificate transparency, reputation providers) may be incomplete, rate-limited or wrong.</li>"
                 f"<li>Operation types executed: {E(', '.join(kinds) or 'none')}. Anything not listed was not checked.</li>"
                 "<li>Integrity hashes are computed by this workstation and are not independently timestamped or signed.</li></ul>")

    parts.append("<h2>8. Recommendations</h2><p class='mute'>Rule-derived from the stored data above — not model-generated.</p><ul>")
    parts += [f"<li>{E(r)}</li>" for r in derive_recommendations(shown, inds, evid)]
    parts.append("</ul>")

    if ai_sections:
        parts.append("<h2>9. AI-Assisted Draft (unverified)</h2>")
        for sec in ai_sections:
            parts.append(f"<div class='ai'><b>{E(sec.get('title', 'Draft'))}</b> — <i>MODEL-GENERATED HYPOTHESIS, not a verified finding. Reviewed by analyst before inclusion.</i>"
                         f"<br>{E(sec.get('body', '')).replace(chr(10), '<br>')}</div>")

    parts.append("<h2>Appendix A — Audit Trail</h2>")
    parts.append(_table(["Time (UTC)", "Actor", "Action", "Entity"], [[a["ts"], a["actor"], a["action"], f"{a['entity_type'] or ''} {a['entity_id'] or ''}".strip()] for a in audit_rows]))
    parts.append("</body></html>")
    return "".join(parts)


def generate(case_id: int, ai_sections: list[dict[str, str]] | None = None) -> dict[str, Any]:
    s = get_settings()
    s.ensure_dirs()
    content = build_html(case_id, ai_sections)
    data = content.encode("utf-8")
    sha = hashlib.sha256(data).hexdigest()
    with db() as c:
        case = c.execute("SELECT ref, name FROM cases WHERE id=?", (case_id,)).fetchone()
        if not case:
            raise NotFound("Case")
        ref = next_ref(c, "RPT")
        filename = f"{ref}.html"
        (s.report_dir / filename).write_bytes(data)
        cur = c.execute(
            "INSERT INTO reports(ref, case_id, title, format, filename, sha256, size, ai_sections, created_by, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (ref, case_id, f"{case['name']} — Investigation Report", "html", filename, sha, len(data), len(ai_sections or []), audit.current_actor(), utcnow()))
        audit.record(c, "report.generate", entity_type="report", entity_id=ref, case_id=case_id, detail={"sha256": sha, "ai_sections": len(ai_sections or [])})
        row = dict(c.execute("SELECT * FROM reports WHERE id=?", (cur.lastrowid,)).fetchone())
    return row


def list_reports(case_id: int | None = None) -> list[dict[str, Any]]:
    with db() as c:
        if case_id is None:
            rows = c.execute("SELECT r.*, c.ref AS case_ref FROM reports r JOIN cases c ON c.id=r.case_id ORDER BY r.id DESC LIMIT 200")
        else:
            rows = c.execute("SELECT r.*, c.ref AS case_ref FROM reports r JOIN cases c ON c.id=r.case_id WHERE r.case_id=? ORDER BY r.id DESC", (case_id,))
        return rows_to_dicts(rows)


def read_report(report_id: int) -> tuple[bytes, dict[str, Any]]:
    with db() as c:
        row = c.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()
    if not row:
        raise NotFound("Report")
    path = get_settings().report_dir / row["filename"]
    if not path.is_file():
        raise NotFound("Report file")
    return path.read_bytes(), dict(row)

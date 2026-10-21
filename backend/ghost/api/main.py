"""Flask application. Thin HTTP layer over ghost.services.* — no business logic lives here."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from flask import Flask, Response, jsonify, request, send_file, send_from_directory
from werkzeug.exceptions import HTTPException

from .. import __version__
from ..config import get_settings
from ..db import db, migrate, rows_to_dicts
from ..errors import GhostError, NotFound
from ..services import (ai, cases, command, evidence, findings, integrations, intel, operations, osint, pcap, reports, sample, system)

log = logging.getLogger("ghost.api")
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
ALLOWED_HOSTS = {"localhost", "127.0.0.1", "[::1]", "testserver"}
_DIST = Path(__file__).resolve().parents[3] / "frontend" / "dist"

app = Flask(__name__, static_folder=None)
app.json.sort_keys = False  # type: ignore[attr-defined]
app.config["MAX_CONTENT_LENGTH"] = (get_settings().max_upload_mb + 8) * 1024 * 1024


def startup() -> None:
    """Idempotent: create directories, migrate the schema, recover interrupted operations."""
    get_settings().ensure_dirs()
    version = migrate()
    interrupted = operations.recover_interrupted()
    log.info("Fidx-Ghost %s ready (schema v%s, %d interrupted operation(s) recovered)", __version__, version, interrupted)


# --- request guards ------------------------------------------------------------------

def _host_name() -> str:
    host = request.host or ""
    return host.rsplit(":", 1)[0] if not host.startswith("[") else host.split("]")[0] + "]"


@app.before_request
def guard():
    """Reject unexpected Host headers (DNS-rebinding) and cross-origin state changes (CSRF)."""
    if _host_name() not in ALLOWED_HOSTS:
        return _err("bad_host", "Unexpected Host header", 400)
    if request.method not in SAFE_METHODS:
        origin = request.headers.get("Origin")
        if origin and origin not in get_settings().cors_origins and origin != f"{request.scheme}://{request.host}":
            return _err("forbidden_origin", "Cross-origin request rejected", 403)
    return None


@app.after_request
def headers(resp: Response):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    origin = request.headers.get("Origin")
    if origin and origin in get_settings().cors_origins:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
        resp.headers["Vary"] = "Origin"
    return resp


def _err(code: str, message: str, status: int):
    return jsonify({"error": {"code": code, "message": message}}), status


@app.errorhandler(GhostError)
def on_ghost_error(exc: GhostError):
    return _err(exc.code, exc.message, exc.status)


@app.errorhandler(HTTPException)
def on_http_error(exc: HTTPException):
    msg = "Upload too large" if exc.code == 413 else (exc.description or exc.name)
    return _err("http_error", msg, exc.code or 500)


@app.errorhandler(Exception)
def on_unhandled(exc: Exception):
    log.exception("Unhandled error")
    return _err("internal", f"Internal error: {type(exc).__name__}", 500)


# --- input helpers -------------------------------------------------------------------

def body() -> dict[str, Any]:
    data = request.get_json(silent=True)
    if data is None and request.data:
        raise GhostError("Request body must be valid JSON", 400, "bad_json")
    if data is not None and not isinstance(data, dict):
        raise GhostError("JSON body must be an object", 422, "validation")
    return data or {}


def text(d: dict, key: str, *, required=False, max_len=4000, default: str | None = "") -> str | None:
    v = d.get(key, default)
    if v is None:
        if required:
            raise GhostError(f"'{key}' is required", 422, "validation")
        return None
    if not isinstance(v, str):
        raise GhostError(f"'{key}' must be a string", 422, "validation")
    if required and not v.strip():
        raise GhostError(f"'{key}' is required", 422, "validation")
    if len(v) > max_len:
        raise GhostError(f"'{key}' is too long (max {max_len})", 422, "validation")
    return v


def integer(d: dict, key: str, *, required=False) -> int | None:
    v = d.get(key)
    if v is None or v == "":
        if required:
            raise GhostError(f"'{key}' is required", 422, "validation")
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        raise GhostError(f"'{key}' must be an integer", 422, "validation")


def flag(d: dict, key: str) -> bool:
    v = d.get(key, False)
    if not isinstance(v, bool):
        raise GhostError(f"'{key}' must be true or false", 422, "validation")
    return v


def qint(name: str) -> int | None:
    v = request.args.get(name)
    if v in (None, ""):
        return None
    try:
        return int(v)
    except ValueError:
        raise GhostError(f"'{name}' must be an integer", 422, "validation")


def qbool(name: str) -> bool:
    return request.args.get(name, "").lower() in ("1", "true", "yes")


def form_int(name: str) -> int | None:
    v = request.form.get(name)
    if not v:
        return None
    try:
        return int(v)
    except ValueError:
        raise GhostError(f"'{name}' must be an integer", 422, "validation")


def one_file():
    f = request.files.get("file")
    if f is None or not f.filename:
        raise GhostError("A file upload named 'file' is required", 422, "validation")
    return f


def attachment(data: bytes | str, media: str, name: str) -> Response:
    safe = Path(name).name.replace('"', "")
    return Response(data, mimetype=media, headers={"Content-Disposition": f'attachment; filename="{safe}"'})


# --- system --------------------------------------------------------------------------

@app.get("/api/health")
def health():
    return {"ok": True, "version": __version__}


@app.get("/api/status")
def status():
    return system.status()


@app.get("/api/config")
def config():
    s = get_settings()
    return {"map": {"tile_url": s.map_tile_url, "attribution": s.map_attribution, "dark": s.map_dark_tiles}, "version": __version__, "max_upload_mb": s.max_upload_mb}


@app.put("/api/settings/field-mode")
def put_field_mode():
    return {"field_mode": system.set_field_mode(flag(body(), "enabled"))}


@app.get("/api/settings/integrations")
def get_integrations():
    return jsonify(integrations.status())


@app.put("/api/settings/integrations")
def put_integrations():
    values = body().get("values")
    if not isinstance(values, dict):
        raise GhostError("'values' must be an object of setting -> value", 422, "validation")
    return jsonify(integrations.save(values))


@app.post("/api/settings/integrations/test")
def test_integration():
    return integrations.test(text(body(), "target", required=True, max_len=20))


@app.post("/api/system/backup")
def make_backup():
    path = evidence.create_backup()
    return {"file": path.name, "size": path.stat().st_size, "download": f"/api/system/backups/{path.name}"}


@app.get("/api/system/backups/<name>")
def get_backup(name: str):
    path = get_settings().data_dir / "backups" / Path(name).name
    if not path.is_file() or path.suffix != ".zip":
        raise NotFound("Backup")
    return send_file(path, mimetype="application/zip", as_attachment=True, download_name=path.name)


@app.get("/api/command/overview")
def command_overview():
    return command.overview(qint("workspace_id"))


@app.get("/api/audit")
def audit_log():
    sql, args = "SELECT * FROM audit WHERE 1=1", []
    if qint("case_id") is not None:
        sql += " AND case_id=?"
        args.append(qint("case_id"))
    if request.args.get("action"):
        sql += " AND action LIKE ?"
        args.append(request.args["action"] + "%")
    limit = min(qint("limit") or 100, 500)
    with db() as c:
        return jsonify(rows_to_dicts(c.execute(sql + " ORDER BY id DESC LIMIT ?", (*args, limit)), ("detail",)))


# --- workspaces / cases --------------------------------------------------------------

@app.get("/api/workspaces")
def get_workspaces():
    return jsonify(cases.list_workspaces())


@app.post("/api/workspaces")
def post_workspace():
    return jsonify(cases.create_workspace(text(body(), "name", required=True, max_len=40))), 201


@app.post("/api/workspaces/<int:ws_id>/activate")
def activate_workspace(ws_id: int):
    cases.set_active_workspace(ws_id)
    return {"active_workspace_id": ws_id}


@app.get("/api/cases")
def get_cases():
    a = request.args
    return jsonify(cases.list_cases(a.get("q") or None, a.get("status") or None, a.get("priority") or None,
                                    qint("workspace_id"), qbool("include_archived")))


def _tags(d: dict) -> list[str] | None:
    t = d.get("tags")
    if t is None:
        return None
    if not isinstance(t, list) or not all(isinstance(x, str) for x in t):
        raise GhostError("'tags' must be a list of strings", 422, "validation")
    return t


@app.post("/api/cases")
def post_case():
    d = body()
    case = cases.create_case(
        name=text(d, "name", required=True, max_len=120), objective=text(d, "objective") or "", scope=text(d, "scope") or "",
        authorisation_ack=flag(d, "authorisation_ack"), priority=text(d, "priority", default="medium", max_len=16) or "medium",
        tags=_tags(d), workspace_id=integer(d, "workspace_id"))
    return jsonify(case), 201


@app.get("/api/cases/<int:case_id>")
def get_case(case_id: int):
    return cases.get_case(case_id)


@app.patch("/api/cases/<int:case_id>")
def patch_case(case_id: int):
    d = body()
    fields: dict[str, Any] = {}
    for k in ("name", "objective", "scope", "status", "priority"):
        if k in d:
            fields[k] = text(d, k, max_len=4000 if k in ("objective", "scope") else 120)
    if "authorisation_ack" in d:
        fields["authorisation_ack"] = flag(d, "authorisation_ack")
    if "tags" in d:
        fields["tags"] = _tags(d)
    return cases.update_case(case_id, **fields)


@app.post("/api/cases/<int:case_id>/archive")
def archive_case(case_id: int):
    return cases.archive_case(case_id)


@app.get("/api/cases/<int:case_id>/notes")
def get_notes(case_id: int):
    cases.get_case(case_id)
    return jsonify(cases.list_notes(case_id))


@app.post("/api/cases/<int:case_id>/notes")
def post_note(case_id: int):
    return jsonify(cases.add_note(case_id, text(body(), "body", required=True, max_len=20000))), 201


@app.get("/api/cases/<int:case_id>/timeline")
def get_timeline(case_id: int):
    return jsonify(cases.case_timeline(case_id))


@app.post("/api/cases/<int:case_id>/report")
def post_report(case_id: int):
    d = body()
    secs = d.get("ai_sections") or None
    if secs is not None and (not isinstance(secs, list) or not all(isinstance(s, dict) for s in secs)):
        raise GhostError("'ai_sections' must be a list of objects", 422, "validation")
    return jsonify(reports.generate(case_id, secs)), 201


# --- operations / findings -----------------------------------------------------------

@app.get("/api/operations")
def get_operations():
    a = request.args
    return jsonify(operations.list_operations(qint("case_id"), a.get("status") or None, a.get("kind") or None, min(qint("limit") or 100, 500)))


@app.get("/api/operations/<int:op_id>")
def get_operation(op_id: int):
    op = operations.get(op_id)
    op["findings"] = findings.list_findings(operation_id=op_id)
    return op


@app.post("/api/operations/<int:op_id>/cancel")
def cancel_operation(op_id: int):
    return operations.cancel(op_id)


@app.get("/api/operations/<int:op_id>/download")
def download_operation(op_id: int):
    op = operations.get(op_id)
    payload = json.dumps({"operation": op["ref"], "kind": op["kind"], "target": op["target"], "status": op["status"],
                          "started_at": op["started_at"], "finished_at": op["finished_at"], "result": op["result"],
                          "error": op["error"]}, indent=2, default=str)
    return attachment(payload, "application/json", f"{op['ref']}.json")


@app.get("/api/findings")
def get_findings():
    a = request.args
    return jsonify(findings.list_findings(case_id=qint("case_id"), review_status=a.get("review_status") or None,
                                          kind=a.get("kind") or None, limit=min(qint("limit") or 200, 1000)))


@app.patch("/api/findings/<int:finding_id>/review")
def review_finding(finding_id: int):
    return findings.set_review(finding_id, text(body(), "review_status", required=True, max_len=16))


# --- OSINT / intel / network ---------------------------------------------------------

@app.post("/api/osint/domain")
def osint_domain():
    d = body()
    op = osint.start_domain_investigation(text(d, "domain", required=True, max_len=253), integer(d, "case_id"),
                                          flag(d, "active"), text(d, "authorisation_note", max_len=500) or "",
                                          geolocate=flag(d, "geolocate") if "geolocate" in d else False)
    return jsonify(op), 202


@app.post("/api/sample")
def load_sample_case():
    return jsonify(sample.load_sample()), 201


def _ioc_type(d: dict) -> str | None:
    t = d.get("type")
    if t in (None, ""):
        return None
    if t not in intel.IOC_TYPES:
        raise GhostError(f"type must be one of {', '.join(intel.IOC_TYPES)}", 422, "validation")
    return t


@app.post("/api/intel/validate")
def intel_validate():
    d = body()
    t, v = intel.normalise(text(d, "value", required=True, max_len=2100), _ioc_type(d))
    return {"type": t, "value": v, "providers": intel.available_providers(t)}


@app.get("/api/intel/indicators")
def list_indicators():
    a = request.args
    return jsonify(intel.list_indicators(a.get("q") or None, a.get("type") or None, qint("case_id"), a.get("min_severity") or None))


@app.post("/api/intel/indicators")
def add_indicator():
    d = body()
    return jsonify(intel.add_indicator(text(d, "value", required=True, max_len=2100), _ioc_type(d), integer(d, "case_id"))), 201


@app.get("/api/intel/indicators/<int:ind_id>")
def get_indicator(ind_id: int):
    return intel.get_indicator(ind_id)


@app.post("/api/intel/indicators/<int:ind_id>/enrich")
def enrich_indicator(ind_id: int):
    return jsonify(intel.start_enrichment(ind_id, qint("case_id"))), 202


@app.post("/api/intel/indicators/<int:ind_id>/link")
def link_indicator(ind_id: int):
    return intel.link_to_case(ind_id, integer(body(), "case_id", required=True))  # type: ignore[arg-type]


@app.get("/api/intel/export")
def export_indicators():
    content, media, name = intel.export_indicators(request.args.get("format", "json"), qint("case_id"))
    return attachment(content, media, name)


@app.get("/api/intel/providers")
def intel_providers():
    return jsonify(system.providers())


@app.get("/api/network/tools")
def network_tools():
    return jsonify(system.tools())


@app.post("/api/network/analyze")
def network_analyze():
    f = one_file()
    upload = pcap.store_upload(f.stream, f.filename or "capture.pcap")
    try:
        return jsonify(pcap.start_analysis(upload, form_int("case_id"), request.form.get("engine", "auto"))), 202
    except GhostError:
        Path(upload["path"]).unlink(missing_ok=True)
        raise


# --- graph / evidence / reports / ai -------------------------------------------------

@app.get("/api/graph")
def get_graph():
    return findings.graph(qint("case_id"), [t for t in request.args.get("types", "").split(",") if t] or None, min(qint("limit") or 600, 1000))


@app.get("/api/evidence")
def get_evidence():
    return jsonify(evidence.list_evidence(qint("case_id"), request.args.get("q") or None))


@app.post("/api/evidence")
def post_evidence():
    f = one_file()
    ev = evidence.register(f.stream, f.filename or "evidence.bin", case_id=form_int("case_id"),
                           description=request.form.get("description", ""), source=request.form.get("source", ""))
    return jsonify(ev), 201


@app.get("/api/evidence/<int:evidence_id>")
def get_one_evidence(evidence_id: int):
    return evidence.get(evidence_id)


@app.post("/api/evidence/<int:evidence_id>/verify")
def verify_evidence(evidence_id: int):
    return evidence.verify(evidence_id)


@app.get("/api/evidence/<int:evidence_id>/download")
def download_evidence(evidence_id: int):
    data, name, _mime = evidence.read_bytes(evidence_id)
    return attachment(data, "application/octet-stream", name)


@app.delete("/api/evidence/<int:evidence_id>")
def delete_evidence(evidence_id: int):
    return evidence.delete(evidence_id)


@app.get("/api/reports")
def get_reports():
    return jsonify(reports.list_reports(qint("case_id")))


@app.get("/api/reports/<int:report_id>/view")
def view_report(report_id: int):
    data, row = reports.read_report(report_id)
    resp = Response(data, mimetype="text/html")
    resp.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; img-src data:"
    if qbool("download"):
        resp.headers["Content-Disposition"] = f'attachment; filename="{row["filename"]}"'
    return resp


@app.get("/api/ai/status")
def ai_status():
    return ai.status()


@app.post("/api/ai/analyse")
def ai_analyse():
    d = body()
    task = text(d, "task", required=True, max_len=32)
    return ai.run(integer(d, "case_id", required=True), task, text(d, "question", max_len=500) or "")  # type: ignore[arg-type]


# --- optional: serve the built frontend (single-process mode) ------------------------

@app.get("/", defaults={"path": ""})
@app.get("/<path:path>")
def spa(path: str):
    if path.startswith("api/"):
        raise NotFound("Route")
    if not _DIST.is_dir():
        return _err("no_ui", "The web UI is not built. Run `npm run build` in frontend/, or use the Vite dev server.", 404)
    target = (_DIST / path).resolve()
    if path and target.is_file() and _DIST.resolve() in target.parents:
        return send_from_directory(_DIST, path)
    return send_from_directory(_DIST, "index.html")

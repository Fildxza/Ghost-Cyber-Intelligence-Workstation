"""`ghost` — command-line interface. Calls the same service layer as the web UI (no HTTP hop,
no duplicated logic). Exit codes: 0 ok · 1 error · 2 usage · 3 unavailable (tool/provider/mode) · 4 operation failed.
"""
from __future__ import annotations

import functools
import json
import logging
import sys
from pathlib import Path
from typing import Any, Callable

import click

from . import __version__
from .config import get_settings
from .db import migrate
from .errors import GhostError
from .services import (cases, evidence, findings, intel, operations, osint, pcap, reports, sample, system)  # noqa: F401  (handlers register on import)

json_opt = click.option("--json", "as_json", is_flag=True, help="Machine-readable JSON output.")


_ASCII = str.maketrans({"—": "-", "–": "-", "×": "x", "…": "...", "→": "->", "·": "-", "’": "'"})


def say(msg: str = "", fg: str | None = None, err: bool = False) -> None:
    if (getattr(sys.stdout, "encoding", None) or "").lower().replace("-", "") != "utf8":
        msg = msg.translate(_ASCII)
    click.echo(click.style(msg, fg=fg) if fg else msg, err=err)


def emit(data: Any, as_json: bool, render: Callable[[Any], None]) -> None:
    if as_json:
        click.echo(json.dumps(data, indent=2, default=str))
    else:
        render(data)


def table(headers: list[str], rows: list[list[Any]]) -> None:
    cols = [headers] + [[str(c) for c in r] for r in rows]
    widths = [min(max(len(r[i]) for r in cols), 60) for i in range(len(headers))]
    line = lambda r: "  ".join(str(c)[:w].ljust(w) for c, w in zip(r, widths))  # noqa: E731
    say(click.style(line(headers), bold=True))
    say("  ".join("-" * w for w in widths))
    for r in cols[1:]:
        say(line(r))


def write_output(path: Path, data: str | bytes) -> None:
    """Write a user-specified output file; turn OS errors into a clean message instead of a traceback."""
    try:
        if isinstance(data, bytes):
            path.write_bytes(data)
        else:
            path.write_text(data, encoding="utf-8")
    except OSError as exc:
        raise GhostError(f"Cannot write {path}: {exc.strerror or exc}", 1, "write_failed")


def guarded(fn):
    """Map domain errors to readable messages and exit codes (3 = unavailable, else 1)."""
    @functools.wraps(fn)
    def wrapper(*a, **kw):
        try:
            return fn(*a, **kw)
        except GhostError as exc:
            say(f"error: {exc.message}", fg="red", err=True)
            sys.exit(3 if exc.status == 503 else 1)
    return wrapper


@click.group(help="Fidx-Ghost — local-first cyber intelligence workstation CLI.", context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, "--version", prog_name="ghost")
@click.option("--debug", is_flag=True, help="Verbose logging (never prints secrets).")
def app(debug: bool):
    logging.basicConfig(level=logging.DEBUG if debug else logging.WARNING, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    migrate()


def finish_operation(op: dict[str, Any], as_json: bool) -> None:
    fnds = findings.list_findings(operation_id=op["id"])
    if as_json:
        click.echo(json.dumps({**op, "findings": fnds}, indent=2, default=str))
    else:
        colour = {"completed": "green", "failed": "red", "cancelled": "yellow"}[op["status"]]
        say(f"{op['ref']} {op['status'].upper()}  {op['kind']}  {op['target']}", fg=colour)
        if op["error"]:
            say(f"  {op['error']}", fg="red")
        for f in fnds:
            say(f"  - {f['ref']} {f['title']}  [{f['summary']}]")
    if op["status"] != "completed":
        sys.exit(4)


def await_op(op: dict[str, Any], as_json: bool, timeout: float) -> dict[str, Any]:
    if not as_json:
        say(f"{op['ref']} {op['status']} - waiting...", err=True)
    return operations.wait_for(op["id"], timeout)


# --- status / serve ------------------------------------------------------------------

@app.command()
@json_opt
@click.option("--api", is_flag=True, help="Also probe the running HTTP API.")
@guarded
def status(as_json: bool, api: bool):
    """Report real system state: database, tools, providers, vault, worker."""
    data = system.status()
    if api:
        import httpx
        s = get_settings()
        url = f"http://{s.host}:{s.port}/api/health"
        try:
            data["api_probe"] = {"url": url, "reachable": httpx.get(url, timeout=2).status_code == 200}
        except httpx.HTTPError as exc:
            data["api_probe"] = {"url": url, "reachable": False, "error": type(exc).__name__}

    def render(d):
        db_ = d["database"]
        rows = [
            ("Database", f"OK  sqlite schema v{db_['schema_version']} ({db_['latency_ms']} ms)" if db_["ok"] else f"FAIL {db_.get('error')}"),
            ("Worker", f"{d['worker']['workers']} threads, queued {d['worker']['queued']}, running {d['worker']['running']}"),
            ("Field mode", "ON (outbound network operations refused)" if d["field_mode"] else "off"),
            ("Vault encryption", d["vault"]["encryption"]),
        ]
        rows += [(f"Tool: {t['name']}", f"available {t.get('version') or ''}" if t["installed"] else "NOT INSTALLED") for t in d["tools"]]
        rows += [(f"Provider: {p['name']}", "key configured" if p["configured"] else f"not configured ({p['env']})") for p in d["providers"]]
        rows.append(("AI analyst", f"configured ({d['ai']['model']})" if d["ai"]["configured"] else "not configured"))
        if "api_probe" in d:
            rows.append(("HTTP API", "reachable" if d["api_probe"]["reachable"] else f"not reachable ({d['api_probe']['url']})"))
        say(f"Fidx-Ghost {d['version']}  session {d['session_id']}", fg="green")
        for k, v in rows:
            say(f"  {k:<34}{v}")
    emit(data, as_json, render)
    if not data["database"]["ok"]:
        sys.exit(1)


@app.command()
@click.option("--host", default=None)
@click.option("--port", default=None, type=int)
def serve(host: str | None, port: int | None):
    """Run the HTTP API (and the built web UI if frontend/dist exists)."""
    from werkzeug.serving import run_simple
    from .api.main import app as flask_app, startup
    s = get_settings()
    startup()
    run_simple(host or s.host, port or s.port, flask_app, threaded=True, use_reloader=False)


@app.command("sample")
@json_opt
@guarded
def sample_cmd(as_json):
    """Create a sample case and run REAL passive lookups against example.com (needs internet)."""
    r = sample.load_sample()
    emit(r, as_json, lambda d: say(f"sample case {d['case']['ref']} created; investigation {d['investigation']['ref']} and enrichment {d['enrichment']['ref']} queued", fg="green"))


# --- cases ---------------------------------------------------------------------------

@app.group("case", help="Case management.")
def case_group():
    pass


@case_group.command("list")
@click.option("--q", default=None)
@click.option("--status", default=None)
@click.option("--archived", is_flag=True)
@json_opt
@guarded
def case_list(q, status, archived, as_json):
    """List cases."""
    rows = cases.list_cases(q=q, status=status, include_archived=archived)
    emit(rows, as_json, lambda rs: table(["Ref", "Name", "Status", "Priority", "Updated"], [[r["ref"], r["name"], r["status"], r["priority"], r["updated_at"][:19]] for r in rs]) if rs else say("No cases."))


@case_group.command("create")
@click.argument("name")
@click.option("--objective", default="")
@click.option("--scope", default="", help="Declared target scope.")
@click.option("--authorised", is_flag=True, help="Acknowledge you are authorised to test the declared scope.")
@click.option("--priority", default="medium")
@click.option("--tag", "tags", multiple=True)
@json_opt
@guarded
def case_create(name, objective, scope, authorised, priority, tags, as_json):
    """Create a case (reference ID is generated)."""
    if authorised and not scope.strip():
        raise GhostError("--authorised requires --scope", 422, "validation")
    c = cases.create_case(name, objective, scope, authorised, priority, list(tags))
    emit(c, as_json, lambda d: say(f"created {d['ref']}  {d['name']}  (id {d['id']})", fg="green"))


@case_group.command("show")
@click.argument("case_id", type=int)
@json_opt
@guarded
def case_show(case_id, as_json):
    """Show a case with record counts."""
    c = cases.get_case(case_id)
    emit(c, as_json, lambda d: click.echo(json.dumps(d, indent=2, default=str)))


# --- osint ---------------------------------------------------------------------------

@app.group("osint", help="Open-source investigation.")
def osint_group():
    pass


@osint_group.command("domain")
@click.argument("domain")
@click.option("--case", "case_id", type=int, default=None, help="Case ID to attach findings to.")
@click.option("--active", is_flag=True, help="Also perform direct TLS + HTTP checks (needs an authorised case).")
@click.option("--authorisation", default="", help="Who authorised active testing of this target.")
@click.option("--geolocate", is_flag=True, help="Also geolocate resolved IPs via ipwho.is (third-party lookup; creates map pins).")
@click.option("--timeout", type=float, default=120)
@json_opt
@guarded
def osint_domain(domain, case_id, active, authorisation, geolocate, timeout, as_json):
    """Investigate a domain: DNS, RDAP, certificate transparency (+TLS/HTTP with --active)."""
    op = osint.start_domain_investigation(domain, case_id, active, authorisation, geolocate)
    finish_operation(await_op(op, as_json, timeout), as_json)


# --- intel ---------------------------------------------------------------------------

@app.group("intel", help="Threat-intelligence indicators.")
def intel_group():
    pass


@intel_group.command("add")
@click.argument("value")
@click.option("--case", "case_id", type=int, default=None)
@json_opt
@guarded
def intel_add(value, case_id, as_json):
    """Validate, normalise and register an indicator (no network access)."""
    i = intel.add_indicator(value, None, case_id)
    emit(i, as_json, lambda d: say(f"{'duplicate' if d['duplicate'] else 'added'} {d['ref']}  {d['type']}:{d['value']}", fg="yellow" if d["duplicate"] else "green"))


@intel_group.command("enrich")
@click.argument("value")
@click.option("--case", "case_id", type=int, default=None)
@click.option("--timeout", type=float, default=90)
@json_opt
@guarded
def intel_enrich(value, case_id, timeout, as_json):
    """Enrich an indicator with configured providers."""
    ind = intel.add_indicator(value, None, case_id)
    done = await_op(intel.start_enrichment(ind["id"], case_id), as_json, timeout)
    if not as_json and done["status"] == "completed":
        r = done["result"]
        say(f"severity {r['severity']} - confidence {r['confidence']}")
        for line in r["reasoning"]:
            say(f"  - {line}")
    finish_operation(done, as_json)


@intel_group.command("list")
@click.option("--case", "case_id", type=int, default=None)
@json_opt
@guarded
def intel_list(case_id, as_json):
    """List indicators."""
    rows = intel.list_indicators(case_id=case_id)
    emit(rows, as_json, lambda rs: table(["Ref", "Type", "Value", "Severity", "Confidence"], [[r["ref"], r["type"], r["value"], r["severity"], r["confidence"]] for r in rs]) if rs else say("No indicators."))


@intel_group.command("export")
@click.option("--format", "fmt", default="json", type=click.Choice(["json", "csv"]))
@click.option("--case", "case_id", type=int, default=None)
@click.option("--output", type=click.Path(path_type=Path), default=None)
@guarded
def intel_export(fmt, case_id, output):
    """Export indicators to JSON or CSV."""
    content, _media, _name = intel.export_indicators(fmt, case_id)
    if output:
        write_output(output, content)
        say(f"wrote {output}")
    else:
        click.echo(content)


# --- network -------------------------------------------------------------------------

@app.group("network", help="Network capture analysis.")
def network_group():
    pass


@network_group.command("analyze")
@click.argument("capture", type=click.Path(path_type=Path))
@click.option("--case", "case_id", type=int, default=None)
@click.option("--engine", default="auto", type=click.Choice(["auto", "builtin", "tshark"]))
@click.option("--output", type=click.Path(path_type=Path), default=None, help="Write full structured results (JSON) here.")
@click.option("--timeout", type=float, default=300)
@json_opt
@guarded
def network_analyze(capture, case_id, engine, output, timeout, as_json):
    """Analyse a pcap / pcapng capture."""
    if not capture.is_file():
        say(f"error: file not found: {capture}", fg="red", err=True)
        sys.exit(1)
    with capture.open("rb") as fh:
        upload = pcap.store_upload(fh, capture.name)
    try:
        op = pcap.start_analysis(upload, case_id, engine)
    except GhostError:
        Path(upload["path"]).unlink(missing_ok=True)
        raise
    done = await_op(op, as_json, timeout)
    if output and done["result"]:
        write_output(output, json.dumps(done["result"], indent=2, default=str))
    if not as_json and done["status"] == "completed":
        r = done["result"]
        a = r["analysis"]
        say(f"{r['file']['filename']}  sha256 {r['file']['sha256']}")
        say(f"engine {r['engine']} - {a['packets']:,} packets - {a['start']} -> {a['end']}")
        table(["Protocol", "Packets"], [[p["name"], f"{p['packets']:,}"] for p in a["protocols"][:10]])
        for w in r["warnings"]:
            say(f"warning: {w}", fg="yellow")
    if as_json or done["status"] != "completed":
        finish_operation(done, as_json)


# --- evidence ------------------------------------------------------------------------

@app.group("evidence", help="Evidence vault.")
def evidence_group():
    pass


@evidence_group.command("add")
@click.argument("path", type=click.Path(path_type=Path))
@click.option("--case", "case_id", type=int, default=None)
@click.option("--description", default="")
@click.option("--source", default="")
@json_opt
@guarded
def evidence_add(path, case_id, description, source, as_json):
    """Register a file in the evidence vault (SHA-256 recorded)."""
    if not path.is_file():
        say(f"error: file not found: {path}", fg="red", err=True)
        sys.exit(1)
    with path.open("rb") as fh:
        e = evidence.register(fh, path.name, case_id=case_id, description=description, source=source)
    emit(e, as_json, lambda d: say(f"registered {d['ref']}  sha256 {d['sha256']}  ({'encrypted' if d['encrypted'] else 'unencrypted'})", fg="green"))


@evidence_group.command("verify")
@click.argument("evidence_id", type=int)
@json_opt
@guarded
def evidence_verify(evidence_id, as_json):
    """Recompute the SHA-256 and compare with the recorded value (exit 4 on mismatch)."""
    r = evidence.verify(evidence_id)
    emit(r, as_json, lambda d: say(f"{'MATCH' if d['intact'] else d['result']} {d['ref']}\n  recorded   {d['recorded_sha256']}\n  recomputed {d['recomputed_sha256']}", fg="green" if d["intact"] else "red"))
    if not r["intact"]:
        sys.exit(4)


@evidence_group.command("list")
@click.option("--case", "case_id", type=int, default=None)
@json_opt
@guarded
def evidence_list(case_id, as_json):
    """List evidence."""
    rows = evidence.list_evidence(case_id)
    emit(rows, as_json, lambda rs: table(["Ref", "Name", "SHA-256", "Size", "Verified"], [[r["ref"], r["name"], r["sha256"][:16] + "...", r["size"], r["last_verify_result"] or "never"] for r in rs]) if rs else say("No evidence."))


# --- reports -------------------------------------------------------------------------

@app.group("report", help="Case reports.")
def report_group():
    pass


@report_group.command("generate")
@click.argument("case_id", type=int)
@click.option("--output", type=click.Path(path_type=Path), default=None, help="Copy the HTML report here.")
@json_opt
@guarded
def report_generate(case_id, output, as_json):
    """Generate an HTML investigation report for a case."""
    r = reports.generate(case_id)
    path = get_settings().report_dir / r["filename"]
    if output:
        write_output(output, path.read_bytes())
    emit({**r, "path": str(output or path)}, as_json, lambda d: say(f"generated {d['ref']} -> {d['path']}  (sha256 {d['sha256'][:16]}...)", fg="green"))


if __name__ == "__main__":  # pragma: no cover
    app()

"""Indicator-of-compromise workspace: validation, normalisation, de-duplication, provider
enrichment with explainable severity/confidence, case association and export.
"""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import ipaddress
import json
import re
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit

from .. import netguard
from ..config import get_settings
from ..db import db, next_ref, row_to_dict, rows_to_dicts, utcnow
from ..errors import GhostError, NotFound, Unavailable
from . import findings, operations, system
from .findings import link, upsert_entity

IOC_TYPES = ("domain", "ip", "url", "hash")
SEVERITY_ORDER = {"unknown": -1, "informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_HASH_LEN = {32: "md5", 40: "sha1", 64: "sha256"}


def refang(value: str) -> str:
    v = value.strip()
    v = re.sub(r"^hxxp", "http", v, flags=re.I)
    v = v.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":").replace("[://]", "://")
    return v


def detect_type(value: str) -> str:
    v = refang(value)
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if re.fullmatch(r"[0-9a-fA-F]+", v) and len(v) in _HASH_LEN:
        return "hash"
    if re.match(r"^[a-z][a-z0-9+.-]*://", v, re.I):
        return "url"
    return "domain"


def normalise(value: str, type_: str | None = None) -> tuple[str, str]:
    """Return (type, canonical value) or raise a validation error."""
    if not value or not value.strip():
        raise GhostError("Indicator value is required", 422, "validation")
    raw = refang(value)
    t = type_ or detect_type(raw)
    if t not in IOC_TYPES:
        raise GhostError(f"Unsupported indicator type '{t}'. Supported: {', '.join(IOC_TYPES)}", 422, "validation")
    if t == "ip":
        try:
            return t, str(ipaddress.ip_address(raw))
        except ValueError:
            raise GhostError(f"'{value}' is not a valid IP address", 422, "validation")
    if t == "hash":
        if not re.fullmatch(r"[0-9a-fA-F]+", raw) or len(raw) not in _HASH_LEN:
            raise GhostError("File hash must be hexadecimal MD5 (32), SHA-1 (40) or SHA-256 (64)", 422, "validation")
        return t, raw.lower()
    if t == "domain":
        return t, netguard.normalise_domain(raw)
    parts = urlsplit(raw)
    if parts.scheme.lower() not in ("http", "https", "ftp") or not parts.hostname:
        raise GhostError("URL must start with http://, https:// or ftp:// and include a host", 422, "validation")
    if parts.username or parts.password:
        raise GhostError("URLs containing credentials are not accepted", 422, "validation")
    if len(raw) > 2048:
        raise GhostError("URL too long (max 2048 characters)", 422, "validation")
    netloc = parts.hostname.lower() + (f":{parts.port}" if parts.port else "")
    return t, urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, ""))


# --- persistence ---------------------------------------------------------------

def add_indicator(value: str, type_: str | None = None, case_id: int | None = None) -> dict[str, Any]:
    t, v = normalise(value, type_)
    now = utcnow()
    with db() as c:
        if case_id is not None and not c.execute("SELECT 1 FROM cases WHERE id=?", (case_id,)).fetchone():
            raise NotFound("Case")
        row = c.execute("SELECT id FROM indicators WHERE type=? AND value=?", (t, v)).fetchone()
        duplicate = row is not None
        if row:
            ind_id = row["id"]
            c.execute("UPDATE indicators SET last_seen=? WHERE id=?", (now, ind_id))
        else:
            ref = next_ref(c, "IOC")
            ind_id = c.execute(
                "INSERT INTO indicators(ref, type, value, first_seen, last_seen) VALUES (?,?,?,?,?)", (ref, t, v, now, now)
            ).lastrowid
        newly_linked = False
        if case_id is not None:
            newly_linked = c.execute(
                "INSERT INTO indicator_cases(indicator_id, case_id, linked_at) VALUES (?,?,?) ON CONFLICT DO NOTHING",
                (ind_id, case_id, now)).rowcount > 0
            case = c.execute("SELECT ref, name FROM cases WHERE id=?", (case_id,)).fetchone()
            link(c, upsert_entity(c, "case", case["ref"], case["name"]), upsert_entity(c, t, v),
                 "contains_indicator", "analyst association")
        from . import audit
        if not duplicate or newly_linked:
            audit.record(c, "indicator.add" if not duplicate else "indicator.link", entity_type="indicator", entity_id=ind_id,
                         case_id=case_id, detail={"type": t, "value": v, "duplicate": duplicate})
        out = get_indicator(ind_id, conn=c)
    out["duplicate"] = duplicate
    return out


def get_indicator(ind_id: int, conn=None) -> dict[str, Any]:
    def _get(c):
        row = row_to_dict(c.execute("SELECT * FROM indicators WHERE id=?", (ind_id,)).fetchone(), ("reasoning",))
        if not row:
            raise NotFound("Indicator")
        row["cases"] = rows_to_dicts(c.execute(
            "SELECT cs.id, cs.ref, cs.name FROM indicator_cases ic JOIN cases cs ON cs.id=ic.case_id WHERE ic.indicator_id=?", (ind_id,)))
        row["enrichments"] = rows_to_dicts(c.execute(
            "SELECT * FROM enrichments WHERE indicator_id=? ORDER BY retrieved_at DESC, id DESC LIMIT 50", (ind_id,)), ("data",))
        return row
    if conn is not None:
        return _get(conn)
    with db() as c:
        return _get(c)


def list_indicators(q: str | None = None, type_: str | None = None, case_id: int | None = None,
                    min_severity: str | None = None, limit: int = 300) -> list[dict[str, Any]]:
    sql = "SELECT i.* FROM indicators i"
    args: list[Any] = []
    where = []
    if case_id is not None:
        sql += " JOIN indicator_cases ic ON ic.indicator_id = i.id"
        where.append("ic.case_id = ?")
        args.append(case_id)
    if type_:
        where.append("i.type = ?")
        args.append(type_)
    if q:
        where.append("(i.value LIKE ? OR i.ref LIKE ?)")
        args += [f"%{q.strip()}%", f"%{q.strip()}%"]
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY i.last_seen DESC LIMIT ?"
    args.append(min(limit, 1000))
    with db() as c:
        rows = rows_to_dicts(c.execute(sql, args), ("reasoning",))
        for r in rows:
            r["case_count"] = c.execute("SELECT COUNT(*) FROM indicator_cases WHERE indicator_id=?", (r["id"],)).fetchone()[0]
    if min_severity:
        floor = SEVERITY_ORDER.get(min_severity, 0)
        rows = [r for r in rows if SEVERITY_ORDER.get(r["severity"], -1) >= floor]
    return rows


def link_to_case(ind_id: int, case_id: int) -> dict[str, Any]:
    with db() as c:
        ind = c.execute("SELECT type, value FROM indicators WHERE id=?", (ind_id,)).fetchone()
        if not ind:
            raise NotFound("Indicator")
    return add_indicator(ind["value"], ind["type"], case_id)


# --- providers -----------------------------------------------------------------

class ProviderResult(dict):
    """status: ok | not_found | rate_limited | auth_error | error | skipped"""


def _vt_url(type_: str, value: str) -> str:
    base = "https://www.virustotal.com/api/v3"
    if type_ == "domain":
        return f"{base}/domains/{quote(value)}"
    if type_ == "ip":
        return f"{base}/ip_addresses/{quote(value)}"
    if type_ == "hash":
        return f"{base}/files/{value}"
    ident = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
    return f"{base}/urls/{ident}"


def _call(url: str, headers: dict[str, str]) -> tuple[int, dict | None, str | None]:
    try:
        resp = netguard.safe_fetch(url, extra_headers=headers)
    except GhostError as exc:
        return 0, None, exc.message
    try:
        body = json.loads(resp.body) if resp.body else None
    except json.JSONDecodeError:
        return resp.status, None, "provider returned a non-JSON body"
    return resp.status, body, None


def _status_from_http(code: int) -> str:
    return {200: "ok", 404: "not_found", 429: "rate_limited", 401: "auth_error", 403: "auth_error"}.get(code, "error")


def query_virustotal(type_: str, value: str) -> ProviderResult:
    key = get_settings().vt_api_key
    url = _vt_url(type_, value)
    code, body, err = _call(url, {"x-apikey": key or ""})
    if err:
        return ProviderResult(provider="virustotal", status="error", error=err, source_url=url)
    status = _status_from_http(code)
    out = ProviderResult(provider="virustotal", status=status, http_status=code, source_url=url)
    if status == "ok" and body:
        attrs = body.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        out["data"] = {"stats": stats, "reputation": attrs.get("reputation"), "tags": attrs.get("tags", [])[:20],
                       "country": attrs.get("country"), "as_owner": attrs.get("as_owner"),
                       "last_analysis_date": attrs.get("last_analysis_date"),
                       "gui_url": url.replace("/api/v3/", "/gui/").replace("ip_addresses", "ip-address")}
    elif status not in ("not_found",):
        out["error"] = f"HTTP {code}"
    return out


def query_abuseipdb(type_: str, value: str) -> ProviderResult:
    key = get_settings().abuseipdb_api_key
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={quote(value)}&maxAgeInDays=90"
    code, body, err = _call(url, {"Key": key or "", "Accept": "application/json"})
    if err:
        return ProviderResult(provider="abuseipdb", status="error", error=err, source_url=url)
    status = _status_from_http(code)
    out = ProviderResult(provider="abuseipdb", status=status, http_status=code, source_url=url)
    if status == "ok" and body:
        d = body.get("data", {})
        out["data"] = {k: d.get(k) for k in ("abuseConfidenceScore", "totalReports", "numDistinctUsers", "countryCode",
                                             "isp", "usageType", "domain", "lastReportedAt", "isTor")}
    elif status != "not_found":
        out["error"] = f"HTTP {code}"
    return out


def query_ipinfo(type_: str, value: str) -> ProviderResult:
    token = get_settings().ipinfo_token
    shown_url = f"https://ipinfo.io/{value}/json"  # token deliberately excluded from the stored URL
    code, body, err = _call(f"{shown_url}?token={quote(token or '')}", {"Accept": "application/json"})
    if err:
        return ProviderResult(provider="ipinfo", status="error", error=err, source_url=shown_url)
    status = _status_from_http(code)
    out = ProviderResult(provider="ipinfo", status=status, http_status=code, source_url=shown_url)
    if status == "ok" and body:
        out["data"] = {k: body.get(k) for k in ("city", "region", "country", "loc", "org", "timezone", "hostname")}
    elif status != "not_found":
        out["error"] = f"HTTP {code}"
    return out


PROVIDERS = {
    "virustotal": (lambda s: s.vt_api_key, ("domain", "ip", "url", "hash"), query_virustotal),
    "abuseipdb": (lambda s: s.abuseipdb_api_key, ("ip",), query_abuseipdb),
    "ipinfo": (lambda s: s.ipinfo_token, ("ip",), query_ipinfo),
}


def available_providers(type_: str) -> list[str]:
    s = get_settings()
    return [n for n, (key, types, _) in PROVIDERS.items() if key(s) and type_ in types]


# --- scoring -------------------------------------------------------------------

def score(results: list[dict[str, Any]]) -> tuple[str, str, list[str]]:
    """Explainable verdict: returns (severity, confidence, reasoning[]). Absence of detections is
    never reported as 'safe'."""
    reasons: list[str] = []
    sev = -1
    agreeing = 0

    def bump(level: str, why: str):
        nonlocal sev
        reasons.append(why)
        sev = max(sev, SEVERITY_ORDER[level])

    for r in results:
        if r["status"] != "ok":
            continue
        d = r.get("data") or {}
        if r["provider"] == "virustotal":
            st = d.get("stats", {})
            mal, sus = int(st.get("malicious", 0)), int(st.get("suspicious", 0))
            total = sum(int(v) for v in st.values()) or 0
            if mal >= 10:
                bump("high", f"VirusTotal: {mal}/{total} engines flag this as malicious (≥10 → high)")
            elif mal >= 3:
                bump("medium", f"VirusTotal: {mal}/{total} engines flag this as malicious (3–9 → medium)")
            elif mal + sus >= 1:
                bump("low", f"VirusTotal: {mal} malicious / {sus} suspicious of {total} engines (1–2 → low)")
            else:
                bump("informational", f"VirusTotal: 0 of {total} engines flagged it. Absence of detections does not prove it is benign.")
        elif r["provider"] == "abuseipdb":
            s = int(d.get("abuseConfidenceScore") or 0)
            n = d.get("totalReports") or 0
            if s >= 75:
                bump("high", f"AbuseIPDB: abuse confidence {s}% from {n} reports in 90 days (≥75 → high)")
            elif s >= 25:
                bump("medium", f"AbuseIPDB: abuse confidence {s}% from {n} reports (25–74 → medium)")
            elif s >= 1:
                bump("low", f"AbuseIPDB: abuse confidence {s}% from {n} reports (1–24 → low)")
            else:
                bump("informational", "AbuseIPDB: no abuse reports in the last 90 days.")
        else:
            continue
        agreeing += 1
    if sev < 0:
        return "unknown", "none", ["No provider returned usable data."]
    confidence = "low" if agreeing <= 1 else "medium"
    if agreeing >= 2:
        # high only when two sources independently reach the same non-trivial severity band
        bands = set()
        for line in reasons:
            for lvl in ("high", "medium"):
                if f"→ {lvl})" in line:
                    bands.add(lvl)
        if bands == {"high"} or bands == {"medium"}:
            confidence = "high"
    reasons.append(f"Confidence {confidence}: {agreeing} source(s) responded." + (" Single source — corroborate before acting." if agreeing == 1 else ""))
    inv = {v: k for k, v in SEVERITY_ORDER.items()}
    return inv[sev], confidence, reasons


# --- enrichment ----------------------------------------------------------------

def start_enrichment(ind_id: int, case_id: int | None = None) -> dict[str, Any]:
    ind = get_indicator(ind_id)
    system.ensure_online("indicator enrichment")
    if not available_providers(ind["type"]):
        s = system.providers()
        hints = "; ".join(f"{p['name']}: {p['setup']}" for p in s if ind["type"] in p["types"])
        raise Unavailable(f"No enrichment provider is configured for {ind['type']} indicators. {hints}", "no_provider")
    cid = case_id if case_id is not None else (ind["cases"][0]["id"] if ind["cases"] else None)
    return operations.create("ioc_enrichment", f"{ind['type']}:{ind['value']}", case_id=cid, params={"indicator_id": ind_id})


@operations.register("ioc_enrichment")
def run_enrichment(ctx: operations.OperationContext) -> dict[str, Any]:
    ind = get_indicator(ctx.params["indicator_id"])
    t, v = ind["type"], ind["value"]
    private = t == "ip" and not netguard.is_public_ip(v)
    provider_status: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    s = get_settings()
    for name, (key, types, fn) in PROVIDERS.items():
        ctx.check_cancel()
        if t not in types:
            continue
        if not key(s):
            provider_status.append({"provider": name, "status": "unconfigured"})
            continue
        if private:
            provider_status.append({"provider": name, "status": "skipped", "error": "Private/reserved address — not sent to third parties"})
            continue
        res = fn(t, v)
        results.append(res)
        provider_status.append({"provider": name, "status": res["status"], "http_status": res.get("http_status"), "error": res.get("error")})
    severity, confidence, reasoning = score(results)
    now = utcnow()
    with db() as c:
        for res in results:
            c.execute(
                "INSERT INTO enrichments(indicator_id, provider, status, http_status, data, error, source_url, retrieved_at) VALUES (?,?,?,?,?,?,?,?)",
                (ind["id"], res["provider"], res["status"], res.get("http_status"), json.dumps(res.get("data") or {}),
                 res.get("error"), res.get("source_url"), now))
            if res["status"] == "ok":
                findings.add_finding(
                    c, kind="ioc_enrichment", title=f"{res['provider']} — {v}", source=res["provider"],
                    summary=next((r for r in reasoning if r.lower().startswith(res["provider"].lower()[:6])), ""),
                    data=res.get("data") or {}, source_url=res.get("source_url"), retrieved_at=now,
                    confidence="medium", case_id=ctx.case_id, operation_id=ctx.id)
            if res["provider"] == "ipinfo" and res["status"] == "ok":
                loc = (res.get("data") or {}).get("loc")
                if loc and "," in loc:
                    lat, lon = (float(x) for x in loc.split(",", 1))
                    d = res["data"]
                    label = ", ".join(x for x in (d.get("city"), d.get("country")) if x)
                    c.execute("UPDATE indicators SET geo_lat=?, geo_lon=?, geo_label=? WHERE id=?", (lat, lon, label, ind["id"]))
        if results and any(r["status"] == "ok" for r in results):
            c.execute("UPDATE indicators SET severity=?, confidence=?, reasoning=?, last_seen=? WHERE id=?",
                      (severity, confidence, json.dumps(reasoning), now, ind["id"]))
    ok = [p for p in provider_status if p["status"] == "ok"]
    if not ok:
        raise GhostError("No provider returned data: " + "; ".join(
            f"{p['provider']}={p['status']}{(' (' + p['error'] + ')') if p.get('error') else ''}" for p in provider_status), 502, "no_data")
    return {"indicator": f"{t}:{v}", "providers": provider_status, "severity": severity, "confidence": confidence, "reasoning": reasoning}


# --- export --------------------------------------------------------------------

def export_indicators(fmt: str = "json", case_id: int | None = None) -> tuple[str, str, str]:
    """Return (content, media_type, filename)."""
    rows = list_indicators(case_id=case_id, limit=1000)
    stamp = utcnow()[:19].replace(":", "").replace("-", "")
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["ref", "type", "value", "severity", "confidence", "first_seen", "last_seen", "reasoning"])
        for r in rows:
            w.writerow([r["ref"], r["type"], r["value"], r["severity"], r["confidence"], r["first_seen"], r["last_seen"], " | ".join(r["reasoning"])])
        return buf.getvalue(), "text/csv", f"ghost-indicators-{stamp}.csv"
    if fmt == "json":
        return json.dumps({"exported_at": utcnow(), "count": len(rows), "indicators": rows}, indent=2), "application/json", f"ghost-indicators-{stamp}.json"
    raise GhostError("format must be 'json' or 'csv'", 422, "validation")

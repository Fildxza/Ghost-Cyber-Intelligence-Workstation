"""Domain investigation. Passive steps (DNS, RDAP, certificate transparency) run by default.
Active steps (direct TLS handshake, HTTP request to the target) require a case with a declared
scope + authorisation acknowledgement. A step that cannot be completed is reported as such —
no result is ever invented.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, NameOID

from .. import dnsclient, netguard
from ..db import db, utcnow
from ..errors import GhostError
from . import cases, findings, operations, system
from .findings import link, upsert_entity

DNS_TYPES = ("A", "AAAA", "NS", "MX", "TXT", "CNAME", "SOA", "CAA")
SECURITY_HEADERS = ("strict-transport-security", "content-security-policy", "x-frame-options",
                    "x-content-type-options", "referrer-policy", "permissions-policy")


def start_domain_investigation(domain: str, case_id: int | None = None, active: bool = False,
                               authorisation_note: str = "") -> dict[str, Any]:
    domain = netguard.normalise_domain(domain)
    system.ensure_online("domain investigation")
    if active:
        cases.require_authorised(case_id)
        if not authorisation_note.strip():
            raise GhostError("Active checks need an authorisation statement (who authorised testing of this target).",
                             403, "authorisation_required")
    return operations.create("domain_investigation", domain, case_id=case_id, params={"active": active},
                             authorised=active, auth_note=authorisation_note)


# --- steps ---------------------------------------------------------------------

def _dns_step(domain: str) -> tuple[dict[str, list[str]], list[str]]:
    records: dict[str, list[str]] = {}
    errors: list[str] = []
    for rtype in DNS_TYPES:
        try:
            answers = dnsclient.resolve(domain, rtype)
        except dnsclient.NXDomain:
            return {}, ["NXDOMAIN — the domain does not exist"]
        except GhostError as exc:
            errors.append(f"{rtype}: {exc.message}")
            continue
        if answers:
            records[rtype] = answers
    return records, errors


def _rdap_step(domain: str) -> dict[str, Any]:
    url = f"https://rdap.org/domain/{domain}"
    resp = netguard.safe_fetch(url, extra_headers={"Accept": "application/rdap+json"})
    if resp.status == 404:
        raise GhostError("RDAP: no registration record found for this domain", 404, "not_found")
    if resp.status == 429:
        raise GhostError("RDAP: rate limited by the registry — try again later", 429, "rate_limited")
    if resp.status != 200:
        raise GhostError(f"RDAP responded with HTTP {resp.status}", 502, "provider_error")
    try:
        doc = json.loads(resp.body)
    except json.JSONDecodeError:
        raise GhostError("RDAP response was not valid JSON (possibly truncated)", 502, "provider_error")
    events = {e.get("eventAction"): e.get("eventDate") for e in doc.get("events", [])}
    registrar = None
    for ent in doc.get("entities", []):
        if "registrar" in ent.get("roles", []):
            vcard = ent.get("vcardArray", [None, []])[1]
            registrar = next((v[3] for v in vcard if v and v[0] == "fn"), None)
    return {
        "ldh_name": doc.get("ldhName"), "status": doc.get("status", []),
        "registrar": registrar,
        "registered": events.get("registration"), "expires": events.get("expiration"),
        "last_changed": events.get("last changed"),
        "nameservers": sorted(n.get("ldhName", "").lower() for n in doc.get("nameservers", [])),
        "resolved_via": resp.url,
    }


def _ct_step(domain: str) -> dict[str, Any]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    resp = netguard.safe_fetch(url, max_bytes=4 * 1024 * 1024)  # CT result sets are large; still bounded
    if resp.status == 429:
        raise GhostError("crt.sh rate limited the request", 429, "rate_limited")
    if resp.status != 200:
        raise GhostError(f"crt.sh responded with HTTP {resp.status}", 502, "provider_error")
    if resp.truncated:
        raise GhostError("crt.sh result set exceeded the safety size limit; not parsed", 502, "too_large")
    try:
        rows = json.loads(resp.body or b"[]")
    except json.JSONDecodeError:
        raise GhostError("crt.sh returned a non-JSON response (service may be overloaded)", 502, "provider_error")
    names: set[str] = set()
    issuers: dict[str, int] = {}
    for row in rows:
        for n in str(row.get("name_value", "")).splitlines():
            n = n.strip().lower().lstrip("*.")
            if n.endswith(domain):
                names.add(n)
        issuers[row.get("issuer_name", "?")] = issuers.get(row.get("issuer_name", "?"), 0) + 1
    return {"certificates_logged": len(rows), "distinct_names": sorted(names)[:500],
            "issuers": dict(sorted(issuers.items(), key=lambda kv: -kv[1])[:10]), "query_url": url}


def parse_certificate(der: bytes) -> dict[str, Any]:
    cert = x509.load_der_x509_certificate(der)

    def _name(n: x509.Name) -> str:
        return ", ".join(f"{a.oid._name}={a.value}" for a in n)

    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        sans = san.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    not_after = cert.not_valid_after_utc
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return {
        "subject": _name(cert.subject), "common_name": cn[0].value if cn else None, "issuer": _name(cert.issuer),
        "serial": format(cert.serial_number, "x"),
        "not_before": cert.not_valid_before_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "not_after": not_after.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "days_remaining": (not_after - datetime.now(timezone.utc)).days,
        "sans": sans[:100], "sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "signature_algorithm": cert.signature_algorithm_oid._name,
    }


def _tls_step(domain: str) -> dict[str, Any]:
    raw = netguard.tls_certificate(domain, 443)
    info = parse_certificate(raw["der"])
    trusted, reason = netguard.trust_check(domain, 443, raw["ip"])
    return {**info, "tls_version": raw["tls_version"], "cipher": raw["cipher"], "peer_ip": raw["ip"],
            "chain_trusted": trusted, "trust_failure": reason}


def _http_step(domain: str) -> dict[str, Any]:
    resp = netguard.safe_fetch(f"https://{domain}/")
    title = None
    m = re.search(rb"<title[^>]*>(.*?)</title>", resp.body[:65536], re.I | re.S)
    if m:
        title = re.sub(r"\s+", " ", m.group(1).decode("utf-8", "replace")).strip()[:200]
    return {
        "final_url": resp.url, "status": resp.status, "peer_ip": resp.peer_ip,
        "server": resp.headers.get("server"), "content_type": resp.headers.get("content-type"),
        "title": title, "redirect_chain": resp.redirect_chain,
        "security_headers": {h: resp.headers.get(h) for h in SECURITY_HEADERS},
        "missing_security_headers": [h for h in SECURITY_HEADERS if h not in resp.headers],
        "body_bytes_read": len(resp.body), "body_truncated": resp.truncated,
    }


# --- handler -------------------------------------------------------------------

@operations.register("domain_investigation")
def run(ctx: operations.OperationContext) -> dict[str, Any]:
    domain = ctx.target
    active = bool(ctx.params.get("active"))
    steps: list[dict[str, Any]] = []
    created: list[str] = []

    with db() as c:
        dom_ent = upsert_entity(c, "domain", domain)
        case_ent = None
        if ctx.case_id:
            ref = c.execute("SELECT ref, name FROM cases WHERE id=?", (ctx.case_id,)).fetchone()
            case_ent = upsert_entity(c, "case", ref["ref"], ref["name"])
            link(c, case_ent, dom_ent, "investigates", f"operation {ctx.ref}")

    def record(step: str, fn, *, source: str, source_url: str | None, confidence: str, title: str, summarise, relate=None):
        ctx.check_cancel()
        started = utcnow()
        try:
            data = fn()
        except GhostError as exc:
            steps.append({"step": step, "status": "failed", "error": exc.message, "code": exc.code, "at": started})
            return None
        except Exception as exc:
            steps.append({"step": step, "status": "failed", "error": f"{type(exc).__name__}: {exc}", "code": "internal", "at": started})
            return None
        with db() as c:
            f = findings.add_finding(c, kind=step, title=title, summary=summarise(data), data=data, source=source,
                                     source_url=source_url, retrieved_at=utcnow(), confidence=confidence,
                                     case_id=ctx.case_id, operation_id=ctx.id)
            if relate:
                relate(c, f["ref"], data)
        created.append(f["ref"])
        steps.append({"step": step, "status": "ok", "finding": f["ref"], "at": started})
        return data

    # DNS ------------------------------------------------------------------------
    ctx.check_cancel()
    started = utcnow()
    try:
        records, errs = _dns_step(domain)
    except Exception as exc:
        records, errs = {}, [f"{type(exc).__name__}: {exc}"]
    if records:
        def dns_rel(c, fref, data):
            for rtype in ("A", "AAAA"):
                for ip in data["records"].get(rtype, []):
                    link(c, dom_ent, upsert_entity(c, "ip", ip), "resolves_to", "DNS (system resolver)", fref)
            for ns in data["records"].get("NS", []):
                link(c, dom_ent, upsert_entity(c, "domain", ns.rstrip(".").lower()), "uses_nameserver", "DNS (system resolver)", fref)
            for mx in data["records"].get("MX", []):
                host = mx.split()[-1].rstrip(".").lower()
                if not host:  # RFC 7505 "null MX" (0 .) means "no mail" — not an entity
                    continue
                link(c, dom_ent, upsert_entity(c, "domain", host), "mail_handled_by", "DNS (system resolver)", fref)
        with db() as c:
            f = findings.add_finding(
                c, kind="dns", title=f"DNS records — {domain}",
                summary=", ".join(f"{k}×{len(v)}" for k, v in records.items()),
                data={"records": records, "errors": errs}, source="DNS (system resolver)",
                retrieved_at=utcnow(), confidence="high", case_id=ctx.case_id, operation_id=ctx.id)
            dns_rel(c, f["ref"], {"records": records})
        created.append(f["ref"])
        steps.append({"step": "dns", "status": "ok", "finding": f["ref"], "at": started, "warnings": errs})
    else:
        steps.append({"step": "dns", "status": "failed" if errs else "empty", "at": started,
                      "error": "; ".join(errs) if errs else "No DNS records returned (domain may not exist)"})

    # RDAP -----------------------------------------------------------------------
    def rdap_rel(c, fref, data):
        for ns in data.get("nameservers", []):
            if ns:
                link(c, dom_ent, upsert_entity(c, "domain", ns), "uses_nameserver", "RDAP", fref)
    record("rdap", lambda: _rdap_step(domain), source="RDAP (rdap.org bootstrap)", source_url=f"https://rdap.org/domain/{domain}",
           confidence="medium", title=f"Registration data — {domain}",
           summarise=lambda d: f"Registrar: {d.get('registrar') or 'unknown'}; registered {d.get('registered') or 'n/a'}; expires {d.get('expires') or 'n/a'}",
           relate=rdap_rel)

    # CT -------------------------------------------------------------------------
    def ct_rel(c, fref, data):
        for name in data["distinct_names"][:50]:
            if name != domain:
                link(c, dom_ent, upsert_entity(c, "domain", name), "ct_logged_name", "crt.sh (Certificate Transparency)", fref)
    record("certificate_transparency", lambda: _ct_step(domain), source="crt.sh (Certificate Transparency)",
           source_url=f"https://crt.sh/?q=%25.{domain}", confidence="medium", title=f"Certificate transparency — {domain}",
           summarise=lambda d: f"{d['certificates_logged']} logged certificates, {len(d['distinct_names'])} distinct names",
           relate=ct_rel)

    if active:
        def tls_rel(c, fref, data):
            cert_ent = upsert_entity(c, "certificate", data["sha256"], f"CERT {data['sha256'][:12]}",
                                     {"subject": data["subject"], "issuer": data["issuer"], "not_after": data["not_after"]})
            link(c, dom_ent, cert_ent, "presents_certificate", "TLS handshake", fref)
            for san in data["sans"][:25]:
                if san != domain and not san.startswith("*"):
                    link(c, cert_ent, upsert_entity(c, "domain", san.lower()), "covers_name", "TLS handshake (SAN)", fref)
            ip_ent = upsert_entity(c, "ip", data["peer_ip"])
            link(c, dom_ent, ip_ent, "served_from", "TLS handshake", fref)
        record("tls", lambda: _tls_step(domain), source="Direct TLS handshake", source_url=f"tls://{domain}:443",
               confidence="high", title=f"TLS certificate — {domain}",
               summarise=lambda d: f"{d['common_name']} issued by {d['issuer'].split('CN=')[-1][:60]}; {d['days_remaining']}d remaining; chain {'trusted' if d['chain_trusted'] else 'NOT trusted'}",
               relate=tls_rel)
        record("http", lambda: _http_step(domain), source="Direct HTTPS request", source_url=f"https://{domain}/",
               confidence="high", title=f"HTTP response — {domain}",
               summarise=lambda d: f"HTTP {d['status']} from {d['peer_ip']}; server {d.get('server') or 'n/a'}; {len(d['missing_security_headers'])} security headers absent")
    else:
        steps.append({"step": "tls", "status": "skipped", "error": "Active check — requires declared scope and authorisation"})
        steps.append({"step": "http", "status": "skipped", "error": "Active check — requires declared scope and authorisation"})

    ok = [s for s in steps if s["status"] == "ok"]
    if not ok:
        raise GhostError("No investigation step produced data: " + "; ".join(f"{s['step']}: {s.get('error')}" for s in steps if s.get("error")), 502, "no_data")
    return {"domain": domain, "active": active, "steps": steps, "findings": created,
            "completed_at": utcnow(), "summary": f"{len(ok)} of {len(steps)} steps returned data"}

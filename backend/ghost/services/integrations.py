"""Integrations: let a non-technical user set provider keys / AI endpoint from the UI instead of editing `.env`.

Security properties
* Only a fixed whitelist of settings can be written; every value is validated (no newlines/NULs, strict charset, URL shape).
* Secrets are write-only: the API reports `configured` plus the last 4 characters, never the value.
* Requests are protected by the API's Host / Origin guards (a web page on another origin cannot call this).
* The .env file is written atomically and (best effort) restricted to the current user.
"""
from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..config import get_settings
from ..db import db
from ..errors import GhostError, Unavailable
from . import audit, system

# env name -> (settings attribute, label, kind, help)
FIELDS: dict[str, tuple[str, str, str, str]] = {
    "VIRUSTOTAL_API_KEY": ("vt_api_key", "VirusTotal API key", "secret", "Free key: create an account at virustotal.com, then profile → API key."),
    "ABUSEIPDB_API_KEY": ("abuseipdb_api_key", "AbuseIPDB API key", "secret", "Free key: create an account at abuseipdb.com, then Account → API."),
    "IPINFO_TOKEN": ("ipinfo_token", "ipinfo.io token", "secret", "Optional. ipwho.is already provides geolocation without a key."),
    "GHOST_AI_BASE_URL": ("ai_base_url", "AI endpoint URL", "url", "OpenAI-compatible base URL, e.g. http://localhost:11434/v1 for Ollama."),
    "GHOST_AI_MODEL": ("ai_model", "AI model name", "text", "e.g. llama3.1 (must exist on that endpoint)."),
    "GHOST_AI_API_KEY": ("ai_api_key", "AI API key", "secret", "Only for hosted providers. Leave empty for a local model."),
    "GHOST_TSHARK_PATH": ("tshark_path", "TShark path", "path", "Only if TShark is installed somewhere unusual."),
}
_SECRET_RE = re.compile(r"^[A-Za-z0-9_\-\.=+/]{8,300}$")
_TEXT_RE = re.compile(r"^[A-Za-z0-9_\-\.:/@+ ]{1,120}$")


def _validate(env: str, value: str) -> str:
    kind = FIELDS[env][2]
    label = FIELDS[env][1]
    v = value.strip()
    if not v or any(c in v for c in "\r\n\x00"):
        raise GhostError(f"{label}: value must be a single non-empty line", 422, "validation")
    if kind == "secret" and not _SECRET_RE.match(v):
        raise GhostError(f"{label}: expected 8-300 characters (letters, digits and _-.=+/ only) — check you copied the whole key without spaces", 422, "validation")
    if kind == "text" and not _TEXT_RE.match(v):
        raise GhostError(f"{label}: contains characters that are not allowed", 422, "validation")
    if kind == "url":
        parts = urlsplit(v)
        if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password or len(v) > 300:
            raise GhostError(f"{label}: must be an http:// or https:// URL without credentials", 422, "validation")
    if kind == "path" and (len(v) > 400 or not Path(v).is_file()):
        raise GhostError(f"{label}: file not found on this computer", 422, "validation")
    return v


def status() -> list[dict[str, Any]]:
    out = []
    for env, (_attr, label, kind, help_) in FIELDS.items():
        val = os.environ.get(env) or ""
        row: dict[str, Any] = {"env": env, "label": label, "kind": kind, "help": help_, "configured": bool(val)}
        if val:
            row["hint"] = ("••••" + val[-4:]) if kind == "secret" else val
        out.append(row)
    return out


def _apply_to_settings() -> None:
    s = get_settings()
    for env, (attr, *_rest) in FIELDS.items():
        setattr(s, attr, os.environ.get(env) or None)


def _line(key: str, value: str) -> str:
    return f'{key}="{value}"' if any(c in value for c in " #'\"") else f"{key}={value}"


def save(values: dict[str, Any]) -> list[dict[str, Any]]:
    """Validate everything first, then write once. A null/empty value removes the setting."""
    unknown = [k for k in values if k not in FIELDS]
    if unknown:
        raise GhostError(f"Unknown setting(s): {', '.join(unknown)}", 422, "validation")
    clean: dict[str, str | None] = {}
    for env, raw in values.items():
        if raw is None or (isinstance(raw, str) and not raw.strip()):
            clean[env] = None
        elif not isinstance(raw, str):
            raise GhostError(f"{FIELDS[env][1]}: must be text", 422, "validation")
        else:
            clean[env] = _validate(env, raw)
    path = get_settings().env_file
    lines = path.read_text(encoding="utf-8").splitlines() if path.is_file() else []
    pending = dict(clean)
    out: list[str] = []
    for line in lines:
        m = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", line)
        if m and m.group(1) in pending:
            val = pending.pop(m.group(1))
            if val is not None:
                out.append(_line(m.group(1), val))
            continue
        out.append(line)
    additions = [(k, v) for k, v in pending.items() if v is not None]
    if additions:
        if out and out[-1].strip():
            out.append("")
        out.append("# --- saved from the web UI (Settings → Integrations) ---")
        out += [_line(k, v) for k, v in additions]
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".env.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join(out) + "\n")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass  # not supported on every filesystem (e.g. some Windows / WSL mounts)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    for env, val in clean.items():
        if val is None:
            os.environ.pop(env, None)
        else:
            os.environ[env] = val
    _apply_to_settings()
    with db() as c:
        audit.record(c, "settings.integrations", detail={"changed": sorted(k for k, v in clean.items() if v is not None),
                                                         "removed": sorted(k for k, v in clean.items() if v is None)})
    return status()


def test(target: str) -> dict[str, Any]:
    """Make one harmless request to confirm a key/endpoint works. Never echoes the secret."""
    from . import ai, intel
    system.ensure_online("integration test")
    if target == "ai":
        return ai.ping()
    probes = {"virustotal": (intel.query_virustotal, "domain", "example.com", "VIRUSTOTAL_API_KEY"),
              "abuseipdb": (intel.query_abuseipdb, "ip", "8.8.8.8", "ABUSEIPDB_API_KEY"),
              "ipinfo": (intel.query_ipinfo, "ip", "8.8.8.8", "IPINFO_TOKEN")}
    if target not in probes:
        raise GhostError("target must be one of virustotal, abuseipdb, ipinfo, ai", 422, "validation")
    fn, typ, value, env = probes[target]
    if not os.environ.get(env):
        raise Unavailable(f"No key saved for {FIELDS[env][1]} yet.", "not_configured")
    res = fn(typ, value)
    st = res["status"]
    msg = {"ok": "Key accepted — the provider answered normally.",
           "not_found": "Key accepted (the provider had no record for the test item).",
           "auth_error": "The provider REJECTED this key (HTTP 401/403). Check you copied the whole key.",
           "rate_limited": "Key looks valid but the provider is rate-limiting you right now (free tier). Try again later."}.get(st, res.get("error") or f"Provider returned {st}")
    return {"ok": st in ("ok", "not_found", "rate_limited"), "status": st, "message": msg, "http_status": res.get("http_status")}

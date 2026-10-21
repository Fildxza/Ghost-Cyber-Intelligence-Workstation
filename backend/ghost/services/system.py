"""System status derived from real checks: database, tools, providers, worker, vault, field mode."""
from __future__ import annotations

import shutil
import subprocess
import time
import secrets
from datetime import datetime, timezone
from typing import Any

from .. import __version__
from ..config import get_settings
from ..db import db, get_setting, set_setting, utcnow
from ..errors import GhostError, Unavailable
from . import audit

_PROCESS_STARTED = datetime.now(timezone.utc)
SESSION_ID = f"OPS-{_PROCESS_STARTED:%Y%m%d}-{secrets.token_hex(2).upper()}"


def field_mode() -> bool:
    with db() as c:
        return get_setting(c, "field_mode", "0") == "1"


def set_field_mode(enabled: bool) -> bool:
    with db() as c:
        set_setting(c, "field_mode", "1" if enabled else "0")
        audit.record(c, "settings.field_mode", detail={"enabled": enabled})
    return enabled


def ensure_online(what: str) -> None:
    """Refuse operations that would touch the network while Field Mode is active."""
    if field_mode():
        raise Unavailable(f"Field Mode is active — {what} requires outbound network access. Disable Field Mode in System Settings.", "field_mode")


def _probe(path: str | None, args: list[str], timeout: int = 8) -> dict[str, Any]:
    if not path:
        return {"installed": False, "path": None, "version": None}
    try:
        out = subprocess.run([path, *args], capture_output=True, text=True, timeout=timeout, shell=False)
        first = (out.stdout or out.stderr).strip().splitlines()
        return {"installed": out.returncode == 0, "path": path, "version": first[0] if first else None}
    except (OSError, subprocess.SubprocessError) as exc:
        return {"installed": False, "path": path, "version": None, "error": f"{type(exc).__name__}: {exc}"}


def find_tool(name: str, configured: str | None) -> str | None:
    if configured:
        return configured if shutil.which(configured) or _exists(configured) else None
    return shutil.which(name)


def _exists(p: str) -> bool:
    import os
    return os.path.isfile(p)


def tools() -> list[dict[str, Any]]:
    s = get_settings()
    tshark = _probe(find_tool("tshark", s.tshark_path), ["--version"])
    zeek = _probe(find_tool("zeek", s.zeek_path), ["--version"])
    return [
        {"id": "builtin-pcap", "name": "Built-in PCAP parser", "installed": True, "path": "ghost.services.pcap",
         "version": "pcap + pcapng, Ethernet/IPv4/IPv6/TCP/UDP/DNS", "role": "Fallback capture analysis (always available)",
         "install_hint": None},
        {"id": "tshark", "name": "TShark", **tshark, "role": "Deep protocol dissection for PCAP analysis",
         "install_hint": "Windows: install Wireshark (includes TShark) or set GHOST_TSHARK_PATH. Ubuntu/WSL: sudo apt install tshark"},
        {"id": "zeek", "name": "Zeek", **zeek, "role": "Network security monitor logs (detected only — not yet used for analysis)",
         "install_hint": "Ubuntu/WSL: https://docs.zeek.org/en/master/install.html or set GHOST_ZEEK_PATH"},
    ]


PROVIDER_INFO = [
    {"id": "virustotal", "name": "VirusTotal", "env": "VIRUSTOTAL_API_KEY", "types": ["domain", "ip", "url", "hash"], "needs_key": True, "reputation": True,
     "sends_to": "virustotal.com", "setup": "Create a free key at virustotal.com and set VIRUSTOTAL_API_KEY in .env"},
    {"id": "abuseipdb", "name": "AbuseIPDB", "env": "ABUSEIPDB_API_KEY", "types": ["ip"], "needs_key": True, "reputation": True,
     "sends_to": "abuseipdb.com", "setup": "Create a free key at abuseipdb.com and set ABUSEIPDB_API_KEY in .env"},
    {"id": "ipinfo", "name": "ipinfo.io (geolocation)", "env": "IPINFO_TOKEN", "types": ["ip"], "needs_key": True, "reputation": False,
     "sends_to": "ipinfo.io", "setup": "Create a token at ipinfo.io and set IPINFO_TOKEN in .env. Provides map coordinates."},
    {"id": "ipwho", "name": "ipwho.is (geolocation + owner)", "env": "", "types": ["ip"], "needs_key": False, "reputation": False,
     "sends_to": "ipwho.is", "setup": "No key needed. Provides map coordinates and network owner."},
    {"id": "internetdb", "name": "Shodan InternetDB (exposure)", "env": "", "types": ["ip"], "needs_key": False, "reputation": False,
     "sends_to": "internetdb.shodan.io", "setup": "No key needed. Open ports, CPEs, associated CVEs. Exposure is not maliciousness."},
    {"id": "circl-hashlookup", "name": "CIRCL hashlookup (known files)", "env": "", "types": ["hash"], "needs_key": False, "reputation": False,
     "sends_to": "hashlookup.circl.lu", "setup": "No key needed. A hit means a known file; a miss means nothing."},
    {"id": "dns-posture", "name": "DNS posture (SPF / DMARC / CAA)", "env": "", "types": ["domain"], "needs_key": False, "reputation": False,
     "sends_to": "your configured DNS resolver only", "setup": "No key needed; uses your DNS resolver."},
]


def providers() -> list[dict[str, Any]]:
    from . import intel  # local import: intel depends on this module
    s = get_settings()
    return [{**info, "configured": bool(intel.PROVIDERS[info["id"]][0](s))} for info in PROVIDER_INFO]


def ai_status() -> dict[str, Any]:
    s = get_settings()
    configured = bool(s.ai_base_url and s.ai_model)
    return {"configured": configured, "base_url": s.ai_base_url if configured else None, "model": s.ai_model,
            "setup": "Set GHOST_AI_BASE_URL (e.g. http://localhost:11434/v1 for Ollama) and GHOST_AI_MODEL in .env. GHOST_AI_API_KEY is optional for local models."}


def vault_status() -> dict[str, Any]:
    s = get_settings()
    return {"encryption": "enabled" if s.vault_passphrase else "disabled",
            "algorithm": "AES-256-GCM, scrypt-derived key" if s.vault_passphrase else None,
            "note": "New evidence is encrypted at rest." if s.vault_passphrase
            else "Evidence is stored unencrypted. Set GHOST_VAULT_PASSPHRASE to encrypt newly registered evidence."}


def database_status() -> dict[str, Any]:
    t0 = time.perf_counter()
    try:
        with db() as c:
            version = c.execute("PRAGMA user_version").fetchone()[0]
            c.execute("SELECT 1").fetchone()
        return {"ok": True, "engine": "sqlite", "schema_version": version,
                "latency_ms": round((time.perf_counter() - t0) * 1000, 2), "path": str(get_settings().db_path)}
    except Exception as exc:  # reported, not swallowed: the status endpoint is the report
        return {"ok": False, "engine": "sqlite", "error": f"{type(exc).__name__}: {exc}"}


def last_successful_operation() -> dict[str, Any] | None:
    with db() as c:
        row = c.execute("SELECT ref, kind, target, finished_at FROM operations WHERE status='completed' ORDER BY finished_at DESC LIMIT 1").fetchone()
        return dict(row) if row else None


def status() -> dict[str, Any]:
    from . import operations
    with db() as c:
        ws_id = c.execute("SELECT value FROM settings WHERE key='active_workspace'").fetchone()
    return {
        "version": __version__,
        "session_id": SESSION_ID,
        "analyst": audit.current_actor(),
        "server_time": utcnow(),
        "started_at": _PROCESS_STARTED.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "api": {"ok": True},
        "database": database_status(),
        "worker": operations.worker_status(),
        "tools": tools(),
        "providers": providers(),
        "ai": ai_status(),
        "vault": vault_status(),
        "field_mode": field_mode(),
        "last_operation": last_successful_operation(),
        "active_workspace_id": int(ws_id["value"]) if ws_id else None,
    }


def require(condition: bool, message: str) -> None:
    if not condition:
        raise GhostError(message, 400)

"""Outbound-network safety: SSRF, DNS-rebinding, private-address and unsafe-redirect protection.

Design
------
* A hostname is resolved ONCE by us; every returned address must be globally routable.
* The request is then made to the *validated IP literal* (Host header + TLS SNI keep the
  hostname), so a second, attacker-influenced DNS answer can never be used (anti-rebinding).
* Redirects are never followed automatically: each hop is re-parsed, re-resolved and
  re-validated, and the scheme/port allow-list is re-applied.
* Response bodies are streamed with a hard byte cap.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import ssl
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urljoin, urlsplit

import httpx

from .config import get_settings
from .errors import GhostError

ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {80, 443, 8080, 8443}
_HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z][a-z0-9-]{0,62}$")


class BlockedTarget(GhostError):
    def __init__(self, reason: str):
        super().__init__(f"Target blocked by network safety policy: {reason}", 400, "blocked_target")


def normalise_domain(value: str) -> str:
    """Validate and normalise a domain name (IDNA -> ASCII, lower-case, no trailing dot)."""
    v = (value or "").strip().lower().rstrip(".")
    if not v:
        raise GhostError("Domain is required", 422, "validation")
    if "://" in v or "/" in v or "@" in v or " " in v or ":" in v:
        raise GhostError("Enter a bare domain name (no scheme, path, port or credentials)", 422, "validation")
    try:
        v = v.encode("idna").decode("ascii")
    except UnicodeError:
        raise GhostError("Domain is not valid IDNA", 422, "validation")
    if not _HOST_RE.match(v):
        raise GhostError(f"'{value}' is not a valid fully-qualified domain name", 422, "validation")
    return v


def is_public_ip(ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    addr = ipaddress.ip_address(ip) if isinstance(ip, str) else ip
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return addr.is_global and not addr.is_multicast


def resolve_public(host: str, port: int = 443) -> list[str]:
    """Resolve *host* and return only after verifying every address is public."""
    settings = get_settings()
    try:
        ipaddress.ip_address(host)
        infos_ips = [host]
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise GhostError(f"DNS resolution failed for {host}: {exc}", 502, "dns_failure")
        infos_ips = sorted({i[4][0] for i in infos})
    if not infos_ips:
        raise GhostError(f"{host} has no address records", 502, "dns_failure")
    if not settings.allow_private_targets:
        for ip in infos_ips:
            if not is_public_ip(ip):
                raise BlockedTarget(f"{host} resolves to non-public address {ip}")
    return infos_ips


def validate_url(url: str) -> tuple[str, str, int, str]:
    """Return (scheme, host, port, path+query) for an acceptable URL, else raise BlockedTarget."""
    parts = urlsplit(url)
    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise BlockedTarget(f"scheme '{parts.scheme}' is not allowed")
    if parts.username or parts.password:
        raise BlockedTarget("credentials in URLs are not allowed")
    host = (parts.hostname or "").lower()
    if not host:
        raise BlockedTarget("URL has no host")
    port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
    if port not in ALLOWED_PORTS and not get_settings().allow_private_targets:
        raise BlockedTarget(f"port {port} is not in the allow-list {sorted(ALLOWED_PORTS)}")
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return parts.scheme.lower(), host, port, path


@dataclass
class SafeResponse:
    url: str
    status: int
    headers: dict[str, str]
    body: bytes
    redirect_chain: list[dict]
    peer_ip: str
    truncated: bool


def safe_fetch(url: str, *, method: str = "GET", extra_headers: dict[str, str] | None = None,
               want_body: bool = True, max_bytes: int | None = None) -> SafeResponse:
    """SSRF-hardened fetch (see module docstring)."""
    settings = get_settings()
    cap = max_bytes or settings.max_response_bytes
    chain: list[dict] = []
    current = url
    for hop in range(settings.max_redirects + 1):
        scheme, host, port, path = validate_url(current)
        ips = resolve_public(host, port)
        ip = ips[0]
        literal = f"[{ip}]" if ":" in ip else ip
        netloc = literal if port in (80, 443) else f"{literal}:{port}"
        target = f"{scheme}://{netloc}{path}"
        headers = {"Host": host if port in (80, 443) else f"{host}:{port}",
                   "User-Agent": "Fidx-Ghost/0.1 (+passive-osint)", "Accept": "*/*",
                   **(extra_headers or {})}
        ext = {"sni_hostname": host} if scheme == "https" else {}
        try:
            with httpx.Client(timeout=settings.http_timeout, follow_redirects=False, verify=True) as client:
                with client.stream(method, target, headers=headers, extensions=ext) as resp:
                    body = b""
                    truncated = False
                    if want_body:
                        for chunk in resp.iter_bytes():
                            body += chunk
                            if len(body) >= cap:
                                body = body[:cap]
                                truncated = True
                                break
                    status = resp.status_code
                    resp_headers = {k.lower(): v for k, v in resp.headers.items()}
        except httpx.ConnectTimeout:
            raise GhostError(f"Connection to {host} timed out", 504, "timeout")
        except httpx.ReadTimeout:
            raise GhostError(f"Reading from {host} timed out", 504, "timeout")
        except httpx.HTTPError as exc:
            raise GhostError(f"HTTP request to {host} failed: {type(exc).__name__}: {exc}", 502, "http_error")
        if status in (301, 302, 303, 307, 308) and "location" in resp_headers:
            nxt = urljoin(current, resp_headers["location"])
            chain.append({"url": current, "status": status, "location": nxt})
            current = nxt
            continue
        return SafeResponse(current, status, resp_headers, body, chain, ip, truncated)
    raise GhostError(f"Too many redirects (>{settings.max_redirects})", 502, "redirect_loop")


def tls_certificate(host: str, port: int = 443) -> dict:
    """Perform a TLS handshake against a validated public IP and return the peer certificate."""
    settings = get_settings()
    ips = resolve_public(host, port)
    ip = ips[0]
    ctx = ssl.create_default_context()
    ctx.check_hostname = False  # we report validity ourselves rather than failing the lookup
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=settings.http_timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
                version = tls.version()
                cipher = tls.cipher()
    except (socket.timeout, TimeoutError):
        raise GhostError(f"TLS connection to {host}:{port} timed out", 504, "timeout")
    except (OSError, ssl.SSLError) as exc:
        raise GhostError(f"TLS handshake with {host}:{port} failed: {exc}", 502, "tls_error")
    return {"der": der, "ip": ip, "tls_version": version, "cipher": cipher[0] if cipher else None}


def trust_check(host: str, port: int, ip: str) -> tuple[bool, str | None]:
    """Second handshake with full verification so we can say whether the chain is trusted."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((ip, port), timeout=get_settings().http_timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host):
                return True, None
    except ssl.SSLCertVerificationError as exc:
        return False, exc.verify_message
    except (OSError, ssl.SSLError) as exc:
        return False, str(exc)


def any_blocked(ips: Iterable[str]) -> list[str]:
    return [ip for ip in ips if not is_public_ip(ip)]

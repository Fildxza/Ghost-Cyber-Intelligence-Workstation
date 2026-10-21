"""Minimal stub DNS client (UDP with TCP fallback) that asks the machine's configured resolver.

Only the resolver the user already trusts is contacted — the target domain cannot steer where
queries go. Responses are accepted only when the transaction id, source address and echoed
question match (basic anti-spoofing); every parse is bounds-checked.
"""
from __future__ import annotations

import ctypes
import os
import secrets
import socket
import struct
import sys

from . import dnswire
from .errors import GhostError, Unavailable


class NXDomain(GhostError):
    def __init__(self, name: str):
        super().__init__(f"{name} does not exist (NXDOMAIN)", 404, "nxdomain")


def _windows_servers() -> list[str]:
    class IPAddrString(ctypes.Structure):
        pass

    IPAddrString._fields_ = [("Next", ctypes.POINTER(IPAddrString)), ("IpAddress", ctypes.c_char * 16),
                             ("IpMask", ctypes.c_char * 16), ("Context", ctypes.c_ulong)]

    class FixedInfo(ctypes.Structure):
        _fields_ = [("HostName", ctypes.c_char * 132), ("DomainName", ctypes.c_char * 132),
                    ("CurrentDnsServer", ctypes.POINTER(IPAddrString)), ("DnsServerList", IPAddrString),
                    ("NodeType", ctypes.c_uint), ("ScopeId", ctypes.c_char * 260), ("EnableRouting", ctypes.c_uint),
                    ("EnableProxy", ctypes.c_uint), ("EnableDns", ctypes.c_uint)]

    fn = ctypes.windll.iphlpapi.GetNetworkParams  # type: ignore[attr-defined]
    size = ctypes.c_ulong(0)
    fn(None, ctypes.byref(size))
    buf = ctypes.create_string_buffer(size.value)
    if fn(buf, ctypes.byref(size)) != 0:
        return []
    info = ctypes.cast(buf, ctypes.POINTER(FixedInfo)).contents
    out, node = [], info.DnsServerList
    while True:
        ip = node.IpAddress.decode("ascii", "ignore").strip("\x00")
        if ip:
            out.append(ip)
        if not node.Next:
            break
        node = node.Next.contents
    return out


def nameservers() -> list[str]:
    override = os.environ.get("GHOST_DNS_SERVER")
    if override:
        return [s.strip() for s in override.split(",") if s.strip()]
    servers: list[str] = []
    try:
        if sys.platform == "win32":
            servers = _windows_servers()
        elif os.path.isfile("/etc/resolv.conf"):
            for line in open("/etc/resolv.conf", encoding="utf-8", errors="ignore"):
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    servers.append(parts[1])
    except OSError:
        servers = []
    if not servers:
        raise Unavailable("No DNS resolver could be discovered. Set GHOST_DNS_SERVER (e.g. 1.1.1.1) in .env.", "no_resolver")
    return servers


def _exchange(server: str, packet: bytes, txid: int, timeout: float) -> bytes:
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(packet, (server, 53))
        while True:
            data, addr = s.recvfrom(4096)
            if addr[0] == server and len(data) >= 2 and struct.unpack(">H", data[:2])[0] == txid:
                return data


def _tcp(server: str, packet: bytes, timeout: float) -> bytes:
    with socket.create_connection((server, 53), timeout=timeout) as s:
        s.sendall(struct.pack(">H", len(packet)) + packet)
        hdr = s.recv(2)
        want = struct.unpack(">H", hdr)[0]
        data = b""
        while len(data) < want:
            chunk = s.recv(want - len(data))
            if not chunk:
                break
            data += chunk
        return data


def resolve(name: str, rtype: str, timeout: float = 3.0) -> list[str]:
    """Return record data strings; [] for NOERROR/NODATA; raises NXDomain / GhostError on failure."""
    last: Exception | None = None
    for server in nameservers():
        txid = secrets.randbits(16)
        packet = dnswire.build_query(name, rtype, txid)
        try:
            raw = _exchange(server, packet, txid, timeout)
            msg = dnswire.parse_response(raw)
            if msg["truncated"]:
                msg = dnswire.parse_response(_tcp(server, packet, timeout))
        except (socket.timeout, TimeoutError) as exc:
            last = exc
            continue
        except (OSError, ValueError, struct.error) as exc:
            last = exc
            continue
        if not msg["response"] or msg["id"] != txid or (msg["questions"] and msg["questions"][0][0] != name.rstrip(".").lower()):
            last = ValueError("response did not match the question")
            continue
        if msg["rcode"] == 3:
            raise NXDomain(name)
        if msg["rcode"] != 0:
            raise GhostError(f"DNS server {server} returned rcode {msg['rcode']} for {rtype} {name}", 502, "dns_failure")
        wanted = rtype
        return sorted(a["data"] for a in msg["answers"] if a["type"] == wanted)
    if isinstance(last, (socket.timeout, TimeoutError)):
        raise GhostError(f"DNS query for {rtype} {name} timed out", 504, "timeout")
    raise GhostError(f"DNS query for {rtype} {name} failed: {type(last).__name__ if last else 'no response'}", 502, "dns_failure")

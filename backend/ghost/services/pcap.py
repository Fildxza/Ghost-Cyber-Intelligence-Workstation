"""Network capture analysis.

Two engines feed one aggregator:
  * builtin — pure-Python pcap / pcapng reader (Ethernet, 802.1Q, Linux SLL, raw IP; IPv4/IPv6;
    TCP/UDP/ICMP; DNS queries and A/AAAA answers). Always available. Never executes anything.
  * tshark  — used automatically when installed (subprocess, argument list, no shell, timeout).

Uploaded captures are treated strictly as data: magic-byte validated, size-capped, stored under a
random name outside any served path, parsed with bounds checks.
"""
from __future__ import annotations

import hashlib
import ipaddress
import struct
import subprocess
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, Iterator

from .. import dnswire, netguard
from ..config import get_settings
from ..db import db, utcnow
from ..errors import GhostError, NotFound, Unavailable
from . import audit, cases, findings, operations, system
from .findings import link, upsert_entity

MAX_PACKETS = 3_000_000
PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
PORT_LABELS = {20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP",
               110: "POP3", 123: "NTP", 137: "NBNS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "TLS/HTTPS",
               445: "SMB", 465: "SMTPS", 587: "SMTP", 993: "IMAPS", 995: "POP3S", 1900: "SSDP", 3306: "MySQL", 3389: "RDP",
               5353: "mDNS", 5432: "PostgreSQL", 8080: "HTTP-ALT", 8443: "TLS/HTTPS"}
DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY"}


# --- file validation -------------------------------------------------------------

def sniff(path: Path) -> str:
    with path.open("rb") as fh:
        head = fh.read(4)
    if head in PCAP_MAGICS:
        return "pcap"
    if head == PCAPNG_MAGIC:
        return "pcapng"
    raise GhostError("Not a packet capture: expected a classic pcap or pcapng file (magic bytes did not match).", 415, "unsupported_type")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# --- readers ---------------------------------------------------------------------

def _read_pcap(fh: BinaryIO) -> Iterator[tuple[float, int, bytes]]:
    magic = fh.read(4)
    endian, res = PCAP_MAGICS[magic]
    header = fh.read(20)
    if len(header) < 20:
        raise GhostError("Truncated pcap global header", 422, "corrupt")
    _vmaj, _vmin, _tz, _sig, _snap, linktype = struct.unpack(endian + "HHiIII", header)
    while True:
        rec = fh.read(16)
        if len(rec) < 16:
            return
        ts_s, ts_f, incl, _orig = struct.unpack(endian + "IIII", rec)
        if incl > 262144 * 4:
            raise GhostError("Corrupt pcap: implausible packet length", 422, "corrupt")
        data = fh.read(incl)
        if len(data) < incl:
            return
        yield ts_s + ts_f * res, linktype, data


def _read_pcapng(fh: BinaryIO) -> Iterator[tuple[float, int, bytes]]:
    endian = "<"
    ifaces: list[tuple[int, float]] = []  # (linktype, resolution)
    while True:
        head = fh.read(8)
        if len(head) < 8:
            return
        btype = struct.unpack("<I", head[:4])[0] if head[:4] != PCAPNG_MAGIC else 0x0A0D0D0A
        if btype == 0x0A0D0D0A:
            blen_raw = head[4:8]
            body = fh.read(4)
            if len(body) < 4:
                return
            endian = "<" if struct.unpack("<I", body)[0] == 0x1A2B3C4D else ">"
            blen = struct.unpack(endian + "I", blen_raw)[0]
            fh.read(max(blen - 12, 0))
            ifaces = []
            continue
        btype, blen = struct.unpack(endian + "II", head)
        if blen < 12 or blen > 64 * 1024 * 1024:
            raise GhostError("Corrupt pcapng: implausible block length", 422, "corrupt")
        body = fh.read(blen - 8)
        if len(body) < blen - 8:
            return
        if btype == 1:  # Interface Description
            linktype = struct.unpack(endian + "H", body[:2])[0]
            res = 1e-6
            opts = body[8:-4]
            i = 0
            while i + 4 <= len(opts):
                code, olen = struct.unpack(endian + "HH", opts[i:i + 4])
                if code == 0:
                    break
                if code == 9 and olen >= 1:  # if_tsresol
                    v = opts[i + 4]
                    res = 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
                i += 4 + ((olen + 3) & ~3)
            ifaces.append((linktype, res))
        elif btype == 6 and len(body) >= 20:  # Enhanced Packet
            iface, th, tl, caplen, _orig = struct.unpack(endian + "IIIII", body[:20])
            if iface < len(ifaces):
                lt, res = ifaces[iface]
                yield ((th << 32) | tl) * res, lt, body[20:20 + caplen]
        elif btype == 3 and ifaces:  # Simple Packet (no timestamp)
            olen = struct.unpack(endian + "I", body[:4])[0]
            yield 0.0, ifaces[0][0], body[4:4 + olen]


# --- decoding --------------------------------------------------------------------

_dns_name = dnswire.read_name


def parse_dns(payload: bytes) -> dict[str, Any] | None:
    if len(payload) < 12:
        return None
    try:
        _id, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", payload[:12])
        off, queries, answers = 12, [], []
        for _ in range(min(qd, 8)):
            name, off = _dns_name(payload, off)
            qtype, _qclass = struct.unpack(">HH", payload[off:off + 4])
            off += 4
            queries.append((name, DNS_TYPES.get(qtype, str(qtype))))
        for _ in range(min(an, 32)):
            name, off = _dns_name(payload, off)
            rtype, _c, _ttl, rdlen = struct.unpack(">HHIH", payload[off:off + 10])
            off += 10
            rdata = payload[off:off + rdlen]
            if rtype == 1 and rdlen == 4:
                answers.append((name, "A", str(ipaddress.IPv4Address(rdata))))
            elif rtype == 28 and rdlen == 16:
                answers.append((name, "AAAA", str(ipaddress.IPv6Address(rdata))))
            elif rtype == 5:
                answers.append((name, "CNAME", _dns_name(payload, off)[0]))
            off += rdlen
        return {"response": bool(flags & 0x8000), "rcode": flags & 0xF, "queries": queries, "answers": answers}
    except (ValueError, struct.error, IndexError):
        return None


def decode_packet(linktype: int, data: bytes) -> dict[str, Any] | None:
    """Return a flat dict for IP packets, or {'l3': 'ARP'|...} for non-IP, or None if undecodable."""
    off = 0
    if linktype == 1:  # Ethernet
        if len(data) < 14:
            return None
        et = struct.unpack(">H", data[12:14])[0]
        off = 14
        while et in (0x8100, 0x88A8) and len(data) >= off + 4:
            et = struct.unpack(">H", data[off + 2:off + 4])[0]
            off += 4
    elif linktype == 113:  # Linux cooked
        if len(data) < 16:
            return None
        et = struct.unpack(">H", data[14:16])[0]
        off = 16
    elif linktype == 0:  # BSD loopback
        if len(data) < 4:
            return None
        af = struct.unpack("<I", data[:4])[0]
        et = 0x0800 if af == 2 else 0x86DD
        off = 4
    elif linktype in (101, 12, 14):  # raw IP
        et = 0x0800 if data and data[0] >> 4 == 4 else 0x86DD
    else:
        return {"l3": f"LINKTYPE_{linktype}"}
    if et == 0x0806:
        return {"l3": "ARP"}
    pkt: dict[str, Any] = {"len": len(data)}
    try:
        if et == 0x0800:
            if len(data) < off + 20:
                return None
            ihl = (data[off] & 0x0F) * 4
            proto = data[off + 9]
            pkt["src"], pkt["dst"] = str(ipaddress.IPv4Address(data[off + 12:off + 16])), str(ipaddress.IPv4Address(data[off + 16:off + 20]))
            l4 = off + ihl
            frag_offset = struct.unpack(">H", data[off + 6:off + 8])[0] & 0x1FFF
            if frag_offset:
                proto = -1
        elif et == 0x86DD:
            if len(data) < off + 40:
                return None
            nxt = data[off + 6]
            pkt["src"], pkt["dst"] = str(ipaddress.IPv6Address(data[off + 8:off + 24])), str(ipaddress.IPv6Address(data[off + 24:off + 40]))
            l4 = off + 40
            for _ in range(6):
                if nxt in (0, 43, 60) and len(data) >= l4 + 2:
                    nxt, l4 = data[l4], l4 + (data[l4 + 1] + 1) * 8
                else:
                    break
            proto = nxt
        else:
            return {"l3": f"0x{et:04x}"}
    except (struct.error, ValueError):
        return None
    pkt["proto"] = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6"}.get(proto, f"IP/{proto}" if proto >= 0 else "IP-FRAG")
    if proto in (6, 17) and len(data) >= l4 + 8:
        sport, dport = struct.unpack(">HH", data[l4:l4 + 4])
        pkt["sport"], pkt["dport"] = sport, dport
        if proto == 6 and len(data) >= l4 + 14:
            pkt["flags"] = data[l4 + 13]
            doff = (data[l4 + 12] >> 4) * 4
            payload = data[l4 + doff:]
        else:
            payload = data[l4 + 8:]
        if proto == 17 and 53 in (sport, dport):
            dns = parse_dns(payload)
            if dns:
                pkt["dns"] = dns
    return pkt


# --- aggregation -----------------------------------------------------------------

class Aggregator:
    def __init__(self) -> None:
        self.packets = 0
        self.bytes = 0
        self.first_ts: float | None = None
        self.last_ts: float | None = None
        self.l7: Counter[str] = Counter()
        self.l4: Counter[str] = Counter()
        self.non_ip: Counter[str] = Counter()
        self.convs: dict[tuple, dict[str, Any]] = {}
        self.tcp_ep: dict[tuple[str, int], dict[str, int]] = defaultdict(lambda: {"packets": 0, "bytes": 0, "syn_in": 0})
        self.dns_q: Counter[tuple[str, str]] = Counter()
        self.dns_answers: dict[str, set[str]] = defaultdict(set)
        self.dns_rcodes: Counter[int] = Counter()
        self.undecoded = 0

    def add(self, ts: float, pkt: dict[str, Any] | None) -> None:
        self.packets += 1
        if pkt is None:
            self.undecoded += 1
            return
        if "l3" in pkt:
            self.non_ip[pkt["l3"]] += 1
            self.l7[pkt["l3"]] += 1
            return
        ln = pkt["len"]
        self.bytes += ln
        if ts > 0:
            self.first_ts = ts if self.first_ts is None else min(self.first_ts, ts)
            self.last_ts = ts if self.last_ts is None else max(self.last_ts, ts)
        proto = pkt["proto"]
        self.l4[proto] += 1
        sp, dp = pkt.get("sport"), pkt.get("dport")
        label = pkt.get("l7") or (PORT_LABELS.get(dp) or PORT_LABELS.get(sp) or proto) if sp is not None else (pkt.get("l7") or proto)
        self.l7[label] += 1
        a, b = (pkt["src"], sp or 0), (pkt["dst"], dp or 0)
        key = (proto, *(sorted([a, b])))
        conv = self.convs.get(key)
        if conv is None:
            if len(self.convs) >= 200_000:
                conv = None
            else:
                conv = self.convs[key] = {"a": f"{key[1][0]}", "a_port": key[1][1], "b": f"{key[2][0]}", "b_port": key[2][1], "proto": proto,
                                         "service": label, "packets": 0, "bytes": 0, "first": ts, "last": ts}
        if conv:
            conv["packets"] += 1
            conv["bytes"] += ln
            if ts > 0:
                conv["first"] = min(conv["first"], ts) if conv["first"] else ts
                conv["last"] = max(conv["last"], ts)
        if proto == "TCP":
            ep = self.tcp_ep[(pkt["dst"], dp)]
            ep["packets"] += 1
            ep["bytes"] += ln
            if pkt.get("flags", 0) & 0x12 == 0x02:  # SYN without ACK → connection attempt to this endpoint
                ep["syn_in"] += 1
        dns = pkt.get("dns")
        if dns:
            if dns["response"]:
                self.dns_rcodes[dns["rcode"]] += 1
                for name, rtype, value in dns["answers"]:
                    self.dns_answers[name].add(f"{rtype} {value}")
            else:
                for name, qtype in dns["queries"]:
                    self.dns_q[(name, qtype)] += 1

    def add_dns_query(self, name: str, qtype: str) -> None:
        self.dns_q[(name.lower().rstrip("."), qtype)] += 1

    def result(self) -> dict[str, Any]:
        def iso(t):
            return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if t else None
        convs = sorted(self.convs.values(), key=lambda c: -c["bytes"])[:200]
        for c in convs:
            c["first"], c["last"] = iso(c["first"]), iso(c["last"])
        eps = sorted(({"ip": k[0], "port": k[1], "service": PORT_LABELS.get(k[1], "-"), **v} for k, v in self.tcp_ep.items()),
                     key=lambda e: -e["packets"])[:100]
        dns = [{"name": n, "type": t, "count": c, "answers": sorted(self.dns_answers.get(n, []))[:6]}
               for (n, t), c in self.dns_q.most_common(200)]
        domains = sorted({n for (n, _t) in self.dns_q if "." in n})
        ips: set[str] = set()
        for c in self.convs.values():
            for ip in (c["a"], c["b"]):
                try:
                    if netguard.is_public_ip(ip):
                        ips.add(ip)
                except ValueError:
                    continue
        return {
            "packets": self.packets, "ip_bytes": self.bytes, "undecoded_packets": self.undecoded,
            "start": iso(self.first_ts), "end": iso(self.last_ts),
            "duration_seconds": round(self.last_ts - self.first_ts, 3) if self.first_ts and self.last_ts else None,
            "protocols": [{"name": k, "packets": v} for k, v in self.l7.most_common(30)],
            "transport": [{"name": k, "packets": v} for k, v in self.l4.most_common()],
            "conversations": convs, "conversation_count": len(self.convs),
            "tcp_endpoints": eps, "dns_queries": dns, "dns_query_count": sum(self.dns_q.values()),
            "dns_rcodes": {str(k): v for k, v in self.dns_rcodes.items()},
            "indicators": {"domains": domains[:500], "public_ips": sorted(ips)[:500]},
        }


def analyse_builtin(path: Path, fmt: str, warnings: list[str], ctx: operations.OperationContext | None = None) -> dict[str, Any]:
    agg = Aggregator()
    with path.open("rb") as fh:
        reader = _read_pcap(fh) if fmt == "pcap" else _read_pcapng(fh)
        for i, (ts, lt, data) in enumerate(reader):
            if i >= MAX_PACKETS:
                warnings.append(f"Packet limit reached ({MAX_PACKETS:,}); remaining packets were not analysed.")
                break
            if ctx and i % 20000 == 0:
                ctx.check_cancel()
            agg.add(ts, decode_packet(lt, data))
    if agg.undecoded:
        warnings.append(f"{agg.undecoded} packet(s) could not be decoded (truncated or unsupported framing).")
    return agg.result()


def analyse_tshark(path: Path, tshark: str, warnings: list[str], ctx: operations.OperationContext | None = None) -> dict[str, Any]:
    fields = ["frame.time_epoch", "frame.len", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "_ws.col.Protocol",
              "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "tcp.flags", "dns.qry.name", "dns.qry.type", "ip.proto", "ipv6.nxt"]
    cmd = [tshark, "-n", "-r", str(path), "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f"]
    for f in fields:
        cmd += ["-e", f]
    timeout = get_settings().pcap_timeout
    agg = Aggregator()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=False, check=False)
    except subprocess.TimeoutExpired:
        raise GhostError(f"TShark exceeded the {timeout}s analysis timeout", 504, "timeout")
    except OSError as exc:
        raise Unavailable(f"TShark could not be started: {exc}", "tool_error")
    if proc.returncode != 0 and not proc.stdout:
        raise GhostError(f"TShark failed (exit {proc.returncode}): {proc.stderr.strip()[:300]}", 502, "tool_error")
    if proc.stderr.strip():
        warnings.append("TShark stderr: " + proc.stderr.strip()[:300])
    for i, line in enumerate(proc.stdout.splitlines()):
        if i >= MAX_PACKETS:
            warnings.append(f"Packet limit reached ({MAX_PACKETS:,}).")
            break
        p = (line.split("\t") + [""] * len(fields))[:len(fields)]
        ts_s, ln, s4, s6, d4, d6, l7, tsp, tdp, usp, udp, flags, qname, qtype, ip4p, ip6p = p
        src, dst = s4 or s6, d4 or d6
        if not src or not dst:
            agg.add(float(ts_s or 0), {"l3": l7 or "non-IP"})
            continue
        proto = "TCP" if tsp else "UDP" if usp else ("ICMP" if ip4p == "1" else "ICMPv6" if ip6p == "58" else "IP")
        pkt: dict[str, Any] = {"len": int(ln or 0), "src": src, "dst": dst, "proto": proto, "l7": l7}
        sport, dport = tsp or usp, tdp or udp
        if sport and dport:
            pkt["sport"], pkt["dport"] = int(sport), int(dport)
        if flags:
            try:
                pkt["flags"] = int(flags, 16)
            except ValueError:
                pass
        agg.add(float(ts_s or 0), pkt)
        if qname:
            agg.add_dns_query(qname, DNS_TYPES.get(int(qtype), qtype) if qtype.isdigit() else qtype)
        if ctx and i % 50000 == 0:
            ctx.check_cancel()
    return agg.result()


# --- upload + operation ------------------------------------------------------------

def store_upload(stream: BinaryIO, filename: str) -> dict[str, Any]:
    """Persist an uploaded capture under a random name; enforce size and magic-byte type."""
    s = get_settings()
    s.ensure_dirs()
    limit = s.max_upload_mb * 1024 * 1024
    dest = s.upload_dir / f"{uuid.uuid4().hex}.cap"
    size = 0
    h = hashlib.sha256()
    try:
        with dest.open("wb") as out:
            while chunk := stream.read(1 << 20):
                size += len(chunk)
                if size > limit:
                    raise GhostError(f"File exceeds the {s.max_upload_mb} MB upload limit", 413, "too_large")
                h.update(chunk)
                out.write(chunk)
        if size == 0:
            raise GhostError("Uploaded file is empty", 422, "validation")
        fmt = sniff(dest)
    except Exception:
        dest.unlink(missing_ok=True)
        raise
    safe_name = Path(filename or "capture").name[:120]
    return {"path": str(dest), "stored_name": dest.name, "filename": safe_name, "size": size, "sha256": h.hexdigest(), "format": fmt}


def start_analysis(upload: dict[str, Any], case_id: int | None = None, engine: str = "auto") -> dict[str, Any]:
    if engine not in ("auto", "builtin", "tshark"):
        raise GhostError("engine must be auto, builtin or tshark", 422, "validation")
    if engine == "tshark" and not system.find_tool("tshark", get_settings().tshark_path):
        Path(upload["path"]).unlink(missing_ok=True)
        raise Unavailable("TShark is not installed or not found. " + next(t["install_hint"] for t in system.tools() if t["id"] == "tshark"), "tool_missing")
    return operations.create("pcap_analysis", upload["filename"], case_id=case_id, params={"upload": upload, "engine": engine})


@operations.register("pcap_analysis")
def run(ctx: operations.OperationContext) -> dict[str, Any]:
    up = ctx.params["upload"]
    path = Path(up["path"])
    if not path.is_file():
        raise GhostError("The uploaded capture is no longer on disk", 410, "gone")
    warnings: list[str] = []
    recomputed = sha256_file(path)
    if recomputed != up["sha256"]:
        raise GhostError("Capture hash changed between upload and analysis — refusing to analyse", 409, "integrity")
    fmt = sniff(path)
    tshark = system.find_tool("tshark", get_settings().tshark_path)
    engine = ctx.params.get("engine", "auto")
    tool_errors: list[str] = []
    if engine in ("auto", "tshark") and tshark:
        try:
            analysis = analyse_tshark(path, tshark, warnings, ctx)
            used = "tshark"
        except GhostError as exc:
            if engine == "tshark":
                raise
            tool_errors.append(f"tshark: {exc.message}")
            warnings.append("TShark failed; fell back to the built-in parser (see tool errors).")
            analysis = analyse_builtin(path, fmt, warnings, ctx)
            used = "builtin"
    else:
        if engine == "auto":
            warnings.append("TShark is not installed — analysed with the built-in parser (reduced protocol coverage).")
        analysis = analyse_builtin(path, fmt, warnings, ctx)
        used = "builtin"
    if analysis["packets"] == 0:
        raise GhostError("The capture contains no packets", 422, "empty")
    with db() as c:
        file_ent = upsert_entity(c, "evidence", f"sha256:{up['sha256']}", up["filename"], {"kind": "pcap", "size": up["size"]})
        f = findings.add_finding(
            c, kind="pcap", title=f"Capture analysis — {up['filename']}",
            summary=f"{analysis['packets']:,} packets, {analysis['conversation_count']} conversations, {analysis['dns_query_count']} DNS queries ({used})",
            data={"file": {k: up[k] for k in ("filename", "size", "sha256", "format")}, "engine": used,
                  "protocols": analysis["protocols"][:10], "start": analysis["start"], "end": analysis["end"]},
            source=f"PCAP analysis ({used})", retrieved_at=utcnow(), confidence="high", case_id=ctx.case_id, operation_id=ctx.id)
        if ctx.case_id:
            case = c.execute("SELECT ref, name FROM cases WHERE id=?", (ctx.case_id,)).fetchone()
            link(c, upsert_entity(c, "case", case["ref"], case["name"]), file_ent, "contains_capture", f"operation {ctx.ref}", f["ref"])
        for name in analysis["indicators"]["domains"][:100]:
            link(c, file_ent, upsert_entity(c, "domain", name), "queried_in_capture", "PCAP DNS query", f["ref"])
        for ip in analysis["indicators"]["public_ips"][:100]:
            link(c, file_ent, upsert_entity(c, "ip", ip), "contacted_in_capture", "PCAP conversation", f["ref"])
    return {"file": {k: up[k] for k in ("filename", "size", "sha256", "format")}, "engine": used,
            "tshark_available": bool(tshark), "warnings": warnings, "tool_errors": tool_errors, "analysis": analysis,
            "finding": f["ref"], "note": "Protocol labels for the built-in engine are inferred from well-known ports, not deep inspection."
            if used == "builtin" else "Protocol labels come from TShark dissectors."}

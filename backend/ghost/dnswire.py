"""DNS wire-format helpers shared by the PCAP parser and the DNS client. Every read is bounds-checked."""
from __future__ import annotations

import ipaddress
import struct

TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 257: "CAA", 255: "ANY"}
TYPE_IDS = {v: k for k, v in TYPES.items()}


def read_name(buf: bytes, off: int) -> tuple[str, int]:
    """Decode a (possibly compressed) name. Returns (name, offset after the name in the original stream)."""
    labels: list[str] = []
    jumped, end, hops = False, off, 0
    while True:
        if off >= len(buf):
            raise ValueError("name runs past end of message")
        n = buf[off]
        if n == 0:
            if not jumped:
                end = off + 1
            break
        if n & 0xC0 == 0xC0:
            if off + 1 >= len(buf):
                raise ValueError("truncated compression pointer")
            hops += 1
            if hops > 64:
                raise ValueError("compression loop")
            if not jumped:
                end = off + 2
            jumped = True
            off = ((n & 0x3F) << 8) | buf[off + 1]
            continue
        if n > 63:
            raise ValueError("bad label length")
        off += 1
        if off + n > len(buf):
            raise ValueError("label runs past end of message")
        labels.append(buf[off:off + n].decode("ascii", "replace"))
        off += n
    return ".".join(labels).lower(), end


def build_query(name: str, qtype: str, txid: int) -> bytes:
    q = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.rstrip(".").split("."))
    return struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0) + q + b"\x00" + struct.pack(">HH", TYPE_IDS[qtype], 1)


def parse_rdata(buf: bytes, off: int, rtype: int, rdlen: int) -> str | None:
    rd = buf[off:off + rdlen]
    if len(rd) != rdlen:
        raise ValueError("rdata truncated")
    if rtype == 1 and rdlen == 4:
        return str(ipaddress.IPv4Address(rd))
    if rtype == 28 and rdlen == 16:
        return str(ipaddress.IPv6Address(rd))
    if rtype in (2, 5, 12):
        return read_name(buf, off)[0] + "."
    if rtype == 15:
        pref = struct.unpack(">H", rd[:2])[0]
        return f"{pref} {read_name(buf, off + 2)[0]}."
    if rtype == 16:
        parts, i = [], 0
        while i < len(rd):
            ln = rd[i]
            parts.append(rd[i + 1:i + 1 + ln].decode("utf-8", "replace"))
            i += 1 + ln
        return " ".join(f'"{p}"' for p in parts)
    if rtype == 6:
        mname, p = read_name(buf, off)
        rname, p = read_name(buf, p)
        serial, refresh, retry, expire, minimum = struct.unpack(">IIIII", buf[p:p + 20])
        return f"{mname}. {rname}. {serial} {refresh} {retry} {expire} {minimum}"
    if rtype == 257 and rdlen >= 2:
        flags, tl = rd[0], rd[1]
        return f'{flags} {rd[2:2 + tl].decode("ascii", "replace")} "{rd[2 + tl:].decode("utf-8", "replace")}"'
    return None


def parse_response(buf: bytes) -> dict:
    """Parse a full response into header fields, questions and answer records."""
    if len(buf) < 12:
        raise ValueError("short message")
    txid, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", buf[:12])
    off, questions, answers = 12, [], []
    for _ in range(qd):
        name, off = read_name(buf, off)
        qtype, _qc = struct.unpack(">HH", buf[off:off + 4])
        off += 4
        questions.append((name, qtype))
    for _ in range(an):
        name, off = read_name(buf, off)
        rtype, _c, ttl, rdlen = struct.unpack(">HHIH", buf[off:off + 10])
        off += 10
        text = parse_rdata(buf, off, rtype, rdlen)
        off += rdlen
        if text is not None:
            answers.append({"name": name, "type": TYPES.get(rtype, str(rtype)), "ttl": ttl, "data": text})
    return {"id": txid, "response": bool(flags & 0x8000), "truncated": bool(flags & 0x0200), "rcode": flags & 0xF,
            "questions": questions, "answers": answers}

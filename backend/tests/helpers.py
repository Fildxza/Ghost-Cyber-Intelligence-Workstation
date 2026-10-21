"""Synthetic capture builders so PCAP tests need no binary fixtures."""
import socket
import struct


def _eth(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + struct.pack(">H", ethertype) + payload


def _ipv4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    total = 20 + len(payload)
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, proto, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return hdr + payload


def _udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def _tcp(sport: int, dport: int, flags: int, payload: bytes = b"") -> bytes:
    return struct.pack(">HHIIBBHHH", sport, dport, 1, 0, 5 << 4, flags, 8192, 0, 0) + payload


def dns_query(name: str, qtype: int = 1) -> bytes:
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + q + struct.pack(">HH", qtype, 1)


def dns_response(name: str, ip: str) -> bytes:
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    ans = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
    return struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + q + struct.pack(">HH", 1, 1) + ans


def packets():
    """(timestamp, ethernet frame) list: one DNS exchange, one TCP SYN to a public host, one ARP."""
    return [
        (1_700_000_000.0, _eth(_ipv4("192.168.1.10", "192.168.1.1", 17, _udp(53000, 53, dns_query("evil.example.org"))))),
        (1_700_000_000.2, _eth(_ipv4("192.168.1.1", "192.168.1.10", 17, _udp(53, 53000, dns_response("evil.example.org", "93.184.216.34"))))),
        (1_700_000_001.0, _eth(_ipv4("192.168.1.10", "93.184.216.34", 6, _tcp(40000, 443, 0x02)))),
        (1_700_000_001.1, _eth(_ipv4("93.184.216.34", "192.168.1.10", 6, _tcp(443, 40000, 0x12)))),
        (1_700_000_005.0, _eth(b"\x00" * 28, 0x0806)),
    ]


def classic_pcap(pkts=None) -> bytes:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for ts, frame in (packets() if pkts is None else pkts):
        sec = int(ts)
        out += struct.pack("<IIII", sec, int((ts - sec) * 1e6), len(frame), len(frame)) + frame
    return out


def pcapng(pkts=None) -> bytes:
    def block(btype, body):
        total = 12 + len(body)
        return struct.pack("<II", btype, total) + body + struct.pack("<I", total)

    shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = block(1, struct.pack("<HHI", 1, 0, 65535))
    out = shb + idb
    for ts, frame in (packets() if pkts is None else pkts):
        t = int(ts * 1e6)
        pad = (4 - len(frame) % 4) % 4
        body = struct.pack("<IIIII", 0, t >> 32, t & 0xFFFFFFFF, len(frame), len(frame)) + frame + b"\x00" * pad
        out += block(6, body)
    return out

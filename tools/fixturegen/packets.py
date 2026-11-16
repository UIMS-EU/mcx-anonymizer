# SPDX-License-Identifier: GPL-3.0-or-later
"""Packet builders for the fixture sets: correct lengths and checksums."""
import struct
import zlib


def inet_sum(data, acc=0):
    if len(data) % 2:
        data = bytes(data) + b"\x00"
    acc += sum(struct.unpack("!%dH" % (len(data) // 2), data))
    return acc


def fold(acc):
    while acc >> 16:
        acc = (acc & 0xFFFF) + (acc >> 16)
    return acc


def inet_checksum(data, acc=0):
    return (~fold(inet_sum(data, acc))) & 0xFFFF


def crc32c(data):
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def fcs(frame):
    return struct.pack("<I", zlib.crc32(frame) & 0xFFFFFFFF)


# --- link layer -----------------------------------------------------------------
def ethernet(dst, src, ethertype, payload):
    return bytes(dst) + bytes(src) + struct.pack("!H", ethertype) + bytes(payload)


def vlan(tci, ethertype, payload):
    return struct.pack("!HH", tci, ethertype) + bytes(payload)


def sll(addr, protocol, payload, hatype=1, pkttype=0):
    halen = len(addr)
    a = bytes(addr)[:8] + b"\x00" * (8 - min(8, len(addr)))
    return struct.pack("!HHH", pkttype, hatype, halen) + a + struct.pack("!H", protocol) + payload


def sll2(addr, protocol, payload, ifindex=2, hatype=1, pkttype=0):
    a = bytes(addr)[:8] + b"\x00" * (8 - min(8, len(addr)))
    return (struct.pack("!HHIHBB", protocol, 0, ifindex, hatype, pkttype, len(addr)) + a + payload)


def arp(sha, spa, tha, tpa, op=1):
    return struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + bytes(sha) + bytes(spa) + bytes(tha) + bytes(tpa)


# --- IP ---------------------------------------------------------------------------
def ipv4(src, dst, proto, payload, ttl=64, ident=0x1234, options=b"", frag=0x4000, totlen=None):
    options = bytes(options) + b"\x00" * (-len(options) % 4)
    ihl = 5 + len(options) // 4
    total = ihl * 4 + len(payload) if totlen is None else totlen
    hdr = struct.pack("!BBHHHBBH4s4s", 0x40 | ihl, 0, total, ident, frag, ttl, proto, 0,
                      bytes(src), bytes(dst)) + options
    return hdr[:10] + struct.pack("!H", inet_checksum(hdr)) + hdr[12:] + bytes(payload)


def ipv6(src, dst, nh, payload, hlim=64):
    return struct.pack("!IHBB", 0x60000000, len(payload), nh, hlim) + bytes(src) + bytes(dst) + bytes(payload)


def ext(nh, body):
    """Hop-by-hop / destination options / routing: body after the 2-byte header, padded to 8n."""
    body = bytes(body)
    total = 2 + len(body)
    assert total % 8 == 0, total
    return bytes([nh, total // 8 - 1]) + body


def pseudo4(src, dst, proto, length):
    return bytes(src) + bytes(dst) + struct.pack("!BBH", 0, proto, length)


def pseudo6(src, dst, nh, length):
    return bytes(src) + bytes(dst) + struct.pack("!IxxxB", length, nh)


# --- transport --------------------------------------------------------------------
def udp(sport, dport, payload, pseudo=b"", checksum=True):
    length = 8 + len(payload)
    hdr = struct.pack("!HHHH", sport, dport, length, 0)
    cs = 0
    if checksum:
        cs = inet_checksum(pseudo + hdr + bytes(payload)) or 0xFFFF
    return struct.pack("!HHHH", sport, dport, length, cs) + bytes(payload)


def tcp(sport, dport, seq, ack, flags, payload=b"", options=b"", pseudo=b""):
    options = bytes(options)
    assert len(options) % 4 == 0
    doff = (20 + len(options)) // 4
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, doff << 4, flags, 65535, 0, 0) + options
    cs = inet_checksum(pseudo + hdr + bytes(payload))
    return hdr[:16] + struct.pack("!H", cs) + hdr[18:] + bytes(payload)


def udp4(src, dst, sport, dport, payload, **kw):
    return ipv4(src, dst, 17, udp(sport, dport, payload, pseudo4(src, dst, 17, 8 + len(payload))), **kw)


def tcp4(src, dst, sport, dport, seq, ack, flags, payload=b"", options=b""):
    seg_len = 20 + len(options) + len(payload)
    return ipv4(src, dst, 6, tcp(sport, dport, seq, ack, flags, payload, options,
                                 pseudo4(src, dst, 6, seg_len)))


def udp6(src, dst, sport, dport, payload):
    return ipv6(src, dst, 17, udp(sport, dport, payload, pseudo6(src, dst, 17, 8 + len(payload))))


def icmp(type_, code, rest4, data=b""):
    body = struct.pack("!BBH", type_, code, 0) + bytes(rest4) + bytes(data)
    return body[:2] + struct.pack("!H", inet_checksum(body)) + body[4:]


def icmpv6(src, dst, type_, code, body):
    msg = struct.pack("!BBH", type_, code, 0) + bytes(body)
    cs = inet_checksum(pseudo6(src, dst, 58, len(msg)) + msg)
    return msg[:2] + struct.pack("!H", cs) + msg[4:]


def sctp(sport, dport, vtag, chunks):
    pkt = struct.pack("!HHII", sport, dport, vtag, 0) + bytes(chunks)
    return pkt[:8] + struct.pack("<I", crc32c(pkt)) + pkt[12:]


def chunk(type_, flags, value):
    c = struct.pack("!BBH", type_, flags, 4 + len(value)) + bytes(value)
    return c + b"\x00" * (-len(c) % 4)


def param(type_, value, pad=b""):
    p = struct.pack("!HH", type_, 4 + len(value)) + bytes(value)
    n = -len(p) % 4
    return p + (bytes(pad[:n]) + b"\x00" * (n - len(pad[:n])))


def gre(proto, payload, key=None, seq=None, checksum=False):
    flags = (0x8000 if checksum else 0) | (0x2000 if key is not None else 0) | (0x1000 if seq is not None else 0)
    hdr = struct.pack("!HH", flags, proto)
    if checksum:
        hdr += b"\x00\x00\x00\x00"
    if key is not None:
        hdr += struct.pack("!I", key)
    if seq is not None:
        hdr += struct.pack("!I", seq)
    pkt = hdr + bytes(payload)
    if checksum:
        cs = inet_checksum(pkt)
        pkt = pkt[:4] + struct.pack("!H", cs) + pkt[6:]
    return pkt


def gtpu(teid, payload, msg_type=0xFF, exts=None):
    """exts: list of (type, content) extension headers (content padded so total is 4n)."""
    opt = b""
    flags = 0x30
    if exts:
        flags |= 0x04
        opt = struct.pack("!HB", 0, 0) + bytes([exts[0][0]])
        for i, (t, content) in enumerate(exts):
            nxt = exts[i + 1][0] if i + 1 < len(exts) else 0
            body = bytes(content)
            total = 1 + len(body) + 1
            assert total % 4 == 0, total
            opt += bytes([total // 4]) + body + bytes([nxt])
    return struct.pack("!BBHI", flags, msg_type, len(opt) + len(payload), teid) + opt + bytes(payload)

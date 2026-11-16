#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Independent SIP message and body extraction for the XML oracles (feature 003).

Reads a pcapng (Ethernet, IPv4/IPv6, optional VLAN tags and GTP-U over UDP 2152), takes SIP over
UDP (one message per datagram) and over TCP (each direction reassembled in sequence order,
retransmitted bytes skipped, messages framed by Content-Length), and splits multipart bodies at
their boundary. Shares no code with the tool or with the fixture generator.

messages(path) -> [Message(start_line, headers[(name, value)], body bytes, parts[Part])]
Part(content_type, headers[(name, value)], body bytes); a non-multipart body is one Part.
"""
import re
import struct
from collections import namedtuple

Message = namedtuple("Message", "start headers body parts")
Part = namedtuple("Part", "content_type headers body")
COMPACT = {"c": "content-type", "l": "content-length", "f": "from", "t": "to", "i": "call-id", "m": "contact",
           "r": "refer-to", "v": "via"}


def _frames(data):
    i = 0
    le = data[8:12] == b"\x4d\x3c\x2b\x1a"
    e = "<" if le else ">"
    while i + 12 <= len(data):
        bt, bl = struct.unpack_from(e + "II", data, i)
        if bl < 12:
            break
        if bt == 6:
            cl = struct.unpack_from(e + "I", data, i + 20)[0]
            yield data[i + 28:i + 28 + cl]
        elif bt == 3:
            yield data[i + 12:i + bl - 4]
        i += bl


def _l4(frame):
    """(proto, src, dst, sport, dport, seq, payload) or None."""
    if len(frame) < 14:
        return None
    et, off = struct.unpack_from(">H", frame, 12)[0], 14
    while et in (0x8100, 0x88A8) and off + 4 <= len(frame):
        et, off = struct.unpack_from(">H", frame, off + 2)[0], off + 4
    return _ip(frame, off, et, 0)


def _ip(frame, off, et, depth):
    if et == 0x0800 and off + 20 <= len(frame):
        ihl = (frame[off] & 15) * 4
        total = struct.unpack_from(">H", frame, off + 2)[0]
        proto, src, dst = frame[off + 9], frame[off + 12:off + 16], frame[off + 16:off + 20]
        if struct.unpack_from(">H", frame, off + 6)[0] & 0x3FFF:
            return None  # fragments: not needed by the XML fixtures
        body = frame[off + ihl:off + total]
    elif et == 0x86DD and off + 40 <= len(frame):
        plen = struct.unpack_from(">H", frame, off + 4)[0]
        proto, src, dst = frame[off + 6], frame[off + 8:off + 24], frame[off + 24:off + 40]
        body = frame[off + 40:off + 40 + plen]
    else:
        return None
    if proto == 17 and len(body) >= 8:
        sport, dport = struct.unpack_from(">HH", body)
        p = body[8:]
        if 2152 in (sport, dport) and depth == 0 and len(p) >= 8:  # GTP-U
            hl = 8 + (4 if p[0] & 7 else 0)
            inner = p[hl:]
            if inner and inner[0] >> 4 in (4, 6):
                return _ip(inner, 0, 0x0800 if inner[0] >> 4 == 4 else 0x86DD, 1)
        return 17, src, dst, sport, dport, 0, p
    if proto == 6 and len(body) >= 20:
        sport, dport, seq = struct.unpack_from(">HHI", body)
        return 6, src, dst, sport, dport, seq, body[(body[12] >> 4) * 4:]
    return None


def _headers(block):
    out = []
    for line in re.split(rb"\r?\n", block):
        if line[:1] in (b" ", b"\t") and out:
            out[-1] = (out[-1][0], out[-1][1] + " " + line.strip().decode("utf-8", "replace"))
        elif b":" in line:
            n, v = line.split(b":", 1)
            name = n.strip().decode("utf-8", "replace").lower()
            out.append((COMPACT.get(name, name), v.strip().decode("utf-8", "replace")))
    return out


def header(headers, name):
    for n, v in headers:
        if n == name:
            return v
    return None


def _parts(content_type, body):
    ct = (content_type or "").strip()
    if not ct.lower().startswith("multipart/"):
        return [Part(ct.split(";")[0].strip().lower(), [], body)]
    m = re.search(r'boundary\s*=\s*"?([^";]+)"?', ct, re.I)
    if not m:
        return []
    delim = b"--" + m.group(1).encode()
    out = []
    chunks = body.split(delim)
    for chunk in chunks[1:]:
        if chunk.startswith(b"--"):
            break
        chunk = chunk[2:] if chunk.startswith(b"\r\n") else chunk
        head, _, pbody = chunk.partition(b"\r\n\r\n")
        if pbody.endswith(b"\r\n"):
            pbody = pbody[:-2]
        hs = _headers(head)
        out.append(Part((header(hs, "content-type") or "").split(";")[0].strip().lower(), hs, pbody))
    return out


def _message(raw):
    head, sep, body = raw.partition(b"\r\n\r\n")
    if not sep:
        return None
    lines = head.split(b"\r\n", 1)
    hs = _headers(lines[1] if len(lines) > 1 else b"")
    return Message(lines[0].decode("utf-8", "replace"), hs, body, _parts(header(hs, "content-type"), body))


def _framed(stream):
    """SIP messages of one TCP direction, framed by Content-Length (RFC 3261 §18.3)."""
    out, i = [], 0
    while True:
        while stream[i:i + 2] == b"\r\n":
            i += 2
        end = stream.find(b"\r\n\r\n", i)
        if end < 0:
            break
        m = re.search(rb"\r\n(?:content-length|l)[ \t]*:[ \t]*(\d+)", stream[i:end + 2], re.I)
        n = int(m.group(1)) if m else 0
        if end + 4 + n > len(stream):
            break
        out.append(stream[i:end + 4 + n])
        i = end + 4 + n
    return out


def _is_sip(p):
    return p.startswith(b"SIP/2.0 ") or re.match(rb"[A-Z]+ \S+ SIP/2\.0\r\n", p) is not None


def messages(path):
    data = open(path, "rb").read()
    out = []  # (order key, Message)
    streams = {}  # direction -> [first frame index, next seq, bytearray]
    for n, frame in enumerate(_frames(data)):
        l4 = _l4(frame)
        if not l4:
            continue
        proto, src, dst, sport, dport, seq, p = l4
        if proto == 17:
            if _is_sip(p):
                m = _message(p)
                if m:
                    out.append(((n, 0), m))
            continue
        if not p:
            continue
        key = (src, dst, sport, dport)
        st = streams.get(key)
        if st is None:
            if not _is_sip(p):
                continue
            st = streams[key] = [n, seq, bytearray()]
        if seq < st[1]:
            p = p[st[1] - seq:]  # retransmitted head
            seq = st[1]
        if seq != st[1] or not p:
            continue
        st[2] += p
        st[1] = seq + len(p)
    for key, (first, _, stream) in streams.items():
        for k, raw in enumerate(_framed(bytes(stream))):
            m = _message(raw)
            if m:
                out.append(((first, k + 1), m))
    out.sort(key=lambda x: x[0])
    return [m for _, m in out]


def xml_bodies(path):
    """(message index, part index, content type, body) of every part whose type ends in +xml."""
    res = []
    for i, m in enumerate(messages(path)):
        for j, p in enumerate(m.parts):
            if p.content_type.endswith("+xml"):
                res.append((i, j, p.content_type, p.body))
    return res

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Large synthetic capture for the performance tests (001: SC-004, SC-005; 002: SC-005, R22).

Default mode: SIZE bytes of Ethernet/IPv4/UDP packets. The first DISTINCT packets use
distinct source MAC and IPv4 addresses (so the project mapping grows to about
2 x DISTINCT entries); the block is then repeated until the size is reached.

--sip mode: a block of CALLS call ladders (the US1 ladder of sip.py: 34 messages, every
non-keep component a fresh value, so each call adds about 290 values to the mapping; the
default of 350 calls gives about 100,000 entries, the scale of 001/SC-004). Even
calls go over UDP, odd calls over TCPCONNS long-lived TCP connections to the P-CSCF, so about
half of the SIP bytes are carried by TCP, segmented at 1400 bytes. Non-SIP UDP filler between
the messages brings the SIP share of the capture bytes to SIPSHARE. The block is repeated
until SIZE is reached; each repetition moves the timestamps forward and continues the TCP
sequence numbers (checksums updated incrementally, RFC 1624 §3), so the TCP connections stay
in order instead of looking like retransmissions. Prints the byte shares as JSON on stdout.

--media mode (004: SC-005): a block of CALLS calls over UDP, each the same 34-message
ladder (so the mapping reaches the 002/I18 scale), whose SDP offer and answer announce an audio
stream with RTCP and an MCPTT floor control channel. Each call then carries AMR-WB RTP in both
directions (one SSRC per direction, the offer's from its a=ssrc), an SR and SDES compound every
RTPGAP packets per direction, and a floor control exchange (Request, Granted, Taken, Release,
Idle) with MCPTT IDs. Non-media UDP filler completes the capture, so that SIP is SIPSHARE and
RTP+RTCP MEDIASHARE of the bytes. Prints the byte shares as JSON on stdout.

--web (with --sip, feature 007 SC-006): each INVITE dialog is followed by an XCAP
exchange over HTTP/1.1 (a group document GET with a Bearer JWT and the GMS response) and a
TLS 1.2 handshake in the clear (ClientHello with SNI, ServerHello, a certificate, ECDHE key
exchange, ServerHelloDone, ClientKeyExchange), on TCPCONNS long-lived connections each to the GMS
port 80 and 443. The handshakes stop before ChangeCipherSpec, so every repetition is parsed
again rather than zeroed as protected records.

Usage: bulk.py OUT [--size BYTES] [--distinct N] [--packet BYTES]
       bulk.py OUT --sip [--size BYTES] [--calls N] [--tcp-conns N] [--sip-share F] [--seed N]
       bulk.py OUT --media [--size BYTES] [--calls N] [--sip-share F] [--media-share F] [--seed N]
"""
import argparse
import base64
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import canary  # noqa: E402
import packets as P  # noqa: E402
import sip  # noqa: E402

PCAP_HEADER = struct.pack("<IHHiiII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)
START = 1_791_963_735  # 2026-10-14, like the SIP fixtures
STEP_US = 50           # packet spacing
TCP = 14 + 20          # offset of the TCP header in an Ethernet/IPv4 frame without IP options


def plain(a):
    payload = b"P" * (a.packet - 14 - 20 - 8)
    dst_mac = bytes([0x00, 0x50, 0x56, 0x00, 0x00, 0x01])
    dst_ip = bytes([10, 255, 0, 1])
    block = bytearray()
    for i in range(a.distinct):
        src_mac = bytes([0x00, 0x1c, 0x42]) + i.to_bytes(3, "big")
        src_ip = bytes([10]) + (i + 256).to_bytes(3, "big")
        frame = P.ethernet(dst_mac, src_mac, 0x0800, P.udp4(src_ip, dst_ip, 40000 + i % 20000, 5060, payload))
        block += struct.pack("<IIII", 1700000000 + i // 1000, (i % 1000) * 1000, len(frame), len(frame)) + frame
    with open(a.out, "wb") as f:
        f.write(PCAP_HEADER)
        written = 24
        while written < a.size:
            f.write(block)
            written += len(block)
    return 0


def _patch_word32(frame, off, value, csum):
    """Writes a 32-bit field at off and returns the TCP checksum updated for it (RFC 1624
    eqn. 3: HC' = ~(~HC + ~m + m'), per 16-bit word)."""
    old = struct.unpack_from("!HH", frame, off)
    struct.pack_into("!I", frame, off, value)
    new = struct.unpack_from("!HH", frame, off)
    acc = ~csum & 0xFFFF
    for m, m2 in zip(old, new):
        acc += (~m & 0xFFFF) + m2
    while acc >> 16:
        acc = (acc & 0xFFFF) + (acc >> 16)
    return ~acc & 0xFFFF


class Block:
    """The records of one repetition: (frame, tcp) with tcp = (conn, direction) or None."""

    def __init__(self):
        self.records = []
        self.bytes = {"sip_udp": 0, "sip_tcp": 0, "other": 0, "web": 0}
        self.packets = {}

    def add(self, frame, kind, tcp=None):
        self.records.append((frame, tcp))
        self.bytes[kind] += 16 + len(frame)
        self.packets[kind] = self.packets.get(kind, 0) + 1


def with_xml_body(m, body):
    """The message with `body` as an mcptt-info body: a bodiless message gets it alone, a message
    with SDP gets a multipart body (SDP + mcptt-info), as INVITEs carry them (feature 003)."""
    head, _, old = m.partition(b"\r\n\r\n")
    ctypes = [ln.split(b":", 1)[1].strip().lower() for ln in head.split(b"\r\n")
              if ln.lower().startswith((b"content-type:", b"c:"))]
    if old and ctypes != [b"application/sdp"]:
        return None  # another body type: left as it is
    lines = [ln for ln in head.split(b"\r\n") if not ln.lower().startswith((b"content-length:", b"content-type:", b"l:", b"c:"))]
    if old:
        bnd = b"bulk-xml-1"
        new = (b"--" + bnd + b"\r\nContent-Type: application/sdp\r\n\r\n" + old + b"\r\n--" + bnd +
               b"\r\nContent-Type: application/vnd.3gpp.mcptt-info+xml\r\n\r\n" + body + b"\r\n--" + bnd + b"--\r\n")
        ctype = b"multipart/mixed;boundary=" + bnd
    else:
        new, ctype = body, b"application/vnd.3gpp.mcptt-info+xml"
    lines += [b"Content-Type: " + ctype, b"Content-Length: " + str(len(new)).encode()]
    return b"\r\n".join(lines) + b"\r\n\r\n" + new


def with_key_mgmt(m, km):
    """An INVITE whose SDP gains a session-level a=key-mgmt:mikey (feature 005, --mikey)."""
    head, _, body = m.partition(b"\r\n\r\n")
    if not m.startswith(b"INVITE ") or b"\r\nt=" not in body:
        return None
    at = body.index(b"\r\nt=") + 2
    eol = body.index(b"\r\n", at) + 2
    body = body[:eol] + km + body[eol:]
    lines = [ln for ln in head.split(b"\r\n") if not ln.lower().startswith((b"content-length:", b"l:"))]
    lines.append(b"Content-Length: " + str(len(body)).encode())
    return b"\r\n".join(lines) + b"\r\n\r\n" + body


def sip_block(a):
    c = canary.Canaries(a.seed)
    xml_bodies = []
    if a.xml:
        import xmlbodies as X
        cv = X.Cv(c, "bulk")
        # The full US1 document and a small one (Appendix A §A.3), alternating.
        xml_bodies = [X.doc(X.mcptt_info_doc(cv)), X.doc(X.mcptt_info_small(cv))]
    nxml = 0
    km = None
    if a.mikey:
        import mikey as K
        ids = [(K.IDRI, K.URI, b"sip:caller@mcx.example.net"), (K.IDRR, K.URI, b"sip:callee@mcx.example.net"),
               (K.IDRKMSI, K.URI, b"kms.mcx.example.net"), (K.IDRKMSR, K.URI, b"kms.mcx.example.net")]
        msg = K.i_message(K.key_id(K.PCK, 0x0123456), 0xE9A1B2C380000000, bytes(range(16)), ids,
                          K.filler(273, 1), K.filler(129, 2))
        km = b"a=key-mgmt:mikey " + base64.b64encode(msg) + b"\r\n"
    nmikey = 0
    pcscf = sip.PCSCF
    conns = [sip.TcpConn(bytes([10, 21, 0, 10 + k]), pcscf, 41000 + k, 5060) for k in range(a.tcp_conns)]
    web = getattr(a, "web", False)
    gms = bytes([172, 16, 40, 21])
    nweb = len(conns)
    if web:
        conns += [sip.TcpConn(bytes([10, 22, 0, 10 + k]), gms, 42000 + k, 80) for k in range(a.tcp_conns)]
        conns += [sip.TcpConn(bytes([10, 23, 0, 10 + k]), gms, 43000 + k, 443) for k in range(a.tcp_conns)]
        import random
        rng = random.Random(a.seed)
    prefix = [f for t in conns for f in t.handshake()]
    blk = Block()
    filler_ratio = (1 - a.sip_share) / a.sip_share
    debt = 0.0
    fill_payload = b"F" * (1400 - 14 - 20 - 8)
    nfill = 0
    for call in range(a.calls):
        msgs, _ = sip.ladder_udp(c, "bulk")
        ua = bytes([10, 30 + (call >> 16 & 0xFF), call >> 8 & 0xFF, call & 0xFF])
        for i, m in enumerate(msgs):
            if xml_bodies and i % 2 == 0:  # half of the SIP messages carry an FR-001 body
                with_body = with_xml_body(m, xml_bodies[nxml % len(xml_bodies)])
                if with_body is not None:
                    m = with_body
                    nxml += 1
            if km is not None:
                with_km = with_key_mgmt(m, km)
                if with_km is not None:
                    m = with_km
                    nmikey += 1
            before = sum(blk.bytes[k] for k in ("sip_udp", "sip_tcp"))
            if call % 2 == 0:
                src, dst = (pcscf, ua) if m.startswith(b"SIP/2.0") else (ua, pcscf)
                blk.add(sip.wrap(sip.udp_packet(src, dst, 5060, 5060, m)), "sip_udp")
            else:
                k = (call // 2) % a.tcp_conns
                t, d = conns[k], sip._dir(m)
                for seg in sip._segments(m):
                    blk.add(t.send(d, seg), "sip_tcp", (k, d))
                blk.add(t.ack(1 - d), "sip_tcp", (k, 1 - d))
            debt += (sum(blk.bytes[k] for k in ("sip_udp", "sip_tcp")) - before) * filler_ratio
            if web and m.startswith(b"INVITE "):
                for kk, d, payload in web_dialog(call, rng):
                    k = nweb + kk * a.tcp_conns + call % a.tcp_conns
                    t = conns[k]
                    for seg in sip._segments(payload):
                        blk.add(t.send(d, seg), "web", (k, d))
                    blk.add(t.ack(1 - d), "web", (k, 1 - d))
                    blk.web_messages = getattr(blk, "web_messages", 0) + 1
            while debt > 0:
                # At most 16,384 filler sources: the mapping scale stays that of 001/SC-004 when
                # bigger SIP messages (--xml) need more filler packets per block.
                k = nfill % 16384
                src = bytes([10, 40, k >> 8 & 0xFF, k & 0xFF])
                frame = sip.wrap(P.udp4(src, bytes([10, 41, 0, 1]), 30000 + nfill % 1000, 9000, fill_payload))
                blk.add(frame, "other")
                debt -= 16 + len(frame)
                nfill += 1
    # Bytes each direction of each connection advances per repetition.
    advance = [[t.next[d] - (1000 + 1, 500000 + 1)[d] for d in (0, 1)] for t in conns]
    blk.xml_messages = nxml
    blk.mikey_messages = nmikey
    return prefix, blk, advance


def web_dialog(call, rng):
    """(connection kind 0 HTTP / 1 TLS, direction, payload) of one call's XCAP and TLS exchanges."""
    import der
    user = f"sip:user{call:05d}@mcx.example.net"
    claims = base64.urlsafe_b64encode(json.dumps({"sub": f"user{call:05d}", "mcptt_id": user,
                                                  "exp": START + 3600}).encode()).rstrip(b"=")
    token = b"eyJhbGciOiJSUzI1NiJ9." + claims + b"." + base64.urlsafe_b64encode(bytes(rng.randrange(256) for _ in range(64))).rstrip(b"=")
    group = f"sip:group{call % 97:03d}@mcx.example.net"
    req = (f"GET /xcap-root/org.openmobilealliance.groups/global/byGroupID/{group} HTTP/1.1\r\n"
           f"Host: gms.mcx.example.net\r\nAuthorization: Bearer ").encode() + token + (
           "\r\nAccept: application/vnd.oma.poc.groups+xml\r\nUser-Agent: Bulk/1.0\r\n\r\n").encode()
    doc = (f"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<group xmlns=\"urn:oma:xml:poc:list-service\" "
           f"xmlns:rl=\"urn:ietf:params:xml:ns:resource-lists\">\n<list-service uri=\"{group}\">"
           f"<display-name xml:lang=\"en\">Group {call % 97}</display-name>\n<list>"
           + "".join(f"<rl:entry uri=\"sip:member{(call + i) % 1000:04d}@mcx.example.net\"/>" for i in range(6))
           + "</list>\n<invite-members>true</invite-members></list-service>\n</group>\n").encode()
    resp = (f"HTTP/1.1 200 OK\r\nContent-Type: application/vnd.oma.poc.groups+xml\r\nETag: \"etag-{call:05d}-b\"\r\n"
            f"Content-Length: {len(doc)}\r\n\r\n").encode() + doc
    hs = lambda t, body: bytes([t]) + struct.pack("!I", len(body))[1:] + body  # noqa: E731
    rec = lambda body: b"\x16\x03\x03" + struct.pack("!H", len(body)) + body  # noqa: E731
    sni = f"gms{call % 50:02d}.mcx.example.net".encode()
    exts = (struct.pack("!HHHBH", 0, len(sni) + 5, len(sni) + 3, 0, len(sni)) + sni
            + struct.pack("!HHH", 10, 4, 2) + b"\x00\x17" + struct.pack("!HHH", 13, 4, 2) + b"\x04\x01")
    rnd = lambda n: bytes(rng.randrange(256) for _ in range(n))  # noqa: E731
    ch = b"\x03\x03" + rnd(32) + b"\x00\x00\x02\xc0\x2f\x01\x00" + struct.pack("!H", len(exts)) + exts
    sh = b"\x03\x03" + rnd(32) + b"\x20" + rnd(32) + b"\xc0\x2f\x00\x00\x00"
    name = der.name([("2.5.4.10", 0x0C, f"Operator {call % 13:02d} Ltd"), ("2.5.4.3", 0x0C, sni.decode())])
    ca = der.name([("2.5.4.3", 0x0C, "Bulk CA")])
    cert = der.certificate(rng, b"\x31" + rnd(15), ca, name, extensions=[
        der.ext("2.5.29.17", der.seq(der.tlv(0x82, sni)))], issuer_raw=True)
    point = b"\x04" + rnd(64)
    ske = b"\x03\x00\x17\x41" + point + b"\x04\x01\x01\x00" + rnd(256)
    flight = (hs(2, sh) + hs(11, struct.pack("!I", len(cert) + 3)[1:] + struct.pack("!I", len(cert))[1:] + cert)
              + hs(12, ske) + hs(14, b""))
    cke = hs(16, b"\x41\x04" + rnd(64))
    return [(0, 0, req), (0, 1, resp), (1, 0, rec(hs(1, ch))), (1, 1, rec(flight)), (1, 0, rec(cke))]


def write_sip(a):
    prefix, blk, advance = sip_block(a)
    reps = 0
    ts = START * 1_000_000
    with open(a.out, "wb") as f:
        f.write(PCAP_HEADER)
        written = 24
        for frame in prefix:
            ts += STEP_US
            f.write(struct.pack("<IIII", ts // 1_000_000, ts % 1_000_000, len(frame), len(frame)) + frame)
            written += 16 + len(frame)
        while written < a.size:
            out = []
            for frame, tcp in blk.records:
                ts += STEP_US
                if tcp is not None and reps:
                    k, d = tcp
                    fr = bytearray(frame)
                    csum = struct.unpack_from("!H", fr, TCP + 16)[0]
                    seq, ack = struct.unpack_from("!II", fr, TCP + 4)
                    csum = _patch_word32(fr, TCP + 4, (seq + reps * advance[k][d]) & 0xFFFFFFFF, csum)
                    csum = _patch_word32(fr, TCP + 8, (ack + reps * advance[k][1 - d]) & 0xFFFFFFFF, csum)
                    struct.pack_into("!H", fr, TCP + 16, csum)
                    frame = bytes(fr)
                out.append(struct.pack("<IIII", ts // 1_000_000, ts % 1_000_000, len(frame), len(frame)))
                out.append(frame)
            chunk = b"".join(out)
            f.write(chunk)
            written += len(chunk)
            reps += 1
    total = sum(blk.bytes.values())
    stats = {"bytes": written, "repetitions": reps, "calls_per_block": a.calls,
             "sip_share": (blk.bytes["sip_udp"] + blk.bytes["sip_tcp"]) / total,
             "sip_tcp_share_of_sip": blk.bytes["sip_tcp"] / (blk.bytes["sip_udp"] + blk.bytes["sip_tcp"]),
             "sip_messages": reps * a.calls * 34, "xml_messages": reps * blk.xml_messages,
             "mikey_messages": reps * getattr(blk, "mikey_messages", 0),
             "web_messages": reps * getattr(blk, "web_messages", 0), "web_share": blk.bytes.get("web", 0) / total}
    print(json.dumps(stats))
    return 0


def media_block(a):
    import ipaddress
    import re
    import media as M
    c = canary.Canaries(a.seed)
    blk = Block()
    blk.bytes = {"sip": 0, "rtp": 0, "rtcp": 0, "fc": 0, "other": 0}
    pcscf = sip.PCSCF
    fill_payload = b"F" * (1400 - 14 - 20 - 8)
    payload = bytes((i * 37) & 0xFF for i in range(61))  # AMR-WB 23.85 kbit/s, 20 ms
    nfill = 0
    ssrcs = set()

    def udp(src, dst, sport, dport, data, kind):
        blk.add(sip.wrap(P.udp4(src, dst, sport, dport, data)), kind)

    for call in range(a.calls):
        msgs, _ = sip.ladder_udp(c, "bulk")
        ua = bytes([10, 30 + (call >> 16 & 0xFF), call >> 8 & 0xFF, call & 0xFF])
        before = blk.bytes["sip"]
        sdps = []
        for m in msgs:
            src, dst = (pcscf, ua) if m.startswith(b"SIP/2.0") else (ua, pcscf)
            udp(src, dst, 5060, 5060, m, "sip")
            text = m.decode("latin-1")
            if "m=audio" in text:
                sdps.append(text)
        sip_bytes = blk.bytes["sip"] - before
        offer, answer = sdps[0], sdps[-1]
        ip = lambda t: ipaddress.IPv4Address(re.search(r"\r\nc=IN IP4 (\S+)", t).group(1)).packed
        oc, ac = ip(offer), ip(answer)
        rtcp_o = ipaddress.IPv4Address(re.search(r"a=rtcp:49171 IN IP4 (\S+)", offer).group(1)).packed
        so = int(re.search(r"a=ssrc:(\d+)", offer).group(1))
        sa = (0x9E3779B1 * (call + 1)) & 0xFFFFFFFF
        fso = int(re.search(r"mc_floor_ssrc=(\d+)", offer).group(1))
        ssrcs.update((so, sa, fso))
        cname = f"call{call}@example.net".encode()
        # Floor control (TS 24.380 §8.2): Request, Granted, Taken, Release, Idle.
        user = f"sip:mcptt-{call}@example.net".encode()
        F = M.app_field
        fc = [(0, oc, 49172, ac, 50172, fso, [F(0, b"\x05\x00"), F(6, user)]),
              (1, ac, 50172, oc, 49172, sa, [F(1, struct.pack("!H", 30)), F(0, b"\x05\x00"), F(8, struct.pack("!H", 1))]),
              (2, ac, 50172, oc, 49172, sa, [F(4, user), F(8, struct.pack("!H", 2))]),
              (4, oc, 49172, ac, 50172, fso, [F(6, user), F(8, struct.pack("!H", 3))]),
              (5, ac, 50172, oc, 49172, sa, [F(8, struct.pack("!H", 4))])]
        for sub, src, sp, dst, dp, ss, fields in fc[:3]:
            udp(src, dst, sp, dp, M.app(b"MCPT", sub, ss, b"".join(fields)), "fc")
        target = sip_bytes * a.media_share / a.sip_share
        got, seq = 0, 0
        while got < target:
            for src, sp, dst, dp, ss in ((oc, 49170, ac, 50170, so), (ac, 50170, oc, 49170, sa)):
                frame = sip.wrap(P.udp4(src, dst, sp, dp, M.rtp(seq & 0xFFFF, seq * 320, ss, pt=97, payload=payload)))
                blk.add(frame, "rtp")
                got += 16 + len(frame)
                if seq % a.rtp_gap == a.rtp_gap - 1:
                    rsrc, rsp = (rtcp_o, 49171) if src == oc else (ac, 50171)
                    pkt = M.compound(M.rtcp_sr(ss, [M.report_block(sa if ss == so else so)], packets=seq),
                                     M.rtcp_sdes([M.sdes_chunk(ss, [(M.SDES["CNAME"], cname)])]))
                    frame = sip.wrap(P.udp4(rsrc, dst, rsp, dp + 1, pkt))
                    blk.add(frame, "rtcp")
                    got += 16 + len(frame)
            seq += 1
        for sub, src, sp, dst, dp, ss, fields in fc[3:]:
            udp(src, dst, sp, dp, M.app(b"MCPT", sub, ss, b"".join(fields)), "fc")
        filler = sip_bytes * (1 - a.sip_share - a.media_share) / a.sip_share
        while filler > 0:
            src = bytes([10, 40, nfill >> 8 & 0xFF, nfill & 0xFF])
            frame = sip.wrap(P.udp4(src, bytes([10, 41, 0, 1]), 30000 + nfill % 1000, 9000, fill_payload))
            blk.add(frame, "other")
            filler -= 16 + len(frame)
            nfill += 1
    return blk, len(ssrcs)


def write_media(a):
    blk, nssrc = media_block(a)
    reps = 0
    ts = START * 1_000_000
    with open(a.out, "wb") as f:
        f.write(PCAP_HEADER)
        written = 24
        while written < a.size:
            out = []
            for frame, _ in blk.records:
                ts += STEP_US
                out.append(struct.pack("<IIII", ts // 1_000_000, ts % 1_000_000, len(frame), len(frame)))
                out.append(frame)
            chunk = b"".join(out)
            f.write(chunk)
            written += len(chunk)
            reps += 1
    total = sum(blk.bytes.values())
    stats = {"bytes": written, "repetitions": reps, "calls_per_block": a.calls, "ssrcs": nssrc,
             "sip_share": blk.bytes["sip"] / total,
             "media_share": (blk.bytes["rtp"] + blk.bytes["rtcp"]) / total,
             "fc_share": blk.bytes["fc"] / total,
             "sip_messages": reps * a.calls * 34,
             "rtp_packets": reps * blk.packets["rtp"], "rtcp_datagrams": reps * blk.packets["rtcp"],
             "app_messages": reps * blk.packets["fc"]}
    print(json.dumps(stats))
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--size", type=int, default=1 << 30)
    ap.add_argument("--distinct", type=int, default=50000)
    ap.add_argument("--packet", type=int, default=1400)
    ap.add_argument("--sip", action="store_true")
    ap.add_argument("--xml", action="store_true", help="with --sip: half of the SIP messages carry mcptt-info")
    ap.add_argument("--mikey", action="store_true", help="with --sip: every INVITE SDP carries a=key-mgmt:mikey")
    ap.add_argument("--web", action="store_true", help="with --sip: an XCAP exchange and a TLS handshake per INVITE dialog")
    ap.add_argument("--calls", type=int, default=350)
    ap.add_argument("--tcp-conns", type=int, default=8)
    ap.add_argument("--sip-share", type=float, default=None, help="default 0.35 (--sip), 0.10 (--media)")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--media", action="store_true")
    ap.add_argument("--media-share", type=float, default=0.60)
    ap.add_argument("--rtp-gap", type=int, default=250)
    a = ap.parse_args()
    if a.media:
        a.sip_share = 0.10 if a.sip_share is None else a.sip_share
        return write_media(a)
    a.sip_share = 0.35 if a.sip_share is None else a.sip_share
    return write_sip(a) if a.sip else plain(a)


if __name__ == "__main__":
    sys.exit(main())

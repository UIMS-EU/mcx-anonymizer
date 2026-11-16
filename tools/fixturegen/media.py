# SPDX-License-Identifier: GPL-3.0-or-later
"""Media-plane fixtures: RTP, RTCP, MCX RTCP APP and MSRP, with the SIP/SDP that announces them.

Builders:
  - rtp(): an RTP packet with any header field, CSRCs, a one-byte or two-byte header
    extension (RFC 5285 §4.2, §4.3) and RTP padding (RFC 3550 §5.1);
  - rtcp_*(): RTCP packets (RFC 3550 §6.4-§6.7, RFC 4585 §6.1, RFC 3611 §2) and compound();
  - app() / app_field(): MCX RTCP APP messages with the field TLV of TS 24.380 §8.1.3;
  - msrp_request() / msrp_response(): MSRP text per RFC 4975 §7.1 and §9;
  - Call: a SIP INVITE / 200 OK pair whose SDP announces the media endpoints, so that the
    anonymiser recognises the flows (FR-001).

Every value is invented. Addresses come from documentation and private ranges, names from
example.net (RFC 2606). Identity values that a non-keep rule classifies are canaries recorded
with their media rule key (see canary.py):
  app:<family>/<field-id>      an APP field, e.g. app:mcpt/4
  rtcp:sdes/<ITEM>             an SDES item, e.g. rtcp:sdes/NAME
  rtcp:bye/reason, rtcp:fb/<pt>/<fmt>, rtcp:xr/<bt>
  rtp:payload, rtp:ext, rtp:ssrc
  msrp:<Header>, msrp:tid, msrp:content, msrp:comment
Each generated file also gets a manifest entry in media_manifest.json with its floor and
transmission control ports, for oracles that need `-d udp.port==<port>,rtcp`.
"""
import json
import os
import struct

import sip as S

FIXTURES = []  # fixture functions (c, out), registered by the fixture sections below

# Endpoints (RFC 5737 / RFC 1918 ranges).
UE_A = bytes([10, 20, 0, 11])
UE_B = bytes([10, 20, 0, 12])
SRV = bytes([10, 20, 0, 1])

MANIFEST = {}  # file name -> {"fc_ports": [...], "tc_ports": [...], "msrp_ports": [...]}


# --- RTP (RFC 3550 §5.1, RFC 5285) -------------------------------------------------
def ext_one_byte(elements, pad=0):
    """One-byte header extension: profile 0xBEDE, elements (id 1..14, data of 1..16 octets)."""
    body = b"".join(bytes([(i << 4) | (len(d) - 1)]) + d for i, d in elements) + b"\0" * pad
    body += b"\0" * (-len(body) % 4)
    return struct.pack("!HH", 0xBEDE, len(body) // 4) + body


def ext_two_byte(elements, appbits=0, pad=0):
    """Two-byte header extension: profile 0x100X, elements (id 1..255, data of 0..255 octets)."""
    body = b"".join(bytes([i, len(d)]) + d for i, d in elements) + b"\0" * pad
    body += b"\0" * (-len(body) % 4)
    return struct.pack("!HH", 0x1000 | (appbits & 0xF), len(body) // 4) + body


def ext_other(profile, body):
    body += b"\0" * (-len(body) % 4)
    return struct.pack("!HH", profile, len(body) // 4) + body


def rtp(seq, ts, ssrc, pt=96, payload=b"", marker=0, csrcs=(), ext=None, padding=0, version=2, pad_fill=None):
    """An RTP packet. `padding` is the total number of padding octets (the last one holds the
    count); the other padding octets are `pad_fill` (default 0xAA) so that a test can see them
    zeroed."""
    p = 1 if padding else 0
    x = 1 if ext is not None else 0
    b0 = (version << 6) | (p << 5) | (x << 4) | len(csrcs)
    pkt = struct.pack("!BBHII", b0, (marker << 7) | pt, seq & 0xFFFF, ts & 0xFFFFFFFF, ssrc)
    pkt += b"".join(struct.pack("!I", c) for c in csrcs)
    if ext is not None:
        pkt += ext
    pkt += payload
    if padding:
        fill = (pad_fill or b"")[:padding - 1]
        pkt += fill + b"\xAA" * (padding - 1 - len(fill)) + bytes([padding])
    return pkt


# --- RTCP (RFC 3550 §6, RFC 4585, RFC 3611) ----------------------------------------
def rtcp(pt, count, body, padding=0):
    """One RTCP packet: V=2, P, count (RC/SC/FMT/subtype), PT, length in words minus one."""
    if padding:
        body = body + b"\0" * (padding - 1) + bytes([padding])
    if len(body) % 4:
        raise ValueError("RTCP body must be a multiple of 4 octets")
    return struct.pack("!BBH", 0x80 | (0x20 if padding else 0) | count, pt, len(body) // 4) + body


def report_block(ssrc, lost_frac=3, cum_lost=7, ext_seq=0x10010, jitter=40, lsr=0x1234, dlsr=0x56):
    return struct.pack("!IB3sIIII", ssrc, lost_frac, cum_lost.to_bytes(3, "big"), ext_seq, jitter, lsr, dlsr)


def rtcp_sr(ssrc, blocks=(), ntp=0xE1234567_89ABCDEF, rtp_ts=160000, packets=500, octets=16000):
    body = struct.pack("!IQIII", ssrc, ntp, rtp_ts, packets, octets) + b"".join(blocks)
    return rtcp(200, len(blocks), body)


def rtcp_rr(ssrc, blocks=()):
    return rtcp(201, len(blocks), struct.pack("!I", ssrc) + b"".join(blocks))


SDES = {"CNAME": 1, "NAME": 2, "EMAIL": 3, "PHONE": 4, "LOC": 5, "TOOL": 6, "NOTE": 7, "PRIV": 8}


def sdes_chunk(ssrc, items):
    """items: [(type, bytes)]; the chunk ends with a null octet and is padded to 32 bits."""
    body = struct.pack("!I", ssrc) + b"".join(bytes([t, len(v)]) + v for t, v in items) + b"\0"
    return body + b"\0" * (-len(body) % 4)


def rtcp_sdes(chunks):
    return rtcp(202, len(chunks), b"".join(chunks))


def rtcp_bye(ssrcs, reason=None):
    body = b"".join(struct.pack("!I", s) for s in ssrcs)
    if reason is not None:
        body += bytes([len(reason)]) + reason
        body += b"\0" * (-len(body) % 4)
    return rtcp(203, len(ssrcs), body)


def rtcp_fb(pt, fmt, sender, media, fci=b""):
    return rtcp(pt, fmt, struct.pack("!II", sender, media) + fci)


def xr_block(bt, type_specific, body):
    return struct.pack("!BBH", bt, type_specific, len(body) // 4) + body


def rtcp_xr(ssrc, blocks):
    return rtcp(207, 0, struct.pack("!I", ssrc) + b"".join(blocks))


def compound(*packets):
    return b"".join(packets)


# --- MCX RTCP APP (TS 24.380 §8.1.2, §8.1.3) ----------------------------------------
def app_field(fid, value):
    """One application specific data field: ID, length (1 octet below 192, 2 octets from
    192), value, zero padding to a multiple of 4 octets."""
    head = bytes([fid, len(value)]) if fid < 192 else bytes([fid]) + struct.pack("!H", len(value))
    f = head + value
    return f + b"\0" * (-len(f) % 4)


def app(name, subtype, ssrc, fields=b"", trailer=b""):
    """An RTCP APP packet (PT 204). `trailer` is appended outside the APP length, e.g. an
    SRTCP-like secure part (which makes the datagram fail the tiling check, FR-030)."""
    body = struct.pack("!I", ssrc) + name + fields
    if len(body) % 4:
        raise ValueError("APP body must be a multiple of 4 octets")
    return struct.pack("!BBH", 0x80 | (subtype & 0x1F), 204, len(body) // 4) + body + trailer


def uri_list(uris):
    """List encoding of TS 24.380 §8.2.3.17: count, then (length, URI) pairs."""
    return bytes([len(uris)]) + b"".join(bytes([len(u)]) + u for u in uris)


# --- MSRP (RFC 4975 §7.1, §9) -------------------------------------------------------
def msrp_request(tid, method, headers, content=None, content_type=None, flag="$"):
    lines = [f"MSRP {tid} {method}"] + list(headers)
    if content is None:
        return ("\r\n".join(lines) + f"\r\n-------{tid}{flag}\r\n").encode()
    lines.append(f"Content-Type: {content_type}")
    head = ("\r\n".join(lines) + "\r\n\r\n").encode()
    return head + content + f"\r\n-------{tid}{flag}\r\n".encode()


def msrp_response(tid, code, comment, headers):
    start = f"MSRP {tid} {code}" + (f" {comment}" if comment else "")
    return ("\r\n".join([start] + list(headers)) + f"\r\n-------{tid}$\r\n").encode()


# --- SIP call that announces the media ----------------------------------------------
def _ip(b):
    return ".".join(str(x) for x in b)


def sdp_body(ip, media, sess=1001):
    """media: list of SDP media sections as text (each starting with "m=")."""
    return (f"v=0\r\no=- {sess} {sess} IN IP4 {_ip(ip)}\r\ns=-\r\nc=IN IP4 {_ip(ip)}\r\nt=0 0\r\n"
            + "".join(media)).encode()


def m_audio(port, proto="RTP/AVP", rtcp_port=None, mux=False, ssrc=None, cname=None, extra=""):
    s = f"m=audio {port} {proto} 96 101\r\na=rtpmap:96 AMR-WB/16000\r\na=rtpmap:101 telephone-event/16000\r\n"
    if rtcp_port is not None:
        s += f"a=rtcp:{rtcp_port}\r\n"
    if mux:
        s += "a=rtcp-mux\r\n"
    if ssrc is not None and cname is not None:
        s += f"a=ssrc:{ssrc} cname:{cname}\r\n"
    return s + extra


def m_video(port, proto="RTP/AVPF", ssrc=None, cname=None):
    s = f"m=video {port} {proto} 100\r\na=rtpmap:100 H264/90000\r\na=rtcp-fb:100 nack pli\r\n"
    if ssrc is not None and cname is not None:
        s += f"a=ssrc:{ssrc} cname:{cname}\r\n"
    return s


def m_floor(port, fmt="MCPTT", floor_ssrc=None):
    s = f"m=application {port} udp {fmt}\r\n"
    if floor_ssrc is not None:
        key = "mc_floor_ssrc" if fmt == "MCPTT" else "mc_transmission_ssrc"
        s += f"a=fmtp:{fmt} mc_queueing;{key}={floor_ssrc}\r\n"
    return s


def m_msrp(ip, port, session, proto="TCP/MSRP"):
    scheme = "msrps" if "TLS" in proto else "msrp"
    return (f"m=message {port} {proto} *\r\na=accept-types:application/vnd.3gpp.mcdata-signalling "
            f"application/vnd.3gpp.mcdata-payload\r\na=path:{scheme}://{_ip(ip)}:{port}/{session};tcp\r\n")


_SESSIONS = [0]


def _session_id():
    """A distinct 10-digit SDP session id per SDP: short ids (4 digits) are number tokens that
    chance-match digits elsewhere in a shared test project."""
    _SESSIONS[0] += 1
    return 3000000000 + 7919 * _SESSIONS[0]


class Call:
    """A capture with one SIP dialog (INVITE from A, 200 OK from B) announcing media."""

    def __init__(self, a_media, b_media, a=UE_A, b=UE_B, call_id="media-call-1@example.net"):
        self.cap = S.Capture()
        self.a, self.b = a, b
        hdr = ["Via: SIP/2.0/UDP %s:5060;branch=z9hG4bKmedia1" % _ip(a), "From: <sip:a@example.net>;tag=ma",
               f"Call-ID: {call_id}", "CSeq: 1 INVITE", "Content-Type: application/sdp"]
        inv = S.request("INVITE", "sip:b@example.net", hdr[:2] + ["To: <sip:b@example.net>"] + hdr[2:],
                        sdp_body(a, a_media, _session_id()))
        ok = S.response(200, "OK", hdr[:2] + ["To: <sip:b@example.net>;tag=mb"] + hdr[2:],
                        sdp_body(b, b_media, _session_id()))
        self.cap.add(S.wrap(S.udp_packet(a, b, 5060, 5060, inv)))
        self.cap.add(S.wrap(S.udp_packet(b, a, 5060, 5060, ok)))

    def udp(self, src, dst, sport, dport, payload, ident=0x4D58):
        self.cap.add(S.wrap(S.udp_packet(src, dst, sport, dport, payload, ident=ident)))

    def a_to_b(self, sport, dport, payload):
        self.udp(self.a, self.b, sport, dport, payload)

    def b_to_a(self, sport, dport, payload):
        self.udp(self.b, self.a, sport, dport, payload)

    def write(self, out, name, fc_ports=(), tc_ports=(), msrp_ports=()):
        S._write(self.cap, out, name)
        MANIFEST[name] = {"fc_ports": list(fc_ports), "tc_ports": list(tc_ports),
                          "msrp_ports": list(msrp_ports)}


def gen(c, out):
    for fn in FIXTURES:
        fn(c, out)
    with open(os.path.join(out, "media_manifest.json"), "w") as fh:
        json.dump(MANIFEST, fh, indent=1, sort_keys=True)


# --- canary helpers -----------------------------------------------------------------
class _Cv:
    """Canaries of one fixture file, with their rule keys."""

    def __init__(self, c, fname):
        self.c, self.f = c, fname

    def ip(self, rule="sdp:c=.address"):
        import ipaddress
        return ipaddress.IPv4Address(self.c.ipv4(None, self.f, rule=rule)).packed

    def ssrc(self, rule="rtp:ssrc"):
        return int(self.c.binary(self.f, rule))

    def payload(self, n=24, rule="rtp:payload"):
        """Bytes that begin with a 16-byte canary (0x80..0xFE, never ASCII) under `rule`."""
        return self.c.bytes(None, self.f, 16, rule) + bytes(0x41 + (i % 26) for i in range(max(0, n - 16)))

    def s(self, rule, prefix="CANARY"):
        return self.c.string(None, self.f, prefix, rule=rule)


def _amr(seq):
    """An AMR-WB-like payload body, no canary (the RTP canary sits in the first packet)."""
    return bytes((seq * 7 + i) & 0xFF for i in range(33))


# --- RTP fixtures (US2) -----------------------------------------------------------
def gen_rtp_audio(c, out):
    name = "rtp_audio.pcapng"
    v = _Cv(c, name)
    a, b = v.ip(), v.ip()
    sa, sb = v.ssrc(), v.ssrc()
    csrc = v.ssrc("rtp:csrc")
    cname_a = v.s("sdp:a=ssrc.cname")
    call = Call([m_audio(40000, ssrc=sa, cname=cname_a)], [m_audio(50000)], a=a, b=b)
    ext1 = ext_one_byte([(1, v.payload(18, "rtp:extension-element-data")[:4]), (2, b"\x7f")])
    ext2 = ext_two_byte([(7, v.payload(20, "rtp:extension-element-data")[:3]), (9, b"")])
    for i in range(12):
        payload = v.payload(32) if i == 0 else _amr(i)
        kw = {}
        if i == 3:
            kw["ext"] = ext1
        if i == 4:
            kw["ext"] = ext2
        if i == 5:
            kw["ext"] = ext_other(0xABCD, b"\x01\x02\x03\x04")
        if i == 6:
            kw["padding"] = 8
            kw["pad_fill"] = v.payload(16, "rtp:padding-octets")[:7]
        if i == 7:
            kw["csrcs"] = (csrc,)
        call.a_to_b(40000, 50000, rtp(100 + i, 160 * i, sa, pt=96, payload=payload, marker=int(i == 0), **kw))
        call.b_to_a(50000, 40000, rtp(900 + i, 320 * i, sb, pt=96, payload=_amr(i + 50)))
    # A DTMF digit (RFC 4733 telephone-event) is content too (FR-008).
    call.a_to_b(40000, 50000, rtp(112, 1920, sa, pt=101, payload=b"\x05\x0a\x00\xa0"))
    call.write(out, name)


def gen_rtp_video(c, out):
    name = "rtp_video.pcapng"
    v = _Cv(c, name)
    a, b = v.ip(), v.ip()
    s1 = v.ssrc()
    call = Call([m_video(40010, ssrc=s1, cname=v.s("sdp:a=ssrc.cname"))], [m_video(50010)], a=a, b=b)
    for i in range(8):
        call.a_to_b(40010, 50010, rtp(5000 + i, 3000 * i, s1, pt=100, payload=v.payload(60) if i == 0 else bytes(60),
                                      marker=int(i == 7)))
    call.write(out, name)


def gen_rtp_mux(c, out):
    name = "rtp_mux.pcapng"
    v = _Cv(c, name)
    a, b = v.ip(), v.ip()
    s1 = v.ssrc()
    call = Call([m_audio(40020, mux=True)], [m_audio(50020, mux=True)], a=a, b=b)
    for i in range(4):
        call.a_to_b(40020, 50020, rtp(10 + i, 160 * i, s1, pt=96, payload=v.payload(24) if i == 0 else _amr(i)))
    call.write(out, name)


def gen_rtp_srtp(c, out):
    name = "rtp_srtp.pcapng"
    v = _Cv(c, name)
    a, b = v.ip(), v.ip()
    s1 = v.ssrc()
    call = Call([m_audio(40030, proto="RTP/SAVP")], [m_audio(50030, proto="RTP/SAVP")], a=a, b=b)
    for i in range(4):
        # Ciphertext, then a 4-octet MKI and a 10-octet authentication tag (RFC 3711 §3.1).
        body = (v.payload(30) if i == 0 else bytes((i * 31 + k) & 0xFF for k in range(30))) + \
            v.payload(16, "rtp:srtp-trailer")[:4] + bytes(10)
        call.a_to_b(40030, 50030, rtp(20 + i, 160 * i, s1, pt=96, payload=body))
    call.write(out, name)


def gen_rtp_unannounced(c, out):
    name = "rtp_unannounced.pcapng"
    v = _Cv(c, name)
    a, b = v.ip(), v.ip()
    s1, s2 = v.ssrc(), v.ssrc()
    call = Call([m_audio(40040)], [m_audio(50040)], a=a, b=b)
    call.a_to_b(40040, 50040, rtp(1, 0, s1, payload=v.payload(24)))
    # A flow that no SDP announces stays zeroed (FR-002), even though it looks like RTP.
    call.a_to_b(41040, 51040, rtp(1, 0, s2, payload=v.payload(24)))
    call.write(out, name)


def gen_rtp_malformed(c, out):
    name = "rtp_malformed.pcapng"
    v = _Cv(c, name)
    a, b = v.ip(), v.ip()
    s1 = v.ssrc()
    call = Call([m_audio(40050)], [m_audio(50050)], a=a, b=b)
    good = rtp(1, 0, s1, payload=v.payload(24))
    bad_version = bytes([0x40]) + good[1:]
    short = good[:7]
    cc_overrun = bytes([0x8F]) + good[1:16]
    pad_zero = rtp(2, 0, s1, payload=v.payload(24))[:-1] + b""
    pad_zero = bytes([pad_zero[0] | 0x20]) + pad_zero[1:] + b"\x00"
    ext_overrun = bytes([good[0] | 0x10]) + good[1:12] + b"\xbe\xde\x00\x09" + v.payload(16)
    for p in (bad_version, short, cc_overrun, pad_zero, ext_overrun):
        call.a_to_b(40050, 50050, p)
    call.write(out, name)


def gen_rtp_ssrc_edge(c, out):
    name = "rtp_ssrc_edge.pcapng"
    v = _Cv(c, name)
    a, b = v.ip(), v.ip()
    announced, unannounced, changed = v.ssrc(), v.ssrc(), v.ssrc()
    call = Call([m_audio(40060, ssrc=announced, cname=v.s("sdp:a=ssrc.cname"))], [m_audio(50060)], a=a, b=b)
    for i in range(3):
        call.a_to_b(40060, 50060, rtp(i, 160 * i, announced, payload=_amr(i)))
    # An SSRC the SDP does not announce, then an SSRC change in mid-stream.
    call.b_to_a(50060, 40060, rtp(0, 0, unannounced, payload=v.payload(24)))
    for i in range(3, 6):
        call.a_to_b(40060, 50060, rtp(i, 160 * i, changed, payload=_amr(i)))
    call.write(out, name)


MAX_MEDIA_ENDPOINTS = 65536  # src/media/limits.hpp kMaxMediaEndpoints


def gen_media_evict(c, out):
    """More announced endpoints than the table holds (FR-001), compactly: 14 INVITEs
    from 14 addresses, each with 2400 bare m=audio lines (an RTP and an RTCP endpoint each). The
    first announced endpoint is evicted and its flow falls back to zeroing; the last one is still
    announced and its flow is rewritten as RTP."""
    name = "media_evict.pcapng"
    v = _Cv(c, name)
    cap = S.Capture()
    per, calls = 2400, 14
    assert calls * per * 2 > MAX_MEDIA_ENDPOINTS
    peer = v.ip()
    addrs = [v.ip() for _ in range(calls)]
    for k, a in enumerate(addrs):
        media = [f"m=audio {2000 + 2 * j} RTP/AVP 0\r\n" for j in range(per)]
        hdr = ["Via: SIP/2.0/UDP %s:5060;branch=z9hG4bKevict%d" % (_ip(a), k), "From: <sip:a@example.net>;tag=e%d" % k,
               "To: <sip:b@example.net>", f"Call-ID: evict-{k}@example.net", "CSeq: 1 INVITE",
               "Content-Type: application/sdp"]
        inv = S.request("INVITE", "sip:b@example.net", hdr, sdp_body(a, media, _session_id()))
        cap.add(S.wrap(S.udp_packet(a, peer, 5060, 5060, inv)))
    first, last = (addrs[0], 2000), (addrs[-1], 2000 + 2 * (per - 1))
    for (a, port), seq in ((first, 1), (last, 2)):
        cap.add(S.wrap(S.udp_packet(a, peer, port, 30000, rtp(seq, 0, v.ssrc(), pt=0, payload=v.payload(24)))))
    S._write(cap, out, name)
    MANIFEST[name] = {"fc_ports": [], "tc_ports": [], "msrp_ports": [], "evicted": [_ip(first[0]), first[1]],
                      "kept": [_ip(last[0]), last[1]]}


FIXTURES += [gen_media_evict]
FIXTURES += [gen_rtp_audio, gen_rtp_video, gen_rtp_mux, gen_rtp_srtp, gen_rtp_unannounced, gen_rtp_malformed,
             gen_rtp_ssrc_edge]


# --- MCPT floor control fixtures (US1) ---------------------------------------------
def _user(v, rule):
    """A SIP URI whose user part is a canary (the URI mapping keeps the syntax)."""
    return f"sip:{v.s(rule, prefix='cnry')}@mcx.example.net".encode()


def _u16(n):
    return struct.pack("!H", n)


def _bcd_plmn(mcc, mnc):
    d = [int(x) for x in mcc + mnc]
    mnc3 = d[5] if len(d) == 6 else 0xF
    return bytes([(d[1] << 4) | d[0], (mnc3 << 4) | d[2], (d[4] << 4) | d[3]])


def _track_info(v, padded=True):
    pt = v.s("app:mcpt/11", prefix="PTYPE").encode()
    body = bytes([1, len(pt)]) + pt
    if padded:
        body += b"\0" * (-(len(body) - 2) % 4)
    for _ in range(2):
        body += struct.pack("!I", v.ssrc("app:mcpt/11"))
    return body


def _locations(v):
    """One Location field of every type (TS 24.380 Table 8.2.3.21-3), canaries in each."""
    out = []
    eci = v.ssrc("app:mcpt/19") & 0x0FFFFFFF
    out.append(bytes([1]) + _bcd_plmn("262", "01") + struct.pack("!I", eci))
    out.append(bytes([2]) + _bcd_plmn("310", "410") + _u16(0x4D2A))
    out.append(bytes([3]) + _bcd_plmn("262", "01"))
    out.append(bytes([4, 0x01, 0x2C]))
    out.append(bytes([5, 0x07]))
    out.append(bytes([6]) + v.payload(16, "app:mcpt/19")[:6])
    out.append(bytes([0]))
    return out


def _altitude(v):
    """Location type 7 (altitude): tshark 4.4 does not know it and misreads what follows, so it
    is always the last field of its message."""
    return bytes([7]) + v.payload(16, "app:mcpt/19")[:2]


def gen_app_mcpt(c, out):
    name = "app_mcpt.pcapng"
    v = _Cv(c, name)
    a, b = v.ip(), v.ip()
    fc_a, fc_b = 40002, 50002
    s_a, s_b = v.ssrc("sdp:a=fmtp:MCPTT.mc_floor_ssrc"), v.ssrc("sdp:a=fmtp:MCPTT.mc_floor_ssrc")
    call = Call([m_audio(40000), m_floor(fc_a, floor_ssrc=s_a)], [m_audio(50000), m_floor(fc_b, floor_ssrc=s_b)],
                a=a, b=b)
    F = app_field
    granted_ssrc = v.ssrc("app:mcpt/14")
    msgs = [
        (0, [F(0, b"\x05\x00"), F(6, _user(v, "app:mcpt/6")), F(11, _track_info(v)), F(17, _user(v, "app:mcpt/17"))]),
        (1, [F(1, _u16(30)), F(0, b"\x05\x00"), F(8, _u16(1)), F(14, struct.pack("!IH", granted_ssrc, 0)),
             F(6, _user(v, "app:mcpt/6")), F(3, b"\x01\x02"), F(7, _u16(1)), F(9, _user(v, "app:mcpt/9"))]),
        (17, [F(1, _u16(30)), F(8, _u16(2))]),
        (2, [F(4, _user(v, "app:mcpt/4")), F(5, _u16(1)), F(8, _u16(3)), F(13, _u16(0x8000)),
             F(15, uri_list([_user(v, "app:mcpt/15"), _user(v, "app:mcpt/15")])),
             F(18, uri_list([_user(v, "app:mcpt/18")]))]
         + [F(19, loc) for loc in _locations(v)]
         + [F(20, bytes([2]) + bytes([6]) + v.payload(16, "app:mcpt/20")[:6] + bytes([3]) + _bcd_plmn("262", "01")),
            # Last: tshark 4.4 misreads the padding after List of SSRCs and the fields after it.
            F(16, bytes([2, 0]) + struct.pack("!II", v.ssrc("app:mcpt/16"), v.ssrc("app:mcpt/16")))]),
        (18, [F(4, _user(v, "app:mcpt/4")), F(8, _u16(4)), F(19, _altitude(v))]),
        (3, [F(2, _u16(3) + v.s("app:mcpt/2", prefix="REJECT").encode()), F(6, _user(v, "app:mcpt/6"))]),
        (4, [F(6, _user(v, "app:mcpt/6")), F(8, _u16(5)), F(11, _track_info(v, padded=False))]),
        (20, [F(8, _u16(6))]),
        (5, [F(8, _u16(7)), F(13, _u16(0))]),
        (21, [F(8, _u16(8))]),
        (6, [F(2, _u16(4))]),
        (7, [F(25, _user(v, "app:mcpt/25")), F(14, struct.pack("!IH", v.ssrc("app:mcpt/14"), 0))]),
        (8, [F(6, _user(v, "app:mcpt/6"))]),
        (9, [F(6, _user(v, "app:mcpt/6")), F(3, b"\x02\x05")]),
        (25, [F(3, b"\x01\x05")]),
        (10, [F(10, _u16(1)), F(12, b"\x01\x00")]),
        (11, [F(24, b"\x80\x00")]),
        (27, [F(24, b"\x00\x00")]),
        (14, [F(21, _u16(0)), F(22, bytes([1]) + bytes([0]) + bytes([len(u := _user(v, "app:mcpt/22"))]) + u)]),
        (30, [F(23, _u16(1))]),
        (15, [F(14, struct.pack("!IH", v.ssrc("app:mcpt/14"), 0))]),
    ]
    for i, (subtype, fields) in enumerate(msgs):
        sender = s_b if i % 2 else s_a
        pkt = app(b"MCPT", subtype, sender, b"".join(fields))
        if i % 2:
            call.b_to_a(fc_b, fc_a, pkt)
        else:
            call.a_to_b(fc_a, fc_b, pkt)
    call.write(out, name, fc_ports=[fc_a, fc_b])


def gen_app_mcpt_malformed(c, out):
    name = "app_mcpt_malformed.pcapng"
    v = _Cv(c, name)
    a, b = v.ip(), v.ip()
    fc_a, fc_b = 40102, 50102
    call = Call([m_floor(fc_a)], [m_floor(fc_b)], a=a, b=b)
    F = app_field
    s = v.ssrc("rtcp:ssrc")
    # Unknown subtype 12 (TS 24.380 §8.1.4: the whole message is ignored).
    call.a_to_b(fc_a, fc_b, app(b"MCPT", 12, s, F(6, _user(v, "app:mcpt/6"))))
    # An unknown name.
    call.a_to_b(fc_a, fc_b, app(b"QQQQ", 0, s, F(6, _user(v, "app:mcpt/6"))))
    # An unknown field ID 26 between two known fields.
    call.a_to_b(fc_a, fc_b, app(b"MCPT", 0, s, F(0, b"\x04\x00") + F(26, v.s("app:mcpt/6").encode()) + F(8, _u16(1))))
    # A field that overruns the packet.
    p = bytearray(app(b"MCPT", 0, s, F(0, b"\x04\x00") + F(6, _user(v, "app:mcpt/6"))))
    p[17] = 200
    call.a_to_b(fc_a, fc_b, bytes(p))
    # An appended SRTCP-like secure part: the datagram does not tile (P3).
    call.a_to_b(fc_a, fc_b, app(b"MCPT", 0, s, F(6, _user(v, "app:mcpt/6")), trailer=v.payload(16, "rtp:srtp-trailer")[:14]))
    # An unparsable URI.
    call.a_to_b(fc_a, fc_b, app(b"MCPT", 2, s, F(4, v.s("app:mcpt/4").encode() + b" not a uri")))
    call.write(out, name, fc_ports=[fc_a, fc_b])


def gen_app_mcpt_secure(c, out):
    name = "app_mcpt_secure.pcapng"
    v = _Cv(c, name)
    a, b = v.ip(), v.ip()
    call = Call([m_audio(40200, proto="RTP/SAVPF", mux=True)], [m_audio(50200, proto="RTP/SAVPF", mux=True)], a=a, b=b)
    s = v.ssrc("rtcp:ssrc")
    # APP on a secure endpoint: the name is encrypted (RFC 3711 §3.4), the SRTCP view applies (A13).
    call.a_to_b(40200, 50200, app(b"MCPT", 0, s, app_field(6, _user(v, "app:mcpt/6")), trailer=v.payload(16, "rtp:srtp-trailer")[:14]))
    call.write(out, name)


FIXTURES += [gen_app_mcpt, gen_app_mcpt_malformed, gen_app_mcpt_secure]


# --- RTCP fixtures (US3) -------------------------------------------------------------
def gen_rtcp_compound(c, out):
    name = "rtcp_compound.pcapng"
    v = _Cv(c, name)
    a, b = v.ip(), v.ip()
    sa, sb = v.ssrc("rtcp:ssrc"), v.ssrc("rtcp:ssrc")
    cname = v.s("sdp:a=ssrc.cname")
    call = Call([m_audio(40300, ssrc=sa, cname=cname)], [m_audio(50300)], a=a, b=b)
    for i in range(3):
        call.a_to_b(40300, 50300, rtp(i, 160 * i, sa, payload=_amr(i)))
    items = [(SDES["CNAME"], cname.encode())]
    for item in ("NAME", "EMAIL", "PHONE", "LOC", "TOOL", "NOTE"):
        items.append((SDES[item], v.s(f"rtcp:sdes/{item}").encode()))
    items.append((SDES["PRIV"], b"\x04" + v.s("rtcp:sdes/PRIV").encode()))
    call.a_to_b(40301, 50301, compound(rtcp_sr(sa, [report_block(sb)]), rtcp_sdes([sdes_chunk(sa, items)])))
    call.b_to_a(50301, 40301, compound(rtcp_rr(sb, [report_block(sa)]),
                                       rtcp_sdes([sdes_chunk(sb, [(SDES["CNAME"], v.s("rtcp:sdes/CNAME").encode())])])))
    call.a_to_b(40301, 50301, compound(rtcp_rr(sa), rtcp_bye([sa], v.s("rtcp:bye/reason").encode())))
    call.write(out, name)


def gen_rtcp_rsize(c, out):
    name = "rtcp_rsize.pcapng"
    v = _Cv(c, name)
    a, b = v.ip(), v.ip()
    sa, sb = v.ssrc("rtcp:ssrc"), v.ssrc("rtcp:ssrc")
    rsize = "a=rtcp-rsize\r\n"
    call = Call([m_video(40310) + rsize], [m_video(50310) + rsize], a=a, b=b)
    call.b_to_a(50311, 40311, rtcp_fb(206, 1, sb, sa))                     # PLI (RFC 5506 §3.4)
    call.b_to_a(50311, 40311, rtcp_fb(205, 1, sb, sa, struct.pack("!HH", 0x1234, 0x0005)))  # NACK
    call.write(out, name)


def gen_rtcp_fb_xr(c, out):
    name = "rtcp_fb_xr.pcapng"
    v = _Cv(c, name)
    a, b = v.ip(), v.ip()
    sa, sb = v.ssrc("rtcp:ssrc"), v.ssrc("rtcp:ssrc")
    call = Call([m_video(40320)], [m_video(50320)], a=a, b=b)
    fbs = [rtcp_fb(205, 1, sb, sa, struct.pack("!HH", 0x0100, 0x8001)),
           rtcp_fb(206, 1, sb, sa),
           rtcp_fb(206, 2, sb, sa, struct.pack("!I", 0x01234567)),
           rtcp_fb(206, 3, sb, sa, bytes([8, 100]) + v.payload(16, "rtcp:fb/206/3")[:5] + b"\x00"),
           rtcp_fb(206, 15, sb, sa, b"REMB" + v.payload(16, "rtcp:fb/206/15")[:8]),
           rtcp_fb(205, 9, sb, sa, v.payload(16, "rtcp:fb/205/9")[:4])]
    for p in fbs:
        call.b_to_a(50321, 40321, compound(rtcp_rr(sb), p))
    blocks = [xr_block(1, 0, struct.pack("!IHH", sa, 1, 16) + struct.pack("!HH", 0x4005, 0)),
              xr_block(2, 0, struct.pack("!IHH", sa, 1, 16) + struct.pack("!HH", 0x4001, 0)),
              xr_block(3, 0, struct.pack("!IHH", sa, 1, 3) + struct.pack("!II", 160, 320)),
              xr_block(4, 0, struct.pack("!II", 0xE1111111, 0x22222222)),
              xr_block(5, 0, struct.pack("!III", sa, 0x11112222, 0x300)),
              xr_block(6, 0xE0, struct.pack("!IHH", sa, 1, 100) + bytes(28)),
              xr_block(7, 0, struct.pack("!I", sa) + bytes(range(1, 29))),
              xr_block(99, 0, v.payload(16, "rtcp:xr/99")[:8])]
    call.b_to_a(50321, 40321, compound(rtcp_rr(sb), rtcp_xr(sb, blocks)))
    call.write(out, name)


def gen_rtcp_srtcp(c, out):
    name = "rtcp_srtcp.pcapng"
    v = _Cv(c, name)
    a, b = v.ip(), v.ip()
    sa = v.ssrc("rtcp:ssrc")
    call = Call([m_audio(40330, proto="RTP/SAVPF")], [m_audio(50330, proto="RTP/SAVPF")], a=a, b=b)
    enc = v.payload(16, "rtp:srtp-trailer") + bytes(12)
    # SRTCP (RFC 3711 §3.4): first 8 octets clear, then ciphertext, E flag + index, tag.
    pkt = struct.pack("!BBHI", 0x80, 200, 6, sa) + enc + struct.pack("!I", 0x80000001) + bytes(10)
    call.a_to_b(40331, 50331, pkt)
    call.write(out, name)


def gen_rtcp_malformed(c, out):
    name = "rtcp_malformed.pcapng"
    v = _Cv(c, name)
    a, b = v.ip(), v.ip()
    sa = v.ssrc("rtcp:ssrc")
    call = Call([m_audio(40340)], [m_audio(50340)], a=a, b=b)
    # An SR that claims two report blocks but carries one.
    sr = bytearray(rtcp_sr(sa, [report_block(v.ssrc("rtcp:ssrc"))]))
    sr[0] = 0x82
    call.a_to_b(40341, 50341, bytes(sr))
    # An SDES item that overruns its chunk.
    bad = bytearray(rtcp_sdes([sdes_chunk(sa, [(SDES["NAME"], v.s("rtcp:sdes/NAME").encode())])]))
    bad[9] = 120
    call.a_to_b(40341, 50341, bytes(bad))
    call.write(out, name)


FIXTURES += [gen_rtcp_compound, gen_rtcp_rsize, gen_rtcp_fb_xr, gen_rtcp_srtcp, gen_rtcp_malformed]


# --- other APP families (US4) --------------------------------------------------------
def _ipv4_canary(v, rule):
    return v.ip(rule)


def _sub_mcptt(v, rule, floor=True, mbs_ssrc=None):
    head = bytes([0x12 if floor else 0x10, 0x00])
    body = head + (struct.pack("!I", 49200) if floor else b"")
    if mbs_ssrc is not None:
        body += struct.pack("!I", mbs_ssrc)
    return body + struct.pack("!I", 49202) + _ipv4_canary(v, rule)


def _sub_mcvideo(v, rule, mbs_ssrc=None):
    body = bytes([0x12, 0x30, 0x00, 0, 0, 0]) + struct.pack("!I", 41000)
    if mbs_ssrc is not None:
        body += struct.pack("!I", mbs_ssrc)
    return body + struct.pack("!II", 41002, 41004) + _ipv4_canary(v, rule)


def _family_call(c, out, name, fmt, msgs, port_a, port_b):
    v = _Cv(c, name)
    a, b = v.ip(), v.ip()
    call = Call([m_floor(port_a, fmt=fmt)], [m_floor(port_b, fmt=fmt)], a=a, b=b)
    s = v.ssrc("rtcp:ssrc")
    for app_name, subtype, fields in msgs(v):
        call.b_to_a(port_b, port_a, app(app_name, subtype, s, b"".join(fields)))
    call.write(out, name, fc_ports=[port_a, port_b] if fmt == "MCPTT" else [], tc_ports=[port_a, port_b] if fmt != "MCPTT" else [])


def gen_app_mcpc(c, out):
    F = app_field

    def msgs(v):
        sess = bytes([3]) + _user(v, "app:mcpc/1")
        return [(b"MCPC", 16, [F(0, _u16(0x0102)), F(1, sess), F(3, _user(v, "app:mcpc/3")), F(5, _user(v, "app:mcpc/5")),
                               F(8, _user(v, "app:mcpc/8")), F(192, v.payload(48, "app:mcpc/192"))]),
                (b"MCPC", 1, [F(6, _u16(2)), F(7, _u16(4)), F(2, ("107 " + v.s("app:mcpc/2")).encode())]),
                (b"MCPC", 2, [F(4, _u16(1))]),
                (b"MCPC", 0, [F(5, b"sip:anonymous@invalid.invalid")])]
    _family_call(c, out, "app_mcpc.pcapng", "MCPTT", msgs, 40402, 50402)


def gen_app_mcmc(c, out):
    F = app_field

    def msgs(v):
        return [(b"MCMC", 0, [F(2, _user(v, "app:mcmc/2")), F(1, v.payload(16, "app:mcmc/1")[:6]),
                              F(0, _sub_mcptt(v, "app:mcmc/0"))]),
                (b"MCMC", 1, [F(2, _user(v, "app:mcmc/2"))]),
                (b"MCMC", 2, [F(2, _user(v, "app:mcmc/2"))]),
                (b"MCMC", 3, [F(1, v.payload(16, "app:mcmc/1")[:6]), F(3, b"\x01")])]
    _family_call(c, out, "app_mcmc.pcapng", "MCPTT", msgs, 40412, 50412)


def gen_app_mcnc(c, out):
    F = app_field

    def msgs(v):
        return [(b"MCNC", 0, [F(0, _u16(1)), F(1, _user(v, "app:mcnc/1")), F(2, b"\x01"), F(3, _user(v, "app:mcnc/3")),
                              F(4, _user(v, "app:mcnc/4"))])]
    _family_call(c, out, "app_mcnc.pcapng", "MCPTT", msgs, 40422, 50422)


def gen_app_mcsc(c, out):
    F = app_field

    def msgs(v):
        return [(b"MCSC", 0, [F(2, _user(v, "app:mcsc/2")), F(1, v.payload(16, "app:mcsc/1")[:8]),
                              F(0, _sub_mcptt(v, "app:mcsc/0", mbs_ssrc=v.ssrc("app:mcsc/0")))]),
                (b"MCSC", 2, [F(2, _user(v, "app:mcsc/2"))]),
                (b"MCSC", 3, [F(1, v.payload(16, "app:mcsc/1")[:8]), F(3, b"\x00")])]
    _family_call(c, out, "app_mcsc.pcapng", "MCPTT", msgs, 40432, 50432)


def gen_app_mcv_tc(c, out):
    F = app_field
    ss = lambda v, rule: struct.pack("!IH", v.ssrc(rule), 0)

    def full(v, fam):
        """Every field of Table 9.2.3.1-1 that a rule changes, with a canary keyed to `fam`."""
        k = lambda i: f"app:{fam}/{i}"
        return [F(4, _user(v, k(4))), F(6, _user(v, k(6))), F(9, _user(v, k(9))), F(11, _track_info_k(v, k(11))),
                F(14, ss(v, k(14))), F(17, _user(v, k(17))), F(18, _user(v, k(18))), F(20, _user(v, k(20))),
                F(21, _user(v, k(21))), F(23, ss(v, k(23))), F(24, ss(v, k(24))),
                F(2, _u16(3) + v.s(k(2), prefix="REJECT").encode())]

    def msgs(v):
        return [(b"MCV0", 16, [F(0, b"\x05\x00"), F(13, _u16(0x8000))] + full(v, "mcv0")),
                (b"MCV1", 0, [F(1, _u16(30)), F(7, _u16(1)), F(3, b"\x01\x02")] + full(v, "mcv1")),
                (b"MCV1", 15, [F(8, _u16(3)), F(13, _u16(0))]),
                (b"MCV2", 0, full(v, "mcv2")),
                (b"MCV2", 4, [F(10, _u16(1)), F(16, b"MCV1\x00\x00"), F(12, b"\x00\x00")])]
    _family_call(c, out, "app_mcv_tc.pcapng", "MCVideo", msgs, 40442, 50442)


def gen_app_mcv345(c, out):
    F = app_field

    def msgs(v):
        return [(b"MCV3", 0, [F(2, _user(v, "app:mcv3/2")), F(1, v.payload(16, "app:mcv3/1")[:6]),
                              F(0, _sub_mcvideo(v, "app:mcv3/0"))]),
                (b"MCV4", 0, [F(0, _u16(0)), F(1, _user(v, "app:mcv4/1")), F(2, b"\x00"), F(3, _user(v, "app:mcv4/3")),
                              F(4, _user(v, "app:mcv4/4"))]),
                (b"MCV5", 0, [F(2, _user(v, "app:mcv5/2")), F(1, v.payload(16, "app:mcv5/1")[:8]),
                              F(0, _sub_mcvideo(v, "app:mcv5/0", mbs_ssrc=v.ssrc("app:mcv5/0")))])]
    _family_call(c, out, "app_mcv345.pcapng", "MCVideo", msgs, 40452, 50452)


def gen_app_mcdm(c, out):
    F = app_field

    def msgs(v):
        sub = bytes([0x10, 0x00]) + struct.pack("!I", 43000) + _ipv4_canary(v, "app:mcdm/0")
        return [(b"MCDM", 0, [F(2, _user(v, "app:mcdm/2")), F(1, v.payload(16, "app:mcdm/1")[:6]), F(0, sub)]),
                (b"MCDM", 3, [F(1, v.payload(16, "app:mcdm/1")[:6]), F(3, b"\x01")])]
    _family_call(c, out, "app_mcdm.pcapng", "MCPTT", msgs, 40462, 50462)


def _track_info_k(v, rule):
    pt = v.s(rule, prefix="PTYPE").encode()
    body = bytes([1, len(pt)]) + pt
    body += b"\0" * (-(len(body) - 2) % 4)
    return body + struct.pack("!I", v.ssrc(rule))


FIXTURES += [gen_app_mcpc, gen_app_mcmc, gen_app_mcnc, gen_app_mcsc, gen_app_mcv_tc, gen_app_mcv345, gen_app_mcdm]


# --- MSRP fixtures (US5) -------------------------------------------------------------
def _msrp_call(c, name, proto="TCP/MSRP"):
    v = _Cv(c, name)
    a, b = v.ip(), v.ip()
    pa, pb = 7000 + (len(name) % 50) * 2, 7100 + (len(name) % 50) * 2
    sa = f"{v.s('sdp:a=path.session-id', prefix='msa')}"
    sb = f"{v.s('sdp:a=path.session-id', prefix='msb')}"
    call = Call([m_msrp(a, pa, sa, proto)], [m_msrp(b, pb, sb, proto)], a=a, b=b)
    # The session ids appear in the a=path of the SDP and in To-Path / From-Path (FR-027).
    v.c.reuse(sa, None, name, "msrp:From-Path")
    v.c.reuse(sb, None, name, "msrp:To-Path")
    scheme = "msrps" if "TLS" in proto else "msrp"
    path_a = f"{scheme}://{_ip(a)}:{pa}/{sa};tcp"
    path_b = f"{scheme}://{_ip(b)}:{pb}/{sb};tcp"
    conn = S.TcpConn(a, b, pa, pb)
    call.cap.extend(conn.handshake())
    return v, call, conn, path_a, path_b, (pa, pb)


def _paths(to, frm):
    return [f"To-Path: {to}", f"From-Path: {frm}"]


def gen_msrp_sds(c, out):
    name = "msrp_sds.pcapng"
    v, call, conn, pa, pb, ports = _msrp_call(c, name)
    tid0, tid1, tid2 = (v.s("msrp:tid", prefix="tx") for _ in range(3))
    mid = v.s("msrp:Message-ID", prefix="mid")
    # TS 24.582 §6.1.1.2.1: the active endpoint binds the connection with an empty SEND.
    call.cap.add(conn.send(0, msrp_request(tid0, "SEND", _paths(pb, pa) + ["Message-ID: " + v.s("msrp:Message-ID", prefix="mid"),
                                                                           "Byte-Range: 1-0/0"])))
    content = v.payload(40, "msrp:content") + b"SDS-TEXT-" + v.s("msrp:content").encode()
    send = msrp_request(tid1, "SEND", _paths(pb, pa) + [f"Message-ID: {mid}", f"Byte-Range: 1-{len(content)}/{len(content)}",
                                                       "Success-Report: yes", "Failure-Report: yes",
                                                       "Content-ID: <" + v.s("msrp:Content-ID") + "@example.net>",
                                                       "Content-Description: " + v.s("msrp:Content-Description"),
                                                       "X-Vendor-Trace: " + v.s("msrp:X-Vendor-Trace")],
                        content, "application/vnd.3gpp.mcdata-signalling")
    call.cap.add(conn.send(0, send))
    call.cap.add(conn.send(1, msrp_response(tid1, 200, "OK " + v.s("msrp:comment"), _paths(pa, pb))))
    call.cap.add(conn.send(1, msrp_request(tid2, "REPORT", _paths(pa, pb) + [f"Message-ID: {mid}", f"Byte-Range: 1-{len(content)}/{len(content)}",
                                                                            "Status: 000 200 " + v.s("msrp:comment")])))
    call.write(out, name, msrp_ports=list(ports))


def gen_msrp_multipart(c, out):
    name = "msrp_multipart.pcapng"
    v, call, conn, pa, pb, ports = _msrp_call(c, name)
    tid = v.s("msrp:tid", prefix="tx")
    body = (b"--bnd7\r\nContent-Type: application/vnd.3gpp.mcdata-signalling\r\n\r\n" + v.payload(24, "msrp:content")
            + b"\r\n--bnd7\r\nContent-Type: application/vnd.3gpp.mcdata-payload\r\n\r\n" + v.s("msrp:content").encode()
            + b"\r\n--bnd7--\r\n")
    call.cap.add(conn.send(0, msrp_request(tid, "SEND", _paths(pb, pa) + ["Message-ID: " + v.s("msrp:Message-ID", prefix="mid"),
                                                                          f"Byte-Range: 1-{len(body)}/{len(body)}"],
                                           body, "multipart/mixed;boundary=bnd7")))
    call.write(out, name, msrp_ports=list(ports))


def gen_msrp_fd(c, out):
    name = "msrp_fd.pcapng"
    v, call, conn, pa, pb, ports = _msrp_call(c, name)
    tid = v.s("msrp:tid", prefix="tx")
    body = v.payload(64, "msrp:content")
    call.cap.add(conn.send(0, msrp_request(tid, "SEND", _paths(pb, pa) + ["Message-ID: " + v.s("msrp:Message-ID", prefix="mid"),
                                                                          f"Byte-Range: 1-{len(body)}/{len(body)}",
                                                                          "Content-Disposition: attachment; filename=" + v.s("msrp:Content-Disposition") + ".pdf"],
                                           body, "application/vnd.3gpp.mcdata-file")))
    call.write(out, name, msrp_ports=list(ports))


def gen_msrp_split(c, out):
    name = "msrp_split.pcapng"
    v, call, conn, pa, pb, ports = _msrp_call(c, name)
    t1, t2 = v.s("msrp:tid", prefix="tx"), v.s("msrp:tid", prefix="tx")
    mid = v.s("msrp:Message-ID", prefix="mid")
    chunk1 = v.payload(1200, "msrp:content")
    chunk2 = v.payload(300, "msrp:content")
    total = len(chunk1) + len(chunk2)
    m1 = msrp_request(t1, "SEND", _paths(pb, pa) + [f"Message-ID: {mid}", f"Byte-Range: 1-{len(chunk1)}/{total}"],
                      chunk1, "text/plain", flag="+")
    m2 = msrp_request(t2, "SEND", _paths(pb, pa) + [f"Message-ID: {mid}", f"Byte-Range: {len(chunk1) + 1}-{total}/{total}"],
                      chunk2, "text/plain")
    for i in range(0, len(m1), 500):  # one chunk across three segments
        call.cap.add(conn.send(0, m1[i:i + 500]))
    call.cap.add(conn.send(0, m2))
    call.write(out, name, msrp_ports=list(ports))


def gen_msrp_tls(c, out):
    name = "msrp_tls.pcapng"
    v, call, conn, pa, pb, ports = _msrp_call(c, name, proto="TCP/TLS/MSRP")
    # TLS application data (FR-029): never recognised, stays zeroed.
    call.cap.add(conn.send(0, b"\x17\x03\x03\x00\x30" + v.payload(48, "msrp:content")))
    call.write(out, name, msrp_ports=list(ports))


def gen_msrp_malformed(c, out):
    name = "msrp_malformed.pcapng"
    v, call, conn, pa, pb, ports = _msrp_call(c, name)
    tid = v.s("msrp:tid", prefix="tx")
    call.cap.add(conn.send(0, msrp_request(tid, "AUTH", _paths(pb, pa) + ["X-Secret: " + v.s("msrp:X-Secret")])))
    tid2 = v.s("msrp:tid", prefix="tx")
    call.cap.add(conn.send(0, f"MSRP {tid2} SEND\r\nbroken line {v.s('msrp:content')}\r\n-------{tid2}$\r\n".encode()))
    call.write(out, name, msrp_ports=list(ports))


FIXTURES += [gen_msrp_sds, gen_msrp_multipart, gen_msrp_fd, gen_msrp_split, gen_msrp_tls, gen_msrp_malformed]

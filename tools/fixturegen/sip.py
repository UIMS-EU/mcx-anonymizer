# SPDX-License-Identifier: GPL-3.0-or-later
"""SIP, SDP and multipart fixtures, with the transport builders they need.

Builders:
  - request() / response(): a SIP message with headers in the given spelling and order,
    compact forms, folding (a value may contain "\\r\\n " continuation lines) and a body;
  - sdp() and multipart();
  - wrap(): an IP packet in Ethernet, GTP-U or GRE; udp_packet(): UDP over IPv4 or IPv6;
  - TcpConn: a TCP connection with seq/ack bookkeeping, retransmission, SACK and gaps;
  - fragment(): IPv4 or IPv6 fragmentation of an IP packet;
  - Capture: a pcapng file with one Ethernet interface.

Every value in a fixture is invented. Addresses come from documentation and private ranges,
names from example.net (RFC 2606). Identity values that a non-keep rule classifies are
canaries, recorded in canaries.json with their rule key (see canary.py).
"""
import json
import struct

import packets as P
import pcapng

CRLF = "\r\n"

# Documentation MACs (RFC 9542 §2.3.2: 00-00-5E-00-53-00 to 00-00-5E-00-53-FF).
MAC_A = bytes.fromhex("00005e005311")
MAC_B = bytes.fromhex("00005e005312")
# Outer tunnel endpoints (RFC 5737 documentation ranges).
TUN_A = bytes([192, 0, 2, 1])
TUN_B = bytes([198, 51, 100, 1])

FIXTURES = []  # (function) registered by the fixture modules of the SIP tasks


# --- SIP, SDP, multipart -----------------------------------------------------------
def message(start, headers, body=b"", content_length="auto"):
    """headers: list of (name, value) pairs or raw header lines (str, without CRLF).
    content_length: "auto" appends Content-Length for the body, an int writes that value,
    None writes no Content-Length header."""
    body = body.encode() if isinstance(body, str) else bytes(body)
    lines = [start]
    for h in headers:
        lines.append(h if isinstance(h, str) else f"{h[0]}: {h[1]}")
    if content_length == "auto":
        lines.append(f"Content-Length: {len(body)}")
    elif content_length is not None:
        lines.append(f"Content-Length: {content_length}")
    return (CRLF.join(lines) + CRLF + CRLF).encode() + body


def request(method, uri, headers, body=b"", **kw):
    return message(f"{method} {uri} SIP/2.0", headers, body, **kw)


def response(code, reason, headers, body=b"", **kw):
    return message(f"SIP/2.0 {code} {reason}", headers, body, **kw)


def sdp(lines):
    return (CRLF.join(lines) + CRLF).encode()


def multipart(boundary, parts, preamble=b"", epilogue=b""):
    """parts: list of (headers, body); headers is a list of (name, value). RFC 2046 §5.1.1."""
    out = bytes(preamble)
    for headers, body in parts:
        body = body.encode() if isinstance(body, str) else bytes(body)
        out += f"{CRLF if out else ''}--{boundary}{CRLF}".encode()
        out += "".join(f"{n}: {v}{CRLF}" for n, v in headers).encode() + CRLF.encode() + body
    out += f"{CRLF}--{boundary}--{CRLF}".encode() + bytes(epilogue)
    return out


# --- IP and tunnels ----------------------------------------------------------------
def udp_packet(src, dst, sport, dport, payload, ident=0x4D58):
    """An unfragmented UDP datagram in IPv4 (4-byte addresses) or IPv6 (16-byte addresses)."""
    if len(src) == 4:
        return P.udp4(src, dst, sport, dport, payload, ident=ident)
    return P.udp6(src, dst, sport, dport, payload)


def wrap(ip_packet, tunnel=None, teid=0x1001):
    """An IP packet in an Ethernet frame, plain or inside GTP-U or GRE over IPv4."""
    v6 = (ip_packet[0] >> 4) == 6
    if tunnel is None:
        return P.ethernet(MAC_B, MAC_A, 0x86DD if v6 else 0x0800, ip_packet)
    if tunnel == "gtpu":
        outer = P.udp4(TUN_A, TUN_B, 2152, 2152, P.gtpu(teid, ip_packet))
    elif tunnel == "gre":
        outer = P.ipv4(TUN_A, TUN_B, 47, P.gre(0x86DD if v6 else 0x0800, ip_packet))
    else:
        raise ValueError(tunnel)
    return P.ethernet(MAC_B, MAC_A, 0x0800, outer)


def fragment(ip_packet, max_payload, ident=0x5A5A):
    """Fragments of an IPv4 or IPv6 packet, each carrying at most max_payload bytes of the
    fragmentable part (a multiple of 8, except the last)."""
    assert max_payload % 8 == 0
    if (ip_packet[0] >> 4) == 4:
        ihl = (ip_packet[0] & 0x0F) * 4
        hdr, data = bytearray(ip_packet[:ihl]), ip_packet[ihl:]
        frags = []
        for off in range(0, len(data), max_payload):
            chunk = data[off:off + max_payload]
            more = off + max_payload < len(data)
            h = bytearray(hdr)
            struct.pack_into("!HHH", h, 2, ihl + len(chunk), ident, (0x2000 if more else 0) | (off // 8))
            h[10:12] = b"\x00\x00"
            h[10:12] = struct.pack("!H", P.inet_checksum(bytes(h)))
            frags.append(bytes(h) + chunk)
        return frags
    # IPv6: the Fragment header (next header 44) follows the fixed header (RFC 8200 §4.5).
    nh, src, dst, data = ip_packet[6], ip_packet[8:24], ip_packet[24:40], ip_packet[40:]
    frags = []
    for off in range(0, len(data), max_payload):
        chunk = data[off:off + max_payload]
        more = off + max_payload < len(data)
        fh = struct.pack("!BBHI", nh, 0, (off // 8) << 3 | (1 if more else 0), ident)
        frags.append(P.ipv6(src, dst, 44, fh + chunk))
    return frags


# --- TCP ---------------------------------------------------------------------------
SYN, FIN, PSH, ACK = 0x02, 0x01, 0x08, 0x10


class TcpConn:
    """One TCP connection between endpoint 0 (a, aport) and endpoint 1 (b, bport)."""

    def __init__(self, a, b, aport, bport, isn=(1000, 500000), tunnel=None):
        self.ep = [(a, aport), (b, bport)]
        self.next = [isn[0], isn[1]]
        self.tunnel = tunnel

    def _ip(self, d, seq, ack, flags, payload=b"", options=b""):
        (s, sp), (t, tp) = self.ep[d], self.ep[1 - d]
        seg_len = 20 + len(options) + len(payload)
        if len(s) == 4:
            pkt = P.ipv4(s, t, 6, P.tcp(sp, tp, seq, ack, flags, payload, options,
                                        P.pseudo4(s, t, 6, seg_len)))
        else:
            pkt = P.ipv6(s, t, 6, P.tcp(sp, tp, seq, ack, flags, payload, options,
                                        P.pseudo6(s, t, 6, seg_len)))
        return wrap(pkt, self.tunnel)

    def handshake(self):
        """SYN, SYN/ACK, ACK with SACK-permitted (RFC 2018 §2)."""
        sackok = b"\x04\x02\x01\x01"
        f = [self._ip(0, self.next[0], 0, SYN, options=sackok)]
        self.next[0] += 1
        f.append(self._ip(1, self.next[1], self.next[0], SYN | ACK, options=sackok))
        self.next[1] += 1
        f.append(self._ip(0, self.next[0], self.next[1], ACK))
        return f

    def send(self, d, payload, seq=None, ack=None, sack=(), advance=True):
        """A data segment of direction d. seq defaults to the next sequence number (a smaller
        explicit seq is a retransmission or an overlap); sack lists (left, right) edges in the
        peer's sequence space (RFC 2018 §3)."""
        seq = self.next[d] if seq is None else seq
        ack = self.next[1 - d] if ack is None else ack
        opts = b""
        if sack:
            opts = b"\x01\x01" + bytes([5, 2 + 8 * len(sack)]) + b"".join(
                struct.pack("!II", left, right) for left, right in sack)
            opts += b"\x01" * (-len(opts) % 4)
        frame = self._ip(d, seq, ack, PSH | ACK, payload, opts)
        if advance:
            self.next[d] = max(self.next[d], seq + len(payload))
        return frame

    def skip(self, d, n):
        """Advances direction d by n bytes without emitting them (a lost segment)."""
        self.next[d] += n

    def ack(self, d, ack=None, sack=()):
        return self.send(d, b"", ack=ack, sack=sack)

    def fin(self, d):
        f = self._ip(d, self.next[d], self.next[1 - d], FIN | ACK)
        self.next[d] += 1
        return f


# --- capture file ------------------------------------------------------------------
class Capture:
    """A pcapng file with one Ethernet interface; packets 1 ms apart unless timed."""

    def __init__(self, snaplen=262144, start_us=1_791_963_735_000_000):
        self.w = pcapng.Writer()
        self.snaplen = snaplen
        self.ts = start_us
        self.blocks = []

    def add(self, frame, ts_us=None):
        self.ts = self.ts + 1000 if ts_us is None else ts_us
        self.blocks.append(self.w.epb(0, self.ts, frame))

    def extend(self, frames):
        for f in frames:
            self.add(f)

    def bytes(self):
        return self.w.shb() + self.w.idb(1, self.snaplen) + b"".join(self.blocks)


def gen(c, out):
    for fn in FIXTURES:
        fn(c, out)


# --- SIP over UDP fixtures ---------------------------------------------------
class _Cv:
    """Canary helper for one fixture file: every value records its rule key."""

    def __init__(self, c, fname):
        self.c, self.f = c, fname

    def s(self, rule, prefix="CANARY"):
        return self.c.string(None, self.f, prefix, rule=rule)

    def label(self, rule):
        """A host-name label (letters, digits, hyphens)."""
        return self.c.string(None, self.f, "cnry", rule=rule)

    def ip(self, rule):
        return self.c.ipv4(None, self.f, rule=rule)

    def num(self, rule, digits):
        return self.c.number(self.f, digits, rule)

    def bin(self, rule):
        return self.c.binary(self.f, rule)

    def hexs(self, rule, n, upper=False):
        v = "".join(self.c.rng.choice("0123456789abcdef") for _ in range(n))
        return self.c.text(v.upper() if upper else v, self.f, rule)


def ladder_udp(c, fname):
    """The SIP methods of US1 with a canary in every component and parameter whose rule is not
    keep. Returns the list of SIP messages (bytes)."""
    v = _Cv(c, fname)
    dom = v.label("sip:From.uri") + ".example.net"
    alice = v.s("sip:From.uri")
    bob = v.s("sip:To.uri")
    ua_ip = v.ip("sip:Via.sent-by")
    pcscf = v.label("sip:Route.uri") + ".example.net"
    callid = v.s("sip:Call-ID.value") + "@" + v.label("sip:Call-ID.value") + ".example.net"
    ftag = v.s("sip-param:From;tag")
    ttag = v.s("sip-param:To;tag")

    def via(branch_rule="sip-param:Via;branch"):
        return ("Via", f"SIP/2.0/UDP {ua_ip}:5060;branch=z9hG4bK{v.s(branch_rule)};"
                       f"received={v.ip('sip-param:Via;received')};maddr={v.label('sip-param:Via;maddr')}.example.net;rport")

    def base(method, cseq, to_tag=False):
        return [via(), ("Max-Forwards", "70"),
                ("From", f"\"{v.s('sip:From.display-name')}\" <sip:{alice}@{dom}>;tag={ftag}"),
                ("To", f"\"{v.s('sip:To.display-name')}\" <sip:{bob}@{dom}>" + (f";tag={ttag}" if to_tag else "")),
                ("Call-ID", callid), ("CSeq", f"{cseq} {method}")]

    def resp(code, reason, cseq, method, extra=(), body=b""):
        return response(code, reason, base(method, cseq, True) + list(extra), body)

    msgs = []
    imei_tac, imei_snr = v.num("tag:+sip.instance", 8), v.num("tag:+sip.instance", 6)
    impi = f"{v.s('sip-param:Authorization;username')}@{v.label('sip-param:Authorization;realm')}.example.net"
    reg = base("REGISTER", 1) + [
        ("Contact", f"<sip:{v.s('sip:Contact.uri')}@{v.ip('sip:Contact.uri')}:5060;"
                    f"gr=urn:uuid:{_uuid(c, v, 'uri-param:gr')}>;expires=600;"
                    f"+sip.instance=\"<urn:gsma:imei:{imei_tac}-{imei_snr}-0>\";+g.3gpp.mcptt;"
                    f"+g.3gpp.registration-token=\"{v.s('tag:+g.3gpp.registration-token')}\";"
                    f"+g.vendor.secret=\"{v.s('tag:+g.vendor.secret')}\""),
        ("Authorization", f"Digest username=\"{impi}\", realm=\"{v.label('sip-param:Authorization;realm')}.example.net\", "
                          f"nonce=\"{v.hexs('sip-param:Authorization;nonce', 32)}\", uri=\"sip:{v.label('sip-param:Authorization;uri')}.example.net\", "
                          f"response=\"{v.hexs('sip-param:Authorization;response', 32)}\", algorithm=AKAv1-MD5, qop=auth, nc=00000001, "
                          f"cnonce=\"{v.hexs('sip-param:Authorization;cnonce', 16)}\", opaque=\"{v.hexs('sip-param:Authorization;opaque', 20)}\", "
                          f"auts=\"{v.hexs('sip-param:Authorization;auts', 28)}\""),
        ("Security-Client", f"ipsec-3gpp; alg=hmac-sha-1-96; spi-c={v.bin('sip-param:Security-Client;spi-c')}; "
                            f"spi-s={v.bin('sip-param:Security-Client;spi-s')}; port-c=5062; port-s=5064"),
        ("P-Access-Network-Info", f"3GPP-E-UTRAN-FDD; utran-cell-id-3gpp={v.hexs('sip-param:P-Access-Network-Info;utran-cell-id-3gpp', 13, True)}; "
                                  f"UE-local-IP-address=\"{v.ip('sip-param:P-Access-Network-Info;ue-local-ip-address')}\""),
        ("P-Visited-Network-ID", f"\"{v.s('sip:P-Visited-Network-ID.value')}\""),
        ("Path", f"<sip:{v.label('sip:Path.uri')}.example.net;lr>"),
        ("User-Agent", v.s("sip:User-Agent")),
        ("Supported", "path, gruu, sec-agree"), ("Require", "sec-agree"), ("Expires", "600"),
        ("X-Vendor-Id", v.s("sip:X-Vendor-Id")),
    ]
    msgs.append(request("REGISTER", f"sip:{pcscf}", reg))
    msgs.append(resp(401, "Unauthorized", 1, "REGISTER", [
        ("WWW-Authenticate", f"Digest realm=\"{v.label('sip-param:WWW-Authenticate;realm')}.example.net\", "
                             f"nonce=\"{v.hexs('sip-param:WWW-Authenticate;nonce', 32)}\", algorithm=AKAv1-MD5, qop=\"auth\", "
                             f"opaque=\"{v.hexs('sip-param:WWW-Authenticate;opaque', 20)}\", "
                             f"ik=\"{v.hexs('sip-param:WWW-Authenticate;ik', 32)}\", ck=\"{v.hexs('sip-param:WWW-Authenticate;ck', 32)}\""),
        ("Security-Server", f"ipsec-3gpp; q=0.1; alg=hmac-sha-1-96; spi-c={v.bin('sip-param:Security-Server;spi-c')}; "
                            f"spi-s={v.bin('sip-param:Security-Server;spi-s')}; port-c=5066; port-s=5068"),
        ("Server", v.s("sip:Server")),
        ("Warning", f"399 {v.label('sip:Warning.agent')}.example.net \"{v.s('sip:Warning.text')}\"")]))
    msgs.append(request("REGISTER", f"sip:{pcscf}", base("REGISTER", 2) + [
        ("Contact", f"<sip:{v.s('sip:Contact.uri')}@{ua_ip}:5060>;expires=600"),
        ("Security-Verify", f"ipsec-3gpp; q=0.1; alg=hmac-sha-1-96; spi-c={v.bin('sip-param:Security-Verify;spi-c')}; "
                            f"spi-s={v.bin('sip-param:Security-Verify;spi-s')}; port-c=5066; port-s=5068")]))
    msgs.append(resp(200, "OK", 2, "REGISTER", [
        ("P-Associated-URI", f"<sip:{v.s('sip:P-Associated-URI.uri')}@{dom}>, <tel:+{v.num('sip:P-Associated-URI.uri', 11)}>"),
        ("Service-Route", f"<sip:orig@{v.label('sip:Service-Route.uri')}.example.net;lr>"),
        ("Contact", f"<sip:{alice}@{ua_ip}:5060>;expires=600;pub-gruu=\"sip:{v.s('sip-param:Contact;pub-gruu')}@{dom};gr\";"
                    f"temp-gruu=\"sip:{v.s('sip-param:Contact;temp-gruu')}@{dom};gr\""),
        ("Authentication-Info", f"nextnonce=\"{v.hexs('sip-param:Authentication-Info;nextnonce', 32)}\", qop=auth, "
                                f"rspauth=\"{v.hexs('sip-param:Authentication-Info;rspauth', 32)}\", "
                                f"cnonce=\"{v.hexs('sip-param:Authentication-Info;cnonce', 16)}\", nc=00000001"),
        ("Date", "Sat, 13 Nov 2010 23:29:00 GMT")]))
    msgs.append(request("PUBLISH", f"sip:{bob}@{dom}", base("PUBLISH", 1) + [
        ("Event", f"presence;id={v.s('sip-param:Event;id')}"), ("SIP-If-Match", v.s("sip:SIP-If-Match.value")),
        ("Expires", "3600"), ("Content-Type", "application/pidf+xml")],
        f"<presence><tuple id=\"{v.s('body:application/pidf+xml')}\"/></presence>"))
    msgs.append(resp(200, "OK", 1, "PUBLISH", [("SIP-ETag", v.s("sip:SIP-ETag.value")), ("Expires", "3600")]))
    msgs.append(request("SUBSCRIBE", f"sip:{bob}@{dom}", base("SUBSCRIBE", 1) + [
        ("Event", "xcap-diff"), ("Expires", "3600"),
        ("Accept-Contact", "*;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mcptt,"
                           f"urn%3Aurn-7%3A3gpp-service.ims.icsi.{v.label('tag:+g.3gpp.icsi-ref')}\";require;explicit"),
        ("P-Preferred-Service", "urn:urn-7:3gpp-service.ims.icsi.mcptt"),
        ("Organization", v.s("sip:Organization"))]))
    msgs.append(resp(200, "OK", 1, "SUBSCRIBE", [("Expires", "3600")]))
    msgs.append(request("NOTIFY", f"sip:{alice}@{ua_ip}:5060", base("NOTIFY", 2, True) + [
        ("Event", "xcap-diff"), ("Subscription-State", "active;expires=3599"),
        ("Content-Type", "application/xcap-diff+xml")],
        f"<xcap-diff><document sel=\"{v.s('body:application/xcap-diff+xml')}\"/></xcap-diff>"))
    msgs.append(resp(200, "OK", 2, "NOTIFY"))
    # INVITE with a multipart body: SDP offer and MCPTT information.
    boundary = v.s("sip-param:Content-Type;boundary")
    offer_c = v.ip("sdp:c=.address")
    answer_c = v.ip("sdp:c=.address")
    sdp_offer = sdp([
        "v=0", f"o={v.s('sdp:o=.username')} {v.num('sdp:o=.sess-id', 10)} 1 IN IP4 {v.ip('sdp:o=.address')}",
        f"s={v.s('sdp:s=')}", f"i={v.s('sdp:i=')}", f"u=http://{v.label('sdp:u=')}.example.net/",
        f"e={v.s('sdp:e=')}@example.net", f"p=+{v.num('sdp:p=', 11)}", f"c=IN IP4 {offer_c}", "t=0 0",
        f"k=clear:{v.s('sdp:k=')}", "m=audio 49170 RTP/AVP 97", "i=speech",
        f"a=rtcp:49171 IN IP4 {v.ip('sdp:a=rtcp.address')}", "a=rtpmap:97 AMR-WB/16000",
        f"a=ssrc:{v.bin('sdp:a=ssrc.ssrc-id')} cname:{v.s('sdp:a=ssrc.cname')}",
        f"a=candidate:1 1 UDP 2130706431 {v.ip('sdp:a=candidate.address')} 49170 typ host",
        f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{v.s('sdp:a=crypto')}",
        f"a=key-mgmt:mikey {v.s('sdp:a=key-mgmt')}", f"a=ice-ufrag:{v.s('sdp:a=ice-ufrag')}",
        f"a=ice-pwd:{v.s('sdp:a=ice-pwd')}", f"a=fingerprint:sha-256 {v.s('sdp:a=fingerprint')}",
        f"a=tool:{v.s('sdp:a=tool')}", f"a=x-vendor:{v.s('sdp:a=x-vendor')}",
        "m=application 49172 udp MCPTT",
        f"a=fmtp:MCPTT mc_queueing;mc_priority=5;mc_floor_ssrc={v.bin('sdp:a=fmtp:MCPTT.mc_floor_ssrc')}"])
    body = multipart(boundary, [([("Content-Type", "application/sdp")], sdp_offer),
                                ([("Content-Type", "application/vnd.3gpp.mcptt-info+xml"),
                                  ("Content-ID", f"<{v.s('sip:Content-ID.value')}@example.net>")],
                                 f"<mcptt-info><mcpttURI>sip:{v.s('body:application/vnd.3gpp.mcptt-info+xml')}@x</mcpttURI></mcptt-info>")],
                     preamble=f"{v.s('body:preamble')}\r\n".encode())
    inv = base("INVITE", 1) + [
        ("Contact", f"<sip:{alice}@{ua_ip}:5060>;+g.3gpp.mcptt"),
        ("P-Preferred-Identity", f"\"{v.s('sip:P-Preferred-Identity.display-name')}\" <sip:{v.s('sip:P-Preferred-Identity.uri')}@{dom}>"),
        ("P-Asserted-Identity", f"<sip:+{v.num('sip:P-Asserted-Identity.uri', 11)}@{dom};user=phone>"),
        ("Referred-By", f"<sip:{v.s('sip:Referred-By.uri')}@{dom}>;cid=\"{v.s('sip-param:Referred-By;cid')}@{dom}\""),
        ("History-Info", f"<sip:{v.s('sip:History-Info.uri')}@{dom}>;index=1"),
        ("P-Charging-Vector", f"icid-value={v.s('sip-param:P-Charging-Vector;icid-value')};"
                              f"icid-generated-at={v.ip('sip-param:P-Charging-Vector;icid-generated-at')};"
                              f"orig-ioi={v.label('sip-param:P-Charging-Vector;orig-ioi')}.example.net"),
        ("P-Charging-Function-Addresses", f"ccf={v.ip('sip-param:P-Charging-Function-Addresses;ccf')};"
                                          f"ecf={v.label('sip-param:P-Charging-Function-Addresses;ecf')}.example.net"),
        ("Session-ID", f"{v.hexs('sip:Session-ID.value', 32)};remote={v.hexs('sip-param:Session-ID;remote', 32)}"),
        ("Origination-Id", _uuid(c, v, "sip:Origination-Id.value")),
        ("Subject", v.s("sip:Subject")), ("s", v.s("sip:Subject")),
        ("Call-Info", f"<http://{v.label('sip:Call-Info.uri')}.example.net/i.png>;purpose=icon"),
        ("Alert-Info", "<file:///dev/null>"),
        ("Content-Type", f"multipart/mixed;boundary={boundary}")]
    msgs.append(request("INVITE", f"sip:{bob}@{dom}", inv, body))
    msgs.append(resp(100, "Trying", 1, "INVITE"))
    msgs.append(resp(180, f"Ringing {v.s('sip:reason-phrase')}", 1, "INVITE",
                     [("RSeq", "1"), ("Require", "100rel"), ("Contact", f"<sip:{bob}@{v.ip('sip:Contact.uri')}:5060>")]))
    msgs.append(request("PRACK", f"sip:{bob}@{dom}", base("PRACK", 2, True) + [("RAck", "1 1 INVITE")]))
    msgs.append(resp(200, "OK", 2, "PRACK"))
    answer = sdp(["v=0", f"o=- {v.num('sdp:o=.sess-id', 10)} 7 IN IP4 {v.ip('sdp:o=.address')}", "s=-",
                  f"c=IN IP4 {answer_c}", "t=0 0", "m=audio 50170 RTP/AVP 97",
                  "a=rtpmap:97 AMR-WB/16000", "m=application 50172 udp MCPTT",
                  f"a=fmtp:MCPTT mc_queueing:mc_ssrc={v.bin('sdp:a=fmtp:MCPTT.mc_ssrc')}"])
    msgs.append(resp(200, "OK", 1, "INVITE", [("Contact", f"<sip:{bob}@{v.ip('sip:Contact.uri')}:5060>"),
                                               ("Content-Type", "application/sdp")], answer))
    msgs.append(request("ACK", f"sip:{bob}@{dom}", base("ACK", 1, True)))
    msgs.append(request("UPDATE", f"sip:{bob}@{dom}", base("UPDATE", 3, True) + [("Session-Expires", "1800;refresher=uac")]))
    msgs.append(resp(200, "OK", 3, "UPDATE", [("Session-Expires", "1800;refresher=uac")]))
    msgs.append(request("INFO", f"sip:{bob}@{dom}", base("INFO", 4, True) + [
        ("Info-Package", "g.3gpp.mcptt-info"), ("Content-Type", "application/vnd.3gpp.mcptt-info+xml"),
        ("Content-Disposition", "Info-Package")], f"<mcptt-info>{v.s('body:application/vnd.3gpp.mcptt-info+xml')}</mcptt-info>"))
    msgs.append(resp(200, "OK", 4, "INFO"))
    msgs.append(request("REFER", f"sip:{bob}@{dom}", base("REFER", 5, True) + [
        ("Refer-To", f"<sip:{v.s('sip:Refer-To.uri')}@{dom}?Replaces={v.s('uri-param:headers')}>"),
        ("Target-Dialog", f"{callid};local-tag={ftag};remote-tag={ttag}"), ("Refer-Sub", "false")]))
    msgs.append(resp(202, "Accepted", 5, "REFER"))
    msgs.append(request("BYE", f"sip:{bob}@{dom}", base("BYE", 6, True) + [
        ("Reason", f"SIP;cause=200;text=\"{v.s('sip-param:Reason;text')}\"")]))
    msgs.append(resp(200, "OK", 6, "BYE"))
    msgs.append(request("MESSAGE", f"sip:{bob}@{dom}", base("MESSAGE", 7) + [
        ("In-Reply-To", f"{v.s('sip:In-Reply-To.value')}@example.net"),
        ("Content-Type", "application/vnd.3gpp.mcdata-signalling")], v.s("body:application/vnd.3gpp.mcdata-signalling")))
    msgs.append(resp(200, "OK", 7, "MESSAGE"))
    msgs.append(request("OPTIONS", f"sip:{bob}@{dom}", base("OPTIONS", 8) + [("Accept", "application/sdp")]))
    msgs.append(resp(200, "OK", 8, "OPTIONS", [("Allow", "INVITE, ACK, CANCEL, BYE, OPTIONS, MESSAGE"),
                                               ("Accept", "application/sdp")]))
    msgs.append(request("INVITE", f"sip:{bob}@{dom}", base("INVITE", 9) + [("Contact", f"<sip:{alice}@{ua_ip}:5060>")]))
    msgs.append(request("CANCEL", f"sip:{bob}@{dom}", base("CANCEL", 9)))
    msgs.append(resp(200, "OK", 9, "CANCEL"))
    msgs.append(resp(487, "Request Terminated", 9, "INVITE"))
    msgs.append(request("ACK", f"sip:{bob}@{dom}", base("ACK", 9, True)))
    # The audio flows the offer and the answer announce (RTP, RFC 3550 §5.1), for the
    # SDP-to-RTP check of the integrity test.
    flows = [(offer_c, 49170, answer_c, 50170), (answer_c, 50170, offer_c, 49170)]
    return msgs, flows


def rtp(seq, ssrc, payload_type=97, payload=b"\x00" * 20):
    return struct.pack("!BBHII", 0x80, payload_type, seq, 160 * seq, ssrc) + payload


def _uuid(c, v, rule):
    h = "".join(c.rng.choice("0123456789abcdef") for _ in range(32))
    u = f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"
    return c.text(u, v.f, rule)


def _ip4(text):
    return bytes(int(x) for x in text.split("."))


UA = bytes([10, 20, 1, 10])
PCSCF = bytes([10, 20, 2, 20])
UA6 = bytes.fromhex("fd000000000000000000000000000a10")
PCSCF6 = bytes.fromhex("fd000000000000000000000000000b20")


def gen_udp(c, out):
    for name, tunnel, v6 in (("sip_udp_ipv4.pcapng", None, False), ("sip_udp_ipv6.pcapng", None, True),
                             ("sip_udp_gtpu.pcapng", "gtpu", False), ("sip_udp_gre.pcapng", "gre", True)):
        cap = Capture()
        a, b = (UA6, PCSCF6) if v6 else (UA, PCSCF)
        msgs, flows = ladder_udp(c, name)
        for m in msgs:
            src, dst = (a, b) if m.startswith(b"SIP/2.0") is False else (b, a)
            cap.add(wrap(udp_packet(src, dst, 5060, 5060, m), tunnel))
        for i, (s_ip, sp, d_ip, dp) in enumerate(flows * 2):
            pkt = P.udp4(_ip4(s_ip), _ip4(d_ip), sp, dp, rtp(i + 1, 0x5A17C0D0 + i % 2))
            cap.add(wrap(pkt, tunnel))
        with open(f"{out}/{name}", "wb") as fh:
            fh.write(cap.bytes())


FIXTURES.append(gen_udp)


# --- rule coverage fixture ------------------------------------------
def gen_coverage(c, out):
    """sip_udp_coverage.pcapng: a canary for every rule that changes a value and that the US1
    ladder does not exercise (headers, parameters, SDP attributes, feature tags, body types),
    so that test_rule_canary_coverage finds one per rule and test_sip_udp checks that none
    survives. Transport ports follow the port policy and have no canary (FR-020)."""
    f = "sip_udp_coverage.pcapng"
    v = _Cv(c, f)
    dom = "cov.example.net"
    ua, core = bytes([10, 31, 0, 1]), bytes([10, 31, 0, 2])
    callid = f"{v.s('sip:Call-ID.value')}@{dom}"

    def host(rule):
        return f"{v.label(rule)}.example.net"

    def uri(rule):
        return f"sip:{v.s(rule)}@{host(rule)}"

    def disp(rule):
        return f"\"{v.s(rule)}\""

    def base(method, cseq):
        return [("Via", f"SIP/2.0/UDP 10.31.0.1:5060;branch=z9hG4bK{v.s('sip-param:Via;branch')};"
                        f"tokenized-by={host('sip-param:Via;tokenized-by')}"),
                ("Max-Forwards", "70"),
                ("From", f"<sip:caller@{dom}>;tag={v.s('sip-param:From;tag')}"),
                ("To", f"<sip:callee@{dom}>"), ("Call-ID", callid), ("CSeq", f"{cseq} {method}")]

    msgs = []
    # Identity headers with display names and URIs (FR-009, FR-010).
    names = [
        ("Additional-Identity", True, True), ("Contact", True, False), ("History-Info", True, False),
        ("P-Asserted-Identity", True, False), ("P-Associated-URI", True, False),
        ("P-Called-Party-ID", True, True), ("P-Profile-Key", True, True), ("P-Served-User", True, True),
        ("Path", True, False), ("Permission-Missing", True, True), ("Record-Route", True, True),
        ("Refer-To", True, False), ("Referred-By", True, False), ("Reply-To", True, True),
        ("Route", True, False), ("Service-Route", True, False)]
    hdrs = []
    for name, has_disp, has_uri in names:
        u = uri(f"sip:{name}.uri") if has_uri else f"sip:plain@{dom}"
        value = f"{disp(f'sip:{name}.display-name')} <{u};lr>" if name in ("Path", "Record-Route", "Route", "Service-Route") \
            else f"{disp(f'sip:{name}.display-name')} <{u}>"
        if name == "Record-Route":
            value += f";tokenized-by={host('sip-param:Record-Route;tokenized-by')}"
        hdrs.append((name, value))
    hdrs += [
        ("P-Refused-URI-List", f"{disp('sip:P-Refused-URI-List.display-name')} <{uri('sip:P-Refused-URI-List.uri')}>;"
                               f"members=\"<{uri('sip-param:P-Refused-URI-List;members')}>\""),
        ("P-User-Database", f"<sip:{host('sip:P-User-Database.uri')}>"),
        # SIP URIs, so that the URI rules run (an http URI removes the header).
        ("Alert-Info", f"<{uri('sip:Alert-Info.uri')}>"),
        ("Error-Info", f"<{uri('sip:Error-Info.uri')}>"),
        ("Geolocation", f"<{uri('sip:Geolocation.uri')}>"),
        ("Trigger-Consent", f"<{uri('sip:Trigger-Consent.uri')}>;target-uri=\"{uri('sip-param:Trigger-Consent;target-uri')}\""),
        ("P-Asserted-Service", f"<{uri('sip:P-Asserted-Service.uri')}>"),
        ("P-Preferred-Service", f"<{uri('sip:P-Preferred-Service.uri')}>"),
        ("P-Private-Network-Indication", host("sip:P-Private-Network-Indication.value")),
        ("Call-Info", f"<sip:info@{dom}>;purpose=info;call-reason=\"{v.s('sip-param:Call-Info;call-reason')}\";"
                      f"integrity=\"{v.s('sip-param:Call-Info;integrity')}\""),
        ("Reason", f"SIP;cause=200;ppi={v.s('sip-param:Reason;ppi')}")]
    # URI parameters (FR-007): maddr is a host, phone-context a domain.
    hdrs.append(("P-Asserted-Identity", f"<sip:alias@{dom};maddr={host('uri-param:maddr')}>, "
                                        f"<tel:5551234;phone-context={host('uri-param:phone-context')}>"))
    # Feature tags (FR-008): domain-valued tags and the removed description.
    hdrs.append(("Contact", f"<sip:caller@10.31.0.1:5060>;+g.3gpp.home-visited=\"{host('tag:+g.3gpp.home-visited')}\";"
                            f"+g.3gpp.loopback=\"{host('tag:+g.3gpp.loopback')}\";description=\"{v.s('tag:description')}\""))
    msgs.append(request("OPTIONS", f"sip:callee@{dom}", base("OPTIONS", 1) + hdrs))
    msgs.append(response(200, "OK", base("OPTIONS", 1)))

    # Dialog references (FR-011), charging and access network (FR-015), removed headers.
    def tag(rule):
        return v.s(rule)
    msgs.append(request("INVITE", f"sip:callee@{dom}", base("INVITE", 2) + [
        ("Contact", f"<sip:caller@10.31.0.1:5060>"),
        ("Join", f"{v.s('sip:Join.value')}@{dom};from-tag={tag('sip-param:Join;from-tag')};to-tag={tag('sip-param:Join;to-tag')}"),
        ("Replaces", f"{v.s('sip:Replaces.value')}@{dom};from-tag={tag('sip-param:Replaces;from-tag')};"
                     f"to-tag={tag('sip-param:Replaces;to-tag')}"),
        ("Target-Dialog", f"{v.s('sip:Target-Dialog.value')}@{dom};local-tag={tag('sip-param:Target-Dialog;local-tag')};"
                          f"remote-tag={tag('sip-param:Target-Dialog;remote-tag')}"),
        ("P-Access-Network-Info", f"3GPP-GERAN; cgi-3gpp={v.hexs('sip-param:P-Access-Network-Info;cgi-3gpp', 14, True)}"),
        ("P-Access-Network-Info", f"3GPP-UTRAN-FDD; utran-sai-3gpp={v.hexs('sip-param:P-Access-Network-Info;utran-sai-3gpp', 14, True)}"),
        ("P-Access-Network-Info", f"3GPP2-1X; ci-3gpp2={v.hexs('sip-param:P-Access-Network-Info;ci-3gpp2', 16, True)}"),
        ("P-Access-Network-Info", f"3GPP2-1X-Femto; ci-3gpp2-femto={v.hexs('sip-param:P-Access-Network-Info;ci-3gpp2-femto', 16, True)}"),
        ("P-Access-Network-Info", f"IEEE-802.11; i-wlan-node-id={v.hexs('sip-param:P-Access-Network-Info;i-wlan-node-id', 12)}"),
        ("P-Access-Network-Info", f"ADSL; dsl-location=\"{v.s('sip-param:P-Access-Network-Info;dsl-location')}\""),
        ("P-Access-Network-Info", f"DOCSIS; eth-location=\"{v.s('sip-param:P-Access-Network-Info;eth-location')}\""),
        ("P-Access-Network-Info", f"GPON; fiber-location=\"{v.s('sip-param:P-Access-Network-Info;fiber-location')}\""),
        ("P-Access-Network-Info", f"GSTN; gstn-location=\"{v.s('sip-param:P-Access-Network-Info;gstn-location')}\""),
        ("P-Access-Network-Info", f"DVB-RCS2; dvb-rcs2-node-id=\"{v.s('sip-param:P-Access-Network-Info;dvb-rcs2-node-id')}\""),
        ("P-Access-Network-Info", f"IEEE-802.11; operator-specific-GI=\"{v.s('sip-param:P-Access-Network-Info;operator-specific-gi')}\""),
        ("P-Access-Network-Info", f"3GPP-NR-SAT; satellite-id={v.hexs('sip-param:P-Access-Network-Info;satellite-id', 8)}"),
        ("P-Access-Network-Info", f"3GPP-NR-U2N-RELAY; u2n-relay-id=\"{v.hexs('sip-param:P-Access-Network-Info;u2n-relay-id', 12)}\""),
        ("P-Access-Network-Info", f"IEEE-802.11; epdg-ip-address=\"{v.ip('sip-param:P-Access-Network-Info;epdg-ip-address')}\""),
        ("Cellular-Network-Info", f"3GPP-E-UTRAN-FDD;utran-cell-id-3gpp={v.hexs('sip-param:Cellular-Network-Info;utran-cell-id-3gpp', 15, True)}"),
        ("Cellular-Network-Info", f"3GPP-GERAN;cgi-3gpp={v.hexs('sip-param:Cellular-Network-Info;cgi-3gpp', 14, True)}"),
        ("Cellular-Network-Info", f"3GPP2-1X;ci-3gpp2={v.hexs('sip-param:Cellular-Network-Info;ci-3gpp2', 16, True)}"),
        ("Cellular-Network-Info", f"3GPP2-1X-Femto;ci-3gpp2-femto={v.hexs('sip-param:Cellular-Network-Info;ci-3gpp2-femto', 16, True)}"),
        ("P-Charging-Vector", ";".join([f"icid-value={v.s('sip-param:P-Charging-Vector;icid-value')}"] + [
            f"{p}={v.s('sip-param:P-Charging-Vector;' + p)}" for p in
            ("5gscid", "auth-token", "bcid", "dslcid", "ecid", "gcid", "related-icid", "term-ioi", "transit-ioi")] + [
            f"{p}={host('sip-param:P-Charging-Vector;' + p)}" for p in
            ("bras", "ggsn", "ip-edge", "pdngw", "related-icid-generated-at", "smf")])),
        ("P-Charging-Function-Addresses", f"ccf={host('sip-param:P-Charging-Function-Addresses;ccf')};"
                                          f"ccf-2={host('sip-param:P-Charging-Function-Addresses;ccf-2')};"
                                          f"ecf-2={v.ip('sip-param:P-Charging-Function-Addresses;ecf-2')}"),
        ("Relayed-Charge", ";".join([f"icid-value={v.s('sip-param:Relayed-Charge;icid-value')}"] + [
            f"{p}={v.s('sip-param:Relayed-Charge;' + p)}" for p in ("orig-ioi", "related-icid", "term-ioi", "transit-ioi")] + [
            f"{p}={host('sip-param:Relayed-Charge;' + p)}" for p in ("icid-generated-at", "related-icid-generated-at")])),
        ("Identity", v.s("sip:Identity")), ("P-Media-Authorization", v.hexs("sip:P-Media-Authorization", 24)),
        ("Geolocation-Routing", v.s("sip:Geolocation-Routing")), ("Restoration-Info", v.s("sip:Restoration-Info")),
        ("Service-Interact-Info", v.s("sip:Service-Interact-Info")), ("User-to-User", v.hexs("sip:User-to-User", 20)),
        ("Content-Type", "application/sdp")], _coverage_sdp(v)))
    msgs.append(response(200, "OK", base("INVITE", 2)))

    # Credentials (FR-013) and sec-agree (FR-014) in their proxy forms.
    msgs.append(response(407, "Proxy Authentication Required", base("MESSAGE", 3) + [
        ("Proxy-Authenticate", f"Digest realm=\"{host('sip-param:Proxy-Authenticate;realm')}\", "
                               f"nonce=\"{v.hexs('sip-param:Proxy-Authenticate;nonce', 32)}\", algorithm=AKAv1-MD5, qop=\"auth\", "
                               f"opaque=\"{v.hexs('sip-param:Proxy-Authenticate;opaque', 20)}\", "
                               f"ik=\"{v.hexs('sip-param:Proxy-Authenticate;ik', 32)}\", ck=\"{v.hexs('sip-param:Proxy-Authenticate;ck', 32)}\""),
        ("Security-Server", f"ipsec-3gpp; q=0.1; alg=hmac-sha-1-96; spi-c=1111; spi-s=2222; port-c=5066; port-s=5068; "
                            f"d-ver=\"{v.hexs('sip-param:Security-Server;d-ver', 32)}\"")]))
    impi = f"{v.s('sip-param:Proxy-Authorization;username')}@{dom}"
    msgs.append(request("MESSAGE", f"sip:callee@{dom}", base("MESSAGE", 4) + [
        ("Proxy-Authorization", f"Digest username=\"{impi}\", realm=\"{host('sip-param:Proxy-Authorization;realm')}\", "
                                f"nonce=\"{v.hexs('sip-param:Proxy-Authorization;nonce', 32)}\", "
                                f"uri=\"{uri('sip-param:Proxy-Authorization;uri')}\", "
                                f"response=\"{v.hexs('sip-param:Proxy-Authorization;response', 32)}\", algorithm=AKAv1-MD5, "
                                f"qop=auth, nc=00000001, cnonce=\"{v.hexs('sip-param:Proxy-Authorization;cnonce', 16)}\", "
                                f"opaque=\"{v.hexs('sip-param:Proxy-Authorization;opaque', 20)}\", "
                                f"auts=\"{v.hexs('sip-param:Proxy-Authorization;auts', 28)}\""),
        ("Security-Client", f"ipsec-3gpp; alg=hmac-sha-1-96; spi-c=3333; spi-s=4444; port-c=5062; port-s=5064; "
                            f"d-ver=\"{v.hexs('sip-param:Security-Client;d-ver', 32)}\""),
        ("Security-Verify", f"ipsec-3gpp; q=0.1; alg=hmac-sha-1-96; spi-c=1111; spi-s=2222; port-c=5066; port-s=5068; "
                            f"d-ver=\"{v.hexs('sip-param:Security-Verify;d-ver', 32)}\""),
        ("Content-Type", "text/plain")], v.s("body:text/plain")))
    msgs.append(response(200, "OK", base("MESSAGE", 4)))

    # Body types without a parser are emptied (FR-023), one message each.
    for n, ct in enumerate(("application/mikey", "application/poc-settings+xml", "application/resource-lists+xml",
                            "application/vnd.3gpp.location-info+xml", "application/vnd.3gpp.mcdata-info+xml",
                            "application/vnd.3gpp.mcdata-payload", "application/vnd.3gpp.mcptt-affiliation-command+xml",
                            "application/vnd.3gpp.mcptt-location-info+xml", "application/vnd.3gpp.mcptt-mbms-usage-info+xml",
                            "application/vnd.3gpp.mcvideo-info+xml",
                            # feature 003: the types added to rules/sip-bodies.yaml (emptied until their
                            # document family is switched to handling xml)
                            "application/vnd.3gpp.mcptt-floor-request+xml",
                            "application/vnd.3gpp.mcptt-signed+xml",
                            "application/vnd.3gpp.mcptt-regroup+xml",
                            "application/vnd.3gpp.mcptt-mbs-usage-info+xml",
                            "application/vnd.3gpp.mcdata-affiliation-command+xml",
                            "application/vnd.3gpp.mcdata-location-info+xml",
                            "application/vnd.3gpp.mcdata-mbms-usage-info+xml",
                            "application/vnd.3gpp.mcdata-regroup+xml",
                            "application/vnd.3gpp.mcdata-msgstore-ctrl-request+xml",
                            "application/vnd.3gpp.mvdata-mbs-usage-info+xml",
                            "application/vnd.3gpp.mcdata-mbs-usage-info+xml",
                            "application/vnd.3gpp.mcvideo-mbms-usage-info+xml",
                            "application/vnd.3gpp.mcvideo-mbs-usage-info+xml",
                            "application/vnd.3gpp.mcvideo-location-info+xml",
                            "application/vnd.3gpp.mcvideo-affiliation-command+xml",
                            "application/vnd.3gpp.mcvideo-transmission-request+xml",
                            "application/vnd.3gpp.mcvideo-regroup+xml",
                            "application/reginfo+xml",
                            "application/conference-info+xml",
                            ), start=5):
        msgs.append(request("MESSAGE", f"sip:callee@{dom}", base("MESSAGE", n) + [("Content-Type", ct)],
                            f"<x>{v.s('body:' + ct)}</x>"))
        msgs.append(response(200, "OK", base("MESSAGE", n)))

    cap = Capture()
    for m in msgs:
        src, dst = (core, ua) if m.startswith(b"SIP/2.0") else (ua, core)
        cap.add(wrap(udp_packet(src, dst, 5060, 5060, m)))
    # The audio flow of the offer, so that the SDP-to-RTP check has frames to compare.
    for i in range(4):
        cap.add(wrap(P.udp4(_ip4("10.31.0.1"), _ip4("10.31.0.2"), 49200, 50200, rtp(i + 1, 0x51525354))))
    _write(cap, out, f)


def _coverage_sdp(v):
    """An offer with every SDP attribute rule that changes a value and that the ladder lacks."""
    removed = ("cat", "keywds", "confid", "userid", "floorctrl", "floorid", "file-selector", "file-transfer-id",
               "file-disposition", "file-date", "file-icon", "file-range", "altc", "tls-id", "content", "rtcp-xr",
               "extmap", "ecn-capable-rtp")
    return sdp(["v=0", "o=- 2890844526 2890844526 IN IP4 10.31.0.1", "s=-", "c=IN IP4 10.31.0.1", "t=0 0",
                "m=audio 49200 RTP/AVP 0", "a=rtpmap:0 PCMU/8000",
                f"a=remote-candidates:1 {v.ip('sdp:a=remote-candidates.address')} 50200",
                f"a=ssrc:1364349780 previous-ssrc:{v.bin('sdp:a=ssrc.previous-ssrc')}",
                f"a=ssrc-group:FID 1364349780 {v.bin('sdp:a=ssrc-group.ssrc-id')}"] +
               [f"a={a}:{v.s('sdp:a=' + a)}" for a in removed] +
               ["m=application 49202 udp MCVideo",
                f"a=fmtp:MCVideo mc_queueing;mc_video_ssrc={v.bin('sdp:a=fmtp:MCVideo.mc_video_ssrc')};"
                f"mc_audio_ssrc={v.bin('sdp:a=fmtp:MCVideo.mc_audio_ssrc')};"
                f"mc_transmission_ssrc={v.bin('sdp:a=fmtp:MCVideo.mc_transmission_ssrc')}",
                "m=message 2855 TCP/MSRP *", "a=accept-types:text/plain",
                f"a=path:msrp://{v.s('sdp:a=path.user')}@{v.label('sdp:a=path.host')}.example.net:2855/"
                f"{v.s('sdp:a=path.session-id')};tcp"])


FIXTURES.append(gen_coverage)


# --- consistency fixtures (User Story 2) ---------------------------------------
def _esp(spi, seq):
    """An ESP packet (RFC 4303 §2): SPI, sequence number, opaque payload."""
    return struct.pack("!II", spi, seq) + bytes(24)


def gen_consistency(c, out):
    """Text addresses equal to the IP header addresses; IMPI and IMPU of one user; a tel URI and
    a user=phone SIP URI of one number; Security-Client SPIs followed by ESP with those SPIs;
    and two captures that share a URI (cross-capture consistency)."""
    shared_user = c.string(None, "sip_consistency_a.pcapng", "CANARY", rule="sip:From.uri")
    c.reuse(shared_user, None, "sip_consistency_b.pcapng", rule="sip:From.uri")
    for name, v6 in (("sip_consistency_a.pcapng", False), ("sip_consistency_b.pcapng", True)):
        v = _Cv(c, name)
        cap = Capture()
        if v6:
            ua = bytes.fromhex("fd12345678900020000000000000a010")
            core = bytes.fromhex("fd12345678900020000000000000b020")
            ua_txt, core_txt = "[fd12:3456:7890:20::a010]", "[fd12:3456:7890:0020:0000:0000:0000:b020]"
            media = ("fd12:3456:7890:20::a010", "fd12:3456:7890:20::b020")
            ipfam = "IP6"
        else:
            ua_ip, core_ip = v.ip("sip:Via.sent-by"), v.ip("sip:Via.sent-by")
            ua, core = _ip4(ua_ip), _ip4(core_ip)
            ua_txt, core_txt = ua_ip, core_ip
            media = (ua_ip, core_ip)
            ipfam = "IP4"
        dom = v.label("sip:From.uri") + ".example.net"
        realm = v.label("sip-param:Authorization;realm") + ".example.net"
        number = v.num("sip:P-Asserted-Identity.uri", 11)
        imsi = v.num("sip-param:Authorization;username", 15)
        spi_c, spi_s = int(v.bin("sip-param:Security-Client;spi-c")), int(v.bin("sip-param:Security-Client;spi-s"))
        tag = v.s("sip-param:From;tag")
        callid = v.s("sip:Call-ID.value")
        user = shared_user
        common = [("Via", f"SIP/2.0/UDP {ua_txt}:5060;branch=z9hG4bK{v.s('sip-param:Via;branch')};received={ua_txt.strip('[]')}"),
                  ("Max-Forwards", "70"), ("From", f"<sip:{user}@{dom}>;tag={tag}"),
                  ("To", f"<sip:{user}@{dom}>"), ("Call-ID", callid)]
        reg = request("REGISTER", f"sip:{realm}", common + [
            ("CSeq", "1 REGISTER"),
            ("Contact", f"<sip:{user}@{ua_txt}:5060>"),
            ("Record-Route", f"<sip:{core_txt};lr>"),
            ("Authorization", f"Digest username=\"{user}@{realm}\", realm=\"{realm}\", nonce=\"\", "
                              f"uri=\"sip:{realm}\", response=\"\""),
            ("Security-Client", f"ipsec-3gpp; alg=hmac-sha-1-96; spi-c={spi_c}; spi-s={spi_s}; port-c=5062; port-s=5064"),
            ("P-Asserted-Identity", f"<sip:+{number}@{dom};user=phone>, <tel:+{number}>")])
        ok = response(200, "OK", common[:4] + [("To", f"<sip:{user}@{dom}>;tag=r1"), ("Call-ID", callid),
                                                ("CSeq", "1 REGISTER"),
                                                ("P-Associated-URI", f"<sip:{user}@{dom}>, <tel:+{number}>")])
        imsi_reg = request("REGISTER", f"sip:ims.mnc001.mcc260.3gppnetwork.org", common + [
            ("CSeq", "2 REGISTER"),
            ("Authorization", f"Digest username=\"{imsi}@ims.mnc001.mcc260.3gppnetwork.org\", "
                              "realm=\"ims.mnc001.mcc260.3gppnetwork.org\", nonce=\"\", "
                              "uri=\"sip:ims.mnc001.mcc260.3gppnetwork.org\", response=\"\"")])
        offer = sdp(["v=0", f"o=- 1 1 IN {ipfam} {media[0]}", "s=-", f"c=IN {ipfam} {media[0]}", "t=0 0",
                     "m=audio 49170 RTP/AVP 97", f"a=rtcp:49171 IN {ipfam} {media[0]}"])
        answer = sdp(["v=0", f"o=- 2 1 IN {ipfam} {media[1]}", "s=-", f"c=IN {ipfam} {media[1]}", "t=0 0",
                      "m=audio 50170 RTP/AVP 97"])
        inv = request("INVITE", f"sip:{user}@{dom}", common + [("CSeq", "3 INVITE"),
                                                               ("Contact", f"<sip:{user}@{ua_txt}:5060>"),
                                                               ("Content-Type", "application/sdp")], offer)
        ans = response(200, "OK", common[:4] + [("To", f"<sip:{user}@{dom}>;tag=r2"), ("Call-ID", callid),
                                                 ("CSeq", "3 INVITE"), ("Contact", f"<sip:{user}@{core_txt}:5060>"),
                                                 ("Content-Type", "application/sdp")], answer)
        for m, up in ((reg, True), (ok, False), (imsi_reg, True), (inv, True), (ans, False)):
            cap.add(wrap(udp_packet(ua, core, 5060, 5060, m) if up else udp_packet(core, ua, 5060, 5060, m)))
        # ESP with the SPIs the Security-Client offered (RFC 3329, TS 24.229 §7.2A.7).
        for i, spi in enumerate((spi_s, spi_c)):
            pkt = (P.ipv4(ua, core, 50, _esp(spi, i + 1)) if not v6 else P.ipv6(ua, core, 50, _esp(spi, i + 1)))
            cap.add(wrap(pkt))
        # RTP on the announced media addresses (ephemeral port 50170 for --pseudonymise-ephemeral-ports).
        src, dst = (_ip4(media[0]), _ip4(media[1])) if not v6 else (ua, core)
        cap.add(wrap(udp_packet(src, dst, 49170, 50170, rtp(1, 0x5151))))
        cap.add(wrap(udp_packet(dst, src, 50170, 49170, rtp(1, 0x5252))))
        with open(f"{out}/{name}", "wb") as fh:
            fh.write(cap.bytes())


FIXTURES.append(gen_consistency)


# --- fail-closed fixtures (User Story 3) ---------------------------------------
def _sctp_data(payload):
    return P.sctp(5060, 5060, 0x1234, P.chunk(0, 0x03, struct.pack("!IHHI", 1, 0, 0, 0) + payload))


def _ws_frame(payload):
    """A WebSocket text frame (RFC 6455 §5.2), unmasked, 16-bit length."""
    return bytes([0x81, 126]) + struct.pack("!H", len(payload)) + payload


def gen_failclosed(c, out):
    f = "sip_failclosed_unknown.pcapng"
    v = _Cv(c, f)
    hdr = [("Via", f"SIP/2.0/UDP 10.30.0.1;branch=z9hG4bK{v.s('sip-param:Via;branch')};x-via-param={v.s('sip-param:Via;x-via-param')}"),
           ("From", f"<sip:{v.s('sip:From.uri')}@fc.example.net;x-uri-param={v.s('uri-param:x-uri-param')}>;tag={v.s('sip-param:From;tag')};"
                    f"x-hdr-param={v.s('sip-param:From;x-hdr-param')}"),
           ("To", "<sip:target@fc.example.net>"), ("Call-ID", v.s("sip:Call-ID.value")), ("CSeq", "1 INVITE"),
           ("X-Vendor-Info", v.s("sip:X-Vendor-Info")), ("P-Vendor-Secret", v.s("sip:P-Vendor-Secret")),
           ("Contact", f"<sip:a@10.30.0.1>;+g.vendor.flag=\"{v.s('tag:+g.vendor.flag')}\";"
                       f"+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.{v.label('tag:+g.3gpp.icsi-ref')}\""),
           ("User-Agent", v.s("sip:User-Agent")), ("Server", v.s("sip:Server")), ("Organization", v.s("sip:Organization")),
           ("Subject", v.s("sip:Subject")), ("Warning", f"399 host.example.net \"{v.s('sip:Warning.text')}\""),
           ("Reason", f"SIP;cause=200;text=\"{v.s('sip-param:Reason;text')}\"")]
    sdp_body = sdp(["v=0", "o=- 1 1 IN IP4 10.30.0.1", "s=-", "c=IN IP4 10.30.0.1", "t=0 0", "m=audio 5000 RTP/AVP 0",
                    f"a=x-unknown-attr:{v.s('sdp:a=x-unknown-attr')}", "a=rtpmap:0 PCMU/8000"])
    nested = multipart("inner", [([("Content-Type", "application/x-vendor-blob")], v.s("body:application/x-vendor-blob"))])
    body = multipart("outer", [([("Content-Type", "application/sdp")], sdp_body),
                               ([("Content-Type", "application/x-unknown")], v.s("body:application/x-unknown")),
                               ([("Content-Type", "multipart/mixed;boundary=inner")], nested)])
    cap = Capture()
    a, b = bytes([10, 30, 0, 1]), bytes([10, 30, 0, 2])
    cap.add(wrap(udp_packet(a, b, 5060, 5060, request("INVITE", "sip:target@fc.example.net", hdr +
                                                       [("Content-Type", "multipart/mixed;boundary=outer")], body))))
    cap.add(wrap(udp_packet(b, a, 5060, 5060, response(486, f"Busy {v.s('sip:reason-phrase')}", hdr[:5]))))
    # A gzip body (Content-Encoding other than identity is emptied).
    cap.add(wrap(udp_packet(a, b, 5060, 5060, request("MESSAGE", "sip:target@fc.example.net", hdr[:5] + [
        ("Content-Type", "application/sdp"), ("Content-Encoding", "gzip")], v.s("body:gzip").encode()))))
    # SIP on a non-standard port is recognised by its grammar (FR-001).
    cap.add(wrap(udp_packet(a, b, 40123, 40456, request("OPTIONS", f"sip:{v.s('sip:Request-URI.user')}@fc.example.net",
                                                        hdr[:5]))))
    # An extension method is a token the rules do not know: the message is zeroed (the method
    # carries a canary; CSeq repeats it).
    xm = v.label("sip:method")
    cap.add(wrap(udp_packet(a, b, 5060, 5060, request(xm, "sip:target@fc.example.net",
                                                       hdr[:4] + [("CSeq", f"1 {xm}")]))))
    # Not SIP although on port 5060: zeroed as in feature 001.
    cap.add(wrap(udp_packet(a, b, 5060, 5060, f"HELLO {v.s('payload.l7')} WORLD\r\n".encode())))
    with open(f"{out}/{f}", "wb") as fh:
        fh.write(cap.bytes())

    # Out-of-scope transports (FR-002): SIP text in SCTP, in ESP with NULL encryption, in a TLS
    # record on 5061 and in a WebSocket frame over TCP stays zeroed.
    f = "sip_failclosed_transports.pcapng"
    v = _Cv(c, f)
    cap = Capture()
    def msg():
        return request("MESSAGE", f"sip:{v.s('sip:Request-URI.user')}@fc.example.net",
                       [("Via", "SIP/2.0/UDP 10.30.0.1;branch=z9hG4bK1"), ("From", f"<sip:{v.s('sip:From.uri')}@x>;tag=1"),
                        ("To", "<sip:t@x>"), ("Call-ID", v.s("sip:Call-ID.value")), ("CSeq", "1 MESSAGE")])
    cap.add(wrap(P.ipv4(a, b, 132, _sctp_data(msg()))))
    cap.add(wrap(P.ipv4(a, b, 50, struct.pack("!II", 0x1001, 1) + msg() + b"\x00\x00\x00\x11")))  # ESP-NULL, RFC 4303 §2
    tls = bytes([0x17, 0x03, 0x03]) + struct.pack("!H", len(msg())) + msg()  # RFC 8446 §5.1 application_data
    t = TcpConn(a, b, 40000, 5061)
    cap.extend(t.handshake())
    cap.add(t.send(0, tls))
    w = TcpConn(a, b, 40002, 443)
    cap.extend(w.handshake())
    cap.add(w.send(0, _ws_frame(msg())))
    with open(f"{out}/{f}", "wb") as fh:
        fh.write(cap.bytes())


FIXTURES.append(gen_failclosed)


# --- SIP over TCP fixtures (User Story 4) --------------------------------------
MSS = 1400


def _segments(m, size=MSS):
    return [m[i:i + size] for i in range(0, len(m), size)]


def _dir(m):
    """Requests go from the UA (direction 0), responses from the core (direction 1)."""
    return 1 if m.startswith(b"SIP/2.0") else 0


def _write(cap, out, name):
    with open(f"{out}/{name}", "wb") as fh:
        fh.write(cap.bytes())


def gen_tcp(c, out):
    # Framing: a message split over three segments, three messages in one segment, keep-alive
    # CRLFs (RFC 5626 §3.5.1), SACK blocks (RFC 2018 §3) and both FINs; over IPv4, IPv6 and
    # GTP-U.
    for name, a, b, tunnel in (("sip_tcp_ipv4.pcapng", UA, PCSCF, None),
                               ("sip_tcp_ipv6.pcapng", UA6, PCSCF6, None),
                               ("sip_tcp_gtpu.pcapng", UA, PCSCF, "gtpu")):
        cap = Capture()
        msgs, _ = ladder_udp(c, name)
        t = TcpConn(a, b, 40100, 5060, tunnel=tunnel)
        cap.extend(t.handshake())
        first = msgs[0]
        third = len(first) // 3
        for part in (first[:third], first[third:2 * third], first[2 * third:]):
            cap.add(t.send(0, part))
        cap.add(t.send(1, msgs[1] + b"\r\n"))
        cap.add(t.send(0, b"\r\n\r\n" + msgs[2] + msgs[4] + msgs[6]))
        cap.add(t.send(1, msgs[3] + msgs[5] + msgs[7]))
        for m in msgs[8:]:
            d = _dir(m)
            start = t.next[d]
            for seg in _segments(m):
                cap.add(t.send(d, seg))
            # The peer acknowledges with a SACK block over the message it just received.
            cap.add(t.ack(1 - d, sack=[(start, t.next[d])]))
        cap.add(t.fin(0))
        cap.add(t.fin(1))
        cap.add(t.ack(0))
        _write(cap, out, name)

    # Retransmissions: a full retransmission and one overlapping into a new message (FR-026).
    name = "sip_tcp_retrans.pcapng"
    cap = Capture()
    msgs, _ = ladder_udp(c, name)
    t = TcpConn(UA, PCSCF, 40200, 5060)
    cap.extend(t.handshake())
    for i, m in enumerate(msgs[:12]):
        d = _dir(m)
        start = t.next[d]
        cap.add(t.send(d, m))
        if i % 3 == 0:
            cap.add(t.send(d, m, seq=start, advance=False))
        elif i % 3 == 1:
            half = len(m) // 2
            nxt = msgs[i + 1] if _dir(msgs[i + 1]) == d else b"\r\n\r\n"
            cap.add(t.send(d, m[half:] + nxt, seq=start + half))
    _write(cap, out, name)

    # Reordering, a lost segment and a capture that starts in the middle of a message (FR-027).
    name = "sip_tcp_reorder.pcapng"
    cap = Capture()
    msgs, _ = ladder_udp(c, name)
    t = TcpConn(UA, PCSCF, 40300, 5060)
    cap.extend(t.handshake())
    m = msgs[0]
    s0 = t.next[0]
    cut1, cut2 = len(m) // 3, 2 * len(m) // 3
    cap.add(t.send(0, m[:cut1], seq=s0, advance=False))
    cap.add(t.send(0, m[cut2:], seq=s0 + cut2, advance=False))
    cap.add(t.send(0, m[cut1:cut2], seq=s0 + cut1, advance=False))
    t.next[0] = s0 + len(m)
    cap.add(t.send(1, msgs[1]))
    lost = msgs[2]
    cap.add(t.send(0, lost[:200]))
    t.skip(0, 300)  # the second segment of the message is not in the capture
    cap.add(t.send(0, lost[500:]))
    # The next message arrives more than the pending timeout later (capture time).
    cap.add(t.send(0, msgs[4]), ts_us=cap.ts + 11_000_000)
    cap.add(t.send(1, msgs[3]))
    # A second connection without its handshake: the first payload is the tail of a message.
    mid = TcpConn(UA, PCSCF, 40301, 5060, isn=(7_000_000, 9_000_000))
    tail = msgs[13][-1200:] if len(msgs[13]) > 1200 else msgs[13][len(msgs[13]) // 2:]
    cap.add(mid.send(0, tail))
    for m in msgs[14:18]:
        cap.add(mid.send(_dir(m), m))
    _write(cap, out, name)

    # Unframable: a message without Content-Length, one larger than 1 MiB, then a valid one.
    name = "sip_tcp_unframable.pcapng"
    cap = Capture()
    v = _Cv(c, name)
    msgs, _ = ladder_udp(c, name)
    t = TcpConn(UA, PCSCF, 40400, 5060)
    cap.extend(t.handshake())
    hdr = [("Via", f"SIP/2.0/TCP 10.20.1.10;branch=z9hG4bK{v.s('sip-param:Via;branch')}"),
           ("From", f"<sip:{v.s('sip:From.uri')}@tcp.example.net>;tag={v.s('sip-param:From;tag')}"),
           ("To", "<sip:t@tcp.example.net>"), ("Call-ID", v.s("sip:Call-ID.value")), ("CSeq", "1 MESSAGE"),
           ("Content-Type", "text/plain")]
    cap.add(t.send(0, request("MESSAGE", "sip:t@tcp.example.net", hdr, v.s("body:text/plain"), content_length=None)))
    big = request("MESSAGE", "sip:t@tcp.example.net", hdr, v.s("body:text/plain") + "x" * (1024 * 1024 + 4096))
    for seg in _segments(big, 16000):
        cap.add(t.send(0, seg))
    cap.add(t.send(0, msgs[0]))
    cap.add(t.send(1, msgs[1]))
    _write(cap, out, name)

    # Drop mode: SIP from the UA, binary data from the core on one connection, and a connection
    # that carries no SIP at all (feature-001 numbering). The binary data is no protocol the tool
    # recognises (not TLS, HTTP or h2, feature 007 FR-003/FR-004), so 001/FR-018 applies to it.
    name = "sip_tcp_mixed.pcapng"
    cap = Capture()
    v = _Cv(c, name)
    msgs, _ = ladder_udp(c, name)
    t = TcpConn(UA, PCSCF, 40500, 5060)
    cap.extend(t.handshake())
    for i, m in enumerate(m for m in msgs[:16] if _dir(m) == 0):
        cap.add(t.send(0, m))
        cap.add(t.send(1, bytes([0xA5, 0x5A, 0x03, 0, 32]) + v.s("payload.l7").encode().ljust(32, b"\0")))
    cap.add(t.fin(0))
    cap.add(t.fin(1))
    other = TcpConn(UA, PCSCF, 40501, 8443)
    cap.extend(other.handshake())
    for i in range(6):
        cap.add(other.send(i % 2, bytes([0xA5, 0x5A, 0x03, 0, 64]) + bytes(range(64))))
    _write(cap, out, name)


FIXTURES.append(gen_tcp)


# --- fragment fixtures (User Story 4) -------------------------------------------
def fragment_at(ip_packet, pieces, ident=0x5A5A):
    """Fragments of an IPv4 or IPv6 packet at explicit (offset, length) pieces of the
    fragmentable part, in the given order; a piece may overlap others. `patch` entries
    (offset, bytes) in a piece's third element change its bytes (a conflicting overlap)."""
    v4 = (ip_packet[0] >> 4) == 4
    ihl = (ip_packet[0] & 0x0F) * 4 if v4 else 40
    data = ip_packet[ihl:]
    frags = []
    for piece in pieces:
        off, n = piece[0], piece[1]
        chunk = bytearray(data[off:off + n])
        for at, b in (piece[2] if len(piece) > 2 else ()):
            chunk[at:at + len(b)] = b
        more = off + n < len(data)
        if v4:
            h = bytearray(ip_packet[:ihl])
            struct.pack_into("!HHH", h, 2, ihl + len(chunk), ident, (0x2000 if more else 0) | (off // 8))
            h[10:12] = b"\x00\x00"
            h[10:12] = struct.pack("!H", P.inet_checksum(bytes(h)))
            frags.append(bytes(h) + bytes(chunk))
        else:
            fh = struct.pack("!BBHI", ip_packet[6], 0, (off // 8) << 3 | (1 if more else 0), ident)
            frags.append(P.ipv6(ip_packet[8:24], ip_packet[24:40], 44, fh + bytes(chunk)))
    return frags


def _big_message(v, n):
    """A MESSAGE larger than the MTU (TS 24.282 MCData signalling over SIP, R19)."""
    hdr = [("Via", f"SIP/2.0/UDP 10.20.1.10;branch=z9hG4bK{v.s('sip-param:Via;branch')}"),
           ("Max-Forwards", "70"),
           ("From", f"\"{v.s('sip:From.display-name')}\" <sip:{v.s('sip:From.uri')}@frag.example.net>;tag={v.s('sip-param:From;tag')}"),
           ("To", f"<sip:{v.s('sip:To.uri')}@frag.example.net>"), ("Call-ID", v.s("sip:Call-ID.value")),
           ("CSeq", f"{n} MESSAGE"), ("Content-Type", "application/vnd.3gpp.mcdata-signalling")]
    body = v.s("body:application/vnd.3gpp.mcdata-signalling") + "".join(
        f"\r\n{v.s('body:application/vnd.3gpp.mcdata-signalling')}" for _ in range(180))
    return request("MESSAGE", f"sip:{v.s('sip:Request-URI.user')}@frag.example.net", hdr, body)


def _big_invite(v, n):
    """An INVITE whose SDP offer is larger than the MTU and stays so after rewriting (media
    lines and rtpmap attributes are kept), so that the output is cut into fragments again."""
    hdr = [("Via", f"SIP/2.0/UDP 10.20.1.10;branch=z9hG4bK{v.s('sip-param:Via;branch')}"),
           ("Max-Forwards", "70"),
           ("From", f"<sip:{v.s('sip:From.uri')}@frag.example.net>;tag={v.s('sip-param:From;tag')}"),
           ("To", f"<sip:{v.s('sip:To.uri')}@frag.example.net>"), ("Call-ID", v.s("sip:Call-ID.value")),
           ("CSeq", f"{n} INVITE"), ("Content-Type", "application/sdp")]
    lines = ["v=0", f"o=- {v.num('sdp:o=.sess-id', 10)} 1 IN IP4 {v.ip('sdp:o=.address')}", "s=-",
             f"c=IN IP4 {v.ip('sdp:c=.address')}", "t=0 0"]
    for k in range(70):
        lines += [f"m=audio {40000 + 2 * k} RTP/AVP 97 98", "a=rtpmap:97 AMR-WB/16000", "a=rtpmap:98 AMR/8000",
                  "a=ptime:20", "a=sendrecv"]
    return request("INVITE", f"sip:{v.s('sip:Request-URI.user')}@frag.example.net", hdr, sdp(lines))


def gen_frag(c, out):
    for name, a, b, tunnel in (("sip_frag_ipv4.pcapng", UA, PCSCF, None),
                               ("sip_frag_ipv6.pcapng", UA6, PCSCF6, None),
                               ("sip_frag_gtpu.pcapng", UA, PCSCF, "gtpu")):
        v = _Cv(c, name)
        cap = Capture()
        ident = [0x4000]

        def dgram(n, invite=False):
            ident[0] += 1
            m = _big_invite(v, n) if invite else _big_message(v, n)
            return udp_packet(a, b, 5060, 5060, m, ident=ident[0]), ident[0]

        def put(frags):
            for f in frags:
                cap.add(wrap(f, tunnel))

        size = 1232 if len(a) == 16 else 1480
        # In order, out of order, duplicated; the first two stay larger than the MTU.
        pkt, i = dgram(1, invite=True)
        put(fragment(pkt, size, i))
        pkt, i = dgram(2, invite=True)
        fs = fragment(pkt, size, i)
        put([fs[2], fs[0], fs[1]] + fs[3:])
        pkt, i = dgram(3)
        fs = fragment(pkt, size, i)
        put([fs[0], fs[1], fs[1]] + fs[2:])
        # Identically overlapping, conflicting, and one fragment missing (zeroed).
        hl = 20 if len(a) == 4 else 40
        pkt, i = dgram(4)
        total = len(pkt) - hl
        put(fragment_at(pkt, [(0, size), (size - 8, size), (2 * size - 8, total - (2 * size - 8))], i))
        pkt, i = dgram(5)
        total = len(pkt) - hl
        put(fragment_at(pkt, [(0, size), (size - 8, size, [(0, b"XXXXXXXX")]),
                              (2 * size - 8, total - (2 * size - 8))], i))
        pkt, i = dgram(6)
        fs = fragment(pkt, size, i)
        put(fs[:1] + fs[2:])
        # Two datagrams interleaved, and a fragmented datagram that is not SIP.
        p1, i1 = dgram(7)
        p2, i2 = dgram(8)
        f1, f2 = fragment(p1, size, i1), fragment(p2, size, i2)
        put([x for pair in zip(f1, f2) for x in pair] + f1[len(f2):] + f2[len(f1):])
        ident[0] += 1
        junk = udp_packet(a, b, 40000, 40001, (v.s("payload.l7") + "-" * 3000).encode(), ident=ident[0])
        put(fragment(junk, size, ident[0]))
        _write(cap, out, name)


FIXTURES.append(gen_frag)


# --- report fixture (User Story 5) ---------------------------------------------
class _Expect:
    """The `sip` object the report of one fixture must carry (FR-036). Each count is declared
    by the fixture code next to the item it describes, from the rule data (rules/sip-*.yaml,
    rules/sdp.yaml); nothing is derived from the tool's output."""

    def __init__(self):
        self.d = {"messages": {"requests": {}, "responses": {}, "malformed": 0}, "headers": {},
                  "malformed_headers": {}, "removed_unknown": {}, "sdp": {}, "bodies": {},
                  "tcp": {"streams_sip": 0, "bytes_unframable": 0, "retransmissions_replayed": 0,
                          "retransmissions_zeroed": 0, "directions_evicted": 0},
                  "fragments": {"datagrams_rewritten": 0, "datagrams_zeroed": {}}}

    @staticmethod
    def _inc(m, *keys, n=1):
        for k in keys[:-1]:
            m = m.setdefault(k, {})
        m[keys[-1]] = m.get(keys[-1], 0) + n

    def header(self, rule, action):
        self._inc(self.d["headers"], rule, action)
        if action == "malformed":
            self._inc(self.d["malformed_headers"], rule)

    def unknown(self, kind, name):
        self._inc(self.d["removed_unknown"], kind, name)

    def sdp(self, lines):
        """lines: (text, key, action); returns the SDP body."""
        for _, key, action in lines:
            self._inc(self.d["sdp"], key, action)
        return sdp([t for t, _, _ in lines])

    def body(self, content_type, handling):
        self._inc(self.d["bodies"], content_type, handling)

    def tcp(self, key, n=1):
        self.d["tcp"][key] += n

    def fragment(self, zeroed_reason=None):
        if zeroed_reason is None:
            self.d["fragments"]["datagrams_rewritten"] += 1
        else:
            self._inc(self.d["fragments"]["datagrams_zeroed"], zeroed_reason)

    def msg(self, start, hdrs, body=b"", outcome="rewritten", method=None, content_length="auto"):
        """A SIP message. hdrs: (name, value, rule, action[, reported name]); rule None is a
        header without a rule, counted under its reported name (default: its name). outcome: "rewritten"; "zeroed" (the
        message is not understood: each header with a rule counts as zero, the message as
        malformed); None (the SIP layer never sees the message: nothing is counted). method:
        the reported method, when it is not the start line's."""
        if outcome is not None:
            if start.startswith("SIP/2.0 "):
                self._inc(self.d["messages"]["responses"], start.split()[1][0] + "xx")
            else:
                self._inc(self.d["messages"]["requests"], method or start.split()[0])
            names = [(h[2], h[3], h[4] if len(h) > 4 else h[0]) for h in hdrs]
            if content_length == "auto":
                names.append(("Content-Length", "keep", None))
            for rule, action, report_name in names:
                if rule is None:
                    self.unknown("sip-header", report_name)
                else:
                    self.header(rule, "zero" if outcome == "zeroed" else action)
            if outcome == "zeroed":
                self.d["messages"]["malformed"] += 1
        return message(start, [(h[0], h[1]) for h in hdrs], body, content_length)


def gen_report(c, out):
    """Known content for the report test: every map of the `sip` object gets entries,
    the item actions keep, pseudonymise, blank, remove, zero and malformed all occur, and so do a replayed retransmission, unframable bytes and the fragment
    reasons "timeout" and "missing". sip_report.expected.json says what every counter must be
    (sip_by_mode: where drop mode differs). Run with the deny list sip_report.deny."""
    name = "sip_report.pcapng"
    v = _Cv(c, name)
    e = _Expect()
    a, b = bytes([10, 40, 1, 10]), bytes([10, 40, 2, 20])
    ua = "10.40.1.10"
    dom = v.label("sip:From.uri") + ".example.net"
    pcscf = v.label("sip:Route.uri") + ".example.net"
    alice, bob = v.s("sip:From.uri"), v.s("sip:To.uri")
    callid = v.s("sip:Call-ID.value") + "@" + ua
    ftag, ttag = v.s("sip-param:From;tag"), v.s("sip-param:To;tag")
    # Header names from the input that the report self-check must not show: one contains a
    # deny-list word, one contains a value that is pseudonymised elsewhere (a scan token). The
    # deny-list word is not a canary: without the deny list the tool cannot know it, and the
    # report shows the name (FR-036); with it, the leak scan proves the word absent.
    deny_word = f"vendorword{c.rng.getrandbits(32):08x}"
    deny_header = f"X-{deny_word}"
    token_header = f"X-{alice}"
    plain_header = "X-Plain-Unknown"

    def base(method, cseq, transport="UDP", to_tag=False):
        return [("Via", f"SIP/2.0/{transport} {ua}:5060;branch=z9hG4bK{v.s('sip-param:Via;branch')}", "Via", "pseudonymise"),
                ("Max-Forwards", "70", "Max-Forwards", "keep"),
                ("From", f"<sip:{alice}@{dom}>;tag={ftag}", "From", "pseudonymise"),
                ("To", f"<sip:{bob}@{dom}>" + (f";tag={ttag}" if to_tag else ""), "To", "pseudonymise"),
                ("Call-ID", callid, "Call-ID", "pseudonymise"),
                ("CSeq", f"{cseq} {method}", "CSeq", "keep")]

    def resp_hdrs(method, cseq, transport="UDP"):
        return [h for h in base(method, cseq, transport, True) if h[0] != "Max-Forwards"]

    udp = []
    # REGISTER: an unknown Via parameter, a removed header, three unknown header names.
    reg = base("REGISTER", 1)
    reg[0] = (reg[0][0], reg[0][1] + ";x-vendor-flag=1") + reg[0][2:]
    e.unknown("sip-param", "x-vendor-flag")
    reg += [("Contact", f"<sip:{v.s('sip:Contact.uri')}@{ua}:5060>;expires=600", "Contact", "pseudonymise"),
            ("Expires", "600", "Expires", "keep"),
            ("Supported", "path, gruu", "Supported", "keep"),
            ("User-Agent", v.s("sip:User-Agent"), "User-Agent", "remove"),
            (deny_header, "1", None, None, "(invalid-name)"),
            (token_header, "1", None, None, "(invalid-name)"),
            (plain_header, v.s("sip:X-Plain-Unknown"), None, None, plain_header)]
    udp.append((0, e.msg(f"REGISTER sip:{pcscf} SIP/2.0", reg)))
    udp.append((1, e.msg("SIP/2.0 200 OK", resp_hdrs("REGISTER", 1) + [
        ("Contact", f"<sip:{v.s('sip:Contact.uri')}@{ua}:5060>;expires=600", "Contact", "pseudonymise")])))
    # INVITE with a multipart body: an SDP offer with every SDP action, and an emptied part.
    boundary = v.s("sip-param:Content-Type;boundary")
    offer = e.sdp([
        ("v=0", "v=", "keep"),
        (f"o={v.s('sdp:o=.username')} {v.num('sdp:o=.sess-id', 10)} 1 IN IP4 {v.ip('sdp:o=.address')}", "o=", "pseudonymise"),
        (f"s={v.s('sdp:s=')}", "s=", "blank"),
        (f"i={v.s('sdp:i=')}", "i=", "remove"),
        (f"c=IN IP4 {v.ip('sdp:c=.address')}", "c=", "pseudonymise"),
        ("t=0 0", "t=", "keep"),
        ("m=audio 49170 RTP/AVP 97", "m=", "pseudonymise"),
        ("i=speech", "i=", "keep"),
        ("a=rtpmap:97 AMR-WB/16000", "a=rtpmap", "keep"),
        ("a=sendrecv", "a=sendrecv", "keep"),
        (f"a=rtcp:49171 IN IP4 {v.ip('sdp:a=rtcp.address')}", "a=rtcp", "pseudonymise"),
        (f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{v.s('sdp:a=crypto')}", "a=crypto", "remove"),
        ("m=application 49172 udp MCPTT", "m=", "pseudonymise"),
        (f"a=fmtp:MCPTT mc_queueing;mc_priority=5;mc_ssrc={v.bin('sdp:a=fmtp:MCPTT.mc_ssrc')}", "a=fmtp:MCPTT",
         "pseudonymise")])
    offer += f"a=x-vendor-attr:{v.s('sdp:a=x-vendor-attr')}\r\n".encode()
    e.unknown("sdp-attribute", "x-vendor-attr")
    parts = [([("Content-Type", "application/sdp")], offer),
             ([("Content-Type", "application/vnd.3gpp.mcptt-info+xml")],
              f"<mcptt-info><mcpttURI>sip:{v.s('body:application/vnd.3gpp.mcptt-info+xml')}@x</mcpttURI></mcptt-info>")]
    e.header("Content-Type", "keep")  # the Content-Type of each part
    e.header("Content-Type", "keep")
    e.body("multipart/mixed", "multipart")
    e.body("application/sdp", "sdp")
    e.body("application/vnd.3gpp.mcptt-info+xml", "emptied")
    udp.append((0, e.msg(f"INVITE sip:{bob}@{dom} SIP/2.0", base("INVITE", 1) + [
        ("Contact", f"<sip:{alice}@{ua}:5060>", "Contact", "pseudonymise"),
        ("Content-Type", f"multipart/mixed;boundary={boundary}", "Content-Type", "keep")],
        multipart(boundary, parts))))
    udp.append((1, e.msg("SIP/2.0 100 Trying", resp_hdrs("INVITE", 1))))
    udp.append((1, e.msg("SIP/2.0 302 Moved Temporarily", resp_hdrs("INVITE", 1) + [
        ("Contact", f"<sip:{v.s('sip:Contact.uri')}@{dom}>", "Contact", "pseudonymise")])))
    udp.append((0, e.msg(f"ACK sip:{bob}@{dom} SIP/2.0", base("ACK", 1, to_tag=True))))
    # An unknown body type is emptied and counted by its Content-Type.
    e.unknown("content-type", "application/x-vendor-blob")
    udp.append((0, e.msg(f"MESSAGE sip:{bob}@{dom} SIP/2.0", base("MESSAGE", 2) + [
        ("Content-Type", "application/x-vendor-blob", "Content-Type", "keep")], v.s("body:application/x-vendor-blob"))))
    udp.append((1, e.msg("SIP/2.0 404 Not Found", resp_hdrs("MESSAGE", 2))))
    udp.append((0, e.msg(f"OPTIONS sip:{pcscf} SIP/2.0", base("OPTIONS", 3) + [
        ("Accept", "application/sdp", "Accept", "keep")])))
    udp.append((1, e.msg("SIP/2.0 503 Service Unavailable", resp_hdrs("OPTIONS", 3) + [
        ("Retry-After", "120", "Retry-After", "keep")])))
    # A header that does not parse is removed alone and counted as malformed (FR-029).
    udp.append((0, e.msg(f"SUBSCRIBE sip:{bob}@{dom} SIP/2.0", base("SUBSCRIBE", 4) + [
        ("Event", "presence", "Event", "keep"), ("Expires", "soon", "Expires", "malformed")])))
    udp.append((1, e.msg("SIP/2.0 603 Decline", resp_hdrs("SUBSCRIBE", 4))))
    # An extension method (I11): the message is zeroed; the method is reported without its name.
    xm = v.label("sip:method")
    udp.append((0, e.msg(f"{xm} sip:{pcscf} SIP/2.0", base(xm, 5), outcome="zeroed", method="(invalid-name)")))

    cap = Capture()
    for d, m in udp:
        src, dst = (a, b) if d == 0 else (b, a)
        cap.add(wrap(udp_packet(src, dst, 5060, 5060, m)))

    # TCP: both directions carry SIP; a full retransmission is replayed; a message without
    # Content-Length cannot be framed (RFC 3261 §18.3) and is zeroed up to the next message.
    t = TcpConn(a, b, 40700, 5060)
    cap.extend(t.handshake())
    e.tcp("streams_sip", 2)  # one per direction
    m = e.msg(f"OPTIONS sip:{pcscf} SIP/2.0", base("OPTIONS", 11, "TCP"))
    start = t.next[0]
    cap.add(t.send(0, m))
    cap.add(t.send(0, m, seq=start, advance=False))
    e.tcp("retransmissions_replayed")
    cap.add(t.send(1, e.msg("SIP/2.0 200 OK", resp_hdrs("OPTIONS", 11, "TCP"))))
    nolen = e.msg(f"MESSAGE sip:{bob}@{dom} SIP/2.0", base("MESSAGE", 12, "TCP") + [
        ("Content-Type", "text/plain", "Content-Type", "keep")], v.s("body:text/plain") + "\r\n",
        outcome=None, content_length=None)
    cap.add(t.send(0, nolen))
    # I10: in zero mode the CRLF that ends the zeroed run is kept, so that the next message
    # starts a line; drop mode removes the whole run.
    e.tcp("bytes_unframable", len(nolen) - 2)
    drop_mode = {"tcp": {"bytes_unframable": len(nolen)}}
    e.body("text/plain", "emptied")
    cap.add(t.send(0, e.msg(f"MESSAGE sip:{bob}@{dom} SIP/2.0", base("MESSAGE", 13, "TCP") + [
        ("Content-Type", "text/plain", "Content-Type", "keep")], v.s("body:text/plain"))))
    cap.add(t.send(1, e.msg("SIP/2.0 200 OK", resp_hdrs("MESSAGE", 13, "TCP"))))
    cap.add(t.fin(0))
    cap.add(t.fin(1))
    cap.add(t.ack(0))

    # Fragmented UDP: one datagram rewritten; one with a fragment that never arrives, given up
    # after the pending timeout (capture time); one still incomplete at the end of the capture.
    def big(cseq, outcome):
        if outcome:
            e.body("application/vnd.3gpp.mcdata-signalling", "emptied")
        body = "".join(f"{v.s('body:application/vnd.3gpp.mcdata-signalling')}\r\n" for _ in range(160))
        return e.msg(f"MESSAGE sip:{bob}@{dom} SIP/2.0", base("MESSAGE", cseq) + [
            ("Content-Type", "application/vnd.3gpp.mcdata-signalling", "Content-Type", "keep")], body, outcome=outcome)

    for ident, cseq, outcome in ((0x6001, 21, "rewritten"), (0x6002, 22, None), (0x6003, 23, None)):
        fs = fragment(udp_packet(a, b, 5060, 5060, big(cseq, outcome), ident=ident), 1480, ident)
        if outcome:
            e.fragment()
            for f in fs:
                cap.add(wrap(f))
        elif ident == 0x6002:
            e.fragment("timeout")
            for f in fs[:1] + fs[2:]:
                cap.add(wrap(f))
            # More than the pending timeout later (R15: 10 s of capture time).
            cap.add(wrap(udp_packet(a, b, 5060, 5060, e.msg(f"OPTIONS sip:{pcscf} SIP/2.0", base("OPTIONS", 24)))),
                    ts_us=cap.ts + 11_000_000)
        else:
            e.fragment("missing")
            for f in fs[:-1]:
                cap.add(wrap(f))
    _write(cap, out, name)
    with open(f"{out}/sip_report.deny", "w") as fh:
        fh.write(f"# sip_report.pcapng: the word in the name of one unknown header\n{deny_word}\n")
    expected = {"fixture": name, "deny_list": "sip_report.deny", "sip": e.d,
                "sip_by_mode": {"drop": drop_mode},
                "redacted_header_names": [deny_header, token_header],
                "token_header_names": [token_header],
                "unknown_header_names": [deny_header, token_header, plain_header]}
    with open(f"{out}/sip_report.expected.json", "w") as fh:
        json.dump(expected, fh, indent=2, sort_keys=True)
        fh.write("\n")


FIXTURES.append(gen_report)

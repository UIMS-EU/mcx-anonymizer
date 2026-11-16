# SPDX-License-Identifier: GPL-3.0-or-later
"""Malformed fixtures for every decoder: truncations, bad lengths, loops, bombs.

Each base packet carries canaries; every variant must be processed without a
crash or hang, with everything after the last understood header zeroed.
"""
import struct

from capfile import PcapBuilder
from common import ip4, ip6, mac, text, write
import packets as P
import pcapng


def _length_variants(pkt, offsets):
    """Copies of pkt with the 16-bit field at each offset set to boundary values."""
    for off in offsets:
        for v in (0, 1, 4, 7, 0xFFFF, len(pkt) - off, len(pkt) + 1):
            b = bytearray(pkt)
            b[off:off + 2] = struct.pack("!H", v & 0xFFFF)
            yield bytes(b)


def _truncations(pkt, upto=96):
    for n in range(0, min(len(pkt), upto)):
        yield pkt[:n]


def gen(c, out):
    f = "malformed_raw.pcap"
    b = PcapBuilder(101)
    s, d = ip4(c, "ipv4.src", f), ip4(c, "ipv4.dst", f)
    s6, d6 = ip6(c, "ipv6.src", f), ip6(c, "ipv6.dst", f)
    bases = {
        "udp": P.udp4(s, d, 1, 2, text(c, "payload.l7", f)),
        "tcp": P.tcp4(s, d, 1, 2, 3, 4, 0x18, text(c, "payload.l7", f), options=bytes([2, 4, 5, 0xB4])),
        "sctp": P.ipv4(s, d, 132, P.sctp(1, 2, 3, P.chunk(1, 0, struct.pack("!IIHHI", 1, 1, 1, 1, 1) +
                                                            P.param(5, ip4(c, "sctp.param.ipv4", f))))),
        "icmp": P.ipv4(s, d, 1, P.icmp(3, 1, bytes(4), P.udp4(ip4(c, "ipv4.src", f), d, 5, 6, b""))),
        "gre": P.ipv4(s, d, 47, P.gre(0x0800, P.udp4(ip4(c, "ipv4.src", f), d, 1, 2, b""), key=1, seq=2)),
        "gtpu": P.udp4(s, d, 2152, 2152, P.gtpu(1, P.udp6(s6, d6, 1, 2, b""), exts=[(0x85, b"\x00\x01")])),
        "ipv6ext": P.ipv6(s6, d6, 0, P.ext(43, bytes([1, 0, 0, 0, 0, 0])) +
                          P.ext(17, bytes([4, 1, 0, 0, 0, 0]) + bytes(8)) + P.udp(1, 2, b"", checksum=False)),
        "ndp": P.ipv6(s6, d6, 58, P.icmpv6(s6, d6, 135, 0, bytes(4) + ip6(c, "ndp.target", f) +
                                          bytes([1, 1]) + mac(c, "ndp.opt.lla", f))),
        "ipv4opt": P.ipv4(s, d, 59, b"", options=bytes([7, 11, 4]) + ip4(c, "ipv4.opt.route.addr", f) + bytes(5)),
    }
    for name, pkt in bases.items():
        b.add(pkt)
        for t in _truncations(pkt):
            b.add(t)
    for pkt in _length_variants(bases["udp"], [2, 24]):            # IPv4 total length, UDP length
        b.add(pkt)
    for pkt in _length_variants(bases["sctp"], [20 + 12 + 2, 20 + 12 + 4 + 16 + 2]):  # chunk, param lengths
        b.add(pkt)
    for pkt in _length_variants(bases["gtpu"], [28 + 2]):           # GTP-U length
        b.add(pkt)
    # IPv6 extension headers that point back to themselves (hop-by-hop after hop-by-hop).
    loop = P.ipv6(s6, d6, 0, P.ext(0, bytes(6)) * 64)
    b.add(loop)
    # SCTP chunk of length zero and a chunk longer than the packet.
    b.add(P.ipv4(s, d, 132, P.sctp(1, 2, 3, b"\x00\x00\x00\x00" + bytes(8))))
    b.add(P.ipv4(s, d, 132, P.sctp(1, 2, 3, b"\x00\x00\xff\xf0" + bytes(8))))
    # GRE / IP-in-IP / GTP-U nesting bomb.
    bomb = P.udp4(s, d, 1, 2, b"")
    for i in range(40):
        bomb = P.ipv4(s, d, 47, P.gre(0x0800, bomb)) if i % 2 else P.udp4(s, d, 2152, 2152, P.gtpu(1, bomb))
    b.add(bomb)
    # TCP data offset beyond the packet, and below the minimum.
    tcp = bytearray(bases["tcp"])
    tcp[32] = 0xF0
    b.add(bytes(tcp))
    tcp[32] = 0x10
    b.add(bytes(tcp))
    # NDP option of length zero; IPv4 IHL larger than the packet.
    ndp = bytearray(bases["ndp"])
    ndp[40 + 24 + 1] = 0
    b.add(bytes(ndp))
    v4 = bytearray(bases["udp"])
    v4[0] = 0x4F
    b.add(bytes(v4))
    write(out, f, b.bytes())

    # Ethernet frames with a broken VLAN stack and a short ARP.
    f = "malformed_eth.pcap"
    b = PcapBuilder(1)
    sm, dm = mac(c, "eth.src", f), mac(c, "eth.dst", f)
    b.add(P.ethernet(dm, sm, 0x8100, b"\x00"))
    b.add(P.ethernet(dm, sm, 0x8100, P.vlan(1, 0x8100, P.vlan(2, 0x8100, b""))))
    b.add(P.ethernet(dm, sm, 0x0806, P.arp(sm, s, dm, d)[:12]))
    b.add(P.ethernet(dm, sm, 0x0800, b"\x45"))
    write(out, f, b.bytes())

    # pcapng: an option that overruns its block (input error), an NRB without an end record.
    w = pcapng.Writer()
    blk = bytearray(w.idb(1, 0, [(2, text(c, "pcapng.idb.name", "malformed_option.pcapng"))]))
    struct.pack_into("<H", blk, 18, 200)  # option length far beyond the block
    write(out, "malformed_option.pcapng", w.shb() + bytes(blk))
    nrb = w.block(4, struct.pack("<HH", 1, 8) + ip4(c, "pcapng.blk.nrb", "malformed_nrb.pcapng") + b"abcd")
    write(out, "malformed_nrb.pcapng", w.shb() + w.idb(1) + nrb +
          w.epb(0, 0, P.ethernet(dm, sm, 0x0800, P.udp4(s, d, 1, 2, b""))))
    gen_sip(c, out)


def gen_sip(c, out):
    """Malformed SIP (FR-029): every variant is one UDP datagram with canaries. Variants
    whose start line, framing, dialog-defining header, Content-Length, multipart nesting or SDP
    is broken are zeroed whole; a broken other header is removed alone."""
    import sip as S

    f = "sip_malformed_udp.pcapng"
    v = S._Cv(c, f)
    a, b = bytes([10, 31, 0, 1]), bytes([10, 31, 0, 2])

    def head(**over):
        h = {"Via": f"SIP/2.0/UDP 10.31.0.1;branch=z9hG4bK{v.s('sip-param:Via;branch')}",
             "From": f"<sip:{v.s('sip:From.uri')}@mf.example.net>;tag={v.s('sip-param:From;tag')}",
             "To": f"<sip:{v.s('sip:To.uri')}@mf.example.net>", "Call-ID": v.s("sip:Call-ID.value"),
             "CSeq": "1 MESSAGE"}
        h.update(over)
        return [(k, x) for k, x in h.items() if x is not None]

    deep = S.sdp(["v=0", "o=- 1 1 IN IP4 10.31.0.1", "s=-", "t=0 0"])
    ctype = "application/sdp"
    for depth in range(6):  # one level beyond kMaxMultipartDepth (4)
        bnd = f"d{depth}"
        deep = S.multipart(bnd, [([("Content-Type", ctype)], deep)])
        ctype = f"multipart/mixed;boundary={bnd}"
    variants = [
        # (label, message bytes, expected: "zeroed" | "header" | "not-sip")
        ("start line", f"MESSAGE sip:{v.s('sip:Request-URI.user')}@x SIP/9.9\r\nContent-Length: 0\r\n\r\n".encode(), "not-sip"),
        ("unterminated header section", ("MESSAGE sip:x@mf.example.net SIP/2.0\r\n" +
                                         "".join(f"{k}: {x}\r\n" for k, x in head())).encode(), "zeroed"),
        ("Via", S.request("MESSAGE", "sip:x@mf.example.net", head(Via="garbage <<")), "zeroed"),
        ("From", S.request("MESSAGE", "sip:x@mf.example.net", head(From=f"<sip:{v.s('sip:From.uri')}@[bad>")), "zeroed"),
        ("To", S.request("MESSAGE", "sip:x@mf.example.net", head(To="<<>>")), "zeroed"),
        ("Call-ID", S.request("MESSAGE", "sip:x@mf.example.net", head(**{"Call-ID": f"two words {v.s('sip:Call-ID.value')}"})), "zeroed"),
        ("CSeq", S.request("MESSAGE", "sip:x@mf.example.net", head(CSeq="MESSAGE one")), "zeroed"),
        ("Content-Length", S.request("MESSAGE", "sip:x@mf.example.net", head(), b"", content_length="abc"), "zeroed"),
        ("Content-Length beyond the datagram", S.request("MESSAGE", "sip:x@mf.example.net", head(), b"short",
                                                         content_length=500), "zeroed"),
        ("Content-Type", S.request("MESSAGE", "sip:x@mf.example.net", head() + [("Content-Type", "???")],
                                   v.s("body:invalid-content-type")), "zeroed"),
        ("multipart too deep", S.request("MESSAGE", "sip:x@mf.example.net", head() + [("Content-Type", ctype)], deep), "zeroed"),
        ("invalid SDP", S.request("MESSAGE", "sip:x@mf.example.net", head() + [("Content-Type", "application/sdp")],
                                  f"v=0\r\nthis is no sdp {v.s('sdp:invalid')}\r\n"), "zeroed"),
        ("unescaped display name", S.request("MESSAGE", "sip:x@mf.example.net",
                                             head(From=f"\"Al\"{v.s('sip:From.display-name')}\" <sip:a@x>;tag=1")), "zeroed"),
        ("oversized header", S.request("MESSAGE", "sip:x@mf.example.net",
                                       head() + [("Subject", v.s("sip:Subject") + "x" * 70000)]), "zeroed"),
        ("one broken other header", S.request("MESSAGE", "sip:x@mf.example.net", head() + [
            ("P-Asserted-Identity", f"<sip:{v.s('sip:P-Asserted-Identity.uri')}@[bad>")]), "header"),
    ]
    cap = S.Capture()
    expected = {"zeroed": 0, "header": 0, "not-sip": 0}
    for label, m, outcome in variants:
        expected[outcome] += 1
        if len(m) > 65000:  # oversized: carried in fragments of a datagram the IPv4 limit allows
            m = m[:65000]
        cap.add(S.wrap(S.udp_packet(a, b, 5060, 5060, m)))
    with open(f"{out}/{f}", "wb") as fh:
        fh.write(cap.bytes())
    import json
    with open(f"{out}/{f}.expected.json", "w", encoding="utf-8") as fh:
        json.dump({"malformed_messages": expected["zeroed"], "malformed_headers": {"P-Asserted-Identity": 1}},
                  fh, indent=1, sort_keys=True)

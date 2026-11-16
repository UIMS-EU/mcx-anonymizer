# SPDX-License-Identifier: GPL-3.0-or-later
"""IPv4 / IPv6 fixtures: options, fragments, extension headers, AH, ESP, special forms."""
import ipaddress
import struct

from capfile import PcapBuilder
from common import ip4, ip6, mac, text, write
import canary as C
import packets as P


def gen(c, out):
    f = "l3_ipv4.pcap"
    b = PcapBuilder(101)
    s, d = ip4(c, "ipv4.src", f), ip4(c, "ipv4.dst", f)
    rr = bytes([7, 11, 4]) + ip4(c, "ipv4.opt.route.addr", f) + ip4(c, "ipv4.opt.route.addr", f)
    ts = bytes([68, 12, 5, 0x01]) + ip4(c, "ipv4.opt.ts.addr", f) + struct.pack("!I", 0x01020304)
    other = bytes([0x99, 8]) + c.bytes("ipv4.opt.other", f, 6)
    opts = rr + b"\x01" + ts + other + b"\x00" + c.bytes("ipv4.opt.padding", f, 7)
    assert len(opts) == 40
    b.add(P.ipv4(s, d, 17, P.udp(1, 2, b"", checksum=False), options=opts))
    bad = bytes([7, 40]) + c.bytes("ipv4.opt.malformed", f, 6)
    b.add(P.ipv4(ip4(c, "ipv4.src", f), d, 59, b"", options=bad))
    # Fragments: first carries the UDP header, later ones only payload.
    u = P.udp(5000, 5060, text(c, "payload.l7", f) + b"#" * 40)
    b.add(P.ipv4(s, d, 17, u[:32], frag=0x2000, ident=7))
    b.add(P.ipv4(s, d, 17, c.bytes("payload.fragment", f, 24), frag=0x0004, ident=7))
    b.add(P.ipv4(s, d, 253, c.bytes("payload.unknown", f, 12)))
    b.add(P.ipv4(s, d, 6, c.bytes("payload.unparsed", f, 10)))  # TCP header cut short
    ah = bytes([17, 4, 0, 0]) + struct.pack("!II", int(c.binary(f, None, field="ah.spi")), 1) + c.bytes("ah.icv", f, 12)
    b.add(P.ipv4(s, d, 51, ah + P.udp(1, 2, b"", checksum=False)))
    b.add(P.ipv4(s, d, 50, struct.pack("!II", int(c.binary(f, None, field="esp.spi")), 1) + c.bytes("payload.encrypted", f, 32)))
    write(out, f, b.bytes())

    f = "l3_ipv6.pcap"
    b = PcapBuilder(101)
    s6, d6 = ip6(c, "ipv6.src", f), ip6(c, "ipv6.dst", f)
    hbh = P.ext(60, bytes([1, 6]) + c.bytes("ipv6.opt.padn", f, 6) + bytes([0x3E, 4]) +
                c.bytes("ipv6.opt.other", f, 4) + bytes([1, 6, 0, 0, 0, 0, 0, 0]))
    dst = P.ext(43, bytes([0xC9, 16]) + ip6(c, "ipv6.opt.hao.addr", f) + bytes([1, 2, 0, 0]))
    rh2 = P.ext(4, bytes([2, 1]) + bytes(4) + ip6(c, "ipv6.rh.addr", f))
    inner = P.udp4(ip4(c, "ipv4.src", f), ip4(c, "ipv4.dst", f), 1, 2, b"")
    b.add(P.ipv6(s6, d6, 0, hbh + dst + rh2 + inner))
    srh = P.ext(59, bytes([4, 1, 1, 0, 0, 0]) + ip6(c, "ipv6.srh.seg", f) + ip6(c, "ipv6.srh.seg", f) +
                c.bytes("ipv6.srh.tlv", f, 8))
    b.add(P.ipv6(s6, d6, 43, srh))
    b.add(P.ipv6(s6, d6, 43, P.ext(59, bytes([253, 0]) + c.bytes("ipv6.rh.data", f, 4))))
    bad = bytes([59, 0]) + bytes([0x3F, 40]) + c.bytes("ipv6.opt.malformed", f, 4)
    b.add(P.ipv6(s6, d6, 0, bad))
    b.add(P.ipv6(s6, d6, 44, bytes([17, 0, 0, 1]) + struct.pack("!I", 5) +
                 P.udp(7, 8, b"abc", pseudo=P.pseudo6(s6, d6, 17, 11))))
    b.add(P.ipv6(s6, d6, 44, bytes([17, 0, 0, 0x20]) + struct.pack("!I", 5) + c.bytes("payload.fragment", f, 16)))
    # Link-local address with an interface identifier derived from a canary MAC (modified EUI-64).
    m = C.mac_bytes(c.mac("ipv6.src", f))
    iid = bytes([m[0] ^ 0x02, m[1], m[2], 0xFF, 0xFE, m[3], m[4], m[5]])
    ll = bytes([0xFE, 0x80]) + bytes(6) + iid
    c._add("ipv6", str(ipaddress.IPv6Address(ll)), "ipv6.src", f)
    mapped_v4 = c.ipv4("ipv6.dst", f)
    mapped = bytes(10) + b"\xff\xff" + C.ipv4_bytes(mapped_v4)
    b.add(P.udp6(ll, mapped, 546, 547, b""))
    nat64_v4 = c.ipv4("ipv6.dst", f)
    b.add(P.udp6(s6, bytes([0, 0x64, 0xff, 0x9b]) + bytes(8) + C.ipv4_bytes(nat64_v4), 1, 2, b""))
    b.add(P.ipv6(s6, d6, 253, c.bytes("payload.unknown", f, 8)))
    write(out, f, b.bytes())

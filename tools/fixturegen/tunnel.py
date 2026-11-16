# SPDX-License-Identifier: GPL-3.0-or-later
"""Tunnel fixtures: GRE (IPv4, Ethernet, unknown), IP-in-IP, GTP-U, nesting bound."""
import struct

from capfile import PcapBuilder
from common import ip4, ip6, mac, text, write
import packets as P


def gen(c, out):
    f = "tunnel.pcap"
    b = PcapBuilder(101)
    s, d = ip4(c, "ipv4.src", f), ip4(c, "ipv4.dst", f)
    inner = P.udp4(ip4(c, "ipv4.src", f), ip4(c, "ipv4.dst", f), 1, 2, text(c, "payload.l7", f))
    b.add(P.ipv4(s, d, 47, P.gre(0x0800, inner, key=42, seq=7, checksum=True)))
    frame = P.ethernet(mac(c, "eth.dst", f), mac(c, "eth.src", f), 0x0800,
                       P.udp4(ip4(c, "ipv4.src", f), ip4(c, "ipv4.dst", f), 1, 2, b""))
    b.add(P.ipv4(s, d, 47, P.gre(0x6558, frame)))
    b.add(P.ipv4(s, d, 47, P.gre(0x88BE, c.bytes("payload.unknown", f, 16))))
    b.add(P.ipv4(s, d, 41, P.udp6(ip6(c, "ipv6.src", f), ip6(c, "ipv6.dst", f), 1, 2, b"")))
    inner6 = P.udp6(ip6(c, "ipv6.src", f), ip6(c, "ipv6.dst", f), 5000, 6000, text(c, "payload.l7", f))
    exts = [(0x85, bytes([0x00, 0x09])), (0x99, c.bytes("gtpu.ext.other", f, 6))]
    b.add(P.udp4(s, d, 2152, 2152, P.gtpu(0x1000, inner6, exts=exts)))
    write(out, f, b.bytes())

    # Nesting beyond the bound of 8: the inner packet is not understood and is zeroed (fail-closed),
    # which an analyser then reports as a bogus inner header. Kept in its own file for that reason.
    f = "tunnel_depth.pcap"
    b = PcapBuilder(101)
    deep = P.udp4(ip4(c, "payload.unparsed", f), ip4(c, "payload.unparsed", f), 1, 2, text(c, "payload.unparsed", f))
    for _ in range(9):
        deep = P.ipv4(s, d, 4, deep)
    b.add(deep)
    write(out, f, b.bytes())

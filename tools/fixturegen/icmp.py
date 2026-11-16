# SPDX-License-Identifier: GPL-3.0-or-later
"""ICMP, ICMPv6 and Neighbor Discovery fixtures."""
import struct

from capfile import PcapBuilder
from common import ip4, ip6, mac, text, write
import packets as P


def gen(c, out):
    f = "icmp.pcap"
    b = PcapBuilder(101)
    s, d = ip4(c, "ipv4.src", f), ip4(c, "ipv4.dst", f)
    b.add(P.ipv4(s, d, 1, P.icmp(8, 0, struct.pack("!HH", 1, 1), text(c, "icmp.data", f))))
    es, ed = ip4(c, "ipv4.src", f), ip4(c, "ipv4.dst", f)
    inv_sctp = P.ipv4(es, ed, 132, struct.pack("!HHI", 2905, 2905, 7) + c.bytes("icmp.embedded.l4.checksum", f, 4) + b"\x01\x00\x00\x10" + bytes(12))
    b.add(P.ipv4(s, d, 1, P.icmp(3, 3, bytes(4), inv_sctp[:28 + 4])))
    inv_udp = P.udp4(ip4(c, "ipv4.src", f), ip4(c, "ipv4.dst", f), 33000, 53, text(c, "icmp.data", f))
    b.add(P.ipv4(s, d, 1, P.icmp(5, 1, ip4(c, "icmp.gateway", f), inv_udp)))
    b.add(P.ipv4(s, d, 1, P.icmp(42, 0, c.bytes("icmp.other", f, 4), c.bytes("icmp.data", f, 8))))
    write(out, f, b.bytes())

    f = "icmpv6.pcap"
    b = PcapBuilder(101)
    s6, d6 = ip6(c, "ipv6.src", f), ip6(c, "ipv6.dst", f)
    inv = P.udp6(ip6(c, "ipv6.src", f), ip6(c, "ipv6.dst", f), 1, 2, text(c, "icmp.data", f))
    b.add(P.ipv6(s6, d6, 58, P.icmpv6(s6, d6, 1, 4, bytes(4) + inv)))
    ns = bytes(4) + ip6(c, "ndp.target", f) + bytes([1, 1]) + mac(c, "ndp.opt.lla", f)
    b.add(P.ipv6(s6, d6, 58, P.icmpv6(s6, d6, 135, 0, ns)))
    prefix = bytes([3, 4, 64, 0xC0]) + struct.pack("!III", 86400, 3600, 0) + ip6(c, "ndp.opt.prefix.addr", f)
    unk = bytes([250, 1]) + c.bytes("ndp.opt.other", f, 6)
    ra = bytes([64, 0]) + struct.pack("!HII", 1800, 0, 0) + prefix + bytes([5, 1, 0, 0]) + \
        struct.pack("!I", 1500) + unk
    b.add(P.ipv6(s6, d6, 58, P.icmpv6(s6, d6, 134, 0, ra)))
    redirect = bytes(4) + ip6(c, "ndp.target", f) + ip6(c, "ndp.dest", f) + bytes([2, 1]) + mac(c, "ndp.opt.lla", f)
    b.add(P.ipv6(s6, d6, 58, P.icmpv6(s6, d6, 137, 0, redirect)))
    b.add(P.ipv6(s6, d6, 58, P.icmpv6(s6, d6, 128, 0, struct.pack("!HH", 1, 1) + text(c, "icmp.data", f))))
    write(out, f, b.bytes())

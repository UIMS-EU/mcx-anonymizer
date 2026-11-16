# SPDX-License-Identifier: GPL-3.0-or-later
"""Link-layer fixtures: Ethernet (+FCS), 802.1ad/802.1Q, ARP, SLL, SLL2, NULL, raw, unknown."""
import struct

from capfile import PcapBuilder
from common import BCAST, ip4, ip6, mac, text, write
import packets as P


def gen(c, out):
    f = "link_eth.pcap"
    b = PcapBuilder(1)
    smac, dmac = mac(c, "eth.src", f), mac(c, "eth.dst", f)
    sip, dip = ip4(c, "ipv4.src", f), ip4(c, "ipv4.dst", f)
    frame = P.ethernet(dmac, smac, 0x0800, P.udp4(sip, dip, 40000, 5060, b"x"))
    b.add(frame + c.bytes("link.trailer", f, 17))  # canary in the Ethernet padding
    inner = P.udp4(ip4(c, "ipv4.src", f), ip4(c, "ipv4.dst", f), 40001, 5060, text(c, "payload.l7", f))
    b.add(P.ethernet(dmac, smac, 0x88A8, P.vlan(0x2064, 0x8100, P.vlan(0x0065, 0x0800, inner))))
    sha, tha = mac(c, "arp.sha", f), mac(c, "arp.tha", f)
    spa, tpa = ip4(c, "arp.spa", f), ip4(c, "arp.tpa", f)
    b.add(P.ethernet(BCAST, mac(c, "eth.src", f), 0x0806, P.arp(sha, spa, tha, tpa)) + bytes(18))
    b.add(P.ethernet(dmac, smac, 0x88B5, c.bytes("payload.unknown", f, 24)))
    write(out, f, b.bytes())

    f = "link_eth_fcs.pcap"
    b = PcapBuilder(1, linktype_field=(2 << 28) | (1 << 26) | 1)
    frame = P.ethernet(mac(c, "eth.dst", f), mac(c, "eth.src", f), 0x0800,
                       P.udp4(ip4(c, "ipv4.src", f), ip4(c, "ipv4.dst", f), 1000, 2000, b"fcs"))
    b.add(frame + P.fcs(frame))
    write(out, f, b.bytes())

    f = "link_sll.pcap"
    b = PcapBuilder(113)
    pad = c.bytes("sll.addr_pad", f, 2)
    pkt = struct.pack("!HHH", 0, 1, 6) + mac(c, "sll.addr", f) + pad + struct.pack("!H", 0x0800) + \
        P.udp4(ip4(c, "ipv4.src", f), ip4(c, "ipv4.dst", f), 1, 2, b"")
    off = b.add(pkt)
    c.at(pad.hex(), off + 12)
    other = c.bytes("sll.addr_other", f, 8)
    b.add(struct.pack("!HHH", 0, 772, 8) + other + struct.pack("!H", 0x0800) +
          P.udp4(ip4(c, "ipv4.src", f), ip4(c, "ipv4.dst", f), 1, 2, b""))
    write(out, f, b.bytes())

    f = "link_sll2.pcap"
    b = PcapBuilder(276)
    pad = c.bytes("sll2.addr_pad", f, 2)
    pkt = struct.pack("!HHIHBB", 0x86DD, 0, 3, 1, 0, 6) + mac(c, "sll2.addr", f) + pad + \
        P.udp6(ip6(c, "ipv6.src", f), ip6(c, "ipv6.dst", f), 1, 2, b"")
    off = b.add(pkt)
    c.at(pad.hex(), off + 18)
    b.add(struct.pack("!HHIHBB", 0x0800, 0, 3, 772, 0, 8) + c.bytes("sll2.addr_other", f, 8) +
          P.udp4(ip4(c, "ipv4.src", f), ip4(c, "ipv4.dst", f), 1, 2, b""))
    write(out, f, b.bytes())

    f = "link_null.pcap"
    b = PcapBuilder(0)
    b.add(struct.pack("<I", 2) + P.udp4(ip4(c, "ipv4.src", f), ip4(c, "ipv4.dst", f), 1, 2, b"n"))
    b.add(struct.pack(">I", 30) + P.udp6(ip6(c, "ipv6.src", f), ip6(c, "ipv6.dst", f), 1, 2, b"n"))
    write(out, f, b.bytes())

    f = "link_raw.pcap"
    b = PcapBuilder(101)
    b.add(P.udp4(ip4(c, "ipv4.src", f), ip4(c, "ipv4.dst", f), 1, 2, b"r"))
    b.add(P.udp6(ip6(c, "ipv6.src", f), ip6(c, "ipv6.dst", f), 1, 2, b"r"))
    write(out, f, b.bytes())

    f = "link_unsupported.pcap"
    b = PcapBuilder(127)  # radiotap: not understood, the whole packet is zeroed
    b.add(c.bytes("payload.unknown", f, 40))
    write(out, f, b.bytes())

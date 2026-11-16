# SPDX-License-Identifier: GPL-3.0-or-later
"""TCP, UDP and SCTP fixtures."""
import struct

from capfile import PcapBuilder
from common import ip4, ip6, text, write
import packets as P


def gen(c, out):
    f = "l4_tcp_udp.pcap"
    b = PcapBuilder(101)
    s, d = ip4(c, "ipv4.src", f), ip4(c, "ipv4.dst", f)
    opts = bytes([19, 18]) + c.bytes("tcp.opt.md5.value", f, 16) + bytes([29, 6]) + \
        c.bytes("tcp.opt.ao.value", f, 4) + bytes([77, 6]) + c.bytes("tcp.opt.other", f, 4) + \
        b"\x00" + c.bytes("tcp.opt.padding", f, 5)
    assert len(opts) == 36
    b.add(P.tcp4(s, d, 40000, 80, 1000, 0, 0x02, options=opts))
    b.add(P.tcp4(s, d, 40000, 80, 1001, 1, 0x10, options=bytes([8, 30]) + c.bytes("tcp.opt.malformed", f, 6)))
    b.add(P.tcp4(s, d, 40000, 80, 1001, 1, 0x18, payload=text(c, "payload.l7", f, "HTTP-CANARY")))
    b.add(P.udp4(s, d, 50000, 5060, text(c, "payload.l7", f, "SIP-CANARY")))
    b.add(P.udp6(ip6(c, "ipv6.src", f), ip6(c, "ipv6.dst", f), 50000, 5060, text(c, "payload.l7", f)))
    write(out, f, b.bytes())

    f = "l4_sctp.pcap"
    b = PcapBuilder(101)
    s, d = ip4(c, "ipv4.src", f), ip4(c, "ipv4.dst", f)
    params = (P.param(5, ip4(c, "sctp.param.ipv4", f)) + P.param(6, ip6(c, "sctp.param.ipv6", f)) +
              P.param(11, text(c, "sctp.param.other", f, "host")) + P.param(12, struct.pack("!HH", 5, 6)) +
              P.param(9, struct.pack("!I", 1000)))
    init = P.chunk(1, 0, struct.pack("!IIHHI", 0x11223344, 65535, 10, 10, 1) + params)
    b.add(P.ipv4(s, d, 132, P.sctp(2905, 2905, 0, init)))
    cookie = P.param(7, c.bytes("sctp.param.other", f, 24))
    initack = P.chunk(2, 0, struct.pack("!IIHHI", 0x55667788, 65535, 10, 10, 1) + cookie)
    b.add(P.ipv4(d, s, 132, P.sctp(2905, 2905, 0x11223344, initack)))
    data = P.chunk(0, 3, struct.pack("!IHHI", 1, 0, 0, 46) + text(c, "payload.l7", f, "DIAMETER"))
    auth = P.chunk(15, 0, struct.pack("!HH", 1, 1) + c.bytes("sctp.auth.hmac", f, 20))
    hb = P.chunk(4, 0, P.param(1, c.bytes("sctp.chunk.other", f, 12)))
    asconf = P.chunk(0xC1, 0, struct.pack("!I", 9) + P.param(5, ip4(c, "sctp.param.ipv4", f)) +
                     P.param(0xC001, struct.pack("!I", 1) + P.param(5, ip4(c, "sctp.param.ipv4", f))))
    unk = P.chunk(0x55, 0, c.bytes("sctp.chunk.other", f, 8))
    b.add(P.ipv4(s, d, 132, P.sctp(2905, 2905, 0x55667788, auth + data)))
    b.add(P.ipv4(s, d, 132, P.sctp(2905, 2905, 0x55667788, hb + asconf + unk)))
    # A chunk whose value has length 1: three padding bytes carry a canary.
    pad = c.bytes("sctp.padding", f, 3)
    tiny = struct.pack("!BBH", 0x56, 0, 5) + b"\x01" + pad
    pkt = P.ipv4(s, d, 132, P.sctp(2905, 2905, 0x55667788, tiny))
    off = b.add(pkt)
    c.at(pad.hex(), off + 20 + 12 + 5)
    write(out, f, b.bytes())

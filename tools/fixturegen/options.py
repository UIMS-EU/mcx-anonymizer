# SPDX-License-Identifier: GPL-3.0-or-later
"""Fixtures for the per-run options: VLAN IDs, ephemeral ports, prefix structure, time shift."""
import struct

from capfile import PcapBuilder
from common import ip4, mac, write
import packets as P
import pcapng


def gen(c, out):
    f = "options_vlan.pcap"
    b = PcapBuilder(1)
    sm, dm = mac(c, "eth.src", f), mac(c, "eth.dst", f)
    s, d = ip4(c, "ipv4.src", f), ip4(c, "ipv4.dst", f)
    for vid in (100, 200, 100):
        b.add(P.ethernet(dm, sm, 0x88A8, P.vlan(0xA000 | vid, 0x8100, P.vlan(0x2000 | (vid + 1), 0x0800,
                                                                             P.udp4(s, d, 1, 2, b"")))))
    write(out, f, b.bytes())

    f = "options_ports.pcap"
    b = PcapBuilder(101)
    s, d = ip4(c, "ipv4.src", f), ip4(c, "ipv4.dst", f)
    for sport in (50000, 50001, 50000):
        b.add(P.udp4(s, d, sport, 5060, b""))
    b.add(P.tcp4(s, d, 61000, 443, 1, 0, 0x02))
    write(out, f, b.bytes())

    f = "options_prefix.pcap"
    b = PcapBuilder(101)
    addrs = [bytes([10, 1, 2, 3]), bytes([10, 1, 2, 200]), bytes([10, 1, 9, 9]), bytes([10, 200, 0, 1]),
             bytes([172, 16, 0, 1])]
    for a in addrs:
        b.add(P.udp4(a, bytes([192, 168, 77, 1]), 1, 2, b""))
    v6a = bytes.fromhex("fd000000000000010000000000000001")
    v6b = bytes.fromhex("fd000000000000010000000000000002")
    v6c = bytes.fromhex("fd000000000000020000000000000001")
    for a in (v6a, v6b, v6c):
        b.add(P.udp6(a, bytes.fromhex("fd0000000000000900000000000000ff"), 1, 2, b""))
    write(out, f, b.bytes())

    f = "options_time.pcap"
    b = PcapBuilder(101)
    s, d = ip4(c, "ipv4.src", f), ip4(c, "ipv4.dst", f)
    for i, (sec, us) in enumerate([(1700000000, 1), (1700000000, 999999), (1700000123, 500000)]):
        b.add(P.udp4(s, d, 1, 2, b""), ts=(sec, us))
    write(out, f, b.bytes())

    f = "options_time.pcapng"
    w = pcapng.Writer()
    frame = P.udp4(ip4(c, "ipv4.src", f), ip4(c, "ipv4.dst", f), 1, 2, b"")
    o = w.o
    data = w.shb() + w.idb(101, 0, [(9, b"\x09")]) + w.idb(101, 0, [(9, b"\x8a")])
    data += w.epb(0, 1700000000123456789, frame) + w.epb(0, 1700000000123456790, frame)
    data += w.epb(1, 1700000000 * 1024 + 3, frame)
    data += w.isb(0, 1700000001000000000, [(2, struct.pack(o + "II", 1700000000123456789 >> 32,
                                                             1700000000123456789 & 0xFFFFFFFF)),
                                            (3, struct.pack(o + "II", 1700000001000000000 >> 32,
                                                            1700000001000000000 & 0xFFFFFFFF))])
    write(out, f, data)

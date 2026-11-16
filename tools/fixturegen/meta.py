# SPDX-License-Identifier: GPL-3.0-or-later
"""pcapng metadata fixtures: canaries in every block and option the tool removes."""
import struct

from common import ip4, ip6, mac, text, write
import canary as C
import packets as P
import pcapng


def _frame(c, f):
    return P.ethernet(mac(c, "eth.dst", f), mac(c, "eth.src", f), 0x0800,
                      P.udp4(ip4(c, "ipv4.src", f), ip4(c, "ipv4.dst", f), 1, 2, b""))


def _section(c, f, w):
    o = w.o
    blocks = [w.shb([(1, text(c, "pcapng.opt.comment", f)), (2, text(c, "pcapng.shb.hardware", f)),
                     (3, text(c, "pcapng.shb.os", f)), (4, text(c, "pcapng.shb.userappl", f)),
                     (2988, struct.pack(o + "I", 32473) + text(c, "pcapng.opt.custom", f)),
                     (0x8001, c.bytes("pcapng.opt.other", f, 8))])]
    v4 = ip4(c, "pcapng.idb.ipv4addr", f)
    v6 = ip6(c, "pcapng.idb.ipv6addr", f)
    blocks.append(w.idb(1, 262144, [
        (2, text(c, "pcapng.idb.name", f)), (3, text(c, "pcapng.idb.description", f)),
        (4, v4 + b"\xff\xff\xff\x00"), (5, v6 + b"\x40"), (6, mac(c, "pcapng.idb.macaddr", f)),
        (7, c.bytes("pcapng.idb.euiaddr", f, 8)), (8, c.bytes("pcapng.idb.speed", f, 8)),
        (9, b"\x06"), (10, c.bytes("pcapng.idb.tzone", f, 4)),
        (11, b"\x00" + text(c, "pcapng.idb.filter", f)), (12, text(c, "pcapng.idb.os", f)),
        (14, struct.pack(o + "q", 0)), (15, text(c, "pcapng.idb.hardware", f)),
        (16, c.bytes("pcapng.idb.txspeed", f, 8)), (17, c.bytes("pcapng.idb.rxspeed", f, 8)),
        (18, text(c, "pcapng.idb.iana_tzname", f)), (1, text(c, "pcapng.opt.comment", f)),
        (99, c.bytes("pcapng.opt.other", f, 6)),
        (2989, struct.pack(o + "I", 32473) + c.bytes("pcapng.opt.custom", f, 8))]))
    blocks.append(w.epb(0, 1700000000000000, _frame(c, f), [
        (1, text(c, "pcapng.opt.comment", f)), (2, struct.pack(o + "I", 0x1)),
        (3, b"\x02" + c.bytes("pcapng.epb.hash", f, 4)), (4, struct.pack(o + "Q", 3)),
        (5, c.bytes("pcapng.epb.packetid", f, 8)), (6, c.bytes("pcapng.epb.queue", f, 4)),
        (7, b"\x00" + c.bytes("pcapng.epb.verdict", f, 7)),
        (8, c.bytes("pcapng.epb.processid_threadid", f, 8)),
        (19372, struct.pack(o + "I", 32473) + text(c, "pcapng.opt.custom", f)),
        (19373, struct.pack(o + "I", 32473) + c.bytes("pcapng.opt.custom", f, 8))]))
    blocks.append(w.spb(_frame(c, f)))
    blocks.append(w.packet_block_obsolete(0, 1700000000000500, _frame(c, f), [
        (2, struct.pack(o + "I", 0x2)), (3, b"\x02" + c.bytes("pcapng.epb.hash", f, 4)),
        (1, text(c, "pcapng.opt.comment", f))]))
    blocks.append(w.isb(0, 1700000000001000, [(1, text(c, "pcapng.opt.comment", f)),
                                               (2, struct.pack(o + "II", 0, 1)),
                                               (4, struct.pack(o + "Q", 4))]))
    nrb_v4 = ip4(c, "pcapng.blk.nrb", f)
    nrb_v6 = ip6(c, "pcapng.blk.nrb", f)
    nrb_mac = mac(c, "pcapng.blk.nrb", f)
    blocks.append(w.nrb([(1, nrb_v4 + text(c, "pcapng.blk.nrb", f, "host") + b"\x00"),
                         (2, nrb_v6 + text(c, "pcapng.blk.nrb", f, "host6") + b"\x00"),
                         (3, nrb_mac + text(c, "pcapng.blk.nrb", f, "macname") + b"\x00")],
                        [(2, text(c, "pcapng.blk.nrb", f, "dns")), (3, ip4(c, "pcapng.blk.nrb", f))]))
    blocks.append(w.dsb(0x544c534b, b"CLIENT_RANDOM " + text(c, "pcapng.blk.dsb", f, "KEYLOG") + b"\n"))
    blocks.append(w.custom(pcapng.CUSTOM_COPY, 32473, c.bytes("pcapng.blk.custom", f, 16)))
    blocks.append(w.custom(pcapng.CUSTOM_NOCOPY, 32473, text(c, "pcapng.blk.custom", f)))
    blocks.append(w.block(9, text(c, "pcapng.blk.journal", f, "__REALTIME_TIMESTAMP")))
    blocks.append(w.block(0x1234, c.bytes("pcapng.blk.other", f, 12)))
    blocks.append(w.block(0x80000001, text(c, "pcapng.blk.other", f)))
    return b"".join(blocks)


def gen(c, out):
    f = "meta_all.pcapng"
    data = _section(c, f, pcapng.Writer(big_endian=False)) + _section(c, f, pcapng.Writer(big_endian=True))
    write(out, f, data)

    f = "fcs_ethernet.pcapng"
    w = pcapng.Writer()
    frame = _frame(c, f)
    write(out, f, w.shb() + w.idb(1, 262144, [(13, b"\x04")]) +
          w.epb(0, 1700000000000000, frame + P.fcs(frame)))

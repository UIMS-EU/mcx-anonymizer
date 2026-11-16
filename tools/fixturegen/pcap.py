# SPDX-License-Identifier: GPL-3.0-or-later
"""Classic pcap writer (draft-ietf-opsawg-pcap-09)."""
import struct

MAGIC_US = 0xA1B2C3D4
MAGIC_NS = 0xA1B23C4D


def pcap_file(packets, linktype=1, snaplen=262144, big_endian=False, nanosecond=False,
              linktype_field=None):
    """packets: iterable of (ts_sec, ts_frac, data[, origlen])."""
    o = ">" if big_endian else "<"
    lt = linktype if linktype_field is None else linktype_field
    out = bytearray(struct.pack(o + "IHHiiII", MAGIC_NS if nanosecond else MAGIC_US, 2, 4, 0, 0,
                                snaplen, lt))
    for p in packets:
        ts_sec, ts_frac, data = p[0], p[1], p[2]
        origlen = p[3] if len(p) > 3 else len(data)
        out += struct.pack(o + "IIII", ts_sec, ts_frac, len(data), origlen) + bytes(data)
    return bytes(out)

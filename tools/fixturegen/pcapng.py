# SPDX-License-Identifier: GPL-3.0-or-later
"""pcapng writer (draft-ietf-opsawg-pcapng-06): arbitrary blocks and options."""
import struct

SHB = 0x0A0D0D0A
IDB = 1
PB_OBSOLETE = 2
SPB = 3
NRB = 4
ISB = 5
EPB = 6
DSB = 10
CUSTOM_COPY = 0x00000BAD
CUSTOM_NOCOPY = 0x40000BAD


def _pad(b):
    return bytes(b) + b"\x00" * (-len(b) % 4)


class Writer:
    def __init__(self, big_endian=False):
        self.o = ">" if big_endian else "<"

    def option(self, code, value):
        value = value.encode() if isinstance(value, str) else bytes(value)
        return struct.pack(self.o + "HH", code, len(value)) + _pad(value)

    def options(self, opts):
        """opts: list of (code, value). Empty list -> no option block."""
        if not opts:
            return b""
        return b"".join(self.option(c, v) for c, v in opts) + struct.pack(self.o + "HH", 0, 0)

    def block(self, btype, body):
        body = _pad(body)
        total = 12 + len(body)
        return struct.pack(self.o + "II", btype, total) + body + struct.pack(self.o + "I", total)

    def shb(self, opts=()):
        body = struct.pack(self.o + "IHHq", 0x1A2B3C4D, 1, 0, -1) + self.options(list(opts))
        return self.block(SHB, body)

    def idb(self, linktype, snaplen=262144, opts=()):
        return self.block(IDB, struct.pack(self.o + "HHI", linktype, 0, snaplen) +
                          self.options(list(opts)))

    def epb(self, ifid, ts, data, opts=(), origlen=None):
        data = bytes(data)
        body = struct.pack(self.o + "IIIII", ifid, (ts >> 32) & 0xFFFFFFFF, ts & 0xFFFFFFFF,
                           len(data), len(data) if origlen is None else origlen)
        return self.block(EPB, body + _pad(data) + self.options(list(opts)))

    def spb(self, data, origlen=None):
        data = bytes(data)
        return self.block(SPB, struct.pack(self.o + "I", len(data) if origlen is None else origlen)
                          + _pad(data))

    def packet_block_obsolete(self, ifid, ts, data, opts=()):
        data = bytes(data)
        body = struct.pack(self.o + "HHIIII", ifid, 0xFFFF, (ts >> 32) & 0xFFFFFFFF,
                           ts & 0xFFFFFFFF, len(data), len(data))
        return self.block(PB_OBSOLETE, body + _pad(data) + self.options(list(opts)))

    def isb(self, ifid, ts, opts=()):
        body = struct.pack(self.o + "III", ifid, (ts >> 32) & 0xFFFFFFFF, ts & 0xFFFFFFFF)
        return self.block(ISB, body + self.options(list(opts)))

    def nrb(self, records, opts=()):
        """records: list of (type, value_bytes)."""
        body = b"".join(struct.pack(self.o + "HH", t, len(v)) + _pad(v) for t, v in records)
        body += struct.pack(self.o + "HH", 0, 0)
        return self.block(NRB, body + self.options(list(opts)))

    def dsb(self, secrets_type, data, opts=()):
        data = bytes(data)
        body = struct.pack(self.o + "II", secrets_type, len(data)) + _pad(data)
        return self.block(DSB, body + self.options(list(opts)))

    def custom(self, btype, pen, data):
        return self.block(btype, struct.pack(self.o + "I", pen) + bytes(data))

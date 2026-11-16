# SPDX-License-Identifier: GPL-3.0-or-later
"""pcap file assembly that remembers where each packet starts in the file."""
import pcap


class PcapBuilder:
    def __init__(self, linktype=1, nanosecond=False, linktype_field=None, big_endian=False):
        self.linktype = linktype
        self.nanosecond = nanosecond
        self.linktype_field = linktype_field
        self.big_endian = big_endian
        self.packets = []
        self.offset = 24  # next record starts here

    def add(self, data, ts=None, origlen=None):
        """Returns the file offset of the packet data."""
        n = len(self.packets)
        ts_sec, ts_frac = ts if ts else (1700000000 + n, 1000 * n)
        self.packets.append((ts_sec, ts_frac, bytes(data)) + ((origlen,) if origlen else ()))
        data_off = self.offset + 16
        self.offset += 16 + len(data)
        return data_off

    def bytes(self):
        return pcap.pcap_file(self.packets, linktype=self.linktype, nanosecond=self.nanosecond,
                              linktype_field=self.linktype_field, big_endian=self.big_endian)

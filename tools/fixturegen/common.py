# SPDX-License-Identifier: GPL-3.0-or-later
"""Helpers shared by the fixture sets."""
import os

import canary as C

BCAST = b"\xff" * 6


def mac(c, field, f):
    return C.mac_bytes(c.mac(field, f))


def ip4(c, field, f):
    return C.ipv4_bytes(c.ipv4(field, f))


def ip6(c, field, f):
    return C.ipv6_bytes(c.ipv6(field, f))


def text(c, field, f, prefix="CANARY"):
    return c.string(field, f, prefix).encode()


def write(out, name, data):
    with open(os.path.join(out, name), "wb") as fh:
        fh.write(data)

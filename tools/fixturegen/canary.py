# SPDX-License-Identifier: GPL-3.0-or-later
"""Canary registry: every planted value with its category and its rule key.

The manifest (canaries.json) lets the independent oracle search the
anonymised output for every planted value, and lets the rule-coverage test
check that every non-keep rule has a canary.

Each canary names what classified it:
  - "field": a packet FieldId of the L2-L4 rule set (rules/*.yaml with "- field:");
  - "rule": a key of the SIP rule set, one of
      sip:<Header>.<component>     a header component, e.g. sip:From.display-name
      sip-param:<Header>;<param>   a header parameter, e.g. sip-param:Via;branch
      uri-param:<name>             a URI parameter, e.g. uri-param:maddr
      sdp:<line|a=attr>[.<field>]  an SDP line or attribute, e.g. sdp:o=.username, sdp:a=rtcp
      tag:<feature-tag>            a media feature tag or capability, e.g. tag:+sip.instance
      body:<content-type>          a body type, e.g. body:application/pidf+xml
  - "rule": a key of the XML rule set (feature 003), one of
      xml:<ns>|<parent or ->|<local>              an element
      xml:<ns>|<element>|@<attr ns or ->|<local>  an attribute
      xml-ns:<ns>                                 a namespace removed as a whole
A canary may carry both keys.

Categories: ipv4, ipv6, mac (text forms and binary), string (text, case-insensitive),
bytes (hex of raw bytes), number (decimal digits, matched on digit boundaries) and
binary (a 32-bit value, recorded as decimal, matched as 4 big-endian bytes and as
digit-bounded decimal text).
"""
import ipaddress
import json
import random


class Canaries:
    def __init__(self, seed):
        self.rng = random.Random(seed)
        self.items = []
        self._used = set()

    def _unique(self, make):
        for _ in range(1000):
            v = make()
            if v not in self._used:
                self._used.add(v)
                return v
        raise RuntimeError("cannot draw a unique canary value")

    def _add(self, category, value, field, fname, rule=None):
        if field is None and rule is None:
            raise ValueError("a canary needs a field or a rule key")
        cid = f"c{len(self.items) + 1:04d}"
        item = {"id": cid, "category": category, "value": value, "files": [fname]}
        if field is not None:
            item["field"] = field
        if rule is not None:
            item["rule"] = rule
        self.items.append(item)
        return value

    def ipv4(self, field, fname, rule=None):
        """A private-range IPv4 address (10.0.0.0/8), as dotted text."""
        v = self._unique(lambda: str(ipaddress.IPv4Address(0x0A000000 | self.rng.getrandbits(24))))
        return self._add("ipv4", v, field, fname, rule)

    def ipv6(self, field, fname, rule=None):
        """A ULA IPv6 address (fd00::/8), as compressed text."""
        v = self._unique(lambda: str(ipaddress.IPv6Address((0xFD << 120) | self.rng.getrandbits(120))))
        return self._add("ipv6", v, field, fname, rule)

    def mac(self, field, fname):
        """A universally administered unicast MAC, as colon-separated text."""
        def make():
            b = [self.rng.getrandbits(8) for _ in range(6)]
            b[0] &= 0xFC
            return ":".join(f"{x:02x}" for x in b)
        return self._add("mac", self._unique(make), field, fname)

    def string(self, field, fname, prefix="CANARY", rule=None):
        v = self._unique(lambda: f"{prefix}-{self.rng.getrandbits(48):012x}")
        return self._add("string", v, field, fname, rule)

    def text(self, value, fname, rule, field=None):
        """Records a given string value (for values with a fixed syntax, e.g. a hex nonce)."""
        if value in self._used:
            raise ValueError("canary value already planted; use reuse()")
        self._used.add(value)
        return self._add("string", value, field, fname, rule)

    def number(self, fname, digits, rule, field=None):
        """A decimal number of the given digit count without a leading zero."""
        def make():
            return str(self.rng.randrange(10 ** (digits - 1), 10 ** digits))
        return self._add("number", self._unique(make), field, fname, rule)

    def binary(self, fname, rule, field=None, low=256):
        """A 32-bit value (SPI, SSRC) in [low, 2^32), recorded as decimal text."""
        return self._add("binary", self._unique(lambda: str(self.rng.randrange(low, 1 << 32))),
                         field, fname, rule)

    def bytes(self, field, fname, n, rule=None):
        """Random bytes in 0x80..0xFE (never plain ASCII), recorded as lowercase hex."""
        def make():
            return bytes(self.rng.randrange(0x80, 0xFF) for _ in range(n)).hex()
        return bytes.fromhex(self._add("bytes", self._unique(make), field, fname, rule))

    def at(self, value_hex, offset):
        """Records the file offset of the last canary with this value (layout-preserving checks)."""
        for it in reversed(self.items):
            if it["value"] == value_hex:
                it["offset"] = offset
                return
        raise KeyError(value_hex)

    def ipv4_text(self, field, fname, prefix, rule=None):
        """An IPv4 address inside a given /8 or /16 (prefix = list of leading octets)."""
        def make():
            octets = list(prefix) + [self.rng.randrange(1, 255) for _ in range(4 - len(prefix))]
            return ".".join(str(o) for o in octets)
        return self._add("ipv4", self._unique(make), field, fname, rule)

    def reuse(self, value, field, fname, rule=None):
        """Records that an existing canary value also appears elsewhere (in another file,
        or under another rule key, kept in "also")."""
        for it in self.items:
            if it["value"] == value:
                if fname not in it["files"]:
                    it["files"].append(fname)
                key = rule or field
                if key and key not in (it.get("rule"), it.get("field")):
                    it.setdefault("also", [])
                    if key not in it["also"]:
                        it["also"].append(key)
                return value
        raise KeyError(value)

    def write(self, path):
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"format": 1, "canaries": self.items}, f, indent=2, sort_keys=True)
            f.write("\n")


def ipv4_bytes(text):
    return ipaddress.IPv4Address(text).packed


def ipv6_bytes(text):
    return ipaddress.IPv6Address(text).packed


def mac_bytes(text):
    return bytes(int(x, 16) for x in text.split(":"))

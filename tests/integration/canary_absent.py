#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Independent oracle: no canary of the manifest may appear in an output file.

Searches the raw bytes of each given file for every canary planted in the
corresponding input (or every canary with --all), in the encodings of FR-032:
binary, text forms (upper/lower case, MAC separators), hex, base64, UTF-16LE/BE,
URL-encoding (also the SIP %xx escaping of every character, RFC 3261 §25.1, with
upper- and lower-case hex digits), reverse DNS, IPv4 embedded in IPv6 and MAC in
modified EUI-64. String canaries are also searched case-insensitively. Number
canaries (decimal digits) match only when bounded by non-digits on both sides.
Binary canaries (32-bit values) match as 4 big-endian bytes and as digit-bounded
decimal text. Short binary canaries (< 4 bytes) are checked at their recorded
offset only (when --layout-preserved is given).

Canaries flagged "chance" (hex values of at most 6 digits) are never searched: they occur by
chance in the hex of pseudonym labels and digests (feature 003; the scanner skips them too).

With --report, OUTPUT is a report: canaries marked "report_allowed" are not searched (names
of unknown XML elements and attributes, which the report lists by name like unknown SIP
header names, FR-020 of feature 003), and a number or binary canary is not matched where it is a
whole JSON number value (the report's numbers are counts and lengths, never input values).

Usage: canary_absent.py MANIFEST OUTPUT [--source INPUT_NAME | --all] [--layout-preserved] [--report]
Prints one line per hit (offset, encoding, canary id; never the value).
"""
import argparse
import base64
import ipaddress
import json
import re
import sys
import urllib.parse


def text_forms(s):
    forms = {s, s.lower(), s.upper()}
    return forms


def encodings(c):
    """Yields (encoding_name, bytes_pattern)."""
    cat, v = c["category"], c["value"]
    raws = []
    texts = []
    if cat == "ipv4":
        a = ipaddress.IPv4Address(v)
        raws.append(("binary", a.packed))
        texts += [("text", str(a)), ("reverse-dns", ".".join(reversed(str(a).split("."))) + ".in-addr.arpa")]
        raws.append(("ipv4-in-ipv6", b"\x00" * 10 + b"\xff\xff" + a.packed))
        texts += [("ipv4-mapped-text", "::ffff:" + str(a))]
    elif cat == "ipv6":
        a = ipaddress.IPv6Address(v)
        raws.append(("binary", a.packed))
        texts += [("text", a.compressed), ("text-full", a.exploded),
                  ("reverse-dns", ".".join(reversed(a.packed.hex())) + ".ip6.arpa")]
    elif cat == "mac":
        b = bytes(int(x, 16) for x in v.split(":"))
        raws.append(("binary", b))
        h = b.hex()
        texts += [("text", ":".join(h[i:i + 2] for i in range(0, 12, 2))),
                  ("text-dash", "-".join(h[i:i + 2] for i in range(0, 12, 2))),
                  ("text-dot", ".".join(h[i:i + 4] for i in range(0, 12, 4)))]
        raws.append(("eui64", bytes([b[0] ^ 0x02, b[1], b[2], 0xFF, 0xFE, b[3], b[4], b[5]])))
    elif cat == "string":
        raws.append(("text", v.encode()))
        texts.append(("text", v))
    elif cat == "bytes":
        raws.append(("binary", bytes.fromhex(v)))
    elif cat == "binary":
        # 4 big-endian bytes only: the hex and base64 forms of a 32-bit value are 8 and 6
        # characters that occur by chance in digit strings.
        yield "binary", int(v).to_bytes(4, "big")
        return
    for name, r in raws:
        if len(r) >= 4:
            yield name, r
            yield "hex", r.hex().encode()
            yield "hex-upper", r.hex().upper().encode()
            for shift in range(3):
                enc = base64.b64encode(b"\x00" * shift + r)
                # Stable inner part, as the scanner computes it (src/scan/patterns.cpp): skip the
                # characters influenced by the alignment bytes or by the end. Feature 005: a shorter
                # 4-character window of a 5-byte value ("ali" of "alice") matched the base64 of the
                # pseudonym TLD ".invalid" inside base64 MIKEY by chance.
                lead = (shift * 8 + 5) // 6
                stable_end = ((shift + len(r)) * 8) // 6
                if stable_end > lead + 4:
                    yield "base64", enc[lead:stable_end]
    for name, t in texts:
        for form in text_forms(t):
            if len(form) < 4:
                continue
            yield name, form.encode()
            yield "utf16le", form.encode("utf-16-le")
            yield "utf16be", form.encode("utf-16-be")
            q = urllib.parse.quote(form, safe="")
            if q != form:
                yield "url", q.encode()
                yield "url-lower", re.sub(r"%[0-9A-F]{2}", lambda m: m.group(0).lower(), q).encode()
            # SIP escaping may encode any character (RFC 3261 §25.1 "escaped")
            full = "".join(f"%{b:02X}" for b in form.encode())
            yield "pct-all", full.encode()
            yield "pct-all-lower", full.lower().encode()


def digit_bounded(data, digits, json_numbers=False):
    """Offset of the first occurrence of the digit string not adjacent to another digit. With
    json_numbers, an occurrence that is a whole JSON number value is skipped: every number of a
    report is a count or length the tool computed (feature 005: the scanner's pattern count of a
    shared project once equalled a 5-digit canary, finding F1 class)."""
    pat = re.compile(rb"(?<![0-9])" + re.escape(digits.encode()) + rb"(?![0-9])")
    for m in pat.finditer(data):
        if json_numbers:
            before = data[:m.start()].rstrip()[-1:]
            after = data[m.end():].lstrip()[:1]
            if before in (b":", b"[", b",") and after in (b",", b"}", b"]"):
                continue
        return m.start()
    return -1


def key(c):
    return c.get("rule") or c.get("field") or "?"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("manifest")
    ap.add_argument("output")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--source")
    g.add_argument("--all", action="store_true")
    ap.add_argument("--layout-preserved", action="store_true")
    ap.add_argument("--report", action="store_true")
    a = ap.parse_args()
    canaries = json.load(open(a.manifest, encoding="utf-8"))["canaries"]
    data = open(a.output, "rb").read()
    lowered = data.lower()
    hits = 0
    checked = 0
    for c in canaries:
        if a.source and a.source not in c["files"]:
            continue
        if a.report and c.get("report_allowed"):
            continue
        if c.get("chance"):
            continue  # a hex value of at most 6 digits: matches pseudonym hex by chance
        checked += 1
        if c["category"] == "bytes" and len(bytes.fromhex(c["value"])) < 4:
            if a.layout_preserved and "offset" in c and a.source in c["files"]:
                v = bytes.fromhex(c["value"])
                if data[c["offset"]:c["offset"] + len(v)] == v:
                    print(f"HIT offset {c['offset']} encoding binary-at-offset canary {c['id']} rule {key(c)}")
                    hits += 1
            continue
        if c["category"] in ("number", "binary"):
            at = digit_bounded(data, c["value"], json_numbers=a.report)
            if at >= 0:
                print(f"HIT offset {at} encoding decimal canary {c['id']} rule {key(c)}")
                hits += 1
                continue
            if c["category"] == "number":
                continue
        for enc, pat in encodings(c):
            at = data.find(pat)
            if at < 0 and c["category"] == "string" and enc == "text":
                at = lowered.find(pat.lower())
                enc = "text-any-case"
            if at >= 0:
                print(f"HIT offset {at} encoding {enc} canary {c['id']} rule {key(c)}")
                hits += 1
                break
    print(f"canary_absent: {checked} canaries checked, {hits} hit(s)", file=sys.stderr)
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())

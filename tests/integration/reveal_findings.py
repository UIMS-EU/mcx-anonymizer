#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Findings-text builder for the reveal tests (feature 006).

From a project's mapping (`mcxanon project show-map`), write an analyst's findings text that
quotes the pseudonyms in several textual styles (as the tool writes them, as tshark shows them,
upper case, compressed and expanded IPv6, 0x and decimal, percent-escaped, inside a Markdown
table and a CSV line), and the text expected after `mcxanon reveal`.

Values that reveal treats as ambiguous by design (small value spaces, 6 characters or fewer)
are left out, so the expected text is exact.

Usage: reveal_findings.py MCXANON DATA_DIR PROJECT FINDINGS_OUT EXPECTED_OUT
"""
import ipaddress
import subprocess
import sys

SMALL = {"vlan", "port-eph", "tac", "nr-tac", "mbsfn-area", "mbms-sai", "mbs-fsa"}
BINARY = {"spi", "ssrc", "fc-ref", "eci", "nci"}
FOLDED_LOWER = {"uuid", "session-id"}  # originals canonicalised to lower case


def luhn(digits):
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return str((10 - total % 10) % 10)


def show_map(exe, data_dir, project):
    out = subprocess.run([exe, "--data-dir", data_dir, "project", "show-map", project], capture_output=True,
                         text=True, check=True).stdout
    rows = []
    for line in out.splitlines()[1:]:
        cat, orig, pseudo, _counter, _runs = line.split("\t")
        rows.append((cat, orig, pseudo))
    return rows


def build(rows):
    pairs = []  # (pseudonym text, expected original text)
    pseudos = {}
    for cat, orig, pseudo in rows:
        pseudos.setdefault(pseudo.lower(), set()).add(orig)
    originals = {orig.lower() for _c, orig, _p in rows}
    domains = {orig: pseudo for cat, orig, pseudo in rows if cat == "domain"}
    orig_of = {pseudo: orig for _c, orig, pseudo in rows}

    def usable(cat, pseudo):
        return (cat not in SMALL and len(pseudo) > 6 and len(pseudos.get(pseudo.lower(), ())) == 1
                and pseudo.lower() not in originals and "\\" not in pseudo + orig_of[pseudo])

    for cat, orig, pseudo in rows:
        if cat == "domain":
            labels = orig.split(".")
            if len(labels) > 1 and all(l and all(c.isalnum() or c == "-" for c in l) for l in labels):
                parts = []
                for i in range(len(labels) - 1):
                    suffix = ".".join(labels[i:])
                    if suffix not in domains:
                        parts = None
                        break
                    parts.append(domains[suffix])
                if parts:
                    chain = ".".join(parts) + ".invalid"
                    pairs.append((chain, orig))
                    pairs.append((chain.upper(), orig.upper()))
            continue
        if cat in ("ipv4", "ipv4-pp"):
            pairs.append((pseudo, orig))
            pairs.append((pseudo + ":5060", orig + ":5060"))
            continue
        if cat in ("ipv6", "ipv6-pp"):
            p, o = ipaddress.IPv6Address(pseudo), ipaddress.IPv6Address(orig)
            pairs.append((p.compressed, o.compressed))
            pairs.append(("[" + p.exploded + "]:5061", "[" + o.exploded + "]:5061"))
            continue
        if cat == "ipv6-iid-ll":
            p = ipaddress.IPv6Address(bytes.fromhex("fe80000000000000" + pseudo))
            o = ipaddress.IPv6Address(bytes.fromhex("fe80000000000000" + orig))
            pairs.append((p.compressed, o.compressed))
            continue
        if cat == "ipv6-sn24":
            p = ipaddress.IPv6Address(bytes.fromhex("ff0200000000000000000001ff" + pseudo))
            o = ipaddress.IPv6Address(bytes.fromhex("ff0200000000000000000001ff" + orig))
            pairs.append((p.compressed, o.compressed))
            continue
        if cat == "mac":
            pairs.append((pseudo, orig))
            pairs.append((pseudo.replace(":", "-").upper(), orig.replace(":", "-").upper()))
            continue
        if cat in BINARY:
            if len(pseudo) <= 6:
                continue
            pairs.append((pseudo, orig))
            if cat in ("ssrc", "spi", "fc-ref"):
                pairs.append((f"0x{int(pseudo):08x}", f"0x{int(orig):08x}"))
            continue
        if cat == "imei":
            pairs.append((pseudo + luhn(pseudo), orig + luhn(orig)))
            continue
        if not usable(cat, pseudo):
            continue
        pairs.append((pseudo, orig))
        if cat in FOLDED_LOWER:
            pairs.append((pseudo.upper(), orig.upper()))
        if "@" in pseudo and orig.isascii():
            unreserved = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~")
            enc = "".join(c if c in unreserved else ("%40" if c == "@" else "%%%02X" % ord(c)) for c in orig)
            pairs.append((pseudo.replace("@", "%40"), enc))
    findings, expected = [], []
    findings.append("# Findings")
    expected.append("# Findings")
    findings.append("")
    expected.append("")
    findings.append("| # | value | note |")
    expected.append("| # | value | note |")
    for i, (p, o) in enumerate(pairs):
        findings.append(f"| {i} | {p} | check |")
        expected.append(f"| {i} | {o} | check |")
    findings.append("")
    expected.append("")
    for i, (p, o) in enumerate(pairs):
        findings.append(f'{i},"{p}",flagged')
        expected.append(f'{i},"{o}",flagged')
    return "\n".join(findings) + "\n", "\n".join(expected) + "\n", pairs


def main():
    if len(sys.argv) != 6:
        print(__doc__, file=sys.stderr)
        return 2
    exe, data_dir, project, out_f, out_e = sys.argv[1:]
    findings, expected, _pairs = build(show_map(exe, data_dir, project))
    open(out_f, "w", encoding="utf-8").write(findings)
    open(out_e, "w", encoding="utf-8").write(expected)
    return 0


if __name__ == "__main__":
    sys.exit(main())

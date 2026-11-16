#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""SC-003: every address written in Via, Contact, Record-Route and SDP (c=, o=, a=rtcp) of the
output is the pseudonym of an address that the IP headers of the same capture carry; and every
SPI of Security-Client/-Server/-Verify equals the SPI of an ESP packet (FR-014).

Text forms are compared by value (bracketed, compressed or full IPv6 all count).
Usage: sip_consistency.py CAPTURE
Exit: 0 ok, 1 differs, 77 tshark not installed (unless MCXANON_REQUIRE_TSHARK=1).
"""
import ipaddress
import os
import re
import shutil
import subprocess
import sys

TEXT = ["sip.Via", "sip.Contact", "sip.Record-Route", "sdp.connection_info", "sdp.owner", "sdp.media_attr"]
V4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
V6 = re.compile(r"\[([0-9A-Fa-f:.]+)\]|(?<![0-9A-Za-z:])((?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})(?![0-9A-Za-z:])")


def fields(path, names, flt=None):
    args = ["tshark", "-n", "-r", path, "-T", "fields", "-E", "separator=\t", "-E", "aggregator=\x1f"]
    if flt:
        args += ["-Y", flt]
    for n in names:
        args += ["-e", n]
    r = subprocess.run(args, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(r.stderr)
    return [line.split("\t") for line in r.stdout.splitlines()]


def addresses(text):
    out = set()
    for m in V4.finditer(text):
        try:
            out.add(ipaddress.ip_address(m.group(1)))
        except ValueError:
            pass
    for m in V6.finditer(text):
        s = m.group(1) or m.group(2)
        try:
            out.add(ipaddress.ip_address(s))
        except ValueError:
            pass
    return out


def main():
    if shutil.which("tshark") is None:
        if os.environ.get("MCXANON_REQUIRE_TSHARK") == "1":
            print("tshark is required but not installed", file=sys.stderr)
            return 1
        print("tshark not installed: skipped", file=sys.stderr)
        return 77
    path = sys.argv[1]
    headers = set()
    for row in fields(path, ["ip.src", "ip.dst", "ipv6.src", "ipv6.dst"]):
        for cell in row:
            for v in cell.split("\x1f"):
                if v:
                    headers.add(ipaddress.ip_address(v))
    problems = []
    written = set()
    for row in fields(path, TEXT, "sip"):
        for cell in row:
            written |= addresses(cell.replace("\x1f", " "))
    for a in sorted(written, key=str):
        if a not in headers and not a.is_unspecified:
            problems.append(f"text address {a} is not an IP header address of the capture")
    esp = set()
    for row in fields(path, ["esp.spi"], "esp"):
        esp |= {int(v, 16) for v in row[0].split("\x1f") if v}
    spis = set()
    for row in fields(path, ["sip.Security-Client", "sip.Security-Server", "sip.Security-Verify"], "sip"):
        for cell in row:
            spis |= {int(x) for x in re.findall(r"spi-[cs]=(\d+)", cell)}
    if esp:
        for s in sorted(spis):
            if s not in esp:
                problems.append(f"SPI {s} of Security-* is not the SPI of an ESP packet")
    for p in problems:
        print("FAIL " + p)
    print(f"sip_consistency: {len(written)} text addresses, {len(spis)} SPIs, {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())

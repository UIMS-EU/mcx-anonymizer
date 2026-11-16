#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Independent oracle for SC-003: every SSRC and every identity has exactly one pseudonym across
SDP, RTP, RTCP, RTCP APP, MSRP and SIP within a project.

Packets quoted inside ICMP errors are ICMP data (zeroed or dropped by feature 001) and are
skipped. Input and output keep their frame numbers (the anonymiser never reorders or drops a media
packet), so the same frame and field position pairs an original with its pseudonym. Pairs are
collected with tshark from:
  - SDP: a=ssrc ids, mc_ssrc, mc_floor_ssrc and mc_transmission_ssrc (sdp.media_attr);
  - RTP: rtp.ssrc and rtp.csrc.item;
  - SDP: a=ssrc cname values and a=path URIs;
  - RTP: rtp.ssrc and rtp.csrc.item;
  - RTCP: the sender SSRC, report block, SDES chunk and BYE SSRCs, and SDES CNAME items;
  - MCPTT APP: the header SSRC, SSRC fields, and the user, queued user, granted party and
    functional alias URIs;
  - SIP: the From, To, P-Asserted-Identity and P-Preferred-Identity URIs, in the same "uri"
    kind as the APP URIs, so that an MCPTT ID has one pseudonym in SIP and in floor control;
  - MSRP: the To-Path and From-Path URIs, in the same kind as the a=path URIs.
tshark 4.4 decodes no MCVideo, MCData or other non-MCPT APP fields; their identities are
covered by the unit tests and the canary checks of test_media_app.py.
The relation original -> pseudonym must be a function in both directions (a bijection).

With --zeroed-ok, a frame whose output carries fewer identity fields than its input, or an SSRC
of 0, is counted as zeroed by the anonymiser (a malformed or unannounced packet, FR-002) and
skipped; without it, such a frame fails the check.

Usage: media_consistency.py INPUT OUTPUT [--zeroed-ok]
"""
import re
import subprocess
import sys

inp, out = sys.argv[1], sys.argv[2]
zeroed_ok = "--zeroed-ok" in sys.argv[3:]
SDP_SSRC = re.compile(r"(?:^ssrc:|mc_ssrc=|mc_floor_ssrc=|mc_transmission_ssrc=)(\d+)")
SDP_CNAME = re.compile(r"^ssrc:\d+ cname:(\S+)")


def fields(path, *names):
    r = subprocess.run(["tshark", "-r", path, "-T", "fields", "-E", "occurrence=a", "-E", "aggregator=|"]
                       + [x for n in names for x in ("-e", n)], capture_output=True, text=True, check=True)
    rows = {}
    for line in r.stdout.splitlines():
        cols = line.split("\t")
        rows[cols[0]] = [c.split("|") if c else [] for c in cols[1:]]
    return rows


def as_int(v):
    v = v.strip()
    return int(v, 16) if v.lower().startswith("0x") else int(v)


def collect(path):
    """frame -> list of (kind, value) in field order."""
    f = fields(path, "frame.number", "frame.protocols", "sdp.media_attr", "rtp.ssrc", "rtp.csrc.item", "rtcp.senderssrc",
               "rtcp.ssrc.identifier", "rtcp.app_data.mcptt.rtcp", "rtcp.mcptt.granted_partys_id",
               "rtcp.app_data.mcptt.user_id", "rtcp.mcptt.queued_user_id", "rtcp.mcptt.func_alias",
               "rtcp.sdes.type", "rtcp.sdes.text", "sip.from.addr", "sip.to.addr", "sip.pai.addr", "sip.ppi.addr",
               "msrp.to.path", "msrp.from.path")
    out = {}
    for frame, (protocols, attrs, ssrc, csrc, sender, ident, app_ssrc, granted, user, queued, alias,
                sdes_type, sdes_text, sfrom, sto, pai, ppi, to_path, from_path) in f.items():
        items = []
        if any(":icmp" in p for p in protocols):
            continue  # a quoted packet is ICMP data, zeroed or dropped by feature 001
        for a in attrs:
            for m in SDP_SSRC.finditer(a):
                items.append(("ssrc", int(m.group(1))))
            for m in SDP_CNAME.finditer(a):
                items.append(("cname", m.group(1)))
            if a.startswith("path:"):
                items += [("path", u) for u in a[5:].split()]
        for group in (ssrc, csrc, sender, ident, app_ssrc):
            items += [("ssrc", as_int(x)) for x in group if x]
        # SDES: item types (0 ends a chunk) align with the item texts; only CNAME is kept.
        texts = iter(sdes_text)
        for t in (x for x in sdes_type if x != "0"):
            v = next(texts, None)
            if t == "1" and v is not None:
                items.append(("cname", v))
        for group in (granted, user, queued, alias, sfrom, sto, pai, ppi):
            items += [("uri", x) for x in group if x]
        for group in (to_path, from_path):
            items += [("path", u) for x in group for u in x.split() if u]
        out[frame] = items
    return out


a, b = collect(inp), collect(out)
failures = []
forward, backward = {}, {}
pairs = zeroed = 0
for frame in sorted(a, key=int):
    x, y = a[frame], b.get(frame, [])
    if zeroed_ok and (len(y) < len(x) or ("ssrc", 0) in y):
        zeroed += 1
        continue
    if len(x) != len(y):
        failures.append(f"frame {frame}: {len(x)} identity fields in the input, {len(y)} in the output")
        continue
    for (k1, v1), (k2, v2) in zip(x, y):
        if k1 != k2:
            failures.append(f"frame {frame}: field kinds differ")
            continue
        pairs += 1
        key1, key2 = (k1, v1), (k2, v2)
        if forward.setdefault(key1, key2) != key2:
            failures.append(f"frame {frame}: one original {k1} has two pseudonyms")
        if backward.setdefault(key2, key1) != key1:
            failures.append(f"frame {frame}: one {k2} pseudonym stands for two originals")
        if v1 == v2 and k1 == "ssrc":
            failures.append(f"frame {frame}: an SSRC passed through unchanged")
print(f"{pairs} identity fields paired, {len(forward)} originals" + (f", {zeroed} zeroed frames skipped" if zeroed_ok else ""))
for f in failures[:20]:
    print("FAIL " + f)
sys.exit(1 if failures or pairs == 0 else 0)

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Feature 006 SC-004: `mcxanon reveal` on a 100 MB text against a project of 100,000
mapping entries finishes within 30 s with at most 512 MiB peak RSS, and reveals every
pseudonym of the text.

The project mapping is written directly in the project-store format
(format 4): 40,000 IPv4 addresses, 30,000 SIP user parts, 20,000 Call-IDs, 10,000 SSRCs.

Skipped (exit 77) unless MCXANON_RUN_PERF=1. MCXANON_PERF_DIR selects the scratch directory.
Usage: test_perf_reveal.py MCXANON
"""
import json
import os
import random
import subprocess
import sys
import tempfile
import time
from pathlib import Path

BUDGET_S = 30
BUDGET_MIB = 512
TEXT_BYTES = 100 * 2**20

if os.environ.get("MCXANON_RUN_PERF") != "1":
    print("perf test skipped (set MCXANON_RUN_PERF=1)")
    sys.exit(77)
exe = sys.argv[1]
failures = []


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def hx(b):
    return b.hex()


rng = random.Random(6)
entries, pairs = [], []
for i in range(40000):
    o = bytes([10, i >> 16 & 255, i >> 8 & 255, i & 255])
    p = bytes([240 | (i >> 24 & 15), i >> 16 & 255, i >> 8 & 255, i & 255])
    entries.append(("ipv4", hx(o), hx(p)))
    pairs.append(("%d.%d.%d.%d" % tuple(p), "%d.%d.%d.%d" % tuple(o)))
for i in range(30000):
    o, p = f"user{i:05d}", f"u-{rng.getrandbits(32):08x}"
    entries.append(("sip-user", hx(o.encode()), hx(p.encode())))
    pairs.append((p, o))
for i in range(20000):
    o, p = f"cid-{i:05d}-xyz", f"c-{rng.getrandbits(64):016x}"
    entries.append(("call-id", hx(o.encode()), hx(p.encode())))
    pairs.append((p, o))
for i in range(10000):
    o, p = 100000000 + i, 3000000000 + i * 7
    entries.append(("ssrc", f"{o:08x}", f"{p:08x}"))
    pairs.append((f"0x{p:08x}", f"0x{o:08x}"))
# Distinct pseudonyms.
seen = set()
pairs = [x for x in pairs if not (x[0] in seen or seen.add(x[0]))]
entries.sort(key=lambda e: (e[0], e[1]))

with tempfile.TemporaryDirectory(dir=os.environ.get("MCXANON_PERF_DIR")) as tmp:
    tmp = Path(tmp)
    dd = tmp / "d"
    subprocess.run([exe, "--data-dir", str(dd), "project", "init", "big"], check=True, capture_output=True)
    doc = {"entries": [{"category": c, "counter": 0, "original": o, "pseudonym": p, "runs_seen": 1}
                       for c, o, p in entries], "format": 4}
    mp = dd / "projects" / "big" / "mapping.map.json"
    fd = os.open(mp, os.O_WRONLY | os.O_TRUNC)
    os.write(fd, json.dumps(doc, indent=2, sort_keys=True).encode())
    os.close(fd)
    # A text with a pseudonym about every 200 bytes.
    text_path, chunks, size, count = tmp / "big.txt", [], 0, 0
    with open(text_path, "w") as f:
        while size < TEXT_BYTES:
            p, _o = pairs[count % len(pairs)]
            line = f"finding {count}: the value {p} was seen in frame {count * 7} (see the ladder above)\n"
            line += "context " * 16 + "\n"
            f.write(line)
            size += len(line)
            count += 1
    t0 = time.monotonic()
    with open(tmp / "stderr", "wb") as err:
        p = subprocess.Popen([exe, "--data-dir", str(dd), "reveal", "--project", "big", str(text_path), "-o",
                              str(tmp / "out.txt")], stdout=subprocess.DEVNULL, stderr=err)
        _, status, usage = os.wait4(p.pid, 0)
    elapsed = time.monotonic() - t0
    rc = os.waitstatus_to_exitcode(status)
    rss_mib = usage.ru_maxrss / 1024
    print(f"reveal: {size / 2**20:.0f} MiB, {len(entries)} mapping entries, {count} pseudonyms, exit {rc}, "
          f"{elapsed:.1f} s, peak RSS {rss_mib:.0f} MiB")
    print((tmp / "stderr").read_text(errors="replace")[:400])
    check(rc == 0, "reveal exits 0")
    check(elapsed <= BUDGET_S, f"within {BUDGET_S} s ({elapsed:.1f} s)")
    check(rss_mib <= BUDGET_MIB, f"peak RSS within {BUDGET_MIB} MiB ({rss_mib:.0f} MiB)")
    err = (tmp / "stderr").read_text()
    check(f"revealed {count} values" in err, "every pseudonym of the text is revealed")

sys.exit(1 if failures else 0)

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Feature 006 US3: ambiguous and unknown candidates in the summary and the report
(FR-015, FR-015a, FR-016, FR-017, FR-017a): at most 20 candidate lines on stderr with an
"... and N more" line, every candidate in the report, counts per category, --replace-ambiguous,
--annotate.

Usage: test_reveal_ambiguity.py MCXANON FIXTURE_DIR
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

exe, fixtures = sys.argv[1], Path(sys.argv[2])
failures = []


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def run(dd, *args, stdin=None):
    env = dict(os.environ)
    env.pop("MCXANON_PASSPHRASE", None)
    return subprocess.run([exe, "--data-dir", str(dd), *map(str, args)], capture_output=True, input=stdin, env=env)


with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    dd = tmp / "d"
    run(dd, "project", "init", "p")
    check(run(dd, "anonymize", "--project", "p", fixtures / "basic_eth.pcap", "-o", tmp / "o.pcap").returncode == 0,
          "anonymize a fixture")
    rows = [l.split("\t") for l in run(dd, "project", "show-map", "p").stdout.decode().splitlines()[1:]]
    ipv4 = [(o, ps) for c, o, ps, *_ in rows if c == "ipv4"]
    # 25 unknown pseudonym-shaped values and one known address.
    unknown = [f"u-{i:08x}" for i in range(25)]
    text = "\n".join(f"line {i} {u}" for i, u in enumerate(unknown)) + f"\nknown {ipv4[0][1]}\n"
    rep = tmp / "r.json"
    r = run(dd, "reveal", "--project", "p", "--report", rep, stdin=text.encode())
    err = r.stderr.decode()
    check(r.returncode == 0, "unknown values do not change the exit code")
    check(r.stdout.decode() == text.replace(ipv4[0][1], ipv4[0][0]), "unknown values stay, the known one is revealed")
    lines = [l for l in err.splitlines() if l.startswith("  ") and "unknown" in l]
    check(len(lines) == 20, f"at most 20 candidate lines ({len(lines)})")
    check("  ... and 5 more (see --report)" in err, "the rest is announced")
    check("0 ambiguous, 25 unknown (sip-user 25)" in err, "counts per category")
    doc = json.loads(rep.read_text())
    check(len(doc["candidates"]) == 25 and doc["unknown"] == {"sip-user": 25}, "the report lists every candidate")
    check(doc["candidates"][0]["line"] == 1 and doc["candidates"][0]["column"] == 8, "positions are 1-based")

    # Annotation.
    r = run(dd, "reveal", "--project", "p", "--annotate", "--quiet", stdin=f"x {ipv4[0][1]} y".encode())
    check(r.stdout.decode() == f"x {ipv4[0][0]}⟦{ipv4[0][1]}⟧ y", "--annotate marks the replacement")
    check(r.stderr.decode().count("\n") == 1, "--quiet keeps only the banner")

sys.exit(1 if failures else 0)

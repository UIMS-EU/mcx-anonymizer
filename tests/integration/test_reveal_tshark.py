#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Feature 006 SC-001 with tshark: the tshark exports of the anonymised demo capture
(`-V` and `-T fields`) are revealed; every canary of a revealed category that tshark shows in
the original capture's export is back in the revealed export, and the revealed field export
equals the original capture's field export for the identity fields.

Usage: test_reveal_tshark.py MCXANON
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
GEN = REPO / "tools" / "fixturegen" / "mcx_demo.py"

if shutil.which("tshark") is None:
    if os.environ.get("MCXANON_REQUIRE_TSHARK") == "1":
        print("FAIL tshark is required (MCXANON_REQUIRE_TSHARK=1) but not found")
        sys.exit(1)
    print("skip: tshark not found")
    sys.exit(77)

exe = sys.argv[1]
failures = []
FIELDS = ["ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "eth.src", "eth.dst", "rtp.ssrc", "sip.Call-ID",
          "sip.from.user", "sip.from.host", "sip.to.user", "sip.to.host"]


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def run(*args, **kw):
    return subprocess.run([str(a) for a in args], capture_output=True, **kw)


def tshark(capture, *args):
    return run("tshark", "-r", capture, *args).stdout.decode(errors="replace")


with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    data = ["--data-dir", tmp / "data"]
    check(run(sys.executable, GEN, "--out", tmp).returncode == 0, "demo generator runs")
    check(run(exe, *data, "project", "init", "demo").returncode == 0, "project init")
    check(run(exe, *data, "anonymize", "--project", "demo", tmp / "mcx_demo.pcapng", "-o", tmp / "out.pcapng")
          .returncode == 0, "anonymize")
    orig_v = tshark(tmp / "mcx_demo.pcapng", "-V")
    anon_v = tshark(tmp / "out.pcapng", "-V")
    (tmp / "anon.V.txt").write_text(anon_v)
    r = run(exe, *data, "reveal", "--project", "demo", tmp / "anon.V.txt", "-o", tmp / "rev.V.txt")
    check(r.returncode == 0, "reveal the -V export")
    rev_v = (tmp / "rev.V.txt").read_text(errors="replace")
    show = run(exe, *data, "project", "show-map", "demo").stdout.decode().splitlines()[1:]
    pseudonym_of = {line.split("\t")[1]: line.split("\t")[2] for line in show}
    canaries = json.loads((tmp / "mcx_demo.canaries.json").read_text())["canaries"]
    # Canaries that tshark shows in the original and whose pseudonym it shows in the output (a
    # long line can be cut by tshark, "[…]"), each as a token of its own: a value inside a longer
    # run of letters and digits (a hex dump of a carrier tshark does not decode) is not a match
    # (006 FR-012).
    def token(v, text):
        return re.search(r"(?<![0-9A-Za-z])" + re.escape(v) + r"(?![0-9A-Za-z])", text) is not None

    shown = [c["value"] for c in canaries if len(c["value"]) > 6 and c["value"] in pseudonym_of
             and token(c["value"], orig_v) and token(pseudonym_of[c["value"]], anon_v)]
    missing = [v for v in shown if v not in rev_v]
    check(len(shown) >= 20 and not missing, f"canaries shown by tshark are restored ({len(shown)}); missing {missing[:5]}")

    fields = [x for f in FIELDS for x in ("-e", f)]
    orig_f = tshark(tmp / "mcx_demo.pcapng", "-T", "fields", "-E", "separator=|", *fields)
    anon_f = tshark(tmp / "out.pcapng", "-T", "fields", "-E", "separator=|", *fields)
    r = run(exe, *data, "reveal", "--project", "demo", "--quiet", input=anon_f.encode())
    rev_f = r.stdout.decode(errors="replace")
    check(r.returncode == 0, "reveal the field export")
    a, b = orig_f.splitlines(), rev_f.splitlines()
    check(len(a) == len(b), "same number of lines")
    diff = [(i, x, y) for i, (x, y) in enumerate(zip(a, b)) if x != y]
    # Short values (6 characters or fewer) stay ambiguous by design; compare the rest.
    real = []
    for i, x, y in diff:
        for fx, fy in zip(x.split("|"), y.split("|")):
            for vx, vy in zip(fx.split(","), fy.split(",")):
                if vx != vy and len(vy) > 6:
                    real.append((i, vx, vy))
    check(not real, f"the revealed field export equals the original's ({real[:3]})")

sys.exit(1 if failures else 0)

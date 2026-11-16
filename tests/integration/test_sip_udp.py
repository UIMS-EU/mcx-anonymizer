#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""User Story 1 over UDP (SC-001, SC-002, SC-004): every sip_udp_* fixture is anonymised in both
payload modes; no canary survives; the independent scan of the output is clean; with tshark,
the SIP ladder is unchanged, and tools/tshark-expert-diff.py finds no new expert errors and, in
zero mode, every packet of an RTP flow that the SDP announces still decoded on that flow
(frame.protocols has "rtp", on the pseudonymised addresses and ports).

Usage: test_sip_udp.py MCXANON FIXTURE_DIR
"""
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CANARY = REPO / "tests" / "integration" / "canary_absent.py"
LADDER = REPO / "tests" / "integration" / "sip_ladder.py"
DIFF = REPO / "tools" / "tshark-expert-diff.py"
exe, fixtures = sys.argv[1], Path(sys.argv[2])
failures = []


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def run(*args):
    return subprocess.run([str(a) for a in args], capture_output=True, text=True)


inputs = sorted(fixtures.glob("sip_udp_*.pcapng"))
check(len(inputs) >= 4, f"SIP UDP fixtures present ({len(inputs)})")
tshark = shutil.which("tshark") is not None
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    data = ["--data-dir", tmp / "data"]
    check(run(exe, *data, "project", "init", "u").returncode == 0, "project init")
    for inp in inputs:
        for mode in ("zero", "drop"):
            out = tmp / f"{mode}-{inp.name}"
            r = run(exe, *data, "anonymize", "--project", "u", "--payload", mode, inp, "-o", out)
            check(r.returncode == 0, f"{inp.name} ({mode}) publishes ({r.stderr.strip()[-200:]})")
            if r.returncode != 0:
                continue
            check("sip: " in r.stderr, f"{inp.name} ({mode}) prints the SIP summary line")
            c = run(sys.executable, CANARY, fixtures / "canaries.json", out, "--source", inp.name)
            check(c.returncode == 0, f"{inp.name} ({mode}) no canary survives ({c.stdout.strip()[:300]})")
            s = run(exe, *data, "scan", "--project", "u", out)
            check(s.returncode == 0, f"{inp.name} ({mode}) the independent scan is clean")
            report = json.loads(Path(str(out) + ".report.json").read_text())
            check(report["format"] == 6 and report["sip"]["messages"]["malformed"] == 0,
                  f"{inp.name} ({mode}) report format 5, no malformed message")
            if not tshark:
                continue
            ld = run(sys.executable, LADDER, inp, out)
            check(ld.returncode == 0, f"{inp.name} ({mode}) SIP ladder unchanged ({ld.stdout.strip()[-300:]})")
            d = run(sys.executable, DIFF, inp, out, "--payload", mode)
            check(d.returncode == 0,
                  f"{inp.name} ({mode}) no new expert errors, SDP-announced RTP set up ({d.stdout.strip()[-300:]})")
            if mode == "zero":
                kept = re.search(r"RTP kept in (\d+) frames", d.stdout)
                check(kept is not None and int(kept.group(1)) > 0,
                      f"{inp.name} the input has SDP-announced RTP flows to check ({d.stdout.strip()[-100:]})")
    if not tshark:
        print("tshark not installed: ladder, expert and SDP-to-RTP checks skipped")
sys.exit(1 if failures else 0)

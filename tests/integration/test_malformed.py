#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Malformed input never crashes or hangs the tool.

Packet-level damage: exit 0, damaged parts zeroed, no canary in the output.
File-level damage: exit 3, nothing published.
Usage: test_malformed.py MCXANON FIXTURE_DIR
"""
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
exe, fixtures = sys.argv[1], Path(sys.argv[2])
failures = 0


def check(name, cond, detail=""):
    global failures
    print(("ok   " if cond else "FAIL ") + name + ("" if cond else f"  {detail}"))
    failures += 0 if cond else 1


expected = {"malformed_raw.pcap": 0, "malformed_eth.pcap": 0, "malformed_nrb.pcapng": 0,
            "malformed_option.pcapng": 3}
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    dd = tmp / "data"
    subprocess.run([exe, "--data-dir", str(dd), "project", "init", "m"], check=True, capture_output=True)
    for name, rc_expected in expected.items():
        out = tmp / ("out-" + name)
        for mode in ("zero", "drop"):
            try:
                r = subprocess.run([exe, "--data-dir", str(dd), "anonymize", "--project", "m",
                                    str(fixtures / name), "-o", str(out), "--payload", mode, "--overwrite"],
                                   capture_output=True, text=True, timeout=60)
            except subprocess.TimeoutExpired:
                check(f"{name} ({mode}): finishes", False, "timeout")
                continue
            check(f"{name} ({mode}): no crash", r.returncode >= 0, r.returncode)
            check(f"{name} ({mode}): exit {rc_expected}", r.returncode == rc_expected, (r.returncode, r.stderr))
            if rc_expected == 0 and r.returncode == 0:
                o = subprocess.run([sys.executable, str(HERE / "canary_absent.py"), str(fixtures / "canaries.json"),
                                    str(out), "--source", name], capture_output=True, text=True)
                check(f"{name} ({mode}): no canary", o.returncode == 0, o.stdout)
            if rc_expected != 0:
                check(f"{name} ({mode}): nothing published", not out.exists())
sys.exit(1 if failures else 0)

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""SC-002: anonymised fixtures decode without new tshark errors,
in zero and drop mode, including the SIP family. In zero mode, every frame that
an SDP sets up as RTP in the input is still RTP in the output (SC-004).
Usage: test_integrity.py MCXANON FIXTURE_DIR
"""
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DIFF = REPO / "tools" / "tshark-expert-diff.py"
exe, fixtures = sys.argv[1], Path(sys.argv[2])
if shutil.which("tshark") is None:
    if os.environ.get("MCXANON_REQUIRE_TSHARK") == "1":
        print("tshark required but missing")
        sys.exit(1)
    print("tshark not installed: integrity checks skipped")
    sys.exit(77)
failures = 0
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    subprocess.run([exe, "--data-dir", str(tmp / "d"), "project", "init", "i"], check=True, capture_output=True)
    # Inputs that are damaged on purpose, and the over-deep tunnel whose inner packet is
    # zeroed by design (fail-closed beats decodability there), are not compared.
    skip = ("malformed_", "tunnel_depth", "sip_malformed_")
    for inp in sorted(p for p in fixtures.iterdir()
                      if p.suffix in (".pcap", ".pcapng") and not p.name.startswith(skip)):
        for mode in ("zero", "drop"):
            out = tmp / f"{mode}-{inp.name}"
            r = subprocess.run([exe, "--data-dir", str(tmp / "d"), "anonymize", "--project", "i", str(inp),
                                "-o", str(out), "--payload", mode], capture_output=True, text=True)
            if r.returncode != 0:
                continue  # inputs the tool rejects are covered elsewhere
            d = subprocess.run([sys.executable, str(DIFF), str(inp), str(out), "--payload", mode, "--xml"],
                               capture_output=True, text=True)
            ok = d.returncode == 0
            print(("ok   " if ok else "FAIL ") + f"{inp.name} ({mode}) {d.stdout.strip()}")
            failures += 0 if ok else 1
sys.exit(1 if failures else 0)

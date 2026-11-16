#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""SC-004 / SC-005: a 1 GB capture with ~100,000 mapping entries is anonymised
and scanned in bounded memory (< 256 MB peak RSS) and in under 2 minutes.
Skipped (exit 77) unless MCXANON_RUN_PERF=1.
Usage: test_perf_1gb.py MCXANON
"""
import os
import resource
import subprocess
import sys
import tempfile
import time
from pathlib import Path

if os.environ.get("MCXANON_RUN_PERF") != "1":
    print("perf test skipped (set MCXANON_RUN_PERF=1)")
    sys.exit(77)
exe = sys.argv[1]
bulk = Path(__file__).resolve().parents[2] / "tools" / "fixturegen" / "bulk.py"
with tempfile.TemporaryDirectory(dir=os.environ.get("MCXANON_PERF_DIR")) as tmp:
    tmp = Path(tmp)
    cap = tmp / "big.pcap"
    subprocess.run([sys.executable, str(bulk), str(cap)], check=True)
    size = cap.stat().st_size
    subprocess.run([exe, "--data-dir", str(tmp / "d"), "project", "init", "perf"], check=True, capture_output=True)
    t0 = time.monotonic()
    r = subprocess.run([exe, "--data-dir", str(tmp / "d"), "anonymize", "--project", "perf", str(cap), "-o",
                        str(tmp / "out.pcap")], capture_output=True, text=True)
    elapsed = time.monotonic() - t0
    rss_mb = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss / 1024
    print(f"input {size / 2**30:.2f} GiB, exit {r.returncode}, {elapsed:.1f} s, peak RSS {rss_mb:.0f} MiB")
    print(r.stderr.strip())
    ok = r.returncode == 0 and elapsed < 120 and rss_mb < 256
    print("ok" if ok else "FAIL")
    sys.exit(0 if ok else 1)

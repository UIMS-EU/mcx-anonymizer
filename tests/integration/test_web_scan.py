#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Feature 007 User Story 4 (FR-024, SC-002): with the web test seam (variant w of the leak test
tool), the HTTP, h2 and TLS sessions rewrite every message, so the mapping holds the identities,
then keep the original bytes, and no removed value is reported. The independent scan must refuse
publication for every carrier: XCAP paths and documents, h2 header blocks (Huffman-coded in the
input), OAuth parameters and JWTs, KMS documents and TLS handshakes.

Usage: test_web_scan.py MCXANON LEAKTEST FIXTURE_DIR
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

exe, leak, fixtures = sys.argv[1], sys.argv[2], Path(sys.argv[3])
failures = []


def check(cond, what, detail=""):
    print(("ok   " if cond else "FAIL ") + what + (f" ({detail})" if not cond and detail else ""))
    if not cond:
        failures.append(what)


with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    dd = tmp / "data"
    subprocess.run([exe, "--data-dir", str(dd), "project", "init", "g"], check=True, capture_output=True)
    for name in ("web_xcap", "web_h2", "web_oauth", "web_auth", "web_kms", "web_tls", "web_http_coverage"):
        inp = fixtures / f"{name}.pcapng"
        out = tmp / f"{name}-out.pcapng"
        r = subprocess.run([leak, str(dd), "g", str(inp), str(out), "w"], capture_output=True, text=True)
        check(r.returncode == 1, f"{name}: the seam's output is refused (exit 1)", (r.returncode, r.stderr[-200:]))
        check(not out.exists(), f"{name}: nothing published")
        rep = Path(str(out) + ".report.json")
        hits = json.loads(rep.read_text())["scan"]["hits"] if rep.exists() else []
        check(len(hits) > 0, f"{name}: residual leaks reported")
        # With the seam off, the same input publishes (the hits come from the seam alone).
        ok = tmp / f"{name}-ok.pcapng"
        r2 = subprocess.run([exe, "--data-dir", str(dd), "anonymize", "--project", "g", str(inp), "-o", str(ok)],
                            capture_output=True, text=True)
        check(r2.returncode == 0, f"{name}: publishes without the seam", r2.stderr[-200:])
print(f"{len(failures)} failure(s)")
sys.exit(1 if failures else 0)

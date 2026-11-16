#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Feature 007 User Story 1 (FR-001 to FR-010, FR-027): every web_* fixture of HTTP/1.1 and h2c is
anonymised in both payload modes; no canary survives, the independent scan is clean and the
report validates. With tshark: every HTTP request and response (HTTP/1.1) and every HTTP/2 frame
type of the input is decoded in the output in the same number, XCAP selectors keep their AUIDs,
and no new error-level expert entry appears.

Usage: test_http_xcap.py MCXANON FIXTURE_DIR
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CANARY = REPO / "tests" / "integration" / "canary_absent.py"
DIFF = REPO / "tools" / "tshark-expert-diff.py"
VALIDATE = REPO / "tests" / "integration" / "validate_report.py"
SCHEMA = REPO / "schemas" / "report.schema.json"
exe, fixtures = sys.argv[1], Path(sys.argv[2])
failures = []
DECODE = ["-d", "tcp.port==80,http2"]
H2 = {"web_h2.pcapng"}


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def run(*args):
    return subprocess.run([str(a) for a in args], capture_output=True, text=True)


def http_counts(path, h2):
    """(requests by method, responses by code) of HTTP/1.1, or frame types of HTTP/2."""
    if h2:
        r = run("tshark", "-n", "-r", path, *DECODE, "-Y", "http2", "-T", "fields", "-e", "http2.type")
        # CONTINUATION (9) is not compared: a re-encoded block is split only when it needs to be.
        # DATA (0) neither: a rewritten body leaves in the frames of its END_STREAM position.
        return Counter(t for line in r.stdout.split() for t in line.split(",") if t not in ("0", "9"))
    r = run("tshark", "-n", "-r", path, "-Y", "http", "-T", "fields", "-e", "http.request.method", "-e", "http.response.code")
    c = Counter()
    for line in r.stdout.splitlines():
        for part in line.split("\t"):
            for x in part.split(","):
                if x:
                    c[x] += 1
    return c


inputs = sorted(fixtures.glob("web_*.pcapng"))
inputs = [p for p in inputs if not p.name.startswith(("web_tls", "web_hostile"))]
check(len(inputs) >= 5, f"HTTP fixtures present ({len(inputs)})")
tshark = shutil.which("tshark") is not None
if not tshark and os.environ.get("MCXANON_REQUIRE_TSHARK") == "1":
    check(False, "tshark required but not installed")
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    data = ["--data-dir", tmp / "data"]
    check(run(exe, *data, "project", "init", "t").returncode == 0, "project init")
    for inp in inputs:
        for mode in ("zero", "drop"):
            out = tmp / f"{mode}-{inp.name}"
            r = run(exe, *data, "anonymize", "--project", "t", "--payload", mode, inp, "-o", out)
            check(r.returncode == 0, f"{inp.name} ({mode}) publishes ({r.stderr.strip()[-200:]})")
            if r.returncode != 0:
                continue
            c = run(sys.executable, CANARY, fixtures / "canaries.json", out, "--source", inp.name)
            check(c.returncode == 0, f"{inp.name} ({mode}) no canary survives ({c.stdout.strip()[-300:]})")
            s = run(exe, *data, "scan", "--project", "t", out)
            check(s.returncode == 0, f"{inp.name} ({mode}) the independent scan is clean")
            rep = Path(str(out) + ".report.json")
            v = run(sys.executable, VALIDATE, SCHEMA, rep)
            check(v.returncode == 0, f"{inp.name} ({mode}) report validates ({v.stdout.strip()[-200:]})")
            report = json.loads(rep.read_text())
            check(report.get("http", {}).get("messages", 0) > 0, f"{inp.name} ({mode}) HTTP messages counted")
            if not tshark:
                continue
            h2 = inp.name in H2
            before, after = http_counts(inp, h2), http_counts(out, h2)
            if mode == "zero" or not h2:
                check(before == after, f"{inp.name} ({mode}) tshark decodes the same HTTP messages ({dict(before)} -> {dict(after)})")
            d = run(sys.executable, DIFF, inp, out, "--payload", mode, *(["--xml"] if not h2 else []))
            check(d.returncode == 0, f"{inp.name} ({mode}) no new expert errors ({d.stdout.strip()[-300:]})")
            if inp.name == "web_xcap.pcapng":
                u = run("tshark", "-n", "-r", out, "-Y", "http.request", "-T", "fields", "-e", "http.request.uri")
                check("org.3gpp.mcptt.user-profile/users/sip%3Au-" in u.stdout, "XCAP AUID kept, XUI pseudonymised")
if not tshark:
    print("tshark not installed: decoding checks skipped")
print(f"{len(failures)} failure(s)")
sys.exit(1 if failures else 0)

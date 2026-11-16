#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Feature 007 SC-006: the 1 GB capture of the 002 perf test (SIP over UDP and
TCP at the 001/SC-004 mapping scale) with an XCAP exchange over HTTP/1.1 and a TLS 1.2 handshake
with a certificate per INVITE dialog (bulk.py --sip --web) is anonymised within the 002 budget:
3 minutes and 256 MiB peak RSS, on a fresh project and again on the same project. Every HTTP
message and every ClientHello must be parsed, so the time covers the HTTP and TLS rewrite.

The anonymiser runs under a 4 GiB address-space limit (RLIMIT_AS), so a run that grows past it
fails here instead of exhausting the machine's memory. Run one perf test at a time.

Skipped (exit 77) unless MCXANON_RUN_PERF=1. MCXANON_PERF_DIR selects the scratch directory.
Usage: test_perf_web.py MCXANON
"""
import json
import os
import resource
import subprocess
import sys
import tempfile
import time
from pathlib import Path

BUDGET_S = 180
BUDGET_MIB = 256
LIMIT = 4 << 30

if os.environ.get("MCXANON_RUN_PERF") != "1":
    print("perf test skipped (set MCXANON_RUN_PERF=1)")
    sys.exit(77)
exe = sys.argv[1]
bulk = Path(__file__).resolve().parents[2] / "tools" / "fixturegen" / "bulk.py"
failures = []


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def _limit():
    resource.setrlimit(resource.RLIMIT_AS, (LIMIT, LIMIT))


with tempfile.TemporaryDirectory(dir=os.environ.get("MCXANON_PERF_DIR")) as tmp:
    tmp = Path(tmp)
    cap = tmp / "web-big.pcap"
    g = subprocess.run([sys.executable, str(bulk), str(cap), "--sip", "--web"], check=True, capture_output=True,
                       text=True, preexec_fn=_limit)
    stats = json.loads(g.stdout)
    check(stats["sip_share"] >= 0.25 and stats["web_share"] >= 0.05,
          f"SIP share {stats['sip_share']:.3f}, HTTP and TLS share {stats['web_share']:.3f}")
    http_expected = stats["web_messages"] * 2 // 5   # request and response of each XCAP exchange
    hello_expected = stats["web_messages"] // 5
    subprocess.run([exe, "--data-dir", str(tmp / "d"), "project", "init", "perf"], check=True, capture_output=True)
    for run in ("fresh project", "second run"):
        out = tmp / "out.pcap"
        t0 = time.monotonic()
        with open(tmp / "stderr", "wb") as err:
            p = subprocess.Popen([exe, "--data-dir", str(tmp / "d"), "anonymize", "--project", "perf", str(cap),
                                  "-o", str(out), "--overwrite"], stdout=subprocess.DEVNULL, stderr=err,
                                 preexec_fn=_limit)
            _, status, usage = os.wait4(p.pid, 0)
        elapsed = time.monotonic() - t0
        rc = os.waitstatus_to_exitcode(status)
        rss_mib = usage.ru_maxrss / 1024
        print(f"{run}: input {stats['bytes'] / 2**30:.2f} GiB, {stats['sip_messages']} SIP messages, "
              f"{http_expected} HTTP messages, {hello_expected} TLS handshakes, exit {rc}, {elapsed:.1f} s, "
              f"peak RSS {rss_mib:.0f} MiB")
        print((tmp / "stderr").read_text(errors="replace").strip()[-600:])
        check(rc == 0, f"{run}: anonymize publishes")
        if rc == 0:
            report = json.loads(Path(str(out) + ".report.json").read_text())
            h, t = report.get("http", {}), report.get("tls", {})
            check(h.get("messages", 0) >= http_expected and not h.get("malformed"),
                  f"{run}: every HTTP message parsed ({h.get('messages')} of {http_expected}, {h.get('malformed')} malformed)")
            hellos = t.get("handshakes", {}).get("client_hello", 0)
            check(hellos >= hello_expected and t.get("certificates_rewritten", 0) >= hello_expected,
                  f"{run}: every ClientHello and certificate parsed ({hellos}, {t.get('certificates_rewritten')} of {hello_expected})")
        check(elapsed <= BUDGET_S, f"{run}: within {BUDGET_S} s ({elapsed:.1f} s)")
        check(rss_mib <= BUDGET_MIB, f"{run}: peak RSS within {BUDGET_MIB} MiB ({rss_mib:.0f} MiB)")
sys.exit(1 if failures else 0)

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Feature 003 SC-005: the 002 perf capture (1 GB, at least 30% SIP, about half over TCP, the
mapping scale of 001/SC-004) with half of the SIP messages carrying an mcptt-info body (the
full mcptt-info document of the fixtures or a small one) is anonymised within 3 minutes with at most
256 MiB peak RSS, on a fresh project and again on the same project. Every SIP message must be
parsed and every mcptt-info body rewritten (none emptied), so the time covers the XML rewrite.
The scan time is recorded (no threshold).

Skipped (exit 77) unless MCXANON_RUN_PERF=1. MCXANON_PERF_DIR selects the scratch directory.
Usage: test_perf_xml.py MCXANON
"""
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

BUDGET_S = 180
BUDGET_MIB = 256

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


with tempfile.TemporaryDirectory(dir=os.environ.get("MCXANON_PERF_DIR")) as tmp:
    tmp = Path(tmp)
    cap = tmp / "xml-big.pcap"
    g = subprocess.run([sys.executable, str(bulk), str(cap), "--sip", "--xml"], check=True, capture_output=True, text=True)
    stats = json.loads(g.stdout)
    check(stats["sip_share"] >= 0.30, f"SIP share of the capture bytes {stats['sip_share']:.3f} >= 0.30")
    check(0.4 <= stats["sip_tcp_share_of_sip"] <= 0.6,
          f"TCP share of the SIP bytes {stats['sip_tcp_share_of_sip']:.3f} is about half")
    subprocess.run([exe, "--data-dir", str(tmp / "d"), "project", "init", "perf"], check=True, capture_output=True)
    for run in ("fresh project", "second run"):
        out = tmp / "out.pcap"
        t0 = time.monotonic()
        with open(tmp / "stderr", "wb") as err:
            p = subprocess.Popen([exe, "--data-dir", str(tmp / "d"), "anonymize", "--project", "perf", str(cap),
                                  "-o", str(out), "--overwrite"], stdout=subprocess.DEVNULL, stderr=err)
            _, status, usage = os.wait4(p.pid, 0)
        elapsed = time.monotonic() - t0
        rc = os.waitstatus_to_exitcode(status)
        rss_mib = usage.ru_maxrss / 1024
        print(f"{run}: input {stats['bytes'] / 2**30:.2f} GiB, {stats['sip_messages']} SIP messages, exit {rc}, "
              f"{elapsed:.1f} s, peak RSS {rss_mib:.0f} MiB")
        err_text = (tmp / "stderr").read_text(errors="replace").strip()
        print(err_text[-600:])
        check(rc == 0, f"{run}: anonymize publishes")
        if rc == 0:
            report = json.loads(Path(str(out) + ".report.json").read_text())
            sip = report["sip"]
            parsed = sum(sip["messages"]["requests"].values()) + sum(sip["messages"]["responses"].values())
            check(sip["messages"]["malformed"] == 0 and parsed == stats["sip_messages"],
                  f"{run}: every SIP message parsed ({parsed} of {stats['sip_messages']}, "
                  f"{sip['messages']['malformed']} malformed)")
            xml = report["xml"]["bodies"].get("application/vnd.3gpp.mcptt-info+xml", {})
            # The 002 ladder also has an mcptt-info body with a non-standard root: emptied (root).
            check(xml.get("rewritten", 0) == stats["xml_messages"] and set(xml) <= {"rewritten", "root"},
                  f"{run}: every added mcptt-info body rewritten ({xml}, expected {stats['xml_messages']})")
            check(stats["xml_messages"] * 2 >= stats["sip_messages"] * 0.4,
                  f"{run}: about half of the SIP messages carry an XML body ({stats['xml_messages']} of {stats['sip_messages']})")
            print(f"{run}: scan {report['scan']['tokens']} tokens, {report['scan']['patterns']} patterns, "
                  f"{report['scan']['suppressed_chance_matches']} chance matches suppressed")
        check(elapsed <= BUDGET_S, f"{run}: within {BUDGET_S} s ({elapsed:.1f} s)")
        check(rss_mib <= BUDGET_MIB, f"{run}: peak RSS within {BUDGET_MIB} MiB ({rss_mib:.0f} MiB)")
sys.exit(1 if failures else 0)

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""SC-005 (feature 004): a 1 GB capture whose bytes are at least 50% RTP and RTCP and 10% SIP,
with MCPTT floor control, at the mapping scale of 002/I18, is anonymised within 3 minutes with at
most 256 MiB peak RSS. Every SIP message, RTP packet, RTCP datagram and APP message of the
capture must be processed as such (none malformed or unknown), so the time covers the media
rewrite and not a fail-closed shortcut. The separate scan of the output is timed and reported
without a threshold; a hit fails the run, since the generator uses
a few SSRCs per call and a chance match of an SSRC slot would need investigating.

Skipped (exit 77) unless MCXANON_RUN_PERF=1. MCXANON_PERF_DIR selects the scratch directory.
Usage: test_perf_media.py MCXANON
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


def timed(args, err_path):
    t0 = time.monotonic()
    with open(err_path, "wb") as err:
        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=err)
        out = p.stdout.read()
        _, status, usage = os.wait4(p.pid, 0)
    return os.waitstatus_to_exitcode(status), time.monotonic() - t0, usage.ru_maxrss / 1024, out


with tempfile.TemporaryDirectory(dir=os.environ.get("MCXANON_PERF_DIR")) as tmp:
    tmp = Path(tmp)
    cap = tmp / "media-big.pcap"
    g = subprocess.run([sys.executable, str(bulk), str(cap), "--media"], check=True, capture_output=True, text=True)
    stats = json.loads(g.stdout)
    print(json.dumps(stats))
    check(stats["media_share"] >= 0.50, f"RTP+RTCP share of the capture bytes {stats['media_share']:.3f} >= 0.50")
    check(0.09 <= stats["sip_share"] <= 0.11, f"SIP share of the capture bytes {stats['sip_share']:.3f} is about 0.10")
    subprocess.run([exe, "--data-dir", str(tmp / "d"), "project", "init", "perf"], check=True, capture_output=True)
    out = tmp / "out.pcap"
    rc, elapsed, rss, _ = timed([exe, "--data-dir", str(tmp / "d"), "anonymize", "--project", "perf", str(cap),
                                 "-o", str(out), "--overwrite"], tmp / "stderr")
    print(f"anonymize: input {stats['bytes'] / 2**30:.2f} GiB, exit {rc}, {elapsed:.1f} s, peak RSS {rss:.0f} MiB")
    print((tmp / "stderr").read_text(errors="replace").strip()[-600:])
    check(rc == 0, "anonymize publishes")
    if rc == 0:
        report = json.loads(Path(str(out) + ".report.json").read_text())
        sip, m = report["sip"], report["media"]
        parsed = sum(sip["messages"]["requests"].values()) + sum(sip["messages"]["responses"].values())
        check(sip["messages"]["malformed"] == 0 and parsed == stats["sip_messages"],
              f"every SIP message parsed ({parsed} of {stats['sip_messages']})")
        check(m["rtp"]["packets"] == stats["rtp_packets"] and not m["rtp"]["zeroed"],
              f"every RTP packet rewritten as RTP ({m['rtp']['packets']} of {stats['rtp_packets']}, zeroed {m['rtp']['zeroed']})")
        check(m["rtcp"]["by_packet_type"].get("200", 0) == stats["rtcp_datagrams"] and not m["rtcp"]["srtcp_view"]
              and not m["rtcp"]["zeroed"], f"every RTCP compound decoded ({m['rtcp']['by_packet_type']})")
        check(sum(m["app"]["messages"].values()) == stats["app_messages"] and not m["app"]["unknown"],
              f"every floor control message decoded ({sum(m['app']['messages'].values())} of {stats['app_messages']})")
        check(m["rtp"]["streams"] == 2 * stats["calls_per_block"], f"{m['rtp']['streams']} RTP streams")
        print(f"anonymize: scan {report['scan']['tokens']} tokens, {report['scan']['patterns']} patterns, "
              f"{report['scan']['suppressed_chance_matches']} chance matches suppressed")
    check(elapsed <= BUDGET_S, f"anonymize within {BUDGET_S} s ({elapsed:.1f} s)")
    check(rss <= BUDGET_MIB, f"anonymize peak RSS within {BUDGET_MIB} MiB ({rss:.0f} MiB)")
    if rc == 0:
        rc, elapsed, rss, sout = timed([exe, "--data-dir", str(tmp / "d"), "scan", "--project", "perf", str(out)],
                                       tmp / "scan-stderr")
        print(f"scan (no threshold): exit {rc}, {elapsed:.1f} s, peak RSS {rss:.0f} MiB")
        print(sout.decode(errors="replace").strip()[-600:])
        check(rc == 0, "the scan of the output reports no hit")
sys.exit(1 if failures else 0)

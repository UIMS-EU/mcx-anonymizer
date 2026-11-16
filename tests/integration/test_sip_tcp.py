#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""User Story 4 over TCP (FR-024, FR-026, FR-027): every sip_tcp_* fixture is
anonymised in both payload modes; no canary survives and the independent scan is clean; with
tshark, every complete SIP message of the output is reassembled with no new error-level expert
entries, the SIP ladder is unchanged, and retransmitted segments carry the bytes of their first
transmission. Unframable bytes are zeroed and counted in the report (sip.tcp).

Usage: test_sip_tcp.py MCXANON FIXTURE_DIR
"""
import json
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CANARY = REPO / "tests" / "integration" / "canary_absent.py"
LADDER = REPO / "tests" / "integration" / "sip_ladder.py"
DIFF = REPO / "tools" / "tshark-expert-diff.py"
exe, fixtures = sys.argv[1], Path(sys.argv[2])
failures = []

# Fixtures with bytes that are zeroed on purpose: their output ladder is a subset of the input's,
# with this many complete messages (reorder: the message with a lost segment and the tail of a
# capture that starts mid-message are zeroed; unframable: a message without Content-Length and
# one larger than 1 MiB are zeroed, the two that follow are framed again).
DAMAGED = {"sip_tcp_reorder.pcapng": 8, "sip_tcp_unframable.pcapng": 2}


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def run(*args):
    return subprocess.run([str(a) for a in args], capture_output=True, text=True)


def segments(path):
    """(stream, seq, len) -> payloads of the TCP segments with data."""
    r = run("tshark", "-n", "-r", path, "-o", "tcp.analyze_sequence_numbers:FALSE", "-T", "fields",
            "-e", "tcp.stream", "-e", "tcp.seq_raw", "-e", "tcp.len", "-e", "tcp.payload", "-Y", "tcp.len > 0")
    out = defaultdict(list)
    for line in r.stdout.splitlines():
        f = line.split("\t")
        if len(f) >= 4:
            out[(f[0], f[1], f[2])].append(f[3])
    return out


def payload_lengths(path, port):
    r = run("tshark", "-n", "-r", path, "-T", "fields", "-e", "tcp.len", "-Y", f"tcp.srcport == {port}")
    return [int(x) for x in r.stdout.split() if x]


inputs = sorted(fixtures.glob("sip_tcp_*.pcapng"))
check(len(inputs) >= 7, f"SIP TCP fixtures present ({len(inputs)})")
tshark = shutil.which("tshark") is not None
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
            check(c.returncode == 0, f"{inp.name} ({mode}) no canary survives ({c.stdout.strip()[:300]})")
            s = run(exe, *data, "scan", "--project", "t", out)
            check(s.returncode == 0, f"{inp.name} ({mode}) the independent scan is clean")
            report = json.loads(Path(str(out) + ".report.json").read_text())
            tcp = report["sip"]["tcp"]
            check(tcp["streams_sip"] >= 1, f"{inp.name} ({mode}) SIP streams found ({tcp})")
            if inp.name in DAMAGED:
                check(tcp["bytes_unframable"] > 0, f"{inp.name} ({mode}) unframable bytes counted ({tcp})")
            else:
                check(report["sip"]["messages"]["malformed"] == 0, f"{inp.name} ({mode}) no malformed message")
            if inp.name == "sip_tcp_retrans.pcapng":
                check(tcp["retransmissions_replayed"] > 0, f"{inp.name} ({mode}) retransmissions replayed ({tcp})")
            if not tshark:
                continue
            if inp.name in DAMAGED:
                n_out = len([l for l in run("tshark", "-n", "-r", out, "-Y", "sip", "-T", "fields",
                                            "-e", "frame.number").stdout.splitlines() if l])
                check(n_out == DAMAGED[inp.name],
                      f"{inp.name} ({mode}) tshark decodes every complete message ({n_out})")
            extra = ["--subset"] if inp.name in DAMAGED else []
            ld = run(sys.executable, LADDER, inp, out, *extra)
            check(ld.returncode == 0, f"{inp.name} ({mode}) SIP ladder unchanged ({ld.stdout.strip()[-300:]})")
            if inp.name not in DAMAGED:
                n_in = run(sys.executable, LADDER, inp, inp).stdout.strip().splitlines()[-1]
                check("0 messages" not in n_in, f"{inp.name} the input has a SIP ladder ({n_in})")
            d = run(sys.executable, DIFF, inp, out, "--payload", mode)
            check(d.returncode == 0, f"{inp.name} ({mode}) no new expert errors ({d.stdout.strip()[-300:]})")
            same = [v for v in segments(out).values() if len(v) > 1]
            check(all(len(set(v)) == 1 for v in same),
                  f"{inp.name} ({mode}) retransmitted segments repeat their first transmission ({len(same)})")
            if inp.name == "sip_tcp_retrans.pcapng":
                check(len(same) > 0, f"{inp.name} ({mode}) the output has retransmissions to compare")
            if inp.name == "sip_tcp_mixed.pcapng" and mode == "drop":
                check(all(n == 0 for n in payload_lengths(out, 8443)),
                      f"{inp.name} (drop) a connection without SIP carries no payload")
                core = payload_lengths(out, 5060)
                check(core and all(n == 0 for n in core),
                      f"{inp.name} (drop) the non-SIP direction of a SIP connection carries no payload")
    if not tshark:
        print("tshark not installed: ladder, expert and retransmission checks skipped")
sys.exit(1 if failures else 0)

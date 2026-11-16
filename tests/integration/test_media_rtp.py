#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""User Story 2 (SC-001, SC-002, SC-003): every rtp_* fixture is anonymised in both payload modes;
no canary survives; the independent scan is clean; the report counts RTP. With tshark:
  - every RTP frame of the input is still RTP in the output, set up from SDP (rtp.setup-frame),
    with the same payload type, marker, sequence number and timestamp;
  - no 8-octet window of an input RTP payload survives in the output (SC-002);
  - the flow that no SDP announces stays zeroed (FR-002);
  - SSRCs have one pseudonym across SDP and RTP (media_consistency.py);
  - tools/tshark-expert-diff.py --media finds no new error-level expert entries.

Usage: test_media_rtp.py MCXANON FIXTURE_DIR
"""
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CANARY = REPO / "tests" / "integration" / "canary_absent.py"
CONSISTENCY = REPO / "tests" / "integration" / "media_consistency.py"
DIFF = REPO / "tools" / "tshark-expert-diff.py"
exe, fixtures = sys.argv[1], Path(sys.argv[2])
failures = []


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def run(*args):
    return subprocess.run([str(a) for a in args], capture_output=True, text=True)


def rtp_rows(path):
    r = run("tshark", "-r", path, "-Y", "rtp", "-T", "fields", "-e", "frame.number", "-e", "rtp.p_type",
            "-e", "rtp.marker", "-e", "rtp.seq", "-e", "rtp.timestamp", "-e", "rtp.setup-frame", "-e", "rtp.payload")
    rows = {}
    for line in r.stdout.splitlines():
        c = line.split("\t")
        rows[c[0]] = c[1:]
    return rows


def udp_payloads(path, frames):
    r = run("tshark", "-r", path, "-T", "fields", "-e", "frame.number", "-e", "udp.payload")
    out = {}
    for line in r.stdout.splitlines():
        c = line.split("\t")
        if c[0] in frames and len(c) > 1:
            out[c[0]] = bytes.fromhex(c[1].replace(":", ""))
    return out


inputs = sorted(fixtures.glob("rtp_*.pcapng"))
check(len(inputs) >= 6, f"RTP fixtures present ({len(inputs)})")
tshark = shutil.which("tshark") is not None
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    data = ["--data-dir", tmp / "data"]
    check(run(exe, *data, "project", "init", "m").returncode == 0, "project init")
    for inp in inputs:
        for mode in ("zero", "drop"):
            out = tmp / f"{mode}-{inp.name}"
            r = run(exe, *data, "anonymize", "--project", "m", "--payload", mode, inp, "-o", out)
            check(r.returncode == 0, f"{inp.name} ({mode}) publishes ({r.stderr.strip()[-200:]})")
            if r.returncode != 0:
                continue
            c = run(sys.executable, CANARY, fixtures / "canaries.json", out, "--source", inp.name)
            check(c.returncode == 0, f"{inp.name} ({mode}) no canary survives ({c.stdout.strip()[:300]})")
            s = run(exe, *data, "scan", "--project", "m", out)
            check(s.returncode == 0, f"{inp.name} ({mode}) the independent scan is clean ({s.stdout.strip()[-200:]})")
            report = json.loads(Path(str(out) + ".report.json").read_text())
            media = report.get("media", {})
            if inp.name not in ("rtp_malformed.pcapng",):
                check(media.get("rtp", {}).get("packets", 0) > 0, f"{inp.name} ({mode}) report counts RTP packets")
            if inp.name == "rtp_malformed.pcapng":
                check(media.get("rtp", {}).get("zeroed", {}).get("malformed", 0) == 5,
                      f"{inp.name} ({mode}) five malformed packets zeroed and counted")
            if not tshark:
                continue
            before, after = rtp_rows(inp), rtp_rows(out)
            if inp.name == "rtp_malformed.pcapng":
                check(not after, f"{inp.name} ({mode}) nothing decodes as RTP in the output")
                frames = set(before) | {str(i) for i in range(3, 8)}
                pl = udp_payloads(out, frames)
                check(all(not any(p) for p in pl.values()), f"{inp.name} ({mode}) malformed payloads are zero")
                continue
            expected = dict(before)
            if inp.name == "rtp_unannounced.pcapng":
                # Frame 4 is the unannounced flow: it must not survive as RTP.
                expected.pop("4", None)
                check("4" not in after, f"{inp.name} ({mode}) the unannounced flow is not RTP in the output")
                pl = udp_payloads(out, {"4"})
                check(all(not any(p) for p in pl.values()), f"{inp.name} ({mode}) the unannounced payload is zero")
            same = all(k in after and after[k][:4] == v[:4] for k, v in expected.items())
            check(same, f"{inp.name} ({mode}) every RTP frame keeps PT, marker, sequence number and timestamp")
            check(all(after[k][4] for k in expected if k in after),
                  f"{inp.name} ({mode}) every RTP frame is set up from SDP")
            leaked = 0
            raw = Path(out).read_bytes()
            for k, v in expected.items():
                payload = bytes.fromhex(v[5].replace(":", "")) if len(v) > 5 and v[5] else b""
                for i in range(0, max(0, len(payload) - 7)):
                    w = payload[i:i + 8]
                    if any(w) and w in raw:
                        leaked += 1
                        break
            check(leaked == 0, f"{inp.name} ({mode}) no 8-octet window of an input RTP payload survives")
            mc = run(sys.executable, CONSISTENCY, inp, out)
            check(mc.returncode == 0, f"{inp.name} ({mode}) one pseudonym per SSRC ({mc.stdout.strip()[-300:]})")
            d = run(sys.executable, DIFF, inp, out, "--payload", mode, "--media")
            check(d.returncode == 0, f"{inp.name} ({mode}) no new expert errors ({d.stdout.strip()[-300:]})")
    if not tshark:
        print("tshark not installed: RTP structure, window, consistency and expert checks skipped")
sys.exit(1 if failures else 0)

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""User Story 3 (FR-009 to FR-013, SC-002 to SC-004): every rtcp_* fixture is anonymised in both
payload modes; no canary survives (SDES items, BYE reason, AFB, RPSI bit string, unknown XR); the
independent scan is clean; the report counts the RTCP packet types, feedback, XR blocks and
removed SDES items. With tshark: the RTCP packet types of every frame are unchanged, the SR/RR
statistics and the kept feedback and XR fields are equal, the CNAME pseudonym equals the
a=ssrc cname pseudonym of the SDP, SSRCs are consistent (media_consistency.py) and there are no
new error-level expert entries.

Usage: test_media_rtcp.py MCXANON FIXTURE_DIR
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
KEPT = ["rtcp.pt", "rtcp.sender.packetcount", "rtcp.sender.octetcount", "rtcp.timestamp.rtp",
        "rtcp.ssrc.fraction", "rtcp.ssrc.cum_nr", "rtcp.ssrc.ext_high", "rtcp.ssrc.jitter", "rtcp.ssrc.lsr",
        "rtcp.ssrc.dlsr", "rtcp.rtpfb.nack_pid", "rtcp.rtpfb.nack_blp", "rtcp.psfb.fmt", "rtcp.xr.bt"]


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def run(*args):
    return subprocess.run([str(a) for a in args], capture_output=True, text=True)


def rows(path, names, flt="rtcp"):
    r = run("tshark", "-r", path, "-Y", flt, "-T", "fields", "-E", "occurrence=a", "-E", "aggregator=|",
            *[x for n in ["frame.number"] + names for x in ("-e", n)])
    return {c.split("\t")[0]: c.split("\t")[1:] for c in r.stdout.splitlines()}


inputs = sorted(fixtures.glob("rtcp_*.pcapng"))
check(len(inputs) >= 5, f"RTCP fixtures present ({len(inputs)})")
tshark = shutil.which("tshark") is not None
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    data = ["--data-dir", tmp / "data"]
    check(run(exe, *data, "project", "init", "r").returncode == 0, "project init")
    for inp in inputs:
        for mode in ("zero", "drop"):
            out = tmp / f"{mode}-{inp.name}"
            r = run(exe, *data, "anonymize", "--project", "r", "--payload", mode, inp, "-o", out)
            check(r.returncode == 0, f"{inp.name} ({mode}) publishes ({r.stderr.strip()[-200:]})")
            if r.returncode != 0:
                continue
            c = run(sys.executable, CANARY, fixtures / "canaries.json", out, "--source", inp.name)
            check(c.returncode == 0, f"{inp.name} ({mode}) no canary survives ({c.stdout.strip()[:300]})")
            s = run(exe, *data, "scan", "--project", "r", out)
            check(s.returncode == 0, f"{inp.name} ({mode}) the independent scan is clean ({s.stdout.strip()[-200:]})")
            rtcp = json.loads(Path(str(out) + ".report.json").read_text())["media"]["rtcp"]
            if inp.name == "rtcp_compound.pcapng":
                check(all(rtcp["sdes_removed"].get(k, 0) >= 1 for k in ("NAME", "EMAIL", "PHONE", "LOC", "TOOL", "NOTE", "PRIV")),
                      f"{inp.name} ({mode}) every SDES item but CNAME removed and counted ({rtcp['sdes_removed']})")
                check(rtcp["by_packet_type"].get("203", 0) == 1, f"{inp.name} ({mode}) BYE counted")
            if inp.name == "rtcp_fb_xr.pcapng":
                check(rtcp["feedback"].get("206/15", {}).get("zero", 0) == 1, f"{inp.name} ({mode}) AFB zeroed and counted")
                check(rtcp["xr_blocks"].get("other", {}).get("zero", 0) == 1, f"{inp.name} ({mode}) unknown XR block zeroed")
                check(rtcp["xr_blocks"].get("7", {}).get("keep", 0) == 1, f"{inp.name} ({mode}) VoIP Metrics kept")
            if inp.name == "rtcp_srtcp.pcapng":
                check(rtcp["srtcp_view"].get("secure", 0) == 1, f"{inp.name} ({mode}) SRTCP gets the 8-octet view")
            if not tshark:
                continue
            if inp.name not in ("rtcp_malformed.pcapng", "rtcp_srtcp.pcapng"):
                a, b = rows(inp, KEPT), rows(out, KEPT)
                check(a.keys() == b.keys() and all(a[k] == b[k] for k in a),
                      f"{inp.name} ({mode}) RTCP packet types, statistics and kept feedback/XR fields unchanged")
                mc = run(sys.executable, CONSISTENCY, inp, out)
                check(mc.returncode == 0, f"{inp.name} ({mode}) one pseudonym per SSRC ({mc.stdout.strip()[-300:]})")
            if inp.name == "rtcp_compound.pcapng":
                sdp = rows(out, ["sdp.media_attr"], "sdp")
                cnames = rows(out, ["rtcp.sdes.text"])
                announced = [x.split("cname:")[1] for v in sdp.values() for x in v[0].split("|") if "cname:" in x]
                check(announced and announced[0] in cnames.get("6", [""])[0].split("|"),
                      f"{inp.name} ({mode}) the SDES CNAME equals the a=ssrc cname pseudonym")
            d = run(sys.executable, DIFF, inp, out, "--payload", mode, "--media")
            check(d.returncode == 0, f"{inp.name} ({mode}) no new expert errors ({d.stdout.strip()[-300:]})")
    if not tshark:
        print("tshark not installed: RTCP structure, consistency and expert checks skipped")
sys.exit(1 if failures else 0)

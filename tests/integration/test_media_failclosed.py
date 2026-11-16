#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Fail-closed media plane (FR-001, FR-002, FR-014, FR-028, FR-031, FR-032; quickstart Scenario 6).

  malformed    every malformed media fixture completes with exit 0 in both payload modes, no
               canary survives, and what was zeroed is counted by reason in the report;
  unannounced  a UDP flow that no SDP announces stays zeroed, even when it looks like RTP;
  evicted      with more announced endpoints than the table holds, the least recently used one
               is evicted and its flow falls back to zeroing, while a still-announced flow is
               rewritten as RTP;
  planted      an original SSRC written back into an otherwise clean output makes the scanner
               fail (exit 1, as for a leak).

Usage: test_media_failclosed.py MCXANON FIXTURE_DIR
"""
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CANARY = REPO / "tests" / "integration" / "canary_absent.py"
exe, fixtures = sys.argv[1], Path(sys.argv[2])
failures = []


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def run(*args):
    return subprocess.run([str(a) for a in args], capture_output=True, text=True)


def udp_packets(path):
    """(file offset of the UDP payload, src, sport, dport, payload) of each Ethernet/IPv4 UDP
    frame of a pcapng file."""
    data = Path(path).read_bytes()
    o = "<" if data[8:12] == b"\x4d\x3c\x2b\x1a" else ">"
    off, out = 0, []
    while off + 12 <= len(data):
        bt, bl = struct.unpack_from(o + "II", data, off)
        if bl < 12:
            break
        if bt == 6:
            cap = struct.unpack_from(o + "I", data, off + 20)[0]
            f0 = off + 28
            frame = data[f0:f0 + cap]
            if len(frame) >= 34 and frame[12:14] == b"\x08\x00" and frame[23] == 17:
                i = 14 + (frame[14] & 15) * 4
                sport, dport, ulen = struct.unpack_from(">HHH", frame, i)
                out.append((f0 + i + 8, ".".join(map(str, frame[26:30])), sport, dport, frame[i + 8:i + ulen]))
        off += bl
    return out


def report(out):
    return json.loads(Path(str(out) + ".report.json").read_text())["media"]


MALFORMED = {
    "rtp_malformed.pcapng": lambda m: m["rtp"]["zeroed"].get("malformed", 0) == 5,
    "rtcp_malformed.pcapng": lambda m: m["rtcp"]["zeroed"].get("malformed", 0) == 2,
    "app_mcpt_malformed.pcapng": lambda m: sum(m["app"]["unknown"].values()) >= 4
    and m["rtcp"]["srtcp_view"].get("undecodable", 0) == 1,
    "msrp_malformed.pcapng": lambda m: m["msrp"]["zeroed"] == {"malformed": 1, "method": 1},
}

with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    data = ["--data-dir", tmp / "data"]
    check(run(exe, *data, "project", "init", "f").returncode == 0, "project init")

    def anonymize(inp, mode="zero"):
        out = tmp / f"{mode}-{inp.name}"
        r = run(exe, *data, "anonymize", "--project", "f", "--payload", mode, inp, "-o", out)
        check(r.returncode == 0, f"{inp.name} ({mode}) completes and publishes ({r.stderr.strip()[-200:]})")
        return out if r.returncode == 0 else None

    # malformed: zeroed and counted, nothing survives.
    for name, counted in MALFORMED.items():
        inp = fixtures / name
        check(inp.exists(), f"{name} present")
        for mode in ("zero", "drop"):
            out = anonymize(inp, mode)
            if out is None:
                continue
            c = run(sys.executable, CANARY, fixtures / "canaries.json", out, "--source", name)
            check(c.returncode == 0, f"{name} ({mode}) no canary survives ({c.stdout.strip()[:300]})")
            m = report(out)
            check(counted(m), f"{name} ({mode}) what was zeroed is counted by reason "
                              f"(rtp {m['rtp']['zeroed']}, rtcp {m['rtcp']['zeroed']}, app {m['app']['unknown']}, "
                              f"msrp {m['msrp']['zeroed']})")

    # unannounced: the second flow of rtp_unannounced is not in any SDP.
    inp = fixtures / "rtp_unannounced.pcapng"
    out = anonymize(inp)
    if out:
        m = report(out)
        check(m["rtp"]["packets"] == 1, f"only the announced flow is RTP ({m['rtp']['packets']})")
        flows = [p for p in udp_packets(out) if p[2] not in (5060,)]
        check(len(flows) == 2, f"two media datagrams in the output ({len(flows)})")
        if len(flows) == 2:
            check(flows[0][4][0] == 0x80, "the announced flow keeps its RTP header")
            check(set(flows[1][4]) == {0}, "the unannounced flow is zeroed (FR-002)")

    # evicted: media_evict announces more endpoints than kMaxMediaEndpoints.
    manifest = json.loads((fixtures / "media_manifest.json").read_text())["media_evict.pcapng"]
    inp = fixtures / "media_evict.pcapng"
    out = anonymize(inp)
    if out:
        m = report(out)
        total = sum(m["announcements"]["endpoints"].values())
        check(total > m["limits"]["max_endpoints"], f"more endpoints announced ({total}) than the table holds")
        check(m["limits"]["endpoints_evicted"] > 0, f"endpoints evicted ({m['limits']['endpoints_evicted']})")
        check(m["rtp"]["packets"] == 1, f"only the still-announced flow is RTP ({m['rtp']['packets']})")
        src = {(a, p): pl for _, a, p, _, pl in udp_packets(inp) if p != 5060}
        res = [pl for _, _, p, _, pl in udp_packets(out) if p != 5060]
        check(len(res) == 2 and len(src) == 2, f"two media datagrams ({len(res)})")
        if len(res) == 2:
            check(set(res[0]) == {0}, "the evicted endpoint's flow falls back to zeroing")
            check(res[1][0] == 0x80 and res[1][8:12] != src[tuple(manifest["kept"])][8:12],
                  "the still-announced flow keeps its RTP header with the SSRC mapped")

    # planted: an original SSRC in an otherwise clean output fails the scan.
    inp = fixtures / "rtp_audio.pcapng"
    out = anonymize(inp)
    if out:
        s = run(exe, *data, "scan", "--project", "f", out)
        check(s.returncode == 0, f"the clean output scans clean ({s.stdout.strip()[-200:]})")
        a = [p for p in udp_packets(inp) if p[2] != 5060 and len(p[4]) >= 12 and p[4][0] == 0x80]
        b = [p for p in udp_packets(out) if p[2] != 5060 and len(p[4]) >= 12 and p[4][0] == 0x80]
        check(bool(a) and len(a) == len(b), "RTP packets in input and output")
        if a and len(a) == len(b):
            buf = bytearray(out.read_bytes())
            orig = a[0][4][8:12]
            check(b[0][4][8:12] != orig, "the output SSRC is a pseudonym")
            buf[b[0][0] + 8:b[0][0] + 12] = orig
            planted = tmp / "planted.pcapng"
            planted.write_bytes(bytes(buf))
            s = run(exe, *data, "scan", "--project", "f", planted)
            check(s.returncode == 1, f"the planted SSRC fails the scan with exit 1 ({s.returncode}: {s.stdout.strip()[-200:]})")

sys.exit(1 if failures else 0)

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""User story 3 / FR-024 / FR-040: consistent pseudonyms across captures,
independent of the order, and byte-identical re-runs.
Usage: test_consistency.py MCXANON
"""
import json
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

exe = sys.argv[1]
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools" / "fixturegen"))
import packets as P  # noqa: E402

failures = 0


def check(name, cond, detail=""):
    global failures
    print(("ok   " if cond else "FAIL ") + name + ("" if cond else f"  {detail}"))
    failures += 0 if cond else 1


def pcap(pkts):
    out = struct.pack("<IHHiiII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 101)
    for i, p in enumerate(pkts):
        out += struct.pack("<IIII", 1700000000 + i, 0, len(p), len(p)) + p
    return out


def addrs(path):
    data = path.read_bytes()
    off, res = 24, []
    while off + 16 <= len(data):
        cap = struct.unpack_from("<I", data, off + 8)[0]
        p = data[off + 16:off + 16 + cap]
        res.append((p[12:16], p[16:20]))
        off += 16 + cap
    return res


A = bytes([10, 9, 0, 1]); B = bytes([10, 9, 0, 2]); C = bytes([10, 9, 0, 3]); D = bytes([10, 9, 0, 4])
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    cap_a = tmp / "a.pcap"
    cap_b = tmp / "b.pcap"
    cap_a.write_bytes(pcap([P.udp4(A, B, 1, 2, b""), P.udp4(A, C, 1, 2, b"")]))
    cap_b.write_bytes(pcap([P.udp4(D, A, 1, 2, b""), P.udp4(C, D, 1, 2, b"")]))
    dd = tmp / "d1"
    subprocess.run([exe, "--data-dir", str(dd), "project", "init", "p"], check=True, capture_output=True)
    # A second project with the same secret: copy the directory before first use.
    dd2 = tmp / "d2"
    shutil.copytree(dd, dd2)

    def anon(d, src, dst):
        r = subprocess.run([exe, "--data-dir", str(d), "anonymize", "--project", "p", str(src), "-o", str(dst)],
                           capture_output=True, text=True)
        check(f"anonymize {src.name} -> {dst.name}", r.returncode == 0, r.stderr)

    anon(dd, cap_a, tmp / "a1.pcap")
    anon(dd, cap_b, tmp / "b1.pcap")
    anon(dd2, cap_b, tmp / "b2.pcap")   # other order
    anon(dd2, cap_a, tmp / "a2.pcap")
    a1, b1, a2, b2 = (addrs(tmp / n) for n in ("a1.pcap", "b1.pcap", "a2.pcap", "b2.pcap"))
    check("A has one pseudonym within capture A", a1[0][0] == a1[1][0])
    check("A has the same pseudonym in captures A and B", a1[0][0] == b1[0][1])
    check("C keeps its pseudonym across captures", a1[1][1] == b1[1][0])
    check("pseudonyms do not depend on the processing order", a1 == a2 and b1 == b2, (a1, a2))

    anon(dd, cap_a, tmp / "a3.pcap")
    check("re-run: byte-identical capture", (tmp / "a1.pcap").read_bytes() == (tmp / "a3.pcap").read_bytes())
    r1 = json.loads((tmp / "a1.pcap.report.json").read_text())
    r3 = json.loads((tmp / "a3.pcap.report.json").read_text())
    for r in (r1, r3):
        r["files"]["output"] = None
        r.pop("mapping")
        r["scan"].pop("tokens")    # the mapping grew with capture B in between
        r["scan"].pop("patterns")
    check("re-run: identical report apart from output name, mapping statistics and scan size", r1 == r3)
    reused = json.loads((tmp / "a3.pcap.report.json").read_text())["mapping"]["reused_entries"]
    check("second run reuses entries", reused.get("ipv4", 0) == 3, reused)
    # Determinism across machines: the same project state gives the same bytes.
    dd3 = tmp / "d3"
    shutil.copytree(tmp / "d2", dd3)
    anon(dd2, cap_a, tmp / "a4.pcap")
    anon(dd3, cap_a, tmp / "a5.pcap")
    check("same state, same bytes", (tmp / "a4.pcap").read_bytes() == (tmp / "a5.pcap").read_bytes())
    r4 = (tmp / "a4.pcap.report.json").read_text().replace("a4.pcap", "X")
    r5 = (tmp / "a5.pcap.report.json").read_text().replace("a5.pcap", "X")
    check("same state, same report", r4 == r5)

    m = json.loads((dd / "projects" / "p" / "mapping.map.json").read_text())
    keys = [(e["category"], e["original"]) for e in m["entries"]]
    check("mapping file sorted", keys == sorted(keys))
    runs = {e["original"]: e["runs_seen"] for e in m["entries"]}
    check("runs_seen counts runs", runs[A.hex()] == 3 and runs[D.hex()] == 1, runs)
sys.exit(1 if failures else 0)

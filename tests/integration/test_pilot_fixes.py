#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Feature 008: the patterns of the first pilot on third-party captures, reproduced by the
pilot_* fixtures (tools/fixturegen/pilot.py), are anonymised without a false leak and without a
change of the protocol view.

  - pilot_tcp_cookie: a TCP segment ends inside the branch cookie (cut after 1 to 6 characters):
    the run publishes, no canary survives, the independent scan is clean, the report counts the
    skipped input fragments (FR-001, FR-002).
  - pilot_tcp_gap: a rewritten multipart PUBLISH split over two segments while the peer
    acknowledges: each direction's output segments are contiguous, every acknowledgement is at a
    segment boundary of the output, every message's Content-Length equals its body, the retransmission repeats its first transmission, and (with tshark) there is no
    "previous segment not captured" or "ACKed segment that wasn't captured" (FR-005).

Usage: test_pilot_fixes.py MCXANON FIXTURE_DIR
"""
import json
import shutil
import struct
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sip_messages  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
CANARY = REPO / "tests" / "integration" / "canary_absent.py"
VALIDATE = REPO / "tests" / "integration" / "validate_report.py"
SCHEMA = REPO / "schemas" / "report.schema.json"
exe, fixtures = sys.argv[1], Path(sys.argv[2])
failures = []


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def run(*args):
    return subprocess.run([str(a) for a in args], capture_output=True, text=True)


def anonymise(tmp, data, name):
    """Anonymises one fixture; returns (output path, report) or (None, report) on failure."""
    inp = fixtures / name
    out = tmp / name
    r = run(exe, *data, "anonymize", "--project", "t", inp, "-o", out)
    rep_path = Path(str(out) + ".report.json")
    report = json.loads(rep_path.read_text()) if rep_path.exists() else {}
    check(r.returncode == 0, f"{name} publishes ({r.stderr.strip()[-300:]})")
    if r.returncode != 0:
        return None, report
    v = run(sys.executable, VALIDATE, SCHEMA, rep_path)
    check(v.returncode == 0, f"{name} report is valid ({v.stderr.strip()[-200:]})")
    c = run(sys.executable, CANARY, fixtures / "canaries.json", out, "--source", name)
    check(c.returncode == 0, f"{name} no canary survives ({c.stdout.strip()[:300]})")
    s = run(exe, *data, "scan", "--project", "t", out)
    check(s.returncode == 0, f"{name} the independent scan is clean")
    return out, report


def tcp_segments(path):
    """[(direction, seq, ack, sequence length, payload, flags)] of the TCP segments, in capture order
    (IPv4 only); SYN and FIN count one sequence number."""
    out = []
    for frame in sip_messages._frames(Path(path).read_bytes()):
        if len(frame) < 34 or struct.unpack_from(">H", frame, 12)[0] != 0x0800 or frame[23] != 6:
            continue
        ihl = (frame[14] & 15) * 4
        total = struct.unpack_from(">H", frame, 16)[0]
        tcp = frame[14 + ihl:14 + total]
        sport, dport, seq, ack = struct.unpack_from(">HHII", tcp)
        payload = tcp[(tcp[12] >> 4) * 4:]
        flags = tcp[13]
        out.append(((frame[26:30], sport, frame[30:34], dport), seq, ack, len(payload) + (1 if flags & 3 else 0),
                    bytes(payload), flags))
    return out


def tshark_flags(path):
    r = run("tshark", "-n", "-r", path, "-Y", "tcp.analysis.lost_segment || tcp.analysis.ack_lost_segment",
            "-T", "fields", "-e", "frame.number")
    return [x for x in r.stdout.split() if x]


with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    data = ["--data-dir", tmp / "data"]
    check(run(exe, *data, "project", "init", "t").returncode == 0, "project init")

    # M1: a segment boundary inside the branch cookie.
    out, report = anonymise(tmp, data, "pilot_tcp_cookie.pcapng")
    if out is not None:
        scan = report["scan"]
        check(scan.get("skipped_input_fragments", 0) >= 3,
              f"pilot_tcp_cookie the cut branches are counted as skipped fragments ({scan.get('skipped_input_fragments')})")
        check(not scan["hits"], "pilot_tcp_cookie no hit")

    # M3: sequence and acknowledgement numbers stay consistent after a length change.
    name = "pilot_tcp_gap.pcapng"
    out, report = anonymise(tmp, data, name)
    if out is not None:
        segs = tcp_segments(out)
        ends = defaultdict(set)   # direction -> sequence numbers at output segment boundaries
        nxt, first = {}, {}
        contiguous, retrans_same = True, True
        for d, seq, ack, n, payload, flags in segs:
            if n == 0:
                continue
            if d in nxt and seq < nxt[d]:  # a retransmission: the bytes of the first transmission
                retrans_same = retrans_same and first.get((d, seq)) == payload
                continue
            if d in nxt and seq != nxt[d]:
                contiguous = False
            first[(d, seq)] = payload
            ends[d].update((seq, seq + n))
            nxt[d] = seq + n
        check(contiguous, f"{name} the output segments of each direction are contiguous")
        check(retrans_same, f"{name} the retransmission repeats its first transmission")
        acks_ok = all(ack in ends[(d[2], d[3], d[0], d[1])] for d, seq, ack, n, payload, flags in segs
                      if flags & 0x10 and ends[(d[2], d[3], d[0], d[1])])
        check(acks_ok, f"{name} every acknowledgement is at a segment boundary of the output")
        msgs = sip_messages.messages(str(out))
        n_in = len(sip_messages.messages(str(fixtures / name)))
        check(len(msgs) == n_in, f"{name} the stream reassembles to whole messages ({len(msgs)} of {n_in})")
        lengths = [(int(sip_messages.header(m.headers, "content-length") or 0), len(m.body)) for m in msgs]
        check(all(a == b for a, b in lengths), f"{name} every Content-Length equals its body ({lengths})")
        if shutil.which("tshark"):
            before, after = tshark_flags(fixtures / name), tshark_flags(out)
            check(len(after) <= len(before), f"{name} no new lost-segment or ACKed-unseen expert entry ({after})")

sys.exit(1 if failures else 0)

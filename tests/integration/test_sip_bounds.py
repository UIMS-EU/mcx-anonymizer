#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Bounds of the SIP stream layer (FR-028). Generated captures hit
each bound:

  - a 20 s gap in a SIP stream (the pending timeout);
  - more than 64 MiB pending behind one stalled message (the hold-queue bound), in large and in
    tiny records;
  - 70,000 concurrent TCP directions (eviction);
  - 5,000 pending fragmented datagrams (the fragment-table bound);
  - a 2 MiB SIP message (the message bound).

Every run completes and publishes; peak RSS stays within 256 MiB; the bytes a bound gives up
are zeroed (no marker survives) and counted in the report.

The RSS bound is a property of the release build (SC-005); with --no-rss (sanitizer and debug
builds, whose shadow memory dominates) it is reported but not checked.

Usage: test_sip_bounds.py MCXANON [--no-rss]
"""
import json
import resource
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "fixturegen"))
import packets as P  # noqa: E402
import sip as S  # noqa: E402

exe = sys.argv[1]
failures = []
RSS_LIMIT_KIB = 256 * 1024
MARK = b"BOUNDMARKER"


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def run(*args):
    return subprocess.run([str(a) for a in args], capture_output=True, text=True)


def message(tag, body=b"", cl="auto"):
    hdr = [("Via", f"SIP/2.0/TCP 10.40.0.1;branch=z9hG4bK{tag}"), ("From", f"<sip:{tag}@b.example.net>;tag=1"),
           ("To", "<sip:t@b.example.net>"), ("Call-ID", f"{tag}"), ("CSeq", "1 MESSAGE"),
           ("Content-Type", "text/plain")]
    return S.request("MESSAGE", "sip:t@b.example.net", hdr, body, content_length=cl)


A, B = bytes([10, 40, 0, 1]), bytes([10, 40, 0, 2])


def gap_capture():
    """A message whose second half arrives 20 s after its first (capture time)."""
    cap = S.Capture()
    t = S.TcpConn(A, B, 41000, 5060)
    cap.extend(t.handshake())
    m = message("gap" + MARK.decode(), MARK * 20)
    cap.add(t.send(0, m[:len(m) // 2]))
    cap.add(t.send(1, message("other")))
    cap.add(t.send(0, m[len(m) // 2:]), ts_us=cap.ts + 20_000_000)
    cap.add(t.send(0, message("after")))
    return cap, {"bytes_unframable": 1}


def held_capture():
    """A stalled message, then 70 MiB of other traffic within the pending timeout."""
    cap = S.Capture()
    t = S.TcpConn(A, B, 42000, 5060)
    cap.extend(t.handshake())
    m = message("held" + MARK.decode(), MARK * 20)
    cap.add(t.send(0, m[:len(m) // 2]))
    payload = bytes(1400)
    frame = S.wrap(S.udp_packet(A, B, 40000, 40001, payload))
    for i in range(50_000):
        cap.add(frame, ts_us=cap.ts + 100)
    return cap, {"bytes_unframable": 1}


def held_small_capture():
    """A stalled message, then 600,000 tiny packets: the bound counts records, not just bytes."""
    cap = S.Capture()
    t = S.TcpConn(A, B, 42001, 5060)
    cap.extend(t.handshake())
    m = message("small" + MARK.decode(), MARK * 20)
    cap.add(t.send(0, m[:len(m) // 2]))
    frame = S.wrap(S.udp_packet(A, B, 40000, 40001, b""))
    for i in range(600_000):
        cap.add(frame, ts_us=cap.ts + 10)
    return cap, {"bytes_unframable": 1}


def directions_capture():
    """70,000 TCP directions; the first carries an incomplete message when it is evicted."""
    cap = S.Capture()
    t = S.TcpConn(A, B, 43000, 5060)
    cap.extend(t.handshake())
    m = message("evict" + MARK.decode(), MARK * 20)
    cap.add(t.send(0, m[:len(m) // 2]))
    for i in range(70_000):
        src = bytes([10, 41, (i >> 8) & 0xFF, i & 0xFF])
        port = 1024 + (i >> 16)
        cap.add(S.wrap(P.ipv4(src, B, 6, P.tcp(port, 5060, 1000, 0, S.SYN, b"", b"", P.pseudo4(src, B, 6, 20)))),
                ts_us=cap.ts + 10)
    # The handshake's two directions and 70,000 more: 70,002 - 65,536 evicted.
    return cap, {"directions_evicted": 70_002 - 65_536}


def fragments_capture():
    """5,000 SIP datagrams of which only the first fragment ever arrives."""
    cap = S.Capture()
    body = MARK * 200
    for i in range(5_000):
        pkt = S.udp_packet(A, B, 5060, 5060, message(f"frag{i}", body), ident=i)
        cap.add(S.wrap(S.fragment(pkt, 1480, i)[0]), ts_us=cap.ts + 100)
    return cap, {"fragments": {"bound": 5_000 - 4_096, "missing": 4_096}}


def large_capture():
    """A 2 MiB message, then a message that must be framed again."""
    cap = S.Capture()
    t = S.TcpConn(A, B, 44000, 5060)
    cap.extend(t.handshake())
    m = message("large", MARK * (2 * 1024 * 1024 // len(MARK)))
    for off in range(0, len(m), 16000):
        cap.add(t.send(0, m[off:off + 16000]))
    cap.add(t.send(0, message("next")))
    return cap, {"bytes_unframable": 2 * 1024 * 1024}


CASES = [("gap", gap_capture), ("held", held_capture), ("held-small", held_small_capture),
         ("directions", directions_capture),
         ("fragments", fragments_capture), ("large", large_capture)]

with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    data = ["--data-dir", tmp / "data"]
    check(run(exe, *data, "project", "init", "b").returncode == 0, "project init")
    for name, make in CASES:
        cap, want = make()
        src = tmp / f"bounds_{name}.pcapng"
        src.write_bytes(cap.bytes())
        for mode in ("zero", "drop"):
            out = tmp / f"{mode}-{name}.pcapng"
            r = run(exe, *data, "anonymize", "--project", "b", "--payload", mode, src, "-o", out)
            check(r.returncode == 0, f"{name} ({mode}) completes and publishes ({r.stderr.strip()[-200:]})")
            if r.returncode != 0:
                continue
            check(MARK not in out.read_bytes(), f"{name} ({mode}) the given-up bytes are zeroed")
            sip = json.loads(Path(str(out) + ".report.json").read_text())["sip"]
            for key, n in want.items():
                if key == "fragments":
                    got = sip["fragments"].get("datagrams_zeroed", {})
                    check(all(got.get(k) == v for k, v in n.items()), f"{name} ({mode}) counted {n} ({got})")
                elif key == "directions_evicted":
                    check(sip["tcp"][key] == n, f"{name} ({mode}) {key} = {n} ({sip['tcp'][key]})")
                else:
                    check(sip["tcp"][key] >= n, f"{name} ({mode}) {key} >= {n} ({sip['tcp'][key]})")
        src.unlink()
    peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    if "--no-rss" in sys.argv:
        print(f"skip peak RSS {peak // 1024} MiB not checked (not a release build)")
    else:
        check(peak <= RSS_LIMIT_KIB, f"peak RSS {peak // 1024} MiB <= 256 MiB")
sys.exit(1 if failures else 0)

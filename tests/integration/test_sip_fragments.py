#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""User Story 4, IP fragments (FR-025): every sip_frag_* fixture is anonymised in
both payload modes; no canary survives and the independent scan is clean; complete SIP
datagrams are reassembled, rewritten and cut into fragments again (no larger than the largest
original fragment, offsets in units of 8, as many as the input had when they fit); ambiguous,
incomplete and non-SIP datagrams are zeroed and counted (sip.fragments). With tshark, the output's SIP messages reassemble with no
new error-level expert entries and form the input ladder minus the zeroed datagrams.

Usage: test_sip_fragments.py MCXANON FIXTURE_DIR
"""
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CANARY = REPO / "tests" / "integration" / "canary_absent.py"
LADDER = REPO / "tests" / "integration" / "sip_ladder.py"
DIFF = REPO / "tools" / "tshark-expert-diff.py"
exe, fixtures = sys.argv[1], Path(sys.argv[2])
failures = []


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def run(*args):
    return subprocess.run([str(a) for a in args], capture_output=True, text=True)


def fragments(path):
    """(id, offset, length, more) of every IP fragment of a SIP datagram (port 5060 or later)."""
    r = run("tshark", "-n", "-r", path, "-o", "ip.defragment:FALSE", "-o", "ipv6.defragment:FALSE",
            "-T", "fields", "-E", "occurrence=l", "-e", "ip.id", "-e", "ip.frag_offset", "-e", "ip.len",
            "-e", "ip.flags.mf", "-e", "ipv6.fraghdr.ident", "-e", "ipv6.fraghdr.offset", "-e", "ipv6.plen",
            "-e", "ipv6.fraghdr.more", "-Y", "ip.flags.mf == 1 || ip.frag_offset > 0 || ipv6.fraghdr")
    out = []
    for line in r.stdout.splitlines():
        f = (line.split("\t") + [""] * 8)[:8]
        # Offsets are in units of 8 bytes (RFC 791 §3.1, RFC 8200 §4.5).
        if f[4]:
            out.append((f[4], int(f[5]) * 8, int(f[6]) - 8, f[7] in ("1", "True")))
        elif f[0]:
            out.append((f[0], int(f[1]) * 8, int(f[2]) - 20, f[3] in ("1", "True")))
    return out


inputs = sorted(fixtures.glob("sip_frag_*.pcapng"))
check(len(inputs) >= 3, f"SIP fragment fixtures present ({len(inputs)})")
tshark = shutil.which("tshark") is not None
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    data = ["--data-dir", tmp / "data"]
    check(run(exe, *data, "project", "init", "f").returncode == 0, "project init")
    for inp in inputs:
        for mode in ("zero", "drop"):
            out = tmp / f"{mode}-{inp.name}"
            r = run(exe, *data, "anonymize", "--project", "f", "--payload", mode, inp, "-o", out)
            check(r.returncode == 0, f"{inp.name} ({mode}) publishes ({r.stderr.strip()[-200:]})")
            if r.returncode != 0:
                continue
            c = run(sys.executable, CANARY, fixtures / "canaries.json", out, "--source", inp.name)
            check(c.returncode == 0, f"{inp.name} ({mode}) no canary survives ({c.stdout.strip()[:300]})")
            s = run(exe, *data, "scan", "--project", "f", out)
            check(s.returncode == 0, f"{inp.name} ({mode}) the independent scan is clean")
            report = json.loads(Path(str(out) + ".report.json").read_text())
            fr = report["sip"]["fragments"]
            # In order, out of order, duplicated, identical overlap and two interleaved: six.
            check(fr["datagrams_rewritten"] == 6, f"{inp.name} ({mode}) six datagrams rewritten ({fr})")
            z = fr.get("datagrams_zeroed", {})
            check(z.get("ambiguous") == 1 and z.get("missing") == 1 and z.get("not-sip") == 1,
                  f"{inp.name} ({mode}) conflicting, incomplete and non-SIP datagrams zeroed and counted ({z})")
            if not tshark:
                continue
            # Zero mode keeps every packet and its number; drop mode removes later
            # fragments of the datagrams it does not rewrite (feature 001), so numbers shift.
            frames = ["--ignore-frames"] if mode == "drop" else []
            ld = run(sys.executable, LADDER, inp, out, "--subset", *frames)
            check(ld.returncode == 0,
                  f"{inp.name} ({mode}) SIP ladder of the rewritten datagrams ({ld.stdout.strip()[-300:]})")
            if mode == "zero":
                count = lambda f: len(run("tshark", "-n", "-r", f, "-T", "fields", "-e", "frame.number").stdout.split())
                check(count(inp) == count(out), f"{inp.name} (zero) every packet is kept ({count(out)})")
            n_out = len([l for l in run("tshark", "-n", "-r", out, "-Y", "sip", "-T", "fields",
                                        "-e", "frame.number").stdout.splitlines() if l])
            check(n_out == 6, f"{inp.name} ({mode}) tshark reassembles six SIP messages ({n_out})")
            d = run(sys.executable, DIFF, inp, out, "--payload", mode)
            check(d.returncode == 0, f"{inp.name} ({mode}) no new expert errors ({d.stdout.strip()[-300:]})")
            fin, fout = fragments(inp), fragments(out)
            largest = max(n for _, _, n, _ in fin)
            check(all(n <= largest for _, _, n, _ in fout),
                  f"{inp.name} ({mode}) no output fragment is larger than the largest input fragment")
            # The two large INVITEs are cut into fragments again: complete, in units of 8.
            by_id = {}
            for ident, off, n, more in fout:
                by_id.setdefault(ident, []).append((off, n, more))
            cut = [sorted(set(v)) for v in by_id.values() if len(set(v)) > 1]
            check(len([v for v in cut if all(v[k][0] + v[k][1] == v[k + 1][0] for k in range(len(v) - 1))
                       and not v[-1][2]]) >= 2,
                  f"{inp.name} ({mode}) rewritten datagrams larger than the MTU are refragmented ({len(cut)})")
            check(all(o % 8 == 0 for _, o, _, _ in fout) and all(n % 8 == 0 for _, _, n, m in fout if m),
                  f"{inp.name} ({mode}) offsets and non-last lengths are multiples of 8")
    if not tshark:
        print("tshark not installed: ladder, expert and fragment-size checks skipped")
sys.exit(1 if failures else 0)

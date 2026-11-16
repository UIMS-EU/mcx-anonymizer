#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Feature 006 US2: `mcxanon project lookup` in both directions over the demo project:
output format, banner, exit codes 0/1/2/3/5, never issues a pseudonym,
the project files unchanged.

Usage: test_lookup.py MCXANON
"""
import fcntl
import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
GEN = REPO / "tools" / "fixturegen" / "mcx_demo.py"
exe = sys.argv[1]
failures = []


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def run(*args):
    return subprocess.run([str(a) for a in args], capture_output=True, text=True)


def files_of(pdir):
    return {f: (hashlib.sha256((pdir / f).read_bytes()).hexdigest(), (pdir / f).stat().st_mtime_ns)
            for f in ("project.secret", "mapping.map.json")}


with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    data = ["--data-dir", tmp / "data"]
    run(sys.executable, GEN, "--out", tmp)
    run(exe, *data, "project", "init", "demo")
    check(run(exe, *data, "anonymize", "--project", "demo", tmp / "mcx_demo.pcapng", "-o", tmp / "o.pcapng")
          .returncode == 0, "anonymize the demo")
    pdir = tmp / "data" / "projects" / "demo"
    before = files_of(pdir)
    rows = [l.split("\t")[:3] for l in run(exe, *data, "project", "show-map", "demo").stdout.splitlines()[1:]]
    BINARY = {"spi", "ssrc", "fc-ref", "eci", "nci", "tac", "nr-tac", "mbms-sai", "mbsfn-area", "mbs-fsa", "vlan",
              "port-eph"}
    SIMPLE = {"ipv4", "ipv4-pp", "mac", "sip-user", "call-id", "tag", "branch", "entity-tag", "uuid", "opaque",
              "digest", "cell-id", "msrp-tid", "msrp-msgid", "msrp-session", "boundary", "cname", "tel", "sdp-sess"}
    bad = []
    tested = 0
    for cat, orig, pseudo in rows:
        if cat not in SIMPLE and cat not in BINARY:
            continue
        r = run(exe, *data, "project", "lookup", "demo", pseudo)
        lines = [l.split("\t") for l in r.stdout.splitlines()]
        if r.returncode != 0 or [cat, pseudo, orig] not in lines:
            bad.append(("to-original", cat, pseudo, r.returncode, r.stdout[:80]))
        r = run(exe, *data, "project", "lookup", "demo", "--original", "--", orig)  # "--": a value may start with "-"
        lines = [l.split("\t") for l in r.stdout.splitlines()]
        if r.returncode != 0 or [cat, orig, pseudo] not in lines:
            bad.append(("to-pseudonym", cat, orig, r.returncode, r.stdout[:80]))
        tested += 1
    check(tested >= 100 and not bad, f"every mapped value of {tested} looks up both ways {bad[:4]}")
    r = run(exe, *data, "project", "lookup", "demo", "u-0badcafe")
    check(r.returncode == 1 and r.stdout == "" and "the output contains ORIGINAL values" in r.stderr,
          "not found: exit 1, empty stdout, banner")
    r = run(exe, *data, "project", "lookup", "demo", "--original", "sip:nobody@example.org")
    check(r.returncode == 1 and r.stdout == "" and "'nobody' has not been seen" in r.stderr,
          "an unseen component is named")
    check(run(exe, *data, "project", "lookup", "demo").returncode == 2, "missing value: exit 2")
    check(run(exe, *data, "project", "lookup", "nope", "x").returncode == 3, "unknown project: exit 3")
    lock = open(pdir / "lock", "r+")
    fcntl.flock(lock, fcntl.LOCK_EX)
    check(run(exe, *data, "project", "lookup", "demo", "x").returncode == 5, "locked project: exit 5")
    fcntl.flock(lock, fcntl.LOCK_UN)
    lock.close()
    check(files_of(pdir) == before, "the project files are unchanged")

sys.exit(1 if failures else 0)

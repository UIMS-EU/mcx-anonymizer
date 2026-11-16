#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Feature 006 SC-002: a control text of at least 1 MB that holds no pseudonym of the
project (the repository's README, rules, licence and schemas, plus the pseudonym column of a
second project's mapping) passes `reveal` unchanged with default options; the second
project's pseudonym-shaped values are listed as unknown.

Usage: test_reveal_control.py MCXANON
"""
import json
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


def run(*args, stdin=None):
    return subprocess.run([str(a) for a in args], capture_output=True, input=stdin)


with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    data = ["--data-dir", tmp / "data"]
    run(sys.executable, GEN, "--out", tmp)
    for p in ("mine", "other"):
        run(exe, *data, "project", "init", p)
        check(run(exe, *data, "anonymize", "--project", p, tmp / "mcx_demo.pcapng", "-o", tmp / f"{p}.pcapng")
              .returncode == 0, f"anonymize the demo into project {p}")
    other = run(exe, *data, "project", "show-map", "other").stdout.decode().splitlines()[1:]
    others = "\n".join(l.split("\t")[2] for l in other) + "\n"
    parts = [REPO / "README.md", REPO / "LICENSE", *sorted((REPO / "rules").glob("*.yaml")),
             *sorted((REPO / "schemas").glob("*.json"))]
    corpus = b"".join(p.read_bytes() for p in parts)
    text = b""
    while len(text) < 1_100_000:
        text += corpus
    text += others.encode()
    (tmp / "control.txt").write_bytes(text)
    rep = tmp / "r.json"
    r = run(exe, *data, "reveal", "--project", "mine", tmp / "control.txt", "-o", tmp / "out.txt", "--report", rep)
    check(r.returncode == 0, "reveal exits 0")
    check(len(text) >= 1_000_000, f"the control text is at least 1 MB ({len(text)})")
    check((tmp / "out.txt").read_bytes() == text, "the control text is unchanged")
    doc = json.loads(rep.read_text())
    check(doc["revealed"] == {}, f"zero replacements ({doc['revealed']})")
    unknown = sum(doc["unknown"].values())
    check(unknown >= 50, f"the other project's shaped pseudonyms are listed as unknown ({doc['unknown']})")

sys.exit(1 if failures else 0)

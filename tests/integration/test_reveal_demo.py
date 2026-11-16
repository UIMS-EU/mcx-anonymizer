#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Feature 006 SC-001: the demo capture anonymised into a fresh project; a findings text
quoting every pseudonym in several styles is revealed exactly to the expected text; every canary
of a revealable category is restored; the project files are unchanged.

Usage: test_reveal_demo.py MCXANON
"""
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
GEN = REPO / "tools" / "fixturegen" / "mcx_demo.py"
sys.path.insert(0, str(Path(__file__).resolve().parent))
import reveal_findings  # noqa: E402

exe = sys.argv[1]
failures = []


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def run(*args, stdin=None):
    return subprocess.run([str(a) for a in args], capture_output=True, input=stdin)


def digest(d):
    return {f: hashlib.sha256((d / f).read_bytes()).hexdigest() + str((d / f).stat().st_mtime_ns)
            for f in ("project.secret", "mapping.map.json")}


with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    data = ["--data-dir", tmp / "data"]
    check(run(sys.executable, GEN, "--out", tmp).returncode == 0, "demo generator runs")
    check(run(exe, *data, "project", "init", "demo").returncode == 0, "project init")
    r = run(exe, *data, "anonymize", "--project", "demo", tmp / "mcx_demo.pcapng", "-o", tmp / "out.pcapng")
    check(r.returncode == 0, f"anonymize ({r.stderr.decode()[-200:]})")
    pdir = tmp / "data" / "projects" / "demo"
    before = digest(pdir)

    rows = reveal_findings.show_map(exe, str(tmp / "data"), "demo")
    findings, expected, pairs = reveal_findings.build(rows)
    check(len(pairs) >= 100, f"findings text quotes many pseudonyms ({len(pairs)})")
    (tmp / "findings.txt").write_text(findings)
    r = run(exe, *data, "reveal", "--project", "demo", tmp / "findings.txt", "-o", tmp / "revealed.txt",
            "--report", tmp / "reveal.json")
    check(r.returncode == 0, f"reveal exits 0 ({r.stderr.decode()[-300:]})")
    revealed = (tmp / "revealed.txt").read_text()
    if revealed != expected:
        for a, b in zip(revealed.splitlines(), expected.splitlines()):
            if a != b:
                print(f"  got:  {a}\n  want: {b}")
                break
    check(revealed == expected, "the revealed text equals the expected text")
    report = json.loads((tmp / "reveal.json").read_text())
    check(sum(report["revealed"].values()) == 2 * len(pairs), "every quoted pseudonym is counted as revealed")
    check(not report["candidates"], f"no ambiguous or unknown candidate ({report['candidates'][:3]})")

    # Every canary that the project maps is restored.
    canaries = json.loads((tmp / "mcx_demo.canaries.json").read_text())["canaries"]
    mapped = {o for c, o, p in rows}
    expected_values = {o for _p, o in pairs}
    restored = [c["value"] for c in canaries if c["value"] in mapped and c["value"] in expected_values]
    missing = [c["value"] for c in canaries if c["value"] in expected_values and c["value"] not in revealed]
    check(len(restored) >= 20 and not missing, f"canaries restored ({len(restored)}), missing {missing[:5]}")

    # stdin -> stdout gives the same text.
    r = run(exe, *data, "reveal", "--project", "demo", "--quiet", stdin=findings.encode())
    check(r.returncode == 0 and r.stdout.decode() == expected, "stdin to stdout")
    check(digest(pdir) == before, "the project files are unchanged")

sys.exit(1 if failures else 0)

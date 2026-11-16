#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Feature 008: the patterns of the first pilot on third-party captures, reproduced by the
pilot_* fixtures (tools/fixturegen/pilot.py), are anonymised without a false leak and without a
change of the protocol view.

  - pilot_tcp_cookie: a TCP segment ends inside the branch cookie (cut after 1 to 6 characters):
    the run publishes, no canary survives, the independent scan is clean, the report counts the
    skipped input fragments (FR-001, FR-002).

Usage: test_pilot_fixes.py MCXANON FIXTURE_DIR
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

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

sys.exit(1 if failures else 0)

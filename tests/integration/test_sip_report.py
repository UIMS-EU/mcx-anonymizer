#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""User Story 5 (FR-036, FR-037): the report of a fixture with known content.

sip_report.pcapng is anonymised in both payload modes, with the fixture's deny list. Every
counter of the report's `sip` object must equal the generator's expected counts
(sip_report.expected.json, written by tools/fixturegen/sip.py from the rule data, not from the
tool's output); the report validates against schemas/report.schema.json; the report self-check
reports an unknown header name that contains a deny-list word or a pseudonymised value as
"(invalid-name)"; stderr carries the SIP summary line and no unknown header name.

Usage: test_sip_report.py MCXANON FIXTURE_DIR
"""
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCHEMA = REPO / "schemas" / "report.schema.json"
VALIDATE = REPO / "tests" / "integration" / "validate_report.py"
CANARY = REPO / "tests" / "integration" / "canary_absent.py"
LIMITS = ("max_message_bytes", "max_tcp_directions", "max_held_bytes", "pending_timeout_ms",
          "retrans_cache_bytes", "max_offset_breakpoints", "max_pending_datagrams")
exe, fixtures = sys.argv[1], Path(sys.argv[2])
failures = []


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def run(*args):
    return subprocess.run([str(a) for a in args], capture_output=True, text=True)


def nonzero(v):
    """The value without zero counts and empty maps: absent and zero mean the same."""
    if isinstance(v, dict):
        out = {k: nonzero(x) for k, x in v.items()}
        return {k: x for k, x in out.items() if x not in (0, {})}
    return v


def diff(want, got, path="sip"):
    """Human-readable differences between two nested count maps."""
    if isinstance(want, dict) and isinstance(got, dict):
        out = []
        for k in sorted(set(want) | set(got)):
            out += diff(want.get(k, 0), got.get(k, 0), f"{path}.{k}")
        return out
    return [] if want == got else [f"{path}: expected {want}, got {got}"]


inp = fixtures / "sip_report.pcapng"
exp_path = fixtures / "sip_report.expected.json"
check(inp.is_file(), "report fixture present")
check(exp_path.is_file(), "expected counts present (written by the generator next to the manifest)")
if failures:
    sys.exit(1)
expected = json.loads(exp_path.read_text())
deny = fixtures / expected["deny_list"]


def overlay(base, over):
    out = dict(base)
    for k, x in over.items():
        out[k] = overlay(base.get(k, {}), x) if isinstance(x, dict) else x
    return out


want_by_mode = {m: nonzero(overlay(expected["sip"], expected.get("sip_by_mode", {}).get(m, {})))
                for m in ("zero", "drop")}
want = want_by_mode["zero"]
messages = sum(want["messages"].get("requests", {}).values()) + \
    sum(want["messages"].get("responses", {}).values())

with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    data = ["--data-dir", tmp / "data"]
    check(run(exe, *data, "project", "init", "r").returncode == 0, "project init")
    for mode in ("zero", "drop"):
        out = tmp / f"{mode}.pcapng"
        r = run(exe, *data, "anonymize", "--project", "r", "--payload", mode, "--deny-list", deny, inp, "-o", out)
        check(r.returncode == 0, f"{mode}: publishes ({r.stderr.strip()[-300:]})")
        if r.returncode != 0:
            continue
        rpath = Path(str(out) + ".report.json")
        text = rpath.read_text()
        report = json.loads(text)
        check(report["format"] == 6, f"{mode}: report format 6")
        v = run(sys.executable, VALIDATE, SCHEMA, rpath)
        check(v.returncode == 0, f"{mode}: report validates against the schema ({v.stdout.strip()[-300:]})")
        sip = report.get("sip", {})
        limits = sip.get("limits", {})
        check(all(isinstance(limits.get(k), int) and limits[k] > 0 for k in LIMITS),
              f"{mode}: every limit is reported ({limits})")
        got = nonzero({k: x for k, x in sip.items() if k != "limits"})
        d = diff(want_by_mode[mode], got)
        check(not d, f"{mode}: every sip counter equals the expected count" + "".join(f"\n       {x}" for x in d))
        # Self-check (FR-036): names from the input that contain a deny-list word or a
        # pseudonymised value are reported as "(invalid-name)".
        for name in expected["redacted_header_names"]:
            check(name.lower() not in text.lower(), f"{mode}: the report does not name the header {name}")
        unknown = sip.get("removed_unknown", {}).get("sip-header", {})
        check(unknown.get("(invalid-name)") == len(expected["redacted_header_names"]),
              f"{mode}: the self-check redacted {len(expected['redacted_header_names'])} header names ({unknown})")
        c = run(sys.executable, CANARY, fixtures / "canaries.json", out, "--source", inp.name)
        check(c.returncode == 0, f"{mode}: no canary survives ({c.stdout.strip()[:300]})")
        # stderr: the summary line, and no name from the input.
        m = re.search(r"^sip: (\d+) messages \((\d+) malformed\)", r.stderr, re.M)
        check(m is not None and int(m.group(1)) == messages and int(m.group(2)) == want["messages"].get("malformed", 0),
              f"{mode}: stderr carries the SIP summary line ({m.group(0) if m else r.stderr.strip()[-200:]})")
        for name in expected["unknown_header_names"]:
            check(name.lower() not in r.stderr.lower(), f"{mode}: stderr does not name the header {name}")

    # Without the deny list, a header name that contains a pseudonymised value is still
    # redacted: the self-check also uses the scan tokens of the run.
    out = tmp / "nodeny.pcapng"
    r = run(exe, *data, "anonymize", "--project", "r", inp, "-o", out)
    check(r.returncode == 0, f"without deny list: publishes ({r.stderr.strip()[-300:]})")
    if r.returncode == 0:
        text = Path(str(out) + ".report.json").read_text()
        for name in expected["token_header_names"]:
            check(name.lower() not in text.lower(), f"without deny list: the report does not name the header {name}")
        unknown = json.loads(text)["sip"]["removed_unknown"].get("sip-header", {})
        check(unknown.get("(invalid-name)") == len(expected["token_header_names"]),
              f"without deny list: the scan tokens redact {len(expected['token_header_names'])} header name ({unknown})")
sys.exit(1 if failures else 0)

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""User Story 6 (FR-003, FR-004, FR-007, FR-009, FR-018, FR-020, SC-001, SC-007): hostile,
unknown or broken XML never leaks.

Every xml_hostile_<case>.pcapng fixture carries one body twice, alone in a MESSAGE and as a
multipart part next to SDP, with canaries inside the body and in the From user part. In
--payload zero and --payload drop each run must exit 0 within the time bound, keep the SIP
message well-formed, count the body or the removed items by reason, and leave no canary in the
output or in the report.

Expectations are lower bounds where a later story's rules change what happens to a nested
element (an encryptable element or MKFC-GKTPs inside mcptt-Params is removed as unknown until
the full mcptt-info rules exist); the items directly under the root keep their outcome.

Usage: test_xml_failclosed.py MCXANON FIXTURE_DIR [--no-time]
"""
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CANARY = REPO / "tests" / "integration" / "canary_absent.py"
exe, fixtures = sys.argv[1], Path(sys.argv[2])
timed = "--no-time" not in sys.argv[3:]
INFO = "application/vnd.3gpp.mcptt-info+xml"
NS = "urn:3gpp:ns:mcpttInfo:1.0"
failures = []


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def run(*args):
    return subprocess.run([str(a) for a in args], capture_output=True, text=True)


def body_outcome(reason):
    def f(x, sip):
        got = x["bodies"].get(INFO, {})
        return got.get(reason, 0) == 2 and sum(got.values()) == 2, f"bodies[{INFO}] == {{{reason}: 2}} ({got})"
    return f


def rewritten_and(pred, what):
    def f(x, sip):
        got = x["bodies"].get(INFO, {})
        ok = got == {"rewritten": 2}
        p, detail = pred(x)
        return ok and p, f"rewritten twice ({got}) and {what} ({detail})"
    return f


def unknown_type(x, sip):
    ct = sip.get("removed_unknown", {}).get("content-type", {})
    n = ct.get("application/vnd.example.vendor-data+xml", 0)
    return n == 2 and not x["bodies"], f"the unknown +xml type is emptied by the SIP rules and counted ({ct}, xml {x['bodies']})"


def vendor(x):
    ns = x["removed"]["namespaces"]
    el = sum(v.get("unknown", 0) for k, v in x["elements"].items() if k.startswith(NS + " "))
    at = sum(v.get("unknown", 0) for k, v in x["attributes"].items() if k.startswith(NS + " mcpttinfo @"))
    ok = ns.get("(invalid-name)", 0) >= 2 and el >= 2 and at >= 2
    return ok, f"namespaces {ns}, unknown elements {el}, unknown attributes {at}"


def comments(x):
    r = x["removed"]
    return r["comments"] == 2 and r["processing_instructions"] == 2, f"{r}"


def xenc_child(x):
    return x["removed"]["encrypted"] >= 2, f"encrypted {x['removed']['encrypted']}"


def gktp(x):
    got = x["elements"].get("urn:3gpp:ns:mcpttGKTP:1.0 GKTP", {})
    return got.get("remove", 0) >= 2, f"{got}"


EXPECT = {
    "dtd-internal": body_outcome("dtd"),
    "dtd-external": body_outcome("dtd"),
    "depth-33": body_outcome("limit"),
    "elements-10001": body_outcome("limit"),
    "attributes-65": body_outcome("limit"),
    "value-65537": body_outcome("limit"),
    "name-257": body_outcome("limit"),
    "invalid-utf8": body_outcome("encoding"),
    "utf16-bom": body_outcome("encoding"),
    "charset-latin1": body_outcome("encoding"),
    "decl-latin1": body_outcome("encoding"),
    "unclosed": body_outcome("malformed"),
    "undeclared-prefix": body_outcome("malformed"),
    "unknown-root": body_outcome("root"),
    "unknown-type": unknown_type,
    "vendor-ns": rewritten_and(vendor, "vendor namespace, unknown element and attribute removed and counted"),
    "comments-pis": rewritten_and(comments, "comments and PIs removed and counted"),
    "xenc-child": rewritten_and(xenc_child, "xenc:EncryptedData subtrees removed and counted"),
    "xenc-root": body_outcome("rewritten"),  # feature 005 (FR-016): rewritten by the xenc rules
    "gktp": rewritten_and(gktp, "GKTP removed as a credential"),
}

inputs = {p.name[len("xml_hostile_"):-len(".pcapng")]: p for p in fixtures.glob("xml_hostile_*.pcapng")}
check(set(inputs) == set(EXPECT), f"one fixture per hostile case (missing {sorted(set(EXPECT) - set(inputs))}, "
                                  f"unexpected {sorted(set(inputs) - set(EXPECT))})")
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    data = ["--data-dir", tmp / "data"]
    run(exe, *data, "project", "init", "x")
    for case in sorted(EXPECT):
        inp = inputs.get(case)
        if inp is None:
            continue
        for pm in ("zero", "drop"):
            out = tmp / f"{pm}-{inp.name}"
            t0 = time.monotonic()
            r = run(exe, *data, "anonymize", "--project", "x", "--payload", pm, inp, "-o", out)
            took = time.monotonic() - t0
            tag = f"{case} ({pm})"
            check(r.returncode == 0, f"{tag}: exits 0 and publishes ({r.stderr.strip()[-200:]})")
            if timed:
                check(took < 1.0, f"{tag}: completes within 1 s ({took:.2f} s)")
            if r.returncode != 0:
                continue
            report = Path(str(out) + ".report.json")
            rep = json.loads(report.read_text())
            sip = rep.get("sip", {})
            check(sip.get("messages", {}).get("malformed") == 0 and sip["messages"]["requests"].get("MESSAGE") == 2,
                  f"{tag}: both SIP messages are rewritten, none malformed ({sip.get('messages')})")
            ok, detail = EXPECT[case](rep["xml"], sip)
            check(ok, f"{tag}: {detail}")
            c = run(sys.executable, CANARY, fixtures / "canaries.json", out, "--source", inp.name)
            check(c.returncode == 0, f"{tag}: no canary in the output ({c.stdout.strip()[:300]})")
            # Unknown element and attribute names are reported by name, like unknown SIP header
            # names in 002 (FR-020); the name canaries are checked in the output only.
            c = run(sys.executable, CANARY, fixtures / "canaries.json", report, "--source", inp.name, "--report")
            check(c.returncode == 0, f"{tag}: no canary value in the report ({c.stdout.strip()[:300]})")
sys.exit(1 if failures else 0)

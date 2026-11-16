#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""US5 of feature 005: --encrypted passthrough.

usage: test_mikey_passthrough.py MCXANON FIXTURE_DIR

Anonymises the US1-US4 fixtures with --encrypted passthrough and checks US5 scenarios 1-5:
- every recognised I_MESSAGE and EncryptedData subtree is byte-identical to the input
  (mikey_consistency.py --passthrough; the XML subtrees compared directly);
- everything outside them is anonymised: the SIP identities carry pseudonyms;
- the output is written with exit 0, and the canaries inside the passthrough elements are scan
  warnings with frame, offset, carrier and category, never a value;
- the stderr summary and the report carry the passthrough statement;
- a deny-list word outside every passthrough element still fails the run (exit 1, no output);
- `scan --encrypted passthrough` gives the same warnings, and plain `scan` fails on them.
"""
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from sip_messages import header, messages  # noqa: E402

exe, fixtures = sys.argv[1], Path(sys.argv[2])
failures = []
STATEMENT = "passthrough: the output contains original identities and key identifiers"


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def run(*args):
    return subprocess.run([str(a) for a in args], capture_output=True, text=True)


ENC = re.compile(rb"<(?:[\w.-]+:)?EncryptedData\b.*?</(?:[\w.-]+:)?EncryptedData>", re.S)

with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    data = ["--data-dir", tmp / "data"]
    check(run(exe, *data, "project", "init", "p").returncode == 0, "project init")
    for name, expect in (("mikey_sdp", 4), ("mikey_body", 8), ("mikey_gktp", 5), ("mikey_mcpc", 2), ("mikey_xenc", 1)):
        inp, out = fixtures / f"{name}.pcapng", tmp / f"{name}.pcapng"
        r = run(exe, *data, "anonymize", "--project", "p", "--encrypted", "passthrough", inp, "-o", out)
        check(r.returncode == 0 and out.exists(), f"{name}: publishes with exit 0 ({r.stderr.strip()[-300:]})")
        if r.returncode != 0:
            continue
        check(STATEMENT in r.stderr, f"{name}: the stderr summary states the passthrough")
        o = run(sys.executable, HERE / "mikey_consistency.py", inp, out, "--passthrough", "--expect", expect)
        check(o.returncode == 0, f"{name}: every I_MESSAGE byte-identical ({(o.stdout + o.stderr).strip()[-300:]})")
        rep = json.loads(Path(str(out) + ".report.json").read_text())
        check(rep["options"]["encrypted"] == "passthrough", f"{name}: report options.encrypted")
        check(any(STATEMENT in s for s in rep["not_anonymised"]), f"{name}: the report states the passthrough")
        warnings = rep.get("scan", {}).get("warnings", [])
        check(len(warnings) > 0 and all(set(w) == {"frame", "offset", "carrier", "category"} for w in warnings),
              f"{name}: warnings with frame, offset, carrier and category ({len(warnings)})")
        check(rep["scan"].get("hits") == [], f"{name}: no hit outside the passthrough elements")
        # Everything outside is anonymised: the From header carries a pseudonym.
        frm_in = [header(m.headers, "from") for m in messages(str(inp))]
        frm_out = [header(m.headers, "from") for m in messages(str(out))]
        check(frm_in and all(a != b for a, b in zip(frm_in, frm_out) if a), f"{name}: the SIP headers are pseudonymised")
        if name == "mikey_xenc":
            ein, eout = ENC.findall(inp.read_bytes()), ENC.findall(out.read_bytes())
            check(len(ein) == 2 and ein == eout, f"{name}: every EncryptedData subtree is byte-identical")
            check(any(w["carrier"] == "encrypted-xml" for w in warnings), f"{name}: encrypted-xml warnings")
        # Scenario 5: the standalone scanner with and without the mode.
        s1 = run(exe, *data, "scan", "--project", "p", "--encrypted", "passthrough", "--report", tmp / "s1.json", out)
        check(s1.returncode == 0, f"{name}: scan --encrypted passthrough passes ({s1.stdout.strip()[-200:]})")
        if s1.returncode == 0:
            # The standalone scan searches the project mapping only (not the input harvest): its
            # warnings are a non-empty subset of the anonymiser's.
            w1 = json.loads((tmp / "s1.json").read_text()).get("scan", {}).get("warnings", [])
            check(w1 and all(w in warnings for w in w1), f"{name}: the same warnings ({len(w1)} of {len(warnings)})")
        s2 = run(exe, *data, "scan", "--project", "p", out)
        check(s2.returncode == 1, f"{name}: plain scan fails on the same values ({s2.returncode})")
    # Scenario 2: a value outside every passthrough element still blocks the output.
    deny = tmp / "deny.txt"
    deny.write_text("poc-settings\n")  # the Event header of the PUBLISH, kept by the rules
    inp, out = fixtures / "mikey_body.pcapng", tmp / "blocked.pcapng"
    r = run(exe, *data, "anonymize", "--project", "p", "--encrypted", "passthrough", "--deny-list", deny, inp, "-o", out)
    check(r.returncode == 1 and not out.exists(), f"a hit outside fails: exit {r.returncode}, no output")

if failures:
    print(f"{len(failures)} failure(s)")
    sys.exit(1)

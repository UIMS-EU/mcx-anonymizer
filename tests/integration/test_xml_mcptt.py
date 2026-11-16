#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""User Story 1 (FR-010..FR-015, SC-001..SC-004): MCPTT information bodies stay readable.

Runs xml_mcptt_info.pcapng (INVITE with SDP + mcptt-info, 200 OK, REFER, MESSAGE, INFO; default
namespace and a prefix with single quotes; every encryptable element encrypted; the
parent-qualified and malformed shapes) in --payload zero and --payload drop and checks:
  - the structure oracle (xml_structure.py) and the consistency oracle (xml_consistency.py);
  - no canary in the output, and no canary value in the report;
  - the report counts: every mcptt-info body rewritten, enumerations and booleans kept, URIs
    pseudonymised, the access token's children removed, encrypted subtrees counted;
  - US1 scenario 1: session-type and emergency-ind keep their values in the INVITE part;
  - US1 scenario 3: the access token value is absent.

Usage: test_xml_mcptt.py MCXANON FIXTURE_DIR
"""
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from sip_messages import messages  # noqa: E402

exe, fixtures = sys.argv[1], Path(sys.argv[2])
NS = "urn:3gpp:ns:mcpttInfo:1.0"
CT = "application/vnd.3gpp.mcptt-info+xml"
failures = []


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def run(*args):
    return subprocess.run([str(a) for a in args], capture_output=True, text=True)


inp = fixtures / "xml_mcptt_info.pcapng"
manifest = fixtures / "canaries.json"
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    data = ["--data-dir", tmp / "data"]
    run(exe, *data, "project", "init", "m")
    for pm in ("zero", "drop"):
        out = tmp / f"{pm}.pcapng"
        r = run(exe, *data, "anonymize", "--project", "m", "--payload", pm, inp, "-o", out)
        check(r.returncode == 0, f"{pm}: publishes ({r.stderr.strip()[-300:]})")
        if r.returncode != 0:
            continue
        rep = json.loads(Path(str(out) + ".report.json").read_text())
        for oracle in ("xml_structure.py", "xml_consistency.py"):
            args = [inp, out] + ([manifest] if oracle == "xml_structure.py" else [])
            o = run(sys.executable, HERE / oracle, *args)
            check(o.returncode == 0, f"{pm}: {oracle} ({(o.stdout + o.stderr).strip()[-400:]})")
        c = run(sys.executable, HERE / "canary_absent.py", manifest, out, "--source", inp.name)
        check(c.returncode == 0, f"{pm}: no canary in the output ({c.stdout.strip()[:300]})")
        c = run(sys.executable, HERE / "canary_absent.py", manifest, Path(str(out) + ".report.json"),
                "--source", inp.name, "--report")
        check(c.returncode == 0, f"{pm}: no canary in the report ({c.stdout.strip()[:300]})")
        x = rep["xml"]
        check(x["bodies"].get(CT) == {"rewritten": 5}, f"{pm}: five mcptt-info bodies rewritten ({x['bodies'].get(CT)})")
        el = x["elements"]
        check(el.get(f"{NS} session-type", {}).get("keep", 0) >= 3, f"{pm}: session-type kept ({el.get(f'{NS} session-type')})")
        check(el.get(f"{NS} mcpttURI", {}).get("pseudonymise", 0) >= 40,
              f"{pm}: mcpttURI pseudonymised ({el.get(f'{NS} mcpttURI')})")
        check(el.get(f"{NS} mcpttString", {}).get("remove", 0) >= 4,
              f"{pm}: access token and free-text strings removed ({el.get(f'{NS} mcpttString')})")
        check(el.get(f"{NS} mcpttURI", {}).get("malformed", 0) == 1, f"{pm}: garbage in a URI element is malformed")
        check(el.get(f"{NS} mcpttString", {}).get("pseudonymise", 0) == 3 and
              el.get(f"{NS} mcpttString", {}).get("malformed", 0) == 0,
              f"{pm}: the MCPTT client IDs are pseudonymised ({el.get(f'{NS} mcpttString')})")
        # The 22 encryptable elements of TS 24.379 §F.1.3 item 1; non-acknowledged-user occurs twice.
        # Feature 005 (FR-016): their EncryptedData is kept by the xenc rules, not removed.
        kept = rep.get("mikey", {}).get("encrypted_xml", {}).get("kept")
        check(kept == 23 and x["removed"]["encrypted"] == 0, f"{pm}: every xenc subtree of the encrypted body kept ({kept})")
        check(not any(k.endswith(" unknown") for k in el) and
              all("unknown" not in v for k, v in el.items() if k.startswith(NS)),
              f"{pm}: no mcptt-info element is unknown ({[k for k, v in el.items() if 'unknown' in v]})")
        # Scenario 1 and 3 on the INVITE's mcptt-info part.
        msgs = messages(str(out))
        invite = next((m for m in msgs if m.start.startswith("INVITE ")), None)
        part = next((p for p in invite.parts if p.content_type == CT), None) if invite else None
        check(part is not None and b"<session-type>private</session-type>" in part.body and
              b"<mcpttBoolean>false</mcpttBoolean>" in part.body, f"{pm}: session-type and emergency-ind values kept")
        check(part is not None and re.search(rb'<mcptt-access-token type="Normal">\s*</mcptt-access-token>', part.body),
              f"{pm}: the access token is an empty marker with its type")
sys.exit(1 if failures else 0)

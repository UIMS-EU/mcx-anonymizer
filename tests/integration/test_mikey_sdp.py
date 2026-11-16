#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""US1 of feature 005: a=key-mgmt:mikey in SDP, ciphertext mode.

usage: test_mikey_sdp.py MCXANON FIXTURE_DIR [--tshark]

Anonymises mikey_sdp.pcapng (INVITE offer, 200 OK answer, re-INVITE with media-level "a=key-mgmt:
mikey", a 488 with Warning 136 and an MBMS announcement with an MSCCK) and checks the US1
scenarios: the I_MESSAGEs stay MIKEY-SAKKE with the same structure (mikey_consistency.py), the
initiator and responder identities are the pseudonyms the SIP headers carry, no canary remains,
the report counts and states what the spec says, and --time-shift moves the MIKEY timestamp.
With --tshark (label integrity) the tshark expert diff runs in --mikey mode.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import mikey_consistency as mc  # noqa: E402
from sip_messages import header, messages  # noqa: E402

exe, fixtures = sys.argv[1], Path(sys.argv[2])
use_tshark = "--tshark" in sys.argv
failures = []
if use_tshark:
    import shutil
    if shutil.which("tshark") is None:
        if os.environ.get("MCXANON_REQUIRE_TSHARK") == "1":
            print("FAIL tshark is required but not installed")
            sys.exit(1)
        print("tshark not installed: skipped")
        sys.exit(77)


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def run(*args):
    return subprocess.run([str(a) for a in args], capture_output=True, text=True)


def uri_of(v):
    m = re.search(r"<([^>]+)>", v or "")
    return m.group(1) if m else None


inp = fixtures / "mikey_sdp.pcapng"
manifest = fixtures / "canaries.json"
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    data = ["--data-dir", tmp / "data"]
    check(run(exe, *data, "project", "init", "k").returncode == 0, "project init")
    out = tmp / "out.pcapng"
    r = run(exe, *data, "anonymize", "--project", "k", inp, "-o", out)
    check(r.returncode == 0, f"publishes ({r.stderr.strip()[-300:]})")
    if r.returncode == 0:
        o = run(sys.executable, HERE / "mikey_consistency.py", inp, out, "--canaries", manifest, "--expect", "4")
        check(o.returncode == 0, f"mikey_consistency ({(o.stdout + o.stderr).strip()[-600:]})")
        c = run(sys.executable, HERE / "canary_absent.py", manifest, out, "--source", inp.name)
        check(c.returncode == 0, f"no canary in the output ({c.stdout.strip()[:300]})")
        c = run(sys.executable, HERE / "canary_absent.py", manifest, Path(str(out) + ".report.json"), "--source",
                inp.name, "--report")
        check(c.returncode == 0, f"no canary in the report ({c.stdout.strip()[:300]})")
        # Scenario 2: IDRi and IDRr carry the pseudonyms of the From and To URIs of the same message.
        outs = [m for m in messages(str(out))]
        invite = next(m for m in outs if m.start.startswith("INVITE"))
        frm, to = uri_of(header(invite.headers, "from")), uri_of(header(invite.headers, "to"))
        first = mc.decode(mc.carriers(str(out))[0][1])
        idrs = {p["role"]: p["data"].decode() for k, p in first["payloads"] if k == "IDR"}
        check(idrs.get(1) == frm, f"IDRi equals the From pseudonym ({idrs.get(1)} / {frm})")
        check(idrs.get(2) == to, f"IDRr equals the To pseudonym ({idrs.get(2)} / {to})")
        # Scenario 5 and the media-level " mikey" (0*1SP) variant.
        sdps = [p.body for m in outs for p in m.parts if (p.content_type or "").startswith("application/sdp")]
        check(any(b"a=key-mgmt: mikey " in s for s in sdps), "the 0*1SP form is kept")
        check(sum(s.count(b"a=key-mgmt:") for s in sdps) == 4, "four a=key-mgmt attributes kept")
        # Scenario 4: the 488 to the rejected offer is still there (its Warning text follows 002 D2).
        check(any(m.start.startswith("SIP/2.0 488") for m in outs), "the 488 response is kept")
        rep = json.loads(Path(str(out) + ".report.json").read_text())
        check(rep["format"] == 6 and rep["options"]["encrypted"] == "ciphertext", "report format 6, ciphertext")
        mk = rep.get("mikey", {})
        check(mk.get("carriers", {}).get("sdp", {}).get("rewritten") == 4, f"4 SDP carriers rewritten ({mk.get('carriers')})")
        check(mk.get("payloads", {}).get("SIGN", {}).get("invalidated") == 4, "4 signatures invalidated")
        check(mk.get("key_ids", {}).get("PCK") == 3 and mk.get("key_ids", {}).get("MSCCK") == 1, f"key ids {mk.get('key_ids')}")
        stm = "\n".join(rep["not_anonymised"])
        check("signatures of rewritten I_MESSAGEs do not verify" in stm, "statement: invalidated signatures")
        check("are kept as ciphertext" in stm, "statement: ciphertext kept")
        if use_tshark:
            t = run(sys.executable, HERE.parent.parent / "tools" / "tshark-expert-diff.py", inp, out, "--mikey")
            check(t.returncode == 0, f"tshark: no new expert entry, MIKEY still decoded ({t.stdout.strip()[-300:]})")
    # The rule coverage fixture (tests/mikey_rule_keys_main.cpp): IDRkms, GENERIC-ID SSRC and SPI,
    # key parameters, the zeroed extensions, the unknown ID role and SP parameter.
    rin, rout = fixtures / "mikey_rules.pcapng", tmp / "rules.pcapng"
    r = run(exe, *data, "anonymize", "--project", "k", rin, "-o", rout)
    check(r.returncode == 0, f"rule fixture publishes ({r.stderr.strip()[-300:]})")
    if r.returncode == 0:
        o = run(sys.executable, HERE / "mikey_consistency.py", rin, rout, "--canaries", manifest, "--expect", "1")
        check(o.returncode == 0, f"rule fixture: mikey_consistency ({(o.stdout + o.stderr).strip()[-400:]})")
        c = run(sys.executable, HERE / "canary_absent.py", manifest, rout, "--source", rin.name)
        check(c.returncode == 0, f"rule fixture: no canary ({c.stdout.strip()[:300]})")
        m = mc.decode(mc.carriers(str(rout))[0][1])
        exts = {p["type"]: p["data"] for k, p in m["payloads"] if k == "EXT"}
        check(all(not any(exts[t]) for t in (0, 1, 9)), "rule fixture: extensions 0, 1 and unknown zeroed")
        idr = {p["role"]: p["data"] for k, p in m["payloads"] if k == "IDR"}
        check(not any(idr[10]) and any(idr[3]), "rule fixture: unknown role zeroed, IDRkms pseudonymised")
        rep = json.loads(Path(str(rout) + ".report.json").read_text())
        check(rep["mikey"]["payloads"].get("key-parameters", {}).get("rewritten") == 1, "rule fixture: key parameters")
    # Scenario 6: --time-shift moves the MIKEY timestamp by the same amount.
    out2 = tmp / "shift.pcapng"
    r = run(exe, *data, "anonymize", "--project", "k", "--time-shift", "+3d", inp, "-o", out2)
    check(r.returncode == 0, "publishes with --time-shift +3d")
    if r.returncode == 0:
        o = run(sys.executable, HERE / "mikey_consistency.py", inp, out2, "--time-shift-s", "259200")
        check(o.returncode == 0, f"T shifted by 3 days ({(o.stdout + o.stderr).strip()[-300:]})")

if failures:
    print(f"{len(failures)} failure(s)")
    sys.exit(1)

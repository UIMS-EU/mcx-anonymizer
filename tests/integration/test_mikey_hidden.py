#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""US2 of feature 005: hidden identities (UIDs) never reveal the user.

usage: test_mikey_hidden.py MCXANON FIXTURE_DIR

mikey_hidden.pcapng has three private calls whose IDRuidi/IDRuidr carry the UIDs of the INVITE's
caller and callee (raw with roles 8/9, base64 with the private-use roles 241/240) and one UID of
an identity that appears nowhere. Without --kms-key-period every UID becomes an opaque pseudonym;
with it, every UID of a known identity becomes the UID of the identity's pseudonym (computed here
with the generator's own TS 33.180 §F.2.1.1 function, checked against §F.2.1.2) and the unknown one
stays opaque. No original UID may remain in any form.
"""
import base64
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent.parent / "tools" / "fixturegen"))
import mikey as gen  # noqa: E402  (the fixture generator's UID function, independent of the tool)
import mikey_consistency as mc  # noqa: E402
from sip_messages import header, messages  # noqa: E402

exe, fixtures = sys.argv[1], Path(sys.argv[2])
failures = []


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def run(*args):
    return subprocess.run([str(a) for a in args], capture_output=True, text=True)


def bare(v):
    v = v[v.find("<") + 1:v.find(">")] if "<" in v else v
    return v.split(";")[0]


inp = fixtures / "mikey_hidden.pcapng"
manifest = fixtures / "canaries.json"
exp = json.loads((fixtures / "mikey_hidden.expect.json").read_text())
in_uids = [{p["role"]: p["data"] for k, p in mc.decode(b)["payloads"] if k == "IDR" and p["role"] not in (6, 7)}
           for _c, b in mc.carriers(str(inp))]
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    data = ["--data-dir", tmp / "data"]
    check(run(exe, *data, "project", "init", "u").returncode == 0, "project init")
    period_arg = f"{exp['kms']}={exp['period']}:{exp['offset']}"
    for resolve in (False, True):
        out = tmp / f"out-{resolve}.pcapng"
        extra = ["--kms-key-period", period_arg] if resolve else []
        r = run(exe, *data, "anonymize", "--project", "u", *extra, inp, "-o", out)
        check(r.returncode == 0, f"resolve={resolve}: publishes ({r.stderr.strip()[-300:]})")
        if r.returncode != 0:
            continue
        c = run(sys.executable, HERE / "canary_absent.py", manifest, out, "--source", inp.name)
        check(c.returncode == 0, f"resolve={resolve}: no original UID or identity ({c.stdout.strip()[:300]})")
        o = run(sys.executable, HERE / "mikey_consistency.py", inp, out, "--canaries", manifest, "--expect", "3")
        check(o.returncode == 0, f"resolve={resolve}: mikey_consistency ({(o.stdout + o.stderr).strip()[-300:]})")
        text = out.read_bytes() + Path(str(out) + ".report.json").read_bytes()
        check(str(exp["period"]).encode() not in text, f"resolve={resolve}: the key period is not written anywhere")
        rep = json.loads(Path(str(out) + ".report.json").read_text())
        uids = rep["mikey"]["uids"]
        want = (5, 1) if resolve else (0, 6)
        check((uids["resolved"], uids["unresolved"]) == want, f"resolve={resolve}: UIDs resolved/unresolved {uids} == {want}")
        invites = [m for m in messages(str(out)) if m.start.startswith("INVITE")]
        for n, ((_c, ob), m, case) in enumerate(zip(mc.carriers(str(out)), invites, exp["cases"])):
            msg = mc.decode(ob)
            idr = {p["role"]: p["data"] for k, p in msg["payloads"] if k == "IDR"}
            kms_out = idr[6].decode()
            t = next(p for k, p in msg["payloads"] if k == "T")
            p5 = gen.period_number(int.from_bytes(t["value"], "big") >> 32, exp["period"], exp["offset"])
            caller, callee = bare(header(m.headers, "from")), bare(header(m.headers, "to"))
            for role in sorted(r for r in idr if r not in (6, 7)):
                initiator = role in (8, 241)
                who = caller if initiator else callee
                got = idr[role]
                orig = in_uids[n][role]
                if case["form"] != "raw":  # base64 text (the "ghost" call too)
                    got, orig = base64.b64decode(got), base64.b64decode(orig)
                check(got != orig, f"resolve={resolve} call {n} role {role}: the UID changed")
                expected = gen.uid(who, kms_out, exp["period"], exp["offset"], p5)
                resolvable = resolve and (initiator or case["resolvable"])
                check((got == expected) == resolvable,
                      f"resolve={resolve} call {n} role {role}: UID {'is' if resolvable else 'is not'} "
                      "the UID of the pseudonym")

if failures:
    print(f"{len(failures)} failure(s)")
    sys.exit(1)

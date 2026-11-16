#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""US3 of feature 005: <GKTP> hexBinary I_MESSAGEs, ciphertext mode.

usage: test_mikey_gktp.py MCXANON FIXTURE_DIR

Anonymises mikey_gktp.pcapng (a NOTIFY whose xcap-diff element carries a group's <GKTPs>, and the
<MKFC-GKTPs> of the MCPTT and MCVideo information) and checks US3 scenario 2: every <GKTP> holds the
hexBinary of the rewritten I_MESSAGE in the letter case of the input, `id` is pseudonymised,
`activationtime` is kept, the IDRi (the GMS XCAP URI) keeps the AUID and takes the host pseudonym
of the xcap-diff root, no canary remains, and the <GKTP> whose I_MESSAGE does not parse is removed
(FR-020 c), counted as a fallback.
"""
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import mikey_consistency as mc  # noqa: E402
from sip_messages import messages  # noqa: E402

exe, fixtures = sys.argv[1], Path(sys.argv[2])
failures = []


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def run(*args):
    return subprocess.run([str(a) for a in args], capture_output=True, text=True)


GKTP_RE = re.compile(rb"<((?:[\w.-]+:)?GKTP)\b([^>]*)>(\s*)([0-9A-Fa-f]*)(\s*)</\1>")


def gktps(path):
    """[(attributes, lead, hex, trail)] of every <GKTP>, in capture order."""
    out = []
    for m in messages(str(path)):
        for p in m.parts:
            out += [(g.group(2), g.group(3), g.group(4), g.group(5)) for g in GKTP_RE.finditer(p.body)]
    return out


def attr(attrs, name):
    m = re.search(rb'\b' + name + rb'="([^"]*)"', attrs)
    return m.group(1).decode() if m else None


def case(hexs):
    letters = [ch for ch in hexs.decode() if ch.isalpha()]
    return "upper" if letters and all(ch.isupper() for ch in letters) else "lower" if letters else "none"


inp = fixtures / "mikey_gktp.pcapng"
manifest = fixtures / "canaries.json"
expect = json.loads((fixtures / "mikey_gktp.expect.json").read_text())
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    data = ["--data-dir", tmp / "data"]
    check(run(exe, *data, "project", "init", "k").returncode == 0, "project init")
    out = tmp / "out.pcapng"
    r = run(exe, *data, "anonymize", "--project", "k", inp, "-o", out)
    check(r.returncode == 0, f"publishes ({r.stderr.strip()[-300:]})")
    if r.returncode == 0:
        o = run(sys.executable, HERE / "mikey_consistency.py", inp, out, "--canaries", manifest, "--expect",
                expect["rewritten"])
        check(o.returncode == 0, f"mikey_consistency ({(o.stdout + o.stderr).strip()[-600:]})")
        for target, extra in ((out, []), (Path(str(out) + ".report.json"), ["--report"])):
            c = run(sys.executable, HERE / "canary_absent.py", manifest, target, "--source", inp.name, *extra)
            check(c.returncode == 0, f"no canary in {target.name} ({c.stdout.strip()[:300]})")
        ins = [g for g in gktps(inp) if mc.decode(bytes.fromhex(g[2].decode())) is not None]
        outs = gktps(out)
        check(len(gktps(inp)) == expect["rewritten"] + expect["fallback"], "fixture: GKTP count")
        check(len(outs) == expect["rewritten"] == len(ins), f"{expect['rewritten']} <GKTP> kept ({len(outs)})")
        for n, (i, o) in enumerate(zip(ins, outs)):
            w = f"GKTP {n + 1}"
            check(case(i[2]) == case(o[2]), f"{w}: letter case kept ({case(i[2])})")
            check((i[1], i[3]) == (o[1], o[3]), f"{w}: whitespace around the value kept")
            check(attr(i[0], b"id") != attr(o[0], b"id") and attr(o[0], b"id"), f"{w}: id pseudonymised")
            check(attr(i[0], b"activationtime") == attr(o[0], b"activationtime"), f"{w}: activationtime kept")
            dec = mc.decode(bytes.fromhex(o[2].decode()))
            check(dec is not None, f"{w}: decodes")
            if dec is None:
                continue
            idri = next((p["data"].decode() for k, p in dec["payloads"] if k == "IDR" and p["role"] == 1), "")
            check(idri.startswith("http://") and idri.endswith("/org.3gpp.MCPTT-GKTP/") and idri != expect["gms"],
                  f"{w}: IDRi is the pseudonymised GMS XCAP URI with the AUID kept ({idri})")
            root = None
            for m in messages(str(out)):
                for p in m.parts:
                    rm = re.search(rb'xcap-root="([^"]+)"', p.body)
                    root = root or (rm.group(1).decode() if rm else None)
            check(root is not None and idri.startswith(root.rstrip("/") + "/"),
                  f"{w}: the IDRi host is the xcap-root pseudonym ({root})")
        rep = json.loads(Path(str(out) + ".report.json").read_text())
        g = rep.get("mikey", {}).get("carriers", {}).get("gktp", {})
        check(g.get("rewritten") == expect["rewritten"], f"gktp rewritten {g}")
        check(sum(g.get("fallback", {}).values()) == expect["fallback"], f"gktp fallback {g.get('fallback')}")
        kp = rep.get("mikey", {}).get("payloads", {}).get("key-parameters", {})
        check(kp.get("rewritten") == expect["rewritten"], f"key parameters rewritten ({kp})")
        kid = rep.get("mikey", {}).get("key_ids", {})
        check(kid.get("GMK", 0) >= 4 and kid.get("MKFC", 0) >= 6, f"key ids {kid}")

if failures:
    print(f"{len(failures)} failure(s)")
    sys.exit(1)

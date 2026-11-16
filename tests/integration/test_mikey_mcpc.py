#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""US3 of feature 005: the MCPC PCK I_MESSAGE field (field 192), ciphertext mode.

usage: test_mikey_mcpc.py MCXANON FIXTURE_DIR

Anonymises mikey_mcpc.pcapng (pre-established session Connect messages whose field 192 carries a
PCK I_MESSAGE, binary and base64, and one whose I_MESSAGE does not parse) and checks US3 scenario 3:
the field holds the rewritten I_MESSAGE in its input form, the field length, padding and APP length
are valid (every APP packet tiles exactly), the IDRi equals the pseudonym of the originating party
field (004), no canary remains, and the unparsable field is zeroed (FR-020 d).
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import mikey_consistency as mc  # noqa: E402
from sip_messages import _frames, _l4  # noqa: E402

exe, fixtures = sys.argv[1], Path(sys.argv[2])
failures = []


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def run(*args):
    return subprocess.run([str(a) for a in args], capture_output=True, text=True)


def apps(path):
    """[(fields {id: [values]}, tiles exactly)] of every MCPC APP packet."""
    out = []
    for frame in _frames(open(path, "rb").read()):
        l4 = _l4(frame)
        if not l4 or l4[0] != 17:
            continue
        p = l4[6]
        i = 0
        while i + 12 <= len(p) and p[i] >> 6 == 2:
            ln = (int.from_bytes(p[i + 2:i + 4], "big") + 1) * 4
            if p[i + 1] == 204 and p[i + 8:i + 12] == b"MCPC":
                fields, j, end, ok = {}, i + 12, i + ln, i + ln <= len(p)
                while ok and j < end:
                    fid = p[j]
                    h = 3 if fid >= 192 else 2
                    fl = int.from_bytes(p[j + 1:j + 3], "big") if fid >= 192 else p[j + 1]
                    nxt = j + (h + fl + 3) // 4 * 4
                    if nxt > end:
                        ok = False
                        break
                    fields.setdefault(fid, []).append(p[j + h:j + h + fl])
                    ok = ok and all(x == 0 for x in p[j + h + fl:nxt])
                    j = nxt
                out.append((fields, ok and j == end))
            i += ln
    return out


inp = fixtures / "mikey_mcpc.pcapng"
manifest = fixtures / "canaries.json"
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    data = ["--data-dir", tmp / "data"]
    check(run(exe, *data, "project", "init", "k").returncode == 0, "project init")
    out = tmp / "out.pcapng"
    r = run(exe, *data, "anonymize", "--project", "k", inp, "-o", out)
    check(r.returncode == 0, f"publishes ({r.stderr.strip()[-300:]})")
    if r.returncode == 0:
        o = run(sys.executable, HERE / "mikey_consistency.py", inp, out, "--canaries", manifest, "--expect", 2)
        check(o.returncode == 0, f"mikey_consistency ({(o.stdout + o.stderr).strip()[-600:]})")
        for target, extra in ((out, []), (Path(str(out) + ".report.json"), ["--report"])):
            c = run(sys.executable, HERE / "canary_absent.py", manifest, target, "--source", inp.name, *extra)
            check(c.returncode == 0, f"no canary in {target.name} ({c.stdout.strip()[:300]})")
        ia, oa = apps(inp), apps(out)
        check(len(ia) == len(oa) == 3, f"three MCPC packets ({len(ia)}/{len(oa)})")
        for n, ((fi, _), (fo, tiles)) in enumerate(zip(ia, oa)):
            w = f"MCPC {n + 1}"
            check(tiles, f"{w}: fields, padding and APP length tile the packet")
            vi, vo = fi.get(192, [b""])[0], fo.get(192, [b""])[0]
            if n == 2:
                check(len(vo) == len(vi) and not any(vo), f"{w}: the unparsable field 192 is zeroed")
                continue
            b64 = n == 1
            dec = mc.decode((mc.b64(vo) or b"") if b64 else vo)
            check(dec is not None, f"{w}: field 192 decodes ({'base64' if b64 else 'binary'})")
            if dec is None:
                continue
            idri = next((p["data"] for k, p in dec["payloads"] if k == "IDR" and p["role"] == 1), None)
            check(idri == fo.get(5, [None])[0], f"{w}: IDRi equals the originating party pseudonym ({idri})")
        rep = json.loads(Path(str(out) + ".report.json").read_text())
        g = rep.get("mikey", {}).get("carriers", {}).get("mcpc", {})
        check(g.get("rewritten") == 2 and sum(g.get("fallback", {}).values()) == 1, f"mcpc carriers {g}")

if failures:
    print(f"{len(failures)} failure(s)")
    sys.exit(1)

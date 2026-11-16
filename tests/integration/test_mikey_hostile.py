#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""US6 of feature 005: hostile or unknown key management never leaks.

usage: test_mikey_hostile.py MCXANON FIXTURE_DIR

mikey_hostile.pcapng carries one a=key-mgmt per INVITE: other MIKEY data types, V = 1, payloads
outside MIKEY-SAKKE, an RSA signature, truncations, an overrunning length, undefined identity and
extension types, and text that is not base64 (mikey_hostile.expect.json). Every fallback must remove
the attribute and be counted with its reason, the zeroed parts must not survive, no canary may
remain, and the tool must neither crash nor refuse the capture.
"""
import collections
import json
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


inp = fixtures / "mikey_hostile.pcapng"
manifest = fixtures / "canaries.json"
expect = json.loads((fixtures / "mikey_hostile.expect.json").read_text())
reasons = collections.Counter(e for _n, e in expect if e != "rewritten")
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    data = ["--data-dir", tmp / "data"]
    check(run(exe, *data, "project", "init", "h").returncode == 0, "project init")
    # In passthrough (user story 5, scenario 4) the hostile messages fall back exactly as in
    # ciphertext mode; only the valid one is copied, and its canaries are scanner warnings.
    for mode in ("ciphertext", "passthrough"):
        out = tmp / f"{mode}.pcapng"
        r = run(exe, *data, "anonymize", "--project", "h", "--encrypted", mode, inp, "-o", out)
        check(r.returncode == 0, f"{mode}: publishes ({r.stderr.strip()[-300:]})")
        if r.returncode != 0:
            continue
        rep = json.loads(Path(str(out) + ".report.json").read_text())
        if mode == "ciphertext":
            c = run(sys.executable, HERE / "canary_absent.py", manifest, out, "--source", inp.name)
            check(c.returncode == 0, f"{mode}: no canary in the output ({c.stdout.strip()[:300]})")
        else:
            warnings = rep.get("scan", {}).get("warnings", [])
            check(warnings and all(w["carrier"] == "sdp" for w in warnings),
                  f"{mode}: the copied message's canaries are warnings ({len(warnings)})")
        sdp = rep.get("mikey", {}).get("carriers", {}).get("sdp", {})
        check(sdp.get("fallback", {}) == dict(reasons), f"{mode}: fallback reasons {sdp.get('fallback')} == {dict(reasons)}")
        kept = 1 if mode == "ciphertext" else 0
        check(sdp.get("rewritten", 0) == kept, f"{mode}: {kept} message rewritten with zeroed parts")
        check(sdp.get("passed_through", 0) == 1 - kept, f"{mode}: {1 - kept} message passed through")
        # Every fallback removed its attribute: only the rewritten message's attribute remains in
        # ciphertext mode, and in passthrough only that message (passed through) remains.
        attrs = sum(p.body.count(b"a=key-mgmt:") for m in messages(str(out)) for p in m.parts)
        check(attrs == 1, f"{mode}: one a=key-mgmt left ({attrs})")
        removed = rep["sip"]["sdp"].get("a=key-mgmt", {}).get("remove", 0)
        check(removed == sum(reasons.values()), f"{mode}: {removed} attributes removed")
        if mode == "ciphertext":
            msg = mc.decode(mc.carriers(str(out))[0][1])
            zeroed = [p for k, p in msg["payloads"] if (k == "IDR" and p["type"] == 2 and p["role"] == 1)
                      or (k == "EXT" and p["type"] == 0)]
            check(len(zeroed) == 2 and all(not any(p.get("data", b"")) for p in zeroed),
                  "undefined identity and extension data are zeroed")
            payloads = rep["mikey"]["payloads"]
            check(payloads.get("IDR", {}).get("unknown-identity") == 1, "unknown-identity counted")
            check(payloads.get("unknown-extension", {}).get("zeroed") == 1, "unknown extension counted")

if failures:
    print(f"{len(failures)} failure(s)")
    sys.exit(1)

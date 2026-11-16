#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""US3 of feature 005: the SRTP and SRTCP MKI (FR-012a, SC-008).

usage: test_mikey_srtp.py MCXANON FIXTURE_DIR

Anonymises mikey_srtp.pcapng (a group call with GMK-ID || GUK-ID MKIs, a private call with PCK-ID
MKIs on SRTP and SRTCP, one unknown MKI) and then, in the same project, mikey_srtp2.pcapng (no
I_MESSAGE, the PCK-ID known only from the mapping). Checks US3 scenario 5 and SC-008: every MKI
holds the pseudonyms that the CSB ID and SPI of the output I_MESSAGEs carry, everything else in the
trailer stays zeroed as in 004, the unknown MKI stays zero, and the report counts them.
"""
import base64
import json
import struct
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


def media(path):
    """[(dport, payload)] of the UDP datagrams that are not SIP."""
    out = []
    for frame in _frames(open(path, "rb").read()):
        l4 = _l4(frame)
        if l4 and l4[0] == 17 and 5060 not in (l4[3], l4[4]):
            out.append((l4[4], l4[6]))
    return out


def output_keys(path):
    """The key identifiers of the output I_MESSAGEs: CSB IDs and SPI words."""
    keys = set()
    for _, m in mc.carriers(str(path)):
        d = mc.decode(m)
        if d is None:
            continue
        keys.add(d["csb"])
        for b in d["blocks"]:
            keys.update(struct.unpack("!%dI" % (len(b["spi"]) // 4), b["spi"]))
    return keys


expect = json.loads((fixtures / "mikey_srtp.expect.json").read_text())
manifest = fixtures / "canaries.json"
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    data = ["--data-dir", tmp / "data"]
    check(run(exe, *data, "project", "init", "k").returncode == 0, "project init")
    out = tmp / "out.pcapng"
    inp = fixtures / "mikey_srtp.pcapng"
    r = run(exe, *data, "anonymize", "--project", "k", inp, "-o", out)
    check(r.returncode == 0, f"publishes ({r.stderr.strip()[-300:]})")
    if r.returncode == 0:
        c = run(sys.executable, HERE / "canary_absent.py", manifest, out, "--source", inp.name)
        check(c.returncode == 0, f"no canary in the output ({c.stdout.strip()[:300]})")
        keys = output_keys(out)
        check(len(keys) == 3, f"three key identifiers in the output I_MESSAGEs ({len(keys)})")
        ins, outs = media(inp), media(out)
        check(len(ins) == len(outs) == 7, f"seven media datagrams ({len(ins)}/{len(outs)})")
        for n, ((_, i), (_, o)) in enumerate(zip(ins, outs)):
            w = f"datagram {n + 1}"
            check(len(i) == len(o), f"{w}: same length")
            rtcp = o[1] == 200
            if n < 3:  # group: GMK-ID || GUK-ID, 4-octet tag
                mki = o[-12:-4]
                words = struct.unpack("!II", mki)
                check(words[0] in keys and words[1] in keys and words[0] >> 28 == 0 and words[1] >> 28 == 0,
                      f"{w}: MKI is the GMK-ID || GUK-ID pseudonyms of the I_MESSAGE")
                check(not any(o[12:-12]) and not any(o[-4:]), f"{w}: the rest of the trailer is zeroed")
            elif n < 6:
                word = struct.unpack("!I", o[-4:])[0]
                check(word in keys and word >> 28 == 1, f"{w}: MKI is the PCK-ID pseudonym ({'SRTCP' if rtcp else 'SRTP'})")
                start = 8 if rtcp else 12
                check(not any(o[start:-4]), f"{w}: the rest is zeroed")
            else:
                check(not any(o[12:]), f"{w}: an unknown MKI stays zeroed")
        rep = json.loads(Path(str(out) + ".report.json").read_text())
        mki = rep.get("mikey", {}).get("mki", {})
        check(mki.get("pseudonymised") == expect["pseudonymised"] and mki.get("unmatched") == expect["unmatched"],
              f"report mki {mki}")
        # Clarification 3: a later capture without I_MESSAGE, same project.
        inp2, out2 = fixtures / "mikey_srtp2.pcapng", tmp / "out2.pcapng"
        r = run(exe, *data, "anonymize", "--project", "k", inp2, "-o", out2)
        check(r.returncode == 0, f"second capture publishes ({r.stderr.strip()[-300:]})")
        if r.returncode == 0:
            pck = [k for k in keys if k >> 28 == 1]
            for n, (_, o) in enumerate(media(out2)):
                check(struct.unpack("!I", o[-4:])[0] in pck, f"second capture, datagram {n + 1}: the PCK-ID pseudonym")
            rep2 = json.loads(Path(str(out2) + ".report.json").read_text())
            check(rep2.get("mikey", {}).get("mki", {}).get("pseudonymised") == 2, "second capture: 2 MKIs from the mapping")
            c = run(sys.executable, HERE / "canary_absent.py", manifest, out2, "--source", inp2.name)
            check(c.returncode == 0, f"no canary in the second output ({c.stdout.strip()[:300]})")

if failures:
    print(f"{len(failures)} failure(s)")
    sys.exit(1)

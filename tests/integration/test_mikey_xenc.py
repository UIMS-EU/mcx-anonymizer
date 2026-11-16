#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""US4 of feature 005: encrypted XML content and encrypted URIs, ciphertext mode.

usage: test_mikey_xenc.py MCXANON FIXTURE_DIR

Anonymises mikey_xenc.pcapng and checks US4 scenarios 1-4 and SC-008: EncryptedData keeps Type,
EncryptionMethod, KeyInfo/KeyName and CipherValue (byte-identical); the part outside the allowlist
is removed and counted; the signature of the signed body keeps its structure, loses its values and
names the key by the same pseudonym; the XPK-ID in KeyName, the CSB ID of the CSK upload and the
key-id of the encrypted URI carry one key identifier pseudonym; no canary remains.
"""
import base64
import json
import re
import struct
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


def bodies(path, ct):
    return [p.body.decode("utf-8", "replace") for m in messages(str(path)) for p in m.parts if p.content_type == ct]


inp = fixtures / "mikey_xenc.pcapng"
manifest = fixtures / "canaries.json"
expect = json.loads((fixtures / "mikey_xenc.expect.json").read_text())
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    data = ["--data-dir", tmp / "data"]
    check(run(exe, *data, "project", "init", "k").returncode == 0, "project init")
    out = tmp / "out.pcapng"
    r = run(exe, *data, "anonymize", "--project", "k", inp, "-o", out)
    check(r.returncode == 0, f"publishes ({r.stderr.strip()[-300:]})")
    if r.returncode == 0:
        for target, extra in ((out, []), (Path(str(out) + ".report.json"), ["--report"])):
            c = run(sys.executable, HERE / "canary_absent.py", manifest, target, "--source", inp.name, *extra)
            check(c.returncode == 0, f"no canary in {target.name} ({c.stdout.strip()[:300]})")
        o = run(sys.executable, HERE / "mikey_consistency.py", inp, out, "--canaries", manifest, "--expect", 1)
        check(o.returncode == 0, f"mikey_consistency ({(o.stdout + o.stderr).strip()[-400:]})")
        # The key identifier pseudonym of the CSK-ID in the output I_MESSAGE.
        dec = mc.decode(mc.carriers(str(out))[0][1])
        csk = dec["csb"] if dec else None
        check(csk is not None and csk >> 28 == 2 and csk != expect["csk"], "the CSK-ID is pseudonymised, tag kept")
        b64k = base64.b64encode(struct.pack("!I", csk or 0)).decode()
        info = bodies(out, "application/vnd.3gpp.mcptt-info+xml")
        check(len(info) == 1, "the MCPTT information body is kept")
        info = info[0] if info else ""
        # Scenario 1: the structure, the allowlisted values and the cipher values.
        check(info.count("<xenc:EncryptedData") == 2, "both EncryptedData elements kept")
        check(info.count('Type="http://www.w3.org/2001/04/xmlenc#Content"') == 2, "Type kept")
        check(info.count('Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"') == 2, "Algorithm kept")
        for cv in expect["cipher"]:
            check(f"<xenc:CipherValue>{cv}</xenc:CipherValue>" in info, "CipherValue byte-identical")
        # Scenario 2 and SC-008: KeyName, CSB ID and URI key-id share one pseudonym.
        names = re.findall(r"<ds:KeyName>([^<]*)</ds:KeyName>", info)
        check(names == [b64k, b64k], f"KeyName is the CSK-ID pseudonym ({names} / {b64k})")
        # Scenario 3: the part outside the allowlist is removed.
        check("EncryptionProperties" not in info, "the unknown element is removed")
        # Scenario 4: the signed body keeps its structure; its KeyName names the same key.
        sig = bodies(out, "application/vnd.3gpp.mcptt-signed+xml")
        sig = sig[0] if sig else ""
        check("<ds:SignatureValue></ds:SignatureValue>" in sig, "the signature value is emptied (003 FR-018a)")
        check(f"<ds:KeyName>{b64k}</ds:KeyName>" in sig, "the signature's KeyName is the CSK-ID pseudonym (P2)")
        pidf = bodies(out, "application/pidf+xml")
        m = re.search(r'entity="sip:([^;"]+);iv=([^;"]+);key-id=([^;"]+);alg=128-aes-gcm@', pidf[0] if pidf else "")
        check(m is not None, "the encrypted URI keeps its structure")
        if m:
            kid = base64.urlsafe_b64decode(m.group(3) + "=" * (-len(m.group(3)) % 4))
            check(kid == struct.pack("!I", csk), "the URI key-id is the CSK-ID pseudonym (URL-safe alphabet kept)")
            check(len(base64.urlsafe_b64decode(m.group(2) + "=" * (-len(m.group(2)) % 4))) == 12, "the IV keeps 96 bits")
        rep = json.loads(Path(str(out) + ".report.json").read_text())
        mk = rep.get("mikey", {})
        check(mk.get("encrypted_xml", {}).get("kept") == 2, f"encrypted_xml {mk.get('encrypted_xml')}")
        check(mk.get("encrypted_xml", {}).get("removed_parts", 0) >= 1, "removed parts counted")
        check(mk.get("encrypted_uri", {}).get("structured") == 1, f"encrypted_uri {mk.get('encrypted_uri')}")

if failures:
    print(f"{len(failures)} failure(s)")
    sys.exit(1)

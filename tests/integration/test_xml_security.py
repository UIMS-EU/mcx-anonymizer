#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""FR-018 and FR-018a: encrypted and signed content.

xml_mcptt_us4.pcapng holds an INVITE with SDP, mcptt-info and an mcptt-signed body that signs
both parts by Content-ID. In --payload zero and drop:
  - the xmldsig structure and the Algorithm attributes are kept;
  - each Reference@URI equals "cid:" + the pseudonymised Content-ID of a part of the same message;
  - SignatureValue and DigestValue are present and empty; KeyName and the key material are absent;
xml_mcptt_info.pcapng (every encryptable element encrypted): every xenc subtree is kept by the
feature 005 xenc rules and counted (FR-016 amends FR-018).

Usage: test_xml_security.py MCXANON FIXTURE_DIR
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


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def run(*args):
    return subprocess.run([str(a) for a in args], capture_output=True, text=True)


with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    data = ["--data-dir", tmp / "data"]
    run(exe, *data, "project", "init", "s")
    for pm in ("zero", "drop"):
        out = tmp / f"{pm}.pcapng"
        r = run(exe, *data, "anonymize", "--project", "s", "--payload", pm, fixtures / "xml_mcptt_us4.pcapng", "-o", out)
        check(r.returncode == 0, f"{pm}: publishes ({r.stderr.strip()[-300:]})")
        if r.returncode != 0:
            continue
        inv = next((m for m in messages(str(out)) if m.start.startswith("INVITE ")), None)
        check(inv is not None, f"{pm}: the signed INVITE is there")
        if inv is None:
            continue
        cids = {header(p.headers, "content-id").strip("<>") for p in inv.parts if header(p.headers, "content-id")}
        signed = next((p.body.decode() for p in inv.parts if p.content_type == "application/vnd.3gpp.mcptt-signed+xml"), "")
        refs = re.findall(r'<ds:Reference URI="cid:([^"]+)"', signed)
        check(len(refs) == 2 and set(refs) == cids, f"{pm}: Reference@URI names the pseudonymised Content-IDs ({refs} vs {cids})")
        for alg in ("REC-xml-c14n-20010315", "xmldsig-more#hmac-sha256", "xmlenc#sha256"):
            check(alg in signed, f"{pm}: Algorithm {alg} kept")
        check(re.search(r"<ds:SignatureValue>\s*</ds:SignatureValue>", signed) is not None,
              f"{pm}: SignatureValue present and empty")
        check(len(re.findall(r"<ds:DigestValue>\s*</ds:DigestValue>", signed)) == 2, f"{pm}: DigestValue present and empty")
        for gone in ("KeyName", "KeyValue", "X509Data", "PGPData", "SPKIData", "MgmtData", "Object", "Transforms",
                     "RetrievalMethod", "HMACOutputLength"):
            check(f"<ds:{gone}" not in signed, f"{pm}: {gone} removed")
        check("<ds:KeyInfo" in signed and "<ds:SignedInfo>" in signed, f"{pm}: KeyInfo and SignedInfo kept")
        r = run(exe, *data, "anonymize", "--project", "s", "--payload", pm, fixtures / "xml_mcptt_info.pcapng",
                "-o", tmp / f"{pm}-enc.pcapng")
        rep = json.loads(Path(str(tmp / f"{pm}-enc.pcapng") + ".report.json").read_text())
        # Feature 005 (FR-016): every EncryptedData is kept by the xenc rules and counted.
        check(rep.get("mikey", {}).get("encrypted_xml", {}).get("kept") == 23, f"{pm}: every encrypted subtree counted")
sys.exit(1 if failures else 0)

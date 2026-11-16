#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""User Story 2 (and, from User Story 5 on, the reginfo, conference and xcap-diff part): the IETF
and presence documents keep their structure with consistent pseudonyms.

Runs xml_ietf_us2.pcapng (resource-lists in INVITE and MESSAGE; pidf PUBLISH for MCPTT, MCData
and MCVideo, one with a vendor element; the affiliation command of the three services) in
--payload zero and drop and checks:
  - the structure and consistency oracles; no canary in the output or the report;
  - scenario 1: the resource-lists entries keep their order and count;
  - scenario 3: affiliation statuses and expiry values kept, identities pseudonymised;
  - scenario 4: the vendor element removed and counted by namespace.

Usage: test_xml_ietf.py MCXANON FIXTURE_DIR
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
failures = []


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def run(*args):
    return subprocess.run([str(a) for a in args], capture_output=True, text=True)


manifest = fixtures / "canaries.json"
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    data = ["--data-dir", tmp / "data"]
    run(exe, *data, "project", "init", "i")
    inp = fixtures / "xml_ietf_us2.pcapng"
    for pm in ("zero", "drop"):
        out = tmp / f"{pm}.pcapng"
        r = run(exe, *data, "anonymize", "--project", "i", "--payload", pm, inp, "-o", out)
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
        b = x["bodies"]
        check(b.get("application/resource-lists+xml") == {"rewritten": 2}, f"{pm}: resource-lists rewritten ({b})")
        check(b.get("application/pidf+xml") == {"rewritten": 3}, f"{pm}: pidf rewritten")
        for svc in ("mcptt", "mcdata", "mcvideo"):
            t = f"application/vnd.3gpp.{svc}-affiliation-command+xml"
            check(b.get(t) == {"rewritten": 1}, f"{pm}: {svc} affiliation command rewritten ({b.get(t)})")
        check(x["removed"]["namespaces"].get("urn:example:vendor:ext") == 1 or
              x["removed"]["namespaces"].get("(invalid-name)", 0) >= 1,
              f"{pm}: scenario 4, the vendor element is removed and counted ({x['removed']['namespaces']})")
        unknown = [k for k, v in x["elements"].items() if "unknown" in v]
        check(not unknown, f"{pm}: no element of a known namespace is unknown ({unknown})")
        msgs = messages(str(out))
        rl = [p.body for m in msgs for p in m.parts if p.content_type == "application/resource-lists+xml"]
        ins = [p.body for m in messages(str(inp)) for p in m.parts if p.content_type == "application/resource-lists+xml"]
        entries = re.compile(rb"<entry[\s/>]")
        check(rl and all(len(entries.findall(o)) == len(entries.findall(i)) for o, i in zip(rl, ins)),
              f"{pm}: scenario 1, every entry kept in order")
        pidf = b"".join(p.body for m in msgs for p in m.parts if p.content_type == "application/pidf+xml")
        check(pidf.count(b'status="affiliated"') == 3 and pidf.count(b'expires="2026-11-14T12:00:00Z"') >= 9,
              f"{pm}: scenario 3, statuses and expiry values kept")
        check(re.search(rb'client="urn:uuid:[0-9a-f-]{36}"', pidf) is not None, f"{pm}: client IDs stay UUID URNs")
    # User Story 5: reg, conference and xcap-diff NOTIFYs and poc-settings.
    inp = fixtures / "xml_ietf_us5.pcapng"
    for pm in ("zero", "drop"):
        out = tmp / f"{pm}-us5.pcapng"
        r = run(exe, *data, "anonymize", "--project", "i", "--payload", pm, inp, "-o", out)
        check(r.returncode == 0, f"us5 {pm}: publishes ({r.stderr.strip()[-300:]})")
        if r.returncode != 0:
            continue
        for oracle in ("xml_structure.py", "xml_consistency.py"):
            args = [inp, out] + ([manifest] if oracle == "xml_structure.py" else [])
            o = run(sys.executable, HERE / oracle, *args)
            check(o.returncode == 0, f"us5 {pm}: {oracle} ({(o.stdout + o.stderr).strip()[-400:]})")
        c = run(sys.executable, HERE / "canary_absent.py", manifest, out, "--source", inp.name)
        check(c.returncode == 0, f"us5 {pm}: no canary in the output ({c.stdout.strip()[:300]})")
        rep = json.loads(Path(str(out) + ".report.json").read_text())
        b = rep["xml"]["bodies"]
        for t, n in (("application/reginfo+xml", 1), ("application/conference-info+xml", 1),
                     ("application/xcap-diff+xml", 1), ("application/poc-settings+xml", 2)):
            check(b.get(t) == {"rewritten": n}, f"us5 {pm}: {t} rewritten ({b.get(t)})")
        ns = rep["xml"]["removed"]["namespaces"]
        check(sum(ns.values()) >= 3, f"us5 {pm}: the extRegExp and vendor namespaces removed and counted ({ns})")
        msgs = messages(str(out))
        body = lambda ct: b"".join(p.body for m in msgs for p in m.parts if p.content_type == ct)  # noqa: E731
        reg = body("application/reginfo+xml")
        check(b'state="active"' in reg and b'event="registered"' in reg and b'version="3"' in reg,
              f"us5 {pm}: scenario 1, reg states, events and versions kept")
        conf = body("application/conference-info+xml")
        check(b"<status>connected</status>" in conf and b'version="4"' in conf, f"us5 {pm}: conference states kept")
        xd = body("application/xcap-diff+xml").decode()
        new = re.search(r'new-etag="([^"]+)"', xd).group(1)
        old = re.search(r'previous-etag="([^"]+)"', xd).group(1)
        from sip_messages import header
        ifm = [header(m.headers, "sip-if-match") for m in msgs if header(m.headers, "sip-if-match")]
        etg = [header(m.headers, "sip-etag") for m in msgs if header(m.headers, "sip-etag")]
        check(ifm == [old] and etg == [new], f"us5 {pm}: scenario 2, one entity-tag pseudonym in xcap-diff and SIP "
                                            f"({old}/{new} vs {ifm}/{etg})")
sys.exit(1 if failures else 0)

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""User Story 4: MCData, MCVideo and the remaining MCPTT documents.

For xml_mcptt_us4.pcapng (floor request, MBMS and MBS usage, regroup x3, a signed INVITE),
xml_mcdata.pcapng and xml_mcvideo.pcapng in --payload zero and drop:
  - every XML body of these files is rewritten (none emptied), no element of a known namespace is
    unknown; structure and consistency oracles; no canary in the output or the report;
  - scenario 1: the MCData SDS MESSAGE keeps its mcdata-signalling part as 002 leaves it;
  - scenario 2: no TMGI survives, the TMGI element stays (X11), the announcement structure is kept.

Usage: test_xml_mcx.py MCXANON FIXTURE_DIR
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
FILES = ["xml_mcptt_us4.pcapng", "xml_mcdata.pcapng", "xml_mcvideo.pcapng"]


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
    run(exe, *data, "project", "init", "x")
    for name in FILES:
        inp = fixtures / name
        check(inp.exists(), f"{name} present")
        if not inp.exists():
            continue
        for pm in ("zero", "drop"):
            out = tmp / f"{pm}-{name}"
            r = run(exe, *data, "anonymize", "--project", "x", "--payload", pm, inp, "-o", out)
            check(r.returncode == 0, f"{name} ({pm}): publishes ({r.stderr.strip()[-300:]})")
            if r.returncode != 0:
                continue
            rep = json.loads(Path(str(out) + ".report.json").read_text())
            for oracle in ("xml_structure.py", "xml_consistency.py"):
                args = [inp, out] + ([manifest] if oracle == "xml_structure.py" else [])
                o = run(sys.executable, HERE / oracle, *args)
                check(o.returncode == 0, f"{name} ({pm}): {oracle} ({(o.stdout + o.stderr).strip()[-400:]})")
            c = run(sys.executable, HERE / "canary_absent.py", manifest, out, "--source", name)
            check(c.returncode == 0, f"{name} ({pm}): no canary in the output ({c.stdout.strip()[:300]})")
            c = run(sys.executable, HERE / "canary_absent.py", manifest, Path(str(out) + ".report.json"),
                    "--source", name, "--report")
            check(c.returncode == 0, f"{name} ({pm}): no canary in the report ({c.stdout.strip()[:300]})")
            x = rep["xml"]
            emptied = {t: o for t, o in x["bodies"].items() if set(o) != {"rewritten"}}
            check(not emptied, f"{name} ({pm}): every XML body rewritten ({emptied})")
            # The odd-shape MCVideo body puts contentType children under parents §F.1.3 does not
            # allow (D6): those are unknown on purpose.
            odd = {f"urn:3gpp:ns:mcvideoInfo:1.0 mcvideo{n}" for n in ("Boolean", "String", "URI")}
            unknown = [k for k, v in x["elements"].items() if "unknown" in v and k.startswith("urn:3gpp:") and k not in odd]
            check(not unknown, f"{name} ({pm}): no element of a known namespace is unknown ({unknown[:5]})")
            ins, outs = messages(str(inp)), messages(str(out))
            if name == "xml_mcdata.pcapng":
                sig_in = [p.body for m in ins for p in m.parts if p.content_type == "application/vnd.3gpp.mcdata-signalling"]
                sig_out = [p.body for m in outs for p in m.parts if p.content_type == "application/vnd.3gpp.mcdata-signalling"]
                check(len(sig_in) == len(sig_out) >= 1, f"{name} ({pm}): scenario 1, the mcdata-signalling part stays")
            if name == "xml_mcptt_us4.pcapng":
                mbms = [p.body for m in outs for p in m.parts if p.content_type.endswith("mbms-usage-info+xml")]
                check(mbms and all(re.search(rb"<TMGI>[^<]+</TMGI>", b) is None and b.count(b"<TMGI></TMGI>") >= 2
                                   and b"<announcement>" in b for b in mbms),
                      f"{name} ({pm}): scenario 2, TMGI emptied, announcement kept")
sys.exit(1 if failures else 0)

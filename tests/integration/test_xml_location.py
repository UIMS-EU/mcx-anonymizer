#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""User Story 3 (FR-016, FR-018, SC-003): location reporting without positions.

xml_location.pcapng: configuration, request, plain and encrypted report for the MCPTT, MCData
and MCVideo namespaces, and the alias Content-Type. xml_location_fc.pcapng: one ECGI in a floor
control Location field (004) and in an XML location report. In --payload zero and drop:
  - oracles (structure, consistency) and no canary in output or report;
  - scenario 1: triggers keep their kind, interval, distance and TriggerId;
  - scenario 2: every coordinate value is 0 with its type attribute kept; ECGIs keep 34 characters
    of the same classes; encrypted coordinates have no fixed value (xenc removed, counted);
  - SC-003: the ECGI pseudonym equals the floor control Location field's.

Usage: test_xml_location.py MCXANON FIXTURE_DIR
"""
import json
import re
import struct
import subprocess
import sys
import tempfile
import xml.parsers.expat as expat
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from sip_messages import messages, _frames, _l4  # noqa: E402

exe, fixtures = sys.argv[1], Path(sys.argv[2])
failures = []
CTS = {"application/vnd.3gpp.mcptt-location-info+xml", "application/vnd.3gpp.mcdata-location-info+xml",
       "application/vnd.3gpp.mcvideo-location-info+xml", "application/vnd.3gpp.location-info+xml"}


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def run(*args):
    return subprocess.run([str(a) for a in args], capture_output=True, text=True)


def elements(body):
    """[(local, attrs, text)] in document order."""
    out, stack = [], []
    p = expat.ParserCreate(namespace_separator=" ")
    p.StartElementHandler = lambda n, a: (stack.append(len(out)), out.append([n.split(" ")[-1], a, ""]))
    p.EndElementHandler = lambda n: stack.pop()
    p.CharacterDataHandler = lambda t: out[stack[-1]].__setitem__(2, out[stack[-1]][2] + t) if stack else None
    p.Parse(body, True)
    return [(a, b, c.strip()) for a, b, c in out]


def fc_ecis(path):
    """ECIs of the type-1 Location fields (field ID 19) of every MCPT APP packet."""
    ecis = []
    for frame in _frames(open(path, "rb").read()):
        l4 = _l4(frame)
        if not l4 or l4[0] != 17 or l4[6][8:12] != b"MCPT":
            continue
        p = l4[6]
        i = 12
        while i + 2 <= len(p):
            fid, ln = p[i], p[i + 1]
            if fid == 19 and ln >= 8 and p[i + 2] == 1:
                ecis.append(struct.unpack("!I", p[i + 6:i + 10])[0] & 0x0FFFFFFF)
            i += (2 + ln + 3) // 4 * 4
    return ecis


manifest = fixtures / "canaries.json"
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    data = ["--data-dir", tmp / "data"]
    run(exe, *data, "project", "init", "l")
    for pm in ("zero", "drop"):
        for name in ("xml_location.pcapng", "xml_location_fc.pcapng"):
            inp = fixtures / name
            out = tmp / f"{pm}-{name}"
            r = run(exe, *data, "anonymize", "--project", "l", "--payload", pm, inp, "-o", out)
            check(r.returncode == 0, f"{name} ({pm}): publishes ({r.stderr.strip()[-300:]})")
            if r.returncode != 0:
                continue
            for oracle in ("xml_structure.py", "xml_consistency.py"):
                args = [inp, out] + ([manifest] if oracle == "xml_structure.py" else [])
                o = run(sys.executable, HERE / oracle, *args)
                check(o.returncode == 0, f"{name} ({pm}): {oracle} ({(o.stdout + o.stderr).strip()[-400:]})")
            c = run(sys.executable, HERE / "canary_absent.py", manifest, out, "--source", inp.name)
            check(c.returncode == 0, f"{name} ({pm}): no canary in the output ({c.stdout.strip()[:300]})")
            c = run(sys.executable, HERE / "canary_absent.py", manifest, Path(str(out) + ".report.json"),
                    "--source", inp.name, "--report")
            check(c.returncode == 0, f"{name} ({pm}): no canary in the report ({c.stdout.strip()[:300]})")
            rep = json.loads(Path(str(out) + ".report.json").read_text())
            x = rep["xml"]
            unknown = [k for k, v in x["elements"].items() if "unknown" in v]
            check(not unknown, f"{name} ({pm}): no location element is unknown ({unknown})")
            ins = [p.body for m in messages(str(inp)) for p in m.parts if p.content_type in CTS]
            outs = [p.body for m in messages(str(out)) for p in m.parts if p.content_type in CTS]
            check(len(ins) == len(outs) and all(outs), f"{name} ({pm}): every location body rewritten")
            for i, (a, b) in enumerate(zip(ins, outs)):
                ea, eb = elements(a), elements(b)
                numeric = ("PeriodicReport", "TravelledDistance", "MinPeriod", "PersistencePeriod")
                trig_a = [(n, at.get("TriggerId"), t if n in numeric else "") for n, at, t in ea if "TriggerId" in at]
                trig_b = [(n, at.get("TriggerId"), t if n in numeric else "") for n, at, t in eb if "TriggerId" in at]
                check(trig_a == trig_b, f"{name} ({pm}) body {i}: scenario 1, triggers kept")
                coords = [(n, t) for n, _, t in eb if n in ("threebytes", "twobytes", "onebyteunsignedhalfrange")]
                check(all(t == "0" for _, t in coords), f"{name} ({pm}) body {i}: scenario 2, coordinates are 0 ({coords[:3]})")
                types_a = [(n, at.get("type")) for n, at, _ in ea if "type" in at]
                types_b = [(n, at.get("type")) for n, at, _ in eb if "type" in at]
                check(types_a == types_b, f"{name} ({pm}) body {i}: type attributes kept")
                for (n, _, t) in eb:
                    if n == "Ecgi":
                        check(re.fullmatch(r"\d{6}[01]{28}", t) is not None, f"{name} ({pm}) body {i}: ECGI form kept ({t})")
                enc = [n for n, at, _ in eb if at.get("type") == "Encrypted"]
                for n in enc:
                    check(not any(m in ("threebytes", "twobytes", "onebyteunsignedhalfrange", "Ecgi") for m, _, _ in
                                  elements(b)[[k for k, (m, at, _) in enumerate(eb) if m == n][0] + 1:][:1]),
                          f"{name} ({pm}) body {i}: encrypted {n} has no fixed value")
            if name == "xml_location_fc.pcapng":
                ecgi = [t for n, _, t in elements(outs[0]) if n == "Ecgi"][0]
                xml_eci = int(ecgi[6:], 2)
                check(fc_ecis(str(out)) == [xml_eci], f"{pm}: SC-003, the ECGI matches the floor control Location field "
                                                     f"({fc_ecis(str(out))} vs {xml_eci})")
                check(x["bodies"].get("application/vnd.3gpp.mcptt-location-info+xml") == {"rewritten": 1},
                      f"{pm}: the location report is rewritten")
            else:
                # Feature 005 (FR-016): the encrypted values are kept as ciphertext and counted.
                check(rep.get("mikey", {}).get("encrypted_xml", {}).get("kept", 0) > 0,
                      f"{pm}: encrypted location values kept as ciphertext and counted")
sys.exit(1 if failures else 0)

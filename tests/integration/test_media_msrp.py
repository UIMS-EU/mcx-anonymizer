#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""User Story 5 (FR-026 to FR-029): every msrp_* fixture is anonymised in both payload modes; no
canary survives (paths, transaction and message ids, content, comments, removed headers); the
independent scan is clean; the report counts MSRP requests, responses and headers. With tshark:
every MSRP message of the input decodes in the output with the same method or status and the
same Byte-Range; To-Path and From-Path are the a=path pseudonyms of the output SDP; a REPORT
carries the Message-ID of its SEND; there are no new error-level expert entries; MSRP over TLS
stays zeroed.

Usage: test_media_msrp.py MCXANON FIXTURE_DIR
"""
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CANARY = REPO / "tests" / "integration" / "canary_absent.py"
DIFF = REPO / "tools" / "tshark-expert-diff.py"
exe, fixtures = sys.argv[1], Path(sys.argv[2])
failures = []
FIELDS = ["msrp.method", "msrp.status.code", "msrp.byte.range", "msrp.to.path", "msrp.from.path",
          "msrp.messageid", "msrp.transaction.id"]


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def run(*args):
    return subprocess.run([str(a) for a in args], capture_output=True, text=True)


def rows(path, names, flt):
    r = run("tshark", "-r", path, "-Y", flt, "-T", "fields", "-E", "occurrence=a", "-E", "aggregator=|",
            *[x for n in ["frame.number"] + names for x in ("-e", n)])
    return {c.split("\t")[0]: c.split("\t")[1:] for c in r.stdout.splitlines()}


inputs = sorted(fixtures.glob("msrp_*.pcapng"))
check(len(inputs) >= 6, f"MSRP fixtures present ({len(inputs)})")
tshark = shutil.which("tshark") is not None
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    data = ["--data-dir", tmp / "data"]
    check(run(exe, *data, "project", "init", "s").returncode == 0, "project init")
    for inp in inputs:
        for mode in ("zero", "drop"):
            out = tmp / f"{mode}-{inp.name}"
            r = run(exe, *data, "anonymize", "--project", "s", "--payload", mode, inp, "-o", out)
            check(r.returncode == 0, f"{inp.name} ({mode}) publishes ({r.stderr.strip()[-200:]})")
            if r.returncode != 0:
                continue
            c = run(sys.executable, CANARY, fixtures / "canaries.json", out, "--source", inp.name)
            check(c.returncode == 0, f"{inp.name} ({mode}) no canary survives ({c.stdout.strip()[:300]})")
            s = run(exe, *data, "scan", "--project", "s", out)
            check(s.returncode == 0, f"{inp.name} ({mode}) the independent scan is clean ({s.stdout.strip()[-200:]})")
            msrp = json.loads(Path(str(out) + ".report.json").read_text())["media"]["msrp"]
            if inp.name == "msrp_sds.pcapng":
                check(msrp["requests"].get("SEND", 0) == 2 and msrp["requests"].get("REPORT", 0) == 1,
                      f"{inp.name} ({mode}) SEND and REPORT counted ({msrp['requests']})")
                check(msrp["responses"].get("2xx", 0) == 1, f"{inp.name} ({mode}) the 200 response counted")
                check(msrp["headers"].get("other", {}).get("remove", 0) >= 1, f"{inp.name} ({mode}) unknown header removed")
            if inp.name == "msrp_malformed.pcapng":
                check(msrp["zeroed"].get("method", 0) == 1 and msrp["zeroed"].get("malformed", 0) == 1,
                      f"{inp.name} ({mode}) AUTH and the malformed SEND zeroed ({msrp['zeroed']})")
            if not tshark:
                continue
            a, b = rows(inp, FIELDS, "msrp"), rows(out, FIELDS, "msrp")
            if inp.name in ("msrp_tls.pcapng", "msrp_malformed.pcapng"):
                check(not b, f"{inp.name} ({mode}) nothing decodes as MSRP in the output")
                continue
            check(a.keys() == b.keys(), f"{inp.name} ({mode}) the same frames carry MSRP ({sorted(a)} / {sorted(b)})")
            check(all(a[k][:3] == b[k][:3] for k in a if k in b),
                  f"{inp.name} ({mode}) method, status and Byte-Range unchanged")
            sdp = rows(out, ["sdp.media_attr"], "sdp")
            paths = {x.split("path:")[1] for v in sdp.values() for x in v[0].split("|") if x.startswith("path:")}
            used = {p for v in b.values() for col in (v[3], v[4]) for p in col.split("|") if p}
            check(used and used <= paths, f"{inp.name} ({mode}) To-Path and From-Path are the a=path pseudonyms")
            if inp.name == "msrp_sds.pcapng":
                ids = {v[0]: v[5] for v in b.values() if v[0] in ("SEND", "REPORT") and v[5]}
                check(ids.get("SEND") == ids.get("REPORT"), f"{inp.name} ({mode}) the REPORT carries its SEND's Message-ID")
            d = run(sys.executable, DIFF, inp, out, "--payload", mode, "--media")
            check(d.returncode == 0, f"{inp.name} ({mode}) no new expert errors ({d.stdout.strip()[-300:]})")
    if not tshark:
        print("tshark not installed: MSRP structure and expert checks skipped")
sys.exit(1 if failures else 0)

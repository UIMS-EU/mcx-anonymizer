#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""User Stories 1 and 4 (SC-001 to SC-004): every app_* fixture is anonymised in both payload
modes; no canary survives; the independent scan is clean; the report counts the APP messages,
fields and unknown items. With tshark: the floor and transmission control ladder is unchanged
(floor_ladder.py), identities are consistent (media_consistency.py) and there are no new
error-level expert entries.

Usage: test_media_app.py MCXANON FIXTURE_DIR [-k SUBSTRING]
"""
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CANARY = REPO / "tests" / "integration" / "canary_absent.py"
LADDER = REPO / "tests" / "integration" / "floor_ladder.py"
CONSISTENCY = REPO / "tests" / "integration" / "media_consistency.py"
DIFF = REPO / "tools" / "tshark-expert-diff.py"
exe, fixtures = sys.argv[1], Path(sys.argv[2])
only = sys.argv[sys.argv.index("-k") + 1] if "-k" in sys.argv else ""
failures = []


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def run(*args):
    return subprocess.run([str(a) for a in args], capture_output=True, text=True)


inputs = [p for p in sorted(fixtures.glob("app_*.pcapng")) if only in p.name]
check(len(inputs) >= 1, f"APP fixtures present ({len(inputs)})")
tshark = shutil.which("tshark") is not None
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    data = ["--data-dir", tmp / "data"]
    check(run(exe, *data, "project", "init", "a").returncode == 0, "project init")
    for inp in inputs:
        for mode in ("zero", "drop"):
            out = tmp / f"{mode}-{inp.name}"
            r = run(exe, *data, "anonymize", "--project", "a", "--payload", mode, inp, "-o", out)
            check(r.returncode == 0, f"{inp.name} ({mode}) publishes ({r.stderr.strip()[-200:]})")
            if r.returncode != 0:
                continue
            c = run(sys.executable, CANARY, fixtures / "canaries.json", out, "--source", inp.name)
            check(c.returncode == 0, f"{inp.name} ({mode}) no canary survives ({c.stdout.strip()[:300]})")
            s = run(exe, *data, "scan", "--project", "a", out)
            check(s.returncode == 0, f"{inp.name} ({mode}) the independent scan is clean ({s.stdout.strip()[-200:]})")
            media = json.loads(Path(str(out) + ".report.json").read_text())["media"]
            app = media["app"]
            if "malformed" in inp.name:
                for key in ("subtype", "name", "field", "malformed"):
                    check(app["unknown"].get(key, 0) >= 1, f"{inp.name} ({mode}) counts unknown {key}")
                check(media["rtcp"]["srtcp_view"].get("undecodable", 0) >= 1,
                      f"{inp.name} ({mode}) a datagram that does not tile gets the SRTCP view")
            elif "secure" in inp.name:
                check(media["rtcp"]["srtcp_view"].get("secure", 0) >= 1,
                      f"{inp.name} ({mode}) a secure endpoint gets the SRTCP view")
            else:
                check(sum(app["messages"].values()) > 0, f"{inp.name} ({mode}) report counts APP messages")
                check(not app["unknown"], f"{inp.name} ({mode}) no unknown APP item ({app['unknown']})")
            if not tshark:
                continue
            ld = run(sys.executable, LADDER, inp, out)
            check(ld.returncode == 0 or "secure" in inp.name,
                  f"{inp.name} ({mode}) floor control ladder unchanged ({ld.stdout.strip()[-300:]})")
            if "malformed" not in inp.name and "secure" not in inp.name:
                mc = run(sys.executable, CONSISTENCY, inp, out)
                check(mc.returncode == 0, f"{inp.name} ({mode}) one pseudonym per identity ({mc.stdout.strip()[-300:]})")
            d = run(sys.executable, DIFF, inp, out, "--payload", mode, "--media")
            check(d.returncode == 0, f"{inp.name} ({mode}) no new expert errors ({d.stdout.strip()[-300:]})")
    if not tshark:
        print("tshark not installed: ladder, consistency and expert checks skipped")
sys.exit(1 if failures else 0)

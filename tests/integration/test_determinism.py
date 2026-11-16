#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""FR-034 / SC-008: two runs with the same input and project state give byte-identical output,
for every SIP fixture and the demo capture. Feature 003 (FR-023): for every XML fixture, two runs
from two copies of the same project state give byte-identical output and the same report
(output file name aside). Feature 005 (FR-026): every MIKEY fixture and the demo with key
management, with and without --kms-key-period, three times from one project state.

Usage: test_determinism.py MCXANON FIXTURE_DIR
"""
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
exe, fixtures = sys.argv[1], Path(sys.argv[2])
failures = 0
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    subprocess.run([sys.executable, str(REPO / "tools" / "fixturegen" / "mcx_demo.py"), "--out", str(tmp)],
                   check=True, capture_output=True)
    inputs = sorted(fixtures.glob("sip_*.pcapng")) + [tmp / "mcx_demo.pcapng"]
    data = ["--data-dir", str(tmp / "data")]
    subprocess.run([exe, *data, "project", "init", "d"], check=True, capture_output=True)
    for inp in inputs:
        outs = []
        for i in range(2):
            out = tmp / f"{i}-{inp.name}"
            r = subprocess.run([exe, *data, "anonymize", "--project", "d", str(inp), "-o", str(out)],
                               capture_output=True, text=True)
            outs.append(out.read_bytes() if r.returncode == 0 else None)
        ok = outs[0] is not None and outs[0] == outs[1]
        print(("ok   " if ok else "FAIL ") + f"{inp.name}: two runs are byte-identical")
        failures += 0 if ok else 1
    # Feature 003: XML fixtures, each run from a copy of the same project state; feature 007: the
    # HTTP and TLS fixtures (the hostile ones are covered by web-hostile).
    web = [f for f in sorted(fixtures.glob("web_*.pcapng")) if not f.name.startswith("web_hostile_")]
    for inp in sorted(fixtures.glob("xml_*.pcapng")) + web:
        outs, reps = [], []
        for i in range(2):
            state = tmp / f"xml-state-{i}"
            shutil.rmtree(state, ignore_errors=True)
            shutil.copytree(tmp / "data", state)
            out = tmp / f"x{i}-{inp.name}"
            r = subprocess.run([exe, "--data-dir", str(state), "anonymize", "--project", "d", str(inp), "-o", str(out)],
                               capture_output=True, text=True)
            outs.append(out.read_bytes() if r.returncode == 0 else None)
            if r.returncode == 0:
                rep = json.loads(Path(str(out) + ".report.json").read_text())
                rep["files"].pop("output", None)
                reps.append(rep)
        ok = outs[0] is not None and outs[0] == outs[1] and len(reps) == 2 and reps[0] == reps[1]
        print(("ok   " if ok else "FAIL ") + f"{inp.name}: two runs from one project state give the same output and report")
        failures += 0 if ok else 1
    # Feature 005 (FR-026): the MIKEY fixtures and the demo with key management, with and without
    # --kms-key-period; three runs from copies of one project state are byte-identical.
    hidden = json.loads((fixtures / "mikey_hidden.expect.json").read_text())
    period = ["--kms-key-period", f"{hidden['kms']}={hidden['period']}:{hidden['offset']}"]
    for inp in sorted(fixtures.glob("mikey_*.pcapng")) + [tmp / "mcx_demo.pcapng"]:
        for opts in ([], period):
            outs = []
            for i in range(3):
                state = tmp / f"mikey-state-{i}"
                shutil.rmtree(state, ignore_errors=True)
                shutil.copytree(tmp / "data", state)
                out = tmp / f"k{i}-{inp.name}"
                r = subprocess.run([exe, "--data-dir", str(state), "anonymize", "--project", "d", *opts, str(inp),
                                    "-o", str(out), "--overwrite"], capture_output=True, text=True)
                outs.append(out.read_bytes() if r.returncode == 0 else None)
            ok = outs[0] is not None and outs[0] == outs[1] == outs[2]
            print(("ok   " if ok else "FAIL ") + f"{inp.name} {' '.join(opts[:1])}: three runs are byte-identical")
            failures += 0 if ok else 1
sys.exit(1 if failures else 0)

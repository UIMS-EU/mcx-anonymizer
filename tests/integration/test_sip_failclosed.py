#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""User Story 3 (FR-002, FR-005, FR-007, FR-008, FR-016, FR-023, FR-029): fail closed.

  canary     no canary of the fail-closed and malformed SIP fixtures survives, in both modes,
             and the run never aborts;
  unknown    unknown headers, parameters, attributes, tags and bodies are removed or emptied
             and counted by name; a message with an extension method is zeroed; SIP on a
             non-standard port is recognised; SIP over SCTP, ESP, TLS and WebSocket stays zeroed;
  malformed  a message with a broken dialog-defining part is zeroed (or dropped) and counted;
             a message with one broken other header keeps its place and loses that header.

Usage: test_sip_failclosed.py MCXANON FIXTURE_DIR canary|unknown|malformed
"""
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CANARY = REPO / "tests" / "integration" / "canary_absent.py"
exe, fixtures, mode = sys.argv[1], Path(sys.argv[2]), sys.argv[3]
failures = []


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def run(*args):
    return subprocess.run([str(a) for a in args], capture_output=True, text=True)


inputs = sorted(fixtures.glob("sip_failclosed_*.pcapng")) + sorted(fixtures.glob("sip_malformed_*.pcapng"))
check(len(inputs) >= 3, f"fail-closed and malformed fixtures present ({len(inputs)})")
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    data = ["--data-dir", tmp / "data"]
    run(exe, *data, "project", "init", "f")
    reports = {}
    for inp in inputs:
        for pm in ("zero", "drop"):
            out = tmp / f"{pm}-{inp.name}"
            r = run(exe, *data, "anonymize", "--project", "f", "--payload", pm, inp, "-o", out)
            check(r.returncode == 0, f"{inp.name} ({pm}) completes and publishes ({r.stderr.strip()[-200:]})")
            if r.returncode != 0:
                continue
            reports[(inp.name, pm)] = json.loads(Path(str(out) + ".report.json").read_text())
            if mode == "canary":
                c = run(sys.executable, CANARY, fixtures / "canaries.json", out, "--source", inp.name)
                check(c.returncode == 0, f"{inp.name} ({pm}) no canary survives ({c.stdout.strip()[:300]})")
            if mode == "malformed" and pm == "zero" and shutil.which("tshark") and "malformed" in inp.name:
                t = run("tshark", "-n", "-r", out, "-Y", "sip", "-T", "fields", "-e", "frame.number", "-e", "sip.Method")
                check(len(t.stdout.splitlines()) == 1, f"{inp.name}: only the message with one broken header stays SIP ({t.stdout.strip()})")
    if mode == "unknown":
        rep = reports.get(("sip_failclosed_unknown.pcapng", "zero"))
        check(rep is not None, "report of the unknown-content fixture")
        if rep:
            sip = rep["sip"]
            ru = sip["removed_unknown"]
            check({"X-Vendor-Info", "P-Vendor-Secret"} <= set(ru.get("sip-header", {})), f"vendor headers removed and counted ({ru.get('sip-header')})")
            check({"x-via-param", "x-hdr-param", "x-uri-param", "+g.vendor.flag"} <= set(ru.get("sip-param", {})),
                  f"unknown header, URI parameters and feature tags removed ({ru.get('sip-param')})")
            check("x-unknown-attr" in ru.get("sdp-attribute", {}), "unknown SDP attribute removed")
            check({"application/x-unknown", "application/x-vendor-blob"} <= set(ru.get("content-type", {})),
                  f"unknown body types emptied and counted ({ru.get('content-type')})")
            for h in ("User-Agent", "Server", "Organization", "Subject"):
                check(sip["headers"].get(h, {}).get("remove", 0) >= 1, f"{h} removed and counted")
            n = sum(sip["messages"]["requests"].values()) + sum(sip["messages"]["responses"].values())
            check(n == 5 and sip["messages"]["requests"].get("OPTIONS") == 1,
                  f"SIP recognised on a non-standard port; 5 messages ({sip['messages']})")
            # An extension method is not understood: zeroed, counted without its name.
            check(sip["messages"]["requests"].get("(invalid-name)") == 1 and sip["messages"]["malformed"] == 1,
                  f"an extension-method message is zeroed and counted ({sip['messages']})")
        tr = reports.get(("sip_failclosed_transports.pcapng", "zero"))
        if tr:
            m = tr["sip"]["messages"]
            check(not m["requests"] and not m["responses"], "SIP over SCTP, ESP, TLS and WebSocket is not processed (zeroed)")
    if mode == "malformed":
        exp = json.loads((fixtures / "sip_malformed_udp.pcapng.expected.json").read_text())
        for pm in ("zero", "drop"):
            rep = reports.get(("sip_malformed_udp.pcapng", pm))
            if not rep:
                continue
            sip = rep["sip"]
            check(sip["messages"]["malformed"] == exp["malformed_messages"],
                  f"({pm}) malformed messages counted ({sip['messages']['malformed']} of {exp['malformed_messages']})")
            check(sip["malformed_headers"] == exp["malformed_headers"],
                  f"({pm}) the broken other header is counted by name ({sip['malformed_headers']})")
sys.exit(1 if failures else 0)

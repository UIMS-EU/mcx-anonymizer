#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Feature 007 User Story 4, scenario 2 (FR-025): the tshark exports (`-V` and
`-T fields`) of the anonymised HTTP and TLS fixtures are revealed; every canary of a revealed
category that tshark shows as a token of its own in the original export, and whose pseudonym it
shows in the anonymised export, is back in the revealed export; and the revealed field export
equals the original's for the identity fields of HTTP and TLS (host names, request URIs, server
names, hello randoms and session ids, certificate names, serial numbers and key identifiers).

Usage: test_web_reveal.py MCXANON FIXTURE_DIR
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

if shutil.which("tshark") is None:
    if os.environ.get("MCXANON_REQUIRE_TSHARK") == "1":
        print("FAIL tshark is required (MCXANON_REQUIRE_TSHARK=1) but not found")
        sys.exit(1)
    print("skip: tshark not found")
    sys.exit(77)

exe, fixtures = sys.argv[1], Path(sys.argv[2])
failures = []
DECODE = ["-d", "tcp.port==8080,http", "-d", "tcp.port==443,tls"]
CASES = {
    "web_xcap.pcapng": ["http.host", "http.request.uri"],
    "web_tls.pcapng": ["tls.handshake.extensions_server_name", "tls.handshake.random", "tls.handshake.session_id",
                       "x509af.serialNumber", "x509ce.dNSName", "x509ce.SubjectKeyIdentifier", "x509ce.keyIdentifier"],
}


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def run(*args, **kw):
    return subprocess.run([str(a) for a in args], capture_output=True, **kw)


def tshark(capture, *args):
    return run("tshark", "-n", "-r", capture, *DECODE, *args).stdout.decode(errors="replace")


def token(v, text):
    return re.search(r"(?<![0-9A-Za-z])" + re.escape(v) + r"(?![0-9A-Za-z])", text) is not None


canaries = json.loads((fixtures / "canaries.json").read_text())["canaries"]
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    data = ["--data-dir", tmp / "data"]
    check(run(exe, *data, "project", "init", "r").returncode == 0, "project init")
    for name, fields in CASES.items():
        inp, out = fixtures / name, tmp / f"anon-{name}"
        r = run(exe, *data, "anonymize", "--project", "r", inp, "-o", out)
        check(r.returncode == 0, f"{name}: anonymize ({r.stderr.decode(errors='replace').strip()[-200:]})")
        if r.returncode != 0:
            continue
        orig_v, anon_v = tshark(inp, "-V"), tshark(out, "-V")
        anon_file, rev_file = tmp / f"anon-{name}.V.txt", tmp / f"rev-{name}.V.txt"
        anon_file.write_text(anon_v)
        r = run(exe, *data, "reveal", "--project", "r", anon_file, "-o", rev_file)
        check(r.returncode == 0, f"{name}: reveal the -V export ({r.stderr.decode(errors='replace').strip()[-200:]})")
        rev_v = rev_file.read_text(errors="replace") if rev_file.exists() else ""
        show = run(exe, *data, "project", "show-map", "r").stdout.decode().splitlines()[1:]
        pseudonym_of = {line.split("\t")[1]: line.split("\t")[2] for line in show}
        mine = [c["value"] for c in canaries if name in c.get("files", [])]
        shown = [v for v in mine if len(v) > 6 and v in pseudonym_of and token(v, orig_v)
                 and token(pseudonym_of[v], anon_v)]
        missing = [v for v in shown if not token(v, rev_v)]
        check(shown and not missing, f"{name}: canaries shown by tshark are restored ({len(shown)}); missing {missing[:5]}")

        # Field exports compared per TCP stream: re-fragmented records (P14) move values between
        # rows, so rows are not compared one by one.
        args = ["-e", "tcp.stream"] + [x for f in fields for x in ("-e", f)]
        orig_f = tshark(inp, "-T", "fields", "-E", "separator=|", *args)
        anon_f = tshark(out, "-T", "fields", "-E", "separator=|", *args)
        r = run(exe, *data, "reveal", "--project", "r", "--quiet", input=anon_f.encode())
        check(r.returncode == 0, f"{name}: reveal the field export")
        rev_f = r.stdout.decode(errors="replace")

        def values(text):
            out = {}
            for line in text.splitlines():
                cols = line.split("|")
                for fname, col in zip(fields, cols[1:]):
                    for v in col.split(","):
                        # Short tokens (6 characters or fewer) stay ambiguous by design (006 FR-015).
                        toks = [t for t in re.split(r"[/?&=;]", v) if len(t) > 6] if fname == "http.request.uri" else [v]
                        out.setdefault((cols[0], fname), set()).update(t for t in toks if len(t) > 6)
            return out
        a, b = values(orig_f), values(rev_f)
        real = [(k, sorted(a[k] ^ b.get(k, set()))[:2]) for k in a if a[k] != b.get(k, set())]
        check(a and not real, f"{name}: the revealed field export equals the original's ({real[:3]})")

print(f"{len(failures)} failure(s)")
sys.exit(1 if failures else 0)

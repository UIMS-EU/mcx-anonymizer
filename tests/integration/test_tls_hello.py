#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Feature 007 User Story 3 (FR-018 to FR-023): the web_tls fixture (TLS 1.2 with a certificate
chain split across records, mutual certificates, ECDHE, a ticket, an alert; TLS 1.3 with a
HelloRetryRequest and a B-TID PSK identity; TLS 1.2 PSK; a CONNECT tunnel) is anonymised in both
payload modes. No canary survives, the scan is clean and the report validates. With tshark: the
same handshake message types, versions, cipher suites and extension types per connection; server
names and certificate names are pseudonyms; the certificates decode; protected records keep
their length with zeroed content; no new error-level expert entry.

Usage: test_tls_hello.py MCXANON FIXTURE_DIR
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CANARY = REPO / "tests" / "integration" / "canary_absent.py"
DIFF = REPO / "tools" / "tshark-expert-diff.py"
VALIDATE = REPO / "tests" / "integration" / "validate_report.py"
SCHEMA = REPO / "schemas" / "report.schema.json"
exe, fixtures = sys.argv[1], Path(sys.argv[2])
failures = []
DECODE = ["-d", "tcp.port==8080,http", "-d", "tcp.port==443,tls"]


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def run(*args):
    return subprocess.run([str(a) for a in args], capture_output=True, text=True)


def fields(path, *names, flt="tls"):
    r = run("tshark", "-n", "-r", path, *DECODE, "-Y", flt, "-T", "fields", *sum((["-e", n] for n in names), []))
    return [line.split("\t") for line in r.stdout.splitlines()]


inp = fixtures / "web_tls.pcapng"
tshark = shutil.which("tshark") is not None
if not tshark and os.environ.get("MCXANON_REQUIRE_TSHARK") == "1":
    check(False, "tshark required but not installed")
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    data = ["--data-dir", tmp / "data"]
    check(run(exe, *data, "project", "init", "t").returncode == 0, "project init")
    for mode in ("zero", "drop"):
        out = tmp / f"{mode}.pcapng"
        r = run(exe, *data, "anonymize", "--project", "t", "--payload", mode, "--time-shift", "-2h", inp, "-o", out)
        check(r.returncode == 0, f"({mode}) publishes ({r.stderr.strip()[-200:]})")
        if r.returncode != 0:
            continue
        c = run(sys.executable, CANARY, fixtures / "canaries.json", out, "--source", inp.name)
        check(c.returncode == 0, f"({mode}) no canary survives ({c.stdout.strip()[-300:]})")
        check(run(exe, *data, "scan", "--project", "t", out).returncode == 0, f"({mode}) the independent scan is clean")
        rep_path = Path(str(out) + ".report.json")
        check(run(sys.executable, VALIDATE, SCHEMA, rep_path).returncode == 0, f"({mode}) report validates")
        rep = json.loads(rep_path.read_text())
        t = rep.get("tls", {})
        check(t.get("certificates_rewritten", 0) >= 3, f"({mode}) certificates rewritten ({t.get('certificates_rewritten')})")
        check(t.get("psk_identities", {}).get("b-tid", 0) >= 1, f"({mode}) a B-TID identity kept its form")
        check(t.get("protected_zeroed", 0) >= 6, f"({mode}) protected records zeroed ({t.get('protected_zeroed')})")
        for s in ("certificate-signatures-invalidated", "certificate-validity-unshifted"):
            check(s in rep["not_anonymised"], f"({mode}) statement {s}")
        if not tshark:
            continue
        names = ("tcp.stream", "tls.handshake.type", "tls.handshake.version", "tls.handshake.ciphersuite",
                 "tls.handshake.extension.type", "tls.record.content_type")
        def per_stream(rows):
            """Per TCP stream, the sequence of each field's values (records may be re-fragmented, P14)."""
            out = {}
            for r in rows:
                s = out.setdefault(r[0], [[] for _ in names[1:-1]])
                for i, v in enumerate(r[1:-1]):
                    s[i] += [x for x in v.split(",") if x]
            return out
        before, after = per_stream(fields(inp, *names)), per_stream(fields(out, *names))
        def subsequence(a, b):
            it = iter(b)
            return all(x in it for x in a)
        # Handshake types: every message tshark decodes in the input is decoded in the output, in order
        # (the output may decode more: re-fragmented records reassemble where a split input did not).
        diff = [(k, i, v[i], after.get(k, [[]] * 4)[i]) for k, v in before.items() for i in range(4)
                if not (subsequence(v[i], after.get(k, [[]] * 4)[i]) if i == 0 else v[i] == after.get(k, [[]] * 4)[i])]
        check(not diff, f"({mode}) same handshake types, versions, suites and extension types per connection ({diff[:1]})")
        sni = [x for row in fields(out, "tls.handshake.extensions_server_name", flt="tls.handshake.type==1") for x in row if x]
        check(sni and all(x.endswith(".invalid") for x in sni), f"({mode}) server names are domain pseudonyms ({sni[:2]})")
        cert = fields(out, "x509sat.uTF8String", "x509ce.dNSName", flt="tls.handshake.type==11")
        flat = ",".join(",".join(r) for r in cert)
        check("example.org" not in flat and ".invalid" in flat, f"({mode}) certificate names pseudonymised")
        app = fields(out, "tls.app_data", flt="tls.record.content_type==23")
        check(app and all(set(x.replace(":", "")) <= {"0"} for r in app for x in r if x), f"({mode}) application data zeroed")
        d = run(sys.executable, DIFF, inp, out, "--payload", mode)
        check(d.returncode == 0, f"({mode}) no new expert errors ({d.stdout.strip()[-300:]})")
if not tshark:
    print("tshark not installed: decoding checks skipped")
print(f"{len(failures)} failure(s)")
sys.exit(1 if failures else 0)

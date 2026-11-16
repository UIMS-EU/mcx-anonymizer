#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Feature 007 User Story 5: hostile HTTP and TLS never crash the tool or leak.

Usage: test_web_hostile.py MCXANON FIXTURE_DIR [--no-time]

Each web_hostile_*.pcapng (oversized heads, endless chunked bodies, a compression bomb, deep JSON
with broken JWTs, HPACK index/Huffman/size attacks and a CONTINUATION flood, lying TLS lengths, a
handshake split in 1-byte records, malformed DER and a long empty chain) is anonymised in both
payload modes under a hard memory limit (4 GiB address space; under AddressSanitizer, whose shadow
memory defeats RLIMIT_AS, a 4 GiB RSS limit instead) and a time bound. The tool must exit normally
(output published, or an explicit failure with nothing published), never by a signal; when it
publishes, no canary of the fixture survives, the independent scan is clean and the fallback is
counted in the report.
"""
import json
import os
import resource
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
exe, fixtures = sys.argv[1], Path(sys.argv[2])
timed = "--no-time" not in sys.argv[3:]
LIMIT = 4 << 30
SECONDS = 30
failures = []


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def sanitized(path):
    with open(path, "rb") as f:
        return b"__asan_init" in f.read()


ASAN = sanitized(exe)


def _limit():
    if not ASAN:
        resource.setrlimit(resource.RLIMIT_AS, (LIMIT, LIMIT))


def run(*args, timeout=600):
    env = dict(os.environ)
    if ASAN:
        env["ASAN_OPTIONS"] = (env.get("ASAN_OPTIONS", "") + ":hard_rss_limit_mb=4096").lstrip(":")
    t0 = time.monotonic()
    r = subprocess.run([str(a) for a in args], capture_output=True, text=True, preexec_fn=_limit, env=env,
                       timeout=timeout)
    return r, time.monotonic() - t0


def counted(rep):
    """Whether the report records a fallback (something zeroed, removed or not understood)."""
    h, t = rep.get("http", {}), rep.get("tls", {})
    removed = any(k.startswith("removed") for v in h.get("bodies", {}).values() for k in v)
    return bool(h.get("malformed") or h.get("h2_undecodable") or h.get("zero_rest") or removed
                or h.get("tokens", {}).get("malformed-jwt") or h.get("removed_unknown")
                or t.get("zero_rest") or t.get("certificates_zeroed")
                or rep.get("sip", {}).get("tcp", {}).get("bytes_unframable"))


inputs = sorted(fixtures.glob("web_hostile_*.pcapng"))
check(len(inputs) >= 6, f"hostile fixtures present ({len(inputs)})")
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    data = ["--data-dir", tmp / "data"]
    check(run(exe, *data, "project", "init", "h")[0].returncode == 0, "project init")
    for inp in inputs:
        for mode in ("zero", "drop"):
            what = f"{inp.stem} ({mode})"
            out = tmp / f"{inp.stem}-{mode}.pcapng"
            r, secs = run(exe, *data, "anonymize", "--project", "h", "--payload", mode, inp, "-o", out)
            check(r.returncode >= 0, f"{what}: exits normally (rc {r.returncode}, {r.stderr.strip()[-200:]})")
            if timed:
                check(secs < SECONDS, f"{what}: within {SECONDS} s ({secs:.1f} s)")
            if r.returncode != 0:
                check(not out.exists(), f"{what}: an explicit failure publishes nothing ({r.stderr.strip()[-200:]})")
                continue
            c = subprocess.run([sys.executable, str(HERE / "canary_absent.py"), str(fixtures / "canaries.json"), str(out),
                                "--source", inp.name], capture_output=True, text=True)
            check(c.returncode == 0, f"{what}: no canary survives ({c.stdout.strip()[-300:]})")
            s, _ = run(exe, *data, "scan", "--project", "h", out)
            check(s.returncode == 0, f"{what}: the independent scan is clean ({s.stdout.strip()[-200:]})")
            rep = json.loads(Path(str(out) + ".report.json").read_text())
            check(counted(rep), f"{what}: the fallback is counted")

print(f"{len(failures)} failure(s)")
sys.exit(1 if failures else 0)

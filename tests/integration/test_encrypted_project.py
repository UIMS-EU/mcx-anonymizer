#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""User story 3 / FR-023b: passphrase-encrypted projects.
Usage: test_encrypted_project.py MCXANON FIXTURE_DIR
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

exe, fixtures = sys.argv[1], Path(sys.argv[2])
failures = 0


def check(name, cond, detail=""):
    global failures
    print(("ok   " if cond else "FAIL ") + name + ("" if cond else f"  {detail}"))
    failures += 0 if cond else 1


def run(dd, *args, pw=None, pwfile=None):
    env = dict(os.environ)
    env.pop("MCXANON_PASSPHRASE", None)
    if pw is not None:
        env["MCXANON_PASSPHRASE"] = pw
    pre = ["--passphrase-file", str(pwfile)] if pwfile else []
    return subprocess.run([exe, "--data-dir", str(dd), *pre, *map(str, args)], capture_output=True, text=True,
                          env=env, stdin=subprocess.DEVNULL)


with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    dd = tmp / "d"
    r = run(dd, "project", "init", "--encrypt", "sec", pw="correct horse battery staple")
    check("init --encrypt", r.returncode == 0, r.stderr)
    pj = json.loads((dd / "projects" / "sec" / "project.json").read_text())
    check("project.json says encrypted with argon2id", pj["encrypted"] and pj["kdf"]["algorithm"] == "argon2id", pj)
    secret = (dd / "projects" / "sec" / "project.secret").read_bytes()
    check("secret file is a container", secret[:8] == b"MCXENC01" and len(secret) == 48 + 32 + 16)

    r = run(dd, "anonymize", "--project", "sec", fixtures / "basic_eth.pcap", "-o", tmp / "o.pcap",
            pw="correct horse battery staple")
    check("anonymize with the right passphrase", r.returncode == 0, r.stderr)
    mapping = (dd / "projects" / "sec" / "mapping.map.json").read_bytes()
    check("mapping is encrypted at rest", mapping[:8] == b"MCXENC01" and b"entries" not in mapping)
    canaries = json.loads((fixtures / "canaries.json").read_text())["canaries"]
    import ipaddress
    plain_hits = [c["value"] for c in canaries if "basic_eth.pcap" in c["files"] and c["category"] == "ipv4"
                  and ipaddress.IPv4Address(c["value"]).packed.hex().encode() in mapping]
    check("no original in the encrypted mapping", not plain_hits, plain_hits)

    r = run(dd, "anonymize", "--project", "sec", fixtures / "basic_eth.pcap", "-o", tmp / "bad.pcap", pw="wrong")
    check("wrong passphrase: exit 3", r.returncode == 3 and "wrong passphrase" in r.stderr, (r.returncode, r.stderr))
    check("wrong passphrase: nothing published", not (tmp / "bad.pcap").exists())
    r = run(dd, "anonymize", "--project", "sec", fixtures / "basic_eth.pcap", "-o", tmp / "nopw.pcap")
    check("no passphrase source and no terminal: exit 3", r.returncode == 3, (r.returncode, r.stderr))

    pwfile = tmp / "pw.txt"
    pwfile.write_text("correct horse battery staple\n")
    r = run(dd, "project", "show-map", "sec", pwfile=pwfile)
    check("show-map with --passphrase-file", r.returncode == 0 and len(r.stdout.splitlines()) == 5, (r.stdout, r.stderr))
    r = run(dd, "project", "list")
    check("list: encrypted, no counts", "sec\tencrypted" in r.stdout and "entries" not in r.stdout, r.stdout)

    # Tampering with the container is detected.
    mp = dd / "projects" / "sec" / "mapping.map.json"
    data = bytearray(mp.read_bytes())
    data[60] ^= 1
    mp.write_bytes(bytes(data))
    r = run(dd, "project", "show-map", "sec", pw="correct horse battery staple")
    check("tampered mapping: exit 3", r.returncode == 3 and "tampered" in r.stderr, (r.returncode, r.stderr))
    # The passphrase never lands on disk.
    found = any(b"correct horse" in p.read_bytes() for p in (dd / "projects" / "sec").iterdir() if p.is_file())
    check("passphrase not stored", not found)
sys.exit(1 if failures else 0)

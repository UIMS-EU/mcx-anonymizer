#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Feature 006 US1 CLI behaviour: banner, stdin/stdout and files,
owner-only output, output = input refused, --overwrite, exit codes, encrypted projects, the
project lock, an empty mapping, the summary, the report schema, determinism, and the project
files unchanged after every run (FR-001, FR-004..FR-008, FR-018, FR-019).

Usage: test_reveal.py MCXANON FIXTURE_DIR
"""
import fcntl
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
import validate_report  # noqa: E402

exe, fixtures = sys.argv[1], Path(sys.argv[2])
failures = []
BANNER = "the output contains ORIGINAL values"


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def run(dd, *args, stdin=None, env_extra=None, pre=()):
    env = dict(os.environ)
    env.pop("MCXANON_PASSPHRASE", None)
    env.update(env_extra or {})
    return subprocess.run([exe, "--data-dir", str(dd), *pre, *map(str, args)], capture_output=True, input=stdin,
                          env=env)


def files_of(pdir):
    return {f: (hashlib.sha256((pdir / f).read_bytes()).hexdigest(), (pdir / f).stat().st_mtime_ns)
            for f in ("project.secret", "mapping.map.json")}


with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    dd = tmp / "d"
    check(run(dd, "project", "init", "p").returncode == 0, "project init")
    r = run(dd, "anonymize", "--project", "p", fixtures / "basic_eth.pcap", "-o", tmp / "o.pcap")
    check(r.returncode == 0, f"anonymize a fixture ({r.stderr.decode()[-200:]})")
    pdir = dd / "projects" / "p"
    before = files_of(pdir)
    rows = [l.split("\t") for l in run(dd, "project", "show-map", "p").stdout.decode().splitlines()[1:]]
    ipv4 = [(o, ps) for c, o, ps, *_ in rows if c == "ipv4"]
    check(len(ipv4) >= 2, "the fixture gives IPv4 pseudonyms")
    text = "".join(f"host {ps} said hello\n" for _o, ps in ipv4) + "no pseudonym here\n"
    want = "".join(f"host {o} said hello\n" for o, _ps in ipv4) + "no pseudonym here\n"
    (tmp / "in.txt").write_text(text)

    # stdin -> stdout, banner and summary.
    r = run(dd, "reveal", "--project", "p", stdin=text.encode())
    check(r.returncode == 0 and r.stdout.decode() == want, "stdin to stdout")
    err = r.stderr.decode()
    check(err.startswith("mcxanon: " + BANNER), "the banner comes first on stderr")
    check(f"revealed {len(ipv4)} values (ipv4 {len(ipv4)})" in err, f"summary counts ({err.splitlines()[1:2]})")
    r = run(dd, "reveal", "--project", "p", "-", "-o", "-", stdin=text.encode())
    check(r.returncode == 0 and r.stdout.decode() == want, "'-' means stdin and stdout")

    # File to file, owner-only.
    out = tmp / "out.txt"
    r = run(dd, "reveal", "--project", "p", tmp / "in.txt", "-o", out)
    check(r.returncode == 0 and out.read_text() == want, "file to file")
    check(stat.S_IMODE(out.stat().st_mode) == 0o600, "the output file is owner-only")
    check(not list(tmp.glob("out.txt.tmp-*")), "no temporary file is left")

    # Existing output, --overwrite.
    r = run(dd, "reveal", "--project", "p", tmp / "in.txt", "-o", out)
    check(r.returncode == 2, "an existing output without --overwrite: exit 2")
    r = run(dd, "reveal", "--project", "p", tmp / "in.txt", "-o", out, "--overwrite")
    check(r.returncode == 0, "--overwrite replaces it")

    # Output = input, also through a symbolic link.
    copy = tmp / "copy.txt"
    copy.write_text(text)
    r = run(dd, "reveal", "--project", "p", copy, "-o", copy, "--overwrite")
    check(r.returncode == 2 and copy.read_text() == text, "output = input refused, input untouched")
    link = tmp / "link.txt"
    link.symlink_to(copy)
    r = run(dd, "reveal", "--project", "p", copy, "-o", link, "--overwrite")
    check(r.returncode == 2 and copy.read_text() == text, "output = input through a link refused")

    # Input and project errors.
    check(run(dd, "reveal", "--project", "p", tmp / "missing.txt").returncode == 3, "missing input: exit 3")
    check(run(dd, "reveal", "--project", "nope", stdin=b"x").returncode == 3, "unknown project: exit 3")
    check(not (tmp / "never.txt").exists() and
          run(dd, "reveal", "--project", "nope", tmp / "in.txt", "-o", tmp / "never.txt").returncode == 3 and
          not (tmp / "never.txt").exists(), "no output file on a project error")

    # Report: schema, determinism.
    rep1, rep2 = tmp / "r1.json", tmp / "r2.json"
    noisy = text + "u-0badcafe and 240.9.9.9\n"
    (tmp / "noisy.txt").write_text(noisy)
    r1 = run(dd, "reveal", "--project", "p", tmp / "noisy.txt", "-o", tmp / "n1.txt", "--report", rep1)
    r2 = run(dd, "reveal", "--project", "p", tmp / "noisy.txt", "-o", tmp / "n2.txt", "--report", rep2)
    check(r1.returncode == 0 and r2.returncode == 0, "reveal with --report")
    check(rep1.read_bytes() == rep2.read_bytes() and (tmp / "n1.txt").read_bytes() == (tmp / "n2.txt").read_bytes(),
          "output and report are deterministic")
    check(stat.S_IMODE(rep1.stat().st_mode) == 0o600, "the report is owner-only")
    schema = json.loads((REPO / "schemas" / "reveal-report.schema.json").read_text())
    doc = json.loads(rep1.read_text())
    errors = validate_report.validate(doc, schema)
    check(not errors, f"the report matches its schema {errors[:3]}")
    check(doc["unknown"] == {"ipv4": 1, "sip-user": 1}, f"unknown values are counted ({doc['unknown']})")
    check(run(dd, "reveal", "--project", "p", tmp / "noisy.txt", "-o", tmp / "n3.txt", "--report", rep1).returncode == 2,
          "an existing report without --overwrite: exit 2")

    # Empty mapping.
    check(run(dd, "project", "init", "empty").returncode == 0, "init an empty project")
    r = run(dd, "reveal", "--project", "empty", stdin=text.encode())
    check(r.returncode == 0 and r.stdout.decode() == text and b"mapping is empty" in r.stderr,
          "an empty mapping passes the text through with a warning")

    # The project lock: busy without --wait (exit 5), waits with --wait.
    lock = open(pdir / "lock", "r+")
    fcntl.flock(lock, fcntl.LOCK_EX)
    r = run(dd, "reveal", "--project", "p", stdin=text.encode())
    check(r.returncode == 5, "locked project: exit 5")
    p = subprocess.Popen([exe, "--data-dir", str(dd), "--wait", "reveal", "--project", "p"], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(0.5)
    check(p.poll() is None, "--wait waits for the lock")
    fcntl.flock(lock, fcntl.LOCK_UN)
    lock.close()
    o, _e = p.communicate(text.encode(), timeout=30)
    check(p.returncode == 0 and o.decode() == want, "--wait proceeds once the lock is free")

    check(files_of(pdir) == before, "the project files are unchanged after every run")

    # Encrypted project.
    ed = tmp / "e"
    pw = {"MCXANON_PASSPHRASE": "correct horse battery staple"}
    check(run(ed, "project", "init", "--encrypt", "s", env_extra=pw).returncode == 0, "init --encrypt")
    check(run(ed, "anonymize", "--project", "s", fixtures / "basic_eth.pcap", "-o", tmp / "e.pcap",
              env_extra=pw).returncode == 0, "anonymize into the encrypted project")
    erows = [l.split("\t") for l in run(ed, "project", "show-map", "s", env_extra=pw).stdout.decode().splitlines()[1:]]
    eip = [(o, ps) for c, o, ps, *_ in erows if c == "ipv4"]
    etext = f"see {eip[0][1]}\n"
    r = run(ed, "reveal", "--project", "s", stdin=etext.encode(), env_extra=pw)
    check(r.returncode == 0 and r.stdout.decode() == f"see {eip[0][0]}\n", "reveal with MCXANON_PASSPHRASE")
    (tmp / "pw.txt").write_text("correct horse battery staple\n")
    r = run(ed, "reveal", "--project", "s", stdin=etext.encode(), pre=("--passphrase-file", tmp / "pw.txt"))
    check(r.returncode == 0 and r.stdout.decode() == f"see {eip[0][0]}\n", "reveal with --passphrase-file")
    r = run(ed, "reveal", "--project", "s", tmp / "in.txt", "-o", tmp / "bad.txt",
            env_extra={"MCXANON_PASSPHRASE": "wrong"})
    check(r.returncode == 3 and not (tmp / "bad.txt").exists(), "wrong passphrase: exit 3, no output")

sys.exit(1 if failures else 0)

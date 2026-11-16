#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""User story 3: project lifecycle commands, permissions, locking.
Usage: test_project_lifecycle.py MCXANON FIXTURE_DIR
"""
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
exe, fixtures = sys.argv[1], Path(sys.argv[2])
failures = 0


def check(name, cond, detail=""):
    global failures
    print(("ok   " if cond else "FAIL ") + name + ("" if cond else f"  {detail}"))
    failures += 0 if cond else 1


def run(dd, *args, **kw):
    return subprocess.run([exe, "--data-dir", str(dd), *map(str, args)], capture_output=True, text=True, **kw)


with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    dd = tmp / "d"
    run(dd, "project", "init", "alpha")
    run(dd, "project", "init", "beta")
    r = run(dd, "anonymize", "--project", "alpha", fixtures / "basic_eth.pcap", "-o", tmp / "o.pcap")
    check("anonymize under alpha", r.returncode == 0, r.stderr)

    r = run(dd, "project", "list")
    lines = r.stdout.strip().splitlines()
    check("list shows both projects", r.returncode == 0 and [l.split("\t")[0] for l in lines] == ["alpha", "beta"], r.stdout)
    check("list shows entry counts, no mapping contents", "4 entries" in lines[0] and "." not in lines[0].split("\t")[-1], lines)

    r = run(dd, "project", "show-map", "alpha")
    rows = r.stdout.strip().splitlines()
    check("show-map: header and 4 rows", r.returncode == 0 and len(rows) == 5, r.stdout)
    check("show-map: warning banner on stderr", "ORIGINAL" in r.stderr, r.stderr)
    check("show-map: IPv4 pseudonyms in 240/4", all(row.split("\t")[2].startswith(("24", "25")) for row in rows[1:]
                                                    if row.startswith("ipv4")), rows)
    r = run(dd, "project", "show-map", "alpha", "--category", "mac")
    check("show-map --category", r.returncode == 0 and all(l.startswith("mac") for l in r.stdout.splitlines()[1:]), r.stdout)

    r = run(dd, "project", "where")
    check("where: data dir and source", r.returncode == 0 and str(dd) in r.stdout and "--data-dir" in r.stdout, r.stdout)
    r = run(dd, "project", "where", "alpha")
    check("where <name>", r.stdout.strip() == str(dd / "projects" / "alpha"), r.stdout)

    r = run(dd, "anonymize", "--project", "nobody", fixtures / "basic_eth.pcap", "-o", tmp / "x.pcap")
    check("missing project: exit 3 with a hint", r.returncode == 3 and "project init" in r.stderr, (r.returncode, r.stderr))
    check("missing project: nothing published", not (tmp / "x.pcap").exists())
    rep = tmp / "x.pcap.report.json"
    check("missing project: report written", rep.exists())
    if rep.exists():
        v = subprocess.run([sys.executable, str(HERE / "validate_report.py"),
                            str(HERE.parents[1] / "schemas" / "report.schema.json"), str(rep)], capture_output=True, text=True)
        check("missing project: report valid", v.returncode == 0, v.stderr)

    secret = dd / "projects" / "beta" / "project.secret"
    os.chmod(secret, 0o640)
    r = run(dd, "anonymize", "--project", "beta", fixtures / "basic_eth.pcap", "-o", tmp / "y.pcap")
    check("group-readable secret: exit 3", r.returncode == 3, (r.returncode, r.stderr))
    check("hint names chmod", "chmod" in r.stderr, r.stderr)
    os.chmod(secret, 0o600)

    # Concurrency: the test holds the project lock itself (flock), like a running mcxanon.
    import fcntl
    lockf = open(dd / "projects" / "alpha" / "lock", "r+")
    fcntl.flock(lockf, fcntl.LOCK_EX)
    r = run(dd, "anonymize", "--project", "alpha", fixtures / "basic_eth.pcap", "-o", tmp / "second.pcap")
    check("concurrent run: exit 5 (busy)", r.returncode == 5, (r.returncode, r.stderr))
    check("busy: report written", (tmp / "second.pcap.report.json").exists())
    waiter = subprocess.Popen([exe, "--data-dir", str(dd), "--wait", "anonymize", "--project", "alpha",
                               str(fixtures / "basic_eth.pcap"), "-o", str(tmp / "third.pcap")],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(0.5)
    check("--wait blocks while the lock is held", waiter.poll() is None)
    fcntl.flock(lockf, fcntl.LOCK_UN)
    lockf.close()
    rc = waiter.wait(timeout=60)
    check("--wait succeeds after the lock is released", rc == 0 and (tmp / "third.pcap").exists())
    fifo = tmp / "pipe.pcap"
    os.mkfifo(fifo)
    r = run(dd, "anonymize", "--project", "alpha", fifo, "-o", tmp / "pipe-out.pcap")
    check("a pipe as input is a usage error", r.returncode == 2 and "regular file" in r.stderr, (r.returncode, r.stderr))

    # Stale temporaries in the project directory are removed when the lock is taken.
    stale = dd / "projects" / "alpha" / "mapping.map.json.tmp-deadbeef"
    stale.write_text("partial")
    run(dd, "anonymize", "--project", "alpha", fixtures / "basic_eth.pcap", "-o", tmp / "z.pcap")
    check("stale tmp cleaned", not stale.exists())
sys.exit(1 if failures else 0)

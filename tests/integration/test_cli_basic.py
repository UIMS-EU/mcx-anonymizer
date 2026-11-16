#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Basic CLI behaviour: --version, project init, exit codes.

Usage: test_cli_basic.py PATH_TO_MCXANON
"""
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

exe = sys.argv[1]
failures = 0


def check(name, cond, detail=""):
    global failures
    print(("ok   " if cond else "FAIL ") + name + ("" if cond else f" {detail}"))
    failures += 0 if cond else 1


def run(*args, env=None):
    e = dict(os.environ)
    e.pop("MCXANON_DATA_DIR", None)
    if env:
        e.update(env)
    return subprocess.run([exe, *args], capture_output=True, text=True, env=e)


r = run("--version")
check("--version exits 0", r.returncode == 0, r.stderr)
check("--version names tool and rule set",
      re.search(r"mcxanon \d+\.\d+\.\d+", r.stdout) is not None and "rule set" in r.stdout, r.stdout)

r = run("--help")
check("--help exits 0", r.returncode == 0, r.stderr)

r = run("--no-such-option")
check("unknown option is a usage error (2)", r.returncode == 2, f"rc={r.returncode}")

r = run()
check("no command is a usage error (2)", r.returncode == 2, f"rc={r.returncode}")

with tempfile.TemporaryDirectory() as d:
    data = Path(d) / "data"
    r = run("--data-dir", str(data), "project", "init", "demo")
    check("project init exits 0", r.returncode == 0, r.stderr)
    pdir = data / "projects" / "demo"
    check("project init prints the project path", str(pdir) in r.stdout, r.stdout)
    check("project directory exists", pdir.is_dir())
    check("project directory is 0700", stat.S_IMODE(pdir.stat().st_mode) == 0o700)
    check("secret is 0600", stat.S_IMODE((pdir / "project.secret").stat().st_mode) == 0o600)

    r = run("--data-dir", str(data), "project", "init", "demo")
    check("second init is a usage error (2)", r.returncode == 2, f"rc={r.returncode}")
    check("second init says the project exists", "exists" in r.stderr, r.stderr)

    r = run("--data-dir", str(data), "project", "init", "../escape")
    check("invalid name is a usage error (2)", r.returncode == 2, f"rc={r.returncode}")
    check("invalid name creates nothing", not (data / "escape").exists())

    r = run("project", "init", "envproj", env={"MCXANON_DATA_DIR": str(Path(d) / "envdata")})
    check("MCXANON_DATA_DIR is honoured", (Path(d) / "envdata" / "projects" / "envproj").is_dir(),
          r.stderr)

    # Nothing secret on the terminal.
    secret_hex = (pdir / "project.secret").read_bytes().hex()
    check("secret never printed", secret_hex not in (r.stdout + r.stderr))

sys.exit(1 if failures else 0)

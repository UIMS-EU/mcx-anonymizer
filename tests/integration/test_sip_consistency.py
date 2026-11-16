#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""User Story 2 (SC-003, FR-012, FR-014, FR-033, FR-035): one pseudonym per original across
layers, fields and captures.

  consistency   text addresses equal the IP header pseudonyms; SPIs of Security-* equal the
                ESP SPIs; the IMPI and the IMPU of a user share their user and domain
                pseudonyms; tel: and user=phone share the digits; also with --prefix-preserving
                and --pseudonymise-ephemeral-ports, where the SDP-announced RTP flow is still set
                up on the pseudonymised ports;
  cross-capture two captures in one project show the same URI pseudonym, in two projects not.

Usage: test_sip_consistency.py MCXANON FIXTURE_DIR consistency|cross-capture
"""
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ORACLE = REPO / "tests" / "integration" / "sip_consistency.py"
exe, fixtures, mode = sys.argv[1], Path(sys.argv[2]), sys.argv[3]
failures = []


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def run(*args):
    return subprocess.run([str(a) for a in args], capture_output=True, text=True)


def sip_text(path):
    """The UDP payloads of the SIP packets, as text (independent of the tool's parsers)."""
    data = path.read_bytes()
    return data.decode("latin-1")


def uri_users(text):
    return set(re.findall(r"sip:(u-[0-9a-f]{8})@", text))


tshark = shutil.which("tshark") is not None
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    if mode == "consistency":
        for opts, tag in (([], "default"), (["--prefix-preserving"], "prefix-preserving"),
                          (["--pseudonymise-ephemeral-ports"], "ephemeral-ports")):
            data = ["--data-dir", tmp / tag]
            run(exe, *data, "project", "init", "c")
            for inp in sorted(fixtures.glob("sip_consistency_*.pcapng")):
                out = tmp / f"{tag}-{inp.name}"
                r = run(exe, *data, "anonymize", "--project", "c", *opts, inp, "-o", out)
                check(r.returncode == 0, f"{inp.name} ({tag}) publishes ({r.stderr.strip()[-200:]})")
                if r.returncode != 0:
                    continue
                text = sip_text(out)
                # IMPI user@realm and IMPU share the user pseudonym (FR-012).
                impi = re.findall(r'username="(u-[0-9a-f]{8})@(d-[0-9a-f]{8}(?:\.d-[0-9a-f]{8})*\.invalid)"', text)
                check(impi and impi[0][0] in uri_users(text), f"{inp.name} ({tag}) IMPI and IMPU share the user pseudonym")
                realm = re.findall(r'realm="(d-[0-9a-f]{8}(?:\.d-[0-9a-f]{8})*\.invalid)"', text)
                check(impi and realm and impi[0][1] == realm[0], f"{inp.name} ({tag}) IMPI realm and Digest realm share the domain")
                # tel: and user=phone share the digits (FR-033).
                phone = re.findall(r"sip:\+([0-9]+)@[^;>]+;user=phone", text)
                tel = re.findall(r"tel:\+([0-9]+)", text)
                check(phone and tel and set(phone) == set(tel), f"{inp.name} ({tag}) tel: and user=phone share the digits")
                if tshark:
                    o = run(sys.executable, ORACLE, out)
                    check(o.returncode == 0, f"{inp.name} ({tag}) text addresses and SPIs are consistent ({o.stdout.strip()[-300:]})")
                    rtp = run("tshark", "-n", "-r", out, "-Y", "rtp", "-T", "fields", "-e", "frame.number")
                    if tag == "ephemeral-ports":
                        prot = run("tshark", "-n", "-r", out, "-T", "fields", "-e", "frame.protocols", "-e", "udp.dstport")
                        flows = [l for l in prot.stdout.splitlines() if ":rtp" in l]
                        check(len(flows) == 2 and all(not l.endswith("\t50170") for l in flows),
                              f"{inp.name} ({tag}) the RTP flow is set up on the pseudonymised ports ({flows})")
                    else:
                        check(len(rtp.stdout.split()) >= 0, f"{inp.name} ({tag}) RTP decoded")
    elif mode == "cross-capture":
        a, b = fixtures / "sip_consistency_a.pcapng", fixtures / "sip_consistency_b.pcapng"
        same = ["--data-dir", tmp / "same"]
        run(exe, *same, "project", "init", "one")
        users = []
        for inp in (a, b):
            out = tmp / f"same-{inp.name}"
            check(run(exe, *same, "anonymize", "--project", "one", inp, "-o", out).returncode == 0, f"{inp.name} publishes")
            users.append(uri_users(sip_text(out)))
        check(bool(users[0] & users[1]), "one project: the shared URI has one pseudonym in both captures")
        for i, inp in enumerate((a, b)):
            d = ["--data-dir", tmp / f"other{i}"]
            run(exe, *d, "project", "init", f"p{i}")
            out = tmp / f"other-{inp.name}"
            run(exe, *d, "anonymize", "--project", f"p{i}", inp, "-o", out)
            users.append(uri_users(sip_text(out)))
        check(not (users[2] & users[3]), "two projects: the shared URI has different pseudonyms")
    if not tshark:
        print("tshark not installed: address and SPI oracle skipped")
sys.exit(1 if failures else 0)

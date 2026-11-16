#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Feature 005 performance (SC-007).

1. SC-007: the demo with key management (mcx_demo.py) is anonymised within 10% of the time of the
   demo without it (mcx_demo.py --no-mikey); the median of several alternating runs is compared.
2. UID resolution with a full identity ledger (65,536 URIs) stays under 50 ms per UID: a capture
   whose MESSAGEs fill the ledger, then INVITEs with unresolvable hidden identities, anonymised
   with and without --kms-key-period; the difference per UID is the resolution cost.
3. The 002 perf capture with an I_MESSAGE in every INVITE (bulk.py --sip --mikey) stays within the
   002 budget (180 s, 256 MiB peak RSS) and every I_MESSAGE is rewritten.

Skipped (exit 77) unless MCXANON_RUN_PERF=1. MCXANON_PERF_DIR selects the scratch directory.
Usage: test_perf_mikey.py MCXANON
"""
import base64
import hashlib
import json
import os
import resource
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

if os.environ.get("MCXANON_RUN_PERF") != "1":
    print("perf test skipped (set MCXANON_RUN_PERF=1)")
    sys.exit(77)
exe = sys.argv[1]
REPO = Path(__file__).resolve().parents[2]
GEN = REPO / "tools" / "fixturegen"
sys.path.insert(0, str(GEN))
failures = []


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def _limit():
    # A hard address-space limit: a run that grows past it fails here instead of exhausting the
    # machine's memory (the budget is 256 MiB).
    resource.setrlimit(resource.RLIMIT_AS, (4 << 30, 4 << 30))


def timed(*args):
    """(exit code, seconds, peak RSS MiB) of one run."""
    t0 = time.monotonic()
    p = subprocess.Popen([str(a) for a in args], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         preexec_fn=_limit)
    _, status, usage = os.wait4(p.pid, 0)
    return os.waitstatus_to_exitcode(status), time.monotonic() - t0, usage.ru_maxrss / 1024


def ledger_capture(path, n_uris, n_invites, kms):
    """MESSAGEs from n_uris distinct users (the identity ledger), then INVITEs whose I_MESSAGE
    carries hidden identities that no user of the capture has (each UID scans the whole ledger)."""
    import mikey as K
    import sip as S
    cap = S.Capture()
    for i in range(n_uris):
        u = f"sip:user{i:06d}@mcx.example.net"
        m = S.request("MESSAGE", "sip:psi@mcx.example.net",
                      [("Via", f"SIP/2.0/UDP 10.20.1.10:5060;branch=z9hG4bKl{i}"), ("Max-Forwards", "70"),
                       ("From", f"<{u}>;tag=ledger-tag-{i:06d}"), ("To", "<sip:psi@mcx.example.net>"),
                       ("Call-ID", f"ledger-call-{i:06d}@mcx.example.net"), ("CSeq", "1 MESSAGE")])
        cap.add(S.wrap(S.udp_packet(S.UA, S.PCSCF, 5060, 5060, m, ident=i & 0xFFFF)))
    for i in range(n_invites):
        rnd = lambda tag, n: hashlib.sha256(f"{tag}-{i}".encode()).digest()[:n]  # noqa: E731
        ids = [(K.IDRUIDI, K.BYTES, rnd("uidi", 32)), (K.IDRUIDR, K.BYTES, rnd("uidr", 32)),
               (K.IDRKMSI, K.URI, kms.encode()), (K.IDRKMSR, K.URI, kms.encode())]
        msg = K.i_message(K.key_id(K.PCK, 0x100000 + i), 0xE9A1B2C380000000, rnd("rand", 16), ids,
                          K.filler(273, i), K.filler(129, i + 1000))
        sdp = S.sdp(["v=0", "o=- 1 1 IN IP4 10.20.1.10", "s=-", "c=IN IP4 10.20.1.10", "t=0 0",
                     "a=key-mgmt:mikey " + base64.b64encode(msg).decode(), "m=audio 40000 RTP/SAVP 96"])
        m = S.request("INVITE", "sip:callee@mcx.example.net",
                      [("Via", f"SIP/2.0/UDP 10.20.1.10:5060;branch=z9hG4bKi{i}"), ("Max-Forwards", "70"),
                       ("From", "<sip:caller@mcx.example.net>;tag=invite-tag"), ("To", "<sip:callee@mcx.example.net>"),
                       ("Call-ID", f"invite-call-{i:06d}@mcx.example.net"), ("CSeq", "1 INVITE"), ("Content-Type", "application/sdp")],
                      sdp)
        cap.add(S.wrap(S.udp_packet(S.UA, S.PCSCF, 5060, 5060, m, ident=i)))
    path.write_bytes(cap.bytes())


with tempfile.TemporaryDirectory(dir=os.environ.get("MCXANON_PERF_DIR")) as tmp:
    tmp = Path(tmp)
    def project(name):
        """A fresh project per part: the 002 budget holds for a fresh project at its own scale."""
        subprocess.run([exe, "--data-dir", tmp / name, "project", "init", "perf"], check=True, capture_output=True)
        return ["--data-dir", tmp / name]

    data = project("demo")

    # 1. SC-007 on the demo.
    for variant, extra in (("with", []), ("without", ["--no-mikey"])):
        subprocess.run([sys.executable, GEN / "mcx_demo.py", "--out", tmp / variant, *extra], check=True,
                       capture_output=True)
    times = {"with": [], "without": []}
    for _ in range(9):
        for variant in ("without", "with"):
            rc, t, _ = timed(exe, *data, "anonymize", "--project", "perf", tmp / variant / "mcx_demo.pcapng",
                             "-o", tmp / f"{variant}.pcapng", "--overwrite")
            if rc != 0:
                check(False, f"demo {variant} key management publishes ({rc})")
            times[variant].append(t)
    med = {k: statistics.median(v) for k, v in times.items()}
    ratio = med["with"] / med["without"]
    print(f"SC-007: median {med['with']:.3f} s with key management, {med['without']:.3f} s without ({ratio:.3f})")
    check(ratio <= 1.10, f"SC-007: the demo with key management within 10% ({ratio:.3f})")

    # 2. UID resolution at the full ledger (under 50 ms per UID).
    data = project("ledger")
    kms = "kms.mcx.example.net"
    cap = tmp / "ledger.pcapng"
    n_inv = 20
    ledger_capture(cap, 70000, n_inv, kms)
    base, resolved = [], []
    for _ in range(3):
        rc0, t0, _ = timed(exe, *data, "anonymize", "--project", "perf", cap, "-o", tmp / "l0.pcapng", "--overwrite")
        rc1, t1, _ = timed(exe, *data, "anonymize", "--project", "perf", "--kms-key-period", f"{kms}=2592000",
                           cap, "-o", tmp / "l1.pcapng", "--overwrite")
        if rc0 or rc1:
            check(False, f"ledger capture publishes ({rc0}/{rc1})")
        base.append(t0)
        resolved.append(t1)
    rep = json.loads(Path(str(tmp / "l1.pcapng") + ".report.json").read_text())
    uids = rep.get("mikey", {}).get("uids", {})
    check(uids.get("unresolved") == 2 * n_inv, f"every UID tried and left opaque ({uids})")
    per_uid_ms = max(0.0, statistics.median(resolved) - statistics.median(base)) / (2 * n_inv) * 1000
    print(f"UID resolution at a full ledger: {per_uid_ms:.2f} ms per UID")
    check(per_uid_ms < 50, f"UID resolution under 50 ms per UID ({per_uid_ms:.2f} ms)")

    # 3. The 002 perf capture with an I_MESSAGE in every INVITE.
    data = project("bulk")
    big = tmp / "mikey-big.pcap"
    g = subprocess.run([sys.executable, GEN / "bulk.py", big, "--sip", "--mikey"], check=True, capture_output=True,
                       text=True)
    stats = json.loads(g.stdout)
    for run in ("fresh project", "second run"):
        rc, t, rss = timed(exe, *data, "anonymize", "--project", "perf", big, "-o", tmp / "big.pcap", "--overwrite")
        print(f"{run}: {stats['bytes'] / 2**30:.2f} GiB, {stats['mikey_messages']} I_MESSAGEs, exit {rc}, "
              f"{t:.1f} s, peak RSS {rss:.0f} MiB")
        check(rc == 0, f"{run}: publishes")
        if rc == 0:
            rep = json.loads(Path(str(tmp / "big.pcap") + ".report.json").read_text())
            got = rep.get("mikey", {}).get("carriers", {}).get("sdp", {}).get("rewritten", 0)
            check(got == stats["mikey_messages"], f"{run}: every I_MESSAGE rewritten ({got} of {stats['mikey_messages']})")
        check(t <= 180, f"{run}: within 180 s ({t:.1f} s)")
        check(rss <= 256, f"{run}: peak RSS within 256 MiB ({rss:.0f} MiB)")
sys.exit(1 if failures else 0)

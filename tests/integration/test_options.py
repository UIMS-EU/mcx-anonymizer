#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""User story 4: VLAN IDs, ephemeral ports, prefix preservation, time shift.
Usage: test_options.py MCXANON FIXTURE_DIR
"""
import ipaddress
import struct
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


def pcap_records(path):
    d = path.read_bytes()
    off, out = 24, []
    while off + 16 <= len(d):
        sec, frac, cap, _ = struct.unpack_from("<IIII", d, off)
        out.append((sec, frac, d[off + 16:off + 16 + cap]))
        off += 16 + cap
    return out


def pcapng_blocks(path):
    d = path.read_bytes()
    off, out = 0, []
    while off + 12 <= len(d):
        t, n = struct.unpack_from("<II", d, off)
        out.append((t, d[off:off + n]))
        off += n
    return out


def prefix(a, b):
    x = int.from_bytes(a, "big") ^ int.from_bytes(b, "big")
    return len(a) * 8 - x.bit_length()


with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    dd = tmp / "d"
    subprocess.run([exe, "--data-dir", str(dd), "project", "init", "o"], check=True, capture_output=True)

    def anon(src, dst, *opts):
        return subprocess.run([exe, "--data-dir", str(dd), "anonymize", "--project", "o", str(fixtures / src), "-o",
                               str(tmp / dst), *opts], capture_output=True, text=True)

    # VLAN IDs.
    r = anon("options_vlan.pcap", "v0.pcap")
    tcis = [(struct.unpack_from("!H", p, 14)[0], struct.unpack_from("!H", p, 18)[0]) for _, _, p in pcap_records(tmp / "v0.pcap")]
    check("VLAN IDs kept by default", r.returncode == 0 and tcis[0] == (0xA000 | 100, 0x2000 | 101), tcis)
    r = anon("options_vlan.pcap", "v1.pcap", "--pseudonymise-vlan")
    tcis = [(struct.unpack_from("!H", p, 14)[0], struct.unpack_from("!H", p, 18)[0]) for _, _, p in pcap_records(tmp / "v1.pcap")]
    check("--pseudonymise-vlan: exit 0", r.returncode == 0, r.stderr)
    check("VLAN IDs changed", tcis[0][0] & 0xFFF != 100 and tcis[0][1] & 0xFFF != 101, tcis)
    check("VLAN IDs consistent", tcis[0] == tcis[2], tcis)
    check("PCP/DEI kept", tcis[0][0] >> 12 == 0xA and tcis[0][1] >> 12 == 0x2, tcis)
    check("VLAN IDs in 1-4094", all(1 <= (t & 0xFFF) <= 4094 for pair in tcis for t in pair), tcis)

    # Ephemeral ports.
    r = anon("options_ports.pcap", "p0.pcap")
    recs = pcap_records(tmp / "p0.pcap")
    check("ports kept by default", struct.unpack_from("!H", recs[0][2], 20)[0] == 50000)
    r = anon("options_ports.pcap", "p1.pcap", "--pseudonymise-ephemeral-ports")
    recs = pcap_records(tmp / "p1.pcap")
    sports = [struct.unpack_from("!H", p, 20)[0] for _, _, p in recs]
    dports = [struct.unpack_from("!H", p, 22)[0] for _, _, p in recs]
    check("ephemeral ports changed, in range", all(49152 <= s <= 65535 for s in sports) and sports[0] != 50000, sports)
    check("ephemeral ports consistent", sports[0] == sports[2] and sports[0] != sports[1], sports)
    check("service ports kept", dports[:3] == [5060] * 3 and dports[3] == 443, dports)
    # A fresh project: an existing mapping keeps its pseudonyms whatever the range.
    dd3 = tmp / "d3"
    subprocess.run([exe, "--data-dir", str(dd3), "project", "init", "r"], check=True, capture_output=True)
    r = subprocess.run([exe, "--data-dir", str(dd3), "anonymize", "--project", "r", str(fixtures / "options_ports.pcap"),
                        "-o", str(tmp / "p2.pcap"), "--pseudonymise-ephemeral-ports", "--ephemeral-range", "60000-62000"],
                       capture_output=True, text=True)
    sports = [struct.unpack_from("!H", p, 20)[0] for _, _, p in pcap_records(tmp / "p2.pcap")]
    check("custom ephemeral range", sports[:3] == [50000, 50001, 50000] and 60000 <= sports[3] <= 62000, sports)
    r = anon("options_ports.pcap", "p3.pcap", "--ephemeral-range", "70000-1")
    check("invalid range: exit 2", r.returncode == 2, r.returncode)

    # Prefix preservation (a separate project: a category is fixed per address).
    dd2 = tmp / "d2"
    subprocess.run([exe, "--data-dir", str(dd2), "project", "init", "pp"], check=True, capture_output=True)
    r = subprocess.run([exe, "--data-dir", str(dd2), "anonymize", "--project", "pp", str(fixtures / "options_prefix.pcap"),
                        "-o", str(tmp / "pp.pcap"), "--prefix-preserving"], capture_output=True, text=True)
    check("--prefix-preserving: exit 0", r.returncode == 0, r.stderr)
    recs = pcap_records(tmp / "pp.pcap")
    v4 = [p[12:16] for _, _, p in recs[:5]]
    check("in 240/4", all(a[0] >> 4 == 0xF for a in v4), v4)
    check("/24 shared prefix kept", prefix(v4[0], v4[1]) == prefix(bytes([10, 1, 2, 3]), bytes([10, 1, 2, 200])), v4)
    check("/16 shared prefix kept", prefix(v4[0], v4[2]) == prefix(bytes([10, 1, 2, 3]), bytes([10, 1, 9, 9])))
    check("/8 shared prefix kept", prefix(v4[0], v4[3]) == prefix(bytes([10, 1, 2, 3]), bytes([10, 200, 0, 1])))
    v6 = [p[8:24] for _, _, p in recs[5:]]
    check("IPv6 /64 kept", prefix(v6[0], v6[1]) == 126 and prefix(v6[0], v6[2]) == prefix(
        bytes.fromhex("fd000000000000010000000000000001"), bytes.fromhex("fd000000000000020000000000000001")), v6)
    check("IPv6 in 2001:db8::/32", all(a[:4] == bytes.fromhex("20010db8") for a in v6))

    # Time shift.
    day = 86400
    r = anon("options_time.pcap", "t.pcap", "--time-shift", "-30d")
    check("--time-shift (pcap): exit 0", r.returncode == 0, r.stderr)
    src = pcap_records(fixtures / "options_time.pcap")
    dst = pcap_records(tmp / "t.pcap")
    check("pcap: every timestamp shifted by exactly 30 days",
          all(d[0] == s[0] - 30 * day and d[1] == s[1] for s, d in zip(src, dst)), (src[:1], dst[:1]))
    r = anon("options_time.pcapng", "t.pcapng", "--time-shift", "+1h30m")
    check("--time-shift (pcapng): exit 0", r.returncode == 0, r.stderr)
    sb, db = pcapng_blocks(fixtures / "options_time.pcapng"), pcapng_blocks(tmp / "t.pcapng")
    def ts(blk):
        hi, lo = struct.unpack_from("<II", blk, 12)
        return (hi << 32) | lo
    s_epb = [ts(b) for t, b in sb if t == 6]
    d_epb = [ts(b) for t, b in db if t == 6]
    shift = 5400
    check("ns interface shifted exactly", d_epb[0] - s_epb[0] == shift * 10**9 and d_epb[1] - s_epb[1] == shift * 10**9,
          (s_epb, d_epb))
    check("2^-10 interface shifted exactly", d_epb[2] - s_epb[2] == shift * 1024, (s_epb, d_epb))
    check("deltas unchanged", d_epb[1] - d_epb[0] == s_epb[1] - s_epb[0])
    s_isb = [b for t, b in sb if t == 5][0]
    d_isb = [b for t, b in db if t == 5][0]
    check("ISB timestamp shifted", ts(d_isb) - ts(s_isb) == shift * 10**9)
    check("ISB start/end options shifted", len(d_isb) == len(s_isb) and
          struct.unpack_from("<II", d_isb, 24) != struct.unpack_from("<II", s_isb, 24))
    r = anon("options_time.pcap", "t1.pcap", "--time-shift", "1ns")
    check("shift finer than the capture's resolution: exit 2", r.returncode == 2, (r.returncode, r.stderr))
    r = anon("options_time.pcap", "t2.pcap", "--time-shift", "-30000d")
    check("shift below the epoch: exit 3", r.returncode == 3, (r.returncode, r.stderr))
    r = anon("options_time.pcap", "t3.pcap", "--time-shift", "soon")
    check("invalid duration: exit 2", r.returncode == 2, r.returncode)
    # Feature 005.
    r = anon("options_time.pcap", "k0.pcap", "--encrypted", "decrypt")
    check("--encrypted decrypt: exit 2 naming the missing feature",
          r.returncode == 2 and "decryption is not available" in r.stderr, (r.returncode, r.stderr))
    for bad in ("kms.example.org", "kms.example.org=", "=2592000", "kms.example.org=0",
                "kms.example.org=100:100", "kms.example.org=abc", "kms.example.org=10:-1"):
        r = anon("options_time.pcap", "k1.pcap", "--kms-key-period", bad)
        check(f"--kms-key-period {bad!r}: exit 2", r.returncode == 2, (r.returncode, r.stderr))
    r = anon("options_time.pcap", "k2.pcap", "--kms-key-period", "kms.example.org=2592000",
             "--kms-key-period", "kms.example.org=86400")
    check("--kms-key-period given twice for one KMS: exit 2", r.returncode == 2, (r.returncode, r.stderr))
    r = anon("options_time.pcap", "k3.pcap", "--kms-key-period", "kms.example.org=2592000:3600",
             "--encrypted", "passthrough")
    check("valid --kms-key-period and --encrypted passthrough: exit 0", r.returncode == 0, (r.returncode, r.stderr))
sys.exit(1 if failures else 0)

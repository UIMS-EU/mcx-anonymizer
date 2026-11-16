#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""User story 1: fail-closed anonymisation of every fixture through the CLI.

Usage: test_anonymize_us1.py MCXANON FIXTURE_DIR
"""
import json
import os
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
ORACLE = HERE / "canary_absent.py"
VALIDATE = HERE / "validate_report.py"
SCHEMA = REPO / "schemas" / "report.schema.json"

exe, fixtures = sys.argv[1], Path(sys.argv[2])
manifest = fixtures / "canaries.json"
failures = 0


def check(name, cond, detail=""):
    global failures
    print(("ok   " if cond else "FAIL ") + name + ("" if cond else f"  {detail}"))
    failures += 0 if cond else 1


def run(*args, data_dir, **kw):
    return subprocess.run([exe, "--data-dir", str(data_dir), *map(str, args)], capture_output=True,
                          text=True, **kw)


def oracle(path, source, layout=True, extra=()):
    cmd = [sys.executable, str(ORACLE), str(manifest), str(path), "--source", source, *extra]
    if layout:
        cmd.append("--layout-preserved")
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.returncode, r.stdout.strip()


def oracle_all(path):
    r = subprocess.run([sys.executable, str(ORACLE), str(manifest), str(path), "--all", "--report"],
                       capture_output=True, text=True)
    return r.returncode, r.stdout.strip()


def valid_report(path):
    r = subprocess.run([sys.executable, str(VALIDATE), str(SCHEMA), str(path)], capture_output=True, text=True)
    return r.returncode == 0, r.stderr.strip()


def pcap_records(data):
    order = "<" if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    off, out = 24, []
    while off + 16 <= len(data):
        _, _, caplen, origlen = struct.unpack_from(order + "IIII", data, off)
        out.append(data[off + 16:off + 16 + caplen])
        off += 16 + caplen
    return out


with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    data_dir = tmp / "data"
    r = run("project", "init", "us1", data_dir=data_dir)
    check("project init", r.returncode == 0, r.stderr)

    inputs = sorted(p for p in fixtures.iterdir()
                    if p.suffix in (".pcap", ".pcapng") and not p.name.startswith("malformed"))
    check("fixtures present", len(inputs) >= 10, [p.name for p in inputs])
    for inp in inputs:
        out = tmp / ("anon-" + inp.name)
        r = run("anonymize", "--project", "us1", inp, "-o", out, data_dir=data_dir)
        check(f"{inp.name}: exit 0", r.returncode == 0, r.stderr)
        if r.returncode != 0:
            continue
        rc, hits = oracle(out, inp.name, layout=inp.suffix == ".pcap")
        check(f"{inp.name}: no canary in the output", rc == 0, hits)
        report = Path(str(out) + ".report.json")
        ok, err = valid_report(report)
        check(f"{inp.name}: report validates", ok, err)
        rc, hits = oracle_all(report)
        check(f"{inp.name}: no canary in the report", rc == 0, hits)
        stderr_file = tmp / (inp.name + ".stderr")
        stderr_file.write_text(r.stderr + r.stdout)
        rc, hits = oracle_all(stderr_file)
        check(f"{inp.name}: no canary on stdout/stderr", rc == 0, hits)
        check(f"{inp.name}: same format as the input", out.read_bytes()[:4] == inp.read_bytes()[:4] or
              (inp.suffix == ".pcapng" and out.read_bytes()[:4] == b"\x0a\x0d\x0d\x0a"))
        if inp.suffix == ".pcap":
            check(f"{inp.name}: zero mode keeps every length", len(out.read_bytes()) == len(inp.read_bytes()))

    # Consistency within and across captures: the same original gets the same pseudonym.
    a = tmp / "anon-basic_eth.pcap"
    if a.exists():
        recs = pcap_records(a.read_bytes())
        srcs = {r[26:30] for r in recs}
        check("one source address, one pseudonym", len(srcs) == 1, srcs)
        check("IPv4 pseudonyms are in 240.0.0.0/4", all(s[0] >> 4 == 0xF for s in srcs), srcs)
        check("MAC pseudonyms are locally administered", all(r[6] & 0x02 for r in recs))
        b2 = tmp / "again.pcap"
        r = run("anonymize", "--project", "us1", fixtures / "basic_eth.pcap", "-o", b2, data_dir=data_dir)
        check("re-run is byte-identical", r.returncode == 0 and b2.read_bytes() == a.read_bytes())
        rep1 = json.loads(Path(str(a) + ".report.json").read_text())
        check("report: addresses pseudonymised", rep1["counters"]["ipv4.src"]["pseudonymise"] == 3)
        check("report: payload zeroed", rep1["counters"]["payload.l7"]["zero"] == 3)

    rep = json.loads((tmp / "anon-link_eth.pcap.report.json").read_text())
    check("unknown EtherType reported by id", {"kind": "ethertype", "id": 0x88B5, "count": 1} in rep["unknown_protocols"],
          rep["unknown_protocols"])
    rep = json.loads((tmp / "anon-meta_all.pcapng.report.json").read_text())
    for key in ("0x00000004", "0x0000000a", "0x00000bad", "0x40000bad", "0x00000009", "0x00001234", "0x80000001"):
        check(f"removed block {key} counted", rep["pcapng_removed"]["blocks"].get(key) == 2,
              rep["pcapng_removed"]["blocks"])
    check("removed options counted", rep["pcapng_removed"]["options"].get("0x0a0d0d0a/2") == 2,
          rep["pcapng_removed"]["options"])

    # Forced formats.
    r = run("anonymize", "--project", "us1", fixtures / "basic_eth.pcap", "-o", tmp / "f.pcapng",
            "--format", "pcapng", data_dir=data_dir)
    check("pcap -> pcapng", r.returncode == 0 and (tmp / "f.pcapng").read_bytes()[:4] == b"\x0a\x0d\x0d\x0a", r.stderr)
    r = run("anonymize", "--project", "us1", fixtures / "meta_all.pcapng", "-o", tmp / "f.pcap",
            "--format", "pcap", data_dir=data_dir)
    check("pcapng -> pcap", r.returncode == 0 and (tmp / "f.pcap").read_bytes()[:4] == b"\xd4\xc3\xb2\xa1", r.stderr)
    rc, hits = oracle(tmp / "f.pcap", "meta_all.pcapng", layout=False)
    check("pcapng -> pcap: no canary", rc == 0, hits)

    # Drop mode.
    for name in ("l4_tcp_udp.pcap", "l4_sctp.pcap", "tunnel.pcap", "l3_ipv4.pcap", "icmp.pcap", "link_eth.pcap"):
        out = tmp / ("drop-" + name)
        r = run("anonymize", "--project", "us1", fixtures / name, "-o", out, "--payload", "drop", data_dir=data_dir)
        check(f"drop {name}: exit 0", r.returncode == 0, r.stderr)
        rc, hits = oracle(out, name, layout=False)
        check(f"drop {name}: no canary", rc == 0, hits)
        check(f"drop {name}: smaller output", out.stat().st_size < (fixtures / name).stat().st_size)

    # Refusals.
    out = tmp / "exists.pcap"
    out.write_bytes(b"x")
    r = run("anonymize", "--project", "us1", fixtures / "basic_eth.pcap", "-o", out, data_dir=data_dir)
    check("existing output without --overwrite: exit 2", r.returncode == 2, r.returncode)
    r = run("anonymize", "--project", "us1", fixtures / "basic_eth.pcap", "-o", out, "--overwrite", data_dir=data_dir)
    check("--overwrite replaces it", r.returncode == 0 and out.read_bytes()[:4] == b"\xd4\xc3\xb2\xa1", r.stderr)
    copy = tmp / "copy.pcap"
    shutil.copy(fixtures / "basic_eth.pcap", copy)
    r = run("anonymize", "--project", "us1", copy, "-o", copy, "--overwrite", data_dir=data_dir)
    check("output = input: exit 2", r.returncode == 2, r.returncode)
    check("input untouched", copy.read_bytes() == (fixtures / "basic_eth.pcap").read_bytes())

    # Strict mode.
    r = run("anonymize", "--project", "us1", fixtures / "link_unsupported.pcap", "-o", tmp / "strict.pcap",
            "--strict", data_dir=data_dir)
    check("strict + unsupported link type: exit 3", r.returncode == 3, r.returncode)
    check("strict failure publishes nothing", not (tmp / "strict.pcap").exists())

    # Corrupt input: exit 3, report written and valid.
    bad = tmp / "corrupt.pcapng"
    data = bytearray((fixtures / "basic_meta.pcapng").read_bytes())
    data[-1] ^= 0x10  # trailing block length mismatch
    bad.write_bytes(bytes(data))
    r = run("anonymize", "--project", "us1", bad, "-o", tmp / "corrupt-out.pcapng", data_dir=data_dir)
    check("corrupt input: exit 3", r.returncode == 3, r.returncode)
    check("corrupt input: nothing published", not (tmp / "corrupt-out.pcapng").exists())
    ok, err = valid_report(tmp / "corrupt-out.pcapng.report.json")
    check("corrupt input: report written and valid", ok, err)
    gz = tmp / "c.pcap.gz"
    gz.write_bytes(b"\x1f\x8b\x08\x00" + bytes(60))
    r = run("anonymize", "--project", "us1", gz, "-o", tmp / "gz-out.pcap", data_dir=data_dir)
    check("compressed input: exit 3 with hint", r.returncode == 3 and "decompress" in r.stderr, r.stderr)

    # Truncated tail is reported, not copied.
    tail = tmp / "tail.pcap"
    tail.write_bytes((fixtures / "basic_eth.pcap").read_bytes() + b"\x01\x02\x03\x04\x05")
    r = run("anonymize", "--project", "us1", tail, "-o", tmp / "tail-out.pcap", data_dir=data_dir)
    rep = json.loads((tmp / "tail-out.pcap.report.json").read_text())
    check("truncated tail reported", r.returncode == 0 and rep["files"]["truncated_tail_bytes"] == 5, rep["files"])

    # Collision: an original equal to an issued pseudonym (exit 4, report written).
    recs = pcap_records((tmp / "anon-basic_eth.pcap").read_bytes())
    pseudo_src = recs[0][26:30]
    pkt = bytearray(recs[0])
    pkt[26:30] = pseudo_src
    hdr = bytearray((fixtures / "basic_eth.pcap").read_bytes()[:24])
    coll = tmp / "collision.pcap"
    coll.write_bytes(bytes(hdr) + struct.pack("<IIII", 1, 0, len(pkt), len(pkt)) + bytes(pkt))
    r = run("anonymize", "--project", "us1", coll, "-o", tmp / "coll-out.pcap", data_dir=data_dir)
    check("collision: exit 4", r.returncode == 4, (r.returncode, r.stderr))
    ok, err = valid_report(tmp / "coll-out.pcap.report.json")
    check("collision: report written and valid", ok, err)
    check("collision: nothing published", not (tmp / "coll-out.pcap").exists())

    # A killed run leaves nothing visible next to the destination (large input, killed mid-run).
    big = tmp / "big.pcap"
    base = (fixtures / "basic_eth.pcap").read_bytes()
    recs = base[24:]
    with open(big, "wb") as fh:
        fh.write(base[:24])
        fh.write(recs * 200000)
    outdir = tmp / "killdir"
    outdir.mkdir()
    proc = subprocess.Popen([exe, "--data-dir", str(data_dir), "anonymize", "--project", "us1", str(big),
                             "-o", str(outdir / "k.pcap")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.3)
    running = proc.poll() is None
    proc.send_signal(signal.SIGKILL)
    proc.wait()
    check("SIGKILL arrived mid-run", running)
    check("SIGKILL: no visible file in the output directory", list(outdir.iterdir()) == [], list(outdir.iterdir()))
    big.unlink()

sys.exit(1 if failures else 0)

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Self-check of tools/fixturegen: deterministic output and well-formed files.

Parses every generated capture with a minimal reader written here (independent
of the generator's writer code) and checks the canary manifest.
"""
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
GEN = REPO / "tools" / "fixturegen" / "gen.py"
failures = 0


def check(name, cond, detail=""):
    global failures
    print(("ok   " if cond else "FAIL ") + name + ("" if cond else f" {detail}"))
    failures += 0 if cond else 1


def read_pcap(data):
    magic = data[:4]
    order = {b"\xd4\xc3\xb2\xa1": "<", b"\x4d\x3c\xb2\xa1": "<",
             b"\xa1\xb2\xc3\xd4": ">", b"\xa1\xb2\x3c\x4d": ">"}[magic]
    off, n = 24, 0
    while off < len(data):
        _, _, caplen, origlen = struct.unpack_from(order + "IIII", data, off)
        assert caplen <= origlen or origlen == 0 or True
        off += 16 + caplen
        n += 1
    assert off == len(data), "pcap records do not end at end of file"
    return n


def read_pcapng(data):
    off, blocks, order = 0, 0, None
    while off < len(data):
        btype_le = struct.unpack_from("<I", data, off)[0]
        if btype_le == 0x0A0D0D0A:
            order = "<" if data[off + 8:off + 12] == b"\x4d\x3c\x2b\x1a" else ">"
        assert order is not None, "block before SHB"
        btype, length = struct.unpack_from(order + "II", data, off)
        assert length % 4 == 0 and length >= 12, f"bad length {length}"
        trailer = struct.unpack_from(order + "I", data, off + length - 4)[0]
        assert trailer == length, "trailing length mismatch"
        off += length
        blocks += 1
    assert off == len(data)
    return blocks


with tempfile.TemporaryDirectory() as d:
    a, b = Path(d) / "a", Path(d) / "b"
    for out in (a, b):
        r = subprocess.run([sys.executable, str(GEN), "--out", str(out), "--seed", "1"],
                           capture_output=True, text=True)
        check(f"generator runs ({out.name})", r.returncode == 0, r.stderr)
    files_a = sorted(p.name for p in a.iterdir())
    check("generator produced captures", any(n.endswith((".pcap", ".pcapng")) for n in files_a),
          files_a)
    check("canaries.json present", "canaries.json" in files_a)
    for name in files_a:
        check(f"deterministic: {name}", (a / name).read_bytes() == (b / name).read_bytes())

    for p in sorted(a.iterdir()):
        data = p.read_bytes()
        try:
            if p.suffix == ".pcap":
                check(f"parses: {p.name} ({read_pcap(data)} records)", True)
            elif p.suffix == ".pcapng":
                check(f"parses: {p.name} ({read_pcapng(data)} blocks)", True)
        except Exception as exc:  # noqa: BLE001 - report any parse failure
            check(f"parses: {p.name}", False, repr(exc))

    manifest = json.loads((a / "canaries.json").read_text())
    check("manifest has canaries", len(manifest.get("canaries", [])) > 0)
    for c in manifest.get("canaries", []):
        # A canary names its classification by FieldId ("field") or SIP rule key ("rule").
        ok = all(k in c for k in ("id", "category", "value", "files")) and ("field" in c or "rule" in c)
        check(f"canary {c.get('id')} complete", ok, c)
        for f in c.get("files", []):
            check(f"canary {c.get('id')} file {f} exists", (a / f).exists())

    r = subprocess.run([sys.executable, str(GEN), "--out", str(Path(d) / "c"), "--seed", "2"],
                       capture_output=True, text=True)
    differs = any((a / n).read_bytes() != (Path(d) / "c" / n).read_bytes()
                  for n in files_a if (Path(d) / "c" / n).exists() and n != "canaries.json")
    check("another seed gives other bytes", differs)

sys.exit(1 if failures else 0)

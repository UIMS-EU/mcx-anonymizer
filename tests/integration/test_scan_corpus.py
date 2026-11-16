#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""SC-003: every deliberately injected leak, one per token category and
encoding, is detected by the scanner.

Usage: test_scan_corpus.py MCXANON
"""
import base64
import ipaddress
import struct
import subprocess
import sys
import tempfile
import urllib.parse
from pathlib import Path

exe = sys.argv[1]
failures = 0
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools" / "fixturegen"))
import packets as P  # noqa: E402


def check(name, cond, detail=""):
    global failures
    print(("ok   " if cond else "FAIL ") + name + ("" if cond else f"  {detail}"))
    failures += 0 if cond else 1


def pcap(packets):
    out = struct.pack("<IHHiiII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)
    for i, p in enumerate(packets):
        out += struct.pack("<IIII", 1700000000 + i, 0, len(p), len(p)) + p
    return out


MAC = bytes.fromhex("00163e5a7b9c")
V4 = ipaddress.IPv4Address("10.77.88.99")
V6 = ipaddress.IPv6Address("fd12:3456:789a::42")
WORD = "KestrelProject"

def b64_variants(raw):
    for shift in range(3):
        yield f"base64+{shift}", base64.b64encode(b"\x00" * shift + raw)

leaks = []
leaks += [("ipv4 binary", V4.packed), ("ipv4 text", str(V4).encode()), ("ipv4 hex", V4.packed.hex().encode()),
          ("ipv4 HEX", V4.packed.hex().upper().encode()), ("ipv4 utf16le", str(V4).encode("utf-16-le")),
          ("ipv4 utf16be", str(V4).encode("utf-16-be")),
          ("ipv4 reverse-dns", "99.88.77.10.in-addr.arpa".encode()),
          ("ipv4 mapped binary", b"\x00" * 10 + b"\xff\xff" + V4.packed), ("ipv4 mapped text", f"::ffff:{V4}".encode())]
leaks += [(f"ipv4 {n}", v) for n, v in b64_variants(V4.packed)]
leaks += [("ipv6 binary", V6.packed), ("ipv6 text", V6.compressed.encode()), ("ipv6 TEXT", V6.compressed.upper().encode()),
          ("ipv6 full", V6.exploded.encode()), ("ipv6 utf16le", V6.compressed.encode("utf-16-le")),
          ("ipv6 reverse-dns", (".".join(reversed(V6.packed.hex())) + ".ip6.arpa").encode()),
          ("ipv6 hex", V6.packed.hex().encode())]
leaks += [(f"ipv6 {n}", v) for n, v in b64_variants(V6.packed)]
mh = MAC.hex()
leaks += [("mac binary", MAC), ("mac colon", ":".join(mh[i:i + 2] for i in range(0, 12, 2)).encode()),
          ("mac COLON", ":".join(mh[i:i + 2] for i in range(0, 12, 2)).upper().encode()),
          ("mac dash", "-".join(mh[i:i + 2] for i in range(0, 12, 2)).encode()),
          ("mac dot", f"{mh[0:4]}.{mh[4:8]}.{mh[8:12]}".encode()), ("mac plain", mh.encode()),
          ("mac eui64", bytes([MAC[0] ^ 2, MAC[1], MAC[2], 0xFF, 0xFE, MAC[3], MAC[4], MAC[5]])),
          ("mac utf16le", ":".join(mh[i:i + 2] for i in range(0, 12, 2)).encode("utf-16-le"))]
leaks += [(f"mac {n}", v) for n, v in b64_variants(MAC)]
leaks += [("deny text", WORD.encode()), ("deny mixed case", "kEsTrElPrOjEcT".encode()),
          ("deny utf16le", WORD.encode("utf-16-le")), ("deny utf16be", WORD.encode("utf-16-be")),
          ("deny url", urllib.parse.quote("Kestrel Project").encode())]
leaks += [(f"deny {n}", v) for n, v in b64_variants(WORD.encode())]

with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    dd = tmp / "d"
    subprocess.run([exe, "--data-dir", str(dd), "project", "init", "c"], check=True, capture_output=True)
    # Teach the project the originals.
    base = tmp / "base.pcap"
    base.write_bytes(pcap([P.ethernet(b"\x02" * 6, MAC, 0x0800, P.udp4(V4.packed, bytes([10, 0, 0, 1]), 1, 2, b"")),
                           P.ethernet(b"\x02" * 6, MAC, 0x86DD, P.udp6(V6.packed, bytes(15) + b"\x02", 1, 2, b""))]))
    r = subprocess.run([exe, "--data-dir", str(dd), "anonymize", "--project", "c", str(base), "-o", str(tmp / "b.out")],
                       capture_output=True, text=True)
    check("base capture anonymised", r.returncode == 0, r.stderr)
    deny = tmp / "deny.txt"
    deny.write_text("Kestrel Project\nKestrelProject\n")
    for name, payload in leaks:
        f = tmp / ("leak-" + name.replace(" ", "_").replace("+", "p") + ".pcap")
        f.write_bytes(pcap([P.ethernet(b"\x02" * 6, b"\x02\x00\x00\x00\x00\x09", 0x0800,
                                       P.udp4(bytes([240, 0, 0, 7]), bytes([240, 0, 0, 8]), 9, 9,
                                              b"pad<" + payload + b">pad"))]))
        r = subprocess.run([exe, "--data-dir", str(dd), "scan", "--project", "c", str(f), "--deny-list", str(deny)],
                           capture_output=True, text=True)
        check(f"detected: {name}", r.returncode == 1, (r.returncode, r.stderr))
    check(f"corpus covers {len(leaks)} category x encoding cases", len(leaks) >= 40)
sys.exit(1 if failures else 0)

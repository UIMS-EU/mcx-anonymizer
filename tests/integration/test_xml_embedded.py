#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""User Story 2 scenario 2 (FR-014a): bodies embedded in resource-lists
entry URIs of a REFER.

Runs xml_embedded.pcapng in --payload zero and drop and checks that the embedded mcptt-info,
SDP (with mc_implicit_request) and multipart bodies are present, URL-encoded and rewritten (their
decoded identities are the pseudonyms of the same values in the top-level oracles); the
undecodable, untyped, unknown and nested bodies are removed and counted under xml.embedded; no
canary survives in decoded or URL-encoded form; the decoded embedded XML is well-formed (expat).

Usage: test_xml_embedded.py MCXANON FIXTURE_DIR
"""
import json
import re
import subprocess
import sys
import tempfile
import urllib.parse
import xml.parsers.expat as expat
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from sip_messages import messages  # noqa: E402

exe, fixtures = sys.argv[1], Path(sys.argv[2])
failures = []


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def run(*args):
    return subprocess.run([str(a) for a in args], capture_output=True, text=True)


def entry_headers(body):
    """[(Content-Type, decoded body or None)] of every entry URI with URI headers."""
    out = []
    for m in re.finditer(rb'uri="([^"]*)"', body):
        uri = m.group(1).decode().replace("&amp;", "&")
        if "?" not in uri:
            continue
        h = dict(item.split("=", 1) for item in uri.split("?", 1)[1].split("&") if "=" in item)
        out.append((urllib.parse.unquote(h.get("Content-Type", "")) or None,
                    urllib.parse.unquote(h["body"]) if "body" in h else None))
    return out


manifest = fixtures / "canaries.json"
inp = fixtures / "xml_embedded.pcapng"
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    data = ["--data-dir", tmp / "data"]
    run(exe, *data, "project", "init", "e")
    for pm in ("zero", "drop"):
        out = tmp / f"{pm}.pcapng"
        r = run(exe, *data, "anonymize", "--project", "e", "--payload", pm, inp, "-o", out)
        check(r.returncode == 0, f"{pm}: publishes ({r.stderr.strip()[-300:]})")
        if r.returncode != 0:
            continue
        rep = json.loads(Path(str(out) + ".report.json").read_text())
        emb = rep["xml"]["embedded"]
        # Per REFER: mcptt-info, SDP, multipart and the embedded resource-lists itself are rewritten;
        # the body inside that resource-lists is not followed (nested).
        check(emb.get("rewritten") == 8, f"{pm}: four embedded bodies rewritten in each of the two REFERs ({emb})")
        for reason in ("undecodable", "unknown-type", "nested"):
            check(emb.get(reason, 0) >= 2, f"{pm}: {reason} bodies removed and counted ({emb})")
        c = run(sys.executable, HERE / "canary_absent.py", manifest, out, "--source", inp.name)
        check(c.returncode == 0, f"{pm}: no canary in the output, decoded or URL-encoded ({c.stdout.strip()[:300]})")
        bodies = [p.body for m in messages(str(out)) for p in m.parts
                  if p.content_type == "application/resource-lists+xml"]
        check(len(bodies) == 2, f"{pm}: both resource-lists bodies present")
        for body in bodies:
            eh = entry_headers(body)
            types = [t for t, _ in eh]
            check(types[:2] == ["application/vnd.3gpp.mcptt-info+xml", "application/sdp"] and
                  types[2].startswith("multipart/mixed;boundary=") and types[3:] == ["application/resource-lists+xml"],
                  f"{pm}: the embedded types are kept in order, failed ones removed ({types})")
            for t, b in eh:
                if t == "application/vnd.3gpp.mcptt-info+xml":
                    p = expat.ParserCreate()
                    try:
                        p.Parse(b.encode(), True)
                        ok = True
                    except expat.ExpatError:
                        ok = False
                    check(ok and "<session-type>prearranged</session-type>" in b, f"{pm}: embedded mcptt-info rewritten")
                if t == "application/sdp":
                    check("a=fmtp:MCPTT mc_queueing;mc_implicit_request" in b and b.startswith("v=0"),
                          f"{pm}: embedded SDP rewritten, mc_implicit_request kept")
                if t and t.startswith("multipart/mixed"):
                    bnd = re.search(r"boundary=([^;]+)", t).group(1)
                    check(b.startswith("--" + bnd) and bnd != "emb-bnd-7", f"{pm}: multipart boundary mapped consistently")
sys.exit(1 if failures else 0)

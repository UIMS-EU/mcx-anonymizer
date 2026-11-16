#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""US3 of feature 005: application/mikey bodies and parts, ciphertext mode.

usage: test_mikey_body.py MCXANON FIXTURE_DIR

Anonymises mikey_body.pcapng (REGISTER, migration REGISTER, PUBLISH, CSK download, MuSiK download,
MCData SDS MESSAGE, SUBSCRIBE, a body in a 200 OK and a version=2 body) and checks US3 scenario 1:
every body keeps its Content-Type and transfer encoding (binary, or base64 with the input's line
layout), decodes as the rewritten I_MESSAGE (mikey_consistency.py), the CSK and MuSiK identifiers
keep their purpose tags, the IDRi is the From pseudonym, no canary remains, the response body is
counted unexpected-carrier and the version=2 body falls back as not-sakke (emptied).
"""
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import mikey_consistency as mc  # noqa: E402
from sip_messages import header, messages  # noqa: E402

exe, fixtures = sys.argv[1], Path(sys.argv[2])
failures = []


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def run(*args):
    return subprocess.run([str(a) for a in args], capture_output=True, text=True)


def mikey_parts(path):
    """[(message start, part headers, body)] of the application/mikey parts, in order."""
    out = []
    for m in messages(str(path)):
        for p in m.parts:
            if (p.content_type or "").split(";")[0].strip().lower() == "application/mikey":
                full = (header(p.headers, "content-type") if p.headers else header(m.headers, "content-type")) or ""
                out.append((m.start, p.headers, p.body, full, m.headers))
    return out


def cte(part_headers, msg_headers):
    hs = part_headers if part_headers else msg_headers
    return (header(hs, "content-transfer-encoding") or "").strip()


def layout(body):
    """(line width, number of lines > 1, ends with CRLF): the base64 line layout of a body."""
    lines = body.split(b"\r\n")
    ends = lines[-1] == b""
    lines = lines[:-1] if ends else lines
    return (max(len(x) for x in lines) if len(lines) > 1 else None, len(lines) > 1, ends)


inp = fixtures / "mikey_body.pcapng"
manifest = fixtures / "canaries.json"
expect = json.loads((fixtures / "mikey_body.expect.json").read_text())
rewritten = sum(1 for _, o in expect if o == "rewritten")
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    data = ["--data-dir", tmp / "data"]
    check(run(exe, *data, "project", "init", "k").returncode == 0, "project init")
    out = tmp / "out.pcapng"
    r = run(exe, *data, "anonymize", "--project", "k", inp, "-o", out)
    check(r.returncode == 0, f"publishes ({r.stderr.strip()[-300:]})")
    if r.returncode == 0:
        o = run(sys.executable, HERE / "mikey_consistency.py", inp, out, "--canaries", manifest, "--expect", rewritten)
        check(o.returncode == 0, f"mikey_consistency ({(o.stdout + o.stderr).strip()[-600:]})")
        for target, extra in ((out, []), (Path(str(out) + ".report.json"), ["--report"])):
            c = run(sys.executable, HERE / "canary_absent.py", manifest, target, "--source", inp.name, *extra)
            check(c.returncode == 0, f"no canary in {target.name} ({c.stdout.strip()[:300]})")
        ins, outs = mikey_parts(inp), mikey_parts(out)
        check(len(ins) == len(outs) == len(expect), f"{len(expect)} application/mikey parts kept ({len(ins)}/{len(outs)})")
        for (name, outcome), i, o in zip(expect, ins, outs):
            ct_in = re.sub(r"\s+", "", i[3] or "")
            ct_out = re.sub(r"\s+", "", o[3] or "")
            check(ct_in == ct_out, f"{name}: Content-Type kept ({ct_in} / {ct_out})")
            check(cte(i[1], i[4]) == cte(o[1], o[4]), f"{name}: Content-Transfer-Encoding kept")
            if outcome != "rewritten":
                check(o[2].strip(b"\r\n") == b"", f"{name}: body emptied ({len(o[2])} octets)")
                continue
            is_b64 = re.fullmatch(rb"[A-Za-z0-9+/=\r\n]+", i[2]) is not None and mc.decode(mc.b64(i[2]) or b"") is not None
            if is_b64:
                check(layout(i[2]) == layout(o[2]), f"{name}: base64 line layout kept ({layout(i[2])} / {layout(o[2])})")
                dec = mc.decode(mc.b64(o[2]) or b"")
            else:
                check(mc.decode(o[2]) is not None or re.fullmatch(rb"[A-Za-z0-9+/=\r\n]+", o[2]) is None,
                      f"{name}: a binary body stays binary")
                dec = mc.decode(o[2])
            check(dec is not None, f"{name}: the output body decodes")
            if dec is None:
                continue
            frm = re.search(r"<([^>]+)>", header(o[4], "from") or "")
            idri = next((p["data"].decode() for k, p in dec["payloads"] if k == "IDR" and p["role"] == 1), None)
            check(frm is not None and idri == frm.group(1), f"{name}: IDRi is the From pseudonym ({idri})")
        rep = json.loads(Path(str(out) + ".report.json").read_text())
        mk = rep.get("mikey", {})
        body = mk.get("carriers", {}).get("body", {})
        check(body.get("rewritten") == rewritten, f"{rewritten} bodies rewritten ({body})")
        check(body.get("fallback", {}).get("not-sakke") == 1, "the version=2 body falls back as not-sakke")
        check(mk.get("unexpected_carrier") == 1, f"one unexpected carrier ({mk.get('unexpected_carrier')})")
        kid = mk.get("key_ids", {})
        check(kid.get("CSK", 0) >= 6 and kid.get("MuSiK") == 1 and kid.get("PCK") == 1, f"key ids {kid}")
        sb = rep.get("sip", {}).get("bodies", {}).get("application/mikey", {})
        check(sb.get("mikey") == rewritten and sb.get("emptied") == 1, f"sip.bodies application/mikey {sb}")
        hd = rep.get("sip", {}).get("headers", {}).get("Content-Transfer-Encoding", {})
        check(hd.get("keep") == 2, f"Content-Transfer-Encoding kept twice ({hd})")

if failures:
    print(f"{len(failures)} failure(s)")
    sys.exit(1)

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""The README demo end to end: tools/fixturegen/mcx_demo.py generates the capture, the
scanner flags the original, anonymisation publishes, no identifying value of the
manifest survives (zero and drop mode), runs are deterministic, and, with tshark
present, the output decodes without new expert errors.

Usage: test_demo_capture.py MCXANON [FIXTURE_DIR]
"""
import json
import re
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
GEN = REPO / "tools" / "fixturegen" / "mcx_demo.py"
HERE = REPO / "tests" / "integration"
CANARY = HERE / "canary_absent.py"
DIFF = REPO / "tools" / "tshark-expert-diff.py"
LADDER = REPO / "tests" / "integration" / "sip_ladder.py"
FLOOR = REPO / "tests" / "integration" / "floor_ladder.py"
CONSISTENCY = REPO / "tests" / "integration" / "media_consistency.py"
exe = sys.argv[1]
fixture_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else None
failures = []


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def run(*args):
    return subprocess.run([str(a) for a in args], capture_output=True, text=True)


sys.path.insert(0, str(HERE))
import mikey_consistency as mc  # noqa: E402


def demo_media(path):
    """[(dport, payload)] of the UDP datagrams that are not SIP or DNS (feature 005: the MKIs)."""
    from sip_messages import _frames, _l4
    out = []
    for frame in _frames(Path(path).read_bytes()):
        l4 = _l4(frame)
        if l4 and l4[0] == 17 and not {5060, 53} & {l4[3], l4[4]}:
            out.append((l4[4], l4[6]))
    return out


def demo_ecis(path):
    """ECIs of the XML location report <Ecgi> elements and of the MCPT Location fields (type 1)."""
    import struct
    sys.path.insert(0, str(HERE))
    from sip_messages import _frames, _l4, messages
    out = []
    for m in messages(str(path)):
        for p in m.parts:
            if p.content_type == "application/vnd.3gpp.mcptt-location-info+xml":
                out += [int(e[6:], 2) for e in re.findall(r"<Ecgi>(\d{6}[01]{28})</Ecgi>", p.body.decode())]
    for frame in _frames(Path(path).read_bytes()):
        l4 = _l4(frame)
        if not l4 or l4[0] != 17 or l4[6][8:12] != b"MCPT":
            continue
        pl, i = l4[6], 12
        while i + 2 <= len(pl):
            fid, ln = pl[i], pl[i + 1]
            if fid == 19 and ln >= 8 and pl[i + 2] == 1:
                out.append(struct.unpack("!I", pl[i + 6:i + 10])[0] & 0x0FFFFFFF)
            i += (2 + ln + 3) // 4 * 4
    return out


with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    data = ["--data-dir", tmp / "data"]
    r = run(sys.executable, GEN, "--out", tmp)
    check(r.returncode == 0, f"generator runs ({r.stderr.strip()[-200:]})")
    src, manifest, deny = tmp / "mcx_demo.pcapng", tmp / "mcx_demo.canaries.json", tmp / "mcx_demo.deny.txt"
    canaries = json.loads(manifest.read_text())["canaries"]
    check(len(canaries) >= 40, f"manifest lists the identifying values ({len(canaries)})")
    rules = {c.get("rule", "").split(".")[0].split(";")[0] for c in canaries}
    check({"sip:Call-ID", "sip-param:Via", "sip-param:Authorization", "sip-param:WWW-Authenticate",
           "sdp:o=", "tag:+sip"} <= rules, f"manifest lists the SIP and SDP identities with rule keys ({sorted(rules)})")
    check(run(sys.executable, GEN, "--out", tmp / "again").returncode == 0
          and (tmp / "again" / "mcx_demo.pcapng").read_bytes() == src.read_bytes(), "generator is deterministic")

    check(run(exe, *data, "project", "init", "demo").returncode == 0, "project init")
    r = run(exe, *data, "scan", "--project", "demo", "--deny-list", deny, src, "--report", tmp / "orig.scan.json")
    check(r.returncode == 1, "scanner flags the original (exit 1)")
    scan_text = (tmp / "orig.scan.json").read_text()
    check("alice.nowak" not in scan_text and "Kowalski" not in scan_text, "scan report does not repeat deny words")

    outputs = {}
    for mode in ("zero", "drop"):
        out = tmp / f"anon-{mode}.pcapng"
        r = run(exe, *data, "anonymize", "--project", "demo", "--deny-list", deny, "--payload", mode, src, "-o", out)
        check(r.returncode == 0, f"anonymize --payload {mode} publishes ({r.stderr.strip()[-300:]})")
        if r.returncode != 0:
            continue
        outputs[mode] = out
        # (feature 003): the CLI summary has an XML line.
        check(any(l.startswith("xml: ") and " rewritten, " in l and l.endswith(" emptied")
                  for l in r.stderr.splitlines()), f"{mode}: summary has the xml line")
        rep = json.loads(Path(str(out) + ".report.json").read_text())
        check(rep["status"]["result"] == "published" and rep["scan"]["hits"] == [], f"{mode}: report says clean")
        removed = rep["pcapng_removed"]
        check(removed["blocks"].get("0x00000004") == 1 and removed["blocks"].get("0x0000000a") == 1,
              f"{mode}: name resolution and decryption secrets blocks removed")
        check(removed["options"].get("0x00000006/1", 0) >= 10, f"{mode}: packet comments removed")
        new = rep["mapping"]["new_entries"] if mode == "zero" else {}
        if mode == "zero":
            check(new.get("ipv4") == 12 and new.get("mac") == 4, f"zero: mapping covers every host ({new})")
            check(new.get("sip-user", 0) > 0 and new.get("call-id", 0) > 0 and new.get("domain", 0) > 0,
                  f"zero: SIP identities are in the mapping ({new})")
        sip = rep.get("sip", {})
        check(sip.get("messages", {}).get("malformed") == 0, f"{mode}: no SIP message is malformed")
        # User Story 4: SIP over TCP to the P-CSCF (IPv4 and IPv6) and the fragmented MCData SDS.
        tcp = sip.get("tcp", {})
        check(tcp.get("streams_sip", 0) >= 4 and tcp.get("bytes_unframable") == 0,
              f"{mode}: every SIP-over-TCP direction is framed, no byte unframable ({tcp})")
        frag = sip.get("fragments", {})
        check(frag.get("datagrams_rewritten") == 1 and not frag.get("datagrams_zeroed"),
              f"{mode}: the fragmented MCData SDS is reassembled and rewritten ({frag})")
        # Feature 003, User Story 1: every mcptt-info body is rewritten, no element of it is
        # unknown; structure kept and URIs consistent with the SIP headers (oracles, expat only).
        xml = rep.get("xml", {})
        info = xml.get("bodies", {}).get("application/vnd.3gpp.mcptt-info+xml", {})
        check(info.get("rewritten", 0) > 0 and set(info) == {"rewritten"},
              f"{mode}: every mcptt-info body is rewritten ({info})")
        # User Story 5: the reg event NOTIFY and the xcap-diff NOTIFY are rewritten.
        for t in ("application/reginfo+xml", "application/xcap-diff+xml"):
            check(xml.get("bodies", {}).get(t, {}).get("rewritten", 0) >= 1, f"{mode}: {t} rewritten")
        # User Story 4: the private call INVITE is integrity-protected (FR-018a).
        signed = xml.get("bodies", {}).get("application/vnd.3gpp.mcptt-signed+xml", {})
        check(signed == {"rewritten": 1}, f"{mode}: the signed body is rewritten ({signed})")
        # User Story 2: the pre-established session REFER embeds SDP and mcptt-info in an entry URI.
        check(xml.get("embedded", {}).get("rewritten", 0) >= 1, f"{mode}: the embedded body is rewritten ({xml.get('embedded')})")
        unknown = [k for k, v in xml.get("elements", {}).items()
                   if k.startswith("urn:3gpp:ns:mcpttInfo:1.0 ") and "unknown" in v]
        check(not unknown, f"{mode}: no mcptt-info element is unknown ({unknown})")
        # User Story 3, SC-003: the serving ECGI of the location report is the ECGI of the floor
        # request's Location field, before and after anonymisation.
        check(demo_ecis(out) and len(set(demo_ecis(out))) == 1 and demo_ecis(src) and len(set(demo_ecis(src))) == 1
              and demo_ecis(out)[0] != demo_ecis(src)[0],
              f"{mode}: one ECI pseudonym in the location report and the floor request ({demo_ecis(out)})")
        for oracle in ("xml_structure.py", "xml_consistency.py"):
            # The XML rule keys come from the XML fixtures' manifest (the demo's has none).
            keys = f"{manifest},{fixture_dir / 'canaries.json'}" if fixture_dir else str(manifest)
            args = [src, out] + ([keys] if oracle == "xml_structure.py" else [])
            o = run(sys.executable, HERE / oracle, *args)
            check(o.returncode == 0, f"{mode}: {oracle} ({(o.stdout + o.stderr).strip()[-400:]})")
        # Feature 005: the private call's PCK, the CSK upload and download, the GKTPs, the MBMS
        # MSCCK and the pre-established session Connect (mikey_consistency.py: one pseudonym per
        # identity and key identifier across every carrier).
        o = run(sys.executable, HERE / "mikey_consistency.py", src, out, "--canaries", manifest, "--expect", "8")
        check(o.returncode == 0, f"{mode}: mikey_consistency ({(o.stdout + o.stderr).strip()[-400:]})")
        mk = rep.get("mikey", {})
        carriers = {k: v.get("rewritten") for k, v in mk.get("carriers", {}).items()}
        check(carriers == {"sdp": 2, "body": 3, "gktp": 2, "mcpc": 1}, f"{mode}: MIKEY carriers rewritten ({carriers})")
        check(mk.get("mki", {}).get("pseudonymised") == 31 and mk.get("mki", {}).get("unmatched") == 0,
              f"{mode}: 30 SRTP and 1 SRTCP MKIs pseudonymised ({mk.get('mki')})")
        # SC-008: the private call's MKI is the PCK-ID pseudonym of its I_MESSAGE.
        keys = set()
        for _, m in mc.carriers(str(out)) + mc.mcpc_carriers(str(out)):
            dm = mc.decode(m)
            if dm is not None and dm["csb"] >> 28 == 1:
                keys.add(dm["csb"].to_bytes(4, "big"))
        mkis = [p[-4:] for dport, p in demo_media(out) if dport in (40010, 40011)]
        check(len(mkis) == 31 and all(k in keys for k in mkis), f"{mode}: every MKI is a PCK-ID pseudonym of the output")
        r = run(sys.executable, CANARY, manifest, out, "--all")
        check(r.returncode == 0, f"{mode}: no identifying value survives {r.stdout.strip()[:300]}")
        r = run(exe, *data, "scan", "--project", "demo", "--deny-list", deny, out)
        check(r.returncode == 0, f"{mode}: independent scan of the output is clean")

    again = tmp / "anon-zero-2.pcapng"
    run(exe, *data, "anonymize", "--project", "demo", "--deny-list", deny, src, "-o", again)
    check("zero" in outputs and again.exists() and again.read_bytes() == outputs["zero"].read_bytes(),
          "second run gives an identical file")

    # Feature 004 (SC-003, SC-007): every media fixture, in the demo's project, twice; the two
    # outputs are byte-identical and every identity has one pseudonym (malformed, unannounced and
    # evicted packets are zeroed, FR-002).
    media_outputs = {}
    if fixture_dir is not None:
        media = sorted(p for p in fixture_dir.glob("*.pcapng") if p.name.split("_")[0] in ("rtp", "rtcp", "app", "msrp", "media"))
        check(len(media) >= 25, f"media fixtures present ({len(media)})")
        for f in media:
            o1, o2 = tmp / f"m1-{f.name}", tmp / f"m2-{f.name}"
            r1 = run(exe, *data, "anonymize", "--project", "demo", f, "-o", o1)
            r2 = run(exe, *data, "anonymize", "--project", "demo", f, "-o", o2)
            check(r1.returncode == 0 and r2.returncode == 0,
                  f"{f.name}: both runs publish ({r1.returncode}/{r2.returncode} "
                  f"{(r1.stderr + r2.stderr).strip()[-300:]})")
            if r1.returncode == 0 and r2.returncode == 0:
                check(o1.read_bytes() == o2.read_bytes(), f"{f.name}: the second run gives an identical file")
                media_outputs[f] = o1

    if shutil.which("tshark") is None:
        if os.environ.get("MCXANON_REQUIRE_TSHARK") == "1":
            check(False, "tshark required but missing")
        else:
            print("skip tshark not installed: decode check not run")
    else:
        for mode, out in outputs.items():
            r = run(sys.executable, DIFF, src, out, "--payload", mode, "--media", "--xml")
            check(r.returncode == 0, f"{mode}: no new tshark expert errors {r.stdout.strip()[:300]}")
            # Feature 004 (SC-001, SC-003): floor control unchanged, one pseudonym per identity.
            r = run(sys.executable, FLOOR, src, out)
            check(r.returncode == 0, f"{mode}: the floor control ladder is unchanged {r.stdout.strip()[-300:]}")
            r = run(sys.executable, CONSISTENCY, src, out)
            check(r.returncode == 0, f"{mode}: one pseudonym per SSRC and identity {r.stdout.strip()[-300:]}")
            # SC-001: the ladder over UDP, over TCP (User Story 4), and as a whole.
            for transport in ("udp", "tcp", None):
                extra = ["--transport", transport] if transport else []
                r = run(sys.executable, LADDER, src, out, *extra)
                check(r.returncode == 0,
                      f"{mode}: the SIP ladder over {transport or 'all transports'} is unchanged "
                      f"{r.stdout.strip()[-200:]}")

        for f, out in media_outputs.items():
            extra = ["--zeroed-ok"] if any(k in f.name for k in ("malformed", "unannounced", "evict")) else []
            r = run(sys.executable, CONSISTENCY, f, out, *extra)
            check(r.returncode == 0, f"{f.name}: one pseudonym per SSRC and identity {r.stdout.strip()[-300:]}")
            r = run(sys.executable, DIFF, f, out, "--payload", "zero", "--media")
            check(r.returncode == 0, f"{f.name}: no new tshark expert errors {r.stdout.strip()[:300]}")

sys.exit(1 if failures else 0)

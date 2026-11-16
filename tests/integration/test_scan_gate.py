#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""User story 2: the independent scanner blocks unsafe output.

Usage: test_scan_gate.py MCXANON MCXANON_LEAKTEST FIXTURE_DIR
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
exe, leak, fixtures = sys.argv[1], sys.argv[2], Path(sys.argv[3])
failures = 0


def check(name, cond, detail=""):
    global failures
    print(("ok   " if cond else "FAIL ") + name + ("" if cond else f"  {detail}"))
    failures += 0 if cond else 1


def valid(path):
    r = subprocess.run([sys.executable, str(HERE / "validate_report.py"), str(REPO / "schemas" / "report.schema.json"),
                        str(path)], capture_output=True, text=True)
    return r.returncode == 0, r.stderr


def no_canary(path):
    r = subprocess.run([sys.executable, str(HERE / "canary_absent.py"), str(fixtures / "canaries.json"), str(path),
                        "--all", "--report"], capture_output=True, text=True)
    return r.returncode == 0, r.stdout


with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    dd = tmp / "d"
    subprocess.run([exe, "--data-dir", str(dd), "project", "init", "g"], check=True, capture_output=True)

    # Variant a: the address is kept by a broken rule set.
    out = tmp / "a.pcap"
    r = subprocess.run([leak, str(dd), "g", str(fixtures / "basic_eth.pcap"), str(out), "a"], capture_output=True, text=True)
    check("leak (address): exit 1", r.returncode == 1, (r.returncode, r.stderr))
    check("leak (address): nothing published", not out.exists())
    rep = Path(str(out) + ".report.json")
    ok, err = valid(rep)
    check("leak (address): report valid", ok, err)
    data = json.loads(rep.read_text())
    check("leak (address): hits listed", len(data["scan"]["hits"]) > 0 and data["status"]["result"] == "leak_found", data["status"])
    check("leak (address): hits carry frame, offset, encoding", all(h["frame"] >= 1 and h["offset"] > 0 and h["encoding"]
                                                                     for h in data["scan"]["hits"]), data["scan"]["hits"][:3])
    ok, hits = no_canary(rep)
    check("leak (address): report free of originals", ok, hits)

    # Variant b: the comment is kept and the anonymiser does not report it; only the harvester knows.
    out = tmp / "b.pcapng"
    r = subprocess.run([leak, str(dd), "g", str(fixtures / "basic_meta.pcapng"), str(out), "b"], capture_output=True, text=True)
    check("leak (unreported comment): exit 1", r.returncode == 1, (r.returncode, r.stderr))
    check("leak (unreported comment): nothing published", not out.exists())
    data = json.loads(Path(str(out) + ".report.json").read_text())
    check("leak (unreported comment): caught by the input harvester",
          any(h["label"].startswith("input:") for h in data["scan"]["hits"]), data["scan"]["hits"][:3])

    # Variant c: the SIP layer keeps the original bytes; the text-category mapping tokens catch it.
    out = tmp / "c.pcapng"
    r = subprocess.run([leak, str(dd), "g", str(fixtures / "sip_udp_ipv4.pcapng"), str(out), "c"], capture_output=True, text=True)
    check("leak (SIP identities): exit 1", r.returncode == 1, (r.returncode, r.stderr))
    check("leak (SIP identities): nothing published", not out.exists())
    data = json.loads(Path(str(out) + ".report.json").read_text())
    labels = {h["label"][:2] for h in data["scan"]["hits"]}
    for prefix, what in (("u-", "user part"), ("n-", "display name"), ("c-", "Call-ID"), ("t-", "tag"),
                         ("d-", "domain label"), ("e-", "entity tag"), ("rt", "registration token")):
        check(f"leak (SIP identities): the {what} is found", prefix in labels, sorted(labels))
    check("leak (SIP identities): numbers and binary values are found",
          {"number", "binary"} <= {h["category"] for h in data["scan"]["hits"]},
          sorted({h["category"] for h in data["scan"]["hits"]}))
    ok, hits = no_canary(Path(str(out) + ".report.json"))
    check("leak (SIP identities): report free of originals", ok, hits)

    # Variant d: a leaky SIP rule set keeps Call-ID, From and To; only the SIP harvester knows.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools" / "fixturegen"))
    import sip as S  # noqa: E402  (the fixture builders; the values occur only in From, To, Call-ID)
    only = S.request("MESSAGE", "sip:x@example.net", [("Via", "SIP/2.0/UDP 10.9.0.1;branch=z9hG4bKgate1"),
                     ("From", "<sip:onlyhere.user@gate.example.net>;tag=g1"), ("To", "<sip:x@example.net>"),
                     ("Call-ID", "only-here-call-id-4711"), ("CSeq", "1 MESSAGE")])
    cap = S.Capture()
    cap.add(S.wrap(S.udp_packet(bytes([10, 9, 0, 1]), bytes([10, 9, 0, 2]), 5060, 5060, only)))
    leaky = tmp / "leaky-sip.pcapng"
    leaky.write_bytes(cap.bytes())
    out = tmp / "d.pcapng"
    r = subprocess.run([leak, str(dd), "g", str(leaky), str(out), "d"], capture_output=True, text=True)
    check("leak (SIP, unreported): exit 1", r.returncode == 1, (r.returncode, r.stderr))
    check("leak (SIP, unreported): nothing published", not out.exists())
    data = json.loads(Path(str(out) + ".report.json").read_text())
    labels = [h["label"] for h in data["scan"]["hits"]]
    check("leak (SIP, unreported): the user part is caught by the SIP harvester",
          any(l.startswith("input:sip-user") for l in labels), labels[:6])
    check("leak (SIP, unreported): the Call-ID is caught by the SIP harvester",
          any(l.startswith("input:call-id") for l in labels), labels[:6])

    # Feature 003 (FR-019, FR-017): the XML layer keeps the original bodies (test seam). An
    # original MCPTT ID that only an XML body carries is caught by the scanner's own XML
    # harvester: in an attribute, in text written with a character reference, and in the
    # URL-encoded body of a URI. (Embedded bodies of resource-lists entry URIs are decoded by
    # the harvester from User Story 2 on; until then the whole URI value is the token.)
    info = "urn:3gpp:ns:mcpttInfo:1.0"
    embedded = ("%3Cmcpttinfo%20xmlns%3D%22urn%3A3gpp%3Ans%3AmcpttInfo%3A1.0%22%3E%3CmcpttURI%3E"
                "sip%3Aembedded.only.user%40gate.example.net%3C%2FmcpttURI%3E%3C%2Fmcpttinfo%3E")
    xml_cases = {
        "attribute": f'<mcpttinfo xmlns="{info}"><mcptt-Params><v uri="sip:attr.only.user@gate.example.net"/>'
                     f'</mcptt-Params></mcpttinfo>',
        "char-ref": f'<mcpttinfo xmlns="{info}"><mcptt-Params><mcpttURI>sip:text.only.user&#x40;gate.example.net'
                    f'</mcpttURI></mcptt-Params></mcpttinfo>',
        "url-encoded": f'<mcpttinfo xmlns="{info}"><mcptt-Params><mcpttURI>sip:grp@gate.example.net?Content-Type='
                       f'application%2Fvnd.3gpp.mcptt-info%2Bxml&amp;body={embedded}</mcpttURI></mcptt-Params></mcpttinfo>',
        "removed-value": f'<mcpttinfo xmlns="{info}" xml:base="2026-11-14T10:00:00Z"/>',
    }
    for case, body in xml_cases.items():
        msg = S.request("MESSAGE", "sip:x@example.net", [("Via", "SIP/2.0/UDP 10.9.0.1;branch=z9hG4bKgatex"),
                        ("From", "<sip:sender@gate.example.net>;tag=gx"), ("To", "<sip:x@example.net>"),
                        ("Call-ID", f"xml-gate-{case}"), ("CSeq", "1 MESSAGE"),
                        ("Content-Type", "application/vnd.3gpp.mcptt-info+xml")], body.encode())
        cap = S.Capture()
        cap.add(S.wrap(S.udp_packet(bytes([10, 9, 0, 1]), bytes([10, 9, 0, 2]), 5060, 5060, msg)))
        inp = tmp / f"xml-{case}.pcapng"
        inp.write_bytes(cap.bytes())
        out = tmp / f"xml-{case}-out.pcapng"
        variant = "r" if case == "removed-value" else "x"
        r = subprocess.run([leak, str(dd), "g", str(inp), str(out), variant], capture_output=True, text=True)
        check(f"leak (XML, {case}): exit 1", r.returncode == 1, (r.returncode, r.stderr))
        check(f"leak (XML, {case}): nothing published", not out.exists())
        data = json.loads(Path(str(out) + ".report.json").read_text())
        labels = [h["label"] for h in data["scan"]["hits"]]
        want = "removed:" if case == "removed-value" else "input:"
        check(f"leak (XML, {case}): caught by the {'removed-value tokens' if want == 'removed:' else 'input harvest'}",
              any(l.startswith(want) for l in labels), labels[:6])

    # Report self-check: a deny-list word in the input file name is redacted from the report.
    named = tmp / "AcmeSecretCustomer.pcap"
    named.write_bytes((fixtures / "basic_eth.pcap").read_bytes())
    deny = tmp / "deny.txt"
    deny.write_text("# names\nAcmeSecret\n")
    r = subprocess.run([exe, "--data-dir", str(dd), "anonymize", "--project", "g", str(named), "-o", str(tmp / "n.pcap"),
                        "--deny-list", str(deny)], capture_output=True, text=True)
    check("deny word only in the file name: exit 0", r.returncode == 0, (r.returncode, r.stderr))
    rep_text = (tmp / "n.pcap.report.json").read_text()
    check("report redacts the file name", "AcmeSecret" not in rep_text and "(redacted)" in rep_text, rep_text[:300])

    # Standalone scan: deny-list words in ASCII mixed case and UTF-16 are hits.
    cap = tmp / "words.pcap"
    hdr = (fixtures / "basic_eth.pcap").read_bytes()[:24]
    payload = b"xx aCmEsEcReT yy " + "AcmeSecret".encode("utf-16-le")
    import struct
    cap.write_bytes(hdr + struct.pack("<IIII", 1, 0, len(payload), len(payload)) + payload)
    r = subprocess.run([exe, "--data-dir", str(dd), "scan", "--project", "g", str(cap), "--deny-list", str(deny)],
                       capture_output=True, text=True)
    check("scan: deny words found, exit 1", r.returncode == 1, (r.returncode, r.stderr))
    data = json.loads(Path(str(cap) + ".scan.json").read_text())
    encs = {h["encoding"] for h in data["scan"]["hits"]}
    check("scan: ASCII (any case) and UTF-16 hits", {"text", "utf16le"} <= encs, encs)
    check("scan: hit label is the deny-list line", all(h["label"] == "deny#2" for h in data["scan"]["hits"]))
    check("scan: report has no deny word", "AcmeSecret" not in Path(str(cap) + ".scan.json").read_text().replace("acmesecret", ""))
    ok, err = valid(Path(str(cap) + ".scan.json"))
    check("scan: report valid", ok, err)

    # Standalone scan of a clean anonymised output: exit 0.
    clean = tmp / "clean.pcap"
    subprocess.run([exe, "--data-dir", str(dd), "anonymize", "--project", "g", str(fixtures / "basic_eth.pcap"), "-o", str(clean)],
                   check=True, capture_output=True)
    r = subprocess.run([exe, "--data-dir", str(dd), "scan", "--project", "g", str(clean)], capture_output=True, text=True)
    check("scan of a clean output: exit 0", r.returncode == 0, (r.returncode, r.stderr))
    data = json.loads(Path(str(clean) + ".scan.json").read_text())
    check("scan report: suppressed_chance_matches present", "suppressed_chance_matches" in data["scan"])
    # Scanning the raw input finds the originals.
    r = subprocess.run([exe, "--data-dir", str(dd), "scan", "--project", "g", str(fixtures / "basic_eth.pcap"),
                        "--report", str(tmp / "raw.scan.json")], capture_output=True, text=True)
    check("scan of the raw input: exit 1", r.returncode == 1, (r.returncode, r.stderr))
    # Bad deny-list: usage error.
    bad = tmp / "bad.txt"
    bad.write_text("ab\n")
    r = subprocess.run([exe, "--data-dir", str(dd), "anonymize", "--project", "g", str(fixtures / "basic_eth.pcap"),
                        "-o", str(tmp / "bad.pcap"), "--deny-list", str(bad)], capture_output=True, text=True)
    check("short deny-list entry: exit 2", r.returncode == 2, (r.returncode, r.stderr))
sys.exit(1 if failures else 0)

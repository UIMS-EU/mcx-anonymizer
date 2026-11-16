#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Feature 007 demo oracle: the README demo capture with its HTTP and TLS parts
(OpenID Connect at the IdMS, XCAP at the CMS and GMS, the GMS over TLS 1.2 with its certificate
chain, the KMS over TLS 1.3) anonymised in both payload modes.

- SC-001: every HTTP message and TLS handshake message tshark decodes in the input is decoded in
  the output, per connection and in order; no new error-level expert entry.
- SC-003: one pseudonym per identity across SIP, XCAP request URIs, JWT claims, server names and
  certificates: the MC user's SIP user part, the MC ID in the token's `sub` claim and the user in
  the XCAP path are one pseudonym; the MCX domain is one pseudonym in SIP hosts, HTTP hosts, server
  names and certificate names; the group identity is one pseudonym in SIP and in the GMS path.
- SC-004: the analyst's questions are answerable from the output: methods, status codes, content
  types, XCAP AUIDs, the OAuth grant and token types and scopes, TLS versions, cipher suites,
  extension types, certificate validity and key usage, and the record layer stay as they were.

Usage: test_web_demo.py MCXANON
"""
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
GEN = REPO / "tools" / "fixturegen" / "mcx_demo.py"
DIFF = REPO / "tools" / "tshark-expert-diff.py"

if shutil.which("tshark") is None:
    if os.environ.get("MCXANON_REQUIRE_TSHARK") == "1":
        print("FAIL tshark is required (MCXANON_REQUIRE_TSHARK=1) but not found")
        sys.exit(1)
    print("skip: tshark not found")
    sys.exit(77)

exe = sys.argv[1]
failures = []
DECODE = ["-d", "tcp.port==8080,http"]


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def run(*args, **kw):
    return subprocess.run([str(a) for a in args], capture_output=True, text=True, **kw)


def fields(path, flt, *names):
    r = run("tshark", "-n", "-r", path, *DECODE, "-Y", flt, "-T", "fields", "-E", "separator=|",
            *sum((["-e", n] for n in names), []))
    return [line.split("|") for line in r.stdout.splitlines()]


def per_stream(rows):
    out = {}
    for r in rows:
        s = out.setdefault(r[0], [[] for _ in r[1:]])
        for i, v in enumerate(r[1:]):
            s[i] += [x for x in v.split(",") if x]
    return out


def subsequence(a, b):
    it = iter(b)
    return all(x in it for x in a)


def jwt_claims(token):
    try:
        p = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    except (IndexError, ValueError):
        return {}


with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    data = ["--data-dir", tmp / "data"]
    check(run(sys.executable, GEN, "--out", tmp).returncode == 0, "demo generator runs")
    src = tmp / "mcx_demo.pcapng"
    check(run(exe, *data, "project", "init", "demo").returncode == 0, "project init")
    for mode in ("zero", "drop"):
        out = tmp / f"anon-{mode}.pcapng"
        r = run(exe, *data, "anonymize", "--project", "demo", "--payload", mode, src, "-o", out)
        check(r.returncode == 0, f"({mode}) publishes ({r.stderr.strip()[-200:]})")
        if r.returncode != 0:
            continue
        rep = json.loads(Path(str(out) + ".report.json").read_text())
        h, t = rep.get("http", {}), rep.get("tls", {})
        check(h.get("messages", 0) >= 20 and h.get("oauth_messages", 0) >= 4,
              f"({mode}) HTTP and OAuth messages counted ({h.get('messages')}, {h.get('oauth_messages')})")
        check(t.get("certificates_rewritten", 0) == 2 and t.get("connections", 0) >= 4,
              f"({mode}) TLS connections and both certificates counted ({t.get('connections')}, {t.get('certificates_rewritten')})")

        # SC-001: HTTP messages and TLS handshake messages per connection.
        names = ("tcp.stream", "http.request.method", "http.response.code", "tls.handshake.type",
                 "tls.handshake.version", "tls.handshake.ciphersuite", "tls.handshake.extension.type")
        before, after = per_stream(fields(src, "http || tls", *names)), per_stream(fields(out, "http || tls", *names))
        empty = [[] for _ in names[1:]]
        bad = [(k, names[i + 1]) for k, v in before.items() for i in range(len(names) - 1)
               if not (subsequence(v[i], after.get(k, empty)[i]) if i == 2 else v[i] == after.get(k, empty)[i])]
        check(before and not bad, f"({mode}) every HTTP message and TLS handshake message decodes in the output ({bad[:3]})")
        d = run(sys.executable, DIFF, src, out, "--payload", mode)
        check(d.returncode == 0, f"({mode}) no new expert errors ({d.stdout.strip()[-300:]})")

        # SC-003: one pseudonym per identity across the carriers.
        reg = fields(out, "sip.Method==REGISTER", "sip.from.user", "sip.from.host")
        user, domain = reg[0] if reg and len(reg[0]) == 2 else ("?", "?")
        uris = [r[0] for r in fields(out, "http.request", "http.request.uri")]
        xcap_users = {m.group(1) for u in uris for m in [re.search(r"/users/sip:([^@/]+)@([^/]+)/", u)] if m}
        xcap_hosts = {m.group(2) for u in uris for m in [re.search(r"/users/sip:([^@/]+)@([^/]+)/", u)] if m}
        check(xcap_users == {user} and xcap_hosts == {domain},
              f"({mode}) the XCAP user is the SIP user ({xcap_users}, {xcap_hosts} vs {user}@{domain})")
        tokens = [v.split(" ", 1)[1] for r in fields(out, "http.authorization", "http.authorization")
                  for v in r if v.startswith("Bearer ")]
        claims = [jwt_claims(x) for x in tokens]
        check(claims and all(c.get("sub") == user for c in claims),
              f"({mode}) the MC ID in the token's sub claim is the SIP user ({[c.get('sub') for c in claims][:2]})")
        check(claims and all(c.get("mcptt_id") == f"sip:{user}@{domain}" for c in claims),
              f"({mode}) the MCPTT ID claim is the SIP URI ({[c.get('mcptt_id') for c in claims][:1]})")
        hosts = {r[0].split(":")[0] for r in fields(out, "http.request", "http.host")}
        sni = {r[0] for r in fields(out, "tls.handshake.type==1", "tls.handshake.extensions_server_name")}
        names_ = {x for r in fields(out, "tls.handshake.type==11", "x509ce.dNSName") for x in r[0].split(",")}
        check(hosts and sni and names_ and all(x.endswith("." + domain) for x in hosts | sni | names_),
              f"({mode}) the MCX domain is one pseudonym in HTTP hosts, server names and certificates")
        check(names_ <= sni, f"({mode}) the certificate names the server the client asked for ({names_} {sni})")
        groups = {m.group(1) for u in uris for m in [re.search(r"/byGroupID/(sip:[^/?]+)", u)] if m}
        sip_text = run("tshark", "-n", "-r", out, "-Y", "sip", "-V").stdout
        check(len(groups) == 2 and all(g in sip_text for g in groups),
              f"({mode}) the group identities in the GMS path are the ones in SIP ({groups})")

        # SC-004: the analyst's questions.
        for flt, f in (("http.request", "http.request.method"), ("http.response", "http.response.code"),
                       ("http", "http.content_type"), ("tls.handshake", "tls.handshake.ciphersuite"),
                       ("tls.handshake", "tls.handshake.extensions_supported_group"),
                       ("tls.handshake.type==11", "x509af.utcTime"), ("tls.handshake.type==11", "x509ce.cA"),
                       ("tls", "tls.record.length")):
            a, b = fields(src, flt, f), fields(out, flt, f)
            if f == "http.content_type":  # parameters are written without the optional whitespace (RFC 9110 §5.6.6)
                a, b = ([[re.sub(r"\s*;\s*", ";", x) for x in r] for r in rows] for rows in (a, b))
            # Record lengths change where records are re-fragmented or the handshake re-encoded:
            # compare the protected records only.
            if f == "tls.record.length":
                a, b = fields(src, "tls.record.content_type==23", f), fields(out, "tls.record.content_type==23", f)
            check(a == b, f"({mode}) {f} unchanged ({len(a)} rows)")
        auids = {u.split("/")[2] for u in uris if u.count("/") > 3 and "org." in u}
        check({"org.3gpp.mcptt.ue-config", "org.3gpp.mcptt.user-profile", "org.openmobilealliance.groups"} <= auids,
              f"({mode}) XCAP AUIDs kept ({sorted(auids)})")
        forms = " ".join(r[0] for r in fields(out, "http.request.method==POST", "http.file_data"))
        check("grant_type=authorization_code" in bytes.fromhex(forms.replace(" ", "")).decode(errors="replace")
              if re.fullmatch(r"[0-9a-f ]*", forms) else "grant_type=authorization_code" in forms,
              f"({mode}) the OAuth grant type is kept")

print(f"{len(failures)} failure(s)")
sys.exit(1 if failures else 0)

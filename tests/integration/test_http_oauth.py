#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Feature 007 User Story 2 (FR-011 to FR-017, SC-002): the IdMS, HTTP authentication and KMS
fixtures (web_oauth, web_auth, web_kms) are anonymised with --time-shift; no canary survives in any
encoding the oracle decodes itself (URL encoding, base64url JWT segments, JSON strings); the flow
stays readable (grant types, scopes, token type, expiry, status codes); JWTs keep their structure
with a zero signature; KMS key material is absent, public keys zeroed and times shifted.

Usage: test_http_oauth.py MCXANON FIXTURE_DIR
"""
import base64
import json
import re
import subprocess
import sys
import tempfile
import urllib.parse
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CANARY = REPO / "tests" / "integration" / "canary_absent.py"
exe, fixtures = sys.argv[1], Path(sys.argv[2])
failures = []


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def run(*args):
    return subprocess.run([str(a) for a in args], capture_output=True)


def b64url(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def decoded_views(data):
    """The output as bytes, URL-decoded, and with every JWT segment and JSON string decoded."""
    text = data.decode("latin-1")
    views = [text, urllib.parse.unquote_plus(text)]
    for m in re.finditer(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", text):
        for seg in m.group(0).split(".")[:2]:
            try:
                views.append(b64url(seg).decode("latin-1"))
            except Exception:
                pass
    return views


canaries = json.loads((fixtures / "canaries.json").read_text())["canaries"]
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    data = ["--data-dir", tmp / "data"]
    check(run(exe, *data, "project", "init", "t").returncode == 0, "project init")
    for name in ("web_oauth.pcapng", "web_auth.pcapng", "web_kms.pcapng", "web_http_coverage.pcapng"):
        inp = fixtures / name
        out = tmp / name
        r = run(exe, *data, "anonymize", "--project", "t", "--time-shift", "+1h", inp, "-o", out)
        check(r.returncode == 0, f"{name} publishes ({r.stderr.decode()[-200:]})")
        if r.returncode != 0:
            continue
        c = run(sys.executable, CANARY, fixtures / "canaries.json", out, "--source", name)
        check(c.returncode == 0, f"{name} no canary in the raw encodings ({c.stdout.decode()[-300:]})")
        blob = out.read_bytes()
        views = decoded_views(blob)
        mine = [x for x in canaries if name in x["files"] and x["category"] == "string"]
        leaked = [x["value"] for x in mine if any(x["value"].lower() in v.lower() for v in views)]
        check(not leaked, f"{name} no canary in the decoded encodings ({leaked[:5]})")
        rep = json.loads(Path(str(out) + ".report.json").read_text())
        h = rep.get("http", {})
        text = urllib.parse.unquote_plus(blob.decode("latin-1"))
        if name == "web_oauth.pcapng":
            for kept in ("grant_type=authorization_code", "response_type=code", "code_challenge_method=S256",
                         '"token_type":"Bearer"', '"expires_in":3600', "openid 3gpp:mc:ptt_service",
                         "grant_type=urn:ietf:params:oauth:grant-type:token-exchange", '"error":"invalid_grant"'):
                check(kept in text, f"oauth flow readable: {kept}")
            check("code_verifier=&" in text or "code_verifier=" in text, "the credential parameter name stays")
            jwts = re.findall(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", blob.decode("latin-1"))
            check(len(jwts) >= 2, f"JWTs keep their structure ({len(jwts)})")
            for t in jwts[:2]:
                hdr, claims, sig = t.split(".")
                check(set(b64url(sig)) <= {0}, "JWT signature zeroed")
                cl = json.loads(b64url(claims))
                check(cl.get("mcptt_id", "").startswith("sip:u-"), "mcptt_id is a SIP pseudonym")
                check(cl.get("exp") == 1791963735 + 3600, "exp shifted by --time-shift")
                check("auth_time" not in cl and "secret_claim" not in cl, "unsourced and unknown claims removed")
            check(h.get("tokens", {}).get("jwt", 0) >= 2 and h.get("tokens", {}).get("opaque", 0) >= 1, f"token counters ({h.get('tokens')})")
            check(h.get("credentials_removed", {}).get("password", 0) >= 1, "password counted as a removed credential")
            check("jwt-signatures-invalidated" in rep["not_anonymised"], "statement: JWT signatures invalidated")
        if name == "web_auth.pcapng":
            check("Authorization: Basic\r\n" in blob.decode("latin-1"), "Basic keeps the scheme only")
            check("qop=auth" in text and "Digest " in text, "Digest structure readable")
            check(h.get("cookie_values_removed", 0) >= 2, "cookie values removed")
        if name == "web_kms.pcapng":
            check("<UserDecryptKey" not in text and "<UserSigningKeySSK" not in text, "user key sets removed")
            check(re.search(r"<PubEncKey>0+</PubEncKey>", text) is not None, "public KMS key zeroed with its length")
            check("2026-11-15T11:00:00Z" in text, "KMS Time shifted")
            check("/keymanagement/identity/v1/keyprov/sip%3Au-" in blob.decode("latin-1"), "KMS path kept, user mapped like SIP")
print(f"{len(failures)} failure(s)")
sys.exit(1 if failures else 0)

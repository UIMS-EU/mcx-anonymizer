# SPDX-License-Identifier: GPL-3.0-or-later
"""HTTP and TLS fixtures of feature 007 (synthetic only).

Every identity, credential and key value is a canary with the HTTP or TLS rule key that
classifies it:
  http:<Header>             a header field rule (rules/http.yaml)
  http-target:<part>        a part of a request target: user (XCAP user part), segment (an
                            opaque path segment), host (an absolute-form or CONNECT host)
  http-param:<name>         a query, form or JSON parameter (rules/http-oauth.yaml)
  jwt:<claim>               a JWT claim; jwt-header:<member>; jwt:signature
  http-body:<content-type>  a body removed because no rule has its type
  cookie:name, cookie:value a Cookie or Set-Cookie pair
The h2c and TLS builders live in this module too.
"""
import re
import struct

import hpack
import sip as S

MSS = 1400
CLIENT = bytes([10, 7, 0, 10])
SERVER = bytes([10, 7, 0, 20])
PROXY = bytes([10, 7, 0, 30])


class _Cv(S._Cv):
    """Canaries of one fixture file."""

    def user(self, rule):
        return self.c.string(None, self.f, "cnry", rule=rule).lower()


def http_request(method, target, headers, body=b"", content_length=True):
    lines = [f"{method} {target} HTTP/1.1"] + [f"{k}: {v}" for k, v in headers]
    if body and content_length:
        lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def http_response(code, reason, headers, body=b"", content_length=True):
    lines = [f"HTTP/1.1 {code} {reason}"] + [f"{k}: {v}" for k, v in headers]
    if content_length:
        lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def chunked(body, size=17, ext=False):
    out = b""
    for i in range(0, len(body), size):
        part = body[i:i + size]
        out += f"{len(part):x}{';x=1' if ext else ''}\r\n".encode() + part + b"\r\n"
    return out + b"0\r\n\r\n"


def resource_list(entries):
    items = "".join(f'<entry uri="{u}"><display-name>{d}</display-name></entry>' for u, d in entries)
    return ('<?xml version="1.0" encoding="UTF-8"?>'
            '<resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists"><list>'
            f'{items}</list></resource-lists>').encode()


class Flow:
    """One TCP connection with a capture: messages from the client (0) or the server (1),
    each cut into segments of at most `mss` octets."""

    def __init__(self, cap, a=CLIENT, b=SERVER, aport=40001, bport=80, isn=(1000, 500000)):
        self.cap = cap
        self.t = S.TcpConn(a, b, aport, bport, isn)
        cap.extend(self.t.handshake())

    def send(self, d, data, mss=MSS):
        for i in range(0, len(data), mss):
            self.cap.add(self.t.send(d, data[i:i + mss]))
        self.cap.add(self.t.ack(1 - d))

    def close(self):
        self.cap.add(self.t.fin(0))
        self.cap.add(self.t.fin(1))


def _write(cap, out, name):
    with open(f"{out}/{name}", "wb") as fh:
        fh.write(cap.bytes())


def gen_xcap(c, out):
    """XCAP over HTTP/1.1 (US1): GET of a user profile document, PUT of a resource list,
    DELETE, a 404, conditional requests with ETags, unknown headers and an unknown body."""
    name = "web_xcap.pcapng"
    v = _Cv(c, name)
    cap = S.Capture()
    f = Flow(cap)
    user = f"sip:{v.user('http-target:user')}@{v.label('http:Host')}.example.org"
    enc = user.replace(":", "%3A").replace("@", "%40")
    host = f"{v.label('http:Host')}.example.org"
    etag = v.s("http:ETag", "etag")
    xui_doc = f"/xcap-root/org.3gpp.mcptt.user-profile/users/{enc}/mcptt-user-profile-0.xml"
    f.send(0, http_request("GET", xui_doc, [("Host", host), ("Accept", "application/vnd.3gpp.mcptt-user-profile+xml"),
                                             ("User-Agent", v.s("http:User-Agent")),
                                             ("X-Custom-Thing", v.s("http-header:unknown"))]))
    members = [(f"sip:{v.user('xml:urn:ietf:params:xml:ns:resource-lists|entry|@-|uri')}@example.org",
                v.s("xml:urn:ietf:params:xml:ns:resource-lists|entry|display-name", "Name")) for _ in range(2)]
    f.send(1, http_response(200, "OK", [("Content-Type", "application/resource-lists+xml"), ("ETag", f'"{etag}"'),
                                        ("Server", v.s("http:Server")), ("Date", "Sun, 15 Nov 2026 10:00:00 GMT")],
                            resource_list(members)))
    rl = f"/org.3gpp.mcptt.user-profile/users/{enc}/index/~~/resource-lists/list"
    f.send(0, http_request("PUT", rl, [("Host", host), ("Content-Type", "application/resource-lists+xml"),
                                        ("If-Match", f'"{etag}"')], resource_list(members)))
    f.send(1, http_response(201, "Created by " + v.s("http:reason"), [("ETag", f'"{v.s("http:ETag", "etag")}"')]))
    f.send(0, http_request("DELETE", f"/opaque/{v.s('http-target:segment', 'seg')}/doc.xml", [("Host", host)]))
    f.send(1, http_response(404, "Not Found", [("Content-Type", "application/octet-stream")],
                            v.s("http-body:application/octet-stream").encode()))
    f.close()
    _write(cap, out, name)


def gen_framing(c, out):
    """Framing (US1 scenario 3, 5; edge cases): a message split across segments, pipelined
    requests in one segment, a chunked body rewritten and one removed, a gzip body, a HEAD
    response with Content-Length, a 204, a response that runs to the connection end, and a
    retransmitted segment."""
    name = "web_framing.pcapng"
    v = _Cv(c, name)
    cap = S.Capture()
    f = Flow(cap, aport=40002)
    host = f"{v.label('http:Host')}.example.net"
    members = [(f"sip:{v.user('xml:urn:ietf:params:xml:ns:resource-lists|entry|@-|uri')}@example.net", "x")]
    doc = resource_list(members)
    f.send(0, http_request("GET", "/a", [("Host", host)]) + http_request("HEAD", "/b", [("Host", host)]))
    f.send(1, http_response(200, "OK", [("Content-Type", "application/resource-lists+xml")], doc), mss=40)
    f.send(1, b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n")  # HEAD: no body
    f.send(0, http_request("GET", "/c", [("Host", host)]))
    f.send(1, b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/resource-lists+xml\r\n\r\n"
           + chunked(doc, ext=True))
    f.send(0, http_request("GET", "/d", [("Host", host)]))
    f.send(1, b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\n\r\n"
           + chunked(v.s("http-body:application/octet-stream").encode() * 3))
    f.send(0, http_request("GET", "/e", [("Host", host)]))
    f.send(1, http_response(200, "OK", [("Content-Type", "application/resource-lists+xml"), ("Content-Encoding", "gzip")],
                            b"\x1f\x8b\x08\x00" + v.s("http-body:gzip").encode()))
    f.send(0, http_request("DELETE", "/f", [("Host", host)]))
    f.send(1, b"HTTP/1.1 204 No Content\r\n\r\n")
    # A retransmission of the next request's first segment.
    req = http_request("GET", "/g", [("Host", host)])
    seq = f.t.next[0]
    cap.add(f.t.send(0, req))
    cap.add(f.t.send(0, req, seq=seq))
    cap.add(f.t.ack(1))
    f.send(1, b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n" + v.s("http-body:to-close").encode())
    f.close()
    _write(cap, out, name)


def gen_ports(c, out):
    """HTTP on the SIP port beside a SIP connection on the same port (edge case), a response
    whose request was not captured, and a WebSocket upgrade whose frames are zeroed."""
    name = "web_ports.pcapng"
    v = _Cv(c, name)
    cap = S.Capture()
    host = f"{v.label('http:Host')}.example.com"
    sipc = Flow(cap, aport=41000, bport=5060)
    sipc.send(0, S.request("OPTIONS", "sip:example.com", [("Via", "SIP/2.0/TCP 10.7.0.10:41000;branch=z9hG4bK77"),
                                                         ("From", "<sip:a@example.com>;tag=1"), ("To", "<sip:a@example.com>"),
                                                         ("Call-ID", "cid1"), ("CSeq", "1 OPTIONS"), ("Max-Forwards", "70")]))
    sipc.close()
    h = Flow(cap, aport=41001, bport=5060)
    h.send(0, http_request("GET", "/x", [("Host", host)]))
    h.send(1, http_response(200, "OK", [("Content-Type", "text/plain")], v.s("http-body:text/plain").encode()))
    h.close()
    # The capture starts after the request: only the response is seen.
    late = Flow(cap, aport=41002, bport=8080)
    late.send(1, http_response(200, "OK", [("Content-Type", "application/resource-lists+xml")],
                               resource_list([(f"sip:{v.user('xml:urn:ietf:params:xml:ns:resource-lists|entry|@-|uri')}@example.com", "y")])))
    late.close()
    ws = Flow(cap, aport=41003, bport=80)
    ws.send(0, http_request("GET", "/ws", [("Host", host), ("Upgrade", "websocket"), ("Connection", "Upgrade"),
                                           ("Sec-WebSocket-Key", v.s("http:Sec-WebSocket-Key")), ("Sec-WebSocket-Version", "13")]))
    ws.send(1, http_response(101, "Switching Protocols", [("Upgrade", "websocket"), ("Connection", "Upgrade")], content_length=False))
    ws.send(0, b"\x81\x05" + v.s("http-body:websocket").encode()[:5])
    ws.close()
    _write(cap, out, name)


# --- HTTP/2 in the clear (RFC 9113) ---------------------------------------------------------
H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
DATA, HEADERS, PRIORITY, RST, SETTINGS, PUSH, PING, GOAWAY, WINDOW, CONT = range(10)


def h2frame(ftype, flags, stream, payload):
    return struct.pack("!I", len(payload))[1:] + bytes([ftype, flags]) + struct.pack("!I", stream) + payload


def h2_headers(enc, stream, fields, end_stream=False, split=None, padded=False, priority=False):
    """A header block, optionally split into HEADERS + CONTINUATION at `split` octets."""
    block = enc.encode(fields)
    flags = 0x1 if end_stream else 0
    first, rest = (block, b"") if split is None else (block[:split], block[split:])
    pre = b""
    if priority:
        flags |= 0x20
        pre = struct.pack("!IB", 0, 15)
    if padded:
        flags |= 0x8
        payload = bytes([3]) + pre + first + b"\x00" * 3
    else:
        payload = pre + first
    if not rest:
        return h2frame(HEADERS, flags | 0x4, stream, payload)
    return h2frame(HEADERS, flags, stream, payload) + h2frame(CONT, 0x4, stream, rest)


def gen_h2(c, out):
    """h2c with prior knowledge (US1, FR-002): SETTINGS, a request with a header block split
    into CONTINUATION, a response whose XML body spans two DATA frames (one padded), a body without
    a rule, PING and GOAWAY opaque data, an unknown frame type; and an h2c Upgrade."""
    name = "web_h2.pcapng"
    v = _Cv(c, name)
    cap = S.Capture()
    f = Flow(cap, aport=42001, bport=80)
    ce, se = hpack.Encoder(), hpack.Encoder()
    host = f"{v.label('http:Host')}.example.org"
    user = f"sip:{v.user('http-target:user')}@example.org".replace(":", "%3A").replace("@", "%40")
    req = [(":method", "GET"), (":scheme", "http"), (":authority", host),
           (":path", f"/org.3gpp.mcptt.user-profile/users/{user}/mcptt-user-profile-0.xml"),
           ("user-agent", v.s("http:User-Agent")), ("x-secret-thing", v.s("http-header:unknown"))]
    f.send(0, H2_PREFACE + h2frame(SETTINGS, 0, 0, struct.pack("!HI", 1, 4096) + struct.pack("!HI", 0xA0A0, 7))
           + h2_headers(ce, 1, req, end_stream=True, split=10, priority=True))
    doc = resource_list([(f"sip:{v.user('xml:urn:ietf:params:xml:ns:resource-lists|entry|@-|uri')}@example.org",
                          v.s("xml:urn:ietf:params:xml:ns:resource-lists|entry|display-name", "Name"))])
    resp = [(":status", "200"), ("content-type", "application/resource-lists+xml"), ("content-length", str(len(doc))),
            ("server", v.s("http:Server")), ("etag", '"' + v.s("http:ETag", "etag") + '"')]
    f.send(1, h2frame(SETTINGS, 0, 0, b"") + h2frame(SETTINGS, 1, 0, b"") + h2_headers(se, 1, resp, padded=True)
           + h2frame(DATA, 0x8, 1, bytes([4]) + doc[:50] + b"\x00" * 4) + h2frame(DATA, 0x1, 1, doc[50:]))
    # Stream 3: the same request again (indexed from the dynamic table), a body without a rule.
    f.send(0, h2frame(SETTINGS, 1, 0, b"") + h2_headers(ce, 3, req, end_stream=True))
    f.send(1, h2_headers(se, 3, [(":status", "200"), ("content-type", "application/octet-stream")])
           + h2frame(DATA, 0x1, 3, v.s("http-body:application/octet-stream").encode())
           + h2frame(PING, 0, 0, v.s("http:h2-ping", "pg")[:8].encode())
           + h2frame(WINDOW, 0, 0, struct.pack("!I", 65535))
           + h2frame(0xFA, 0, 0, v.s("http:h2-unknown-frame").encode())
           + h2frame(GOAWAY, 0, 0, struct.pack("!II", 3, 0) + v.s("http:h2-goaway-debug").encode()))
    f.close()
    # h2c through an HTTP/1.1 Upgrade (RFC 9113 §3.1 deprecates it; still recognised).
    u = Flow(cap, aport=42002, bport=80)
    ue, us = hpack.Encoder(), hpack.Encoder()
    u.send(0, http_request("GET", "/org.3gpp.mcptt.user-profile/global/index", [("Host", host), ("Connection", "Upgrade, HTTP2-Settings"),
                                                                               ("Upgrade", "h2c"), ("HTTP2-Settings", "AAMAAABkAAQAAP__")]))
    u.send(1, b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n"
           + h2frame(SETTINGS, 0, 0, b"")
           + h2_headers(us, 1, [(":status", "200"), ("content-type", "application/resource-lists+xml")])
           + h2frame(DATA, 0x1, 1, doc))
    u.send(0, H2_PREFACE + h2frame(SETTINGS, 0, 0, b"") + h2frame(SETTINGS, 1, 0, b""))
    u.close()
    _write(cap, out, name)


# --- XML rule coverage of the CMS, GMS and KMS documents ---------------------
_RULE_LINE = re.compile(r"^\s*- \{(.*)\}\s*$")
_FIELD = re.compile(r"(\w+): (\[[^\]]*\]|\{[^}]*\}|\"[^\"]*\"|[^,]+)")


def _rules(path):
    """The documents and namespaces of an XML rule file written in one-line flow mappings."""
    docs, ns, cur, section = [], {}, None, None
    lines = open(path, encoding="utf-8").read().splitlines()
    for i, line in enumerate(lines):
        m = re.match(r'^  - name: "([^"]+)"', line)
        if m:
            cur = ns.setdefault(m.group(1), {"elements": [], "attributes": []})
            continue
        if line.startswith("  - content_type:"):
            ct = line.split(":", 1)[1].strip()
            roots = re.findall(r'\{ns: "([^"]+)", name: ([\w.-]+)\}', lines[i + 1])
            docs.append((ct, roots))
            continue
        if line.strip() == "elements:":
            section = "elements"
            continue
        if line.strip() == "attributes:":
            section = "attributes"
            continue
        if line.strip() == "prefixes:":
            section = None  # feature 008: namespace prefixes, no element or attribute rules
            continue
        m = _RULE_LINE.match(line)
        if m and cur is not None and section:
            f = {k: v.strip() for k, v in _FIELD.findall(m.group(1))}
            cur[section].append(f)
    return docs, ns


def _value(v, key, category):
    if category == "web-uri":
        return f"sip:{v.user(key)}@example.org"
    if category == "ip":
        return v.ip(key)
    if category == "display-name":
        return v.s(key, "Name")
    return v.s(key, "cnry")


def _xml_doc(v, ns, local, nsr, extra):
    """A document whose root is (ns, local), with every non-keep rule of `nsr` and of the
    `extra` namespaces carrying a canary."""
    attrs, body = [], []
    for a in nsr["attributes"]:
        if a.get("action") in ("keep", "container") or a["element"] != local:
            continue
        key = f"xml:{ns}|{local}|@-|{a['name']}"
        attrs.append(f' {a["name"]}="{_value(v, key, a.get("category"))}"')

    def items(uri, rules, prefix):
        out = []
        for e in rules["elements"]:
            if e.get("action") in ("keep", "container"):
                continue
            parents = [p.strip() for p in e.get("parent", "[]").strip("[]").split(",") if p.strip()]
            for parent in parents or ["-"]:
                key = f"xml:{uri}|{parent}|{e['name']}"
                val = v.hexs(key, 32) if e.get("action") == "zero" else _value(v, key, e.get("category"))
                el = f"<{prefix}{e['name']}>{val}</{prefix}{e['name']}>"
                out.append(el if parent == "-" else f"<{prefix}{parent}>{el}</{prefix}{parent}>")
        for a in rules["attributes"]:
            if a.get("action") in ("keep", "container") or a["element"] == local and not prefix:
                continue
            key = f"xml:{uri}|{a['element']}|@-|{a['name']}"
            out.append(f'<{prefix}{a["element"]} {a["name"]}="{_value(v, key, a.get("category"))}"/>')
        return out

    body += items(ns, nsr, "")
    decls = ""
    for i, (uri, rules) in enumerate(extra):
        decls += f' xmlns:x{i}="{uri}"'
        body += items(uri, rules, f"x{i}:")
    return (f'<?xml version="1.0" encoding="UTF-8"?><{local} xmlns="{ns}"{decls}{"".join(attrs)}>'
            + "".join(body) + f"</{local}>").encode()


def gen_xml_coverage(c, out):
    """One HTTP response per CMS, GMS and KMS document type with a canary in every element and
    attribute that a rule pseudonymises, removes or zeroes (rules/xml-cms.yaml, xml-gms.yaml,
    xml-kms.yaml). Namespaces without a document of their own ride in a related document."""
    name = "web_xml_coverage.pcapng"
    v = _Cv(c, name)
    cap = S.Capture()
    f = Flow(cap, aport=43001, bport=80)
    rules_dir = __import__("os").path.join(__import__("os").path.dirname(__file__), "..", "..", "rules")
    host_of = {"urn:3gpp:ns:mcpttGroupInfo:1.0": "urn:oma:xml:poc:list-service",
               "urn:3gpp:ns:mcsecKMSKRR:1.0": "urn:3gpp:ns:mcsecKMSInterface:1.0"}
    for fname in ("xml-cms.yaml", "xml-gms.yaml", "xml-kms.yaml"):
        docs, ns = _rules(f"{rules_dir}/{fname}")
        done = set()
        for ct, roots in docs:
            for rns, rlocal in roots[:1]:
                if rns in done:
                    continue
                done.add(rns)
                extra = [(u, r) for u, r in ns.items() if host_of.get(u) == rns]
                body = _xml_doc(v, rns, rlocal, ns[rns], extra)
                f.send(0, http_request("GET", "/doc", [("Host", "cms.example.org")]))
                f.send(1, http_response(200, "OK", [("Content-Type", ct)], body))
    f.close()
    _write(cap, out, name)


# --- OAuth / OIDC, HTTP authentication and KMS (User Story 2) ---------------------------------
import base64 as _b64
import json as _json


def b64url(b):
    return _b64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jwt(header, claims, sig_len=64, rng=None):
    sig = bytes((rng.randrange(256) if rng else 0x5A) for _ in range(sig_len))
    return (b64url(_json.dumps(header, separators=(",", ":")).encode()) + "." +
            b64url(_json.dumps(claims, separators=(",", ":")).encode()) + "." + b64url(sig))


def _form(pairs):
    from urllib.parse import quote
    return "&".join(f"{quote(k, safe='')}={quote(v, safe='')}" for k, v in pairs)


def gen_oauth(c, out):
    """The IdMS flows of TS 33.180 Annex B (US2): authorization request (query), authorization code
    response (Location), token request (form, PKCE), token response (JSON with ID, access and
    refresh tokens as JWT and opaque), refresh, token exchange, introspection and revocation, and
    an error response. Canaries in every identity and every credential."""
    name = "web_oauth.pcapng"
    v = _Cv(c, name)
    cap = S.Capture()
    f = Flow(cap, aport=44001, bport=80)
    host = f"{v.label('http:Host')}.example.org"
    mcptt_id = f"sip:{v.user('jwt:mcptt_id')}@example.org"
    client = v.s("http-param:client_id", "client")
    state = v.s("http-param:state", "state")
    q = _form([("response_type", "code"), ("client_id", client), ("redirect_uri", f"http://{v.label('http-param:redirect_uri')}.example.org/cb"),
               ("scope", "openid 3gpp:mc:ptt_service"), ("state", state), ("acr_values", "3gpp:acr:password"),
               ("code_challenge", v.s("http-param:code_challenge", "cc")), ("code_challenge_method", "S256"),
               ("login_hint", v.s("http-param:unknown"))])
    f.send(0, http_request("GET", f"/authorize?{q}", [("Host", host)]))
    code = v.s("http-param:code", "code")
    f.send(1, http_response(302, "Found", [("Location", f"http://app.example.org/cb?code={code}&state={state}")]))
    form = _form([("grant_type", "authorization_code"), ("code", code), ("client_id", client),
                  ("code_verifier", v.s("http-param:code_verifier", "verifier")), ("redirect_uri", "http://app.example.org/cb"),
                  ("client_secret", v.s("http-param:client_secret", "secret")), ("password", v.s("http-param:password", "pw"))]).encode()
    f.send(0, http_request("POST", "/token", [("Host", host), ("Content-Type", "application/x-www-form-urlencoded")], form))
    hdr = {"alg": "ES256", "typ": "JWT", "kid": v.s("jwt-header:kid", "kid")}
    claims = {"iss": f"https://{v.label('jwt:iss')}.example.org", "sub": mcptt_id, "aud": client, "exp": 1791963735,
              "iat": 1791960135, "mcptt_id": mcptt_id, "scope": "openid", "jti": v.s("jwt:jti", "jti"),
              "auth_time": 1791960100, "nonce": v.s("jwt:nonce", "nonce"), "secret_claim": v.s("jwt:unknown")}
    id_token = jwt(hdr, claims, rng=c.rng)
    access = jwt(hdr, dict(claims, client_id=client), rng=c.rng)
    c.text(id_token.rsplit(".", 1)[1], name, "jwt:signature")
    refresh = v.s("http-param:refresh_token", "refresh")
    body = _json.dumps({"access_token": access, "token_type": "Bearer", "expires_in": 3600, "refresh_token": refresh,
                        "id_token": id_token, "scope": "openid 3gpp:mc:ptt_service", "extra": v.s("json-member:unknown")}).encode()
    f.send(1, http_response(200, "OK", [("Content-Type", "application/json;charset=UTF-8"), ("Cache-Control", "no-store")], body))
    opaque = v.s("http-param:access_token", "opaq") + "Zz9"
    f.send(0, http_request("POST", "/token", [("Host", host), ("Content-Type", "application/x-www-form-urlencoded")],
                           _form([("grant_type", "refresh_token"), ("refresh_token", refresh), ("scope", "openid")]).encode()))
    f.send(1, http_response(200, "OK", [("Content-Type", "application/json")],
                            _json.dumps({"access_token": opaque, "token_type": "Bearer", "expires_in": 600}).encode()))
    f.send(0, http_request("POST", "/token", [("Host", host), ("Content-Type", "application/x-www-form-urlencoded")],
                           _form([("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"), ("subject_token", access),
                                  ("subject_token_type", "urn:ietf:params:oauth:token-type:access_token"),
                                  ("resource", f"https://{v.label('http-param:resource')}.example.net/x")]).encode()))
    f.send(1, http_response(400, "Bad Request", [("Content-Type", "application/json")],
                            _json.dumps({"error": "invalid_grant", "error_description": v.s("http-param:error_description")}).encode()))
    f.send(0, http_request("POST", "/introspect", [("Host", host), ("Content-Type", "application/x-www-form-urlencoded"),
                                                   ("Authorization", f"Bearer {opaque}")],
                           _form([("token", opaque), ("token_type_hint", "access_token")]).encode()))
    f.send(1, http_response(200, "OK", [("Content-Type", "application/json")],
                            _json.dumps({"active": True, "client_id": client, "username": v.s("http-param:username", "user"),
                                         "sub": mcptt_id, "exp": 1791963735}).encode()))
    f.close()
    _write(cap, out, name)


def gen_auth(c, out):
    """HTTP authentication and cookies (US2 scenario 4, FR-013, FR-014)."""
    name = "web_auth.pcapng"
    v = _Cv(c, name)
    cap = S.Capture()
    f = Flow(cap, aport=44002, bport=8080)
    host = f"{v.label('http:Host')}.example.org"
    user = v.s("http:Authorization", "basicuser")
    pw = v.s("http:Authorization", "basicpw")
    basic = _b64.b64encode(f"{user}:{pw}".encode()).decode()
    c.text(basic, name, "http:Authorization")
    f.send(0, http_request("GET", "/org.3gpp.mcptt.user-profile/global/index", [("Host", host), ("Authorization", f"Basic {basic}")]))
    nonce = v.hexs("sip-param:WWW-Authenticate;nonce", 32)
    realm = f"{v.label('sip-param:WWW-Authenticate;realm')}.example.org"
    f.send(1, http_response(401, "Unauthorized", [("WWW-Authenticate", f'Digest realm="{realm}", nonce="{nonce}", qop="auth", algorithm=MD5')]))
    duser = v.s("sip-param:Authorization;username", "digestuser")
    resp = v.hexs("sip-param:Authorization;response", 32)
    f.send(0, http_request("GET", "/org.3gpp.mcptt.user-profile/global/index", [("Host", host), ("Authorization",
           f'Digest username="{duser}", realm="{realm}", nonce="{nonce}", uri="/x", response="{resp}", qop=auth, nc=00000001, cnonce="{v.hexs("sip-param:Authorization;cnonce", 16)}"')]))
    cookie = v.s("cookie:value", "cookieval")
    f.send(1, http_response(200, "OK", [("Set-Cookie", f"{v.s('cookie:name', 'cookiename')}={cookie}; Path=/; Domain=.{v.label('cookie:domain')}.example.org; HttpOnly; Secure"),
                                        ("Content-Type", "application/octet-stream")], b""))
    f.send(0, http_request("GET", "/x", [("Host", host), ("Cookie", f"a1b2c3d4={cookie}; theme={v.s('cookie:value', 'theme')}"),
                                         ("Authorization", "Bearer " + v.s("http:Authorization", "bearertoken"))]))
    f.send(1, http_response(204, "No Content", []))
    f.close()
    _write(cap, out, name)


def kms_response(v, user_uri, kms_uri, signed=True):
    pub = v.hexs("xml:urn:3gpp:ns:mcsecKMSInterface:1.0|-|PubEncKey", 64)
    kpak = v.hexs("xml:urn:3gpp:ns:mcsecKMSInterface:1.0|-|PubAuthKey", 64)
    ssk = v.s("xml:urn:3gpp:ns:mcsecKMSInterface:1.0|-|UserSigningKeySSK", "ssk")
    rsk = v.s("xml:urn:3gpp:ns:mcsecKMSInterface:1.0|-|UserDecryptKey", "rsk")
    pvt = v.s("xml:urn:3gpp:ns:mcsecKMSInterface:1.0|-|UserPubTokenPVT", "pvt")
    return (f'<?xml version="1.0" encoding="UTF-8"?><KmsResponse xmlns="urn:3gpp:ns:mcsecKMSInterface:1.0" Version="1.0.0">'
            f"<KmsUri>{kms_uri}</KmsUri><UserUri>{user_uri}</UserUri><Time>2026-11-15T10:00:00Z</Time>"
            f"<KmsId>{v.s('xml:urn:3gpp:ns:mcsecKMSInterface:1.0|-|KmsId', 'kmsid')}</KmsId>"
            f"<ClientReqUrl>http://{v.label('xml:urn:3gpp:ns:mcsecKMSInterface:1.0|-|ClientReqUrl')}.example.org/keymanagement/identity/v1/keyprov</ClientReqUrl>"
            "<KmsMessage><KmsKeyProv Version='1.0.0'>"
            f"<KmsKeySet><KmsUri>{kms_uri}</KmsUri><UserUri>{user_uri}</UserUri><UserID>{v.s('xml:urn:3gpp:ns:mcsecKMSInterface:1.0|-|UserID', 'uid')}</UserID>"
            "<ValidFrom>2026-11-01T00:00:00Z</ValidFrom><ValidTo>2026-12-01T00:00:00Z</ValidTo><KeyPeriodNo>1650</KeyPeriodNo>"
            f"<UserDecryptKey>{rsk}</UserDecryptKey><UserSigningKeySSK>{ssk}</UserSigningKeySSK><UserPubTokenPVT>{pvt}</UserPubTokenPVT>"
            "</KmsKeySet></KmsKeyProv></KmsMessage></KmsResponse>"
            ).encode(), (pub, kpak)


def gen_kms(c, out):
    """KMS Init and KeyProvision (US2 scenario 3, FR-015 to FR-017): user key sets removed, URIs
    mapped like SIP, times shifted, public keys zeroed."""
    name = "web_kms.pcapng"
    v = _Cv(c, name)
    cap = S.Capture()
    f = Flow(cap, aport=44003, bport=80)
    user = f"sip:{v.user('xml:urn:3gpp:ns:mcsecKMSInterface:1.0|-|UserUri')}@example.org"
    kms = f"https://{v.label('xml:urn:3gpp:ns:mcsecKMSInterface:1.0|-|KmsUri')}.example.org"
    req = (f'<?xml version="1.0" encoding="UTF-8"?><KmsRequest xmlns="urn:3gpp:ns:mcsecKMSInterface:1.0" Version="1.1.0">'
           f"<UserUri>{user}</UserUri><KmsUri>{kms}</KmsUri><Time>2026-11-15T09:59:59Z</Time>"
           f"<ClientId>{v.s('xml:urn:3gpp:ns:mcsecKMSInterface:1.0|-|ClientId', 'clientid')}</ClientId>"
           f"<ClientReqUrl>{kms}/keymanagement/identity/v1/keyprov</ClientReqUrl></KmsRequest>").encode()
    enc = user.replace(":", "%3A").replace("@", "%40")
    f.send(0, http_request("POST", f"/keymanagement/identity/v1/keyprov/{enc}", [("Host", "kms.example.org"), ("Content-Type", "application/xml")], req))
    body, _ = kms_response(v, user, kms)
    cert = (f'<?xml version="1.0"?><KmsResponse xmlns="urn:3gpp:ns:mcsecKMSInterface:1.0"><KmsUri>{kms}</KmsUri><UserUri>{user}</UserUri>'
            "<Time>2026-11-15T10:00:01Z</Time><ClientReqUrl>http://kms.example.org/keymanagement/identity/v1/init</ClientReqUrl>"
            f"<KmsMessage><KmsInit><KmsCertificate><KmsUri>{kms}</KmsUri><UserIdFormat>2</UserIdFormat><UserKeyPeriod>2592000</UserKeyPeriod>"
            f"<UserKeyOffset>0</UserKeyOffset><PubEncKey>{v.hexs('xml:urn:3gpp:ns:mcsecKMSInterface:1.0|-|PubEncKey', 64)}</PubEncKey>"
            f"<PubAuthKey>{v.hexs('xml:urn:3gpp:ns:mcsecKMSInterface:1.0|-|PubAuthKey', 64)}</PubAuthKey></KmsCertificate></KmsInit></KmsMessage></KmsResponse>").encode()
    f.send(1, http_response(200, "OK", [("Content-Type", "application/xml")], body))
    f.send(0, http_request("POST", "/keymanagement/identity/v1/init", [("Host", "kms.example.org"), ("Content-Type", "text/xml")], req))
    f.send(1, http_response(200, "OK", [("Content-Type", "text/xml")], cert))
    f.close()
    _write(cap, out, name)


def _oauth_rules():
    """(params, jwt header members, jwt claims) of rules/http-oauth.yaml: (name, action)."""
    import os
    path = os.path.join(os.path.dirname(__file__), "..", "..", "rules", "http-oauth.yaml")
    out = {"params": [], "header": [], "claims": []}
    section = None
    for line in open(path, encoding="utf-8"):
        st = line.strip()
        if st == "params:":
            section = "params"
        elif st == "header:":
            section = "header"
        elif st == "claims:":
            section = "claims"
        m = re.match(r'\s*- \{name: "?([^",]+)"?, action: (\w+)', line)
        if m and section:
            out[section].append((m.group(1), m.group(2)))
    return out


def gen_http_coverage(c, out):
    """A canary in every HTTP header, parameter, JSON member, JWT claim and JOSE header member
    whose rule pseudonymises or removes (keys of tests/http_rule_keys_main.cpp)."""
    name = "web_http_coverage.pcapng"
    v = _Cv(c, name)
    cap = S.Capture()
    f = Flow(cap, aport=45001, bport=80)
    r = _oauth_rules()

    def dg(hdr, params):
        return ", ".join(f'{p}="{v.s(f"http:{hdr};{p}", "dg")}"' for p in params)

    url = lambda key: f"http://{v.label(key)}.example.org/{v.s(key, 'seg')}"
    headers = [("Host", f"{v.label('http:Host')}.example.org"),
               ("Authorization", "Digest " + dg("Authorization", ["username", "realm", "nonce", "response", "cnonce", "opaque"])),
               ("Proxy-Authorization", "Digest " + dg("Proxy-Authorization", ["username", "realm", "nonce", "response", "cnonce", "opaque"])),
               ("Content-Type", f"multipart/mixed; boundary={v.s('http:Content-Type;boundary', 'bnd')}"),
               ("Location", url("http:Location")), ("Content-Location", url("http:Content-Location")),
               ("If-Match", f'"{v.s("http:If-Match", "etag")}"'), ("If-None-Match", f'W/"{v.s("http:If-None-Match", "etag")}"'),
               ("ETag", f'"{v.s("http:ETag", "etag")}"'),
               ("From", v.s("http:From")), ("Referer", url("http:Referer")), ("Via", "1.1 " + v.s("http:Via")),
               ("Trailer", v.s("http:Trailer")), ("User-Agent", v.s("http:User-Agent")), ("Server", v.s("http:Server")),
               ("Cookie", f"{v.s('cookie:name', 'ck')}={v.s('cookie:value', 'cv')}"),
               ("X-3GPP-Asserted-Identity", f'"sip:{v.user("http:X-3GPP-Asserted-Identity")}@example.org"'),
               ("X-Not-A-Rule", v.s("http-header:unknown"))]
    c.reuse(dict(headers)["Cookie"].split("=")[0], None, name, "http:Cookie")
    c.reuse(dict(headers)["Proxy-Authorization"].split('"')[1], None, name, "http:Proxy-Authorization")
    form = []
    for pname, action in r["params"]:
        if action == "keep":
            continue
        key = f"http-param:{pname}"
        if action == "uri":
            form.append((pname, f"https://{v.label(key)}.example.org/{v.s(key, 'p')}"))
        elif pname in ("mcptt_id", "mcvideo_id", "mcdata_id", "mcrec_id", "sub", "username"):
            form.append((pname, f"sip:{v.user(key)}@example.org"))
        else:
            form.append((pname, v.s(key, "pv")))
    form.append(("unknown_param", v.s("http-param:unknown")))
    parts = (b"--BND\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n" + _form(form).encode() + b"\r\n--BND--\r\n")
    f.send(0, http_request("POST", "/token", headers, parts.replace(b"BND", headers[3][1].split("=")[1].encode())))
    hdr = {}
    for m, action in r["header"]:
        hdr[m] = "ES256" if m == "alg" else v.s(f"jwt-header:{m}", "jh") if action != "keep" else "JWT"
    claims = {}
    for cl, action in r["claims"]:
        key = f"jwt:{cl}"
        if action in ("keep", "shift"):
            claims[cl] = 1791963735 if action == "shift" else ("openid" if cl == "scope" else "Bearer")
        elif action == "uri":
            claims[cl] = f"https://{v.label(key)}.example.org"
        elif cl in ("mcptt_id", "mcvideo_id", "mcdata_id", "mcrec_id", "sub", "username"):
            claims[cl] = f"sip:{v.user(key)}@example.org"
        else:
            claims[cl] = v.s(key, "jc")
    claims["custom"] = v.s("jwt:unknown")
    token = jwt(hdr, claims, rng=c.rng)
    c.text(token.rsplit(".", 1)[1], name, "jwt:signature")
    body = _json.dumps({"id_token": token, "token_type": "Bearer", "odd_member": v.s("json-member:unknown")}).encode()
    resp = [("Content-Type", "application/json"),
            ("WWW-Authenticate", "Digest " + dg("WWW-Authenticate", ["realm", "nonce", "opaque"])),
            ("Proxy-Authenticate", "Digest " + dg("Proxy-Authenticate", ["realm", "nonce", "opaque"])),
            ("Authentication-Info", ", ".join(f'{p}="{v.s(f"http:Authentication-Info;{p}", "ai")}"' for p in ("nextnonce", "rspauth", "cnonce"))),
            ("Set-Cookie", f"{v.s('cookie:name', 'ck')}={v.s('cookie:value', 'cv')}; Path=/{v.s('cookie:path', 'cp')}; "
                           f"Domain={v.label('cookie:domain')}.example.org")]
    c.reuse(resp[4][1].split("=")[0], None, name, "http:Set-Cookie")
    c.reuse(resp[3][1].split('"')[1], None, name, "http:Authentication-Info")
    f.send(1, http_response(200, "OK", resp, body))
    f.close()
    _write(cap, out, name)


# --- TLS (User Story 3) -------------------------------------------------------------------------
import der as D


def tls_record(ctype, payload, version=0x0303):
    return struct.pack("!BHH", ctype, version, len(payload)) + payload


def hs(htype, body):
    return bytes([htype]) + struct.pack("!I", len(body))[1:] + body


def v8(b):
    return bytes([len(b)]) + b


def v16(b):
    return struct.pack("!H", len(b)) + b


def v24(b):
    return struct.pack("!I", len(b))[1:] + b


def tls_ext(t, data):
    return struct.pack("!H", t) + v16(data)


def certificates(v, rng):
    """A server chain of two certificates and a client certificate with canaries in every
    pseudonymised name, alternative name, access URI, serial and key identifier."""
    def cn(key):
        return f"{v.label(key)}.example.org"
    ca_name = [("2.5.4.6", 0x13, "PL"), ("2.5.4.10", 0x0C, v.s("x509:organizationName", "Org")),
               ("2.5.4.3", 0x0C, v.s("x509:commonName", "CA"))]
    ski_ca = c_bytes(v, "x509:subjectKeyIdentifier", 20)
    ca = D.certificate(rng, c_bytes(v, "x509:serial", 16), ca_name, ca_name, key="rsa",
                       key_bytes=b"\x80" + c_bytes(v, "x509:rsaEncryption", 255), sig=c_bytes(v, "x509:signature", 256),
                       extensions=[D.ext("2.5.29.19", D.seq(D.tlv(0x01, b"\xff")), True),
                                   D.ext("2.5.29.14", D.tlv(0x04, ski_ca)),
                                   D.ext("2.5.29.15", D.tlv(0x03, b"\x01\x06"), True)])
    srv_name = [("2.5.4.6", 0x13, "PL"), ("2.5.4.7", 0x0C, v.s("x509:localityName", "City")),
                ("2.5.4.11", 0x0C, v.s("x509:organizationalUnitName", "Unit")),
                ("2.5.4.3", 0x13, cn("x509:commonName")),
                ("1.2.840.113549.1.9.1", 0x16, f"{v.user('x509:emailAddress')}@example.org"),
                ("0.9.2342.19200300.100.1.25", 0x16, v.s("x509:domainComponent", "dc")),
                ("2.5.4.99", 0x0C, v.s("x509:unknown-attribute", "attr"))]
    ip = bytes(int(x) for x in v.ip("x509:san-ip").split("."))
    san = D.seq(D.tlv(0x82, cn("x509:subjectAltName").encode()), D.tlv(0x82, ("*." + cn("x509:subjectAltName")).encode()),
                D.tlv(0x81, f"{v.user('x509:subjectAltName')}@example.org".encode()),
                D.tlv(0x86, f"sip:{v.user('x509:subjectAltName')}@example.org".encode()), D.tlv(0x87, ip),
                D.tlv(0xA0, D.oid("1.3.6.1.4.1.311.20.2.3") + D.tlv(0xA0, D.tlv(0x0C, v.s("x509:subjectAltName", "upn").encode()))))
    aia = D.seq(D.seq(D.oid("1.3.6.1.5.5.7.48.1"), D.tlv(0x86, f"http://{cn('x509:authorityInfoAccess')}/ocsp".encode())))
    sia = D.seq(D.seq(D.oid("1.3.6.1.5.5.7.48.5"), D.tlv(0x86, f"http://{cn('x509:subjectInfoAccess')}/repo".encode())))
    crl = D.seq(D.seq(D.tlv(0xA0, D.tlv(0xA0, D.tlv(0x86, f"http://{cn('x509:cRLDistributionPoints')}/ca.crl".encode())))))
    fresh = D.seq(D.seq(D.tlv(0xA0, D.tlv(0xA0, D.tlv(0x86, f"http://{cn('x509:freshestCRL')}/d.crl".encode())))))
    ian = D.seq(D.tlv(0x82, cn("x509:issuerAltName").encode()))
    pol = D.seq(D.seq(D.oid("2.23.140.1.2.2"), D.seq(D.seq(D.oid("1.3.6.1.5.5.7.2.1"),
                                                         D.tlv(0x16, f"http://{cn('x509:certificatePolicies')}/cps".encode())))))
    v.c.reuse(ski_ca.hex(), None, v.f, "x509:authorityKeyIdentifier")
    aki = D.seq(D.tlv(0x80, ski_ca))
    srv = D.certificate(rng, c_bytes(v, "x509:serial", 16), ca_name, srv_name, key="ec", sig_len=72,
                        key_bytes=c_bytes(v, "x509:id-ecPublicKey", 64),
                        extensions=[D.ext("2.5.29.17", san), D.ext("1.3.6.1.5.5.7.1.1", aia), D.ext("2.5.29.31", crl),
                                    D.ext("2.5.29.35", aki), D.ext("2.5.29.37", D.seq(D.oid("1.3.6.1.5.5.7.3.1"))),
                                    D.ext("2.5.29.32", pol), D.ext("2.5.29.18", ian), D.ext("2.5.29.46", fresh),
                                    D.ext("1.3.6.1.5.5.7.1.11", sia),
                                    D.ext("1.2.3.4.5.6.7", v.s("x509:unknown-extension", "ext").encode())])
    cli = D.certificate(rng, c_bytes(v, "x509:serial", 8), ca_name,
                        [("2.5.4.3", 0x0C, f"sip:{v.user('x509:commonName')}@example.org")]
                        + [(o, 0x0C, v.s(f"x509:{n}", n[:4])) for o, n in (
                            ("2.5.4.8", "stateOrProvinceName"), ("2.5.4.5", "serialNumber"), ("2.5.4.12", "title"),
                            ("2.5.4.41", "name"), ("2.5.4.42", "givenName"), ("2.5.4.4", "surname"),
                            ("2.5.4.43", "initials"), ("2.5.4.44", "generationQualifier"), ("2.5.4.46", "dnQualifier"),
                            ("2.5.4.65", "pseudonym"))], key="ec", sig_len=72)
    return [srv, ca], cli


def c_bytes(v, key, n):
    return v.c.bytes(None, v.f, n, rule=key)


def client_hello(v, sni_key, extra=b"", btid=None, version_list=(0x0304, 0x0303)):
    exts = (tls_ext(0, v16(b"\x00" + v16(f"{v.label('tls:server_name')}.example.org".encode())))
            + tls_ext(16, v16(v8(b"h2") + v8(b"http/1.1") + v8(v.s("tls:application_layer_protocol_negotiation", "alpn").encode())))
            + tls_ext(5, b"\x01" + v16(b"") + v16(c_bytes(v, "tls:status_request", 8)))
            + tls_ext(21, c_bytes(v, "tls:padding", 8)) + tls_ext(35, c_bytes(v, "tls:session_ticket", 32))
            + tls_ext(44, v16(c_bytes(v, "tls:cookie", 16)))
            + tls_ext(47, v16(v16(D.name([("2.5.4.3", 0x0C, v.s("tls:certificate_authorities", "ca"))]))))
            + tls_ext(43, v8(b"".join(struct.pack("!H", x) for x in version_list)))
            + tls_ext(10, v16(b"\x00\x1d\x00\x17")) + tls_ext(13, v16(b"\x04\x03\x08\x04"))
            + tls_ext(51, v16(struct.pack("!H", 0x1D) + v16(c_bytes(v, "tls:key_share", 32))))
            + tls_ext(45, v8(b"\x01")) + tls_ext(23, b"") + tls_ext(65281, v8(c_bytes(v, "tls:renegotiation_info", 12)))
            + tls_ext(0xFE0D, v.s("tls:extension-unknown", "ech").encode()) + extra)
    if btid is not None:
        ident = btid.encode()
        exts += tls_ext(41, v16(v16(ident) + struct.pack("!I", 0x11223344)) + v16(v8(c_bytes(v, "tls:pre_shared_key", 32))))
    body = (struct.pack("!H", 0x0303) + c_bytes(v, "tls:random", 32) + v8(c_bytes(v, "tls:session-id", 32))
            + v16(struct.pack("!HHHH", 0x1301, 0xC02F, 0x008C, 0x00FF)) + v8(b"\x00") + v16(exts))
    return hs(1, body)


def server_hello(v, suite, tls13=False, hrr=False):
    if hrr:
        random = bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")
        exts = tls_ext(43, struct.pack("!H", 0x0304)) + tls_ext(51, struct.pack("!H", 0x17))
    elif tls13:
        random = c_bytes(v, "tls:random", 32)
        exts = tls_ext(43, struct.pack("!H", 0x0304)) + tls_ext(51, struct.pack("!H", 0x1D) + v16(c_bytes(v, "tls:key_share", 32)))
    else:
        random = c_bytes(v, "tls:random", 24) + b"DOWNGRD\x01"
        exts = tls_ext(65281, v8(b"")) + tls_ext(23, b"") + tls_ext(11, v8(b"\x00"))
    return hs(2, struct.pack("!H", 0x0303) + random + v8(c_bytes(v, "tls:session-id", 32)) + struct.pack("!HB", suite, 0) + v16(exts))


def gen_tls(c, out):
    """TLS 1.2 with a certificate chain split across records, ECDHE key exchange, mutual
    authentication, a session ticket, protected records and an alert; TLS 1.3 with a
    HelloRetryRequest and a PSK identity in B-TID form; TLS 1.2 PSK; TLS through an HTTP CONNECT
    tunnel (US3, FR-018 to FR-023)."""
    name = "web_tls.pcapng"
    v = _Cv(c, name)
    v.c = c
    cap = S.Capture()
    chain, client_cert = certificates(v, c.rng)
    # TLS 1.2, ECDHE_RSA (0xC02F), mutual certificates.
    f = Flow(cap, aport=46001, bport=443)
    f.send(0, tls_record(22, client_hello(v, "tls:server_name"), 0x0301))
    cert_msg = hs(11, v24(b"".join(v24(x) for x in chain)))
    flight = (server_hello(v, 0xC02F) + cert_msg
              + hs(12, b"\x03\x00\x17" + v8(b"\x04" + c_bytes(v, "tls:server_key_exchange", 64)) + b"\x04\x03" + v16(c_bytes(v, "tls:server_key_exchange", 70)))
              + hs(22, b"\x01" + v24(c_bytes(v, "tls:certificate_status", 40)))
              + hs(13, v8(b"\x01\x40") + v16(b"\x04\x03") + v16(v16(D.name([("2.5.4.3", 0x0C, v.s("x509:commonName", "CA2"))]))))
              + hs(14, b""))
    split = len(server_hello(v, 0xC02F)) + 300
    f.send(1, tls_record(22, flight[:split]) + tls_record(22, flight[split:]), mss=200)
    f.send(0, tls_record(22, hs(11, v24(v24(client_cert))) + hs(16, v8(b"\x04" + c_bytes(v, "tls:client_key_exchange", 64)))
                         + hs(15, b"\x04\x03" + v16(c_bytes(v, "tls:certificate_verify", 72))))
           + tls_record(20, b"\x01") + tls_record(22, c_bytes(v, "tls:finished", 40)))
    f.send(1, tls_record(22, hs(4, struct.pack("!I", 7200) + v16(c_bytes(v, "tls:new_session_ticket", 64))))
           + tls_record(20, b"\x01") + tls_record(22, c_bytes(v, "tls:finished", 40)))
    f.send(0, tls_record(23, c_bytes(v, "tls:application_data", 120)) + tls_record(24, c_bytes(v, "tls:heartbeat", 20)))
    f.send(1, tls_record(23, c_bytes(v, "tls:application_data", 300)) + tls_record(21, c_bytes(v, "tls:alert", 26)))
    f.close()
    # TLS 1.3 with a HelloRetryRequest and a B-TID PSK identity (TS 33.220 §4.4.7).
    g = Flow(cap, aport=46002, bport=443)
    btid = f"{v.s('tls:pre_shared_key', 'rand')}@{v.label('tls:pre_shared_key')}.example.org"
    g.send(0, tls_record(22, client_hello(v, "tls:server_name", btid=btid), 0x0301))
    g.send(1, tls_record(22, server_hello(v, 0x1301, hrr=True)) + tls_record(20, b"\x01"))
    g.send(0, tls_record(20, b"\x01") + tls_record(22, client_hello(v, "tls:server_name", btid=btid)))
    g.send(1, tls_record(22, server_hello(v, 0x1301, tls13=True)) + tls_record(20, b"\x01")
           + tls_record(23, c_bytes(v, "tls:application_data", 200)))
    g.send(0, tls_record(23, c_bytes(v, "tls:application_data", 64)))
    g.close()
    # TLS 1.2 PSK (0x008C): identity hint and identity (RFC 4279 §2).
    p = Flow(cap, aport=46003, bport=443)
    p.send(0, tls_record(22, client_hello(v, "tls:server_name")))
    p.send(1, tls_record(22, server_hello(v, 0x008C) + hs(12, v16(v.s("tls:server_key_exchange", "hint").encode())) + hs(14, b"")))
    p.send(0, tls_record(22, hs(16, v16(v.s("tls:client_key_exchange", "pskid").encode()))) + tls_record(20, b"\x01"))
    p.close()
    # TLS inside an HTTP CONNECT tunnel through the HTTP proxy.
    t = Flow(cap, a=CLIENT, b=PROXY, aport=46004, bport=8080)
    target = f"{v.label('http-target:host')}.example.org:443"
    t.send(0, http_request("CONNECT", target, [("Host", target)]))
    t.send(1, b"HTTP/1.1 200 Connection established\r\n\r\n")
    t.send(0, tls_record(22, client_hello(v, "tls:server_name")))
    t.close()
    _write(cap, out, name)


# --- Hostile input (User Story 5) --------------------------------------------------------------
def gen_hostile(c, out):
    """One file per hostile shape (US5); each carries a canary that must not
    survive whatever the tool decides to do."""
    def write(kind, build):
        name = f"web_hostile_{kind}.pcapng"
        v = _Cv(c, name)
        cap = S.Capture()
        build(v, cap)
        _write(cap, out, name)

    def oversized_head(v, cap):
        f = Flow(cap, aport=47001)
        f.send(0, b"GET /x HTTP/1.1\r\nHost: h.example.org\r\nX-Big: " + b"A" * 70000 + v.s("http-header:unknown").encode() + b"\r\n\r\n")
        f.send(0, http_request("GET", "/after", [("Host", f"{v.label('http:Host')}.example.org")]))
        f.close()

    def endless_chunked(v, cap):
        f = Flow(cap, aport=47002)
        f.send(0, http_request("GET", "/x", [("Host", "h.example.org")]))
        body = b"".join(b"1\r\n" + bytes([65 + i % 26]) + b"\r\n" for i in range(20000))
        f.send(1, b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\n\r\n"
               + body + b"ffffffffff\r\n" + v.s("http-body:application/octet-stream").encode())
        f.close()

    def compression_bomb(v, cap):
        import zlib
        f = Flow(cap, aport=47003)
        f.send(0, http_request("GET", "/x", [("Host", "h.example.org")]))
        bomb = zlib.compress(v.s("http-body:gzip").encode() + b"\x00" * 5_000_000, 9)
        f.send(1, http_response(200, "OK", [("Content-Type", "application/json"), ("Content-Encoding", "deflate")], bomb))
        f.close()

    def deep_json(v, cap):
        f = Flow(cap, aport=47004)
        f.send(0, http_request("POST", "/token", [("Host", "h.example.org"), ("Content-Type", "application/json")],
                               (b'{"a":' * 5000) + _json.dumps(v.s("json-member:unknown")).encode() + b"}" * 5000))
        f.send(0, http_request("POST", "/token", [("Host", "h.example.org"), ("Content-Type", "application/x-www-form-urlencoded")],
                               _form([("access_token", "eyJ!!!." + v.s("http-param:access_token", "bad") + ".x"),
                                      ("id_token", "eyJhbGciOiJub25lIn0." + "A" * 3 + "." + v.s("http-param:id_token", "bad"))]).encode()))
        f.close()

    def hpack_attacks(v, cap):
        for i, block in enumerate([b"\xff\xff\xff\xff\x0f", b"\x00\x83\xff\xff\xff" + b"\x01a", b"\x3f\xe1\xff\xff\x0f",
                                   b"\x40" + b"\x7f\xff\xff\x03" + b"x"]):
            f = Flow(cap, aport=47010 + i)
            f.send(0, H2_PREFACE + h2frame(HEADERS, 0x5, 1, block) + h2frame(DATA, 0x1, 1, v.s("http-body:application/octet-stream").encode()))
            f.close()
        # A CONTINUATION flood: many tiny fragments of one block.
        f = Flow(cap, aport=47020)
        enc = hpack.Encoder()
        block = enc.encode([(":method", "GET"), (":path", "/" + v.s("http-target:segment", "seg"))])
        frames = h2frame(HEADERS, 0x1, 1, block[:1]) + b"".join(h2frame(CONT, 0, 1, b"\x00") for _ in range(70000))
        f.send(0, H2_PREFACE + frames)
        f.close()

    def tls_lies(v, cap):
        f = Flow(cap, aport=47030, bport=443)
        f.send(0, tls_record(22, client_hello(v, "tls:server_name"))[:20] + b"\x16\x03\x03\xff\xff" + v.s("tls:server_name").encode())
        f.close()
        g = Flow(cap, aport=47031, bport=443)
        ch = client_hello(v, "tls:server_name")
        g.send(0, b"".join(tls_record(22, ch[i:i + 1]) for i in range(len(ch))))
        g.close()
        h = Flow(cap, aport=47032, bport=443)
        bad_cert = b"\x30\x82\xff\xff" + v.s("x509:commonName").encode() * 3
        msg = server_hello(v, 0xC02F) + hs(11, v24(v24(bad_cert) + b"".join(v24(b"\x30\x00") for _ in range(100))))
        h.send(1, tls_record(22, msg))
        h.close()
        k = Flow(cap, aport=47033, bport=443)
        k.send(0, b"\x17\x03\x03\x40\x01" + c_bytes(v, "tls:application_data", 64))
        k.close()

    for kind, fn in (("head", oversized_head), ("chunked", endless_chunked), ("bomb", compression_bomb),
                     ("json", deep_json), ("hpack", hpack_attacks), ("tls", tls_lies)):
        write(kind, fn)


FIXTURES = [gen_xcap, gen_framing, gen_ports, gen_h2, gen_xml_coverage, gen_oauth, gen_auth, gen_kms, gen_http_coverage, gen_tls,
            gen_hostile]


def gen(c, out):
    for fn in FIXTURES:
        fn(c, out)

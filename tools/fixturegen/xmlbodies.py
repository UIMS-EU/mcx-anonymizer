# SPDX-License-Identifier: GPL-3.0-or-later
"""MCX XML body fixtures: XML documents carried in SIP messages, alone or as multipart parts.

Builders:
  - El / doc(): an XML document from a nested structure, with control over prefixes, the
    default namespace, quote style, whitespace, CDATA, comments, processing instructions,
    character references, the byte order mark and the XML declaration;
  - esc_text() / esc_attr(): XML escaping for text and for either quote character;
  - Sender: SIP requests and responses that carry one body, or a multipart body with SDP.

Every value is invented. Names come from example.net (RFC 2606). Identity values that a
non-keep XML rule classifies are canaries recorded with their XML rule key (see canary.py):
  xml:<namespace name>|<parent local or ->|<local>                     an element
  xml:<namespace name>|<element local>|@<attr namespace or ->|<local>  an attribute
  xml-ns:<namespace name>                                              a namespace removed as a whole
Each generated file gets an entry in xml_manifest.json listing its bodies
(frame, part index or null, Content-Type), for the oracles.
"""
import json
import os
import struct

import packets as P
import sip as S

FIXTURES = []  # fixture functions (c, out), registered by the fixture sections below
MANIFEST = {}  # file name -> [{"frame": n, "part": i | None, "content_type": ct}]
BODIES = []    # every XML body written by a Sender, in order (seed corpus of the XML fuzzers)

UE_A = bytes([10, 30, 0, 11])
UE_B = bytes([10, 30, 0, 12])


# --- escaping -----------------------------------------------------------------------
def esc_text(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def esc_attr(s, quote='"'):
    s = s.replace("&", "&amp;").replace("<", "&lt;")
    return s.replace('"', "&quot;") if quote == '"' else s.replace("'", "&apos;")


# --- documents ----------------------------------------------------------------------
class Raw:
    """Markup inserted as written: a comment, a PI, CDATA, or deliberately broken XML."""

    def __init__(self, text):
        self.text = text

    def render(self, indent, level):
        return self.text


class El:
    """One element. name: "local" or "prefix:local". attrs: (name, value) pairs, escaped
    unless raw=True. ns: (prefix or "", namespace name) declarations on this element.
    children: El, Raw or str (text, escaped unless it is a Raw)."""

    def __init__(self, name, *children, attrs=(), ns=(), quote='"', raw=False, empty=None):
        self.name, self.children, self.attrs, self.ns = name, children, attrs, ns
        self.quote, self.raw = quote, raw
        self.empty = (not children) if empty is None else empty

    def render(self, indent=None, level=0):
        q = self.quote
        parts = [f"<{self.name}"]
        for prefix, uri in self.ns:
            parts.append(f" xmlns{':' + prefix if prefix else ''}={q}{esc_attr(uri, q)}{q}")
        for n, v in self.attrs:
            parts.append(f" {n}={q}{v if self.raw else esc_attr(v, q)}{q}")
        if self.empty:
            return "".join(parts) + "/>"
        parts.append(">")
        only_text = all(isinstance(c, (str, Raw)) for c in self.children)
        for c in self.children:
            if isinstance(c, str):
                parts.append(esc_text(c))
                continue
            if indent is not None and not only_text:
                parts.append("\r\n" + " " * (indent * (level + 1)))
            parts.append(c.render(indent, level + 1))
        if indent is not None and not only_text:
            parts.append("\r\n" + " " * (indent * level))
        parts.append(f"</{self.name}>")
        return "".join(parts)


def doc(root, decl='<?xml version="1.0" encoding="UTF-8"?>', bom=False, indent=2, tail="\r\n"):
    """The bytes of a document: optional BOM, declaration, root, trailing newline."""
    text = (decl + "\r\n" if decl else "") + root.render(indent) + tail
    return (b"\xef\xbb\xbf" if bom else b"") + text.encode("utf-8")


# --- SIP carriers -------------------------------------------------------------------
class Sender:
    """SIP messages from UE_A to UE_B over UDP (or over one TCP connection with tcp=True, for
    bodies too large for a datagram); records every body in the manifest. from_user replaces
    the user part of From (a canary that shows the rest of the message is rewritten)."""

    def __init__(self, fname, tcp=False, from_user="ue-a"):
        self.fname = fname
        self.cap = S.Capture()
        self.n = 0
        self.from_user = from_user
        self.tcp = S.TcpConn(UE_A, UE_B, 40300, 5060) if tcp else None
        if self.tcp:
            self.cap.extend(self.tcp.handshake())
        MANIFEST.setdefault(fname, [])

    def _headers(self, method, cseq):
        self.n += 1
        transport = "TCP" if self.tcp else "UDP"
        return [("Via", f"SIP/2.0/{transport} 10.30.0.11:5060;branch=z9hG4bKx{self.n}"),
                ("From", f"<sip:{self.from_user}@example.net>;tag=xa1"), ("To", "<sip:ue-b@example.net>"),
                ("Call-ID", f"xml-{self.n}@example.net"), ("CSeq", f"{cseq} {method}"),
                ("Max-Forwards", "70")]

    def _send(self, msg):
        if self.tcp:
            for i in range(0, len(msg), 1400):
                self.cap.add(self.tcp.send(0, msg[i:i + 1400]))
            return len(self.cap.blocks)
        self.cap.add(P.ethernet(S.MAC_B, S.MAC_A, 0x0800, S.udp_packet(UE_A, UE_B, 5060, 5060, msg)))
        return len(self.cap.blocks)

    def request(self, method, content_type, body, extra=()):
        h = self._headers(method, 1) + list(extra) + [("Content-Type", content_type)]
        frame = self._send(S.request(method, "sip:ue-b@example.net", h, body))
        MANIFEST[self.fname].append({"frame": frame, "part": None, "content_type": content_type})
        if content_type.split(";")[0].strip().endswith("+xml"):
            BODIES.append(body)
        return frame

    def response(self, code, reason, cseq_method, content_type, body, extra=()):
        h = self._headers(cseq_method, 1) + list(extra) + [("Content-Type", content_type)]
        frame = self._send(S.response(code, reason, h, body))
        MANIFEST[self.fname].append({"frame": frame, "part": None, "content_type": content_type})
        if content_type.split(";")[0].strip().endswith("+xml"):
            BODIES.append(body)
        return frame

    def multipart(self, method, parts, extra=(), boundary="xml-bnd-1"):
        """parts: list of (content_type, body, extra part headers)."""
        mp = S.multipart(boundary, [([("Content-Type", ct)] + list(ph), b) for ct, b, ph in parts])
        h = self._headers(method, 1) + list(extra) + [("Content-Type", f"multipart/mixed;boundary={boundary}")]
        frame = self._send(S.request(method, "sip:ue-b@example.net", h, mp))
        for i, (ct, _, _) in enumerate(parts):
            MANIFEST[self.fname].append({"frame": frame, "part": i, "content_type": ct})
        BODIES.extend(b for ct, b, _ in parts if ct.split(";")[0].strip().endswith("+xml"))
        return frame

    def write(self, out):
        with open(os.path.join(out, self.fname), "wb") as fh:
            fh.write(self.cap.bytes())


def sdp_offer():
    return S.sdp(["v=0", "o=- 1 1 IN IP4 10.30.0.11", "s=-", "c=IN IP4 10.30.0.11", "t=0 0",
                  "m=audio 40000 RTP/AVP 96", "a=rtpmap:96 AMR-WB/16000"])


# --- canary helpers -----------------------------------------------------------------
def el_key(ns, parent, local):
    return f"xml:{ns}|{parent or '-'}|{local}"


def attr_key(ns, element, attr, attr_ns=None):
    return f"xml:{ns}|{element}|@{attr_ns or '-'}|{attr}"


class Cv:
    """Canaries of one fixture file, with their XML rule keys."""

    def __init__(self, c, fname):
        self.c, self.f = c, fname

    def s(self, rule, prefix="CANARY", also=(), report_allowed=False):
        """A free-text or opaque value. also: further rule keys the value exercises;
        report_allowed: a name the report may list (an unknown element or attribute name)."""
        v = self.c.string(None, self.f, prefix, rule=rule)
        if also:
            self.c.items[-1]["also"] = list(also)
        if report_allowed:
            self.c.items[-1]["report_allowed"] = True
        return v

    def uri(self, rule, domain="example.net", also=()):
        """A SIP URI whose user part is the canary."""
        user = self.c.string(None, self.f, 'canary', rule=rule)
        if also:
            self.c.items[-1]["also"] = list(also)
        return f"sip:{user}@{domain}"

    def text(self, value, rule):
        """A value with a fixed syntax (a UUID, a host name), recorded as it is."""
        return self.c.text(value, self.f, rule)

    def uuid(self, rule):
        """A random UUID (RFC 9562 text form), recorded as a canary."""
        r = self.c.rng
        v = "%08x-%04x-4%03x-%04x-%012x" % (r.getrandbits(32), r.getrandbits(16), r.getrandbits(12),
                                            0x8000 | r.getrandbits(14), r.getrandbits(48))
        return self.c.text(v, self.f, rule)


# --- fixtures: the xml namespace (Appendix E §E.9) ----------------------------------------
XML_NS = "http://www.w3.org/XML/1998/namespace"
MCPTT_INFO = "urn:3gpp:ns:mcpttInfo:1.0"
MCPTT_INFO_CT = "application/vnd.3gpp.mcptt-info+xml"


def xml_common(c, out):
    """xml:base (removed, E17) next to the kept xml:lang and xml:space, on any element."""
    fname = "xml_common.pcapng"
    cv = Cv(c, fname)
    base = f"http://{cv.s(attr_key(XML_NS, '*', 'base', XML_NS), 'canary')}.example.net/"
    body = doc(El("mcpttinfo", El("mcptt-Params", attrs=(("xml:lang", "en"), ("xml:space", "preserve"))),
                  attrs=(("xml:base", base),), ns=(("", MCPTT_INFO),)))
    tx = Sender(fname)
    tx.request("MESSAGE", MCPTT_INFO_CT, body)
    tx.multipart("MESSAGE", [("application/sdp", sdp_offer(), []), (MCPTT_INFO_CT, body, [])])
    tx.write(out)


FIXTURES.append(xml_common)


# --- fixtures: hostile, malformed and unexpected bodies (User Story 6) ---------------
XENC = "http://www.w3.org/2001/04/xmlenc#"
GKTP = "urn:3gpp:ns:mcpttGKTP:1.0"
VGKTP = "urn:3gpp:ns:mcvideoGKTP:1.0"
VENDOR = "urn:example:vendor:ext"


def _enc_data(cv, key):
    """An xenc:EncryptedData subtree with canaries in the cipher value and the key name."""
    also = ("xml-ns:" + XENC,)
    return El("xenc:EncryptedData",
              El("xenc:EncryptionMethod", attrs=(("Algorithm", "http://www.w3.org/2009/xmlenc11#aes128-gcm"),)),
              El("ds:KeyInfo", El("ds:KeyName", cv.s(key + "#KeyName", "canary", also)),
                 ns=(("ds", "http://www.w3.org/2000/09/xmldsig#"),)),
              El("xenc:CipherData", El("xenc:CipherValue", cv.s(key + "#CipherValue", "canary", also))),
              ns=(("xenc", XENC),), attrs=(("Type", "http://www.w3.org/2001/04/xmlenc#Content"),))


def _info(*children, attrs=(), ns=()):
    return El("mcpttinfo", *children, attrs=attrs, ns=(("", MCPTT_INFO),) + tuple(ns))


def _t(cv, case):
    return cv.s("xml-hostile:" + case, "canary")


def _h_dtd_internal(cv):
    v = _t(cv, "dtd-internal")
    laughs = "".join(f'<!ENTITY l{i} "{("&l%d;" % (i - 1)) * 10}">' for i in range(1, 10))
    return (f'<?xml version="1.0"?>\r\n<!DOCTYPE mcpttinfo [<!ENTITY l0 "{v}">{laughs}]>\r\n'
            f'<mcpttinfo xmlns="{MCPTT_INFO}">&l9;</mcpttinfo>\r\n').encode(), MCPTT_INFO_CT, False


def _h_dtd_external(cv):
    v = _t(cv, "dtd-external")
    return (f'<?xml version="1.0"?>\r\n<!DOCTYPE mcpttinfo [<!ENTITY x SYSTEM "http://{v}.example.net/x.xml">]>'
            f'\r\n<mcpttinfo xmlns="{MCPTT_INFO}">&x;</mcpttinfo>\r\n').encode(), MCPTT_INFO_CT, False


def _h_depth_33(cv):
    inner = El("mcptt-Params", _t(cv, "depth-33"))
    for _ in range(31):
        inner = El("mcptt-Params", inner)
    return doc(_info(inner), indent=None), MCPTT_INFO_CT, False


def _h_elements_10001(cv):
    many = [El("mcptt-Params", empty=True) for _ in range(9999)] + [El("mcptt-Params", _t(cv, "elements-10001"))]
    return doc(_info(*many), indent=None), MCPTT_INFO_CT, True


def _h_attributes_65(cv):
    attrs = tuple((f"a{i}", "1") for i in range(64)) + (("a64", _t(cv, "attributes-65")),)
    return doc(_info(attrs=attrs)), MCPTT_INFO_CT, False


def _h_value_65537(cv):
    v = _t(cv, "value-65537")
    return doc(_info(El("mcptt-Params", v + "x" * (65537 - len(v))))), MCPTT_INFO_CT, True


def _h_name_257(cv):
    return doc(_info(El("n" * 257, _t(cv, "name-257")))), MCPTT_INFO_CT, False


def _h_invalid_utf8(cv):
    v = _t(cv, "invalid-utf8")
    return doc(_info(El("mcptt-Params", v))).replace(v.encode(), v.encode() + b"\xc3\x28"), MCPTT_INFO_CT, False


def _h_utf16_bom(cv):
    v = _t(cv, "utf16-bom")
    text = f'<?xml version="1.0" encoding="UTF-16"?>\r\n<mcpttinfo xmlns="{MCPTT_INFO}"><a>{v}</a></mcpttinfo>\r\n'
    return b"\xff\xfe" + text.encode("utf-16-le"), MCPTT_INFO_CT, False


def _h_charset_latin1(cv):
    body = doc(_info(El("mcptt-Params", _t(cv, "charset-latin1") + "\u00e9"))).decode().encode("latin-1")
    return body, MCPTT_INFO_CT + ";charset=iso-8859-1", False


def _h_decl_latin1(cv):
    return (doc(_info(El("mcptt-Params", _t(cv, "decl-latin1"))), decl='<?xml version="1.0" encoding="ISO-8859-1"?>'),
            MCPTT_INFO_CT, False)


def _h_unclosed(cv):
    return (f'<mcpttinfo xmlns="{MCPTT_INFO}"><mcptt-Params>{_t(cv, "unclosed")}</mcpttinfo>\r\n'.encode(),
            MCPTT_INFO_CT, False)


def _h_undeclared_prefix(cv):
    return (f'<mcpttinfo xmlns="{MCPTT_INFO}"><v:ext>{_t(cv, "undeclared-prefix")}</v:ext></mcpttinfo>\r\n'.encode(),
            MCPTT_INFO_CT, False)


def _h_unknown_root(cv):
    return doc(El("mcpttinfo-x", El("a", _t(cv, "unknown-root")), ns=(("", MCPTT_INFO),))), MCPTT_INFO_CT, False


def _h_unknown_type(cv):
    return (doc(El("data", El("item", _t(cv, "unknown-type")), ns=(("", VENDOR),))),
            "application/vnd.example.vendor-data+xml", False)


def _h_vendor_ns(cv):
    # A vendor namespace and unknown names inside a known document; the names themselves are
    # canaries, so the report must not repeat them.
    vns = f"urn:example:{_t(cv, 'vendor-ns-name')}"
    name = lambda case: cv.s("xml-hostile:" + case, "canary", report_allowed=True)  # noqa: E731
    root = _info(El("v:ext", El("v:item", _t(cv, "vendor-ns")), attrs=(("v:a", _t(cv, "vendor-ns-attr")),)),
                 El(name("unknown-element-name"), _t(cv, "unknown-element")),
                 attrs=((name("unknown-attribute-name"), "1"),), ns=(("v", vns),))
    return doc(root), MCPTT_INFO_CT, False


def _h_comments_pis(cv):
    return doc(_info(Raw(f"<!-- {_t(cv, 'comment')} -->"), Raw(f"<?vendor {_t(cv, 'pi')}?>"))), MCPTT_INFO_CT, False


def _h_xenc_child(cv):
    # FR-018: under an encryptable element, and directly under the root.
    nested = El("mcptt-calling-user-id", _enc_data(cv, "xml-hostile:xenc-nested"), attrs=(("type", "Encrypted"),))
    return doc(_info(El("mcptt-Params", nested), _enc_data(cv, "xml-hostile:xenc-child"))), MCPTT_INFO_CT, False


def _h_xenc_root(cv):
    # P1: a wholly encrypted document.
    return doc(_enc_data(cv, "xml-hostile:xenc-root")), MCPTT_INFO_CT, False


def _h_gktp(cv):
    # A12, D3: group key transport payloads, nested and directly under the root, in the MCPTT GKTP
    # namespace and in the MCVideo one that TS 24.281 imports.
    def gk(key, prefix="mgktp", ns=GKTP):
        return El(f"{prefix}:GKTP", cv.s("xml-hostile:" + key, "canary", ("xml-ns:" + ns,)), attrs=(("id", "1"),))
    root = _info(El("mcptt-Params", El("MKFC-GKTPs", gk("gktp-nested"))), gk("gktp"), gk("gktp-video", "mvgktp", VGKTP),
                 ns=(("mgktp", GKTP), ("mvgktp", VGKTP)))
    return doc(root), MCPTT_INFO_CT, False


HOSTILE = {name[3:].replace("_", "-"): fn for name, fn in list(globals().items()) if name.startswith("_h_")}


def xml_hostile(c, out):
    """One file per case, xml_hostile_<case>.pcapng: the body alone in a MESSAGE, then as a
    multipart part next to SDP. Each file also has a canary in the From user part."""
    for name, build in HOSTILE.items():
        fname = f"xml_hostile_{name}.pcapng"
        body, ct, tcp = build(Cv(c, fname))
        tx = Sender(fname, tcp=tcp, from_user=c.string(None, fname, "canary", rule="sip:From.uri"))
        tx.request("MESSAGE", ct, body)
        tx.multipart("MESSAGE", [("application/sdp", sdp_offer(), []), (ct, body, [])])
        tx.write(out)


FIXTURES.append(xml_hostile)


# --- fixtures: MCPTT information (User Story 1, Appendix A §A.3) ----------------------
def ik(local, parent=None):
    """The rule key of an mcpttInfo element."""
    return el_key(MCPTT_INFO, parent, local)


ENCRYPTABLE = ("mcptt-access-token mcptt-request-uri mcptt-calling-user-id mcptt-called-party-id "
               "mcptt-calling-group-id emergency-ind alert-ind imminentperil-ind originated-by mcptt-client-id "
               "functional-alias-URI called-functional-alias-URI non-acknowledged-user multiple-devices-ind "
               "associated-group-id migration-auth-result partner-mcptt-id primary-mcptt-id "
               "selected-user-profile-index req-type resp-type connected-functional-alias-URI").split()


def mcptt_info_doc(cv, p="", quote='"', encrypted=False, calling=None):
    """Every element and attribute of Appendix A §A.3. p: the prefix ("" = default namespace).
    Canaries in every value a rule does not keep; valid values in the kept ones. With
    encrypted=True every encryptable element carries type="Encrypted" and xenc:EncryptedData."""
    def e(name, *children, attrs=()):
        return El(p + name, *children, attrs=attrs, quote=quote)

    def ct(name, child):
        """A contentType element (TS 24.379 §F.1.2) with its type attribute."""
        if encrypted and name in ENCRYPTABLE:
            return e(name, _enc_data(cv, "xml-ns-enc:" + name), attrs=(("type", "Encrypted"),))
        return e(name, child, attrs=(("type", "Normal"),))

    def uri(name, rule=ik("mcpttURI")):
        return ct(name, e("mcpttURI", cv.uri(rule, "fire.example.net")))

    def boolean(name, v="true"):
        return ct(name, e("mcpttBoolean", v))

    def entry(rule_parent=None):
        return e("entry", e("uri-entry", cv.uri(ik("uri-entry", rule_parent))),
                 e("display-name", cv.s(ik("display-name"), "Canary Name")), e("anyExt"))

    gktp = El("mgktp:GKTP", cv.s(ik("MKFC-GKTPs"), "canary"), attrs=(("id", "1"),), ns=(("mgktp", GKTP),))
    cid = cv.s("xml-replaces:call-id", "canary") + "@fire.example.net"
    any_ext = e(
        "anyExt",
        e("ambient-listening-type", "remote-init"),
        e("release-reason", "not selected for call"),
        e("request-type", "remotely-initiated-private-call-request"),
        ct("req-type", e("mcpttString", "mc-service-authorisation-notify-request")),
        ct("resp-type", e("mcpttString", "get-userlist-adhoc-group-call-response")),
        e("response-type", "transfer-private-call-response"),
        e("urgency-ind", "high"),
        e("time-of-request", "2026-11-14T10:00:00"),
        e("selected-group-change-outcome", "success"),
        e("affiliation-required", "true"),
        e("remotely-initiated-call-outcome", "fail"),
        e("notify-remote-user", "true"),
        uri("functional-alias-URI"),
        e("user-requested-priority", "5"),
        e("used-priority", "4"),
        e("emergency-alert-area-ind", "false"),
        e("group-geo-area-ind", "0"),
        uri("non-acknowledged-user"),
        uri("non-acknowledged-user"),
        e("call-to-functional-alias-ind", "false"),
        boolean("emergency-ind-rcvd"),
        e("call-transfer-ind", "true"),
        boolean("multiple-devices-ind", "false"),
        e("transfer-call-outcome", "success"),
        uri("called-functional-alias-URI"),
        e("call-forwarding-ind", "1"),
        e("forwarding-call-outcome", "fail"),
        e("forwarding-immediate-list", entry(), e("anyExt")),
        e("forwarding-other-list", entry()),
        e("adhoc-alert-participant-list", entry()),
        e("adhoc-alert-participant-not-ack-list", entry()),
        e("forwarding-reason", "no-answer"),
        e("PrivateCallKMSURI", e("PrivateCallKMSURI", e("uri-entry", cv.uri(ik("uri-entry", "PrivateCallKMSURI"),
                                                                             "kms.example.net"))), e("anyExt")),
        e("binding-ind", "true"),
        e("binding-fa-uri", cv.uri(ik("binding-fa-uri"))),
        e("unbinding-fa-uri", cv.uri(ik("unbinding-fa-uri"))),
        e("replaces-header-value", f"{cid};{cv.s('xml-replaces:from-tag', 'canary')};"
                                   f"{cv.s(ik('replaces-header-value'), 'canary')}"),
        e("transfer-announced-ind", "false"),
        e("forwarding-sequence-number", "7"),
        e("forwarded-by-mcptt-id", cv.uri(ik("forwarded-by-mcptt-id"))),
        e("forwarded-by-functional-alias", cv.uri(ik("forwarded-by-functional-alias"))),
        e("forwarding-target-id", cv.uri(ik("forwarding-target-id"))),
        e("forwarding-target-is-functional-alias", "false"),
        e("ric-app-level-priority", "mcpttp.5"),
        e("ric-commencement-mode", "auto-mode"),
        boolean("remotely-initiated-call-request-ind"),
        e("forwarding-target-orig-id", cv.uri(ik("forwarding-target-orig-id"))),
        e("end-to-end-security", "true"),
        e("call-participants-criterias", cv.s(ik("call-participants-criterias"), "canary") + ",role=chief"),
        e("preconfigured-group-id", cv.uri(ik("preconfigured-group-id"))),
        e("adhoc-grp-emg-alert-grp-ind", "false"),
        boolean("migration-auth-result"),
        uri("partner-mcptt-id"),
        (e("selected-user-profile-index", _enc_data(cv, "xml-ns-enc:selected-user-profile-index"),
           attrs=(("type", "Encrypted"),)) if encrypted else
         e("selected-user-profile-index", e("user-profile-index", "2"), attrs=(("type", "Normal"),))),
        uri("primary-mcptt-id"),
        e("adhoc-emergency-ind", "true"),
        e("adhoc-alert-ind", "false"),
        e("adhoc-additional-information", cv.s(ik("adhoc-additional-information"), "Canary text")),
        e("adhoc-emergency-ind-rcvd", "true"),
        e("adhoc-alert-ind-rcvd", "true"),
        uri("location-of-functional-alias-URI"),
        uri("connected-functional-alias-URI"),
    )
    params = e(
        "mcptt-Params",
        ct("mcptt-access-token", e("mcpttString", cv.s(ik("mcpttString", "mcptt-access-token"), "eyJcanary"))),
        e("session-type", "private"),
        uri("mcptt-request-uri"),
        (ct("mcptt-calling-user-id", e("mcpttURI", calling)) if calling else uri("mcptt-calling-user-id")),
        uri("mcptt-called-party-id"),
        uri("mcptt-calling-group-id"),
        boolean("required"),
        boolean("emergency-ind", "false"),
        boolean("alert-ind", "false"),
        boolean("imminentperil-ind", "false"),
        e("broadcast-ind", "false"),
        e("mc-org", cv.s(ik("mc-org"), "Canary Org")),
        e("floor-state", "floor-taken"),
        uri("associated-group-id"),
        uri("originated-by"),
        e("MKFC-GKTPs", gktp),
        ct("mcptt-client-id", e("mcpttString", "urn:uuid:" + cv.uuid(ik("mcpttString", "mcptt-client-id")))),
        boolean("alert-ind-rcvd", "false"),
        e("gw-mcptt-usage", "true"),
        any_ext,
    )
    ns = (("", MCPTT_INFO),) if not p else ((p[:-1], MCPTT_INFO),)
    return El(p + "mcpttinfo", params, e("anyExt", e("urgency-ind", "low")), ns=ns, quote=quote)


def mcptt_info_odd(cv):
    """The parent-qualified and malformed shapes: every child of mcptt-access-token removed as a
    credential (A4), an mcpttString under another contentType (free text, A1), a URI written with
    a character reference, garbage text in a URI element, a KMS URI as a bare host (A3)."""
    v = cv.s(ik("mcpttURI", "mcptt-access-token"), "canary")
    body = (f'<mcpttinfo xmlns="{MCPTT_INFO}"><mcptt-Params>\r\n'
            f'<mcptt-access-token type="Normal"><mcpttURI>sip:{v}@fire.example.net</mcpttURI>'
            f'<mcpttBoolean>{cv.s(ik("mcpttBoolean", "mcptt-access-token"), "canary")}</mcpttBoolean>'
            f'<anyExt><x>{cv.s(ik("anyExt", "mcptt-access-token"), "canary")}</x></anyExt></mcptt-access-token>\r\n'
            f'<originated-by type="Normal"><mcpttString>{cv.s(ik("mcpttString"), "canary")}</mcpttString>'
            f'</originated-by>\r\n'
            f'<mcptt-calling-user-id type="Normal"><mcpttURI>sip:{cv.s("xml-charref:user", "canary")}&#x40;'
            f'fire.example.net</mcpttURI></mcptt-calling-user-id>\r\n'
            f'<mcptt-called-party-id type="Normal"><mcpttURI>not a uri {cv.s("xml-garbage:uri", "canary")}'
            f'</mcpttURI></mcptt-called-party-id>\r\n'
            f'<anyExt><PrivateCallKMSURI><PrivateCallKMSURI><uri-entry>'
            f'{cv.s("xml-kms:host", "canary")}.example.net</uri-entry></PrivateCallKMSURI></PrivateCallKMSURI>'
            f'</anyExt></mcptt-Params></mcpttinfo>\r\n')
    return body.encode()


def xml_mcptt(c, out):
    """mcptt-info carried by INVITE (multipart with SDP), 200 OK, REFER, MESSAGE and INFO; the
    default namespace with double quotes, a prefix with single quotes; every encryptable
    element encrypted; the odd shapes of mcptt_info_odd."""
    fname = "xml_mcptt_info.pcapng"
    cv = Cv(c, fname)
    tx = Sender(fname)
    # US1 scenario 2: the calling MCPTT ID also in P-Asserted-Identity.
    calling = cv.uri(ik("mcpttURI"), "fire.example.net")
    plain = doc(mcptt_info_doc(cv, calling=calling))
    prefixed = doc(mcptt_info_doc(cv, "m:", "'"), indent=None)
    enc = doc(mcptt_info_doc(cv, encrypted=True))
    tx.multipart("INVITE", [("application/sdp", sdp_offer(), []), (MCPTT_INFO_CT, plain, [])],
                 extra=[("P-Asserted-Identity", f"<{calling}>")])
    tx.response(200, "OK", "INVITE", MCPTT_INFO_CT, prefixed)
    tx.request("REFER", MCPTT_INFO_CT, enc, extra=[("Refer-To", "<sip:ue-c@example.net>")])
    tx.request("MESSAGE", MCPTT_INFO_CT, mcptt_info_odd(cv))
    tx.request("INFO", MCPTT_INFO_CT, plain)
    tx.write(out)


FIXTURES.append(xml_mcptt)


# --- fixtures: User Story 2 (Appendix E §E.3-E.4, Appendix B §B.7) -------------------
RL_NS = "urn:ietf:params:xml:ns:resource-lists"
RLX_NS = "urn:3gpp:ns:mcpttResLists:1.0"
PIDF_NS = "urn:ietf:params:xml:ns:pidf"
AFF_NS = "urn:3gpp:ns:affiliationCommand:1.0"
PRES = {"mcptt": ("urn:3gpp:ns:mcpttPresInfo:1.0", True), "mcdata": ("urn:3gpp:ns:mcdataPresInfo:1.0", False),
        "mcvideo": ("urn:3gpp:ns:mcvideoPresInfo:1.0", True)}
PRES_FA = {"mcptt": "urn:3gpp:ns:mcpttPresInfoFA:1.0", "mcdata": "urn:3gpp:ns:mcdataPresInfoFA:1.0",
           "mcvideo": "urn:3gpp:ns:mcvideoPresInfoFA:1.0"}


def hesc(v):
    """RFC 3261 §25.1 hvalue escaping (unreserved kept)."""
    out = []
    for b in v.encode():
        ch = chr(b)
        out.append(ch if ch.isalnum() or ch in "-_.!~*'()" else "%%%02X" % b)
    return "".join(out)


def resource_lists_doc(cv, entries_extra=()):
    rk = lambda local, parent=None: el_key(RL_NS, parent, local)  # noqa: E731
    ak = lambda element, attr: attr_key(RL_NS, element, attr)  # noqa: E731
    name = lambda: El("display-name", cv.s(rk("display-name"), "Canary Display"), attrs=(("xml:lang", "en"),))  # noqa: E731
    inner = El("list", name(),
               El("entry", name(), attrs=(("uri", cv.uri(ak("entry", "uri"), "fire.example.net")),)),
               attrs=(("name", cv.s(ak("list", "name"), "canary")),))
    root = El("resource-lists",
              El("list",
                 name(),
                 El("entry", name(), El("fa:functional-alias", cv.uri(el_key(RLX_NS, None, "functional-alias"))),
                    attrs=(("uri", cv.uri(ak("entry", "uri"), "fire.example.net")),)),
                 El("entry", attrs=(("uri", "tel:+48" + c_digits(cv, 9)),)),
                 El("entry", attrs=(("uri", "urn:service:sos"),)),
                 El("entry", attrs=(("uri", "org.3gpp.mcptt.user-profile/users/"
                                     + cv.uri(ak("entry", "uri")) + "/mcptt-user-profile-0.xml"),)),
                 El("entry-ref", name(), attrs=(("ref", "resource-lists/users/" + cv.uri(ak("entry-ref", "ref"))
                                                 + "/index/~~/resource-lists/list%5b@name=%22friends%22%5d"),)),
                 El("external", name(), attrs=(("anchor", "https://xcap.example.net/resource-lists/users/"
                                                + cv.uri(ak("external", "anchor")) + "/index"),)),
                 inner,
                 *entries_extra,
                 attrs=(("name", "friends"),)),
              ns=(("", RL_NS), ("fa", RLX_NS)))
    return doc(root)


def c_digits(cv, n):
    """A canary number of n digits (recorded as a number canary)."""
    return cv.c.number(cv.f, n, rule="xml-tel:entry")


def pidf_doc(cv, service, vendor=False):
    pns, group = PRES[service]
    fns = PRES_FA[service]
    pk = lambda local: el_key(pns, None, local)  # noqa: E731
    pa = lambda element, attr: attr_key(pns, element, attr)  # noqa: E731
    fa = lambda element, attr: attr_key(fns, element, attr)  # noqa: E731
    status = [El("pidf:basic", "open"),
              El("p:affiliation", attrs=(("group", cv.uri(pa("affiliation", "group"))),
                                         ("client", "urn:uuid:" + cv.uuid(pa("affiliation", "client"))),
                                         ("status", "affiliated"), ("expires", "2026-11-14T12:00:00Z"))),
              El("p:functionalAlias", attrs=(("functionalAliasID", cv.uri(pa("functionalAlias", "functionalAliasID"))),
                                             ("expires", "2026-11-14T12:00:00Z"))),
              El("f:functionalAlias", attrs=(("functionalAliasID", cv.uri(fa("functionalAlias", "functionalAliasID"))),
                                             ("user", cv.uri(fa("functionalAlias", "user"))),
                                             ("status", "take-over-possible"), ("expires", "2026-11-14T12:00:00Z"))),
              El("f:take-over", "false")]
    if vendor:
        status.append(El("v:secret", cv.s("xml-pidf:vendor", "canary"), ns=(("v", VENDOR),)))
    top = [El("pidf:tuple",
              El("pidf:status", *status),
              El("pidf:contact", cv.uri(el_key(PIDF_NS, None, "contact")), attrs=(("priority", "0.8"),)),
              El("pidf:note", cv.s(el_key(PIDF_NS, None, "note"), "Canary note"), attrs=(("xml:lang", "en"),)),
              El("pidf:timestamp", "2026-11-14T10:00:00Z"),
              attrs=(("id", cv.s(attr_key(PIDF_NS, "tuple", "id"), "canary")),)),
           El("pidf:tuple", El("pidf:status", El("pidf:basic", "closed")),
              attrs=(("id", "urn:uuid:" + cv.uuid(attr_key(PIDF_NS, "tuple", "id"))),)),
           El("p:p-id", cv.s(pk("p-id"), "canary")),
           El("f:p-id-fa", cv.s(el_key(fns, None, "p-id-fa"), "canary"))]
    if group:
        top += [El("p:groupStatus", "emergency", attrs=(("ModifiedBy", cv.uri(pa("groupStatus", "ModifiedBy"))),)),
                El("p:additionalData", attrs=(("groupBroadcastAlias", cv.uri(pa("additionalData", "groupBroadcastAlias"))),
                                              ("groupRegroupAlias", cv.uri(pa("additionalData", "groupRegroupAlias"))),
                                              ("groupCallOngoing", "true")))]
    root = El("pidf:presence", *top, attrs=(("entity", cv.uri(attr_key(PIDF_NS, "presence", "entity"))),),
              ns=(("pidf", PIDF_NS), ("p", pns), ("f", fns)))
    return doc(root)


def affiliation_doc(cv):
    g = lambda: El("group", cv.uri(el_key(AFF_NS, None, "group")))  # noqa: E731
    return doc(El("command-list", El("affiliate", g(), g(), El("anyExt")), El("de-affiliate", g()), El("anyExt"),
                  ns=(("", AFF_NS),)))


def xml_ietf_us2(c, out):
    """resource-lists in an INVITE target list and in MESSAGE; pidf PUBLISH/NOTIFY for the three
    services, one with a vendor element; the affiliation command for the three services."""
    fname = "xml_ietf_us2.pcapng"
    cv = Cv(c, fname)
    tx = Sender(fname)
    tx.multipart("INVITE", [("application/sdp", sdp_offer(), []),
                            ("application/resource-lists+xml", resource_lists_doc(cv), [])])
    tx.request("MESSAGE", "application/resource-lists+xml", resource_lists_doc(cv))
    for svc in ("mcptt", "mcdata", "mcvideo"):
        tx.request("PUBLISH", "application/pidf+xml", pidf_doc(cv, svc, vendor=svc == "mcdata"),
                   extra=[("Event", "presence")])
        tx.request("MESSAGE", f"application/vnd.3gpp.{svc}-affiliation-command+xml", affiliation_doc(cv))
    tx.write(out)


def xml_embedded(c, out):
    """REFER for pre-established sessions (TS 24.379 §11.1.1.2.2.1): resource-lists entry URIs with
    URI headers Content-Type and body (mcptt-info; SDP with mc_implicit_request; multipart with a
    boundary), an undecodable body, a body without Content-Type, an unknown type and a nested
    embedded body."""
    fname = "xml_embedded.pcapng"
    cv = Cv(c, fname)
    tx = Sender(fname)
    ak = attr_key(RL_NS, "entry", "uri")
    info = doc(mcptt_info_small(cv))
    sdp = S.sdp(["v=0", "o=" + cv.s("xml-embedded:sdp-user", "canary") + " 2890844526 1 IN IP4 10.30.0.11", "s=-",
                 "c=IN IP4 10.30.0.11", "t=0 0", "m=audio 40000 RTP/AVP 96", "a=rtpmap:96 AMR-WB/16000",
                 "m=application 40002 udp MCPTT", "a=fmtp:MCPTT mc_queueing;mc_implicit_request"])
    mp = S.multipart("emb-bnd-7", [([("Content-Type", "application/sdp")], sdp),
                                   ([("Content-Type", MCPTT_INFO_CT)], info)])
    nested_rl = doc(El("resource-lists", El("list", El("entry", attrs=(
        ("uri", cv.uri(ak) + "?Content-Type=" + hesc(MCPTT_INFO_CT) + "&body=" + hesc(info.decode())),))),
        ns=(("", RL_NS),)))

    def entry(headers):
        return El("entry", attrs=(("uri", cv.uri(ak, "fire.example.net") + "?" + headers),))
    entries = [
        entry("Content-Type=" + hesc(MCPTT_INFO_CT) + "&body=" + hesc(info.decode())),
        entry("Content-Type=application%2Fsdp&body=" + hesc(sdp.decode())),
        entry("Content-Type=" + hesc("multipart/mixed;boundary=emb-bnd-7") + "&body=" + hesc(mp.decode())),
        entry("Content-Type=" + hesc(MCPTT_INFO_CT) + "&body=%3Cmcpttinfo%G1" + cv.s("xml-embedded:undecodable", "canary")),
        entry("body=" + hesc("<x>" + cv.s("xml-embedded:no-type", "canary") + "</x>")),
        entry("Content-Type=application%2Fx-vendor&body=" + hesc(cv.s("xml-embedded:unknown-type", "canary"))),
        entry("Content-Type=" + hesc("application/resource-lists+xml") + "&body=" + hesc(nested_rl.decode())),
    ]
    rl = doc(El("resource-lists", El("list", *entries), ns=(("", RL_NS),)))
    tx.multipart("REFER", [("application/resource-lists+xml", rl, [])],
                 extra=[("Refer-To", "<cid:emb-list@example.net>"), ("Refer-Sub", "false")])
    tx.request("REFER", "application/resource-lists+xml", rl, extra=[("Refer-To", "<sip:ue-c@example.net>")])
    tx.write(out)


def mcptt_info_small(cv):
    return El("mcpttinfo", El("mcptt-Params",
                              El("session-type", "prearranged"),
                              El("mcptt-calling-user-id", El("mcpttURI", cv.uri(ik("mcpttURI"), "fire.example.net")),
                                 attrs=(("type", "Normal"),))),
              ns=(("", MCPTT_INFO),))


FIXTURES.append(xml_ietf_us2)
FIXTURES.append(xml_embedded)


# --- fixtures: User Story 3, location (Appendix B §B.3, §B.4) -------------------------
LOC = {"mcptt": ("urn:3gpp:ns:mcpttLocationInfo:1.0", "application/vnd.3gpp.mcptt-location-info+xml"),
       "mcdata": ("urn:3gpp:ns:mcdataLocationInfo:1.0", "application/vnd.3gpp.mcdata-location-info+xml"),
       "mcvideo": ("urn:3gpp:ns:mcvideoLocationInfo:1.0", "application/vnd.3gpp.mcvideo-location-info+xml")}
LOC_ALIAS_CT = "application/vnd.3gpp.location-info+xml"


def _bits(v, n):
    return format(v, "0%db" % n)


class LocCv:
    """Canaries of a location document; values have the field formats of Appendix B."""

    def __init__(self, cv, ns):
        self.cv, self.ns, self.r = cv, ns, cv.c.rng

    def k(self, local, parent=None):
        return el_key(self.ns, parent, local)

    def text(self, local, make):
        """A canary drawn by `make` until it is not planted yet."""
        for _ in range(1000):
            v = make()
            if v not in self.cv.c._used:
                return self.cv.text(v, self.k(local))
        raise RuntimeError("cannot draw a unique location canary")

    def plmn(self):
        return "262" + "%03d" % self.r.randrange(100, 999)

    def ecgi(self, local):
        return self.text(local, lambda: self.plmn() + _bits(self.r.getrandbits(28) | 1 << 20, 28))

    def ncgi(self, local):
        return self.text(local, lambda: self.plmn() + _bits(self.r.getrandbits(36) | 1 << 30, 36))

    def tai(self, local):
        return self.text(local, lambda: self.plmn() + _bits(self.r.getrandbits(16) | 1 << 12, 16))

    def hexv(self, local, n):
        """A hex canary. Up to 6 digits it is flagged `chance`: such strings occur by chance in the
        hex of pseudonym labels and digests, so the oracle does not search them (as the short
        binary canaries of 004); the scanner does not either (N17)."""
        v = self.text(local, lambda: "".join(self.r.choice("0123456789abcdefABCDEF") for _ in range(n)))
        if n <= 6:
            self.cv.c.items[-1]["chance"] = True
        return v

    def short_dec(self, local, lo, hi):
        """A value of at most 3 digits: recorded for rule coverage, but too short to search (as
        the short binary values of 004), so it is a 3-character string canary."""
        return self.text(local, lambda: str(self.r.randrange(lo, hi)))

    def dec(self, local, lo, hi):
        """A decimal canary, matched on digit boundaries (a number canary)."""
        for _ in range(1000):
            v = str(self.r.randrange(lo, hi))
            if v not in self.cv.c._used:
                self.cv.c._used.add(v)
                return self.cv.c._add("number", v, None, self.cv.f, self.k(local))
        raise RuntimeError("cannot draw a unique location canary")


def short_hex(lc, local):
    """A 4-hex-digit canary (TAC, SAI): recorded for rule coverage, flagged `chance` by hexv."""
    return lc.hexv(local, 4)


def location_config(lc, svc):
    t = lambda name: (("TriggerId", f"trig-{name}"),)  # noqa: E731
    ev = {"mcptt": "McpttSignallingEvent", "mcdata": "McdataSignallingEvent", "mcvideo": "McvideoSignallingEvent"}[svc]

    def tc(name):
        corner = lambda: El("Corner", El("longitude", El("threebytes", str(lc.r.randrange(1000000, 9999999)))),  # noqa: E731
                            El("latitude", El("threebytes", str(lc.r.randrange(1000000, 9999999)))))
        return El(name,
                  El("CellChange", El("AnyCellChange", attrs=t("cell")),
                     El("EnterSpecificCell", lc.ecgi("EnterSpecificCell"), attrs=t("enter-cell")),
                     El("ExitSpecificCell", lc.ecgi("ExitSpecificCell"), attrs=t("exit-cell")),
                     El("anyExt", El("EnterSpecificNRCell", lc.ncgi("EnterSpecificNRCell"), attrs=t("enter-nr")),
                        El("ExitSpecificNRCell", lc.ncgi("ExitSpecificNRCell"), attrs=t("exit-nr")))),
                  El("TrackingAreaChange", El("AnyTrackingAreaChange", attrs=t("ta")),
                     El("EnterSpecificTrackingArea", lc.tai("EnterSpecificTrackingArea"), attrs=t("enter-ta")),
                     El("ExitSpecificTrackingArea", lc.tai("ExitSpecificTrackingArea"), attrs=t("exit-ta"))),
                  El("PlmnChange", El("AnyPlmnChange", attrs=t("plmn")),
                     El("EnterSpecificPlmn", lc.text("EnterSpecificPlmn", lc.plmn), attrs=t("enter-plmn")),
                     El("ExitSpecificPlmn", lc.text("ExitSpecificPlmn", lc.plmn), attrs=t("exit-plmn"))),
                  El("MbmsSaChange", El("AnyMbmsSaChange", attrs=t("sa")),
                     El("EnterSpecificMbmsSa", lc.dec("EnterSpecificMbmsSa", 10000, 65535), attrs=t("enter-sa")),
                     El("ExitSpecificMbmsSa", lc.dec("ExitSpecificMbmsSa", 10000, 65535), attrs=t("exit-sa"))),
                  El("MbsfnAreaChange",
                     El("EnterSpecificMbsfnArea", lc.short_dec("EnterSpecificMbsfnArea", 100, 255), attrs=t("enter-mbsfn")),
                     El("ExitSpecificMbsfnArea", lc.short_dec("ExitSpecificMbsfnArea", 100, 255), attrs=t("exit-mbsfn")),
                     El("anyExt", El("AnyMbsfnAreaChange", attrs=t("mbsfn")))),
                  El("PeriodicReport", "60", attrs=t("periodic")),
                  El("TravelledDistance", "200", attrs=t("distance")),
                  El(ev, El("InitialLogOn", attrs=t("logon")), El("GroupCallNonEmergency", attrs=t("gc")),
                     El("PrivateCallNonEmergency", attrs=t("pc")), El("LocationConfigurationReceived", attrs=t("lcr")),
                     El("anyExt", El("FunctionalAliasActivation", attrs=t("fa-on")),
                        El("FunctionalAliasDeactivation", attrs=t("fa-off")))),
                  El("GeographicalAreaChange", El("AnyAreaChange", attrs=t("area")),
                     El("EnterSpecificAreaType",
                        El("GeographicalArea", El("PolygonArea", corner(), corner(), corner()),
                           El("anyExt", El("InnerBorderWidth", "5"), El("OuterBorderWidth", "10"))),
                        attrs=t("enter-area")),
                     El("ExitSpecificAreaType",
                        El("GeographicalArea", El("EllipsoidArcArea",
                                                  El("Center", El("longitude", El("threebytes", "1234567")),
                                                     El("latitude", El("threebytes", "7654321"))),
                                                  El("Radius", "500"), El("OffsetAngle", "10"), El("IncludedAngle", "90"))),
                        attrs=t("exit-area"))),
                  El("anyExt",
                     El("RatTypeChange", El("AnyRatTypeChange", attrs=t("rat"))),
                     El("NR5GMbsfsaAreaChange",
                        El("EnterSpecific5GMbsfsaArea", lc.hexv("EnterSpecific5GMbsfsaArea", 6), attrs=t("enter-fsa")),
                        El("ExitSpecific5GMbsfsaArea", lc.hexv("ExitSpecific5GMbsfsaArea", 6), attrs=t("exit-fsa")),
                        El("anyExt", El("Any5GMbsfsaAreaChange", attrs=t("fsa")))),
                     El("NR5GTrackingAreaChange", El("Any5GTrackingAreaChange", attrs=t("5gta")),
                        El("EnterSpecific5GTrackingArea", short_hex(lc, "EnterSpecific5GTrackingArea"),
                           attrs=t("enter-5gta")),
                        El("ExitSpecific5GTrackingArea", lc.hexv("ExitSpecific5GTrackingArea", 6), attrs=t("exit-5gta"))),
                     El("AddaptiveTrigger", El("MinPeriod", "10", attrs=t("minp")), El("MinDistance", "50"),
                        El("PersistencePeriod", "30", attrs=t("persist")), El("AdditionalTime", "5"),
                        El("RRC_INACTIVE_MinPeriod", "20", attrs=t("rrc-minp")),
                        El("RRC_INACTIVE_MinDistance", "100", attrs=t("rrc-mind")),
                        El("RRC_INACTIVE_PersistencePeriod", "40", attrs=t("rrc-persist")),
                        El("RRC_INACTIVE_AdditionalTime", "8", attrs=t("rrc-add")), attrs=t("adaptive"))))

    rl = lambda name: El(name, El("ServingEcgi"), El("NeighbouringEcgi"), El("MbmsSaId"), El("MbsfnArea"),  # noqa: E731
                         El("GeographicalCoordinate"), El("minimumIntervalLength", "10"),
                         El("anyExt", El("ServingNcgi"), El("NeighbouringNcgi"), El("NR5GMbsfsaArea"),
                            El("R_BearingAndSpeed")))
    return El("location-info",
              El("Configuration", rl("NonEmergencyLocationInformation"), rl("EmergencyLocationInformation"),
                 tc("TriggeringCriteria"), El("anyExt", tc("EmergencyTriggeringCriteria")),
                 attrs=(("ConfigScope", "Full"),)),
              ns=(("", lc.ns),))


def location_request(lc):
    rid = lc.cv.s(attr_key(lc.ns, "Request", "RequestId"), "req")
    return El("location-info",
              El("Request", El("anyExt", El("LocationFilter", El("AreaIdentifier", "trig-enter-area"),
                                            El("AreaIn", "true"))),
                 attrs=(("RequestId", rid), ("refresh", "true"))),
              ns=(("", lc.ns),)), rid


def location_report(lc, svc, rid, encrypted=False, ecgi=None):
    uri_el = {"mcptt": "mcptt-reporting-uri", "mcdata": "mcdata-reporting-uri", "mcvideo": "mcvideo-reporting-uri"}[svc]
    N = lambda: (("type", "Normal"),)  # noqa: E731

    def coord(name, inner, digits):
        if encrypted:
            return El(name, _enc_data(lc.cv, "xml-loc-enc:" + name), attrs=(("type", "Encrypted"),))
        if inner == "twobytes":
            value = "-" + lc.dec(inner, 20000, 32768)  # altitude: 5 digits, rarely met by chance
        elif digits:
            value = lc.cv.c.number(lc.cv.f, digits, rule=lc.k(inner))
        else:
            value = lc.text(inner, lambda: "1" + "%02d" % lc.r.randrange(10, 27))
        return El(name, El(inner, value), attrs=N())

    def lt(name, inner, value, enc_ok=True):
        if encrypted and enc_ok:
            return El(name, _enc_data(lc.cv, "xml-loc-enc:" + name), attrs=(("type", "Encrypted"),))
        return El(name, inner if isinstance(inner, El) else El(inner, value), attrs=N())

    serving = ecgi or lc.ecgi("Ecgi")
    cl = El("CurrentLocation",
            lt("CurrentServingEcgi", "Ecgi", serving),
            lt("NeighbouringEcgi", "Ecgi", lc.ecgi("Ecgi")),
            lt("MbmsSaId", "SaId", lc.dec("SaId", 10000, 65535)),
            lt("MbsfnArea", "MbsfnAreaId", lc.short_dec("MbsfnAreaId", 100, 255)),
            El("CurrentCoordinate", coord("longitude", "threebytes", 7), coord("latitude", "threebytes", 7),
               El("anyExt", coord("altitude", "twobytes", 4), coord("horizontalaccuracy", "onebyteunsignedhalfrange", 0),
                  coord("verticalaccuracy", "onebyteunsignedhalfrange", 0))),
            El("anyExt",
               lt("CurrentServingNcgi", El("anyExt", El("Ncgi", lc.ncgi("Ncgi"))), None),
               lt("CL_NeighbouringNcgi", "Ncgi", lc.ncgi("Ncgi")),
               lt("CL_5GMbsfsaArea", "NR5GMbsfsaAreaId", lc.hexv("NR5GMbsfsaAreaId", 6)),
               (El("CL_BearingAndSpeed", _enc_data(lc.cv, "xml-loc-enc:bearing"), attrs=(("type", "Encrypted"),))
                if encrypted else El("CL_BearingAndSpeed", El("BearingAndSpeed", lc.hexv("BearingAndSpeed", 14)), attrs=N())),
               El("locTimestamp", "2026-11-14T10:00:00Z"),
               El("FunctionalAlias", lc.cv.uri(lc.k("FunctionalAlias"))),
               El("InterRatType", "LTE-MBMS-to-5G-MBS")))
    return El("location-info",
              El("Report", El("TriggerId", "trig-enter-cell"), El(uri_el, lc.cv.uri(lc.k(uri_el))), cl,
                 attrs=(("ReportID", lc.cv.text(rid, attr_key(lc.ns, "Report", "ReportID"))
                         if rid else lc.cv.s(attr_key(lc.ns, "Report", "ReportID"), "rep")),
                        ("ReportType", "NonEmergency"))),
              ns=(("", lc.ns),))


def xml_location(c, out):
    """Configuration, request and report (plain and encrypted) for the three location
    namespaces, and the alias Content-Type with an MCData root (X6)."""
    fname = "xml_location.pcapng"
    cv = Cv(c, fname)
    tx = Sender(fname)
    for svc, (ns, ct) in LOC.items():
        lc = LocCv(cv, ns)
        tx.request("MESSAGE", ct, doc(location_config(lc, svc)))
        req, rid = location_request(lc)
        tx.request("MESSAGE", ct, doc(req))
        # The report answers the request: one opaque pseudonym for RequestId and ReportID (X3).
        tx.request("MESSAGE", ct, doc(location_report(lc, svc, None)))
        tx.request("MESSAGE", ct, doc(location_report(lc, svc, None, encrypted=True)))
    lc = LocCv(cv, LOC["mcdata"][0])
    tx.request("MESSAGE", LOC_ALIAS_CT, doc(location_report(lc, "mcdata", None)))
    tx.write(out)


def xml_location_fc(c, out):
    """SC-003: one ECGI in a floor control Location field (004) and in an XML location report."""
    import media as M
    fname = "xml_location_fc.pcapng"
    cv = Cv(c, fname)
    lc = LocCv(cv, LOC["mcptt"][0])
    eci = lc.r.getrandbits(28) | 1 << 24
    ecgi = lc.text("Ecgi", lambda: "262010" + _bits(eci, 28))
    # Random SSRCs: a patterned value (0x11223344) occurs in other fixtures' headers and would hit
    # as a mapping token there.
    sa, sb = (cv.c.binary(fname, "sdp:a=fmtp:MCPTT.mc_floor_ssrc", low=1 << 24) for _ in range(2))
    sa, sb = int(sa), int(sb)
    call = M.Call([M.m_audio(40000), M.m_floor(40002, floor_ssrc=sa)],
                  [M.m_audio(50000), M.m_floor(50002, floor_ssrc=sb)], a=UE_A, b=UE_B)
    loc = bytes([1]) + M._bcd_plmn("262", "010") + struct.pack("!I", eci)
    call.a_to_b(40002, 50002, M.app(b"MCPT", 0, sa, M.app_field(0, b"\x05\x00") + M.app_field(19, loc)))
    msg = S.request("MESSAGE", "sip:ue-b@example.net",
                    [("Via", "SIP/2.0/UDP 10.30.0.11:5060;branch=z9hG4bKloc1"), ("From", "<sip:ue-a@example.net>;tag=l1"),
                     ("To", "<sip:ue-b@example.net>"), ("Call-ID", "loc-fc@example.net"), ("CSeq", "1 MESSAGE"),
                     ("Content-Type", LOC["mcptt"][1])], doc(location_report(lc, "mcptt", None, ecgi=ecgi)))
    call.a_to_b(5060, 5060, msg)
    call.write(out, fname, fc_ports=[40002, 50002])
    MANIFEST[fname] = [{"frame": 4, "part": None, "content_type": LOC["mcptt"][1]}]


FIXTURES.append(xml_location)
FIXTURES.append(xml_location_fc)


# --- fixtures: User Story 4, MCPTT documents (Appendix A §A.4-A.6, Appendix B §B.5-B.6) --
FLOOR_NS = "urn:3gpp:ns:mcpttFloorRequest:1.0"
MBMS_NS = "urn:3gpp:ns:mcpttMbmsUsage:1.0"
MBS_NS = "urn:3gpp:ns:mcpttMbsUsage:1.0"
REGROUP_NS = "urn:3gpp:ns:preconfiguredRegroup:1.0"
SIGNED_NS = "urn:3gpp:ns:mcpttSignedDoc:1.0"
DSIG_NS = "http://www.w3.org/2000/09/xmldsig#"


def _hex(cv, key, n):
    """A random hex canary of n digits for `key`."""
    r = cv.c.rng
    for _ in range(1000):
        v = "".join(r.choice("0123456789abcdef") for _ in range(n))
        if v not in cv.c._used:
            out = cv.text(v, key)
            if n <= 6:
                cv.c.items[-1]["chance"] = True  # see LocCv.hexv
            return out
    raise RuntimeError("no unique hex canary")


def floor_request_doc(cv):
    k = lambda local: el_key(FLOOR_NS, None, local)  # noqa: E731
    return El("mcptt-floor-request",
              El("floor-type", "general"),
              El("ssrc", cv.c.binary(cv.f, k("ssrc"), low=1 << 24)),
              El("floor-priority", "7"),
              El("user-id", cv.uri(k("user-id"))),
              El("track-info", El("queueing-capability", "1"),
                 El("participant-type", cv.s(k("participant-type"), "canary")),
                 El("floor-participant-reference", cv.c.binary(cv.f, k("floor-participant-reference"), low=1 << 24)),
                 El("floor-participant-reference", cv.c.binary(cv.f, k("floor-participant-reference"), low=1 << 24))),
              El("floor-indicator", "4096"),
              ns=(("", FLOOR_NS),))


def mbms_usage_doc(cv):
    k = lambda local: el_key(MBMS_NS, None, local)  # noqa: E731
    return El("mcptt-mbms-usage-info",
              El("mbms-listening-status", El("mbms-listening-status", "listening"),
                 El("session-id", cv.uri(k("session-id"))), El("general-purpose", "true"),
                 El("TMGI", _hex(cv, k("TMGI"), 12)), El("anyExt", El("mbms-reception-quality", "4"))),
              El("mbms-suspension-status", El("mbms-suspension-status", "suspending"),
                 El("number-of-reported-bearers", "1a"), El("suspended-TMGI", _hex(cv, k("suspended-TMGI"), 12)),
                 El("other-TMGI", _hex(cv, k("other-TMGI"), 12))),
              El("announcement", El("TMGI", _hex(cv, k("TMGI"), 12)), El("QCI", "65"), El("frequency", "2112400"),
                 El("mbms-service-areas", El("mbms-service-area-id", _hex(cv, k("mbms-service-area-id"), 4))),
                 El("GPMS", "2"), El("report-suspension", "true"),
                 El("anyExt", El("mcptt-mbms-rohc"), El("max-cid", "15"))),
              El("version", "1"),
              El("anyExt", El("mbms-defaultMuSiK-download", El("group", cv.uri(k("group")))),
                 El("mbms-explicitMuSiK-download", El("group", cv.uri(k("group"))))),
              ns=(("", MBMS_NS),))


def mbs_usage_doc(cv):
    k = lambda local: el_key(MBS_NS, None, local)  # noqa: E731
    sess = lambda local: _hex(cv, k(local), 12)  # noqa: E731
    v4 = cv.c.ipv4(None, cv.f, rule=k("IPv4Address"))
    v6 = cv.c.ipv6(None, cv.f, rule=k("IPv6Address"))
    return El("mcptt-mbs-usage-info",
              El("mbs-listening-status", El("mbs-listening-status", "not-listening"),
                 El("unicast-listening-status", "listening"), El("session-id", cv.uri(k("session-id"))),
                 El("general-purpose", "false"), El("mbs-session-id", sess("mbs-session-id"))),
              El("mbs-session-de-announcement-status", El("mbs-session-de-announcement-status", "deleting"),
                 El("number-of-reported-sessions", "2"), El("deleted-mbs-session-id", sess("deleted-mbs-session-id")),
                 El("other-mbs-session-id", sess("other-mbs-session-id"))),
              El("ue-session-join-notification", El("mbs-multicast-joining-status", "ue-session-join"),
                 El("mbs-session-id", sess("mbs-session-id")), El("session-id", cv.uri(k("session-id")))),
              El("announcement",
                 El("mbs-session-info", El("mbs-session-id", sess("mbs-session-id")), El("mbs-session-mode", "multicast"),
                    El("mc-service-group-id", cv.c.number(cv.f, 8, rule=k("mc-service-group-id"))),
                    El("frequency", "632628"), El("GPMS", "3"),
                    El("mbs-service-areas", El("mbs-service-area-id", _hex(cv, k("mbs-service-area-id"), 4))),
                    El("report-ue-session-join-notification", "true"),
                    El("multicast-mbs-session-related-info",
                       El("PlmnId", cv.text("2620" + "%02d" % cv.c.rng.randrange(10, 99), k("PlmnId")),
                          attrs=(("TriggerId", "plmn-1"),)),
                       El("DNN", cv.s(k("DNN"), "canary") + ".apn.example.net"),
                       El("IPInformation", El("IPInformationListEntry", El("IPv4Address", v4)),
                          El("IPInformationListEntry", El("IPv6Address", v6)),
                          El("IPInformationListEntry", El("FQDN", cv.s(k("FQDN"), "canary") + ".example.net"))),
                       El("MC-ID-ref-SNSSAI", _hex(cv, k("MC-ID-ref-SNSSAI"), 8))),
                    El("mbs-fsa-id", _hex(cv, k("mbs-fsa-id"), 6)),
                    El("mbs-session-de-announcement-acknowledgement", "false")),
                 El("eMBMS-bearer-info", El("TMGI", _hex(cv, k("TMGI"), 12)),
                    El("Alternative-TMGI", El("Alternative-TMGI-id", _hex(cv, k("Alternative-TMGI-id"), 12))),
                    El("QCI", "65"), El("frequency", "2112400"),
                    El("mbms-service-areas", El("mbms-service-area-id", _hex(cv, k("mbms-service-area-id"), 4))),
                    El("GPMS", "2"), El("report-suspension", "false"),
                    El("anyExt", El("mcptt-mbs-rohc"), El("max-cid", "15")))),
              El("version", "1"),
              El("anyExt", El("mbs-defaultMuSiK-download", El("group", cv.uri(k("group")))),
                 El("mbs-explicitMuSiK-download", El("group", cv.uri(k("group"))))),
              ns=(("", MBS_NS),))


def regroup_doc(cv, svc):
    k = lambda local, parent=None: el_key(REGROUP_NS, parent, local)  # noqa: E731
    ru = f"{svc}-regroup-uri"
    return El(f"{svc}regroup",
              El(f"{svc}regroup-Params",
                 El("preconfig-group-id", El("preconfigured-group", cv.uri(k("preconfigured-group"))), El("anyExt")),
                 El(ru, El(ru, cv.uri(k(ru, ru)))),
                 El("groups-for-regroup", El("group", cv.uri(k("group"))), El("group", cv.uri(k("group")))),
                 El("users-for-regroup", El("user", cv.uri(k("user")))),
                 El("regroup-action", "create")),
              El("anyExt"),
              ns=(("", REGROUP_NS),))


def signed_doc(cv, cids):
    """TS 24.379 §F.6.3 signatures over the parts named by `cids`, with every xmldsig element and
    attribute that a rule removes (A15) and canaries in the values FR-018a empties or removes."""
    dk = lambda local: el_key(DSIG_NS, None, local)  # noqa: E731
    da = lambda element, attr: attr_key(DSIG_NS, element, attr)  # noqa: E731

    def ref(cid):
        return El("ds:Reference",
                  El("ds:Transforms", El("ds:Transform", attrs=(("Algorithm", "http://www.w3.org/2000/09/xmldsig#base64"),)),
                     Raw(f"<!-- {cv.s(dk('Transforms'), 'canary')} -->")),
                  El("ds:DigestMethod", attrs=(("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256"),)),
                  El("ds:DigestValue", cv.s(dk("DigestValue"), "Q2FuYXJ5")),
                  attrs=(("URI", "cid:" + cid), ("Id", cv.s(da("Reference", "Id"), "ref")),
                         ("Type", "http://" + cv.s(da("Reference", "Type"), "canary") + ".example.net/t")))

    sig = El("ds:Signature",
             El("ds:SignedInfo",
                El("ds:CanonicalizationMethod", attrs=(("Algorithm", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"),)),
                El("ds:SignatureMethod", El("ds:HMACOutputLength", cv.c.number(cv.f, 5, rule=dk("HMACOutputLength"))),
                   attrs=(("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"),)),
                *[ref(c) for c in cids], attrs=(("Id", cv.s(da("SignedInfo", "Id"), "si")),)),
             El("ds:SignatureValue", cv.s(dk("SignatureValue"), "U2lnbmF0dXJl"),
                attrs=(("Id", cv.s(da("SignatureValue", "Id"), "sv")),)),
             El("ds:KeyInfo",
                El("ds:KeyName", cv.s(dk("KeyName"), "WFBLLUlE")),
                El("ds:KeyValue", El("ds:RSAKeyValue", El("ds:Modulus", cv.s(dk("KeyValue"), "bW9k")),
                                     El("ds:Exponent", "AQAB"))),
                El("ds:RetrievalMethod", attrs=(("URI", "http://" + cv.s(dk("RetrievalMethod"), "canary") + ".example.net/k"),)),
                El("ds:X509Data", El("ds:X509SubjectName", "CN=" + cv.s(dk("X509Data"), "canary"))),
                El("ds:PGPData", El("ds:PGPKeyID", cv.s(dk("PGPData"), "cGdw"))),
                El("ds:SPKIData", El("ds:SPKISexp", cv.s(dk("SPKIData"), "c3BraQ"))),
                El("ds:MgmtData", cv.s(dk("MgmtData"), "canary")),
                attrs=(("Id", cv.s(da("KeyInfo", "Id"), "ki")),)),
             El("ds:Object", El("ds:SignatureProperties", El("ds:SignatureProperty", cv.s(dk("Object"), "canary"),
                                                             attrs=(("Target", "#sig"),)))),
             attrs=(("Id", cv.s(da("Signature", "Id"), "sig")),))
    return El("signatures", sig, El("anyExt"), ns=(("", SIGNED_NS), ("ds", DSIG_NS)))


def xml_mcptt_us4(c, out):
    """Floor request, MBMS and MBS usage, the three regroup documents, and an integrity-protected
    INVITE whose mcptt-signed body signs the SDP and the mcptt-info part by Content-ID."""
    fname = "xml_mcptt_us4.pcapng"
    cv = Cv(c, fname)
    tx = Sender(fname)
    tx.request("MESSAGE", "application/vnd.3gpp.mcptt-floor-request+xml", doc(floor_request_doc(cv)))
    tx.request("MESSAGE", "application/vnd.3gpp.mcptt-mbms-usage-info+xml", doc(mbms_usage_doc(cv)))
    tx.request("MESSAGE", "application/vnd.3gpp.mcptt-mbs-usage-info+xml", doc(mbs_usage_doc(cv)))
    for svc in ("mcptt", "mcdata", "mcvideo"):
        tx.request("MESSAGE", f"application/vnd.3gpp.{svc}-regroup+xml", doc(regroup_doc(cv, svc)))
    cid_sdp = cv.s(attr_key(DSIG_NS, "Reference", "URI"), "sdp") + "@fire.example.net"
    cid_info = cv.s(attr_key(DSIG_NS, "Reference", "URI"), "info") + "@fire.example.net"
    tx.multipart("INVITE", [("application/sdp", sdp_offer(), [("Content-ID", f"<{cid_sdp}>")]),
                            (MCPTT_INFO_CT, doc(mcptt_info_small(cv)), [("Content-ID", f"<{cid_info}>")]),
                            ("application/vnd.3gpp.mcptt-signed+xml", doc(signed_doc(cv, [cid_sdp, cid_info])), [])])
    tx.write(out)


FIXTURES.append(xml_mcptt_us4)


# --- fixtures: User Story 5 (Appendix E §E.5-E.8) -------------------------------------
REG_NS = "urn:ietf:params:xml:ns:reginfo"
GRUU_NS = "urn:ietf:params:xml:ns:gruuinfo"
CONF_NS = "urn:ietf:params:xml:ns:conference-info"
CONF_X = {"mcptt": "urn:3gpp:ns:mcpttConfInfo:1.0", "mcdata": "urn:3gpp:ns:mcdataConfInfo:1.0",
          "mcvideo": "urn:3gpp:ns:mcvideoConfInfo:1.0"}
XDIFF_NS = "urn:ietf:params:xml:ns:xcap-diff"
POC_NS = "urn:oma:params:xml:ns:poc:poc-settings"
MCS_NS = "urn:3gpp:mcsSettings:1.0"


def reginfo_doc(cv):
    a = lambda el, at: attr_key(REG_NS, el, at)  # noqa: E731
    k = lambda local: el_key(REG_NS, None, local)  # noqa: E731
    contact = El("contact",
                 El("uri", cv.uri(k("uri"), "10.30.0.11")),
                 El("display-name", cv.s(k("display-name"), "Canary Name"), attrs=(("xml:lang", "en"),)),
                 El("unknown-param", cv.s(k("unknown-param"), "canary"), attrs=(("name", "audio"),)),
                 El("g:pub-gruu", attrs=(("uri", cv.uri(attr_key(GRUU_NS, "pub-gruu", "uri")) + ";gr=urn:uuid:"
                                          + cv.uuid("xml-reginfo:gr")),)),
                 El("g:temp-gruu", attrs=(("uri", cv.uri(attr_key(GRUU_NS, "temp-gruu", "uri")) + ";gr"),
                                          ("first-cseq", "1"))),
                 El("x:wildcardedIdentity", "sip:!.*!@example.net", ns=(("x", "urn:3gpp:ns:extRegExp:1.0"),)),
                 attrs=(("id", cv.s(a("contact", "id"), "c")), ("state", "active"), ("event", "registered"),
                        ("expires", "600000"), ("duration-registered", "12"), ("q", "0.5"),
                        ("callid", cv.s(a("contact", "callid"), "canary") + "@10.30.0.11"), ("cseq", "2")))
    reg = El("registration", contact,
             attrs=(("aor", cv.uri(a("registration", "aor"))), ("id", cv.s(a("registration", "id"), "r")),
                    ("state", "active")))
    return El("reginfo", reg, attrs=(("version", "3"), ("state", "full")), ns=(("", REG_NS), ("g", GRUU_NS)))


def conference_doc(cv):
    a = lambda el, at: attr_key(CONF_NS, el, at)  # noqa: E731
    k = lambda local, parent=None: el_key(CONF_NS, parent, local)  # noqa: E731
    fr = lambda: cv.s(k("display-text"), "Canary text")  # noqa: E731
    x = lambda name: El(name, El("when", "2026-11-14T10:00:00Z"), El("reason", cv.s(k("reason"), "canary")),  # noqa: E731
                        El("by", cv.uri(k("by"))))
    uris = lambda name: El(name, El("entry", El("uri", cv.uri(k("uri"))), El("display-text", fr()),  # noqa: E731
                                    El("purpose", cv.s(k("purpose"), "canary")), x("modified")),
                           attrs=(("state", "full"),))
    endpoint = El("endpoint",
                  El("display-text", cv.s(k("display-text", "endpoint"), "Canary Endpoint")),
                  x("referred"), El("status", "connected"), El("joining-method", "dialed-in"), x("joining-info"),
                  El("disconnection-method", "departed"), x("disconnection-info"),
                  El("media", El("display-text", fr()), El("type", "audio"), El("label", "1"),
                     El("src-id", cv.c.binary(cv.f, k("src-id"), low=1 << 24)), El("status", "sendrecv"),
                     attrs=(("id", cv.s(a("media", "id"), "m")),)),
                  El("call-info", El("sip", El("display-text", fr()),
                                     El("call-id", cv.s(k("call-id"), "canary") + "@fire.example.net"),
                                     El("from-tag", cv.s(k("from-tag"), "canary")),
                                     El("to-tag", cv.s(k("to-tag"), "canary")))),
                  *[El(f"{svc}:functional-alias", cv.uri(el_key(ns, None, "functional-alias"))) for svc, ns in CONF_X.items()],
                  attrs=(("entity", cv.uri(a("endpoint", "entity"))), ("state", "full")))
    user = El("user", El("display-text", cv.s(k("display-text", "user"), "Canary User")), uris("associated-aors"),
              El("roles", El("entry", cv.s(k("entry", "roles"), "canary"))), El("languages", "en"),
              El("cascaded-focus", cv.uri(k("cascaded-focus"))), endpoint,
              attrs=(("entity", cv.uri(a("user", "entity"))), ("state", "full")))
    desc = El("conference-description", El("display-text", fr()), El("subject", cv.s(k("subject"), "canary")),
              El("free-text", cv.s(k("free-text"), "canary")), El("keywords", cv.s(k("keywords"), "canary")),
              uris("conf-uris"), uris("service-uris"), El("maximum-user-count", "50"),
              El("available-media", El("entry", El("display-text", fr()), El("type", "audio"), El("status", "sendrecv"),
                                       attrs=(("label", "1"),))))
    host = El("host-info", El("display-text", fr()), El("web-page", "http://" + cv.s(k("web-page"), "canary") + ".example.net/"),
              uris("uris"))
    side = El("sidebars-by-val", El("entry", attrs=(("entity", cv.uri(a("entry", "entity"))), ("state", "full"),
                                                    ("version", "1"))), attrs=(("state", "full"),))
    return El("conference-info", desc, host,
              El("conference-state", El("user-count", "2"), El("active", "true"), El("locked", "false")),
              El("users", user, attrs=(("state", "full"),)), uris("sidebars-by-ref"), side,
              attrs=(("entity", cv.uri(a("conference-info", "entity"))), ("state", "full"), ("version", "4")),
              ns=(("", CONF_NS),) + tuple((svc, ns) for svc, ns in CONF_X.items()))


def xcap_diff_doc(cv, etag_new, etag_old):
    a = lambda el, at: attr_key(XDIFF_NS, el, at)  # noqa: E731
    user = cv.uri(a("document", "sel"))
    doc_el = El("document",
                El("add", El("rl:entry", attrs=(("uri", "sip:ue-c@example.net"),)),
                   attrs=(("sel", f"/resource-lists/list[@name='{cv.s(a('add', 'sel'), 'list')}']"), ("pos", "after"),
                          ("type", "@" + cv.s(a("add", "type"), "attr")))),
                El("replace", attrs=(("sel", f"/resource-lists/list[@name='{cv.s(a('replace', 'sel'), 'list')}']"),)),
                El("remove", attrs=(("sel", f"/resource-lists/list[@name='{cv.s(a('remove', 'sel'), 'list')}']"),
                                    ("ws", "after"))),
                attrs=(("sel", f"resource-lists/users/{user}/index"), ("new-etag", etag_new),
                       ("previous-etag", etag_old)), ns=(("rl", RL_NS),))
    return El("xcap-diff",
              doc_el,
              El("document", El("body-not-changed"),
                 attrs=(("sel", "org.3gpp.mcptt.service-config/global/" + cv.s("xml-xcap:doc", "svc") + ".xml"),
                        ("new-etag", cv.s("xml-xcap:etag-2", "etag")))),
              El("element", attrs=(("sel", f"resource-lists/users/{cv.uri(a('element', 'sel'))}/index/~~/resource-lists"),
                                   ("exists", "0"))),
              El("attribute", cv.s(el_key(XDIFF_NS, None, "attribute"), "canary"),
                 attrs=(("sel", f"resource-lists/users/{cv.uri(a('attribute', 'sel'))}/index/~~/resource-lists/list/@name"),
                        ("exists", "1"))),
              attrs=(("xcap-root", "https://" + cv.s(a("xcap-diff", "xcap-root"), "xcap") + ".example.net/root/"),),
              ns=(("", XDIFF_NS),))


def poc_doc(cv):
    a = lambda el, at: attr_key(POC_NS, el, at)  # noqa: E731
    ent = El("entity", El("isb-settings", El("incoming-session-barring", attrs=(("active", "false"),))),
             El("am-settings", El("answer-mode", "automatic")),
             El("ipab-settings", El("incoming-personal-alert-barring", attrs=(("active", "true"),))),
             El("sss-settings", El("simultaneous-sessions-support", attrs=(("active", "true"),))),
             El("m:selected-user-profile-index", El("m:user-profile-index", "1")),
             El("m:multiplex-support", "true"),
             El("v:vendor", cv.s("xml-poc:vendor", "canary"), ns=(("v", VENDOR),)),
             attrs=(("id", "urn:uuid:" + cv.uuid(a("entity", "id"))),))
    return El("poc-settings", ent, ns=(("", POC_NS), ("m", MCS_NS)))


def xml_ietf_us5(c, out):
    """reg, conference and xcap-diff NOTIFYs and a poc-settings PUBLISH; one entity tag in
    xcap-diff and in SIP-ETag / SIP-If-Match."""
    fname = "xml_ietf_us5.pcapng"
    cv = Cv(c, fname)
    tx = Sender(fname)
    etag_old = cv.s(attr_key(XDIFF_NS, "document", "previous-etag"), "etag")
    etag_new = cv.s(attr_key(XDIFF_NS, "document", "new-etag"), "etag")
    tx.request("NOTIFY", "application/reginfo+xml", doc(reginfo_doc(cv)), extra=[("Event", "reg")])
    tx.request("NOTIFY", "application/conference-info+xml", doc(conference_doc(cv)), extra=[("Event", "conference")])
    tx.request("NOTIFY", "application/xcap-diff+xml", doc(xcap_diff_doc(cv, etag_new, etag_old)),
               extra=[("Event", "xcap-diff")])
    tx.request("PUBLISH", "application/poc-settings+xml", doc(poc_doc(cv)),
               extra=[("Event", "poc-settings"), ("SIP-If-Match", etag_old)])
    tx.response(200, "OK", "PUBLISH", "application/poc-settings+xml", doc(poc_doc(cv)),
                extra=[("SIP-ETag", etag_new)])
    tx.write(out)


FIXTURES.append(xml_ietf_us5)


def seed_documents():
    """Small documents that exercise the reader's syntax (seeds next to the fixture bodies)."""
    ns = "urn:3gpp:ns:mcpttInfo:1.0"
    return [
        doc(El("mcpttinfo", El("mcptt-Params", El("session-type", "private"),
                               El("mcptt-request-uri", El("mcpttURI", "sip:ue-b@example.net"), attrs=(("type", "Normal"),))),
               ns=(("", ns),))),
        doc(El("m:mcpttinfo", El("m:mcptt-Params", El("m:session-type", Raw("<![CDATA[ad-hoc]]>")),
                                 Raw("<!-- note -->"), Raw("<?app x?>"), Raw("&#x40;&#64;")),
               ns=(("m", ns), ("x", "urn:example:vendor")), quote="'"), bom=True, indent=None),
        doc(El("a", attrs=(("xml:lang", "en"),), empty=True), decl=None),
        b"<a xmlns:p='urn:x'><p:b p:c=\"&amp;&lt;&quot;\">t&gt;</p:b><d xmlns=''/></a>",
        b"<!DOCTYPE a [<!ENTITY e 'x'>]><a>&e;</a>",
        b"<a><b></a>",
    ]


def gen(c, out):
    for fn in FIXTURES:
        fn(c, out)
    with open(os.path.join(out, "xml_manifest.json"), "w") as fh:
        json.dump(MANIFEST, fh, indent=1, sort_keys=True)


# --- fixtures of User Story 4 kept in their own modules (they import this one) -----------------
import xmlmcdata  # noqa: E402
import xmlmcvideo  # noqa: E402

FIXTURES += xmlmcdata.FIXTURES + xmlmcvideo.FIXTURES


# --- fixtures of feature 008 (namespace prefixes, FR-003, FR-004) -------------------------------
FILTER_NS = "urn:ietf:params:xml:ns:simple-filter"


def filter_doc():
    """An RFC 4661 event filter whose ns-binding values name the standard prefixes: a body without
    rules (emptied), from which a scanner learns the prefix names as values (the pilot's case)."""
    binding = lambda p, n: El("ns-binding", attrs=(("prefix", p), ("urn", n)))  # noqa: E731
    return doc(El("filter-set", El("ns-bindings", binding("pidf", PIDF_NS),
                                   *(binding(f"{svc}PI10", PRES[svc][0]) for svc in PRES),
                                   binding("mcs10Set", "urn:3gpp:mcsSettings:1.0")),
                  ns=(("", FILTER_NS),)))


def pidf_affiliation(cv, service, prefix, entity_rule):
    """A pidf affiliation body (TS 24.379 §9.3.1.2) with the extension namespace under `prefix`."""
    pns, _ = PRES[service]
    p = prefix
    return doc(El("presence",
                  El("tuple", El("status", El(f"{p}:affiliation",
                                              attrs=(("group", cv.uri(attr_key(pns, "affiliation", "group"))),
                                                     ("status", "affiliated")))),
                     attrs=(("id", "urn:uuid:" + cv.uuid(attr_key(PIDF_NS, "tuple", "id"))),)),
                  El(f"{p}:p-id", cv.s(el_key(pns, None, "p-id"), "canary")),
                  attrs=(("entity", cv.uri(entity_rule)),), ns=(("", PIDF_NS), (p, pns))))


def xml_prefixes(c, out):
    """A SUBSCRIBE with the filter, then PUBLISHes with the standard prefixes mcpttPI10, mcdataPI10
    and mcvideoPI10, one with a vendor prefix (a canary) for the MCPTT namespace, and one declaring
    the MCPTT namespace under the standard and a vendor prefix."""
    fname = "xml_prefixes.pcapng"
    cv = Cv(c, fname)
    tx = Sender(fname)
    tx.request("SUBSCRIBE", "application/simple-filter+xml", filter_doc(), extra=[("Event", "presence")])
    entity = attr_key(PIDF_NS, "presence", "entity")
    for svc in PRES:
        tx.request("PUBLISH", "application/pidf+xml", pidf_affiliation(cv, svc, f"{svc}PI10", entity),
                   extra=[("Event", "presence")])
    vendor = cv.s("xml-prefix:" + PRES["mcptt"][0], "canary")
    tx.request("PUBLISH", "application/pidf+xml", pidf_affiliation(cv, "mcptt", vendor, entity),
               extra=[("Event", "presence")])
    pns = PRES["mcptt"][0]
    both = doc(El("presence",
                  El("tuple", El("status", El("mcpttPI10:affiliation", attrs=(("status", "affiliated"),)),
                                 El(f"{vendor}:affiliation", attrs=(("status", "deaffiliated"),)))),
                  attrs=(("entity", cv.uri(entity)),), ns=(("", PIDF_NS), ("mcpttPI10", pns), (vendor, pns))))
    tx.request("PUBLISH", "application/pidf+xml", both, extra=[("Event", "presence")])
    tx.write(out)


FIXTURES.append(xml_prefixes)

# SPDX-License-Identifier: GPL-3.0-or-later
"""Synthetic reproductions of the patterns found by the first pilot on third-party captures
(feature 008). No pilot capture is used; every value is invented, every identity a canary.

  - pilot_tcp_cookie.pcapng (FR-001, FR-002): six TCP connections, each with three 200 OK in one
    segment whose last Via is cut by the segment boundary after 1 to 6 characters of the branch
    cookie z9hG4bK; the rest follows in the next segment.
  - pilot_tcp_gap.pcapng (FR-005): on a direction with many rewritten values and no
    acknowledgement yet, a multipart PUBLISH (mcptt-info with an access token, pidf) is split over
    two segments, the second also starting the next SUBSCRIBE; the server acknowledges the second
    segment before the third completes the SUBSCRIBE; then a retransmission of the second segment.
"""
from sip import Capture, TcpConn, UA, PCSCF, _Cv, multipart, request, response

FIXTURES = []

COOKIE = b"z9hG4bK"


def _write(cap, out, name):
    with open(f"{out}/{name}", "wb") as fh:
        fh.write(cap.bytes())


def _ok(v, n, dom):
    """A 200 OK to a SUBSCRIBE with a canary in every value a rule does not keep."""
    return response(200, "OK", [
        ("Via", f"SIP/2.0/TCP {v.label('sip:Via.sent-by')}.example.net:5060;"
                f"received={v.ip('sip-param:Via;received')};branch=z9hG4bK{v.s('sip-param:Via;branch')}.0"),
        ("From", f"<sip:{v.s('sip:From.uri')}@{dom}>;tag={v.s('sip-param:From;tag')}"),
        ("To", f"<sip:{v.s('sip:To.uri')}@{dom}>;tag={v.s('sip-param:To;tag')}"),
        ("Call-ID", v.s("sip:Call-ID.value")),
        ("CSeq", f"{n} SUBSCRIBE"),
        ("Expires", "600"),
    ])


def gen_cookie(c, out):
    name = "pilot_tcp_cookie.pcapng"
    v = _Cv(c, name)
    dom = v.label("sip:From.uri") + ".example.net"
    cap = Capture()
    for k in range(1, len(COOKIE)):
        t = TcpConn(UA, PCSCF, 41000 + k, 5060)
        cap.extend(t.handshake())
        data = b"".join(_ok(v, 10 * k + i, dom) for i in range(3))
        cut = data.rfind(b";branch=" + COOKIE) + len(b";branch=") + k
        cap.add(t.send(1, data[:cut]))
        cap.add(t.ack(0))
        cap.add(t.send(1, data[cut:]))
        cap.add(t.ack(0))
        cap.add(t.fin(1))
        cap.add(t.fin(0))
        cap.add(t.ack(1))
    _write(cap, out, name)


FIXTURES.append(gen_cookie)

INFO_NS = "urn:3gpp:ns:mcpttInfo:1.0"
PIDF_NS = "urn:ietf:params:xml:ns:pidf"
PRES_NS = "urn:3gpp:ns:mcpttPresInfo:1.0"


def _xk(ns, parent, local):
    return f"xml:{ns}|{parent or '-'}|{local}"


def _xa(ns, element, attr):
    return f"xml:{ns}|{element}|@-|{attr}"


def _dialog(v, method, n, dom):
    return [("Via", f"SIP/2.0/TCP {v.label('sip:Via.sent-by')}.example.net:5060;branch=z9hG4bK{v.s('sip-param:Via;branch')}"),
            ("Max-Forwards", "70"),
            ("From", f"<sip:{v.s('sip:From.uri')}@{dom}>;tag={v.s('sip-param:From;tag')}"),
            ("To", f"<sip:{v.s('sip:To.uri')}@{dom}>"),
            ("Call-ID", v.s("sip:Call-ID.value")),
            ("CSeq", f"{n} {method}")]


def _subscribe(v, n, dom):
    return request("SUBSCRIBE", f"sip:{v.s('sip:To.uri')}@{dom}",
                   _dialog(v, "SUBSCRIBE", n, dom) + [("Event", "presence"), ("Expires", "600")])


def _publish(v, n, dom):
    info = (f'<?xml version="1.0"?><mcpttinfo xmlns="{INFO_NS}"><mcptt-Params>'
            f'<mcptt-access-token type="Normal"><mcpttString>{v.s(_xk(INFO_NS, "mcptt-access-token", "mcpttString"))}'
            f'</mcpttString></mcptt-access-token><mcptt-request-uri type="Normal"><mcpttURI>sip:'
            f'{v.s(_xk(INFO_NS, "mcptt-request-uri", "mcpttURI"))}@{dom}</mcpttURI></mcptt-request-uri>'
            f'</mcptt-Params></mcpttinfo>')
    pidf = (f'<?xml version="1.0"?><presence xmlns="{PIDF_NS}" xmlns:mcpttPI10="{PRES_NS}" '
            f'entity="sip:{v.s(_xa(PIDF_NS, "presence", "entity"))}@{dom}"><tuple id="canary-tuple-1"><status>'
            f'<mcpttPI10:affiliation group="sip:{v.s(_xa(PRES_NS, "affiliation", "group"))}@{dom}" status="affiliated"/>'
            f'</status></tuple><mcpttPI10:p-id>{v.s(_xk(PRES_NS, None, "p-id"))}</mcpttPI10:p-id></presence>')
    body = multipart("mcx-bnd-0001", [([("Content-Type", "application/vnd.3gpp.mcptt-info+xml")], info),
                                      ([("Content-Type", "application/pidf+xml")], pidf)])
    return request("PUBLISH", f"sip:{v.s('sip:To.uri')}@{dom}",
                   _dialog(v, "PUBLISH", n, dom) + [("Event", "presence"), ("Expires", "4294967295"),
                                                    ("Content-Type", "multipart/mixed;boundary=mcx-bnd-0001")], body)


def gen_gap(c, out):
    name = "pilot_tcp_gap.pcapng"
    v = _Cv(c, name)
    dom = v.label("sip:From.uri") + ".example.net"
    cap = Capture()
    t = TcpConn(UA, PCSCF, 42149, 5060)
    cap.extend(t.handshake())
    # More than 64 rewritten values in the client's direction before the PUBLISH, none acknowledged.
    for n in range(1, 9):
        cap.add(t.send(0, _subscribe(v, n, dom)))
    pub, sub = _publish(v, 20, dom), _subscribe(v, 21, dom)
    cut = len(pub) // 2
    a = _subscribe(v, 19, dom) + pub[:cut]
    b = pub[cut:] + sub[:40]
    cap.add(t.send(0, a))
    b_seq = t.next[0]
    cap.add(t.send(0, b))
    cap.add(t.ack(1))  # acknowledges the end of b before the SUBSCRIBE is complete
    cap.add(t.send(0, sub[40:]))
    cap.add(t.send(0, b, seq=b_seq))  # a retransmission of b
    cap.add(t.ack(1))
    cap.add(t.fin(0))
    cap.add(t.fin(1))
    cap.add(t.ack(0))
    _write(cap, out, name)


FIXTURES.append(gen_gap)


def gen(c, out):
    for fn in FIXTURES:
        fn(c, out)


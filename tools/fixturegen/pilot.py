# SPDX-License-Identifier: GPL-3.0-or-later
"""Synthetic reproductions of the patterns found by the first pilot on third-party captures
(feature 008). No pilot capture is used; every value is invented, every identity a canary.

  - pilot_tcp_cookie.pcapng (FR-001, FR-002): six TCP connections, each with three 200 OK in one
    segment whose last Via is cut by the segment boundary after 1 to 6 characters of the branch
    cookie z9hG4bK; the rest follows in the next segment.
"""
from sip import Capture, TcpConn, UA, PCSCF, _Cv, response

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


def gen(c, out):
    for fn in FIXTURES:
        fn(c, out)


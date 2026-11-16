#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Synthetic MCX demo capture: one dispatcher's working session, end to end.

Every value in it is invented. Addresses come from private and documentation ranges
(RFC 1918, RFC 4193, RFC 7042), names from example.net (RFC 2606).

Interface 0 is the LAN of a dispatcher console (VLAN 120, dual-stack) running an
MCPTT and an MCData client. Interface 1 is an S1-U mirror at the eNodeB that carries
the traffic of a handheld (GTP-U).

The session covers:
  - DHCPv4, IPv6 router discovery and SLAAC (EUI-64 address), ARP and DNS;
  - OpenID Connect user authentication at the IdMS (TS 24.482, TS 33.180 annex B);
  - key material retrieval from the KMS over TLS;
  - SIP registration over TCP with AKA challenge, MCPTT client over IPv4 and MCData
    client over IPv6;
  - service authorisation of both (PUBLISH poc-settings, TS 24.379 and TS 24.282
    clause 7.2.2);
  - configuration management (SUBSCRIBE xcap-diff, NOTIFY, XCAP GET of the UE
    configuration, the MCPTT and MCData user profiles and the service configuration,
    TS 24.484);
  - KMS initialisation and key provisioning over HTTP/2 in the clear (h2c, prior knowledge):
    the user key set is credential material (TS 33.180 §D.2, §D.3);
  - the GMS over HTTPS (TLS 1.2 with its certificate chain, ECDHE, a session ticket);
  - group documents from the GMS and affiliation of both clients (PUBLISH, SUBSCRIBE,
    NOTIFY; TS 24.379 clause 9.2.1.2, TS 24.282 clause 8.2.2);
  - a location report (TS 24.379 annex F.3);
  - a pre-arranged group call with floor control (TS 24.380) and AMR-WB media with RTCP
    sender reports, SDES and BYE, with the handheld talking through GTP-U;
  - an incoming private call;
  - an MCVideo private call with H.264 video and transmission control (TS 24.581);
  - MCData short data service (TS 24.282 clauses 9.2.2 and 15): a one-to-one message
    from the handheld and a group message from the console, fanned out to the handheld,
    and an SDS session over MSRP (SEND, REPORT and the 200 response);
  - call release, a late RTP packet and the ICMP error it triggers, de-registration;
  - pcapng metadata: section and interface options, name resolution and decryption
    secrets blocks, packet comments and interface statistics.

Usage: mcx_demo.py --out DIR
Writes DIR/mcx_demo.pcapng, DIR/mcx_demo.canaries.json (every identifying value,
in the manifest format of tests/integration/canary_absent.py) and DIR/mcx_demo.deny.txt.
"""
import argparse
import base64
import datetime
import hashlib
import ipaddress
import json
import os
import random
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import der  # noqa: E402
import hpack  # noqa: E402
import packets as P  # noqa: E402
import pcapng  # noqa: E402

NAME = "mcx_demo.pcapng"


def mac(s):
    return bytes(int(x, 16) for x in s.split(":"))


def v4(s):
    return ipaddress.IPv4Address(s).packed


def v6(s):
    return ipaddress.IPv6Address(s).packed


class Demo:
    """Collects frames (timestamp, interface, frame, comment) and the canary manifest."""

    def __init__(self, seed):
        self.rng = random.Random(seed)
        start = datetime.datetime(2026, 10, 14, 7, 42, 5, tzinfo=datetime.timezone.utc)
        self.t0 = int(start.timestamp() * 1_000_000)
        self.now = self.t0
        self.frames = []
        self.canaries = []

    # --- bookkeeping ----------------------------------------------------------------------
    def canary(self, category, value, field):
        if not any(c["value"] == value for c in self.canaries):
            self.canaries.append({"id": f"d{len(self.canaries) + 1:03d}", "category": category,
                                  "value": value, "field": field, "files": [NAME]})
        return value

    def at(self, dt_ms):
        self.now += int(dt_ms * 1000)
        return self.now

    def put(self, dt_ms, iface, frame, comment=None):
        self.frames.append((self.at(dt_ms), iface, bytes(frame), comment))

    def put_abs(self, ts, iface, frame, comment=None):
        self.frames.append((ts, iface, bytes(frame), comment))

    def rand(self, n):
        return bytes(self.rng.randrange(256) for _ in range(n))

    def token(self, n):
        return base64.urlsafe_b64encode(self.rand(n)).rstrip(b"=").decode()

    # SIP and SDP identities, recorded with their rule key (feature 002, FR-039). Values
    # shorter than 4 characters are not listed (the oracle cannot search them).
    def sip_canary(self, category, value, rule):
        if len(value) >= 4 and not any(c["value"] == value for c in self.canaries):
            self.canaries.append({"id": f"d{len(self.canaries) + 1:03d}", "category": category,
                                  "value": value, "rule": rule, "files": [NAME]})
        return value

    def branch(self):
        b = self.token(9)
        self.sip_canary("string", b, "sip-param:Via;branch")
        return "z9hG4bK" + b

    def callid(self):
        return self.sip_canary("string", self.token(12), "sip:Call-ID.value")


# --- the cast ------------------------------------------------------------------------------
DOMAIN = "mcx.example.net"
LAN_DOMAIN = "wn.fire.example.net"
CON_MAC, GW_MAC = "00:00:5e:00:53:11", "00:00:5e:00:53:01"
ENB_MAC, SGW_MAC = "00:00:5e:00:53:21", "00:00:5e:00:53:22"
CON4, GW4, DNS4 = "10.45.12.34", "10.45.0.1", "10.45.0.53"
PREFIX6 = "fd12:3456:789a:1::"
CON6 = "fd12:3456:789a:1:200:5eff:fe00:5311"        # SLAAC, modified EUI-64 of CON_MAC
CON_LL, GW_LL = "fe80::200:5eff:fe00:5311", "fe80::200:5eff:fe00:5301"
PCSCF4, PCSCF6 = "172.16.20.10", "fd12:3456:789a:20::10"
MEDIA4 = "172.16.30.5"
IDMS4, CMS4, GMS4, KMS4 = "172.16.40.10", "172.16.40.20", "172.16.40.21", "172.16.40.30"
ENB4, SGW4 = "10.200.1.10", "10.200.0.1"
HH4, HH6 = "10.60.0.23", "fd12:3456:789a:60::23"     # the handheld, inside GTP-U
TEID_UL, TEID_DL = 0x0A1B2C3D, 0x00C0FFEE
VLAN = 120

ALICE = f"sip:alice.nowak@{DOMAIN}"
BOB = f"sip:bob.zielinski@{DOMAIN}"
CHIEF = f"sip:chief.kowalczyk@{DOMAIN}"
GROUP = f"sip:fire-brigade-west@{DOMAIN}"
GROUP2 = f"sip:wn-command@{DOMAIN}"
PSI = f"sip:mcptt-part@{DOMAIN}"
CMS_PSI = f"sip:cms@{DOMAIN}"
IMPI = "260011234567890@ims.mnc001.mcc260.3gppnetwork.org"
IMEI = "35-209900-176148-1"
CELL = "3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=2600100A1B2C3D4"
CLIENT_ID = "urn:uuid:5f0e8c2a-3b71-4d9e-9a44-2c7b1e6f0d18"
HOSTNAME = "DISPATCH-WN-03"
PASSWORD = "Str0ng-P@ss-2026!"
UA = "ExampleMCX-Dispatch/5.2.1 (ExampleOS 14)"


def eth0(d, ip_payload, ethertype=0x0800, up=True, dst=None):
    """Interface 0: tagged frame between the console and its gateway."""
    if dst is None:
        a, b = (GW_MAC, CON_MAC) if up else (CON_MAC, GW_MAC)
    else:
        a, b = dst, (CON_MAC if up else GW_MAC)
    return P.ethernet(mac(a), mac(b), 0x8100, P.vlan(VLAN, ethertype, ip_payload))


def crlf(lines, body=b""):
    head = "\r\n".join(lines).replace("{LEN}", str(len(body))) + "\r\n\r\n"
    return head.encode() + body


def signed_multipart(boundary, parts, d):
    """Feature 003 (R18, FR-018a): an integrity-protected body (TS 24.379 §6.6.3.1, §F.6.3): each
    part has a Content-ID and an mcptt-signed part signs them by cid URL."""
    refs = "".join(
        f"<ds:Reference URI=\"cid:{cid}\"><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>"
        f"<ds:DigestValue>{d.token(43)}=</ds:DigestValue></ds:Reference>" for _, _, cid in parts)
    sig = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<signatures xmlns=\"urn:3gpp:ns:mcpttSignedDoc:1.0\" "
           "xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:Signature><ds:SignedInfo>"
           "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>"
           "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256\"/>" + refs +
           f"</ds:SignedInfo><ds:SignatureValue>{d.token(43)}=</ds:SignatureValue>"
           f"<ds:KeyInfo><ds:KeyName>{d.token(24)}</ds:KeyName></ds:KeyInfo></ds:Signature></signatures>\n").encode()
    out = b""
    for ctype, body, cid in parts:
        out += f"--{boundary}\r\nContent-Type: {ctype}\r\nContent-ID: <{cid}>\r\n\r\n".encode() + body + b"\r\n"
    out += f"--{boundary}\r\nContent-Type: application/vnd.3gpp.mcptt-signed+xml\r\n\r\n".encode() + sig + b"\r\n"
    return out + f"--{boundary}--\r\n".encode()


def multipart(boundary, parts):
    """parts: (ctype, body) or (ctype, body, extra header lines)."""
    out = b""
    for ctype, body, *extra in parts:
        hdrs = "".join(f"{h}\r\n" for h in (extra[0] if extra else ()))
        out += f"--{boundary}\r\nContent-Type: {ctype}\r\n{hdrs}\r\n".encode() + body + b"\r\n"
    return out + f"--{boundary}--\r\n".encode()


class Tcp:
    """A TCP connection on interface 0 with consistent sequence numbers and MSS segmentation."""

    def __init__(self, d, cli, srv, cport, sport, v6=False):
        self.d, self.cli, self.srv, self.cport, self.sport, self.v6 = d, cli, srv, cport, sport, v6
        self.mss = 1440 if v6 else 1460
        self.cseq = d.rng.getrandbits(32)
        self.sseq = d.rng.getrandbits(32)

    def _seg(self, up, flags, data=b"", opts=b"", ack=None):
        src, dst, sp, dp = (self.cli, self.srv, self.cport, self.sport) if up else (self.srv, self.cli, self.sport, self.cport)
        seq, nxt = (self.cseq, self.sseq) if up else (self.sseq, self.cseq)
        nxt = nxt if ack is None else ack
        if self.v6:
            seg = P.tcp(sp, dp, seq, nxt, flags, data, opts, P.pseudo6(v6(src), v6(dst), 6, 20 + len(opts) + len(data)))
            return eth0(self.d, P.ipv6(v6(src), v6(dst), 6, seg), 0x86DD, up=up)
        return eth0(self.d, P.tcp4(v4(src), v4(dst), sp, dp, seq, nxt, flags, data, opts), up=up)

    def open(self, rtt=4.0):
        mss = struct.pack("!BBH", 2, 4, self.mss) + b"\x01\x03\x03\x07"   # MSS, NOP, window scale 7
        self.d.put(0.5, 0, self._seg(True, 0x02, opts=mss, ack=0))
        self.cseq = (self.cseq + 1) & 0xFFFFFFFF
        self.d.put(rtt, 0, self._seg(False, 0x12, opts=mss))
        self.sseq = (self.sseq + 1) & 0xFFFFFFFF
        self.d.put(0.2, 0, self._seg(True, 0x10))

    def send(self, up, data, gap=1.0, comment=None, ack_delay=0.3):
        first = True
        for i in range(0, len(data), self.mss):
            chunk = data[i:i + self.mss]
            last = i + self.mss >= len(data)
            self.d.put(gap if first else 0.05, 0, self._seg(up, 0x18 if last else 0x10, chunk),
                       comment if first else None)
            if up:
                self.cseq = (self.cseq + len(chunk)) & 0xFFFFFFFF
            else:
                self.sseq = (self.sseq + len(chunk)) & 0xFFFFFFFF
            first = False
        self.d.put(ack_delay, 0, self._seg(not up, 0x10))

    def close(self, up=True):
        self.d.put(1.0, 0, self._seg(up, 0x11))
        if up:
            self.cseq = (self.cseq + 1) & 0xFFFFFFFF
        else:
            self.sseq = (self.sseq + 1) & 0xFFFFFFFF
        self.d.put(2.0, 0, self._seg(not up, 0x11))
        if up:
            self.sseq = (self.sseq + 1) & 0xFFFFFFFF
        else:
            self.cseq = (self.cseq + 1) & 0xFFFFFFFF
        self.d.put(0.2, 0, self._seg(up, 0x10))


def udp0(d, src, dst, sp, dp, data, up=True):
    return eth0(d, P.udp4(v4(src), v4(dst), sp, dp, data, ident=d.rng.randrange(65536)), up=up)


def s1u(d, inner, up=True):
    """Interface 1: the handheld's packet inside GTP-U between eNodeB and SGW."""
    teid = TEID_UL if up else TEID_DL
    src, dst = (ENB4, SGW4) if up else (SGW4, ENB4)
    smac, dmac = (ENB_MAC, SGW_MAC) if up else (SGW_MAC, ENB_MAC)
    outer = P.udp4(v4(src), v4(dst), 2152, 2152, P.gtpu(teid, inner), ident=d.rng.randrange(65536))
    return P.ethernet(mac(dmac), mac(smac), 0x0800, outer)


# --- link and network bring-up -----------------------------------------------------------
def dhcp(d, op, msgtype, xid, yiaddr=b"\0" * 4, extra=b""):
    opts = bytes([53, 1, msgtype]) + bytes([61, 7, 1]) + mac(CON_MAC)
    opts += bytes([12, len(HOSTNAME)]) + HOSTNAME.encode() + extra + b"\xff"
    body = struct.pack("!BBBBIHH4s4s4s4s", op, 1, 6, 0, xid, 0, 0x8000, b"\0" * 4, yiaddr, b"\0" * 4, b"\0" * 4)
    body += mac(CON_MAC) + b"\0" * 10 + b"\0" * 192 + b"\x63\x82\x53\x63" + opts
    return body + b"\0" * max(0, 300 - len(body))


def bring_up(d):
    xid = 0x3903F326
    server_opts = (bytes([54, 4]) + v4(GW4) + bytes([1, 4]) + v4("255.255.0.0") + bytes([3, 4]) + v4(GW4)
                   + bytes([6, 4]) + v4(DNS4) + bytes([15, len(LAN_DOMAIN)]) + LAN_DOMAIN.encode()
                   + bytes([51, 4]) + struct.pack("!I", 86400))
    bcast = "ff:ff:ff:ff:ff:ff"
    d.put(0, 0, eth0(d, P.udp4(v4("0.0.0.0"), v4("255.255.255.255"), 68, 67,
                               dhcp(d, 1, 1, xid, extra=bytes([55, 4, 1, 3, 6, 15]))), dst=bcast),
          "console boots: DHCP, router discovery, DNS")
    d.put(3.1, 0, eth0(d, P.udp4(v4(GW4), v4("255.255.255.255"), 67, 68,
                                 dhcp(d, 2, 2, xid, v4(CON4), server_opts)), up=False, dst=bcast))
    d.put(1.2, 0, eth0(d, P.udp4(v4("0.0.0.0"), v4("255.255.255.255"), 68, 67,
                                 dhcp(d, 1, 3, xid, extra=bytes([50, 4]) + v4(CON4) + bytes([54, 4]) + v4(GW4))),
                       dst=bcast))
    d.put(2.4, 0, eth0(d, P.udp4(v4(GW4), v4("255.255.255.255"), 67, 68,
                                 dhcp(d, 2, 5, xid, v4(CON4), server_opts)), up=False, dst=bcast))

    sllao = bytes([1, 1]) + mac(CON_MAC)
    rs = P.icmpv6(v6(CON_LL), v6("ff02::2"), 133, 0, b"\0" * 4 + sllao)
    d.put(40, 0, eth0(d, P.ipv6(v6(CON_LL), v6("ff02::2"), 58, rs, hlim=255), 0x86DD, dst="33:33:00:00:00:02"))
    pio = struct.pack("!BBBBIII", 3, 4, 64, 0xC0, 2592000, 604800, 0) + v6(PREFIX6)
    mtu = struct.pack("!BBHI", 5, 1, 0, 1500)
    ra_body = struct.pack("!BBHII", 64, 0, 1800, 0, 0) + bytes([1, 1]) + mac(GW_MAC) + mtu + pio
    ra = P.icmpv6(v6(GW_LL), v6("ff02::1"), 134, 0, ra_body)
    d.put(6.5, 0, eth0(d, P.ipv6(v6(GW_LL), v6("ff02::1"), 58, ra, hlim=255), 0x86DD, up=False,
                       dst="33:33:00:00:00:01"))
    sol = "ff02::1:ff00:5311"
    ns = P.icmpv6(v6("::"), v6(sol), 135, 0, b"\0" * 4 + v6(CON6))
    d.put(1.1, 0, eth0(d, P.ipv6(v6("::"), v6(sol), 58, ns, hlim=255), 0x86DD, dst="33:33:ff:00:53:11"))

    d.put(900, 0, eth0(d, P.arp(mac(CON_MAC), v4(CON4), b"\0" * 6, v4(GW4)), 0x0806, dst=bcast))
    d.put(0.8, 0, eth0(d, P.arp(mac(GW_MAC), v4(GW4), mac(CON_MAC), v4(CON4), op=2), 0x0806, up=False))

    def name(n):
        return b"".join(bytes([len(p)]) + p.encode() for p in n.split(".")) + b"\0"

    for i, (host, rtype, addr) in enumerate((("idms", 1, IDMS4), ("kms", 1, KMS4), ("pcscf", 1, PCSCF4),
                                             ("pcscf", 28, PCSCF6), ("cms", 1, CMS4), ("gms", 1, GMS4))):
        qid = 0x4A10 + i
        q = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + name(f"{host}.{DOMAIN}") + struct.pack("!HH", rtype, 1)
        rdata = v4(addr) if rtype == 1 else v6(addr)
        r = (struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0) + name(f"{host}.{DOMAIN}")
             + struct.pack("!HH", rtype, 1) + b"\xc0\x0c" + struct.pack("!HHIH", rtype, 1, 300, len(rdata)) + rdata)
        port = 50320 + i
        d.put(2.0, 0, udp0(d, CON4, DNS4, port, 53, q))
        d.put(1.6, 0, udp0(d, DNS4, CON4, 53, port, r, up=False))


# --- user authentication at the IdMS (OpenID Connect, plain HTTP in this lab) -------------
def oidc(d):
    state = d.token(12)
    verifier = d.token(32)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    redirect = "http%3A%2F%2F127.0.0.1%3A50123%2Fcb"
    scope = ("openid%203gpp%3Amc%3Aptt_service%203gpp%3Amc%3Adata_service%20"
             "3gpp%3Amc%3Aptt_config_management_service%203gpp%3Amc%3Aptt_key_management_service")
    host = f"idms.{DOMAIN}:8080"
    c = Tcp(d, CON4, IDMS4, 51734, 8080)
    c.open(rtt=3.2)
    c.send(True, crlf([
        f"GET /authorize?response_type=code&client_id=mcptt_client&redirect_uri={redirect}&scope={scope}"
        f"&state={state}&code_challenge={challenge}&code_challenge_method=S256"
        "&acr_values=3gpp%3Aacr%3Apassword HTTP/1.1",
        f"Host: {host}", f"User-Agent: {UA}", "Accept: text/html", "Connection: keep-alive"]),
        comment="OpenID Connect user authentication at the IdMS")
    form = (b"<!DOCTYPE html><html><head><title>MCX sign-in</title></head><body>"
            b"<form method=\"post\" action=\"/authenticate\"><input name=\"username\"/>"
            b"<input name=\"password\" type=\"password\"/><input type=\"hidden\" name=\"state\" value=\""
            + state.encode() + b"\"/><button>Sign in</button></form></body></html>\n")
    c.send(False, crlf(["HTTP/1.1 200 OK", "Content-Type: text/html; charset=utf-8",
                        f"Set-Cookie: idms_session={d.token(18)}; HttpOnly", "Content-Length: {LEN}"], form), gap=6)
    cred = f"username=alice.nowak&password={PASSWORD.replace('@', '%40').replace('!', '%21')}&state={state}".encode()
    c.send(True, crlf(["POST /authenticate HTTP/1.1", f"Host: {host}",
                       "Content-Type: application/x-www-form-urlencoded", "Content-Length: {LEN}"], cred), gap=2400)
    code = d.token(16)
    d.canary("string", code, "oidc.code")
    c.send(False, crlf(["HTTP/1.1 302 Found",
                        f"Location: http://127.0.0.1:50123/cb?code={code}&state={state}", "Content-Length: 0"]), gap=35)
    tok = (f"grant_type=authorization_code&code={code}&redirect_uri={redirect}&client_id=mcptt_client"
           f"&code_verifier={verifier}").encode()
    c.send(True, crlf(["POST /token HTTP/1.1", f"Host: {host}", "Content-Type: application/x-www-form-urlencoded",
                       "Content-Length: {LEN}"], tok), gap=4)
    body = json.dumps({"access_token": ACCESS_TOKEN, "token_type": "Bearer", "expires_in": 3600,
                       "refresh_token": REFRESH_TOKEN, "id_token": ID_TOKEN,
                       "scope": "openid 3gpp:mc:ptt_service 3gpp:mc:data_service"}, indent=1).encode()
    c.send(False, crlf(["HTTP/1.1 200 OK", "Content-Type: application/json", "Cache-Control: no-store",
                        "Content-Length: {LEN}"], body), gap=28)
    c.close()


def jwt(d, claims):
    head = base64.urlsafe_b64encode(b'{"alg":"RS256","kid":"idms-2026-1"}').rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(json.dumps(claims, separators=(",", ":")).encode()).rstrip(b"=").decode()
    return f"{head}.{body}.{d.token(64)}"


# --- key material from the KMS over TLS --------------------------------------------------
def kms(d):
    c = Tcp(d, CON4, KMS4, 51740, 443)
    c.open(rtt=3.4)
    sni = f"kms.{DOMAIN}".encode()
    client_random = d.rand(32)
    exts = (struct.pack("!HHHBH", 0, len(sni) + 5, len(sni) + 3, 0, len(sni)) + sni
            + struct.pack("!HHH", 16, 11, 9) + b"\x08http/1.1"
            + struct.pack("!HHB", 43, 3, 2) + b"\x03\x04"
            + struct.pack("!HHH", 10, 4, 2) + b"\x00\x1d"
            + struct.pack("!HHH", 13, 6, 4) + b"\x08\x04\x04\x03"
            + struct.pack("!HHHHH", 51, 38, 36, 0x1d, 32) + d.rand(32))
    hello = (b"\x03\x03" + client_random + b"\x20" + d.rand(32) + struct.pack("!H", 4) + b"\x13\x01\x13\x02"
             + b"\x01\x00" + struct.pack("!H", len(exts)) + exts)
    hs = b"\x01" + struct.pack("!I", len(hello))[1:] + hello
    c.send(True, b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs, comment="KMS: identity key provisioning (TLS)")
    sh_ext = struct.pack("!HHH", 43, 2, 0x0304) + struct.pack("!HHHH", 51, 36, 0x1d, 32) + d.rand(32)
    sh = b"\x03\x03" + d.rand(32) + b"\x20" + d.rand(32) + b"\x13\x01\x00" + struct.pack("!H", len(sh_ext)) + sh_ext
    sh = b"\x02" + struct.pack("!I", len(sh))[1:] + sh
    flight = (b"\x16\x03\x03" + struct.pack("!H", len(sh)) + sh + b"\x14\x03\x03\x00\x01\x01"
              + b"\x17\x03\x03" + struct.pack("!H", 2800) + d.rand(2800))
    c.send(False, flight, gap=5)
    c.send(True, b"\x14\x03\x03\x00\x01\x01" + b"\x17\x03\x03\x00\x35" + d.rand(0x35)
           + b"\x17\x03\x03\x01\x20" + d.rand(0x120), gap=2)
    c.send(False, b"\x17\x03\x03" + struct.pack("!H", 3900) + d.rand(3900), gap=21)
    c.close()
    return client_random


# --- SIP over TCP to the P-CSCF ------------------------------------------------------------
class Sip:
    """One SIP-over-TCP flow between a client on the console and the P-CSCF."""

    def __init__(self, d, v6=False, port=5062):
        self.d, self.port = d, port
        self.me_raw = CON6 if v6 else CON4
        self.me = f"[{CON6}]" if v6 else CON4
        self.pcscf = f"[{PCSCF6}]" if v6 else PCSCF4
        self.c = Tcp(d, self.me_raw, PCSCF6 if v6 else PCSCF4, port, 5060, v6=v6)

    def contact(self):
        return f"sip:alice.nowak@{self.me}:{self.port};transport=tcp"

    def req(self, method, ruri, cseq, extra, body=b"", ctype=None, frm=ALICE, to=None, tag="a1", call=None,
            gap=1.0, comment=None, to_hdr=None):
        branch = self.d.branch()
        lines = [f"{method} {ruri} SIP/2.0", f"Via: SIP/2.0/TCP {self.me}:{self.port};branch={branch}",
                 "Max-Forwards: 70", f"From: <{frm}>;tag={tag}", to_hdr or f"To: <{to or ruri}>",
                 f"Call-ID: {call or self.d.callid()}", f"CSeq: {cseq} {method}", *extra]
        if ctype:
            lines.append(f"Content-Type: {ctype}")
        lines.append("Content-Length: {LEN}")
        self.c.send(True, crlf(lines, body), gap=gap, comment=comment)
        return branch, lines

    def resp(self, code, reason, req_lines, extra=(), body=b"", ctype=None, gap=20.0, totag="s1", up=False):
        hdr = {l.split(":", 1)[0]: l for l in req_lines[1:] if ":" in l}
        to = hdr["To"] if ";tag=" in hdr["To"] else hdr["To"] + f";tag={totag}"
        via = hdr["Via"] + (f";received={self.me_raw}" if not up else "")
        lines = [f"SIP/2.0 {code} {reason}", via, hdr["From"], to, hdr["Call-ID"], hdr["CSeq"], *extra]
        if ctype:
            lines.append(f"Content-Type: {ctype}")
        lines.append("Content-Length: {LEN}")
        self.c.send(up, crlf(lines, body), gap=gap)

    def incoming(self, method, ruri, frm, to, call, cseq, extra, body=b"", ctype=None, gap=1.0, comment=None,
                 from_tag="ps1", to_tag=None):
        """A request from the P-CSCF to the console; returns its header lines."""
        lines = [f"{method} {ruri} SIP/2.0", f"Via: SIP/2.0/TCP {self.pcscf}:5060;branch={self.d.branch()}",
                 "Max-Forwards: 69", f"From: <{frm}>;tag={from_tag}",
                 f"To: <{to}>" + (f";tag={to_tag}" if to_tag else ""), f"Call-ID: {call}",
                 f"CSeq: {cseq} {method}", *extra]
        if ctype:
            lines.append(f"Content-Type: {ctype}")
        lines.append("Content-Length: {LEN}")
        self.c.send(False, crlf(lines, body), gap=gap, comment=comment)
        return lines


def mcptt_info(params):
    return ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<mcpttinfo xmlns=\"urn:3gpp:ns:mcpttInfo:1.0\">\n"
            "<mcptt-Params>\n" + params + "</mcptt-Params>\n</mcpttinfo>\n").encode()


def uri_el(name, uri):
    return f"<{name} type=\"Normal\"><mcpttURI>{uri}</mcpttURI></{name}>\n"


def str_el(name, value):
    return f"<{name} type=\"Normal\"><mcpttString>{value}</mcpttString></{name}>\n"


def bool_el(name, value):
    return f"<{name} type=\"Normal\"><mcpttBoolean>{value}</mcpttBoolean></{name}>\n"


def register(d, s, features, comment):
    """IMS registration with AKA challenge (TS 24.229) for the client behind flow s."""
    contact = f"Contact: <{s.contact()}>;{features};+sip.instance=\"<urn:gsma:imei:{IMEI}>\""
    common = [contact, f"P-Access-Network-Info: {CELL}", f"User-Agent: {UA}", "Expires: 600000",
              "Supported: path, gruu, sec-agree", "Require: sec-agree", "Proxy-Require: sec-agree",
              f"Security-Client: ipsec-3gpp; alg=hmac-sha-1-96; spi-c={d.rng.randrange(1 << 28)}; "
              f"spi-s={d.rng.randrange(1 << 28)}; port-c={s.port}; port-s={s.port + 2}"]
    call = d.callid()
    _, l1 = s.req("REGISTER", f"sip:{DOMAIN}", 1, [*common, f"Authorization: Digest username=\"{IMPI}\", "
                  f"realm=\"{DOMAIN}\", nonce=\"\", uri=\"sip:{DOMAIN}\", response=\"\""],
                  to=ALICE, call=call, gap=200, comment=comment)
    nonce = d.sip_canary("string", base64.b64encode(d.rand(32)).decode(), "sip-param:WWW-Authenticate;nonce")
    s.resp(401, "Unauthorized", l1, [f"WWW-Authenticate: Digest realm=\"{DOMAIN}\", nonce=\"{nonce}\", "
                                     "algorithm=AKAv1-MD5, qop=\"auth\"",
                                     f"Security-Server: ipsec-3gpp; q=0.1; alg=hmac-sha-1-96; "
                                     f"spi-c={d.rng.randrange(1 << 28)}; spi-s={d.rng.randrange(1 << 28)}; "
                                     "port-c=5066; port-s=5068"], gap=42)
    _, l2 = s.req("REGISTER", f"sip:{DOMAIN}", 2, [*common, f"Authorization: Digest username=\"{IMPI}\", "
                  f"realm=\"{DOMAIN}\", nonce=\"{nonce}\", uri=\"sip:{DOMAIN}\", qop=auth, nc=00000001, "
                  f"cnonce=\"{d.sip_canary('string', d.token(8), 'sip-param:Authorization;cnonce')}\", "
                  f"response=\"{d.sip_canary('string', d.rand(16).hex(), 'sip-param:Authorization;response')}\", "
                  "algorithm=AKAv1-MD5"],
                  to=ALICE, call=call, gap=31)
    s.resp(200, "OK", l2, [f"P-Associated-URI: <{ALICE}>, <tel:+48601234567>",
                           f"Service-Route: <sip:orig@scscf1.{DOMAIN};lr>",
                           f"Contact: <{s.contact()}>;expires=600000"], gap=67)


MCPTT_FEATURES = "+g.3gpp.mcptt;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mcptt\""
MCDATA_FEATURES = ("+g.3gpp.mcdata.sds;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mcdata,"
                   "urn%3Aurn-7%3A3gpp-service.ims.icsi.mcdata.sds\"")
MCDATA_PSI = f"sip:mcdata-part@{DOMAIN}"
MCDATA_CLIENT_ID = "urn:uuid:9b2d41c7-08e3-4f6a-b5d0-7e13c9a2f864"


def mcdata_service_authorisation(d, s6):
    """MCData client: registration and PUBLISH poc-settings (TS 24.282 clauses 7.2.1, 7.2.2)."""
    register(d, s6, MCDATA_FEATURES, "MCData client registration (IPv6)")
    info = (f"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<mcdatainfo xmlns=\"urn:3gpp:ns:mcdataInfo:1.0\">\n"
            "<mcdata-Params>\n"
            f"<mcdata-access-token type=\"Normal\"><mcdataString>{ACCESS_TOKEN}</mcdataString></mcdata-access-token>\n"
            f"<mcdata-client-id type=\"Normal\"><mcdataString>{MCDATA_CLIENT_ID}</mcdataString></mcdata-client-id>\n"
            "</mcdata-Params>\n</mcdatainfo>\n").encode()
    poc = (f"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<poc-settings xmlns=\"urn:oma:params:xml:ns:poc:poc-settings\""
           f" xmlns:mcs10Set=\"urn:3gpp:mcsSettings:1.0\">\n<entity id=\"{MCDATA_CLIENT_ID}\">\n"
           "<mcs10Set:selected-user-profile-index>1</mcs10Set:selected-user-profile-index>\n"
           "</entity>\n</poc-settings>\n").encode()
    _, l = s6.req("PUBLISH", MCDATA_PSI, 1, ["Event: poc-settings", "Expires: 4294967295",
                                             f"P-Preferred-Identity: <{ALICE}>",
                                             "P-Preferred-Service: urn:urn-7:3gpp-service.ims.icsi.mcdata"],
                  multipart("mcdata-b0", [("application/vnd.3gpp.mcdata-info+xml", info),
                                          ("application/poc-settings+xml", poc)]),
                  "multipart/mixed;boundary=mcdata-b0", tag="md1", gap=40,
                  comment="MCData service authorisation (PUBLISH)")
    s6.resp(200, "OK", l, ["SIP-ETag: poc-md-3c", "Expires: 4294967295"], gap=52)


def service_authorisation(d, s):
    info = mcptt_info(str_el("mcptt-access-token", ACCESS_TOKEN) + str_el("mcptt-client-id", CLIENT_ID))
    poc = (f"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<poc-settings xmlns=\"urn:oma:params:xml:ns:poc:poc-settings\""
           f" xmlns:mcs10Set=\"urn:3gpp:mcsSettings:1.0\">\n<entity id=\"{CLIENT_ID}\">\n"
           "<am-settings><answer-mode>auto-answer</answer-mode></am-settings>\n"
           "<mcs10Set:selected-user-profile-index>2</mcs10Set:selected-user-profile-index>\n"
           "<mcs10Set:multiplex-support>true</mcs10Set:multiplex-support>\n</entity>\n</poc-settings>\n").encode()
    _, l = s.req("PUBLISH", PSI, 1, ["Event: poc-settings", "Expires: 4294967295",
                                     f"P-Preferred-Identity: <{ALICE}>",
                                     "P-Preferred-Service: urn:urn-7:3gpp-service.ims.icsi.mcptt"],
                 multipart("mcptt-b1", [("application/vnd.3gpp.mcptt-info+xml", info),
                                        ("application/poc-settings+xml", poc)]
                           + ([("application/mikey", mikey_csk(ALICE, PSI))] if WITH_MIKEY[0] else [])),
                 "multipart/mixed;boundary=mcptt-b1", gap=40,
                 comment="MCPTT service authorisation (PUBLISH) with the CSK upload (TS 24.379 §7.2.2)")
    s.resp(200, "OK", l, ["SIP-ETag: poc-7a2c", "Expires: 4294967295"], gap=58)


XCAP_ROOT = f"http://cms.{DOMAIN}/xcap-root"


def config_subscription(d, s):
    info = mcptt_info(str_el("mcptt-access-token", ACCESS_TOKEN))
    rl = (f"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<resource-lists xmlns=\"urn:ietf:params:xml:ns:resource-lists\">"
          f"<list><entry uri=\"org.3gpp.mcptt.ue-config/users/{ALICE}/\"/>"
          f"<entry uri=\"org.3gpp.mcptt.user-profile/users/{ALICE}/\"/>"
          f"<entry uri=\"org.3gpp.mcdata.user-profile/users/{ALICE}/\"/>"
          "<entry uri=\"org.3gpp.mcptt.service-config/global/\"/></list></resource-lists>\n").encode()
    call = d.callid()
    _, l = s.req("SUBSCRIBE", CMS_PSI, 1, ["Event: xcap-diff;diff-processing=aggregate", "Expires: 7200",
                                           "Accept: application/xcap-diff+xml, message/external-body",
                                           f"Contact: <{s.contact()}>",
                                           f"P-Preferred-Identity: <{ALICE}>"],
                 multipart("mcptt-b2", [("application/vnd.3gpp.mcptt-info+xml", info),
                                        ("application/resource-lists+xml", rl)]),
                 "multipart/mixed;boundary=mcptt-b2", call=call, tag="cm1", gap=25,
                 comment="configuration management: subscribe to the CMS documents")
    s.resp(200, "OK", l, ["Expires: 7200"], gap=44, totag="cms9")
    diff = (f"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<xcap-diff xmlns=\"urn:ietf:params:xml:ns:xcap-diff\" "
            f"xcap-root=\"{XCAP_ROOT}/\">\n"
            f"<document sel=\"org.3gpp.mcptt.ue-config/users/{ALICE}/imei-{IMEI}/mcptt-ue-config.xml\" "
            "new-etag=\"u81\"/>\n"
            f"<document sel=\"org.3gpp.mcptt.user-profile/users/{ALICE}/mcptt-user-profile-2.xml\" new-etag=\"p72\"/>\n"
            f"<document sel=\"org.3gpp.mcdata.user-profile/users/{ALICE}/mcdata-user-profile-1.xml\" new-etag=\"d33\"/>\n"
            "<document sel=\"org.3gpp.mcptt.service-config/global/service-config.xml\" new-etag=\"s15\"/>\n"
            "</xcap-diff>\n").encode()
    n = s.incoming("NOTIFY", s.contact(), CMS_PSI, ALICE, call, 1,
                   ["Event: xcap-diff", "Subscription-State: active;expires=7200"], diff,
                   "application/xcap-diff+xml", gap=6)
    s.resp(200, "OK", n, gap=3, up=True)


def xcap_get(d, c, path, ctype, doc, gap, comment=None):
    c.send(True, crlf([f"GET /xcap-root/{path} HTTP/1.1", f"Host: {c.host}",
                       f"Authorization: Bearer {ACCESS_TOKEN}", f"X-3GPP-Intended-Identity: \"{ALICE}\"",
                       f"Accept: {ctype}", f"User-Agent: {UA}"]), gap=gap, comment=comment)
    c.send(False, crlf(["HTTP/1.1 200 OK", f"Content-Type: {ctype}", f"ETag: \"{d.token(4)}\"",
                        "Content-Length: {LEN}"], doc), gap=14)


# --- the GMS over HTTPS (feature 007): TLS 1.2 with the certificate chain ------------------
GMS_ORG, GMS_CA = "Warsaw North Fire Service", "WN Fire Lab Issuing CA"
PKI_ADMIN = "pki-admin@wn.fire.example.net"


def gms_https(d):
    """A full TLS 1.2 handshake with the GMS (RFC 5246 §7.3, ECDHE_RSA with AES-GCM, RFC 5289):
    the certificate chain names the GMS, its operator and the CA, then XCAP runs in protected
    records. Its values come from a generator of its own and its packets are placed without moving
    the session clock, so the rest of the demo is unchanged."""
    saved_rng, saved_now = d.rng, d.now
    d.rng = random.Random(7007)
    try:
        c = Tcp(d, CON4, GMS4, 51761, 443)
        c.open(rtt=2.9)
        name = f"gms.{DOMAIN}".encode()
        hs = lambda t, body: bytes([t]) + struct.pack("!I", len(body))[1:] + body  # noqa: E731
        rec = lambda t, body: bytes([t, 3, 3]) + struct.pack("!H", len(body)) + body  # noqa: E731
        exts = (struct.pack("!HHHBH", 0, len(name) + 5, len(name) + 3, 0, len(name)) + name
                + struct.pack("!HHH", 10, 6, 4) + b"\x00\x17\x00\x18"
                + struct.pack("!HHB", 11, 2, 1) + b"\x00"
                + struct.pack("!HHH", 13, 8, 6) + b"\x04\x01\x05\x01\x04\x03"
                + struct.pack("!HH", 35, 0) + struct.pack("!HH", 23, 0) + struct.pack("!HHB", 0xff01, 1, 0))
        hello = (b"\x03\x03" + d.rand(32) + b"\x00" + struct.pack("!H", 4) + b"\xc0\x2f\xc0\x30"
                 + b"\x01\x00" + struct.pack("!H", len(exts)) + exts)
        c.send(True, rec(22, hs(1, hello)), comment="GMS over HTTPS: TLS 1.2 handshake with the certificate chain")
        sh_ext = struct.pack("!HHB", 0xff01, 1, 0) + struct.pack("!HH", 23, 0) + struct.pack("!HH", 35, 0)
        sh = (b"\x03\x03" + d.rand(32) + b"\x20" + d.rand(32) + b"\xc0\x2f\x00"
              + struct.pack("!H", len(sh_ext)) + sh_ext)
        ca_name = der.name([("2.5.4.6", 0x13, "PL"), ("2.5.4.10", 0x0C, GMS_ORG), ("2.5.4.3", 0x0C, GMS_CA)])
        gms_name = der.name([("2.5.4.6", 0x13, "PL"), ("2.5.4.10", 0x0C, GMS_ORG), ("2.5.4.3", 0x0C, name.decode())])
        ca_kid, gms_kid = d.rand(20), d.rand(20)
        ca = der.certificate(d.rng, b"\x5a" + d.rand(15), ca_name, ca_name, extensions=[
            der.ext("2.5.29.19", der.seq(der.tlv(0x01, b"\xff")), critical=True),
            der.ext("2.5.29.14", der.tlv(0x04, ca_kid))], issuer_raw=True)
        leaf = der.certificate(d.rng, b"\x91" + d.rand(15), ca_name, gms_name, extensions=[
            der.ext("2.5.29.17", der.seq(der.tlv(0x82, name), der.tlv(0x81, PKI_ADMIN.encode()))),
            der.ext("2.5.29.14", der.tlv(0x04, gms_kid)),
            der.ext("2.5.29.35", der.seq(der.tlv(0x80, ca_kid)))], issuer_raw=True)
        chain = b"".join(struct.pack("!I", len(x))[1:] + x for x in (leaf, ca))
        point = b"\x04" + d.rand(64)
        ske = b"\x03\x00\x17" + bytes([len(point)]) + point + b"\x04\x01" + struct.pack("!H", 256) + d.rand(256)
        ticket = d.rand(160)
        flight = (rec(22, hs(2, sh) + hs(11, struct.pack("!I", len(chain))[1:] + chain) + hs(12, ske) + hs(14, b"")))
        c.send(False, flight, gap=6)
        cke = hs(16, bytes([65]) + b"\x04" + d.rand(64))
        c.send(True, rec(22, cke) + rec(20, b"\x01") + rec(22, d.rand(40)), gap=3)
        c.send(False, rec(22, hs(4, struct.pack("!IH", 7200, len(ticket)) + ticket)) + rec(20, b"\x01")
               + rec(22, d.rand(40)), gap=4)
        c.send(True, rec(23, d.rand(612)), gap=2)
        c.send(False, rec(23, d.rand(1890)), gap=11)
        c.send(True, rec(21, d.rand(26)), gap=40)
        c.close()
    finally:
        d.rng, d.now = saved_rng, saved_now


# --- KMS init and key provisioning over h2c (feature 007, TS 33.180 Annex D) ----------------
KMS_NS = "urn:3gpp:ns:mcsecKMSInterface:1.0"


def h2frame(ftype, flags, stream, payload):
    return struct.pack("!I", len(payload))[1:] + bytes([ftype, flags]) + struct.pack("!I", stream) + payload


def kms_h2c(d):
    """The lab KMS also serves its HTTP interface over h2c (RFC 9113 §3.3): KMS Init returns the
    KMS certificate, KeyProvision the user's key set (SSK, RSK, PVT). Header blocks are
    Huffman-coded. Drawn from a generator of its own, placed without moving the session clock."""
    saved_rng, saved_now = d.rng, d.now
    d.rng = random.Random(7008)
    try:
        c = Tcp(d, CON4, KMS4, 51742, 8080)
        c.open(rtt=3.3)
        kms_uri, user = f"kms.{DOMAIN}", ALICE
        enc_c, enc_s = hpack.Encoder(), hpack.Encoder()
        settings = h2frame(4, 0, 0, struct.pack("!HI", 3, 100) + struct.pack("!HI", 4, 65535))
        req = lambda path, body: [(":method", "POST"), (":scheme", "http"), (":authority", f"kms.{DOMAIN}:8080"),  # noqa: E731
                                  (":path", path), ("authorization", f"Bearer {ACCESS_TOKEN}"),
                                  ("content-type", "application/xml"), ("content-length", str(len(body))),
                                  ("user-agent", UA)]
        rsp = lambda body: [(":status", "200"), ("content-type", "application/xml"),  # noqa: E731
                            ("content-length", str(len(body))), ("cache-control", "no-store")]
        kreq = (f'<?xml version="1.0" encoding="UTF-8"?>\n<KmsRequest xmlns="{KMS_NS}" Version="1.1.0">'
                f"<UserUri>{user}</UserUri><KmsUri>{kms_uri}</KmsUri><Time>2026-10-14T07:43:20</Time>"
                f"<ClientId>{CLIENT_ID}</ClientId></KmsRequest>\n").encode()
        hexs = lambda n: d.rand(n).hex().upper()  # noqa: E731
        init = (f'<?xml version="1.0" encoding="UTF-8"?>\n<KmsResponse xmlns="{KMS_NS}" Version="1.1.0">'
                f"<KmsUri>{kms_uri}</KmsUri><UserUri>{user}</UserUri><Time>2026-10-14T07:43:20</Time>"
                "<KmsMessage><KmsInit><KmsCertificate Version=\"1.1.0\" Role=\"Root\">"
                f"<CertUri>{kms_uri}.cert.root</CertUri><KmsUri>{kms_uri}</KmsUri><Issuer>{kms_uri}</Issuer>"
                "<ValidFrom>2026-01-01T00:00:00</ValidFrom><ValidTo>2027-12-31T23:59:59</ValidTo><Revoked>false</Revoked>"
                "<UserIdFormat>2</UserIdFormat><UserKeyPeriod>2592000</UserKeyPeriod><UserKeyOffset>0</UserKeyOffset>"
                f"<PubEncKey>04{hexs(256)}</PubEncKey><PubAuthKey>04{hexs(64)}</PubAuthKey>"
                "</KmsCertificate></KmsInit></KmsMessage></KmsResponse>\n").encode()
        # The user key set (TS 33.180 §D.3.5): never in the output.
        rsk = d.canary("string", "04" + hexs(256), "kms.UserDecryptKey")
        ssk = d.canary("string", hexs(32), "kms.UserSigningKeySSK")
        pvt = d.canary("string", "04" + hexs(64), "kms.UserPubTokenPVT")
        prov = (f'<?xml version="1.0" encoding="UTF-8"?>\n<KmsResponse xmlns="{KMS_NS}" Version="1.1.0">'
                f"<KmsUri>{kms_uri}</KmsUri><UserUri>{user}</UserUri><Time>2026-10-14T07:43:21</Time>"
                "<KmsMessage><KmsKeyProv Version=\"1.1.0\"><KmsKeySet Version=\"1.1.0\">"
                f"<KmsUri>{kms_uri}</KmsUri><CertUri>{kms_uri}.cert.root</CertUri><Issuer>{kms_uri}</Issuer>"
                f"<UserUri>{user}</UserUri><UserID>{hexs(32)}</UserID>"
                "<ValidFrom>2026-10-01T00:00:00</ValidFrom><ValidTo>2026-10-31T00:00:00</ValidTo>"
                "<KeyPeriodNo>678</KeyPeriodNo><Revoked>false</Revoked>"
                f"<UserDecryptKey>{rsk}</UserDecryptKey><UserSigningKeySSK>{ssk}</UserSigningKeySSK>"
                f"<UserPubTokenPVT>{pvt}</UserPubTokenPVT></KmsKeySet></KmsKeyProv></KmsMessage></KmsResponse>\n").encode()
        init_req = kreq
        prov_req = kreq.replace(b"<ClientId>", b"<ClientReqUrl>http://kms." + DOMAIN.encode()
                                + b":8080/keymanagement/identity/v1/keyprov</ClientReqUrl><ClientId>")
        c.send(True, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + settings
               + h2frame(1, 0x4, 1, enc_c.encode(req("/keymanagement/identity/v1/init", init_req)))
               + h2frame(0, 0x1, 1, init_req), comment="KMS: initialisation and key provisioning over h2c")
        c.send(False, settings + h2frame(4, 0x1, 0, b"") + h2frame(1, 0x4, 1, enc_s.encode(rsp(init)))
               + h2frame(0, 0x1, 1, init), gap=4)
        c.send(True, h2frame(4, 0x1, 0, b"")
               + h2frame(1, 0x4, 3, enc_c.encode(req("/keymanagement/identity/v1/keyprov", prov_req)))
               + h2frame(0, 0x1, 3, prov_req), gap=2)
        c.send(False, h2frame(1, 0x4, 3, enc_s.encode(rsp(prov))) + h2frame(0, 0x1, 3, prov), gap=5)
        c.send(True, h2frame(7, 0, 0, struct.pack("!II", 3, 0)), gap=30)
        c.close()
    finally:
        d.rng, d.now = saved_rng, saved_now


def entry(uri, name):
    return f"<entry><uri-entry>{uri}</uri-entry><display-name xml:lang=\"en\">{name}</display-name></entry>"


def cms_documents(d):
    c = Tcp(d, CON4, CMS4, 51752, 80)
    c.host = f"cms.{DOMAIN}"
    c.open(rtt=2.8)
    ue = (f"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<mcptt-UE-configuration xmlns=\"urn:3gpp:mcptt:mcpttUEConfig:1.0\" "
          f"domain=\"{DOMAIN}\" XUI-URI=\"{ALICE}\">\n<common><Max-Simul-Call-N10>2</Max-Simul-Call-N10></common>\n"
          f"<mcptt-UE-id><Instance-ID-URN>urn:gsma:imei:{IMEI}</Instance-ID-URN></mcptt-UE-id>\n"
          "<on-network><IPv6Preferred>false</IPv6Preferred><Relay-Service>false</Relay-Service></on-network>\n"
          "</mcptt-UE-configuration>\n").encode()
    xcap_get(d, c, f"org.3gpp.mcptt.ue-config/users/{ALICE}/imei-{IMEI}/mcptt-ue-config.xml",
             "application/vnd.3gpp.mcptt-ue-config+xml", ue, 6, "XCAP: UE configuration, user profile, service configuration")
    profile = (f"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<mcptt-user-profile xmlns=\"urn:3gpp:mcptt:user-profile:1.0\" "
               f"XUI-URI=\"{ALICE}\" user-profile-index=\"2\">\n"
               "<Name>Alice Nowak</Name>\n<Status>true</Status>\n<ProfileName>Dispatcher day shift</ProfileName>\n"
               "<Common>\n<UserAlias><alias-entry><display-name>Dispatcher WN-3</display-name></alias-entry></UserAlias>\n"
               f"<MCPTTUserID>{entry(ALICE, 'Alice Nowak')}</MCPTTUserID>\n"
               f"<PrivateCall><PrivateCallList><PrivateCallURI>{entry(BOB, 'Bob Zielinski')}</PrivateCallURI>"
               f"<PrivateCallURI>{entry(CHIEF, 'Chief Kowalczyk')}</PrivateCallURI></PrivateCallList></PrivateCall>\n"
               "<MissionCriticalOrganization>Warsaw North Fire Service</MissionCriticalOrganization>\n"
               "<ParticipantType>Dispatcher</ParticipantType>\n</Common>\n"
               f"<OnNetwork>\n<MCPTTGroupInfo>{entry(GROUP, 'Fire Brigade West')}{entry(GROUP2, 'WN Command')}"
               "</MCPTTGroupInfo>\n<MaxAffiliationsN2>8</MaxAffiliationsN2>\n"
               f"<ImplicitAffiliations>{entry(GROUP, 'Fire Brigade West')}</ImplicitAffiliations>\n</OnNetwork>\n"
               "</mcptt-user-profile>\n").encode()
    xcap_get(d, c, f"org.3gpp.mcptt.user-profile/users/{ALICE}/mcptt-user-profile-2.xml",
             "application/vnd.3gpp.mcptt-user-profile+xml", profile, 3)
    mdp = (f"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<mcdata-user-profile xmlns=\"urn:3gpp:ns:mcdata:user-profile:1.0\" "
           f"XUI-URI=\"{ALICE}\" user-profile-index=\"1\">\n"
           "<Name>Alice Nowak</Name>\n<Status>true</Status>\n<ProfileName>Dispatcher data</ProfileName>\n"
           f"<Common>\n<MCDataUserID>{entry(ALICE, 'Alice Nowak')}</MCDataUserID>\n"
           "<ParticipantType>Dispatcher</ParticipantType>\n"
           "<MissionCriticalOrganization>Warsaw North Fire Service</MissionCriticalOrganization>\n</Common>\n"
           f"<OnNetwork>\n<MaxAffiliationsN2>4</MaxAffiliationsN2>\n"
           f"<ImplicitAffiliations>{entry(GROUP, 'Fire Brigade West')}</ImplicitAffiliations>\n"
           "</OnNetwork>\n</mcdata-user-profile>\n").encode()
    xcap_get(d, c, f"org.3gpp.mcdata.user-profile/users/{ALICE}/mcdata-user-profile-1.xml",
             "application/vnd.3gpp.mcdata-user-profile+xml", mdp, 3)
    svc = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<service-configuration-info "
           "xmlns=\"urn:3gpp:mcptt:service-configuration:1.0\">\n<service-configuration-params domain=\""
           f"{DOMAIN}\"><common><private-call><hang-time>PT30S</hang-time></private-call></common>"
           "<on-network><emergency-call><private-cancel-timeout>PT60S</private-cancel-timeout></emergency-call>"
           "</on-network></service-configuration-params>\n</service-configuration-info>\n").encode()
    xcap_get(d, c, "org.3gpp.mcptt.service-config/global/service-config.xml",
             "application/vnd.3gpp.mcptt-service-config+xml", svc, 3)
    c.close()


def gms_documents(d):
    c = Tcp(d, CON4, GMS4, 51760, 80)
    c.host = f"gms.{DOMAIN}"
    c.open(rtt=2.9)
    for uri, title, members in ((GROUP, "Fire Brigade West - Unit 12",
                                 [(ALICE, "Alice Nowak"), (BOB, "Bob Zielinski"), (CHIEF, "Chief Kowalczyk"),
                                  (f"sip:engine-12-crew@{DOMAIN}", "Engine 12 crew")]),
                                (GROUP2, "WN Command", [(ALICE, "Alice Nowak"), (CHIEF, "Chief Kowalczyk")])):
        doc = (f"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<group xmlns=\"urn:oma:xml:poc:list-service\" "
               "xmlns:rl=\"urn:ietf:params:xml:ns:resource-lists\">\n"
               f"<list-service uri=\"{uri}\"><display-name xml:lang=\"en\">{title}</display-name>\n<list>"
               + "".join(f"<rl:entry uri=\"{m}\"><rl:display-name>{n}</rl:display-name></rl:entry>" for m, n in members)
               + "</list>\n<invite-members>true</invite-members></list-service>\n</group>\n").encode()
        # The group document by its group identity (ETSI TS 103 564 §7.9.5, CSC-GMS/GROUP/UE/01).
        xcap_get(d, c, f"org.openmobilealliance.groups/global/byGroupID/{uri}",
                 "application/vnd.oma.poc.groups+xml", doc, 4,
                 "XCAP: group documents from the GMS" if uri == GROUP else None)
    c.close()


def mcdata_info(params):
    return ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<mcdatainfo xmlns=\"urn:3gpp:ns:mcdataInfo:1.0\">\n"
            "<mcdata-Params>\n" + params + "</mcdata-Params>\n</mcdatainfo>\n").encode()


def md_uri(name, uri):
    return f"<{name} type=\"Normal\"><mcdataURI>{uri}</mcdataURI></{name}>\n"


def md_str(name, value):
    return f"<{name} type=\"Normal\"><mcdataString>{value}</mcdataString></{name}>\n"


SERVICES = {
    "mcptt": {"psi": PSI, "icsi": "urn:urn-7:3gpp-service.ims.icsi.mcptt", "ns": "urn:3gpp:ns:mcpttPresInfo:1.0",
              "pfx": "mcpttPI10", "client": CLIENT_ID, "info": lambda: mcptt_info(uri_el("mcptt-request-uri", ALICE)),
              "info_type": "application/vnd.3gpp.mcptt-info+xml", "clause": "TS 24.379 9.2.1.2"},
    "mcdata": {"psi": MCDATA_PSI, "icsi": "urn:urn-7:3gpp-service.ims.icsi.mcdata",
               "ns": "urn:3gpp:ns:mcdataPresInfo:1.0", "pfx": "mcdataPI10", "client": MCDATA_CLIENT_ID,
               "info": lambda: mcdata_info(md_uri("mcdata-request-uri", ALICE)),
               "info_type": "application/vnd.3gpp.mcdata-info+xml", "clause": "TS 24.282 8.2.2"},
}


def affiliate(d, s, service, groups, comment):
    """Affiliation status change (PUBLISH presence) and subscription to the affiliation status."""
    sv = SERVICES[service]
    pfx = sv["pfx"]

    def pidf(status):
        attrs = " status=\"affiliated\" expires=\"2026-10-14T09:42:00Z\"" if status else ""
        return (f"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<presence xmlns=\"urn:ietf:params:xml:ns:pidf\" "
                f"xmlns:{pfx}=\"{sv['ns']}\" entity=\"{ALICE}\">\n<tuple id=\"{sv['client']}\"><status>"
                + "".join(f"<{pfx}:affiliation group=\"{g}\"{attrs}/>" for g in groups)
                + f"</status></tuple>\n<{pfx}:p-id>{d.token(12)}</{pfx}:p-id>\n</presence>\n").encode()

    bnd = f"{service}-af"
    _, l = s.req("PUBLISH", sv["psi"], 1, ["Event: presence", "Expires: 4294967295",
                                           f"P-Preferred-Identity: <{ALICE}>", f"P-Preferred-Service: {sv['icsi']}"],
                 multipart(bnd, [(sv["info_type"], sv["info"]()), ("application/pidf+xml", pidf(False))]),
                 f"multipart/mixed;boundary={bnd}", tag=f"{service[:3]}a1", gap=30, comment=comment)
    s.resp(200, "OK", l, [f"SIP-ETag: aff-{d.token(3)}", "Expires: 4294967295"], gap=46)
    call = d.callid()
    _, l = s.req("SUBSCRIBE", sv["psi"], 1, ["Event: presence", "Accept: application/pidf+xml", "Expires: 7200",
                                             f"Contact: <{s.contact()}>", f"P-Preferred-Service: {sv['icsi']}"],
                 multipart(bnd + "2", [(sv["info_type"], sv["info"]())]), f"multipart/mixed;boundary={bnd}2",
                 tag=f"{service[:3]}a2", call=call, gap=8)
    s.resp(200, "OK", l, ["Expires: 7200"], gap=39, totag="ps2")
    n = s.incoming("NOTIFY", s.contact(), sv["psi"], ALICE, call, 1,
                   ["Event: presence", "Subscription-State: active;expires=7200"], pidf(True), "application/pidf+xml",
                   gap=5)
    s.resp(200, "OK", n, gap=2, up=True)


DEMO_ECI = 0x0A1B2C3  # the serving cell of the location report and of the floor request


def reg_notify(d, s):
    """Feature 003 (R18, US5): the reg event NOTIFY after the registration (TS 24.229 §5.4.2.1.2)."""
    reg = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<reginfo xmlns=\"urn:ietf:params:xml:ns:reginfo\" "
           "xmlns:gr=\"urn:ietf:params:xml:ns:gruuinfo\" version=\"0\" state=\"full\">\n"
           f"<registration aor=\"{ALICE}\" id=\"a7\" state=\"active\">\n"
           f"<contact id=\"c9\" state=\"active\" event=\"registered\" expires=\"600000\">\n"
           f"<uri>{s.contact()}</uri>\n<gr:pub-gruu uri=\"{ALICE};gr={CLIENT_ID}\"/>\n"
           "</contact>\n</registration>\n</reginfo>\n").encode()
    call = d.callid()
    msg = s.incoming("NOTIFY", s.contact(), ALICE, ALICE, call, 1,
                     ["Event: reg", "Subscription-State: active;expires=600000"],
                     reg, "application/reginfo+xml", gap=120, comment="reg event NOTIFY", from_tag="rg1",
                     to_tag="rg2")
    s.resp(200, "OK", msg, gap=15, up=True)


def location_config(d, s):
    """Feature 003 (R18, US3): the server configures location reporting (TS 24.379 §13.2.3.2)."""
    cfg = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<location-info xmlns=\"urn:3gpp:ns:mcpttLocationInfo:1.0\">\n"
           "<Configuration ConfigScope=\"Full\"><NonEmergencyLocationInformation><ServingEcgi/><NeighbouringEcgi/>"
           "<GeographicalCoordinate/><minimumIntervalLength>10</minimumIntervalLength></NonEmergencyLocationInformation>"
           "<TriggeringCriteria><CellChange><AnyCellChange TriggerId=\"cell-any\"/><EnterSpecificCell "
           "TriggerId=\"cell-west-1\">260001" + format(DEMO_ECI, "028b") + "</EnterSpecificCell></CellChange>"
           "<PeriodicReport TriggerId=\"periodic-60s\">60</PeriodicReport>"
           "<TravelledDistance TriggerId=\"distance-500m\">500</TravelledDistance></TriggeringCriteria>"
           "</Configuration>\n</location-info>\n").encode()
    call = d.callid()
    msg = s.incoming("MESSAGE", s.contact(), PSI, ALICE, call, 1,
                     ["Accept-Contact: *;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mcptt\"",
                      f"P-Asserted-Identity: <{PSI}>"],
                     cfg, "application/vnd.3gpp.mcptt-location-info+xml", gap=800,
                     comment="location reporting configuration", from_tag="lc1")
    s.resp(200, "OK", msg, gap=20, up=True, totag="lc2")


def location_report(d, s):
    lat = int((1 << 23) * 52.2905 / 90)
    lon = int((1 << 24) * 20.9661 / 360)
    loc = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<location-info xmlns=\"urn:3gpp:ns:mcpttLocationInfo:1.0\">\n"
           "<Report ReportType=\"NonEmergency\" ReportID=\"r-0042\"><CurrentLocation>"
           "<CurrentServingEcgi><Ecgi>260001" + format(DEMO_ECI, "028b") + "</Ecgi></CurrentServingEcgi>"
           f"<CurrentCoordinate><longitude type=\"Normal\"><threebytes>{lon}</threebytes></longitude>"
           f"<latitude type=\"Normal\"><threebytes>{lat}</threebytes></latitude></CurrentCoordinate>"
           "</CurrentLocation><TriggerId>periodic-60s</TriggerId></Report>\n</location-info>\n").encode()
    info = mcptt_info(uri_el("mcptt-request-uri", PSI) + uri_el("mcptt-calling-user-id", ALICE))
    _, l = s.req("MESSAGE", PSI, 1, ["Accept-Contact: *;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mcptt\"",
                                     f"P-Preferred-Identity: <{ALICE}>", f"P-Access-Network-Info: {CELL}"],
                 multipart("mcptt-b3", [("application/vnd.3gpp.mcptt-info+xml", info),
                                        ("application/vnd.3gpp.mcptt-location-info+xml", loc)]),
                 "multipart/mixed;boundary=mcptt-b3", tag="lr1", gap=1500, comment="location report")
    s.resp(200, "OK", l, gap=33)


# --- media plane --------------------------------------------------------------------------
CON_RTP, CON_FC = 40000, 40002
SRV_RTP, SRV_FC = 50000, 50002
HH_RTP, HH_FC = 41000, 41002
HSRV_RTP, HSRV_FC = 52000, 52002
CON_SSRC, SRV_SSRC, HH_SSRC = 0x1A2B3C4D, 0x55AA0001, 0x7E0F1234


def fc_field(fid, value):
    f = bytes([fid, len(value)]) + value
    return f + b"\0" * (-len(f) % 4)


def floor_msg(subtype, ssrc, fields=b""):
    body = struct.pack("!I", ssrc) + b"MCPT" + fields
    return struct.pack("!BBH", 0x80 | subtype, 204, len(body) // 4) + body


def amr_wb(d, seq, ts, ssrc):
    """RTP with one AMR-WB 12.65 kbit/s frame, bandwidth-efficient: CMR=15, F=0, FT=2, Q=1."""
    bits = "1111" + "0" + "0010" + "1" + "".join(d.rng.choice("01") for _ in range(253))
    bits += "0" * (-len(bits) % 8)
    return struct.pack("!BBHII", 0x80, 97, seq, ts, ssrc) + int(bits, 2).to_bytes(len(bits) // 8, "big")


SDP_CANARIES = []  # (category, value, rule) of the SDP identities, added to the manifest


def sdp(owner, ip, rtp, fc, sess, sep=";", key_mgmt=None, proto="RTP/AVP"):
    """An MCPTT SDP. The fmtp:MCPTT separator is ";" as in every example of the standards
    (TS 24.380 §4.3.3.1); one offer uses ":" of the TS 24.380 §12.1.2.3 ABNF.
    key_mgmt: a MIKEY-SAKKE I_MESSAGE for a session-level a=key-mgmt (feature 005)."""
    SDP_CANARIES.append(("number", str(sess), "sdp:o=.sess-id"))
    if owner not in ("mcptt",):  # "mcptt" is standard vocabulary (+g.3gpp.mcptt): unscannable
        SDP_CANARIES.append(("string", owner, "sdp:o=.username"))
    km = f"a=key-mgmt:mikey {base64.b64encode(key_mgmt).decode()}\r\n" if key_mgmt else ""
    return (f"v=0\r\no={owner} {sess} {sess} IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n{km}"
            f"m=audio {rtp} {proto} 97\r\na=rtpmap:97 AMR-WB/16000\r\na=fmtp:97 mode-set=0,1,2\r\n"
            f"a=rtcp:{rtp + 1}\r\nm=application {fc} udp MCPTT\r\na=fmtp:MCPTT mc_queueing{sep}mc_priority=4\r\n").encode()


def group_call(d, s):
    # Feature 003 (R18): the indicators and an anyExt block, so the demo shows kept values.
    info = mcptt_info("<session-type>prearranged</session-type>\n" + uri_el("mcptt-request-uri", GROUP)
                      + uri_el("mcptt-calling-user-id", ALICE) + bool_el("emergency-ind", "false")
                      + bool_el("alert-ind", "false") + bool_el("imminentperil-ind", "false")
                      + "<broadcast-ind>false</broadcast-ind>\n" + str_el("mcptt-client-id", CLIENT_ID)
                      + "<anyExt>\n<urgency-ind>normal</urgency-ind>\n<user-requested-priority>5</user-requested-priority>\n"
                      "</anyExt>\n")
    call = d.callid()
    _, inv = s.req("INVITE", PSI, 1, [f"Contact: <{s.contact()}>;+g.3gpp.mcptt",
                                      "Accept-Contact: *;+g.3gpp.mcptt;require;explicit",
                                      "P-Preferred-Service: urn:urn-7:3gpp-service.ims.icsi.mcptt",
                                      f"P-Preferred-Identity: <{ALICE}>", f"P-Access-Network-Info: {CELL}",
                                      "Session-Expires: 1800", "Supported: timer"],
                   multipart("mcptt-b4", [("application/sdp", sdp("alice", CON4, CON_RTP, CON_FC, 2890844526)),
                                          ("application/vnd.3gpp.mcptt-info+xml", info)]),
                   "multipart/mixed;boundary=mcptt-b4", tag="gc1", call=call, gap=4000,
                   comment="pre-arranged group call to fire-brigade-west")
    s.resp(100, "Trying", inv, gap=18)
    handheld_joins(d, call)
    s.resp(200, "OK", inv, [f"Contact: <sip:mcptt-part@{PCSCF4}:5060;transport=tcp>;+g.3gpp.mcptt",
                            f"P-Asserted-Identity: <{GROUP}>", "Session-Expires: 1800;refresher=uac"],
           sdp("mcptt", MEDIA4, SRV_RTP, SRV_FC, 1), "application/sdp", gap=210, totag="gc9")
    to = [l for l in inv if l.startswith("To:")][0] + ";tag=gc9"
    s.c.send(True, crlf([f"ACK sip:mcptt-part@{PCSCF4}:5060;transport=tcp SIP/2.0",
                         f"Via: SIP/2.0/TCP {s.me}:{s.port};branch={d.branch()}", "Max-Forwards: 70",
                         f"From: <{ALICE}>;tag=gc1", to, f"Call-ID: {call}", "CSeq: 1 ACK", "Content-Length: 0"]), gap=3)

    # the console talks first
    # The Location field (TS 24.380 §8.2.4, §8.2.3.21) carries the ECGI of the location report
    # (feature 003, SC-003: one pseudonym in XML and in floor control). PLMN 260/001 in BCD.
    demo_loc = bytes([1, 0x62, 0x10, 0x00]) + struct.pack("!I", DEMO_ECI)
    d.put(15, 0, udp0(d, CON4, MEDIA4, CON_FC, SRV_FC, floor_msg(0b00000, CON_SSRC, fc_field(0, b"\x04\x00")
                                                                 + fc_field(19, demo_loc))),
          "floor request")
    d.put(44, 0, udp0(d, MEDIA4, CON4, SRV_FC, CON_FC,
                      floor_msg(0b00001, SRV_SSRC, fc_field(1, b"\x00\x1e") + fc_field(0, b"\x04\x00")
                                + fc_field(8, b"\x00\x01")), up=False))
    for i in range(60):
        d.put(20, 0, udp0(d, CON4, MEDIA4, CON_RTP, SRV_RTP, amr_wb(d, 1000 + i, 160000 + 320 * i, CON_SSRC)))
    d.put(20, 0, udp0(d, CON4, MEDIA4, CON_FC, SRV_FC, floor_msg(0b00100, CON_SSRC, fc_field(6, ALICE.encode()))),
          "floor release")
    d.put(29, 0, udp0(d, MEDIA4, CON4, SRV_FC, CON_FC, floor_msg(0b00101, SRV_SSRC, fc_field(8, b"\x00\x02")),
                      up=False))

    # the handheld takes the floor: its uplink is on the S1-U mirror, the console hears it
    d.at(1800)
    t = d.now
    d.put_abs(t, 1, s1u(d, P.udp4(v4(HH4), v4(MEDIA4), HH_FC, HSRV_FC,
                                  floor_msg(0b00000, HH_SSRC, fc_field(0, b"\x04\x00")), ident=0x2201)),
              "handheld floor request (GTP-U)")
    d.put_abs(t + 38000, 1, s1u(d, P.udp4(v4(MEDIA4), v4(HH4), HSRV_FC, HH_FC,
                                          floor_msg(0b00001, SRV_SSRC, fc_field(1, b"\x00\x1e")), ident=0x9101),
                                up=False))
    d.now = t + 40000
    d.put(1, 0, udp0(d, MEDIA4, CON4, SRV_FC, CON_FC,
                     floor_msg(0b10010, SRV_SSRC, fc_field(4, BOB.encode()) + fc_field(5, b"\x00\x01")
                               + fc_field(8, b"\x00\x03")), up=False), "floor taken by bob")
    d.put(3, 0, udp0(d, CON4, MEDIA4, CON_FC, SRV_FC, floor_msg(0b01010, CON_SSRC, fc_field(12, b"\x02\x00"))))
    for i in range(60):
        ts = d.at(20)
        d.put_abs(ts - 11000, 1, s1u(d, P.udp4(v4(HH4), v4(MEDIA4), HH_RTP, HSRV_RTP,
                                               amr_wb(d, 7000 + i, 900000 + 320 * i, HH_SSRC), ident=0x2210 + i)))
        d.frames.append((ts, 0, bytes(udp0(d, MEDIA4, CON4, SRV_RTP, CON_RTP,
                                           amr_wb(d, 7000 + i, 900000 + 320 * i, HH_SSRC), up=False)), None))
    d.put_abs(d.now + 9000, 1, s1u(d, P.udp4(v4(HH4), v4(MEDIA4), HH_FC, HSRV_FC,
                                             floor_msg(0b00100, HH_SSRC), ident=0x2280)))
    d.put(30, 0, udp0(d, MEDIA4, CON4, SRV_FC, CON_FC, floor_msg(0b00101, SRV_SSRC, fc_field(8, b"\x00\x04")),
                      up=False))

    # Feature 004 (US1): a floor request with Track Info is denied with a Reject Phrase, then the
    # console asks for its queue position. Participant Type and Reject Phrase are free text; the
    # Floor Participant Reference is an opaque server reference.
    ptype = d.sip_canary("string", "dispatch-" + d.token(6), "app:mcpt/11")
    phrase = d.sip_canary("string", "Busy " + d.token(6), "app:mcpt/2")
    ref = int.from_bytes(d.rand(4), "big") | 0x01000000
    d.canary("binary", str(ref), "app:mcpt/11")
    track = bytes([1, len(ptype)]) + ptype.encode()
    track += b"\0" * (-(len(track) - 2) % 4) + struct.pack("!I", ref)
    d.put(400, 0, udp0(d, CON4, MEDIA4, CON_FC, SRV_FC,
                       floor_msg(0b00000, CON_SSRC, fc_field(0, b"\x03\x00") + fc_field(11, track))),
          "floor request with track info")
    d.put(35, 0, udp0(d, MEDIA4, CON4, SRV_FC, CON_FC,
                      floor_msg(0b00011, SRV_SSRC, fc_field(2, b"\x00\x03" + phrase.encode())
                                + fc_field(6, ALICE.encode()) + fc_field(11, track)), up=False),
          "floor deny with a reject phrase")
    d.put(120, 0, udp0(d, CON4, MEDIA4, CON_FC, SRV_FC,
                       floor_msg(0b01000, CON_SSRC, fc_field(6, ALICE.encode()))), "queue position request")
    d.put(30, 0, udp0(d, MEDIA4, CON4, SRV_FC, CON_FC,
                      floor_msg(0b01001, SRV_SSRC, fc_field(6, ALICE.encode()) + fc_field(3, b"\xfe\x04")),
                      up=False))

    # Feature 004 (US3): RTCP on the a=rtcp ports, SR + SDES from the console (CNAME and a NAME
    # item), RR from the server, and a BYE with a reason at the end of the talk burst.
    name = d.sip_canary("string", "Console " + d.token(6), "rtcp:sdes/NAME")
    cname = d.sip_canary("string", "con-" + d.token(6) + "@ue.example.net", "rtcp:sdes/CNAME")
    reason = d.sip_canary("string", "shift end " + d.token(6), "rtcp:bye/reason")

    def sdes_item(t, v):
        return bytes([t, len(v)]) + v.encode()

    chunk = struct.pack("!I", CON_SSRC) + sdes_item(1, cname) + sdes_item(2, name) + b"\0"
    chunk += b"\0" * (-len(chunk) % 4)
    sr = struct.pack("!BBHIIIIII", 0x81, 200, 12, CON_SSRC, 0xE6C1A000, 0x10000000, 179200, 60, 2340)
    sr += struct.pack("!IIIIII", SRV_SSRC, 0, 0x00001000, 4, 0, 0)
    sdes = struct.pack("!BBH", 0x81, 202, len(chunk) // 4) + chunk
    d.put(20, 0, udp0(d, CON4, MEDIA4, CON_RTP + 1, SRV_RTP + 1, sr + sdes), "RTCP SR + SDES")
    rr = struct.pack("!BBHI", 0x81, 201, 7, SRV_SSRC) + struct.pack("!IIIIII", CON_SSRC, 0x01000002, 0x0000103B, 12, 0, 0)
    d.put(15, 0, udp0(d, MEDIA4, CON4, SRV_RTP + 1, CON_RTP + 1, rr, up=False), "RTCP RR")
    bye = struct.pack("!BBHI", 0x81, 203, 0, CON_SSRC) + bytes([len(reason)]) + reason.encode()
    bye += b"\0" * (-len(bye) % 4)
    bye = bye[:2] + struct.pack("!H", len(bye) // 4 - 1) + bye[4:]
    d.put(30, 0, udp0(d, CON4, MEDIA4, CON_RTP + 1, SRV_RTP + 1, rr[:4].replace(b"\x81\xc9", b"\x80\xc9") [:2]
                     + struct.pack("!H", 1) + struct.pack("!I", CON_SSRC) + bye), "RTCP RR + BYE")
    return call, to


# --- MCVideo (feature 004, US4): a private video call with transmission control ----------
CON_VID, CON_TC, SRV_VID, SRV_TC = 40020, 40022, 50020, 50022
CON_VSSRC, SRV_TSSRC = 0x3C3C0A01, 0x3C3C0B02
MCVIDEO_PSI = f"sip:mcvideo-part@{DOMAIN}"


def mcv_msg(name, subtype, ssrc, fields=b""):
    body = struct.pack("!I", ssrc) + name + fields
    return struct.pack("!BBH", 0x80 | subtype, 204, len(body) // 4) + body


def video_sdp(owner, ip, vid, tc, sess):
    return (f"v=0\r\no={owner} {sess} {sess} IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n"
            f"m=video {vid} RTP/AVP 100\r\na=rtpmap:100 H264/90000\r\na=rtcp:{vid + 1}\r\n"
            f"m=application {tc} udp MCVideo\r\n").encode()


def mcvideo_call(d, s):
    call = d.callid()
    _, inv = s.req("INVITE", MCVIDEO_PSI, 1, [f"Contact: <{s.contact()}>"],
                   video_sdp("alice", CON4, CON_VID, CON_TC, 3141592653), "application/sdp", tag="vc1", call=call,
                   gap=900, comment="MCVideo private call")
    s.resp(200, "OK", inv, [f"Contact: <sip:mcvideo-part@{PCSCF4}:5060;transport=tcp>"],
           video_sdp("mcvideo", MEDIA4, SRV_VID, SRV_TC, 2718281828), "application/sdp", gap=180, totag="vc9")
    F = fc_field
    d.put(40, 0, udp0(d, CON4, MEDIA4, CON_TC, SRV_TC,
                      mcv_msg(b"MCV0", 0b00000, CON_VSSRC, F(0, b"\x05\x00") + F(6, ALICE.encode()))),
          "MCVideo transmission request")
    d.put(30, 0, udp0(d, MEDIA4, CON4, SRV_TC, CON_TC,
                      mcv_msg(b"MCV1", 0b00000, SRV_TSSRC, F(1, b"\x00\x3c") + F(6, ALICE.encode())
                              + F(14, struct.pack("!IH", CON_VSSRC, 0))), up=False), "MCVideo transmission granted")
    for i in range(8):
        pkt = struct.pack("!BBHII", 0x80, 100 | (0x80 if i == 7 else 0), 300 + i, 90000 + 3000 * i, CON_VSSRC)
        d.put(33, 0, udp0(d, CON4, MEDIA4, CON_VID, SRV_VID, pkt + d.rand(120)))
    d.put(30, 0, udp0(d, CON4, MEDIA4, CON_TC, SRV_TC, mcv_msg(b"MCV0", 0b00010, CON_VSSRC, F(6, ALICE.encode()))),
          "MCVideo transmission release")
    d.put(30, 0, udp0(d, MEDIA4, CON4, SRV_TC, CON_TC, mcv_msg(b"MCV1", 0b01111, SRV_TSSRC, F(8, b"\x00\x01")),
                      up=False), "MCVideo transmission idle")
    return call


# --- MCData SDS over MSRP (feature 004, US5) ------------------------------------------------
CON_MSRP, SRV_MSRP = 2855, 2856


def mcdata_msrp(d, s):
    """A one-to-one MCData session: SDP m=message with a=path (TS 24.282 §9.2.3.2.1), the binding
    SEND, an SDS with a data payload, its 200 response and a delivery REPORT (RFC 4975)."""
    sess_a = d.sip_canary("string", "a" + d.token(12), "sdp:a=path.session-id")
    sess_b = d.sip_canary("string", "b" + d.token(12), "sdp:a=path.session-id")
    path_a = f"msrp://{CON4}:{CON_MSRP}/{sess_a};tcp"
    path_b = f"msrp://{MEDIA4}:{SRV_MSRP}/{sess_b};tcp"

    def msrp_sdp(owner, ip, port, path, sess):
        return (f"v=0\r\no={owner} {sess} {sess} IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n"
                f"m=message {port} TCP/MSRP *\r\na=accept-types:application/vnd.3gpp.mcdata-signalling "
                f"application/vnd.3gpp.mcdata-payload\r\na=path:{path}\r\na=setup:active\r\n").encode()

    call = d.callid()
    _, inv = s.req("INVITE", MCDATA_PSI, 1, [f"Contact: <{s.contact()}>"],
                   msrp_sdp("alice", CON4, CON_MSRP, path_a, 1618033988), "application/sdp", tag="md1", call=call,
                   gap=700, comment="MCData SDS session over MSRP")
    s.resp(200, "OK", inv, [f"Contact: <sip:mcdata-part@{PCSCF4}:5060;transport=tcp>"],
           msrp_sdp("mcdata", MEDIA4, SRV_MSRP, path_b, 1414213562), "application/sdp", gap=150, totag="md9")
    t = Tcp(d, CON4, MEDIA4, CON_MSRP, SRV_MSRP)
    t.open()

    def tid():
        # ident (RFC 4975 §9) has no "_": the URL-safe token's "_" becomes "x".
        return d.sip_canary("string", "t" + d.token(9).replace("_", "x"), "msrp:tid")

    paths = f"To-Path: {path_b}\r\nFrom-Path: {path_a}\r\n"
    t0 = tid()
    t.send(True, f"MSRP {t0} SEND\r\n{paths}Message-ID: {d.sip_canary('string', 'm' + d.token(9).replace('_', 'x'), 'msrp:Message-ID')}"
                 f"\r\nByte-Range: 1-0/0\r\n-------{t0}$\r\n".encode(), gap=20, comment="MSRP binding SEND")
    mid = d.sip_canary("string", "m" + d.token(9).replace("_", "x"), "msrp:Message-ID")
    text = d.sip_canary("string", "Water level rising at " + d.token(6), "msrp:content")
    body = bytes([1]) + text.encode()
    t1 = tid()
    t.send(True, (f"MSRP {t1} SEND\r\n{paths}Message-ID: {mid}\r\nByte-Range: 1-{len(body)}/{len(body)}\r\n"
                  f"Success-Report: yes\r\nContent-Type: application/vnd.3gpp.mcdata-payload\r\n\r\n").encode()
           + body + f"\r\n-------{t1}$\r\n".encode(), gap=300, comment="MSRP SEND with an SDS")
    back = f"To-Path: {path_a}\r\nFrom-Path: {path_b}\r\n"
    t.send(False, f"MSRP {t1} 200 OK\r\n{back}-------{t1}$\r\n".encode(), gap=40)
    t2 = tid()
    t.send(False, (f"MSRP {t2} REPORT\r\n{back}Message-ID: {mid}\r\nByte-Range: 1-{len(body)}/{len(body)}\r\n"
                   f"Status: 000 200 OK\r\n-------{t2}$\r\n").encode(), gap=60, comment="MSRP REPORT")
    return call


def handheld_joins(d, alice_call):
    """The controlling function invites the handheld into the group call (UDP SIP inside GTP-U)."""
    info = mcptt_info("<session-type>prearranged</session-type>\n" + uri_el("mcptt-request-uri", BOB)
                      + uri_el("mcptt-calling-user-id", ALICE) + uri_el("mcptt-calling-group-id", GROUP))
    call = d.callid()
    via = f"Via: SIP/2.0/UDP {PCSCF4}:5060;branch={d.branch()}"
    head = [via, f"From: <{GROUP}>;tag=gcf3", f"To: <{BOB}>", f"Call-ID: {call}"]
    inv = crlf([f"INVITE sip:bob.zielinski@{HH4}:5060 SIP/2.0", *head[:1], "Max-Forwards: 68", *head[1:],
                "CSeq: 1 INVITE", f"Contact: <sip:mcptt-ctrl@{PCSCF4}:5060>;+g.3gpp.mcptt;isfocus",
                f"P-Asserted-Identity: <{GROUP}>", "Answer-Mode: Auto",
                "Content-Type: multipart/mixed;boundary=mcptt-b6", "Content-Length: {LEN}"],
               multipart("mcptt-b6", [("application/sdp", sdp("mcptt", MEDIA4, HSRV_RTP, HSRV_FC, 3)),
                                      ("application/vnd.3gpp.mcptt-info+xml", info)]))
    t = d.now + 60000
    d.put_abs(t, 1, s1u(d, P.udp4(v4(PCSCF4), v4(HH4), 5060, 5060, inv, ident=0x9120), up=False),
              "handheld invited into the group call (GTP-U)")
    ok = crlf(["SIP/2.0 200 OK", *head[:2], f"To: <{BOB}>;tag=hh2", f"Call-ID: {call}", "CSeq: 1 INVITE",
               f"Contact: <sip:bob.zielinski@{HH4}:5060>;+g.3gpp.mcptt", f"User-Agent: {UA.replace('Dispatch', 'Handheld')}",
               "Content-Type: application/sdp", "Content-Length: {LEN}"],
              sdp("bob", HH4, HH_RTP, HH_FC, 4471))
    d.put_abs(t + 95000, 1, s1u(d, P.udp4(v4(HH4), v4(PCSCF4), 5060, 5060, ok, ident=0x2200)))
    ack = crlf([f"ACK sip:bob.zielinski@{HH4}:5060 SIP/2.0", f"Via: SIP/2.0/UDP {PCSCF4}:5060;branch={d.branch()}",
                "Max-Forwards: 70", f"From: <{GROUP}>;tag=gcf3", f"To: <{BOB}>;tag=hh2", f"Call-ID: {call}",
                "CSeq: 1 ACK", "Content-Length: 0"])
    d.put_abs(t + 131000, 1, s1u(d, P.udp4(v4(PCSCF4), v4(HH4), 5060, 5060, ack, ident=0x9121), up=False))


def sds_parts(d, sent_at, text, disposition=None):
    """SDS SIGNALLING PAYLOAD and DATA PAYLOAD (TS 24.282 clauses 15.1.2 and 15.1.4)."""
    sig = b"\x01" + sent_at.to_bytes(5, "big") + d.rand(16) + d.rand(16)   # type, date/time, conversation, message
    if disposition:
        sig += bytes([0x80 | disposition])                                  # SDS disposition request type
    data = text.encode()
    payload = b"\x03\x01" + b"\x78" + struct.pack("!H", 1 + len(data)) + b"\x01" + data   # one TEXT payload
    return [("application/vnd.3gpp.mcdata-signalling", sig), ("application/vnd.3gpp.mcdata-payload", payload)]


SDS_HEADERS = ["Accept-Contact: *;+g.3gpp.mcdata.sds;require;explicit",
               "Accept-Contact: *;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mcdata.sds\";require;explicit"]


def fragment6(ip_packet, max_payload, ident):
    """IPv6 fragments (RFC 8200 §4.5) of an IPv6 packet without extension headers."""
    nh, src, dst, data = ip_packet[6], ip_packet[8:24], ip_packet[24:40], ip_packet[40:]
    out = []
    for off in range(0, len(data), max_payload):
        more = off + max_payload < len(data)
        fh = struct.pack("!BBHI", nh, 0, (off // 8) << 3 | (1 if more else 0), ident)
        out.append(P.ipv6(src, dst, 44, fh + data[off:off + max_payload]))
    return out


def mcdata_sds(d, s6):
    """One-to-one SDS from the handheld to the console (TS 24.282 clause 9.2.2.2.1)."""
    sent = d.now // 1_000_000 + 3
    parts = sds_parts(d, sent, "Engine 12 at Marszalkowska 104: hydrant blocked, switching to Wilcza", disposition=1)
    rl = (f"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<resource-lists xmlns=\"urn:ietf:params:xml:ns:resource-lists\">"
          f"<list><entry uri=\"{ALICE}\"/></list></resource-lists>\n").encode()
    orig = multipart("mcdata-b1", [("application/vnd.3gpp.mcdata-info+xml",
                                    mcdata_info("<request-type>one-to-one-sds</request-type>\n")),
                                   ("application/resource-lists+xml", rl), *parts])
    term = multipart("mcdata-b1", [("application/vnd.3gpp.mcdata-info+xml", mcdata_info(
        "<request-type>one-to-one-sds</request-type>\n" + md_uri("mcdata-calling-user-id", BOB)
        + md_uri("mcdata-called-party-id", ALICE))), *parts])
    call = f"{d.token(10)}@{HH6}"
    msg = crlf([f"MESSAGE {MCDATA_PSI} SIP/2.0", f"Via: SIP/2.0/UDP [{HH6}]:5060;branch={d.branch()}",
                "Max-Forwards: 70", f"From: <{BOB}>;tag=hh71", f"To: <{MCDATA_PSI}>", f"Call-ID: {call}",
                "CSeq: 1 MESSAGE", *SDS_HEADERS, "P-Preferred-Service: urn:urn-7:3gpp-service.ims.icsi.mcdata.sds",
                f"P-Preferred-Identity: <{BOB}>", "Content-Type: multipart/mixed;boundary=mcdata-b1",
                "Content-Length: {LEN}"], orig)

    d.at(2500)
    t = d.now
    # Larger than the path MTU inside the tunnel: IPv6 fragments of at most 1232 bytes (RFC 8200
    # §5, the minimum MTU of 1280 less the IPv6 and Fragment headers).
    pkt = P.udp6(v6(HH6), v6(PCSCF6), 5060, 5060, msg)
    assert len(pkt) - 40 > 1232, "the SDS must need IPv6 fragmentation"
    for i, frag in enumerate(fragment6(pkt, 1232, 0x6D640001)):
        d.put_abs(t + 40 * i, 1, s1u(d, frag),
                  "handheld sends a one-to-one MCData SDS (IPv6 in GTP-U, fragmented)" if i == 0 else None)
    d.now = t + 48000
    lines = s6.incoming("MESSAGE", s6.contact(), BOB, ALICE, f"{d.token(10)}@mcdata", 1,
                        [*SDS_HEADERS, f"P-Asserted-Identity: <{BOB}>"], term, "multipart/mixed;boundary=mcdata-b1",
                        gap=0, comment="one-to-one SDS delivered to the console", from_tag="md71")
    s6.resp(200, "OK", lines, gap=31, up=True, totag="sd2")
    ok = crlf(["SIP/2.0 200 OK", f"Via: SIP/2.0/UDP [{HH6}]:5060;branch={d.branch()}",
               f"From: <{BOB}>;tag=hh71", f"To: <{MCDATA_PSI}>;tag=sd9", f"Call-ID: {call}", "CSeq: 1 MESSAGE",
               "Content-Length: 0"])
    d.put_abs(d.now + 47000, 1, s1u(d, P.udp6(v6(PCSCF6), v6(HH6), 5060, 5060, ok), up=False))


def group_sds(d, s6):
    """Group SDS from the console to fire-brigade-west, fanned out to the handheld (TS 24.282 9.2.2.2.1)."""
    parts = sds_parts(d, d.now // 1_000_000 + 4,
                      "All units fire-brigade-west: hydrant Marszalkowska 104 out of service, use Wilcza 21")
    info = mcdata_info("<request-type>group-sds</request-type>\n" + md_uri("mcdata-request-uri", GROUP)
                       + md_str("mcdata-client-id", MCDATA_CLIENT_ID))
    _, l = s6.req("MESSAGE", MCDATA_PSI, 1, [*SDS_HEADERS, f"P-Preferred-Identity: <{ALICE}>",
                                             "P-Preferred-Service: urn:urn-7:3gpp-service.ims.icsi.mcdata.sds"],
                  multipart("mcdata-b2", [("application/vnd.3gpp.mcdata-info+xml", info), *parts]),
                  "multipart/mixed;boundary=mcdata-b2", tag="gs1", gap=1800,
                  comment="group SDS to fire-brigade-west")
    s6.resp(200, "OK", l, gap=40)
    term = multipart("mcdata-b2", [("application/vnd.3gpp.mcdata-info+xml", mcdata_info(
        "<request-type>group-sds</request-type>\n" + md_uri("mcdata-calling-user-id", ALICE)
        + md_uri("mcdata-calling-group-id", GROUP))), *parts])
    call = f"{d.token(10)}@mcdata"
    msg = crlf([f"MESSAGE sip:bob.zielinski@[{HH6}]:5060 SIP/2.0",
                f"Via: SIP/2.0/UDP [{PCSCF6}]:5060;branch={d.branch()}", "Max-Forwards: 66",
                f"From: <{GROUP}>;tag=gs7", f"To: <{BOB}>", f"Call-ID: {call}", "CSeq: 1 MESSAGE", *SDS_HEADERS,
                f"P-Asserted-Identity: <{ALICE}>", "Content-Type: multipart/mixed;boundary=mcdata-b2",
                "Content-Length: {LEN}"], term)
    t = d.now + 20000
    d.put_abs(t, 1, s1u(d, P.udp6(v6(PCSCF6), v6(HH6), 5060, 5060, msg), up=False),
              "group SDS fanned out to the handheld (GTP-U)")
    ok = crlf(["SIP/2.0 200 OK", f"Via: SIP/2.0/UDP [{PCSCF6}]:5060;branch={d.branch()}",
               f"From: <{GROUP}>;tag=gs7", f"To: <{BOB}>;tag=hh9", f"Call-ID: {call}", "CSeq: 1 MESSAGE",
               "Content-Length: 0"])
    d.put_abs(t + 88000, 1, s1u(d, P.udp6(v6(HH6), v6(PCSCF6), 5060, 5060, ok)))


# Feature 005: MIKEY-SAKKE in the demo, drawn from its own generator so that the rest of the demo
# keeps its values.
MIKEY_RNG = random.Random(5005)
WITH_MIKEY = [True]  # --no-mikey: the demo without key management (the SC-007 baseline of feature 005)


MIKEY_KEYS = {}  # the key identifiers the demo's media plane refers to


def mikey_key(tag):
    import mikey as M
    k = M.key_id(tag, MIKEY_RNG.getrandbits(28) | 0x0100000)
    SDP_CANARIES.append(("binary", str(k), "mikey:hdr/csb-id"))
    return k


def mikey_message(csb, initiator, responder, seed, blocks=None, extensions=()):
    """A MIKEY-SAKKE I_MESSAGE (TS 33.180 §E.1.2) with its RAND and signature as canaries."""
    import mikey as M
    rand = bytes(MIKEY_RNG.randrange(0x80, 0xFF) for _ in range(16))
    sig = bytes(MIKEY_RNG.randrange(0x80, 0xFF) for _ in range(129))
    SDP_CANARIES.append(("bytes", rand.hex(), "mikey:rand"))
    SDP_CANARIES.append(("bytes", sig.hex(), "mikey:sign"))
    kms_uri = f"kms.{DOMAIN}"
    ids = [(M.IDRI, M.URI, initiator.encode()), (M.IDRR, M.URI, responder.encode()),
           (M.IDRKMSI, M.URI, kms_uri.encode()), (M.IDRKMSR, M.URI, kms_uri.encode())]
    return M.i_message(csb, 0xE9A1B2C380000000, rand, ids, M.filler(273, seed), sig, blocks=blocks,
                       extensions=extensions)


def mikey_pck(initiator, responder):
    """A PCK I_MESSAGE (TS 33.180 §E.3.1); its PCK-ID is the MKI of the private call."""
    import mikey as M
    MIKEY_KEYS["pck"] = mikey_key(M.PCK)
    return mikey_message(MIKEY_KEYS["pck"], initiator, responder, 77)


def mikey_csk(initiator, responder):
    """A CSK upload or download (TS 33.180 §E.4.1, §9.2.1)."""
    import mikey as M
    return mikey_message(mikey_key(M.CSK), initiator, responder, 78)


GMS_PSI = f"sip:gms@{DOMAIN}"
GMS_XCAP = f"http://gms.{DOMAIN}/xcap-root/org.3gpp.MCPTT-GKTP/"  # the GMS identity (TS 24.481 §7.4.2)


def key_distribution(d, s):
    """Feature 005: key management outside the call set-up (spec US3). A CSK download (TS 24.379
    §7.3.7, base64 with Content-Transfer-Encoding), the subscription to the group's GKTPs with the
    CSK upload (TS 24.481 §6.3.13.2.1) and the NOTIFY that carries a GMK and an MKFC (TS 24.481 Table
    A.2.3-11), an MBMS bearer announcement whose general purpose subchannel carries an MSCCK
    (TS 24.379 §14.2.2.2), and the pre-established session Connect with its PCK I_MESSAGE field
    (TS 24.380 §8.3.3.10)."""
    import mikey as M
    call = d.callid()
    dl = mikey_csk(PSI, ALICE)
    b64 = base64.b64encode(dl).decode()
    n = s.incoming("MESSAGE", s.contact(), PSI, ALICE, call, 1,
                   ["Content-Transfer-Encoding: base64", "P-Asserted-Service: urn:urn-7:3gpp-service.ims.icsi.mcptt"],
                   ("\r\n".join(b64[i:i + 76] for i in range(0, len(b64), 76)) + "\r\n").encode(),
                   "application/mikey", gap=900, comment="CSK download (TS 24.379 §7.3.7)")
    s.resp(200, "OK", n, gap=4, up=True)
    rl = (f"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<resource-lists xmlns=\"urn:ietf:params:xml:ns:resource-lists\">"
          f"<list><entry uri=\"org.3gpp.MCPTT-GKTP/global/byGroupID/{GROUP}/~~/group/list-service/mgktp:GKTPs?"
          "xmlns(mgktp=urn:3gpp:ns:mcpttGKTP:1.0)\"/></list></resource-lists>\n").encode()
    call = d.callid()
    _, l = s.req("SUBSCRIBE", GMS_PSI, 1, ["Event: xcap-diff;diff-processing=no-patching", "Expires: 7200",
                                           "Accept: application/xcap-diff+xml", f"Contact: <{s.contact()}>",
                                           f"P-Preferred-Identity: <{ALICE}>"],
                 multipart("mcptt-b8", [("application/resource-lists+xml", rl),
                                        ("application/mikey", mikey_csk(ALICE, GMS_PSI))]),
                 "multipart/mixed;boundary=mcptt-b8", call=call, tag="gk1", gap=40,
                 comment="group management: subscribe to the group's GKTPs with the CSK (TS 24.481 §6.3.13.2.1)")
    s.resp(200, "OK", l, ["Expires: 7200"], gap=38, totag="gms7")
    guk = mikey_key(M.GMK)
    gmk = mikey_key(M.GMK)
    MIKEY_KEYS.update(gmk=gmk, guk=guk)
    iv = bytes(MIKEY_RNG.randrange(0x80, 0xFF) for _ in range(16))
    SDP_CANARIES.append(("bytes", iv.hex(), "mikey:rand"))
    kp = M.key_parameters(guk, iv, M.filler(48, 79), date_time=(1792000000).to_bytes(5, "big"))
    gmk_msg = mikey_message(guk, GMS_XCAP, ALICE, 80, blocks=[M.generic_id_block(4, spi=struct.pack("!II", gmk, guk))],
                            extensions=[(M.EXT_KEY_PARAMETERS, kp)])
    mkfc = mikey_message(mikey_key(M.MKFC), GMS_XCAP, ALICE, 81)
    diff = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<d:xcap-diff xmlns:d=\"urn:ietf:params:xml:ns:xcap-diff\" "
            f"xcap-root=\"http://gms.{DOMAIN}/xcap-root\">\n<d:element sel=\"org.3gpp.MCPTT-GKTP/global/byGroupID/"
            f"{GROUP}/~~/group/list-service/mgktp:GKTPs?xmlns(mgktp=urn:3gpp:ns:mcpttGKTP:1.0)\">\n"
            "<mgktp:GKTPs xmlns:mgktp=\"urn:3gpp:ns:mcpttGKTP:1.0\">\n<mgktp:GMK-GKTPs>\n"
            f"<mgktp:GKTP id=\"gmk-1\" activationtime=\"2026-10-14T08:00:00Z\">{gmk_msg.hex()}</mgktp:GKTP>\n"
            f"</mgktp:GMK-GKTPs>\n<mgktp:MKFC-GKTPs>\n<mgktp:GKTP id=\"mkfc-1\">{mkfc.hex().upper()}</mgktp:GKTP>\n"
            "</mgktp:MKFC-GKTPs>\n</mgktp:GKTPs>\n</d:element>\n</d:xcap-diff>\n").encode()
    n = s.incoming("NOTIFY", s.contact(), GMS_PSI, ALICE, call, 1,
                   ["Event: xcap-diff", "Subscription-State: active;expires=7200"], diff,
                   "application/xcap-diff+xml", gap=7, comment="the GKTPs of fire-brigade-west (GMK and MKFC)")
    s.resp(200, "OK", n, gap=3, up=True)
    mscck = mikey_message(mikey_key(M.MSCCK), PSI, ALICE, 82)
    ann = (f"v=0\r\no=mcptt 9 9 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\n"
           f"m=audio 9 RTP/SAVP 97\r\na=rtpmap:97 AMR-WB/16000\r\na=rtcp-mux\r\na=rtcp:9\r\n"
           f"m=application 41000 udp MCPTT\r\nc=IN IP4 239.12.1.7/16\r\n"
           f"a=key-mgmt:mikey {base64.b64encode(mscck).decode()}\r\n").encode()
    n = s.incoming("MESSAGE", s.contact(), PSI, ALICE, d.callid(), 1,
                   ["Accept-Contact: *;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mcptt\";require;explicit",
                    "P-Asserted-Service: urn:urn-7:3gpp-service.ims.icsi.mcptt", "Content-Disposition: render"],
                   ann, "application/sdp", gap=300, comment="MBMS bearer announcement with an MSCCK (TS 24.379 §14.2.2.2)")
    s.resp(200, "OK", n, gap=4, up=True)
    # Pre-established session call control (TS 24.380 §8.3.3): the Connect on the session's floor
    # control port carries the PCK I_MESSAGE "as received in the SIP INVITE" (§8.3.3.10).
    connect = mikey_message(mikey_key(M.PCK), CHIEF, ALICE, 83)
    fields = (fc_field(1, bytes([3]) + GROUP2.encode()) + fc_field(5, CHIEF.encode())
              + bytes([192]) + struct.pack("!H", len(connect)) + connect + b"\0" * (-(3 + len(connect)) % 4))
    body = struct.pack("!I", SRV_SSRC) + b"MCPC" + fields
    d.put(500, 0, udp0(d, MEDIA4, CON4, SRV_FC + 20, CON_FC + 20,
                       struct.pack("!BBH", 0x80 | 0b10000, 204, len(body) // 4) + body, up=False),
          "pre-established session Connect with the PCK I_MESSAGE field")


def private_call(d, s):
    info = mcptt_info("<session-type>private</session-type>\n" + uri_el("mcptt-request-uri", ALICE)
                      + uri_el("mcptt-calling-user-id", CHIEF))
    call = d.callid()
    inv = s.incoming("INVITE", s.contact(), CHIEF, ALICE, call, 1,
                     [f"Contact: <sip:mcptt-part@{PCSCF4}:5060;transport=tcp>;+g.3gpp.mcptt",
                      f"P-Asserted-Identity: <{CHIEF}>", "Answer-Mode: Auto",
                      "Accept-Contact: *;+g.3gpp.mcptt;require;explicit"],
                     signed_multipart("mcptt-b5", [("application/sdp", sdp("mcptt", MEDIA4, SRV_RTP + 10, SRV_FC + 10, 7,
                                                                                key_mgmt=mikey_pck(CHIEF, ALICE) if WITH_MIKEY[0] else None,
                                                                                proto="RTP/SAVP" if WITH_MIKEY[0] else "RTP/AVP"),
                                                    "pc-sdp@mcx.example.net"),
                                                   ("application/vnd.3gpp.mcptt-info+xml", info,
                                                    "pc-info@mcx.example.net")], d),
                     "multipart/mixed;boundary=mcptt-b5", gap=3000, comment="incoming private call from the chief",
                     from_tag="ch1")
    s.resp(200, "OK", inv, [f"Contact: <{s.contact()}>;+g.3gpp.mcptt"],
           sdp("alice", CON4, CON_RTP + 10, CON_FC + 10, 2890844601, sep=":",
               proto="RTP/SAVP" if WITH_MIKEY[0] else "RTP/AVP"), "application/sdp",
           gap=12, up=True, totag="pc1")
    s.incoming("ACK", s.contact(), CHIEF, ALICE, call, 1, [], gap=40,
               from_tag="ch1", to_tag="pc1")
    d.put(10, 0, udp0(d, MEDIA4, CON4, SRV_FC + 10, CON_FC + 10,
                      floor_msg(0b10010, SRV_SSRC, fc_field(4, CHIEF.encode()) + fc_field(8, b"\x00\x01")), up=False))
    d.put(2, 0, udp0(d, CON4, MEDIA4, CON_FC + 10, SRV_FC + 10, floor_msg(0b01010, CON_SSRC, fc_field(12, b"\x02\x00"))))
    # Feature 005: SRTP with the PCK-ID as MKI and the AEAD tag inside the ciphertext (TS 33.180
    # §7.4.1, §E.3.2); one SRTCP report with E+index and the MKI (RFC 3711 §3.4).
    mki = struct.pack("!I", MIKEY_KEYS["pck"]) if WITH_MIKEY[0] else b""
    for i in range(30):
        d.put(20, 0, udp0(d, MEDIA4, CON4, SRV_RTP + 10, CON_RTP + 10,
                          amr_wb(d, 300 + i, 48000 + 320 * i, 0x3C3C0007) + mki, up=False))
    srtcp = struct.pack("!BBHI", 0x80, 200, 6, 0x3C3C0007) + bytes(d.rng.randrange(256) for _ in range(20))
    if WITH_MIKEY[0]:
        d.put(5, 0, udp0(d, MEDIA4, CON4, SRV_RTP + 11, CON_RTP + 11, srtcp + struct.pack("!I", 0x80000001) + mki,
                         up=False))
    bye = s.incoming("BYE", s.contact(), CHIEF, ALICE, call, 2, [], gap=600,
                     from_tag="ch1", to_tag="pc1")
    s.resp(200, "OK", bye, gap=4, up=True)


def hvalue(v):
    """RFC 3261 §25.1 hvalue escaping of a URI header value (unreserved characters kept)."""
    return "".join(ch if ch.isalnum() or ch in "-_.!~*'()" else "%%%02X" % b for b, ch in ((b, chr(b)) for b in v))


def preestablished_refer(d, s):
    """Feature 003 (R18, US2 scenario 2): a REFER for a pre-established session (TS 24.379
    §11.1.1.2.2.1). The resource-lists entry URI carries the SDP offer and the mcptt-info body in
    the hname "body", with their type in the Content-Type URI header."""
    info = mcptt_info("<session-type>prearranged</session-type>\n" + uri_el("mcptt-request-uri", GROUP2)
                      + uri_el("mcptt-calling-user-id", ALICE))
    offer = sdp("alice", CON4, CON_RTP + 20, CON_FC + 20, 2890844777)
    inner = multipart("mcptt-e1", [("application/sdp", offer), ("application/vnd.3gpp.mcptt-info+xml", info)])
    entry = (GROUP2 + "?Content-Type=" + hvalue(b"multipart/mixed;boundary=mcptt-e1") + "&amp;body=" + hvalue(inner))
    rl = (f"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<resource-lists xmlns=\"urn:ietf:params:xml:ns:resource-lists\">"
          f"<list><entry uri=\"{entry}\"/></list></resource-lists>\n").encode()
    _, ref = s.req("REFER", PSI, 1, [f"Contact: <{s.contact()}>;+g.3gpp.mcptt",
                                     "Refer-To: <cid:prearranged-list@mcx.example.net>", "Refer-Sub: false",
                                     "Require: multiple-refer", f"P-Preferred-Identity: <{ALICE}>"],
                   multipart("mcptt-b7", [("application/resource-lists+xml", rl)]),
                   "multipart/mixed;boundary=mcptt-b7", tag="pe1", gap=1500,
                   comment="pre-established session: REFER with embedded SDP and mcptt-info")
    s.resp(202, "Accepted", ref, gap=25)


def wrap_up(d, s, s6, call, to):
    _, bye = s.req("BYE", f"sip:mcptt-part@{PCSCF4}:5060;transport=tcp", 2, [], to_hdr=to,
                   tag="gc1", call=call, gap=2000, comment="group call released")
    s.resp(200, "OK", bye, gap=36)
    late = P.udp4(v4(MEDIA4), v4(CON4), SRV_RTP, CON_RTP, amr_wb(d, 7060, 919200, HH_SSRC))
    d.put(12, 0, eth0(d, late, up=False))
    d.put(0.2, 0, eth0(d, P.ipv4(v4(CON4), v4(MEDIA4), 1, P.icmp(3, 3, b"\0\0\0\0", late[:28 + 12]))),
          "late media after release: ICMP port unreachable quotes it")
    _, l = s.req("REGISTER", f"sip:{DOMAIN}", 3, [f"Contact: <{s.contact()}>;expires=0",
                                                  "Expires: 0"], to=ALICE, gap=5000, comment="de-registration")
    s.resp(200, "OK", l, gap=51)
    _, l = s6.req("REGISTER", f"sip:{DOMAIN}", 3, [f"Contact: <{s6.contact()}>;expires=0", "Expires: 0"],
                  to=ALICE, gap=20)
    s6.resp(200, "OK", l, gap=48)
    s.c.close()
    s6.c.close()


def build(seed=2026):
    global ACCESS_TOKEN, REFRESH_TOKEN, ID_TOKEN
    d = Demo(seed)
    now = 1792000000
    ACCESS_TOKEN = jwt(d, {"iss": f"http://idms.{DOMAIN}:8080", "sub": "alice.nowak", "client_id": "mcptt_client",
                           "mcptt_id": ALICE, "exp": now + 3600,
                           "scope": ["openid", "3gpp:mc:ptt_service", "3gpp:mc:data_service"]})
    REFRESH_TOKEN = d.token(40)
    ID_TOKEN = jwt(d, {"iss": f"http://idms.{DOMAIN}:8080", "sub": "alice.nowak", "aud": "mcptt_client",
                       "name": "Alice Nowak", "email": "alice.nowak@wn.fire.example.net", "exp": now + 3600})

    bring_up(d)
    oidc(d)
    client_random = kms(d)
    kms_h2c(d)
    s = Sip(d)
    s.c.open(rtt=3.0)
    register(d, s, MCPTT_FEATURES, "MCPTT client registration")
    reg_notify(d, s)
    service_authorisation(d, s)
    config_subscription(d, s)
    cms_documents(d)
    gms_documents(d)
    gms_https(d)
    affiliate(d, s, "mcptt", (GROUP, GROUP2), "MCPTT affiliation to two groups")
    s6 = Sip(d, v6=True, port=5064)
    s6.c.open(rtt=3.1)
    mcdata_service_authorisation(d, s6)
    affiliate(d, s6, "mcdata", (GROUP,), "MCData affiliation to fire-brigade-west")
    location_config(d, s)
    location_report(d, s)

    # GTP-U path management on the S1-U mirror
    t = d.now
    echo_req = struct.pack("!BBHIHBB", 0x32, 1, 4, 0, 0x0102, 0, 0)            # S flag, sequence number
    echo_rsp = struct.pack("!BBHIHBB", 0x32, 2, 6, 0, 0x0102, 0, 0) + b"\x0e\x00"   # Recovery IE
    d.put_abs(t - 4000_000, 1, P.ethernet(mac(SGW_MAC), mac(ENB_MAC), 0x0800,
                                          P.udp4(v4(ENB4), v4(SGW4), 2152, 2152, echo_req)), "S1-U mirror: GTP-U echo")
    d.put_abs(t - 3999_400, 1, P.ethernet(mac(ENB_MAC), mac(SGW_MAC), 0x0800,
                                          P.udp4(v4(SGW4), v4(ENB4), 2152, 2152, echo_rsp)))
    call, to = group_call(d, s)
    mcvideo_call(d, s)
    mcdata_msrp(d, s)
    mcdata_sds(d, s6)
    group_sds(d, s6)
    private_call(d, s)
    preestablished_refer(d, s)
    if WITH_MIKEY[0]:
        key_distribution(d, s)
    wrap_up(d, s, s6, call, to)

    for v, f in ((CON_MAC, "eth.console"), (GW_MAC, "eth.gateway"), (ENB_MAC, "eth.enb"), (SGW_MAC, "eth.sgw")):
        d.canary("mac", v, f)
    for v, f in ((CON4, "ipv4.console"), (GW4, "ipv4.gateway"), (DNS4, "ipv4.dns"), (PCSCF4, "ipv4.pcscf"),
                 (MEDIA4, "ipv4.mcptt-media"), (IDMS4, "ipv4.idms"), (CMS4, "ipv4.cms"), (GMS4, "ipv4.gms"),
                 (KMS4, "ipv4.kms"), (ENB4, "ipv4.enb"), (SGW4, "ipv4.sgw"), (HH4, "ipv4.handheld")):
        d.canary("ipv4", v, f)
    for v, f in ((CON6, "ipv6.console"), (CON_LL, "ipv6.console-ll"), (GW_LL, "ipv6.gateway-ll"),
                 (PCSCF6, "ipv6.pcscf"), (HH6, "ipv6.handheld")):
        d.canary("ipv6", v, f)
    for v, f in ((ALICE, "sip.alice"), (BOB, "sip.bob"), (CHIEF, "sip.chief"), (GROUP, "sip.group"),
                 (GROUP2, "sip.group2"), (IMPI, "ims.impi"), (IMEI, "ue.imei"), ("2600100A1B2C3D4", "ims.cell-id"),
                 (CLIENT_ID, "mcptt.client-id"), (MCDATA_CLIENT_ID, "mcdata.client-id"), (HOSTNAME, "dhcp.hostname"), (PASSWORD, "oidc.password"),
                 (ACCESS_TOKEN, "oidc.access-token"), (REFRESH_TOKEN, "oidc.refresh-token"), (ID_TOKEN, "oidc.id-token"),
                 ("+48601234567", "ims.tel"), ("Alice Nowak", "display-name"), ("Marszalkowska", "sds.text"),
                 (f"kms.{DOMAIN}", "tls.sni"), (DOMAIN, "domain"), (LAN_DOMAIN, "dhcp.domain"),
                 ("Kowalski", "pcapng.shb.comment"), ("EXB-7HX2Q93", "pcapng.shb.hardware"),
                 ("sw-wn-03", "pcapng.idb.description"), ("WN-0412", "pcapng.idb1.description"),
                 ("Warsaw North", "pcapng.shb.comment"), (f"gms.{DOMAIN}", "tls.gms-name"),
                 (GMS_ORG, "x509.organizationName"), (GMS_CA, "x509.commonName"), (PKI_ADMIN, "x509.rfc822Name")):
        d.canary("string", v, f)
    # SIP and SDP identities (feature 002): IMEI digits (TAC, SNR), the cell identity, and the
    # SDP owners and session ids.
    d.sip_canary("number", "35209900", "tag:+sip.instance")
    d.sip_canary("number", "176148", "tag:+sip.instance")
    for cat, v, rule in SDP_CANARIES:
        d.sip_canary(cat, v, rule)
    return d, client_random


def write(d, client_random, out):
    w = pcapng.Writer()
    blocks = [w.shb([(1, "MCX acceptance test WN-2026-10, Warsaw North fire station, captured by J. Kowalski"),
                     (2, "ExampleBook 14 (SN EXB-7HX2Q93)"), (3, "Linux 6.8.0-45-generic"), (4, "dumpcap 4.2.2")])]
    blocks.append(w.idb(1, 262144, [
        (2, "enp0s31f6"), (3, "Dispatcher console DISPATCH-WN-03, switch sw-wn-03 port 17"),
        (4, v4(CON4) + v4("255.255.0.0")), (5, v6(CON6) + b"\x40"), (6, mac(CON_MAC)), (9, b"\x06"),
        (11, b"\x00host 10.45.12.34 or net fd12:3456:789a:1::/64 or port 2152"), (12, "Linux 6.8.0-45-generic")]))
    blocks.append(w.idb(1, 262144, [(2, "ens2f1"), (3, "S1-U mirror at eNodeB WN-0412, cell 2600100A1B2C3D4"),
                                    (9, b"\x06"), (11, b"\x00udp port 2152")]))
    recs = []
    for ip, n in ((PCSCF4, f"pcscf.{DOMAIN}"), (IDMS4, f"idms.{DOMAIN}"), (KMS4, f"kms.{DOMAIN}"),
                  (CMS4, f"cms.{DOMAIN}"), (GMS4, f"gms.{DOMAIN}"), (CON4, f"dispatch-wn-03.{LAN_DOMAIN}")):
        recs.append((1, v4(ip) + n.encode() + b"\0"))
    recs.append((2, v6(PCSCF6) + f"pcscf.{DOMAIN}".encode() + b"\0"))
    blocks.append(w.nrb(recs, [(1, "names resolved by dumpcap")]))
    keylog = (f"CLIENT_HANDSHAKE_TRAFFIC_SECRET {client_random.hex()} {d.rand(32).hex()}\n"
              f"SERVER_HANDSHAKE_TRAFFIC_SECRET {client_random.hex()} {d.rand(32).hex()}\n"
              f"CLIENT_TRAFFIC_SECRET_0 {client_random.hex()} {d.rand(32).hex()}\n"
              f"SERVER_TRAFFIC_SECRET_0 {client_random.hex()} {d.rand(32).hex()}\n").encode()
    blocks.append(w.dsb(0x544C534B, keylog))
    frames = sorted(d.frames, key=lambda f: f[0])
    for ts, iface, frame, comment in frames:
        blocks.append(w.epb(iface, ts, frame, [(1, comment)] if comment else []))
    end = frames[-1][0] + 500
    for iface in (0, 1):
        n = sum(1 for f in frames if f[1] == iface)
        blocks.append(w.isb(iface, end, [(1, "capture stopped by J. Kowalski"),
                                         (2, struct.pack("<II", d.t0 >> 32, d.t0 & 0xFFFFFFFF)),
                                         (3, struct.pack("<II", end >> 32, end & 0xFFFFFFFF)),
                                         (4, struct.pack("<Q", n)), (5, struct.pack("<Q", 0))]))
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, NAME), "wb") as f:
        f.write(b"".join(blocks))
    with open(os.path.join(out, "mcx_demo.canaries.json"), "w", encoding="utf-8") as f:
        json.dump({"canaries": d.canaries}, f, indent=1)
    with open(os.path.join(out, "mcx_demo.deny.txt"), "w", encoding="utf-8") as f:
        f.write("# words that must never appear in a published capture of this case\n")
        for w_ in ("alice.nowak", "bob.zielinski", "chief.kowalczyk", "fire-brigade-west", "Kowalski",
                   "Marszalkowska", "260011234567890", "DISPATCH-WN-03", CLIENT_ID.split(":")[-1],
                   MCDATA_CLIENT_ID.split(":")[-1]):
            f.write(w_ + "\n")
    return len(frames)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", required=True)
    ap.add_argument("--seed", type=int, default=2026)
    ap.add_argument("--no-mikey", action="store_true", help="without key management (feature 005 perf baseline)")
    a = ap.parse_args()
    WITH_MIKEY[0] = not a.no_mikey
    d, cr = build(a.seed)
    n = write(d, cr, a.out)
    print(f"{os.path.join(a.out, NAME)}: {n} packets, {len(d.canaries)} canaries")


if __name__ == "__main__":
    main()

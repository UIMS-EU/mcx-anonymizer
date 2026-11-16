# SPDX-License-Identifier: GPL-3.0-or-later
"""MIKEY-SAKKE I_MESSAGE builder for the synthetic fixtures of feature 005.

Pure functions that build the payloads of RFC 3830 §6, RFC 6043 §6 and RFC 6509 §4 as profiled by
3GPP TS 33.180 Annex E, plus the MIKEY-SAKKE UID of TS 33.180 §F.2.1.1. No cryptography is
performed: the SAKKE encapsulated data, the ECCSI signature and the ciphertexts are bytes of the
right lengths (canary-filled by the fixture sets). The fixture sets themselves are added per user
story; `gen` writes those that exist.
"""

import base64
import hashlib
import json
import struct

# Next-payload values (RFC 3830 Table 6.1.b; RFC 6043; RFC 6509 Table 2).
LAST, KEMAC, PKE, DH, SIGN, T, ID, CERT, CHASH, V, SP, RAND, ERR = 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12
IDR, KEYDATA, GENEXT, SAKKE = 14, 20, 21, 26

# ID roles (RFC 6043 Table 6.11; RFC 6509 Table 7; TS 33.180 §E.7; TS 24.481 §7.5.2).
IDRI, IDRR, IDRKMS, IDRPSK, IDRAPP, IDRKMSI, IDRKMSR, IDRUIDI, IDRUIDR = 1, 2, 3, 4, 5, 6, 7, 8, 9
IDRUIDR_PRIVATE, IDRUIDI_PRIVATE = 240, 241
# ID types (RFC 3830 Table 6.7.a; RFC 6043 Table 6.10).
NAI, URI, BYTES = 0, 1, 2

# General extension types (TS 33.180 §E.5, §E.6.1).
EXT_SAKKE_TO_SELF, EXT_KEY_PARAMETERS = 6, 7

# Purpose tags (TS 33.180 Table G-1).
GMK, PCK, CSK, SPK, MKFC, MSCCK, MUSIK = 0, 1, 2, 3, 4, 5, 6


def key_id(tag, low28):
    """A 32-bit key identifier with the purpose tag in the 4 most significant bits."""
    return ((tag & 0xF) << 28) | (low28 & 0x0FFFFFFF)


def generic_id_block(cs_id, prot_type=0, policies=(0,), session=(), spi=b"", s_flag=0):
    """One GENERIC-ID crypto session block (RFC 6043 §6.1.1). `session` holds (ssrc, roc) pairs."""
    data = b"".join(struct.pack("!II", ssrc, roc) for ssrc, roc in session)
    return (bytes([cs_id, prot_type, ((s_flag & 1) << 7) | (len(policies) & 0x7F)]) + bytes(policies) +
            struct.pack("!H", len(data)) + data + bytes([len(spi)]) + spi)


def hdr(nxt, csb_id, blocks=None, prf=1, v=0, data_type=26, version=1):
    """Common header (RFC 3830 §6.1). Without blocks: #CS 0 and the empty map (type 1)."""
    head = bytes([version, data_type, nxt, ((v & 1) << 7) | (prf & 0x7F)]) + struct.pack("!I", csb_id)
    if not blocks:
        return head + bytes([0, 1])
    return head + bytes([len(blocks), 2]) + b"".join(blocks)


def t(nxt, value, ts_type=0):
    """Timestamp payload (RFC 3830 §6.6): NTP-UTC and NTP are 64 bits, COUNTER 32 bits."""
    body = struct.pack("!Q", value) if ts_type in (0, 1) else struct.pack("!I", value)
    return bytes([nxt, ts_type]) + body


def rand(nxt, r):
    return bytes([nxt, len(r)]) + r


def idr(nxt, role, id_type, data):
    """ID payload with role indicator (RFC 6043 §6.6)."""
    return bytes([nxt, role, id_type]) + struct.pack("!H", len(data)) + data


def sp(nxt, policy_no, prot_type, params):
    """Security policy payload (RFC 3830 §6.10); params are (type, value bytes)."""
    body = b"".join(bytes([typ, len(val)]) + val for typ, val in params)
    return bytes([nxt, policy_no, prot_type]) + struct.pack("!H", len(body)) + body


def sakke(nxt, data, params=1, id_scheme=2):
    """SAKKE payload (RFC 6509 §4.2)."""
    return bytes([nxt, params, id_scheme]) + struct.pack("!H", len(data)) + data


def ext(nxt, typ, data):
    """General extension payload (RFC 3830 §6.15)."""
    return bytes([nxt, typ]) + struct.pack("!H", len(data)) + data


def sakke_to_self(nxt, data, params=1, id_scheme=2):
    """SAKKE-to-self (TS 33.180 §E.5): a full SAKKE payload whose own next payload is zero."""
    return ext(nxt, EXT_SAKKE_TO_SELF, sakke(0, data, params, id_scheme))


def key_parameters(dppk_id, iv, ciphertext, date_time=b"\x00" * 5, message_type=1, payload_id=0,
                   payload_seq=0, payload_alg=1, signalling_alg=None, iei=0x78):
    """The data of the '3GPP key parameters' extension: a protected payload (TS 33.180 Table 8.5.4.1-1)."""
    head = bytes([message_type]) + date_time + struct.pack("!I", payload_id) + bytes([payload_seq, payload_alg])
    if signalling_alg is not None:
        head += bytes([signalling_alg])
    return head + iv + struct.pack("!I", dppk_id) + bytes([iei]) + struct.pack("!H", len(ciphertext)) + ciphertext


def sign(signature, s_type=2):
    """Signature payload (RFC 3830 §6.5): 4-bit S type and 12-bit length, then the signature."""
    return struct.pack("!H", ((s_type & 0xF) << 12) | (len(signature) & 0x0FFF)) + signature


def i_message(csb_id, ntp, rand_bytes, identities, sakke_data, signature, blocks=None, extensions=(),
              sp_payloads=(), prf=1):
    """A complete MIKEY-SAKKE I_MESSAGE (TS 33.180 §E.1.2) with the next-payload chain filled in.

    identities: [(role, id_type, data bytes)]; extensions: [(type, data bytes)];
    sp_payloads: [(policy_no, prot_type, params)].
    """
    parts = [(T, lambda n: t(n, ntp)), (RAND, lambda n: rand(n, rand_bytes))]
    for role, id_type, data in identities:
        parts.append((IDR, lambda n, r=role, it=id_type, d=data: idr(n, r, it, d)))
    for pol, prot, params in sp_payloads:
        parts.append((SP, lambda n, a=pol, b=prot, c=params: sp(n, a, b, c)))
    for typ, data in extensions:
        parts.append((GENEXT, lambda n, ty=typ, d=data: ext(n, ty, d)))
    parts.append((SAKKE, lambda n: sakke(n, sakke_data)))
    out = hdr(parts[0][0], csb_id, blocks, prf=prf)
    for i, (_, build) in enumerate(parts):
        nxt = parts[i + 1][0] if i + 1 < len(parts) else SIGN
        out += build(nxt)
    return out + sign(signature)


def _int_octets(v):
    """A non-negative integer in the fewest big-endian octets (TS 33.220 Annex B.2; 0 is one octet)."""
    n = max(1, (v.bit_length() + 7) // 8)
    return v.to_bytes(n, "big")


def uid(identifier, kms, period, offset, number):
    """The 32-octet MIKEY-SAKKE UID (TS 33.180 §F.2.1.1). `number` is P5, the key period number."""
    s = b"\x00"
    for p in (b"MIKEY-SAKKE-UID", identifier.encode() if isinstance(identifier, str) else identifier,
              kms.encode() if isinstance(kms, str) else kms, _int_octets(period), _int_octets(offset),
              _int_octets(number)):
        s += p + struct.pack("!H", len(p))
    return hashlib.sha256(s).digest()


def period_number(ntp_seconds, period, offset):
    """P5 = floor((TIME - P4) / P3) (TS 33.180 §F.2.1.1)."""
    return (ntp_seconds - offset) // period


def _self_check():
    """The worked example of TS 33.180 §F.2.1.2."""
    got = base64.b64encode(uid("sip:user@example.org", "kms.example.org", 2592000, 0, 1388)).decode()
    assert got == "OoH7FMOx0P5DycV3EE1VptgXiL/S8JdDxFV3RqWgNTs=", got
    assert period_number(3599719634, 2592000, 0) == 1388


_self_check()


def gen(c, out):
    """Writes the 005 fixture sets that exist so far."""
    for fn in SETS:
        fn(c, out)


# --- fixture helpers --------------------------------------------------------------
class Plant:
    """Canaries for one fixture file, with the MIKEY rule keys of tests/mikey_rule_keys_main.cpp."""

    def __init__(self, c, fname):
        self.c = c
        self.fname = fname

    def user(self, role):
        """A SIP URI whose user part is a canary (IDRi/IDRr and the SIP headers share it)."""
        return "sip:" + self.c.string(None, self.fname, prefix="mkuser", rule=f"mikey:idr/{role}") + "@mcx.example.org"

    def kms(self):
        return self.c.string(None, self.fname, prefix="mkkms", rule="mikey:idr/kms") + ".kms.example.org"

    def key_id(self, tag):
        """A key identifier with a purpose tag, recorded as a 32-bit binary canary."""
        while True:
            v = key_id(tag, self.c.rng.getrandbits(28))
            if v >= 0x10000 and str(v) not in self.c._used:
                self.c._used.add(str(v))
                self.c._add("binary", str(v), None, self.fname, "mikey:hdr/csb-id")
                return v

    def rand(self, n=16):
        return self.c.bytes(None, self.fname, n, rule="mikey:rand")

    def signature(self):
        return self.c.bytes(None, self.fname, 129, rule="mikey:sign")


def _canary(uri):
    """The canary user part of a Plant.user URI."""
    return uri.split(":", 1)[1].split("@")[0]


def filler(n, seed):
    """Deterministic non-canary bytes for kept ciphertext (SAKKE data)."""
    block = hashlib.sha256(b"sakke-filler-%d" % seed).digest()
    return (block * (n // len(block) + 1))[:n]


def pck_message(pl, caller, callee, kms, seed, ntp=0xE9A1B2C380000000):
    pck = pl.key_id(PCK)
    ids = [(IDRI, URI, caller.encode()), (IDRR, URI, callee.encode()),
           (IDRKMSI, URI, kms.encode()), (IDRKMSR, URI, kms.encode())]
    return i_message(pck, ntp, pl.rand(), ids, filler(273, seed), pl.signature())


# --- US1: a=key-mgmt in SDP -----------------------------------------
def gen_mikey_sdp(c, out):
    import sip as S
    fname = "mikey_sdp.pcapng"
    pl = Plant(c, fname)
    caller, callee = pl.user("caller"), pl.user("callee")
    kms = pl.kms()
    c.reuse(_canary(caller), None, fname, "mikey:idr/1")
    c.reuse(_canary(callee), None, fname, "mikey:idr/2")
    for role in (6, 7):
        c.reuse(kms.split(".")[0], None, fname, f"mikey:idr/{role}")
    cap = S.Capture()

    def hdrs(method, cseq, call_id, frm=caller, to=callee, extra=()):
        return [("Via", "SIP/2.0/UDP 10.20.1.10:5060;branch=z9hG4bK" + call_id), ("Max-Forwards", "70"),
                ("From", f"<{frm}>;tag=a1"), ("To", f"<{to}>"), ("Call-ID", call_id + "@mcx.example.org"),
                ("CSeq", f"{cseq} {method}"), ("P-Asserted-Identity", f"<{frm}>"), *extra]

    def body(session_attr=None, media_attr=None, proto="RTP/SAVP", mline="m=audio 40000 {p} 96"):
        lines = ["v=0", "o=- 1 1 IN IP4 10.20.1.10", "s=-", "c=IN IP4 10.20.1.10", "t=0 0"]
        if session_attr:
            lines.append(session_attr)
        lines += [mline.format(p=proto), "a=rtpmap:96 AMR-WB/16000"]
        if media_attr:
            lines.append(media_attr)
        return S.sdp(lines)

    def km(msg, space=""):
        return "a=key-mgmt:" + space + "mikey " + base64.b64encode(msg).decode()

    invite = S.request("INVITE", callee, hdrs("INVITE", 1, "mk1", extra=[("Content-Type", "application/sdp")]),
                       body(session_attr=km(pck_message(pl, caller, callee, kms, 1))))
    ok = S.response(200, "OK", hdrs("INVITE", 1, "mk1", extra=[("Content-Type", "application/sdp")]),
                    body(media_attr=km(pck_message(pl, callee, caller, kms, 2))))
    reinvite = S.request("INVITE", callee, hdrs("INVITE", 2, "mk1", extra=[("Content-Type", "application/sdp")]),
                         body(media_attr=km(pck_message(pl, caller, callee, kms, 3), space=" ")))
    rejected = S.response(488, "Not Acceptable Here",
                          hdrs("INVITE", 3, "mk2", extra=[("Warning", '399 mcx.example.org "136 authentication '
                                                                     'of the MIKEY-SAKKE I_MESSAGE failed"')]))
    # MBMS bearer announcement (TS 24.379 §14.2.2.2): an MSCCK at media level on m=application.
    psi = pl.user("psi")
    mscck = key_id(MSCCK, c.rng.getrandbits(28))
    c._used.add(str(mscck))
    c._add("binary", str(mscck), None, fname, "mikey:hdr/csb-id")
    ids = [(IDRI, URI, psi.encode()), (IDRR, URI, callee.encode()), (IDRKMSI, URI, kms.encode()),
           (IDRKMSR, URI, kms.encode())]
    announce_msg = i_message(mscck, 0xE9A1B2C380000000, pl.rand(), ids, filler(273, 4), pl.signature())
    announce = S.request("MESSAGE", callee, hdrs("MESSAGE", 4, "mk3", frm=psi,
                                                 extra=[("Content-Type", "application/sdp")]),
                         body(media_attr=km(announce_msg), proto="udp", mline="m=application 41000 {p} MCPTT"))
    for i, m in enumerate((invite, ok, reinvite, rejected, announce)):
        src, dst = (S.UA, S.PCSCF) if not m.startswith(b"SIP/2.0") else (S.PCSCF, S.UA)
        cap.add(S.wrap(S.udp_packet(src, dst, 5060, 5060, m, ident=0x4D00 + i)))
    S._write(cap, out, fname)


# --- US6: hostile and unknown key management -------------------------
HOSTILE = []  # (name, expected outcome) of the messages of mikey_hostile.pcapng, in order


def gen_mikey_hostile(c, out):
    import sip as S
    fname = "mikey_hostile.pcapng"
    pl = Plant(c, fname)
    kms = pl.kms()
    HOSTILE.clear()
    msgs = []

    def ids():
        return [(IDRI, URI, pl.user("caller").encode()), (IDRR, URI, pl.user("callee").encode()),
                (IDRKMSI, URI, kms.encode()), (IDRKMSR, URI, kms.encode())]

    def chain(parts, csb=None, data_type=26, v=0):
        """HDR + parts (type, builder(next)) + SIGN, with canaries in RAND and the signature."""
        csb = csb if csb is not None else pl.key_id(PCK)
        out_b = hdr(parts[0][0] if parts else SIGN, csb, v=v, data_type=data_type)
        for i, (_, build) in enumerate(parts):
            out_b += build(parts[i + 1][0] if i + 1 < len(parts) else SIGN)
        return out_b + sign(pl.signature())

    def std_parts():
        p = [(T, lambda n: t(n, 0xE9A1B2C380000000)), (RAND, lambda n, r=pl.rand(): rand(n, r))]
        for role, it, d in ids():
            p.append((IDR, lambda n, a=role, b=it, e=d: idr(n, a, b, e)))
        p.append((SAKKE, lambda n: sakke(n, filler(64, 9))))
        return p

    # Not MIKEY-SAKKE: other data types and V = 1.
    for dt in (0, 2, 4, 27):
        msgs.append((f"data-type-{dt}", "not-sakke", chain(std_parts(), data_type=dt)))
    msgs.append(("v-flag", "not-sakke", chain(std_parts(), v=1)))
    # Payloads outside MIKEY-SAKKE: KEMAC, a certificate, IDRpsk.
    msgs.append(("kemac", "unknown-payload",
                 chain([(T, lambda n: t(n, 1)), (KEMAC, lambda n: bytes([n, 0]) + b"\x00\x04" + pl.rand(4) + b"\x00")])))
    msgs.append(("cert", "unknown-payload",
                 chain([(T, lambda n: t(n, 1)), (CERT, lambda n: bytes([n, 0]) + b"\x00\x08" + pl.rand(8))])))
    msgs.append(("idrpsk", "unknown-payload", chain([(T, lambda n: t(n, 1)), (IDR, lambda n: idr(n, IDRPSK, BYTES, pl.rand(8)))])))
    # An RSA signature (S type 0) instead of ECCSI.
    full = chain(std_parts())
    rsa = full[:-131] + struct.pack("!H", (0 << 12) | 129) + full[-129:]
    msgs.append(("rsa-sign", "not-sakke", rsa))
    # Truncations inside the message.
    whole = chain(std_parts())
    for cut in (11, 25, 40, 90, len(whole) - 1):
        msgs.append((f"truncated-{cut}", "malformed", whole[:cut]))
    # An IDR length that overruns the message.
    over = bytearray(chain(std_parts()))
    pos = over.find(b"sip:")
    over[pos - 2:pos] = struct.pack("!H", 1000)  # within the 1024-octet limit, past the end
    msgs.append(("idr-overrun", "malformed", bytes(over)))
    # Rewritten with zeroing: an undefined role/type pair and an unknown extension type.
    p = std_parts()
    p.insert(2, (IDR, lambda n: idr(n, IDRI, BYTES, pl.c.string(None, fname, prefix="mkraw", rule="mikey:idr/unknown").encode())))
    p.insert(3, (GENEXT, lambda n: ext(n, 0, pl.c.string(None, fname, prefix="mkvendor", rule="mikey:ext/unknown").encode())))
    msgs.append(("zeroed-parts", "rewritten", chain(p)))
    cap = S.Capture()
    for i, (name, expect, m) in enumerate(msgs):
        HOSTILE.append((name, expect))
        sdp = S.sdp(["v=0", "o=- 1 1 IN IP4 10.20.1.10", "s=-", "c=IN IP4 10.20.1.10", "t=0 0",
                     "a=key-mgmt:mikey " + base64.b64encode(m).decode(), "m=audio 40000 RTP/SAVP 96"])
        req = S.request("INVITE", "sip:target@mcx.example.org",
                        [("Via", f"SIP/2.0/UDP 10.20.1.10:5060;branch=z9hG4bKh{i}"), ("Max-Forwards", "70"),
                         ("From", "<sip:host@mcx.example.org>;tag=h"), ("To", "<sip:target@mcx.example.org>"),
                         ("Call-ID", f"h{i}@mcx.example.org"), ("CSeq", "1 INVITE"),
                         ("Content-Type", "application/sdp")], sdp)
        cap.add(S.wrap(S.udp_packet(S.UA, S.PCSCF, 5060, 5060, req, ident=0x4E00 + i)))
    # Not base64 at all.
    HOSTILE.append(("bad-base64", "encoding"))
    sdp = S.sdp(["v=0", "o=- 1 1 IN IP4 10.20.1.10", "s=-", "c=IN IP4 10.20.1.10", "t=0 0",
                 "a=key-mgmt:mikey ****" + pl.c.string(None, fname, prefix="mkb64", rule="mikey:carrier/encoding"),
                 "m=audio 40000 RTP/SAVP 96"])
    req = S.request("INVITE", "sip:target@mcx.example.org",
                    [("Via", "SIP/2.0/UDP 10.20.1.10:5060;branch=z9hG4bKhx"), ("Max-Forwards", "70"),
                     ("From", "<sip:host@mcx.example.org>;tag=h"), ("To", "<sip:target@mcx.example.org>"),
                     ("Call-ID", "hx@mcx.example.org"), ("CSeq", "1 INVITE"), ("Content-Type", "application/sdp")], sdp)
    cap.add(S.wrap(S.udp_packet(S.UA, S.PCSCF, 5060, 5060, req, ident=0x4EFF)))
    S._write(cap, out, fname)
    with open(f"{out}/mikey_hostile.expect.json", "w") as fh:
        json.dump(HOSTILE, fh)


# --- US2: hidden identities --------------------------------------------
HIDDEN_PERIOD, HIDDEN_OFFSET = 2592000, 3600


def gen_mikey_hidden(c, out):
    """Private calls whose IDRuidi/IDRuidr carry the UIDs (TS 33.180 §E.7, §F.2.1.1) of the caller
    and callee of the same INVITE, raw and base64, with the IANA and the private-use roles; one UID
    belongs to an identity that appears nowhere in the capture."""
    import sip as S
    fname = "mikey_hidden.pcapng"
    pl = Plant(c, fname)
    kms = pl.kms()
    ntp = 0xE9A1B2C380000000
    p5 = period_number(ntp >> 32, HIDDEN_PERIOD, HIDDEN_OFFSET)
    cap = S.Capture()
    cases = []
    for i, (ri, rr, form) in enumerate(((IDRUIDI, IDRUIDR, "raw"), (IDRUIDI_PRIVATE, IDRUIDR_PRIVATE, "base64"),
                                         (IDRUIDI, IDRUIDR, "ghost"))):
        caller, callee = pl.user("caller"), pl.user("callee")
        target = callee if form != "ghost" else "sip:" + c.string(None, fname, prefix="mkghost", rule="mikey:idr/uid") + "@mcx.example.org"
        ui = uid(caller, kms, HIDDEN_PERIOD, HIDDEN_OFFSET, p5)
        ur = uid(target, kms, HIDDEN_PERIOD, HIDDEN_OFFSET, p5)
        for u, role in ((ui, ri), (ur, rr)):
            c._add("bytes", u.hex(), None, fname, "mikey:idr/uid")
            c.reuse(u.hex(), None, fname, f"mikey:idr/{role}")
        data_i = ui if form == "raw" else base64.b64encode(ui)
        data_r = ur if form == "raw" else base64.b64encode(ur)
        type_i = BYTES if form == "raw" else URI
        ids = [(ri, type_i, data_i), (rr, type_i, data_r), (IDRKMSI, URI, kms.encode()), (IDRKMSR, URI, kms.encode())]
        msg = i_message(pl.key_id(PCK), ntp, pl.rand(), ids, filler(273, 20 + i), pl.signature())
        sdp = S.sdp(["v=0", "o=- 1 1 IN IP4 10.20.1.10", "s=-", "c=IN IP4 10.20.1.10", "t=0 0",
                     "a=key-mgmt:mikey " + base64.b64encode(msg).decode(), "m=audio 40000 RTP/SAVP 96"])
        req = S.request("INVITE", callee,
                        [("Via", f"SIP/2.0/UDP 10.20.1.10:5060;branch=z9hG4bKu{i}"), ("Max-Forwards", "70"),
                         ("From", f"<{caller}>;tag=u{i}"), ("To", f"<{callee}>"), ("Call-ID", f"u{i}@mcx.example.org"),
                         ("CSeq", "1 INVITE"), ("P-Asserted-Identity", f"<{caller}>"),
                         ("Content-Type", "application/sdp")], sdp)
        cap.add(S.wrap(S.udp_packet(S.UA, S.PCSCF, 5060, 5060, req, ident=0x4F00 + i)))
        cases.append({"form": form, "resolvable": form != "ghost"})
    S._write(cap, out, fname)
    with open(f"{out}/mikey_hidden.expect.json", "w") as fh:
        json.dump({"kms": kms, "period": HIDDEN_PERIOD, "offset": HIDDEN_OFFSET, "cases": cases}, fh)


# --- US3: application/mikey bodies -------------------------------------
BODY = []  # (name, expected outcome) of the application/mikey carriers of mikey_body.pcapng, in order


def _b64_lines(raw, width=76):
    t = base64.b64encode(raw).decode()
    return "".join(t[i:i + width] + "\r\n" for i in range(0, len(t), width))


def csk_message(pl, user, server, kms, seed, ntp=0xE9A1B2C380000000, tag=CSK):
    """A CSK upload or download, or a MuSiK download (TS 33.180 §E.4.1): IDRi the sender, IDRr the
    receiver, the KMS of both."""
    ids = [(IDRI, URI, user.encode()), (IDRR, URI, server.encode()), (IDRKMSI, URI, kms.encode()),
           (IDRKMSR, URI, kms.encode())]
    return i_message(pl.key_id(tag), ntp, pl.rand(), ids, filler(273, seed), pl.signature())


def gen_mikey_body(c, out):
    """application/mikey bodies and parts (spec FR-004 b; TS 24.379 §7.2.1, §7.2.2, §7.3.7,
    §7A.2.1, §14.2.2.5; TS 24.282 §9.2.2.2.1; TS 24.481 §6.3.13.2.1), binary and base64, with and
    without Content-Transfer-Encoding; one body in a response (unexpected carrier) and one with
    version=2 (falls back as not-sakke)."""
    import sip as S
    fname = "mikey_body.pcapng"
    pl = Plant(c, fname)
    user = pl.user("csk-upload")
    server = "sip:mcptt-server@mcx.example.org"  # the MC domain's server identity (TS 33.180 §E.4.1)
    kms = pl.kms()
    cap = S.Capture()
    BODY.clear()
    info = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<mcpttinfo xmlns=\"urn:3gpp:ns:mcpttInfo:1.0\">\n"
            "<mcptt-Params>\n<mcptt-request-uri type=\"Normal\"><mcpttURI>" + user +
            "</mcpttURI></mcptt-request-uri>\n</mcptt-Params>\n</mcpttinfo>\n").encode()
    usage = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<mcptt-mbms-usage-info xmlns=\"urn:3gpp:ns:mcpttMbmsUsage:1.0\">"
             "\n<mbms-listening-status><mbms-listening-status>listening</mbms-listening-status>"
             "</mbms-listening-status>\n</mcptt-mbms-usage-info>\n").encode()

    def hdrs(method, cseq, call_id, frm, to, ct, extra=()):
        return [("Via", "SIP/2.0/UDP 10.20.1.10:5060;branch=z9hG4bKb" + call_id), ("Max-Forwards", "70"),
                ("From", f"<{frm}>;tag=b1"), ("To", f"<{to}>"), ("Call-ID", call_id + "@mcx.example.org"),
                ("CSeq", f"{cseq} {method}"), *extra, ("Content-Type", ct)]

    msgs = []
    # 1. REGISTER (TS 24.379 §7.2.1): multipart with the MCPTT information and a binary CSK upload.
    body = S.multipart("mk-b1", [([("Content-Type", "application/vnd.3gpp.mcptt-info+xml")], info),
                                 ([("Content-Type", "application/mikey")], csk_message(pl, user, server, kms, 30))])
    msgs.append(S.request("REGISTER", "sip:mcx.example.org",
                          hdrs("REGISTER", 1, "kb1", user, user, "multipart/mixed;boundary=mk-b1"), body))
    BODY.append(("register-binary-part", "rewritten"))
    # 2. Migration REGISTER (§7A.2.1): the part base64 with Content-Transfer-Encoding, 76 columns.
    body = S.multipart("mk-b2", [([("Content-Type", "application/vnd.3gpp.mcptt-info+xml")], info),
                                 ([("Content-Type", "application/mikey"), ("Content-Transfer-Encoding", "base64")],
                                  _b64_lines(csk_message(pl, user, server, kms, 31)))])
    msgs.append(S.request("REGISTER", "sip:partner.example.org",
                          hdrs("REGISTER", 2, "kb2", user, user, "multipart/mixed;boundary=mk-b2"), body))
    BODY.append(("migration-register-base64-part", "rewritten"))
    # 3. PUBLISH (§7.2.2): a whole base64 body with Content-Transfer-Encoding on one line, version=1.
    msgs.append(S.request("PUBLISH", "sip:mcptt-server@mcx.example.org",
                          hdrs("PUBLISH", 3, "kb3", user, server, "application/mikey;version=1",
                               extra=[("Event", "poc-settings"), ("Content-Transfer-Encoding", "base64")]),
                          base64.b64encode(csk_message(pl, user, server, kms, 32))))
    BODY.append(("publish-base64", "rewritten"))
    # 4. CSK download MESSAGE (§7.3.7): binary body from the server to the user.
    msgs.append(S.request("MESSAGE", user, hdrs("MESSAGE", 4, "kb4", server, user, "application/mikey"),
                          csk_message(pl, server, user, kms, 33)))
    BODY.append(("csk-download-binary", "rewritten"))
    # 5. MuSiK download MESSAGE (§14.2.2.5): multipart with the MBMS usage information and a base64
    # part without Content-Transfer-Encoding (detected by content).
    body = S.multipart("mk-b5", [([("Content-Type", "application/vnd.3gpp.mcptt-mbms-usage-info+xml")], usage),
                                 ([("Content-Type", "application/mikey")],
                                  base64.b64encode(csk_message(pl, server, user, kms, 34, tag=MUSIK)))])
    msgs.append(S.request("MESSAGE", user, hdrs("MESSAGE", 5, "kb5", server, user, "multipart/mixed;boundary=mk-b5"), body))
    BODY.append(("musik-download-base64-no-cte", "rewritten"))
    # 6. MCData one-to-one SDS MESSAGE (TS 24.282 §9.2.2.2.1): a PCK in a binary body.
    callee = pl.user("sds-callee")
    msgs.append(S.request("MESSAGE", callee, hdrs("MESSAGE", 6, "kb6", user, callee, "application/mikey"),
                          pck_message(pl, user, callee, kms, 35)))
    BODY.append(("mcdata-sds-binary", "rewritten"))
    # 7. SUBSCRIBE to the group management server (TS 24.481 §6.3.13.2.1): binary CSK upload.
    msgs.append(S.request("SUBSCRIBE", "sip:gms@mcx.example.org",
                          hdrs("SUBSCRIBE", 7, "kb7", user, "sip:gms@mcx.example.org", "application/mikey",
                               extra=[("Event", "xcap-diff")]), csk_message(pl, user, server, kms, 36)))
    BODY.append(("subscribe-binary", "rewritten"))
    # 8. A body in a response: rewritten the same way, counted unexpected-carrier.
    msgs.append(S.response(200, "OK", hdrs("MESSAGE", 4, "kb4", server, user, "application/mikey"),
                           csk_message(pl, server, user, kms, 37)))
    BODY.append(("response-unexpected", "rewritten"))
    # 9. version=2 (RFC 3830 §10.1 "Optional parameters: version"): falls back, body emptied.
    msgs.append(S.request("MESSAGE", user, hdrs("MESSAGE", 9, "kb9", server, user, "application/mikey;version=2"),
                          csk_message(pl, server, user, kms, 38)))
    BODY.append(("version-2", "fallback:not-sakke"))
    for i, m in enumerate(msgs):
        src, dst = (S.UA, S.PCSCF) if not m.startswith(b"SIP/2.0") else (S.PCSCF, S.UA)
        cap.add(S.wrap(S.udp_packet(src, dst, 5060, 5060, m, ident=0x5000 + i)))
    S._write(cap, out, fname)
    with open(f"{out}/mikey_body.expect.json", "w") as fh:
        json.dump(BODY, fh)


# --- US3: <GKTP> hexBinary ---------------------------------------------
GKTP_NS = "urn:3gpp:ns:mcpttGKTP:1.0"
VGKTP_NS = "urn:3gpp:ns:mcvideoGKTP:1.0"


def _xk(ns, parent, local):
    return f"xml:{ns}|{parent or '-'}|{local}"


def _xa(ns, element, attr):
    return f"xml:{ns}|{element}|@-|{attr}"


def gen_mikey_gktp(c, out):
    """<GKTP> elements (TS 24.481 §7.7.4.2): a NOTIFY whose xcap-diff element carries the <GKTPs> of
    a group (TS 24.481 Table A.2.3-11) with GMK and MKFC GKTPs and an on-network regroup, and the
    <MKFC-GKTPs> of the MCPTT and MCVideo information (TS 24.379 §F.1.3 item 16, TS 24.281). The
    GMK I_MESSAGE comes from the GMS, whose IDRi is its XCAP URI (TS 24.481 §7.4.2). Lower and
    upper case hexBinary; one <GKTP> whose I_MESSAGE does not parse (removed as a credential)."""
    import sip as S
    fname = "mikey_gktp.pcapng"
    pl = Plant(c, fname)
    user = pl.user("gktp-user")
    kms = pl.kms()
    gms_host = c.string(None, fname, prefix="mkgms", rule="mikey:idr/gms") + ".mcx.example.org"
    gms = f"http://{gms_host}/org.3gpp.MCPTT-GKTP/"
    gname = c.string(None, fname, prefix="mkgroup", rule=_xa(GKTP_NS, "on-network-regrouped-GKTPs",
                                                             "temporary-MCPTT-group-ID"))
    c.reuse(gname, None, fname, _xa(VGKTP_NS, "on-network-regrouped-GKTPs", "temporary-MCPTT-group-ID"))
    group = "sip:" + gname + "@mcx.example.org"
    for ns in (GKTP_NS, VGKTP_NS):
        c.reuse(user[4:].split("@")[0], None, fname, _xk(ns, None, "GKTP"))
    cap = S.Capture()

    def gmk(seed, tag=GMK):
        ids = [(IDRI, URI, gms.encode()), (IDRR, URI, user.encode()), (IDRKMSI, URI, kms.encode()),
               (IDRKMSR, URI, kms.encode())]
        guk = pl.key_id(tag)
        gmk_id = pl.key_id(tag)
        blocks = [generic_id_block(4, spi=struct.pack("!II", gmk_id, guk))]
        kp = key_parameters(guk, pl.rand(), filler(48, seed + 100))
        return i_message(guk, 0xE9A1B2C380000000, pl.rand(), ids, filler(273, seed), pl.signature(), blocks=blocks,
                         extensions=[(EXT_KEY_PARAMETERS, kp)])

    gid = c.string(None, fname, prefix="mkgktpid", rule=_xa(GKTP_NS, "GKTP", "id"))
    vid = c.string(None, fname, prefix="mkgktpid", rule=_xa(VGKTP_NS, "GKTP", "id"))
    any_ext = c.string(None, fname, prefix="mkanyext", rule=_xk(GKTP_NS, None, "anyExt"))
    c.reuse(any_ext, None, fname, _xk(VGKTP_NS, None, "anyExt"))
    bad = gmk(40)[:-60]  # truncated: the I_MESSAGE does not parse
    gktps = (f'<mgktp:GKTPs xmlns:mgktp="{GKTP_NS}">'
             f'<mgktp:GMK-GKTPs><mgktp:GKTP id="{gid}" activationtime="2026-11-14T10:00:00Z">{gmk(41).hex()}</mgktp:GKTP>'
             f'<mgktp:on-network-regrouped-GKTPs temporary-MCPTT-group-ID="{group}">'
             f'<mgktp:GKTP id="g2">\n  {gmk(42).hex().upper()}\n</mgktp:GKTP></mgktp:on-network-regrouped-GKTPs>'
             f'<mgktp:anyExt><x>{any_ext}</x></mgktp:anyExt></mgktp:GMK-GKTPs>'
             f'<mgktp:MKFC-GKTPs><mgktp:GKTP id="k1">{gmk(43, MKFC).hex()}</mgktp:GKTP>'
             f'<mgktp:GKTP id="k2">{bad.hex()}</mgktp:GKTP></mgktp:MKFC-GKTPs></mgktp:GKTPs>')
    sel = ("org.3gpp.MCPTT-GKTP/global/byGroupID/sip:fire-west@mcx.example.org/~~/group/list-service/"
           f"mgktp:GKTPs?xmlns(mgktp={GKTP_NS})")
    diff = ('<?xml version="1.0" encoding="UTF-8"?>\n<d:xcap-diff xmlns:d="urn:ietf:params:xml:ns:xcap-diff" '
            f'xcap-root="http://{gms_host}"><d:element sel="{sel}">{gktps}</d:element></d:xcap-diff>\n')

    def hdrs(method, cseq, call_id, frm, to, ct, extra=()):
        return [("Via", "SIP/2.0/UDP 10.20.1.10:5060;branch=z9hG4bKg" + call_id), ("Max-Forwards", "70"),
                ("From", f"<{frm}>;tag=g1"), ("To", f"<{to}>"), ("Call-ID", call_id + "@mcx.example.org"),
                ("CSeq", f"{cseq} {method}"), *extra, ("Content-Type", ct)]

    gms_sip = "sip:gms@mcx.example.org"
    notify = S.request("NOTIFY", user, hdrs("NOTIFY", 1, "kg1", gms_sip, user, "application/xcap-diff+xml",
                                            extra=[("Event", "xcap-diff"), ("Subscription-State", "active;expires=7200")]),
                       diff.encode())
    info = ('<?xml version="1.0" encoding="UTF-8"?>\n<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0" '
            f'xmlns:mgktp="{GKTP_NS}"><mcptt-Params><MKFC-GKTPs>'
            f'<mgktp:GKTP id="k3">{gmk(44, MKFC).hex().upper()}</mgktp:GKTP></MKFC-GKTPs></mcptt-Params></mcpttinfo>\n')
    vinfo = ('<?xml version="1.0" encoding="UTF-8"?>\n<mcvideoinfo xmlns="urn:3gpp:ns:mcvideoInfo:1.0" '
             f'xmlns:mvgktp="{VGKTP_NS}"><mcvideo-Params><MKFC-GKTPs>'
             f'<mvgktp:GKTP id="{vid}">{gmk(45, MKFC).hex()}</mvgktp:GKTP>'
             f'<mvgktp:anyExt>{any_ext}</mvgktp:anyExt></MKFC-GKTPs></mcvideo-Params></mcvideoinfo>\n')
    m2 = S.request("MESSAGE", user, hdrs("MESSAGE", 2, "kg2", gms_sip, user, "application/vnd.3gpp.mcptt-info+xml"),
                   info.encode())
    m3 = S.request("MESSAGE", user, hdrs("MESSAGE", 3, "kg3", gms_sip, user, "application/vnd.3gpp.mcvideo-info+xml"),
                   vinfo.encode())
    for i, m in enumerate((notify, m2, m3)):
        cap.add(S.wrap(S.udp_packet(S.PCSCF, S.UA, 5060, 5060, m, ident=0x5100 + i)))
    S._write(cap, out, fname)
    with open(f"{out}/mikey_gktp.expect.json", "w") as fh:
        json.dump({"gms": gms, "rewritten": 5, "fallback": 1}, fh)


# --- US3: MCPC field 192 ----------------------------------------------
def gen_mikey_mcpc(c, out):
    """The PCK I_MESSAGE field of pre-established session call control (TS 24.380 §8.3.3.10): a
    Connect with field 192 binary, one with it base64, and one whose field does not parse (zeroed).
    The originating party (field 5) is the IDRi of the I_MESSAGE."""
    import media as M
    fname = "mikey_mcpc.pcapng"
    pl = Plant(c, fname)
    caller, callee = pl.user("mcpc-caller"), pl.user("mcpc-callee")
    kms = pl.kms()
    F = M.app_field
    good1 = pck_message(pl, caller, callee, kms, 50)
    good2 = pck_message(pl, caller, callee, kms, 51)
    bad = pck_message(pl, caller, callee, kms, 52)[:-40]

    def msgs(v):
        sess = bytes([3]) + callee.encode()
        return [(b"MCPC", 16, [F(0, M._u16(0x0102)), F(1, sess), F(5, caller.encode()), F(192, good1)]),
                (b"MCPC", 16, [F(0, M._u16(0x0102)), F(1, sess), F(5, caller.encode()),
                               F(192, base64.b64encode(good2))]),
                (b"MCPC", 0, [F(5, caller.encode()), F(192, bad)])]
    M._family_call(c, out, fname, "MCPTT", msgs, 40442, 50442)


# --- US3: SRTP and SRTCP MKI --------------------------------------------
SRTP = {}  # what mikey_srtp.pcapng holds, for the test


def gen_mikey_srtp(c, out):
    """SRTP and SRTCP on endpoints announced with an I_MESSAGE (TS 33.180 §7.4.1, §7.4.2, RFC 3711):
    a group call whose GMK I_MESSAGE carries GMK-ID || GUK-ID in a GENERIC-ID SPI (MKI of 8 octets,
    tag 4, the default GMK profile of §E.2.2), a private call with a PCK (MKI of 4 octets, AEAD tag
    inside the ciphertext, §E.3.2), SRTCP with E+index and an unknown MKI (ambiguous positions are
    covered by tests/unit/srtp_mki_test.cpp).
    mikey_srtp2.pcapng has no I_MESSAGE: its PCK-ID MKI is known only from the project mapping of a
    run over mikey_srtp.pcapng."""
    import media as M
    fname, fname2 = "mikey_srtp.pcapng", "mikey_srtp2.pcapng"
    pl = Plant(c, fname)
    caller, callee = pl.user("srtp-caller"), pl.user("srtp-callee")
    kms = pl.kms()
    gmk, guk, pck = pl.key_id(GMK), pl.key_id(GMK), pl.key_id(PCK)
    for k in (gmk, guk, pck):
        c.reuse(str(k), None, fname2, "mikey:mki")
    ids = [(IDRI, URI, b"http://gms.mcx.example.org/org.3gpp.MCPTT-GKTP/"), (IDRR, URI, caller.encode()),
           (IDRKMSI, URI, kms.encode()), (IDRKMSR, URI, kms.encode())]
    gmk_msg = i_message(guk, 0xE9A1B2C380000000, pl.rand(), ids, filler(273, 60), pl.signature(),
                        blocks=[generic_id_block(4, session=[(int(c.binary(fname, "mikey:hdr/ssrc", low=0x80000000)), 0)],
                                                 spi=struct.pack("!II", gmk, guk))])
    ids = [(IDRI, URI, caller.encode()), (IDRR, URI, callee.encode()), (IDRKMSI, URI, kms.encode()),
           (IDRKMSR, URI, kms.encode())]
    pck_msg = i_message(pck, 0xE9A1B2C380000000, pl.rand(), ids, filler(273, 61), pl.signature())
    km = lambda m: "a=key-mgmt:mikey " + base64.b64encode(m).decode() + "\r\n"  # noqa: E731

    def srtp(seq, ssrc, mki, tag=0, enc=40):
        return M.rtp(seq, 1000 + seq * 160, ssrc) + bytes(0xE5 for _ in range(enc)) + mki + bytes([0x7A]) * tag

    def srtcp(ssrc, mki, enc=20):
        return bytes([0x80, 200, 0, 6]) + struct.pack("!I", ssrc) + bytes([0xC3]) * enc + struct.pack("!I", 0x80000007) + mki

    group = M.Call([M.m_audio(40500, "RTP/SAVP", extra=km(gmk_msg))], [M.m_audio(50500, "RTP/SAVP")],
                   call_id="srtp-group@mcx.example.org")
    private = M.Call([M.m_audio(40600, "RTP/SAVP", extra=km(pck_msg))], [M.m_audio(50600, "RTP/SAVP")],
                     call_id="srtp-private@mcx.example.org")
    ssrc = 0x51525354
    # Group call, b -> a (the endpoint whose SDP carried the GMK): GMK-ID || GUK-ID, then a 4-octet tag.
    for i in range(3):
        group.b_to_a(50500, 40500, srtp(i, ssrc, struct.pack("!II", gmk, guk), tag=4))
    # Private call, b -> a: the PCK-ID, no tag after it; SRTCP on the RTCP port with E+index.
    for i in range(2):
        private.b_to_a(50600, 40600, srtp(i, ssrc + 1, struct.pack("!I", pck)))
    private.b_to_a(50601, 40601, srtcp(ssrc + 1, struct.pack("!I", pck)))
    # An MKI that is no key identifier: the trailer stays zeroed, counted unmatched.
    private.b_to_a(50600, 40600, srtp(5, ssrc + 1, struct.pack("!I", 0x1F00F00D)))
    group.cap.blocks += private.cap.blocks
    group.write(out, fname)
    SRTP.update({"gmk": gmk, "guk": guk, "pck": pck, "pseudonymised": 6, "unmatched": 1})
    # The second capture: a secure call without key management, the same PCK-ID in the MKI.
    later = M.Call([M.m_audio(40700, "RTP/SAVP")], [M.m_audio(50700, "RTP/SAVP")],
                   call_id="srtp-later@mcx.example.org")
    for i in range(2):
        later.b_to_a(50700, 40700, srtp(i, ssrc + 2, struct.pack("!I", pck)))
    later.write(out, fname2)
    with open(f"{out}/mikey_srtp.expect.json", "w") as fh:
        json.dump(SRTP, fh)


# --- Rule coverage (the canaries of tests/mikey_rule_keys_main.cpp) -----
def gen_mikey_rules(c, out):
    """One I_MESSAGE that exercises the rules no other fixture reaches: IDRkms (role 3), a GENERIC-ID
    block with an SSRC and an SPI, the key parameters extension, the Vendor ID and SDP IDs
    extensions, an extension, an ID role and an SP parameter without a rule."""
    import sip as S
    fname = "mikey_rules.pcapng"
    pl = Plant(c, fname)
    caller, callee = pl.user("rules-caller"), pl.user("rules-callee")
    kms = c.string(None, fname, prefix="mkkms", rule="mikey:idr/3") + ".kms.example.org"
    unknown_id = c.string(None, fname, prefix="mkunknownid", rule="mikey:idr/unknown")
    ssrc = int(c.binary(fname, "mikey:hdr/ssrc", low=0x80000000))  # never ASCII: a 4-octet text chance match
    gmk = pl.key_id(GMK)
    c.reuse(str(gmk), None, fname, "mikey:hdr/spi")
    csb = pl.key_id(GMK)
    iv = c.bytes(None, fname, 16, rule="mikey:ext/7")
    ids = [(IDRI, URI, caller.encode()), (IDRR, URI, callee.encode()), (IDRKMS, URI, kms.encode()),
           (10, URI, unknown_id.encode())]
    exts = [(EXT_KEY_PARAMETERS, key_parameters(csb, iv, filler(32, 90))),
            (0, c.bytes(None, fname, 16, rule="mikey:ext/0")), (1, c.bytes(None, fname, 16, rule="mikey:ext/1")),
            (9, c.bytes(None, fname, 16, rule="mikey:ext/unknown"))]
    sps = [(0, 0, [(0, b"\x06"), (30, c.bytes(None, fname, 16, rule="mikey:sp/unknown"))])]
    msg = i_message(csb, 0xE9A1B2C380000000, pl.rand(), ids, filler(273, 91), pl.signature(),
                    blocks=[generic_id_block(4, session=[(ssrc, 0)], spi=struct.pack("!II", gmk, csb))],
                    extensions=exts, sp_payloads=sps)
    sdp = S.sdp(["v=0", "o=- 1 1 IN IP4 10.20.1.10", "s=-", "c=IN IP4 10.20.1.10", "t=0 0",
                 "a=key-mgmt:mikey " + base64.b64encode(msg).decode(), "m=audio 40000 RTP/SAVP 96"])
    req = S.request("INVITE", callee, [("Via", "SIP/2.0/UDP 10.20.1.10:5060;branch=z9hG4bKr1"), ("Max-Forwards", "70"),
                                       ("From", f"<{caller}>;tag=r1"), ("To", f"<{callee}>"),
                                       ("Call-ID", "rules@mcx.example.org"), ("CSeq", "1 INVITE"),
                                       ("Content-Type", "application/sdp")], sdp)
    cap = S.Capture()
    cap.add(S.wrap(S.udp_packet(S.UA, S.PCSCF, 5060, 5060, req, ident=0x5300)))
    S._write(cap, out, fname)


# --- US4: encrypted XML and encrypted URIs ------------------------------
XENC_NS = "http://www.w3.org/2001/04/xmlenc#"
DSIG_NS = "http://www.w3.org/2000/09/xmldsig#"


def _xenc(xpk, cipher, typ="Content", alg="http://www.w3.org/2009/xmlenc11#aes128-gcm", extra=""):
    """xenc:EncryptedData as TS 33.180 §9.3.4.2 shows it: Type, EncryptionMethod, KeyInfo/KeyName
    with the base64 XPK-ID, CipherData/CipherValue."""
    return (f'<xenc:EncryptedData xmlns:xenc="{XENC_NS}" Type="http://www.w3.org/2001/04/xmlenc#{typ}">'
            f'<xenc:EncryptionMethod Algorithm="{alg}"/>'
            f'<ds:KeyInfo xmlns:ds="{DSIG_NS}"><ds:KeyName>{base64.b64encode(struct.pack("!I", xpk)).decode()}'
            f'</ds:KeyName></ds:KeyInfo>{extra}<xenc:CipherData><xenc:CipherValue>{base64.b64encode(cipher).decode()}'
            '</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>')


def gen_mikey_xenc(c, out):
    """A REGISTER whose MCPTT information has an encrypted access token and client ID (TS 33.180
    §9.3.4.2) next to the CSK upload whose CSK-ID is the XPK-ID; one EncryptedData has a part
    outside the allowlist. A signed body whose signature names the same key (§9.3.5), and a PIDF
    whose entity is an encrypted URI attribute (§9.3.4.3) with the same key-id."""
    import sip as S
    fname = "mikey_xenc.pcapng"
    pl = Plant(c, fname)
    user = pl.user("xenc-user")
    server = "sip:mcptt-server@mcx.example.org"
    kms = pl.kms()
    csk = pl.key_id(CSK)
    c.reuse(str(csk), None, fname, f"xml:{DSIG_NS}|-|KeyName")
    upload = i_message(csk, 0xE9A1B2C380000000, pl.rand(), [(IDRI, URI, user.encode()), (IDRR, URI, server.encode()),
                                                             (IDRKMSI, URI, kms.encode()), (IDRKMSR, URI, kms.encode())],
                       filler(273, 95), pl.signature())
    unknown = c.string(None, fname, prefix="mkxencunknown", rule=f"xml:{XENC_NS}|-|EncryptionProperties")
    info = ('<?xml version="1.0" encoding="UTF-8"?>\n<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"><mcptt-Params>'
            f'<mcptt-access-token type="Encrypted">{_xenc(csk, filler(64, 96))}</mcptt-access-token>'
            '<mcptt-client-id type="Encrypted">'
            + _xenc(csk, filler(48, 97), extra=f"<xenc:EncryptionProperties>{unknown}</xenc:EncryptionProperties>")
            + '</mcptt-client-id></mcptt-Params></mcpttinfo>\n')
    sig = ('<?xml version="1.0" encoding="UTF-8"?>\n<signatures xmlns="urn:3gpp:ns:mcpttSignedDoc:1.0" '
           f'xmlns:ds="{DSIG_NS}"><ds:Signature><ds:SignedInfo>'
           '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>'
           '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"/>'
           '<ds:Reference URI="cid:xenc-info@mcx.example.org"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
           f'<ds:DigestValue>{base64.b64encode(filler(32, 98)).decode()}</ds:DigestValue></ds:Reference></ds:SignedInfo>'
           f'<ds:SignatureValue>{base64.b64encode(filler(32, 99)).decode()}</ds:SignatureValue>'
           f'<ds:KeyInfo><ds:KeyName>{base64.b64encode(struct.pack("!I", csk)).decode()}</ds:KeyName></ds:KeyInfo>'
           '</ds:Signature></signatures>\n')
    body = S.multipart("mk-x1", [([("Content-Type", "application/vnd.3gpp.mcptt-info+xml"),
                                   ("Content-ID", "<xenc-info@mcx.example.org>")], info),
                                 ([("Content-Type", "application/mikey")], upload),
                                 ([("Content-Type", "application/vnd.3gpp.mcptt-signed+xml")], sig)])

    def hdrs(method, cseq, call_id, frm, to, ct, extra=()):
        return [("Via", "SIP/2.0/UDP 10.20.1.10:5060;branch=z9hG4bKx" + call_id), ("Max-Forwards", "70"),
                ("From", f"<{frm}>;tag=x1"), ("To", f"<{to}>"), ("Call-ID", call_id + "@mcx.example.org"),
                ("CSeq", f"{cseq} {method}"), *extra, ("Content-Type", ct)]

    reg = S.request("REGISTER", "sip:mcx.example.org", hdrs("REGISTER", 1, "kx1", user, user,
                                                            "multipart/mixed;boundary=mk-x1"), body)
    # An encrypted URI attribute (TS 33.180 §9.3.4.3): ciphertext, a 96-bit IV, the XPK-ID.
    iv = pl.rand(12)
    ct = c.bytes(None, fname, 18, rule="xml:urn:ietf:params:xml:ns:pidf|presence|@-|entity")
    b64u = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")  # noqa: E731
    enc_uri = (f"sip:{b64u(ct)};iv={b64u(iv)};key-id={b64u(struct.pack('!I', csk))};alg=128-aes-gcm"
               "@mc1-encryption.3gppnetwork.org")
    pidf = ('<?xml version="1.0" encoding="UTF-8"?>\n<presence xmlns="urn:ietf:params:xml:ns:pidf" '
            f'entity="{enc_uri}"><tuple id="xt1"><status><basic>open</basic></status></tuple></presence>\n')
    pub = S.request("PUBLISH", server, hdrs("PUBLISH", 2, "kx2", user, server, "application/pidf+xml",
                                            extra=[("Event", "presence")]), pidf.encode())
    cap = S.Capture()
    for i, m in enumerate((reg, pub)):
        cap.add(S.wrap(S.udp_packet(S.UA, S.PCSCF, 5060, 5060, m, ident=0x5400 + i)))
    S._write(cap, out, fname)
    with open(f"{out}/mikey_xenc.expect.json", "w") as fh:
        json.dump({"csk": csk, "cipher": [base64.b64encode(filler(64, 96)).decode(),
                                          base64.b64encode(filler(48, 97)).decode()]}, fh)


SETS = [gen_mikey_sdp, gen_mikey_hostile, gen_mikey_hidden, gen_mikey_body, gen_mikey_gktp, gen_mikey_mcpc,
        gen_mikey_srtp, gen_mikey_rules, gen_mikey_xenc]


def corpus():
    """Seed I_MESSAGEs for the MIKEY fuzz targets: one per payload kind and map type."""
    cks = key_id(CSK, 0x0123456)
    ids = [(IDRI, URI, b"sip:alice@example.org"), (IDRR, URI, b"sip:bob@example.org"),
           (IDRKMSI, URI, b"kms.example.org"), (IDRKMSR, URI, b"kms.example.org")]
    plain = i_message(cks, 0xE9A1B2C300000000, b"R" * 16, ids, b"S" * 273, b"G" * 129)
    gmk = key_id(GMK, 0x0AAAAAA)
    guk = key_id(GMK, 0x0BBBBBB)
    blocks = [generic_id_block(4, session=[(0x11223344, 0)], spi=struct.pack("!II", gmk, guk))]
    hidden = [(IDRUIDI, BYTES, b"U" * 32), (IDRUIDR, URI, base64.b64encode(b"V" * 32)),
              (IDRKMSI, URI, b"kms.example.org"), (IDRKMSR, URI, b"kms.example.org")]
    kp = key_parameters(guk, b"I" * 16, b"C" * 24)
    rich = i_message(guk, 0xE9A1B2C300000000, b"R" * 16, hidden, b"S" * 64, b"G" * 129, blocks=blocks,
                     extensions=[(EXT_SAKKE_TO_SELF, sakke(0, b"T" * 64)), (EXT_KEY_PARAMETERS, kp)],
                     sp_payloads=[(0, 0, [(0, b"\x06"), (1, b"\x10"), (20, b"\x10")])])
    return [plain, rich, base64.b64encode(plain), rich.hex().encode()]

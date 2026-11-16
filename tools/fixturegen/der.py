# SPDX-License-Identifier: GPL-3.0-or-later
"""A DER writer for synthetic X.509 certificates (RFC 5280; feature 007 fixtures). Keys and
signatures are random octets: no private key exists, nothing verifies."""


def tlv(tag, content):
    n = len(content)
    if n < 0x80:
        length = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + length + content


def seq(*items):
    return tlv(0x30, b"".join(items))


def set_(*items):
    return tlv(0x31, b"".join(items))


def oid(dotted):
    parts = [int(x) for x in dotted.split(".")]
    out = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.insert(0, 0x80 | (p & 0x7F))
            p >>= 7
        out += bytes(chunk)
    return tlv(0x06, out)


def integer(value_bytes):
    b = value_bytes.lstrip(b"\x00") or b"\x00"
    if b[0] & 0x80:
        b = b"\x00" + b
    return tlv(0x02, b)


def name(attrs):
    """attrs: [(oid, tag, text)] -> RDNSequence, one attribute per RDN."""
    return seq(*(set_(seq(oid(o), tlv(t, v.encode() if t != 0x1E else v.encode("utf-16-be")))) for o, t, v in attrs))


def ext(o, value, critical=False):
    return seq(oid(o), *([tlv(0x01, b"\xff")] if critical else []), tlv(0x04, value))


def utc(text):
    return tlv(0x17, text.encode())


RSA, EC = "1.2.840.113549.1.1.1", "1.2.840.10045.2.1"
SHA256_RSA, ECDSA_SHA256 = "1.2.840.113549.1.1.11", "1.2.840.10045.4.3.2"


def certificate(rng, serial, issuer, subject, key="rsa", extensions=(), sig_len=256, key_bytes=None, sig=None,
                issuer_raw=False):
    """issuer and subject: attribute lists for name(), or encoded Names with issuer_raw."""
    if key == "rsa":
        modulus = key_bytes or (bytes([0x80 | rng.randrange(128)]) + bytes(rng.randrange(256) for _ in range(255)))
        spki = seq(seq(oid(RSA), tlv(0x05, b"")), tlv(0x03, b"\x00" + seq(integer(modulus), integer(b"\x01\x00\x01"))))
        alg = seq(oid(SHA256_RSA), tlv(0x05, b""))
    else:
        point = b"\x04" + (key_bytes or bytes(rng.randrange(256) for _ in range(64)))
        spki = seq(seq(oid(EC), oid("1.2.840.10045.3.1.7")), tlv(0x03, b"\x00" + point))
        alg = seq(oid(ECDSA_SHA256))
    issuer_der, subject_der = (issuer, subject) if issuer_raw else (name(issuer), name(subject))
    tbs = seq(tlv(0xA0, integer(b"\x02")), integer(serial), alg, issuer_der,
              seq(utc("260101000000Z"), utc("271231235959Z")), subject_der, spki,
              *([tlv(0xA3, seq(*extensions))] if extensions else []))
    sig = sig or bytes(rng.randrange(256) for _ in range(sig_len))
    return seq(tbs, alg, tlv(0x03, b"\x00" + sig))

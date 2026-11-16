#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Synthetic fixture generator.

Writes capture files with canary values in identity and metadata fields, plus
canaries.json describing every planted value. Deterministic for a given seed.

Usage: gen.py --out DIR [--seed N] [--only NAME[,NAME...]] [--corpus DIR] [--sip-corpus DIR] [--sdp-corpus DIR]
              [--media-corpus DIR] [--xml-corpus DIR] [--mikey-corpus DIR] [--web-corpus DIR]
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import canary as canary_mod  # noqa: E402
import icmp  # noqa: E402
import l3  # noqa: E402
import l4  # noqa: E402
import link  # noqa: E402
import malformed  # noqa: E402
import media  # noqa: E402
import xmlbodies  # noqa: E402
import meta  # noqa: E402
import mikey  # noqa: E402
import options  # noqa: E402
import packets  # noqa: E402
import pilot  # noqa: E402
import pcap  # noqa: E402
import pcapng  # noqa: E402
import sip  # noqa: E402
import tunnel  # noqa: E402
import web  # noqa: E402


def gen_basic_pcap(c, out):
    """Ethernet / IPv4 / UDP with canary MAC and IPv4 addresses and canary payload text."""
    name = "basic_eth.pcap"
    smac = canary_mod.mac_bytes(c.mac("eth.src", name))
    dmac = canary_mod.mac_bytes(c.mac("eth.dst", name))
    sip = canary_mod.ipv4_bytes(c.ipv4("ipv4.src", name))
    dip = canary_mod.ipv4_bytes(c.ipv4("ipv4.dst", name))
    text = c.string("payload.l7", name).encode()
    pkts = []
    for i in range(3):
        udp = packets.udp4(sip, dip, 40000 + i, 5060, text)
        frame = packets.ethernet(dmac, smac, 0x0800, packets.ipv4(sip, dip, 17, udp))
        pkts.append((1700000000 + i, 1000 * i, frame))
    with open(os.path.join(out, name), "wb") as f:
        f.write(pcap.pcap_file(pkts, linktype=1))


def gen_basic_pcapng(c, out):
    """pcapng with canary strings in SHB, IDB and EPB options and comments."""
    name = "basic_meta.pcapng"
    w = pcapng.Writer()
    smac = canary_mod.mac_bytes(c.mac("eth.src", name))
    dmac = canary_mod.mac_bytes(c.mac("eth.dst", name))
    sip = canary_mod.ipv4_bytes(c.ipv4("ipv4.src", name))
    dip = canary_mod.ipv4_bytes(c.ipv4("ipv4.dst", name))
    shb = w.shb([(1, c.string("pcapng.opt.comment", name)), (2, c.string("pcapng.shb.hardware", name)),
                 (3, c.string("pcapng.shb.os", name)), (4, c.string("pcapng.shb.userappl", name))])
    idb = w.idb(1, 262144, [(2, c.string("pcapng.idb.name", name)),
                            (3, c.string("pcapng.idb.description", name)), (9, b"\x06")])
    udp = packets.udp4(sip, dip, 40000, 5060, b"x" * 16)
    frame = packets.ethernet(dmac, smac, 0x0800, packets.ipv4(sip, dip, 17, udp))
    epb = w.epb(0, 1700000000000000, frame, [(1, c.string("pcapng.opt.comment", name))])
    with open(os.path.join(out, name), "wb") as f:
        f.write(shb + idb + epb)


SETS = {
    "basic_pcap": gen_basic_pcap,
    "basic_pcapng": gen_basic_pcapng,
    "link": link.gen,
    "l3": l3.gen,
    "icmp": icmp.gen,
    "l4": l4.gen,
    "tunnel": tunnel.gen,
    "meta": meta.gen,
    "malformed": malformed.gen,
    "options": options.gen,
    "sip": sip.gen,
    "media": media.gen,
    "xml": xmlbodies.gen,
    "mikey": mikey.gen,
    "web": web.gen,
    "pilot": pilot.gen,
}


def write_corpus(corpus_dir, out):
    """Seed corpora for the fuzz targets: the generated captures themselves."""
    os.makedirs(corpus_dir, exist_ok=True)
    for name in sorted(os.listdir(out)):
        if name.endswith((".pcap", ".pcapng")):
            with open(os.path.join(out, name), "rb") as src, \
                    open(os.path.join(corpus_dir, name), "wb") as dst:
                dst.write(src.read())


def write_packet_corpus(corpus_dir, out):
    """Seeds for packet-level fuzz targets: first byte selects the link type."""
    import struct
    os.makedirs(corpus_dir, exist_ok=True)
    selector = {0: 0, 1: 1, 101: 2, 113: 3, 228: 4, 229: 5, 276: 6}
    n = 0
    for name in sorted(os.listdir(out)):
        if not name.endswith(".pcap"):
            continue
        data = open(os.path.join(out, name), "rb").read()
        order = "<" if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        lt = struct.unpack_from(order + "I", data, 20)[0] & 0xFFFF
        off = 24
        while off + 16 <= len(data):
            cap = struct.unpack_from(order + "I", data, off + 8)[0]
            with open(os.path.join(corpus_dir, f"p{n:05d}"), "wb") as fh:
                fh.write(bytes([selector.get(lt, 7)]) + data[off + 16:off + 16 + cap])
            n += 1
            off += 16 + cap


APP_NAMES = [b"MCPT", b"MCPC", b"MCMC", b"MCNC", b"MCSC", b"MCV0", b"MCV1", b"MCV2", b"MCV3", b"MCV4", b"MCV5",
             b"MCDM", b"XXXX"]  # the order of fuzz_rtcp_app.cpp
SECURE = ("rtp_srtp", "rtcp_srtcp", "app_mcpt_secure")


def _pcapng_frames(data):
    """The Ethernet frames of a pcapng file written by the fixture generator."""
    import struct
    o = "<" if data[8:12] == b"\x4d\x3c\x2b\x1a" else ">"
    off = 0
    while off + 12 <= len(data):
        bt, bl = struct.unpack_from(o + "II", data, off)
        if bl < 12:
            return
        if bt == 6:
            cap = struct.unpack_from(o + "I", data, off + 20)[0]
            yield data[off + 28:off + 28 + cap]
        off += bl


def _l4(frame):
    """(proto, src, dst, sport, dport, payload) of an Ethernet/IPv4 or IPv6 UDP/TCP frame."""
    import struct
    et, i = struct.unpack_from(">H", frame, 12)[0], 14
    while et in (0x8100, 0x88A8):
        et, i = struct.unpack_from(">H", frame, i + 2)[0], i + 4
    if et == 0x0800:
        ihl = (frame[i] & 15) * 4
        proto, src, dst, i = frame[i + 9], frame[i + 12:i + 16], frame[i + 16:i + 20], i + ihl
    elif et == 0x86DD:
        proto, src, dst, i = frame[i + 6], frame[i + 8:i + 24], frame[i + 24:i + 40], i + 40
    else:
        return None
    sport, dport = struct.unpack_from(">HH", frame, i)
    if proto == 17:
        return 17, src, dst, sport, dport, frame[i + 8:]
    if proto == 6:
        return 6, src, dst, sport, dport, frame[i + (frame[i + 12] >> 4) * 4:]
    return None


def write_web_corpus(corpus_dir, out):
    """Seeds for the feature 007 fuzz targets, from the web fixtures: each TCP direction as one
    stream (http/, h2/ with the selector byte of fuzz_http_message and fuzz_h2; tls/ as client and
    server of one connection, fuzz_tls), the HPACK header blocks (hpack/), JSON bodies (json/),
    JWTs (jwt/), certificates (der/), and raw payloads for the scanner's harvest (harvest/)."""
    import re
    import struct
    dirs = {k: os.path.join(corpus_dir, k) for k in ("http", "h2", "hpack", "json", "jwt", "tls", "der", "harvest")}
    for d in dirs.values():
        os.makedirs(d, exist_ok=True)
    seeds = {k: set() for k in dirs}

    def put(kind, blob):
        if blob and len(seeds[kind]) < 400:
            seeds[kind].add(bytes(blob[:1 << 20]))

    def certificates(stream):
        """X.509 certificates of the TLS 1.2 and 1.3 Certificate messages of one direction."""
        hs, off = b"", 0
        while off + 5 <= len(stream):
            t, n = stream[off], struct.unpack_from(">H", stream, off + 3)[0]
            if t == 22:
                hs += stream[off + 5:off + 5 + n]
            off += 5 + n
        off = 0
        while off + 4 <= len(hs):
            t, n = hs[off], int.from_bytes(hs[off + 1:off + 4], "big")
            body = hs[off + 4:off + 4 + n]
            if t == 11:
                for skip in (0, 1 + (body[0] if body else 0)):  # TLS 1.2; 1.3 has a context first
                    i = skip + 3
                    while i + 3 <= len(body):
                        m = int.from_bytes(body[i:i + 3], "big")
                        cert = body[i + 3:i + 3 + m]
                        if cert[:1] == b"\x30":
                            put("der", cert)
                        i += 3 + m
                        if skip:  # per-certificate extensions (RFC 8446 §4.4.2)
                            i += 2 + int.from_bytes(body[i:i + 2], "big") if i + 2 <= len(body) else 0
            off += 4 + n

    for name in sorted(os.listdir(out)):
        if not (name.startswith("web_") and name.endswith(".pcapng")):
            continue
        streams, order = {}, []
        for frame in _pcapng_frames(open(os.path.join(out, name), "rb").read()):
            l4 = _l4(frame)
            if not l4 or l4[0] != 6 or not l4[5]:
                continue
            key = l4[1:5]
            if key not in streams:
                streams[key] = b""
                order.append(key)
            streams[key] += l4[5]
            put("harvest", l4[5])
        for key in order:
            data = streams[key]
            back = streams.get((key[1], key[0], key[3], key[2]), b"")
            if data[:1] == b"\x16" and data[1:2] == b"\x03":
                if data[5:6] == b"\x01":  # the client side: seed the pair
                    put("tls", len(data[:65535]).to_bytes(2, "big") + b"\x00" + data[:65535] + back)
                certificates(data)
                continue
            server = data.startswith(b"\x00") or (len(data) >= 9 and data[3] == 4 and data[5:9] == b"\x00\x00\x00\x00")
            if data.startswith(b"PRI * HTTP/2.0") or server:
                put("h2", (b"\x01" if server else b"\x00") + data)
                off = 24 if data.startswith(b"PRI") else 0
                while off + 9 <= len(data):
                    n, t, fl = int.from_bytes(data[off:off + 3], "big"), data[off + 3], data[off + 4]
                    payload = data[off + 9:off + 9 + n]
                    if t == 1:
                        pad = payload[0] if fl & 8 and payload else 0
                        payload = payload[(1 if fl & 8 else 0) + (5 if fl & 0x20 else 0):len(payload) - pad]
                        put("hpack", payload)
                    off += 9 + n
                continue
            if re.match(rb"[A-Z]+ \S+ HTTP/1\.[01]\r\n|HTTP/1\.[01] ", data):
                put("http", (b"\x01" if data.startswith(b"HTTP/") else b"\x00") + data)
                for m in re.finditer(rb"\r\n\r\n(\{.*?\})(?=HTTP/|[A-Z]+ /|$)", data, re.S):
                    put("json", m.group(1))
            for m in re.finditer(rb"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*", data):
                put("jwt", m.group(0))
    for kind, blobs in seeds.items():
        for i, blob in enumerate(sorted(blobs)):
            with open(os.path.join(dirs[kind], f"w{i:04d}"), "wb") as fh:
                fh.write(blob)


def write_media_corpus(corpus_dir, out):
    """Seeds for the media fuzz targets, from the media fixtures: RTP packets and
    RTCP datagrams (first byte 1 under SRTP/SRTCP), APP packets (first byte: the name index),
    MSRP byte streams (one per TCP direction), SDP bodies, and harvester inputs."""
    import struct
    dirs = {k: os.path.join(corpus_dir, k) for k in ("rtp", "rtcp", "app", "msrp", "announce", "harvest")}
    for d in dirs.values():
        os.makedirs(d, exist_ok=True)
    n = 0

    def put(kind, data):
        nonlocal n
        n += 1
        with open(os.path.join(dirs[kind], f"m{n:05d}"), "wb") as fh:
            fh.write(data)

    for name in sorted(os.listdir(out)):
        stem = name.rsplit(".", 1)[0]
        if not name.endswith(".pcapng") or not stem.split("_")[0] in ("rtp", "rtcp", "app", "msrp"):
            continue
        sel = bytes([1 if stem in SECURE else 0])
        streams = {}
        for frame in _pcapng_frames(open(os.path.join(out, name), "rb").read()):
            l4 = _l4(frame)
            if not l4 or not l4[5]:
                continue
            proto, src, dst, sport, dport, p = l4
            if b"\r\n\r\nv=0" in p:
                put("announce", p.split(b"\r\n\r\n", 1)[1])
                continue
            if proto == 6:
                streams.setdefault((src, dst, sport, dport), bytearray()).extend(p)
                continue
            if sport == 5060 or dport == 5060:
                continue
            if len(p) >= 2 and 192 <= p[1] <= 223:
                put("rtcp", sel + p)
                put("harvest", p)
                i = 0
                while i + 4 <= len(p):
                    ln = 4 + 4 * struct.unpack_from(">H", p, i + 2)[0]
                    if p[i + 1] == 204 and i + 12 <= len(p):
                        nm = bytes(p[i + 8:i + 12])
                        idx = APP_NAMES.index(nm) if nm in APP_NAMES else len(APP_NAMES) - 1
                        put("app", bytes([idx]) + p[i:i + ln])
                    i += ln
            else:
                put("rtp", sel + p)
        for s in streams.values():
            put("msrp", bytes(s))
            put("harvest", bytes(s))


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--only", default="")
    ap.add_argument("--corpus")
    ap.add_argument("--packet-corpus")
    ap.add_argument("--sip-corpus", help="write the SIP messages of the SIP fixtures, one per file")
    ap.add_argument("--sdp-corpus", help="write the SDP bodies of those messages, one per file")
    ap.add_argument("--media-corpus", help="write the seeds of the media fuzz targets under this directory")
    ap.add_argument("--web-corpus", help="write the seeds of the feature 007 fuzz targets under this directory")
    ap.add_argument("--mikey-corpus", help="write the seed I_MESSAGEs of the MIKEY fuzz targets, one per file")
    ap.add_argument("--xml-corpus", help="write the XML bodies of the XML fixtures and the seed documents, one per file")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    only = [s for s in args.only.split(",") if s]
    unknown = [s for s in only if s not in SETS]
    if unknown:
        print(f"unknown fixture set(s): {', '.join(unknown)}; known: {', '.join(SETS)}",
              file=sys.stderr)
        return 2
    c = canary_mod.Canaries(args.seed)
    for name, fn in SETS.items():
        if not only or name in only:
            fn(c, args.out)
    c.write(os.path.join(args.out, "canaries.json"))
    if args.corpus:
        write_corpus(args.corpus, args.out)
    if args.packet_corpus:
        write_packet_corpus(args.packet_corpus, args.out)
    if args.media_corpus:
        write_media_corpus(args.media_corpus, args.out)
    if args.xml_corpus:
        os.makedirs(args.xml_corpus, exist_ok=True)
        for i, body in enumerate(xmlbodies.BODIES + xmlbodies.seed_documents()):
            with open(os.path.join(args.xml_corpus, f"x{i:04d}"), "wb") as fh:
                fh.write(body)
    if args.web_corpus:
        write_web_corpus(args.web_corpus, args.out)
    if args.mikey_corpus:
        os.makedirs(args.mikey_corpus, exist_ok=True)
        for i, m in enumerate(mikey.corpus()):
            with open(os.path.join(args.mikey_corpus, f"k{i:03d}"), "wb") as fh:
                fh.write(m)
    if args.sip_corpus or args.sdp_corpus:
        msgs, _ = sip.ladder_udp(canary_mod.Canaries(args.seed), "corpus")
        for i, m in enumerate(msgs):
            if args.sip_corpus:
                os.makedirs(args.sip_corpus, exist_ok=True)
                with open(os.path.join(args.sip_corpus, f"m{i:03d}"), "wb") as fh:
                    fh.write(m)
            body = m.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in m else b""
            if args.sdp_corpus and body.startswith(b"v=0"):
                os.makedirs(args.sdp_corpus, exist_ok=True)
                with open(os.path.join(args.sdp_corpus, f"s{i:03d}"), "wb") as fh:
                    fh.write(body)
    return 0


if __name__ == "__main__":
    sys.exit(main())

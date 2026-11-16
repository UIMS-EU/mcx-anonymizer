#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Protocol integrity: the output must not have more Error-level
expert entries (malformed packets, bad checksums, bad lengths) than the input,
per protocol and kind, for the protocols the tool rewrites.

With --payload zero, every frame that the input decodes as RTP through an SDP-set-up
conversation must still be decoded as RTP in the output (SC-004). Zero mode
keeps every packet and its number, so the frame numbers are compared; drop mode removes the
zeroed media and is not checked. --no-rtp skips the check for inputs whose SDP is zeroed on
purpose (fail-closed fixtures).

With --media (feature 004), RTP and RTCP are compared too, since the tool now rewrites them,
and the RTP check applies in both payload modes: media packets are kept in drop mode as well.
Codec payloads (AMR, EVS, H.264, ...) are zeroed by design (FR-007): their dissectors report
the zeroed frames as malformed under the RTP protocol, so they are disabled for the comparison
of both files (CODECS), and the RTP header and RTCP stay compared.

With --xml (feature 003), XML is compared too, and every SIP frame whose input carries XML that
tshark decodes keeps at least as many XML layers in the output, unless the tool emptied the
top-level body (Content-Length 0). An emptied multipart part has a CRLF body (002 I2), which
tshark still shows as XML. Types tshark does not decode (8 of the 30) have no XML
layer in either file; the expat oracle (tests/integration/xml_structure.py) covers them.

tshark is used as an external test tool only; it is never linked.
Usage: tshark-expert-diff.py INPUT OUTPUT [--payload zero|drop] [--no-rtp] [--media] [--xml] [--mikey]
Exit: 0 ok, 1 new errors or lost RTP set-up, 77 tshark not installed (unless
MCXANON_REQUIRE_TSHARK=1).
"""
import argparse
import collections
import os
import re
import shutil
import subprocess
import sys


# Checksum validation is off by default in Wireshark; turn it on so that a
# wrongly recomputed checksum shows up as a new error.
PREFS = ["-o", "ip.check_checksum:TRUE", "-o", "tcp.check_checksum:TRUE",
         "-o", "udp.check_checksum:TRUE", "-o", "sctp.checksum:crc32c",
         "-o", "eth.check_fcs:TRUE"]
# covers the layers the tool rewrites: L2-L4 and tunnels (feature 001), and the
# SIP family it parses and re-serialises (feature 002). Other payloads are zeroed or dropped
# by design, so their dissectors (M3UA, Diameter, RTP, ...) and link types the tool does not
# understand (radiotap) may report a zeroed payload as malformed; those are not compared.
REWRITTEN = {"frame", "eth", "ethernet", "vlan", "ieee 802.1q", "ieee 802.1ad", "sll", "linux sll",
             "linux sllv2", "null", "raw", "arp", "arp/rarp", "ipv4", "ip", "ipv6", "icmp", "icmpv6",
             "tcp", "udp", "sctp", "gre", "gtp", "gtpv1-u", "gtp-u",
             "sip", "sdp", "msrp", "mime multipart", "multipart"}
# A TCP or IP reassembly error is reported under the protocol on top of the reassembled data,
# so it is compared whatever that protocol is: the tool re-segments and re-fragments SIP.
REASSEMBLY = re.compile(r"reassembl", re.IGNORECASE)
# "   Frequency      Group           Protocol  Summary": columns are separated by two spaces;
# a protocol name may contain a single space ("MIME multipart", "802.11 Radiotap").
ROW = re.compile(r"^\s+(\d+)\s+(\S+)\s+(\S(?:\S| (?! ))*)  (.*?)\s*$")
SECTIONS = ("Errors", "Warns", "Notes", "Chats", "Comments")


MEDIA = {"rtp", "rtcp", "srtp", "srtcp"}
compare_media = False
compare_xml = False
compare_mikey = False


def compared(group, proto, summary):
    return (proto.lower() in REWRITTEN or (compare_media and proto.lower() in MEDIA)
            or (compare_xml and proto.lower() == "xml") or (compare_mikey and proto.lower() == "mikey")
            or group.lower() == "reassemble"
            or REASSEMBLY.search(summary) is not None)


def parse_expert(text):
    """Counter of (group, protocol, normalised summary) for the Errors section."""
    counts = collections.Counter()
    in_errors = False
    for line in text.splitlines():
        if line.startswith(SECTIONS):
            in_errors = line.startswith("Errors")
            continue
        m = ROW.match(line) if in_errors else None
        if m and compared(m.group(2), m.group(3), m.group(4)):
            summary = re.sub(r"\[[^]]*\]|0x[0-9a-fA-F]+|\d+", "#", m.group(4)).strip()
            counts[(m.group(2), m.group(3), summary)] += int(m.group(1))
    return counts


def tshark(*args):
    r = subprocess.run(["tshark", "-n", *args], capture_output=True, text=True)
    if r.returncode not in (0, 2):
        raise RuntimeError(r.stderr)
    return r.stdout


# Payload dissectors of the codecs met in MCX captures (AMR-WB for MCPTT, EVS, H.264/H.265 for
# MCVideo, and others a lab may use).
CODECS = ("amr", "evs", "h264", "h265", "h263", "mp4ves", "vp8", "vp9", "iuup")


def zeroed_frames(inp, out):
    """Frames whose output UDP payload is zero after its first 12 octets (an RTCP header, SSRC
    and APP name) while the input's was not: content the tool zeroed on purpose (fail-closed:
    the SRTCP view, an unknown APP subtype). Their dissectors report the zeros as malformed, as
    for any zeroed payload, so these frames are not compared."""
    def payloads(path):
        r = tshark("-r", path, "-T", "fields", "-e", "frame.number", "-e", "frame.protocols", "-e", "udp.payload")
        rows = {}
        for line in r.splitlines():
            c = line.split("\t")
            # RTCP frames only: an RTP frame's zeroed payload is compared with the codec
            # dissectors disabled, so its header errors still count.
            if len(c) > 2 and c[2] and ("rtcp" in c[1].split(":") or "srtcp" in c[1].split(":")):
                rows[c[0]] = bytes.fromhex(c[2].split(",")[-1].replace(":", ""))
        return rows
    a, b = payloads(inp), payloads(out)
    return sorted((f for f, p in b.items()
                   if len(p) > 12 and not any(p[12:]) and any(a.get(f, b"")[12:])), key=int)


def expert_errors(path, skip=()):
    extra = []
    if compare_media:
        listing = subprocess.run(["tshark", "-G", "protocols"], capture_output=True, text=True).stdout
        known = {line.split("\t")[2] for line in listing.splitlines() if line.count("\t") >= 2}
        for c in CODECS:
            if c in known:
                extra += ["--disable-protocol", c]
    stat = "expert,error"
    if skip:
        stat += ",!(" + " || ".join(f"frame.number=={f}" for f in skip) + ")"
    return parse_expert(tshark("-r", path, *PREFS, *extra, "-q", "-z", stat))


def rtp_frames(path):
    """Frame numbers decoded as RTP. Without a heuristic RTP dissector (the default), a UDP
    frame is RTP only through a conversation that an SDP offer or answer has set up."""
    out = tshark("-r", path, "-T", "fields", "-e", "frame.number", "-e", "frame.protocols")
    # RTP quoted inside an ICMP error is ICMP data, which feature 001 zeroes or drops.
    return {int(f[0]) for f in (line.split("\t") for line in out.splitlines())
            if len(f) >= 2 and ":rtp" in f[1] and ":icmp" not in f[1]}


def rtp_lost(before, after):
    return before - after


def xml_layers(path):
    """frame number -> (XML layer count, top-level SIP Content-Length or None)."""
    out = tshark("-r", path, "-T", "fields", "-E", "occurrence=l", "-e", "frame.number", "-e", "frame.protocols",
                 "-e", "sip.Content-Length")
    rows = {}
    for line in out.splitlines():
        c = line.split("\t") + ["", ""]
        layers = c[1].split(":")
        # XML bodies of SIP only: XML over HTTP (XCAP) is zeroed by design until feature 007.
        rows[int(c[0])] = (layers.count("xml") if "sip" in layers else 0, c[2] or None)
    return rows


def xml_lost(inp, out):
    a, b = xml_layers(inp), xml_layers(out)
    return sorted(f for f, (n, _) in a.items()
                  if n and f in b and b[f][1] != "0" and b[f][0] < n)


def mikey_layers(path):
    """frame number -> number of MIKEY layers tshark decodes."""
    out = tshark("-r", path, "-T", "fields", "-e", "frame.number", "-e", "frame.protocols")
    rows = {}
    for line in out.splitlines():
        c = line.split("\t") + [""]
        rows[int(c[0])] = c[1].split(":").count("mikey")
    return rows


def mikey_lost(inp, out):
    """Frames where the output has fewer MIKEY layers than the input (feature 005, --mikey)."""
    a, b = mikey_layers(inp), mikey_layers(out)
    return sorted(f for f, n in a.items() if n and b.get(f, 0) < n)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("output")
    ap.add_argument("--payload", choices=("zero", "drop"))
    ap.add_argument("--no-rtp", action="store_true")
    ap.add_argument("--media", action="store_true")
    ap.add_argument("--xml", action="store_true")
    ap.add_argument("--mikey", action="store_true")
    args = ap.parse_args()
    global compare_media, compare_xml, compare_mikey
    compare_mikey = args.mikey
    compare_media = args.media
    compare_xml = args.xml
    if shutil.which("tshark") is None:
        if os.environ.get("MCXANON_REQUIRE_TSHARK") == "1":
            print("tshark is required but not installed", file=sys.stderr)
            return 1
        print("tshark not installed: skipped", file=sys.stderr)
        return 77
    skip = zeroed_frames(args.input, args.output) if args.media else []
    if skip:
        print(f"{len(skip)} frames zeroed by design after the RTCP header are not compared")
    before, after = expert_errors(args.input, skip), expert_errors(args.output, skip)
    worse = {k: (before.get(k, 0), v) for k, v in after.items() if v > before.get(k, 0)}
    for k, (b, a) in sorted(worse.items()):
        print(f"new expert entries {k}: {b} -> {a}")
    lost = set()
    if (args.payload == "zero" or args.media) and not args.no_rtp:
        want = rtp_frames(args.input)
        lost = rtp_lost(want, rtp_frames(args.output))
        if lost:
            print(f"SDP-set-up RTP lost in {len(lost)} of {len(want)} frames: {sorted(lost)[:20]}")
        else:
            print(f"SDP-set-up RTP kept in {len(want)} frames")
    xml_gone = xml_lost(args.input, args.output) if args.xml else []
    if xml_gone:
        print(f"XML no longer decoded in {len(xml_gone)} frames: {xml_gone[:20]}")
    mikey_gone = mikey_lost(args.input, args.output) if args.mikey else []
    if mikey_gone:
        print(f"MIKEY no longer decoded in {len(mikey_gone)} frames: {mikey_gone[:20]}")
    return 1 if worse or lost or xml_gone or mikey_gone else 0


if __name__ == "__main__":
    sys.exit(main())

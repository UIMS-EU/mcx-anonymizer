#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""The MIKEY-SAKKE oracle of feature 005.

usage: mikey_consistency.py INPUT OUTPUT [--canaries MANIFEST] [--time-shift-s N] [--passthrough]
                            [--expect N]

Extracts the MIKEY messages of the SIP carriers (SDP a=key-mgmt at any level, application/mikey
bodies and parts, binary or base64, <GKTP> hexBinary in XML parts) of both captures with its own
decoder, which shares no code with the tool, and pairs them in order. For each pair it checks what
the MIKEY rule set keeps and what it changes:

- the same header fields (version, data type, V, PRF, #CS, map type, CS IDs, protocol types,
  policies), the same payload chain, the same T type (value equal, or shifted by --time-shift-s),
  the same RAND length, the same IDR roles and types, the same SP parameter types and kept values,
  the same SAKKE parameters, ID scheme and data (ciphertext mode), the same SIGN type and length;
- the CSB ID and SPI words keep their purpose tag and change; RAND changes; the signature is zero;
- every pseudonymised value maps one to one across all pairs (one pseudonym per original);
- with --canaries, no canary value occurs in any decoded output message;
- with --passthrough, every output message equals its input.

tshark is used where it decodes MIKEY (session-level a=key-mgmt and binary bodies; tshark 4.4.19
decodes neither base64 bodies, media-level attributes, GENERIC-ID maps nor extension contents): the
frames with a decoded MIKEY layer and their kept mikey.* values must match, except an input body
whose version is not 1 (the tool empties it). Exit status 0 when every
check passes, 1 otherwise.
"""
import argparse
import base64
import binascii
import json
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from sip_messages import _frames, _l4, header, messages  # noqa: E402

failures = []


def check(cond, what):
    if not cond:
        failures.append(what)
        print("FAIL " + what)


# --- an independent MIKEY decoder (RFC 3830 §6, RFC 6043 §6, RFC 6509 §4) -----------------
def decode(b):
    if len(b) < 10 or b[0] != 1:
        return None
    m = {"version": b[0], "data_type": b[1], "v": b[3] >> 7, "prf": b[3] & 0x7F,
         "csb": int.from_bytes(b[4:8], "big"), "cs": b[8], "map": b[9], "blocks": [], "payloads": []}
    i = 10
    if m["cs"] and m["map"] == 2:
        for _ in range(m["cs"]):
            cs_id, prot, sp = b[i], b[i + 1], b[i + 2]
            np = sp & 0x7F
            pol = list(b[i + 3:i + 3 + np])
            i += 3 + np
            sl = int.from_bytes(b[i:i + 2], "big")
            sess = b[i + 2:i + 2 + sl]
            i += 2 + sl
            spl = b[i]
            spi = b[i + 1:i + 1 + spl]
            i += 1 + spl
            m["blocks"].append({"cs_id": cs_id, "prot": prot, "s": sp >> 7, "policies": pol, "session": sess, "spi": spi})
    nxt = b[2]
    while nxt:
        if nxt == 4:
            w = int.from_bytes(b[i:i + 2], "big")
            m["payloads"].append(("SIGN", {"s_type": w >> 12, "sig": b[i + 2:i + 2 + (w & 0xFFF)]}))
            i += 2 + (w & 0xFFF)
            break
        following = b[i]
        i += 1
        if nxt == 5:
            ln = 4 if b[i] == 2 else 8
            m["payloads"].append(("T", {"ts_type": b[i], "value": b[i + 1:i + 1 + ln]}))
            i += 1 + ln
        elif nxt == 11:
            ln = b[i]
            m["payloads"].append(("RAND", {"rand": b[i + 1:i + 1 + ln]}))
            i += 1 + ln
        elif nxt == 14:
            ln = int.from_bytes(b[i + 2:i + 4], "big")
            m["payloads"].append(("IDR", {"role": b[i], "type": b[i + 1], "data": b[i + 4:i + 4 + ln]}))
            i += 4 + ln
        elif nxt == 10:
            ln = int.from_bytes(b[i + 2:i + 4], "big")
            params, j = [], i + 4
            while j < i + 4 + ln:
                params.append((b[j], b[j + 2:j + 2 + b[j + 1]]))
                j += 2 + b[j + 1]
            m["payloads"].append(("SP", {"policy": b[i], "prot": b[i + 1], "params": params}))
            i += 4 + ln
        elif nxt == 26:
            ln = int.from_bytes(b[i + 2:i + 4], "big")
            m["payloads"].append(("SAKKE", {"params": b[i], "scheme": b[i + 1], "data": b[i + 4:i + 4 + ln]}))
            i += 4 + ln
        elif nxt == 21:
            ln = int.from_bytes(b[i + 1:i + 3], "big")
            m["payloads"].append(("EXT", {"type": b[i], "data": b[i + 3:i + 3 + ln]}))
            i += 3 + ln
        else:
            return None
        nxt = following
    if i != len(b):
        return None
    return m


# --- carriers --------------------------------------------------------------------------------
def b64(text):
    try:
        return base64.b64decode(re.sub(rb"[\r\n]", b"", text), validate=True)
    except (binascii.Error, ValueError):
        return None


SKIPPED = []  # the input paths of application/mikey bodies whose version is not 1


def carriers(path):
    """[(carrier, bytes)] in capture order."""
    out = []
    for msg in messages(path):
        for part in msg.parts:
            ct = (part.content_type or "").split(";")[0].strip().lower()
            if ct == "application/sdp":
                for line in part.body.split(b"\r\n"):
                    mm = re.match(rb"a=key-mgmt: ?mikey (\S+)", line)
                    if mm:
                        d = b64(mm.group(1))
                        if d:
                            out.append(("sdp", d))
            elif ct == "application/mikey":
                # RFC 3830 §10.1: a version other than 1 is not this MIKEY (the tool falls back).
                full = (header(part.headers, "content-type") if part.headers else header(msg.headers, "content-type")) or ""
                ver = re.search(r";\s*version\s*=\s*\"?([^\s;\"]+)", full, re.I)
                if ver and ver.group(1) != "1":
                    SKIPPED.append(path)
                    continue
                body = part.body
                d = b64(body) if re.fullmatch(rb"[A-Za-z0-9+/=\r\n]+", body or b"-") else None
                cand = d if d and decode(d) else body
                if cand and decode(cand):
                    out.append(("body", cand))
            elif ct.endswith("+xml"):
                for mm in re.finditer(rb"<(?:[\w.-]+:)?GKTP\b[^>]*>\s*([0-9A-Fa-f]+)\s*<", part.body):
                    try:
                        d = bytes.fromhex(mm.group(1).decode())
                    except ValueError:
                        continue
                    if decode(d):
                        out.append(("gktp", d))
    return out


def mcpc_fields(path):
    """[(form, value)] of every MCPC field 192 (TS 24.380 §8.3.3.10) in RTCP APP packets."""
    out = []
    for frame in _frames(open(path, "rb").read()):
        l4 = _l4(frame)
        if not l4 or l4[0] != 17:
            continue
        p = l4[6]
        i = 0
        while i + 12 <= len(p) and p[i] >> 6 == 2:
            ln = (int.from_bytes(p[i + 2:i + 4], "big") + 1) * 4
            if p[i + 1] == 204 and p[i + 8:i + 12] == b"MCPC":
                j, end = i + 12, min(i + ln, len(p))
                while j + 2 <= end:
                    fid = p[j]
                    h = 3 if fid >= 192 else 2
                    if j + h > end:
                        break
                    fl = int.from_bytes(p[j + 1:j + 3], "big") if fid >= 192 else p[j + 1]
                    val = p[j + h:j + h + fl]
                    if fid == 192:
                        out.append(val)
                    j += (h + fl + 3) // 4 * 4
            i += ln
    return out


def mcpc_carriers(path):
    out = []
    for val in mcpc_fields(path):
        d = b64(val) if re.fullmatch(rb"[A-Za-z0-9+/=]+", val or b"-") else None
        cand = d if d and decode(d) else val
        if decode(cand):
            out.append(("mcpc", cand))
    return out


# --- tshark ----------------------------------------------------------------------------------
def tshark_fields(path):
    exe = shutil.which("tshark")
    if not exe:
        return None
    names = ["frame.number", "mikey.type", "mikey.t.ts_type", "mikey.id.role", "mikey.id.type", "mikey.sakke.len",
             "mikey.sign.type", "mikey.sign.len", "mikey.rand.len"]
    cmd = [exe, "-r", path, "-T", "fields", "-E", "occurrence=a", "-E", "aggregator=|"]
    for n in names:
        cmd += ["-e", n]
    r = subprocess.run(cmd, capture_output=True, text=True)
    rows = {}
    for line in r.stdout.splitlines():
        frame, _, rest = line.partition("\t")
        if rest.strip("\t|"):
            rows[frame] = rest
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("output")
    ap.add_argument("--canaries")
    ap.add_argument("--time-shift-s", type=int, default=0)
    ap.add_argument("--passthrough", action="store_true")
    ap.add_argument("--expect", type=int)
    a = ap.parse_args()
    ins, outs = carriers(a.input) + mcpc_carriers(a.input), carriers(a.output) + mcpc_carriers(a.output)
    check(len(ins) == len(outs), f"{len(ins)} MIKEY messages in, {len(outs)} out")
    if a.expect is not None:
        check(len(outs) == a.expect, f"{a.expect} MIKEY messages expected, {len(outs)} found")
    fwd, back = {}, {}

    def pair(kind, orig, pseudo):
        k = (kind, bytes(orig))
        v = (kind, bytes(pseudo))
        check(fwd.setdefault(k, v) == v, f"{kind}: one original, two pseudonyms")
        check(back.setdefault(v, k) == k, f"{kind}: one pseudonym, two originals")

    for n, ((ck, ib), (ok, ob)) in enumerate(zip(ins, outs)):
        w = f"message {n + 1} ({ck})"
        check(ck == ok, f"{w}: carrier {ck} became {ok}")
        if a.passthrough:
            check(ib == ob, f"{w}: passthrough changed the message")
            continue
        i, o = decode(ib), decode(ob)
        if i is None or o is None:
            check(False, f"{w}: does not decode")
            continue
        for f in ("version", "data_type", "v", "prf", "cs", "map"):
            check(i[f] == o[f], f"{w}: header {f} changed")
        check(i["csb"] >> 28 == o["csb"] >> 28 and i["csb"] != o["csb"], f"{w}: CSB ID purpose tag / pseudonym")
        pair("key-id", i["csb"].to_bytes(4, "big"), o["csb"].to_bytes(4, "big"))
        check(len(i["blocks"]) == len(o["blocks"]), f"{w}: GENERIC-ID blocks")
        for bi, bo in zip(i["blocks"], o["blocks"]):
            for f in ("cs_id", "prot", "s", "policies"):
                check(bi[f] == bo[f], f"{w}: CS block {f} changed")
            check(len(bi["spi"]) == len(bo["spi"]), f"{w}: SPI length")
            for k in range(0, len(bi["spi"]) - len(bi["spi"]) % 4 if len(bi["spi"]) in (4, 8) else 0, 4):
                iw, ow = bi["spi"][k:k + 4], bo["spi"][k:k + 4]
                check(iw[0] >> 4 == ow[0] >> 4 and iw != ow, f"{w}: SPI word purpose tag / pseudonym")
                pair("key-id", iw, ow)
        check([p[0] for p in i["payloads"]] == [p[0] for p in o["payloads"]], f"{w}: payload chain changed")
        for (kind, pi), (_, po) in zip(i["payloads"], o["payloads"]):
            if kind == "T":
                check(pi["ts_type"] == po["ts_type"], f"{w}: T type")
                if pi["ts_type"] in (0, 1):
                    iv, ov = int.from_bytes(pi["value"], "big"), int.from_bytes(po["value"], "big")
                    check(((ov >> 32) - (iv >> 32)) % (1 << 32) == a.time_shift_s % (1 << 32) and
                          (ov & 0xFFFFFFFF) == (iv & 0xFFFFFFFF), f"{w}: T shifted by {a.time_shift_s} s")
                else:
                    check(pi["value"] == po["value"], f"{w}: T counter kept")
            elif kind == "RAND":
                check(len(pi["rand"]) == len(po["rand"]) and pi["rand"] != po["rand"], f"{w}: RAND same length, changed")
                pair("nonce", pi["rand"], po["rand"])
            elif kind == "IDR":
                check((pi["role"], pi["type"]) == (po["role"], po["type"]), f"{w}: IDR role/type")
                check(pi["data"] != po["data"], f"{w}: IDR role {pi['role']} data unchanged")
                if any(po["data"]):
                    pair(f"idr-{pi['role'] in (3, 6, 7)}", pi["data"], po["data"])
            elif kind == "SP":
                check((pi["policy"], pi["prot"]) == (po["policy"], po["prot"]), f"{w}: SP header")
                check([t for t, _ in pi["params"]] == [t for t, _ in po["params"]], f"{w}: SP parameter types")
            elif kind == "SAKKE":
                check(pi == po, f"{w}: SAKKE payload changed (ciphertext mode keeps it)")
            elif kind == "EXT":
                check(pi["type"] == po["type"] and len(pi["data"]) == len(po["data"]), f"{w}: extension type/length")
            elif kind == "SIGN":
                check(pi["s_type"] == po["s_type"] and len(pi["sig"]) == len(po["sig"]), f"{w}: SIGN type/length")
                check(not any(po["sig"]), f"{w}: signature not zeroed")
    if a.canaries:
        # Only the canaries planted in the input: a short canary of another fixture can occur by
        # chance inside the hex digits of a pseudonym (finding F1).
        src = os.path.basename(a.input)
        cans = [c for c in json.load(open(a.canaries))["canaries"]
                if src in c.get("files", [src]) and not c.get("chance")]
        blob = b"".join(ob for _, ob in outs)
        for c in cans:
            v = c["value"]
            forms = []
            if c["category"] == "string":
                forms = [v.encode(), v.lower().encode()]
            elif c["category"] == "bytes":
                forms = [bytes.fromhex(v)]
            elif c["category"] == "binary" and str(c.get("rule", "")).startswith("mikey:"):
                forms = [int(v).to_bytes(4, "big")]
            for f in forms:
                check(len(f) < 4 or f not in blob, f"canary {c['id']} ({c.get('rule')}) inside a decoded output MIKEY message")
    ti, to = tshark_fields(a.input), tshark_fields(a.output)
    if ti is not None and to is not None:
        # A body whose version is not 1 falls back (emptied), but tshark decodes it in the input.
        gone = [f for f in ti if f not in to]
        check(all(f in ti for f in to) and len(gone) == SKIPPED.count(a.input),
              f"tshark: {len(ti)} frames with MIKEY in, {len(to)} out, {SKIPPED.count(a.input)} version fallbacks")
        for f, lo in to.items():
            if f in ti:
                check(ti[f] == lo, f"tshark: frame {f}: kept MIKEY fields differ: {ti[f]!r} -> {lo!r}")
    print(f"mikey-consistency: {len(outs)} messages, {len(fwd)} pseudonymised values, "
          f"{len(failures)} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

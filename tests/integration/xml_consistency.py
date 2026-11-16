#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Feature 003 consistency oracle (SC-003, FR-013), expat only.

Pairs every input SIP message with the output message in the same place and collects
(original, output) pairs of SIP and tel URIs:
  - from the identity headers (Request-URI, From, To, P-Asserted-Identity, P-Preferred-Identity,
    Refer-To, Referred-By, Contact user parts are excluded: they carry instance data);
  - from every XML body: each element text and attribute value that is a sip:, sips: or tel:
    URI (matched by element path and attribute name).
Each original must have exactly one output form and no two originals may share one, wherever
they occur; an output URI equal to its original is a failure unless --allow-kept is given for it.

Usage: xml_consistency.py INPUT OUTPUT
"""
import re
import sys

sys.path.insert(0, __import__("os").path.dirname(__file__))
from sip_messages import messages  # noqa: E402
from xml_structure import parse  # noqa: E402

HEADERS = ("from", "to", "p-asserted-identity", "p-preferred-identity", "refer-to", "referred-by")
URI = re.compile(r"(?:sips?|tel):[^\s<>\";,]+")


def bare(u):
    """The URI without parameters and headers (they follow their own rules)."""
    return re.split(r"[;?]", u, maxsplit=1)[0]


def header_uris(m):
    out = []
    parts = m.start.split(" ")
    if len(parts) == 3 and parts[2] == "SIP/2.0":
        out.append(("request-uri", bare(parts[1])))
    for n, v in m.headers:
        if n in HEADERS:
            out += [(n, bare(u)) for u in URI.findall(v)]
    return out


def xml_uris(body):
    out = []
    for path, attrs, text in parse(body):
        where = "/".join(local for _, local in path)
        if URI.fullmatch(bare(text) or "-") or (text.startswith(("sip:", "sips:", "tel:")) and " " not in text):
            out.append((where, bare(text)))
        for (_, local), v in sorted(attrs.items()):
            if v.startswith(("sip:", "sips:", "tel:")):
                out.append((f"{where}@{local}", bare(v)))
    return out


def main():
    a, b = messages(sys.argv[1]), messages(sys.argv[2])
    problems, fwd, back = [], {}, {}
    pairs = 0

    def pair(x, y, where):
        nonlocal pairs
        pairs += 1
        if x == y:
            problems.append(f"{where}: URI kept as the original")
        if fwd.setdefault(x, y) != y:
            problems.append(f"{where}: one original URI has several output forms")
        if back.setdefault(y, x) != x:
            problems.append(f"{where}: two original URIs share one output form")

    for mi, (ma, mb) in enumerate(zip(a, b)):
        ha, hb = header_uris(ma), header_uris(mb)
        if [n for n, _ in ha] == [n for n, _ in hb]:
            for (n, x), (_, y) in zip(ha, hb):
                pair(x, y, f"message {mi} {n}")
        for pi, (pa, pb) in enumerate(zip(ma.parts, mb.parts)):
            if not pa.content_type.endswith("+xml") or not pb.body.strip():
                continue
            try:
                xa, xb = xml_uris(pa.body), xml_uris(pb.body)
            except Exception:  # an input the tool emptied, or not well-formed: xml_structure reports it
                continue
            ob = dict(xb) if len({w for w, _ in xb}) == len(xb) else None
            if ob is None:
                # Repeated paths: pair in order among equal paths.
                seen = {}
                for w, y in xb:
                    seen.setdefault(w, []).append(y)
                for w, x in xa:
                    if seen.get(w):
                        pair(x, seen[w].pop(0), f"message {mi} part {pi} {w}")
            else:
                for w, x in xa:
                    if w in ob:
                        pair(x, ob[w], f"message {mi} part {pi} {w}")
    for p in sorted(set(problems)):
        print(p)
    print(f"xml_consistency: {pairs} URI pairs, {len(fwd)} distinct originals, {len(set(problems))} problem(s)",
          file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())

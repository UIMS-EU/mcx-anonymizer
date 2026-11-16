#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Feature 003 structure oracle (SC-002, SC-004, FR-010, FR-022), expat only.

For every XML body of the input and the body in the same place of the output (message and part
order are kept by the tool):
  - an emptied output body (empty, or CRLF in multipart) is accepted (its reason is in the
    report); otherwise the output parses with xml.parsers.expat, namespaces resolved;
  - the output's element paths (namespace, local name from the root) are the input's minus
    removed subtrees, in order (a subsequence), and each output element's attributes are a
    subset of the input element's;
  - kept values are equal: an element text or attribute value may differ only where the canary
    manifest names a rule for that (namespace, local name), i.e. a rule that does not keep it
    (rule keys xml:<ns>|<parent>|<local>, xml:<ns>|<element>|@<attr ns>|<attr>), or where it is
    inside an element whose local name has such a rule as a container of pseudonymised parts;
  - the markup is the input's minus removed items: the output's tags (names, attribute names,
    empty-tag form) are a subsequence of the input's.

Usage: xml_structure.py INPUT OUTPUT CANARIES.json[,CANARIES2.json...] [--types T1,T2,...]
(several manifests: the rule keys of all of them count, e.g. the demo's and the XML fixtures').
Prints one line per problem; exit 1 when there is one.
"""
import json
import re
import sys
import xml.parsers.expat as expat

sys.path.insert(0, __import__("os").path.dirname(__file__))
from sip_messages import messages  # noqa: E402


def parse(body):
    """[(path, attrs{(ns, local): value}, text)] in document order, or raises."""
    out, stack, texts = [], [], []
    p = expat.ParserCreate(namespace_separator=" ")

    def split(name):
        ns, _, local = name.rpartition(" ")
        return ns, local

    def start(name, attrs):
        stack.append(split(name))
        out.append([tuple(stack), {split(k): v for k, v in attrs.items()}, ""])
        texts.append(len(out) - 1)

    def end(name):
        stack.pop()
        texts.pop()

    def data(t):
        if texts:
            out[texts[-1]][2] += t

    p.StartElementHandler, p.EndElementHandler, p.CharacterDataHandler = start, end, data
    p.Parse(body, True)
    return [(a, b, c.strip()) for a, b, c in out]


TOKEN = re.compile(rb"<!--.*?-->|<\?.*?\?>|<!\[CDATA\[.*?\]\]>|<[^>]*>|[^<]+", re.S)
ATTR = re.compile(rb"""([^\s=/>]+)\s*=\s*("[^"]*"|'[^']*')""")


def skeleton(body):
    """Markup tokens: tags as (name, attribute names), whitespace text as itself, other text as T."""
    out = []
    for m in TOKEN.finditer(body):
        t = m.group(0)
        if t.startswith(b"<!--") or t.startswith(b"<?") or t.startswith(b"<![CDATA["):
            out.append(("other", t[:4]))
        elif t.startswith(b"<"):
            name = re.match(rb"</?\s*([^\s/>]+)", t)
            out.append(("tag", t[:2] == b"</", name.group(1) if name else b"", tuple(a for a, _ in ATTR.findall(t)),
                        t.rstrip().endswith(b"/>")))
        elif t.strip():
            out.append(("text",))
        else:
            out.append(("ws", t))
    return out


def tag_fits(a, b):
    """Output tag b is input tag a with attributes possibly removed."""
    if a[0] != "tag" or b[0] != "tag" or a[1:3] != b[1:3] or a[4] != b[4]:
        return False
    it = iter(a[3])
    return all(x in it for x in b[3])


def subsequence(inp, out, fits):
    i = 0
    for y in out:
        while i < len(inp) and not fits(inp[i], y):
            i += 1
        if i == len(inp):
            return False
        i += 1
    return True


def main():
    inp, outp, manifest = sys.argv[1:4]
    types = None
    if "--types" in sys.argv:
        types = set(sys.argv[sys.argv.index("--types") + 1].split(","))
    changed_el, changed_attr = set(), set()
    canaries = [c for m in manifest.split(",") for c in json.load(open(m))["canaries"]]
    for c in canaries:
        for key in [c.get("rule", "")] + c.get("also", []):
            if not key.startswith("xml:"):
                continue
            parts = key[4:].split("|")
            if len(parts) == 3:
                changed_el.add((parts[0], parts[2]))
            elif len(parts) == 4:  # <ns>|<element>|@<attr ns or ->|<attr>
                changed_attr.add(("" if parts[2] == "@-" else parts[2][1:], parts[3]))
    a_msgs, b_msgs = messages(inp), messages(outp)
    problems = []
    if len(a_msgs) != len(b_msgs):
        problems.append(f"message count differs: {len(a_msgs)} in, {len(b_msgs)} out")
    bodies = 0
    for mi, (ma, mb) in enumerate(zip(a_msgs, b_msgs)):
        if len(ma.parts) != len(mb.parts):
            problems.append(f"message {mi}: part count differs")
            continue
        for pi, (pa, pb) in enumerate(zip(ma.parts, mb.parts)):
            if not pa.content_type.endswith("+xml") or (types and pa.content_type not in types):
                continue
            where = f"message {mi} part {pi} ({pa.content_type})"
            if pb.body.strip() == b"":
                continue  # emptied, counted in the report
            bodies += 1
            try:
                ea, eb = parse(pa.body), parse(pb.body)
            except expat.ExpatError as e:
                problems.append(f"{where}: output is not well-formed XML ({e})")
                continue
            # Element paths: a subsequence; attributes: a subset; values: equal unless changeable.
            i = 0
            for path, attrs, text in eb:
                while i < len(ea) and ea[i][0] != path:
                    i += 1
                if i == len(ea):
                    problems.append(f"{where}: output element {path[-1]} not in the input in this order")
                    break
                ia, iattrs, itext = ea[i]
                i += 1
                ns, local = path[-1]
                for k, v in attrs.items():
                    if k not in iattrs:
                        problems.append(f"{where}: attribute {k} of {local} is not in the input")
                    elif v != iattrs[k] and k not in changed_attr:
                        problems.append(f"{where}: kept attribute {local}@{k[1]} changed")
                children = any(len(q) > len(path) and q[:len(path)] == path for q, _, _ in eb)
                if not children and text != itext and (ns, local) not in changed_el and text != "" and itext != "":
                    problems.append(f"{where}: kept value of {local} changed ({itext[:20]!r} -> {text[:20]!r})")
            # Tags only (names, attribute names, empty-tag form): values are compared above.
            tags = lambda body: [t for t in skeleton(body) if t[0] == "tag"]  # noqa: E731
            if not subsequence(tags(pa.body), tags(pb.body), lambda x, y: x == y or tag_fits(x, y)):
                problems.append(f"{where}: the output markup is not the input markup minus removed items")
    for p in problems:
        print(p)
    print(f"xml_structure: {bodies} rewritten bodies checked, {len(problems)} problem(s)", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())

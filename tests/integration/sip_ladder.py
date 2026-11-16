#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""SC-001: the SIP ladder of the output equals the input's.

Compares, per frame, the SIP method or status code and CSeq of input and output (tshark
fields), in frame order, and checks that dialog identifiers map one to one: every input
Call-ID, From tag and To tag has exactly one output value and no two input values share one
(equivalence classes, so dialogs and transactions group the same way).

With --subset, the output may lack messages the input has (bytes deliberately zeroed: a lost
segment, a capture that starts mid-message, an ambiguous fragment), but every output message is
an input message, in order. With --ignore-frames, frame numbers are not compared (IP
refragmentation may change the number of fragments).

Usage: sip_ladder.py INPUT OUTPUT [--transport udp|tcp] [--subset] [--ignore-frames]
Exit: 0 ok, 1 differs, 77 tshark not installed (unless MCXANON_REQUIRE_TSHARK=1).
"""
import os
import shutil
import subprocess
import sys

FIELDS = ["frame.number", "sip.Method", "sip.Status-Code", "sip.CSeq", "sip.Call-ID", "sip.from.tag", "sip.to.tag"]


def ladder(path, transport=None):
    flt = f"sip && {transport}" if transport else "sip"
    r = subprocess.run(["tshark", "-n", "-r", path, "-Y", flt, "-T", "fields", "-E", "occurrence=f",
                        *sum((["-e", f] for f in FIELDS), [])], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(r.stderr)
    return [line.split("\t") for line in r.stdout.splitlines()]


def bijection(pairs, what, problems):
    fwd, back = {}, {}
    for a, b in pairs:
        if not a:
            continue
        if fwd.setdefault(a, b) != b:
            problems.append(f"{what}: one input value has several output values")
        if back.setdefault(b, a) != a:
            problems.append(f"{what}: two input values share one output value")


def main():
    if shutil.which("tshark") is None:
        if os.environ.get("MCXANON_REQUIRE_TSHARK") == "1":
            print("tshark is required but not installed", file=sys.stderr)
            return 1
        print("tshark not installed: skipped", file=sys.stderr)
        return 77
    transport = sys.argv[sys.argv.index("--transport") + 1] if "--transport" in sys.argv else None
    a, b = ladder(sys.argv[1], transport), ladder(sys.argv[2], transport)
    first = 1 if "--ignore-frames" in sys.argv else 0
    problems = []
    if "--subset" in sys.argv:
        # Every output message matches the next input message with the same key, in order.
        i, pairs = 0, []
        for y in b:
            while i < len(a) and a[i][first:4] != y[first:4]:
                i += 1
            if i == len(a):
                problems.append(f"output message not in the input: frame {y[0]} {y[1:4]}")
                break
            pairs.append((a[i], y))
            i += 1
        if not problems:
            for col, what in ((4, "Call-ID"), (5, "From tag"), (6, "To tag")):
                bijection([(x[col], y[col]) for x, y in pairs], what, problems)
    elif [r[first:4] for r in a] != [r[first:4] for r in b]:
        problems.append(f"ladder differs: {len(a)} input and {len(b)} output SIP messages")
        for x, y in zip(a, b):
            if x[:4] != y[:4]:
                problems.append(f"first difference: frame {x[0]} {x[1:4]} vs frame {y[0]} {y[1:4]}")
                break
    else:
        for col, what in ((4, "Call-ID"), (5, "From tag"), (6, "To tag")):
            bijection([(x[col], y[col]) for x, y in zip(a, b)], what, problems)
    for p in problems:
        print("FAIL " + p)
    print(f"sip_ladder: {len(a)} messages, {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())

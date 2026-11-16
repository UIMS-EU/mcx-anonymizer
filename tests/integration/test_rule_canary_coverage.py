#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Constitution VI: every rule that pseudonymises, removes, zeroes or pads a
field has at least one canary planted in that field by the fixture generator.
(The absence of the canaries in the output is checked by test_anonymize_us1 and,
for the SIP rules, by test_sip_udp and the other SIP tests.)

The L2-L4 rules are read from rules/*.yaml ("- field:" entries). The SIP rules
(sip:, sip-param:, uri-param:, sdp:, tag: and body: keys) come from SIP_RULE_KEYS,
a program that prints the key of every SIP rule that changes a value from the
embedded rule set, so that the rule loader itself defines them. The media and XML
rule sets have such programs too (xml: and xml-ns: keys, feature 003).

Usage: test_rule_canary_coverage.py FIXTURE_DIR [RULE_KEYS_PROGRAM...]
"""
import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
fixtures = Path(sys.argv[1])
rules = {}
for f in sorted((REPO / "rules").glob("*.yaml")):
    for m in re.finditer(r"- field: (\S+)\n\s+action: (\S+)", f.read_text()):
        rules[m.group(1)] = m.group(2)
canaries = json.loads((fixtures / "canaries.json").read_text())["canaries"]
planted = {c["field"] for c in canaries if "field" in c}
missing = sorted(f for f, a in rules.items() if a in ("pseudonymise", "remove", "zero", "pad") and f not in planted)
non_keep = sum(1 for a in rules.values() if a in ("pseudonymise", "remove", "zero", "pad"))
print(f"{len(rules)} rules, {non_keep} that change a field, {len(missing)} without a canary")
for f in missing:
    print(f"FAIL no canary for {f} ({rules[f]})")
unknown = sorted(planted - set(rules))
for f in unknown:
    print(f"FAIL canary names a field without a rule: {f}")
sip_missing = []
planted_rules = {c["rule"] for c in canaries if "rule" in c}
planted_rules |= {k for c in canaries for k in c.get("also", [])}
for program in sys.argv[2:]:
    # One program per rule set (the SIP rule set, the media rule set), each printing the key of
    # every rule that changes a value.
    keys = subprocess.run([program], check=True, capture_output=True, text=True).stdout.split()
    missing_here = sorted(set(keys) - planted_rules)
    sip_missing += missing_here
    print(f"{len(keys)} rules of {Path(program).name} that change a value, {len(missing_here)} without a canary")
    for k in missing_here:
        print(f"FAIL no canary for rule {k}")
sys.exit(1 if missing or unknown or sip_missing else 0)

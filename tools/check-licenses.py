#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Licence gate: every Conan dependency must be permissively licensed.

Usage:
    tools/check-licenses.py [--project DIR]        # runs `conan graph info DIR --format=json`
    tools/check-licenses.py --graph-json FILE      # checks an existing graph document

Every node in every context (host, build, test) must carry a licence expression
with at least one alternative from ALLOWED. Expressions are SPDX-like strings
("MIT", "Apache-2.0 OR MIT", "Apache-2.0 WITH LLVM-exception") or lists of such
strings (all list entries must pass). Exit 0 if all pass, 1 otherwise.
"""
import argparse
import json
import re
import subprocess
import sys

# The project's licence policy: the list in the governing document of the
# project, nothing more. Keep in sync with README / CONTRIBUTING.
ALLOWED = {
    "MIT",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "Apache-2.0",
    "BSL-1.0",
    "Unlicense",
    "Zlib",
}
# Exceptions that only add permissions to an allowed licence.
ALLOWED_EXCEPTIONS = {"LLVM-exception"}


def term_allowed(term: str) -> bool:
    term = term.strip().strip("()").strip()
    m = re.fullmatch(r"(\S+)\s+WITH\s+(\S+)", term)
    if m:
        return m.group(1) in ALLOWED and m.group(2) in ALLOWED_EXCEPTIONS
    return term in ALLOWED


def expression_allowed(expr) -> bool:
    if expr is None:
        return False
    if isinstance(expr, (list, tuple)):
        return len(expr) > 0 and all(expression_allowed(e) for e in expr)
    if not isinstance(expr, str) or not expr.strip():
        return False
    # Disjunction: at least one alternative must be allowed. Conjunctions
    # (AND) require every operand to be allowed.
    for alternative in re.split(r"\s+OR\s+", expr.strip()):
        operands = re.split(r"\s+AND\s+", alternative)
        if all(term_allowed(op) for op in operands):
            return True
    return False


def load_graph(args) -> dict:
    if args.graph_json:
        with open(args.graph_json, encoding="utf-8") as f:
            return json.load(f)
    cmd = ["conan", "graph", "info", args.project, "--format=json", "--no-remote"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"check-licenses: `{' '.join(cmd)}` failed:\n{r.stderr}", file=sys.stderr)
        sys.exit(2)
    return json.loads(r.stdout)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--project", default=".")
    ap.add_argument("--graph-json")
    args = ap.parse_args()

    nodes = load_graph(args).get("graph", {}).get("nodes", {})
    offending = []
    checked = 0
    for node in nodes.values():
        ref = node.get("ref") or ""
        if ref in ("", "conanfile") or node.get("recipe") == "Consumer":
            continue  # the project itself
        checked += 1
        if not expression_allowed(node.get("license")):
            ctx = node.get("context", "?") + ("/test" if node.get("test") else "")
            offending.append(f"{ref} [{ctx}]: {node.get('license')!r}")

    if offending:
        print("Dependencies with a licence outside the allowed set "
              f"({', '.join(sorted(ALLOWED))}):", file=sys.stderr)
        for line in offending:
            print(f"  {line}", file=sys.stderr)
        return 1
    print(f"check-licenses: {checked} dependencies, all permissive")
    return 0


if __name__ == "__main__":
    sys.exit(main())

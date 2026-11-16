#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Validate a report JSON document against schemas/report.schema.json.

A small validator for the JSON-Schema keywords the report schema uses (type,
const, enum, required, properties, additionalProperties, propertyNames, items,
pattern, minimum), so the tests need nothing beyond the Python standard library.

Usage: validate_report.py SCHEMA REPORT|-      (or: --command CMD... to validate CMD's stdout)
"""
import json
import re
import subprocess
import sys

TYPES = {
    "object": dict, "array": list, "string": str, "boolean": bool,
    "integer": int, "number": (int, float), "null": type(None),
}


def type_ok(value, t):
    if isinstance(t, list):
        return any(type_ok(value, x) for x in t)
    if t in ("integer", "number") and isinstance(value, bool):
        return False
    return isinstance(value, TYPES[t])


def validate(value, schema, path="$"):
    errors = []
    if "type" in schema and not type_ok(value, schema["type"]):
        return [f"{path}: expected {schema['type']}, got {type(value).__name__}"]
    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: expected const {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: {value!r} not in {schema['enum']}")
    if "pattern" in schema and isinstance(value, str) and not re.search(schema["pattern"], value):
        errors.append(f"{path}: {value!r} does not match {schema['pattern']}")
    if "minimum" in schema and isinstance(value, (int, float)) and value < schema["minimum"]:
        errors.append(f"{path}: {value} < {schema['minimum']}")
    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}: missing required '{key}'")
        if "propertyNames" in schema:
            for key in value:
                errors += validate(key, schema["propertyNames"], f"{path}.<name {key!r}>")
        props = schema.get("properties", {})
        extra = schema.get("additionalProperties", True)
        for key, sub in value.items():
            if key in props:
                errors += validate(sub, props[key], f"{path}.{key}")
            elif extra is False:
                errors.append(f"{path}: unexpected property '{key}'")
            elif isinstance(extra, dict):
                errors += validate(sub, extra, f"{path}.{key}")
    if isinstance(value, list) and "items" in schema:
        for i, item in enumerate(value):
            errors += validate(item, schema["items"], f"{path}[{i}]")
    return errors


def main():
    if len(sys.argv) >= 3 and sys.argv[2] == "--command":
        text = subprocess.run(sys.argv[3:], capture_output=True, text=True, check=True).stdout
    elif len(sys.argv) == 3:
        text = sys.stdin.read() if sys.argv[2] == "-" else open(sys.argv[2], encoding="utf-8").read()
    else:
        print(__doc__, file=sys.stderr)
        return 2
    schema = json.load(open(sys.argv[1], encoding="utf-8"))
    errors = validate(json.loads(text), schema)
    for e in errors:
        print(e, file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())

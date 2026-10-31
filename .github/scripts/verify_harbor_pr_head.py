#!/usr/bin/env python3
"""Compare a checked-out Git SHA with an exact PR HEAD, fail-closed."""
import re
import sys

SHA = re.compile(r"[0-9a-f]{40}", re.ASCII)


def matches(expected: str, actual: str) -> bool:
    return bool(SHA.fullmatch(expected) and SHA.fullmatch(actual) and expected == actual)


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: verify_harbor_pr_head.py EXPECTED_SHA ACTUAL_SHA", file=sys.stderr)
        return 2
    expected, actual = sys.argv[1:]
    if not matches(expected, actual):
        print("PR head SHA mismatch or malformed SHA; refusing benchmark", file=sys.stderr)
        return 1
    print(f"Exact PR head verified: {actual}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

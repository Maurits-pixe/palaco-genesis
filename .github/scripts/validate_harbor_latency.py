#!/usr/bin/env python3
"""Fail-closed parser for Harbor recovery latency evidence (observation only)."""
import pathlib
import re
import sys

PATTERN = re.compile(
    r"HARBOR_RECOVER frames=(1|16|64) runs=7 "
    r"min_us=([0-9]+) median_us=([0-9]+) max_us=([0-9]+)"
)
EXPECTED = {1, 16, 64}


def validate(raw: str) -> str:
    lines = [line for line in raw.splitlines() if line.startswith("HARBOR_RECOVER ")]
    if len(lines) != 3:
        raise ValueError("expected exactly 3 recovery results")
    seen = set()
    for line in lines:
        match = PATTERN.fullmatch(line)
        if match is None:
            raise ValueError("malformed recovery result")
        frame, low, median, high = map(int, match.groups())
        if frame in seen or not (0 <= low <= median <= high):
            raise ValueError("duplicate frame group or invalid duration ordering")
        seen.add(frame)
    if seen != EXPECTED:
        raise ValueError("missing recovery frame group")
    return "\n".join(lines) + "\n"


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: validate_harbor_latency.py RAW_LOG SUMMARY", file=sys.stderr)
        return 2
    try:
        summary = validate(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"invalid Harbor latency evidence: {exc}", file=sys.stderr)
        return 1
    pathlib.Path(sys.argv[2]).write_text(summary, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())

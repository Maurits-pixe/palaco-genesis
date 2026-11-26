#!/usr/bin/env python3
"""Validate design-time offline recovery policy. Does not implement synchronization."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "ecosystem" / "offline-recovery-policy.v0.1.json"
STATES = {"untrusted", "pending-review", "quarantined"}
TRANSITIONS = {
    ("untrusted", "pending-review", "integrity-check"),
    ("untrusted", "quarantined", "integrity-failure"),
    ("pending-review", "quarantined", "integrity-failure"),
}
FORBIDDEN = {
    "issue-identity", "grant-role", "authorize-execution",
    "mark-evidence-verified", "publish", "deploy",
}


def validate(data):
    errors = []
    if not isinstance(data, dict):
        return ["policy must be an object"]
    if data.get("schema_version") != "0.1.0":
        errors.append("unsupported schema")
    if data.get("release_gate") != "HOLD" or data.get("runtime_enabled") is not False:
        errors.append("HOLD and disabled runtime required")
    states = data.get("allowed_states")
    if not isinstance(states, list) or len(states) != len(STATES) or any(
        not isinstance(x, str) for x in states
    ) or set(states) != STATES:
        errors.append("unexpected state set")
    raw = data.get("allowed_transitions")
    if not isinstance(raw, list):
        errors.append("transitions must be an array")
    else:
        transitions = set()
        for entry in raw:
            if not isinstance(entry, dict) or any(
                not isinstance(entry.get(k), str) for k in ("from", "to", "requires")
            ):
                errors.append("invalid transition")
                continue
            transitions.add((entry["from"], entry["to"], entry["requires"]))
        if transitions != TRANSITIONS or len(raw) != len(TRANSITIONS):
            errors.append("unexpected transition set")
    actions = data.get("forbidden_offline_actions")
    if not isinstance(actions, list) or len(actions) != len(FORBIDDEN) or any(
        not isinstance(x, str) for x in actions
    ) or set(actions) != FORBIDDEN:
        errors.append("forbidden action set changed")
    for field, expected in {
        "reconciliation": "manual-reviewed-server-side",
        "duplicate_detection": "stable-record-id",
        "conflict_policy": "quarantine",
        "missing_provenance": "quarantine",
        "unsupported_schema": "quarantine",
    }.items():
        if data.get(field) != expected:
            errors.append(f"{field} must remain {expected}")
    return errors


def main():
    try:
        data = json.loads(POLICY.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 2
    errors = validate(data)
    for error in errors:
        print("FAIL:", error, file=sys.stderr)
    if errors:
        return 1
    print("PASS: offline recovery design contract; no automatic trust elevation; HOLD")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

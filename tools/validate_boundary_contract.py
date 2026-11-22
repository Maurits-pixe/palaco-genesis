#!/usr/bin/env python3
"""Static boundary contract checks; no authorization is issued or evaluated live."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "ecosystem" / "integration-registry.v0.1.json"
CONTRACT = ROOT / "ecosystem" / "boundary-contract.v0.1.json"
FIELDS = {"consumer", "provider", "purpose", "data_class", "authentication",
          "authorization", "offline_behavior", "runtime_enabled"}
OFFLINE = {"deny", "queue-untrusted"}
CLASSES = {"identity-reference", "evidence-metadata", "session-claims",
           "evidence-reference"}


def validate(registry, contract):
    errors = []
    if not isinstance(registry, dict) or not isinstance(contract, dict):
        return ["registry and contract must be objects"]
    if registry.get("release_gate") != "HOLD" or contract.get("release_gate") != "HOLD":
        errors.append("release gates must both be HOLD")
    if contract.get("schema_version") != "0.1.0":
        errors.append("unsupported contract schema")
    modules = registry.get("modules")
    if not isinstance(modules, list) or any(not isinstance(m, dict) for m in modules):
        return errors + ["invalid module registry"]
    dependencies = {}
    for module in modules:
        name = module.get("id")
        deps = module.get("depends_on")
        if isinstance(name, str) and isinstance(deps, list):
            dependencies[name] = deps
    edges = contract.get("edges")
    if not isinstance(edges, list) or not edges:
        return errors + ["edges must be nonempty array"]
    seen = set()
    for i, edge in enumerate(edges):
        loc = f"edges[{i}]"
        if not isinstance(edge, dict):
            errors.append(f"{loc}: expected object")
            continue
        if not FIELDS.issubset(edge):
            errors.append(f"{loc}: missing required fields")
            continue
        consumer, provider = edge["consumer"], edge["provider"]
        if not isinstance(consumer, str) or not isinstance(provider, str):
            errors.append(f"{loc}: endpoints must be strings")
            continue
        pair = (consumer, provider)
        if pair in seen:
            errors.append(f"{loc}: duplicate interface")
        seen.add(pair)
        if consumer not in dependencies or provider not in dependencies:
            errors.append(f"{loc}: unknown module")
        elif provider not in dependencies[consumer]:
            errors.append(f"{loc}: dependency not registered")
        if not isinstance(edge["purpose"], str) or not edge["purpose"].strip():
            errors.append(f"{loc}: missing purpose")
        if edge["data_class"] not in CLASSES:
            errors.append(f"{loc}: unsupported data class")
        if edge["authentication"] != "required":
            errors.append(f"{loc}: authentication must be required")
        if edge["authorization"] != "provider-enforced":
            errors.append(f"{loc}: provider authorization required")
        if edge["offline_behavior"] not in OFFLINE:
            errors.append(f"{loc}: invalid offline behavior")
        if edge["data_class"] in {"identity-reference", "session-claims"} and edge["offline_behavior"] != "deny":
            errors.append(f"{loc}: identity and session operations must deny offline")
        if edge["runtime_enabled"] is not False:
            errors.append(f"{loc}: runtime must be disabled")
    return errors


def main():
    try:
        registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 2
    errors = validate(registry, contract)
    for error in errors:
        print("FAIL:", error, file=sys.stderr)
    if errors:
        return 1
    print(f"PASS: {len(contract['edges'])} proposed interfaces; authorization provider-enforced; HOLD")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

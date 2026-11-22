#!/usr/bin/env python3
"""Validate PALACO integration registry without third-party dependencies.

This checks design-time integrity only. It cannot verify deployed services,
identity, permissions, database migrations, live connectivity or readiness.
"""
import json
import re
import sys
from pathlib import Path

DEFAULT = Path(__file__).resolve().parents[1] / "ecosystem" / "integration-registry.v0.1.json"
ID = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")


try:
    from tools.strict_contract_json import load_strict_json
except ModuleNotFoundError:
    # Support direct execution: python3 tools/validate_*.py
    from strict_contract_json import load_strict_json


def load_registry(path):
    """Preserve the validator's public loader while sharing strict parsing."""
    return load_strict_json(path)


def validate(data):
    errors = []
    if not isinstance(data, dict):
        return ["registry must be an object"]
    if data.get("schema_version") != "0.1.0":
        errors.append("unsupported schema_version")
    if data.get("release_gate") != "HOLD":
        errors.append("release_gate must remain HOLD in v0.1")
    modules = data.get("modules")
    if not isinstance(modules, list) or not modules:
        return errors + ["modules must be a nonempty array"]
    by_id = {}
    for idx, module in enumerate(modules):
        prefix = f"modules[{idx}]"
        if not isinstance(module, dict):
            errors.append(f"{prefix}: must be an object")
            continue
        name = module.get("id")
        if not isinstance(name, str) or not ID.fullmatch(name):
            errors.append(f"{prefix}: invalid id")
            continue
        if name in by_id:
            errors.append(f"{prefix}: duplicate id {name}")
        by_id[name] = module
        if not isinstance(module.get("role"), str) or not module["role"].strip():
            errors.append(f"{prefix}: role must be nonempty")
        if module.get("stage") != "proposed":
            errors.append(f"{prefix}: stage must be proposed in v0.1")
        if module.get("runtime_enabled") is not False:
            errors.append(f"{prefix}: runtime_enabled must be false")
        deps = module.get("depends_on")
        if not isinstance(deps, list) or not all(isinstance(x, str) for x in deps):
            errors.append(f"{prefix}: depends_on must be an array of ids")
        elif len(deps) != len(set(deps)):
            errors.append(f"{prefix}: duplicate dependencies")
    graph = {}
    for name, module in by_id.items():
        deps = module.get("depends_on")
        if not isinstance(deps, list) or not all(isinstance(x, str) for x in deps):
            continue
        graph[name] = deps
        for dep in deps:
            if dep not in by_id:
                errors.append(f"{name}: unknown dependency {dep}")
            if dep == name:
                errors.append(f"{name}: self dependency")
    state = {}

    def visit(name, stack):
        if state.get(name) == 2:
            return
        if state.get(name) == 1:
            errors.append("dependency cycle: " + " -> ".join(stack + [name]))
            return
        state[name] = 1
        for dep in graph.get(name, []):
            if dep in graph:
                visit(dep, stack + [name])
        state[name] = 2

    for name in graph:
        if name not in state:
            visit(name, [])
    return errors


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT
    try:
        data = load_registry(path)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        print(f"FAIL: cannot read registry: {exc}", file=sys.stderr)
        return 2
    errors = validate(data)
    if errors:
        for error in errors:
            print("FAIL:", error, file=sys.stderr)
        return 1
    print(f"PASS: {len(data['modules'])} proposed modules, dependency graph valid; release HOLD")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

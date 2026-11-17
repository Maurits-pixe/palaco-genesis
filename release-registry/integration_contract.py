"""Offline integration contract validation; never grants release authority.

Requires a package-integrity.json covering all package contents.
The module contract itself must be listed in that integrity manifest.
"""
import json
from pathlib import Path

from package_integrity import IntegrityError, verify_package

SCHEMA = "palaco-unified-integration/v1"
MODULES = frozenset(("palaco-one", "rio", "mundo", "citadel", "neo-os"))


class ContractError(ValueError):
    pass


def validate_integration(root):
    """Return immutable module identifiers after structural integrity checks.

    The manifest is untrusted input, even when every hash matches. No code is
    executed, no external service contacted, and no authority is inferred.
    """
    try:
        verified = set(verify_package(root))
    except (IntegrityError, OSError) as exc:
        raise ContractError("PACKAGE_INTEGRITY_FAILED") from exc
    name = "module-contract.json"
    if name not in verified:
        raise ContractError("CONTRACT_NOT_IN_INTEGRITY_MANIFEST")
    path = Path(root) / name
    try:
        if path.stat().st_size > 131_072:
            raise ContractError("CONTRACT_TOO_LARGE")
        raw = path.read_bytes()
        if len(raw) > 131_072:
            raise ContractError("CONTRACT_TOO_LARGE")
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, OSError) as exc:
        raise ContractError("INVALID_CONTRACT_JSON") from exc
    if type(document) is not dict or set(document) != {"schema", "modules"}:
        raise ContractError("INVALID_CONTRACT_SCHEMA")
    if document["schema"] != SCHEMA or type(document["modules"]) is not list:
        raise ContractError("INVALID_CONTRACT_SCHEMA")
    module_map = {}
    paths = set()
    for module in document["modules"]:
        if type(module) is not dict or set(module) != {"id", "entrypoint", "requires"}:
            raise ContractError("INVALID_MODULE")
        module_id = module["id"]
        entrypoint = module["entrypoint"]
        requires = module["requires"]
        if type(module_id) is not str or module_id not in MODULES or module_id in module_map:
            raise ContractError("DUPLICATE_OR_UNKNOWN_MODULE")
        if (type(entrypoint) is not str or not entrypoint.startswith(module_id + "/")
                or entrypoint not in verified or entrypoint in paths):
            raise ContractError("INVALID_ENTRYPOINT")
        if (type(requires) is not list or
                any(type(dep) is not str or dep not in MODULES for dep in requires) or
                len(set(requires)) != len(requires) or module_id in requires):
            raise ContractError("INVALID_DEPENDENCIES")
        module_map[module_id] = tuple(requires)
        paths.add(entrypoint)
    if set(module_map) != MODULES:
        raise ContractError("INCOMPLETE_MODULE_SET")
    for module_id, deps in module_map.items():
        if any(dep not in module_map for dep in deps):
            raise ContractError("MISSING_DEPENDENCY")
    visited, active = set(), set()

    def visit(node):
        if node in active:
            raise ContractError("DEPENDENCY_CYCLE")
        if node in visited:
            return
        active.add(node)
        for required in module_map[node]:
            visit(required)
        active.remove(node)
        visited.add(node)

    for module_id in sorted(module_map):
        visit(module_id)
    return tuple(sorted(module_map))


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory")
    args = parser.parse_args()
    try:
        validated = validate_integration(args.directory)
    except ContractError as exc:
        parser.exit(1, "FAIL: " + str(exc) + "\n")
    print("PASS: %d candidate module contracts; NO RELEASE AUTHORITY" % len(validated))

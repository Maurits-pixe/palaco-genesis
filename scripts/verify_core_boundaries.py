#!/usr/bin/env python3
"""FCP-002-CORE-001: enforce the dependency-free PALACO foundational boundaries.

Reads Cargo manifests only; no network, build artifacts, or authorization effects.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys
import tomllib

PROTECTED = frozenset({"palaco-foundation", "palaco-constitution"})
DEPENDENCY_SECTIONS = ("dependencies", "dev-dependencies", "build-dependencies")


def check_boundaries(root: Path) -> list[str]:
    workspace = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    members = workspace["workspace"]["members"]
    manifests = []
    for member in members:
        path = root / member / "Cargo.toml"
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        manifests.append((member, data))
    internal = {data["package"]["name"] for _, data in manifests}
    errors = []
    for member, data in manifests:
        name = data["package"]["name"]
        if name not in PROTECTED:
            continue
        for section in DEPENDENCY_SECTIONS:
            for alias, config in data.get(section, {}).items():
                actual = config.get("package", alias) if isinstance(config, dict) else alias
                if actual in internal:
                    errors.append(f"{member}: {section} references internal crate {actual}")
        for target, target_data in data.get("target", {}).items():
            for section in DEPENDENCY_SECTIONS:
                for alias, config in target_data.get(section, {}).items():
                    actual = config.get("package", alias) if isinstance(config, dict) else alias
                    if actual in internal:
                        errors.append(
                            f"{member}: target {target} {section} references internal crate {actual}"
                        )
    return sorted(errors)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        violations = check_boundaries(args.root)
    except (OSError, KeyError, ValueError, tomllib.TOMLDecodeError) as exc:
        print(f"FCP-002-CORE-001 ERROR: {exc}", file=sys.stderr)
        return 2
    if violations:
        for violation in violations:
            print(f"FCP-002-CORE-001 FAIL: {violation}", file=sys.stderr)
        return 1
    print("FCP-002-CORE-001 PASS: Foundation and Constitution boundaries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

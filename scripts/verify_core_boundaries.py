#!/usr/bin/env python3
"""FCP-002-CORE-001: verify protected Cargo workspace dependency boundaries."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys
import tomllib

PROTECTED = frozenset({"palaco-foundation", "palaco-constitution"})
DEPENDENCY_SECTIONS = ("dependencies", "dev-dependencies", "build-dependencies")


def check_boundaries(root: Path) -> list[str]:
    root = root.resolve()
    workspace = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    members = workspace["workspace"]["members"]
    manifests = []
    for member in members:
        directory = (root / member).resolve()
        data = tomllib.loads((directory / "Cargo.toml").read_text(encoding="utf-8"))
        manifests.append((member, directory, data))

    internal_names = {data["package"]["name"] for _, _, data in manifests}
    internal_dirs = {directory for _, directory, _ in manifests}
    missing = PROTECTED - internal_names
    if missing:
        raise ValueError(f"protected crates missing from workspace: {', '.join(sorted(missing))}")

    errors = []
    for member, directory, data in manifests:
        if data["package"]["name"] not in PROTECTED:
            continue
        scopes = [(section, data.get(section, {})) for section in DEPENDENCY_SECTIONS]
        for target, target_data in data.get("target", {}).items():
            scopes.extend(
                (f"target {target} {section}", target_data.get(section, {}))
                for section in DEPENDENCY_SECTIONS
            )
        for scope, dependencies in scopes:
            for alias, config in dependencies.items():
                actual = config.get("package", alias) if isinstance(config, dict) else alias
                resolved_path = (
                    (directory / config["path"]).resolve()
                    if isinstance(config, dict) and "path" in config
                    else None
                )
                if actual in internal_names or resolved_path in internal_dirs:
                    errors.append(
                        f"{member}: {scope} references internal crate {actual}"
                    )
    return sorted(errors)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        violations = check_boundaries(args.root)
    except (OSError, KeyError, ValueError, TypeError, tomllib.TOMLDecodeError) as exc:
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

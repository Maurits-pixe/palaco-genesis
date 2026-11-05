#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

WORKFLOW_DIR = Path(__file__).resolve().parents[1] / "workflows"
SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
FLOATING_REFS = {"main", "master", "latest", "head"}
ALLOWED_PERMISSION_VALUES = {"read", "write", "none"}


def load_yaml(path: Path):
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def get_on_block(data: dict):
    return data.get("on", data.get(True))


def iter_uses(step: dict):
    uses = step.get("uses")
    if isinstance(uses, str):
        return uses
    return None


def validate(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        data = load_yaml(path)
    except OSError as exc:
        return [f"{path.name}: unable to read workflow file: {exc}"]
    except yaml.YAMLError as exc:
        return [f"{path.name}: invalid YAML: {exc}"]

    if not isinstance(data, dict):
        return [f"{path.name}: top-level YAML must be a mapping"]

    workflow_name = data.get("name")
    if not isinstance(workflow_name, str) or not workflow_name.strip():
        errors.append(f"{path.name}: top-level name must be a non-empty string")

    permissions = data.get("permissions")
    if not isinstance(permissions, dict) or permissions.get("contents") != "read":
        errors.append(f"{path.name}: top-level permissions.contents must be read")
    else:
        for perm_name, perm_value in permissions.items():
            if perm_value not in ALLOWED_PERMISSION_VALUES:
                errors.append(
                    f"{path.name}: top-level permission {perm_name} must be one of {sorted(ALLOWED_PERMISSION_VALUES)}"
                )
            if path.name != "pages.yml" and perm_value == "write":
                errors.append(
                    f"{path.name}: top-level write permission {perm_name}=write is not allowed"
                )

    concurrency = data.get("concurrency")
    if not isinstance(concurrency, dict):
        errors.append(f"{path.name}: missing top-level concurrency block")
    else:
        expected_group = "${{ github.workflow }}-${{ github.ref }}"
        group = concurrency.get("group")
        if group != expected_group:
            errors.append(
                f"{path.name}: concurrency.group must be '{expected_group}', got {group!r}"
            )
        if concurrency.get("cancel-in-progress") is not True:
            errors.append(f"{path.name}: concurrency.cancel-in-progress must be true")

    on_block = get_on_block(data)
    if isinstance(on_block, dict) and "pull_request_target" in on_block:
        errors.append(f"{path.name}: pull_request_target trigger is not allowed")
    elif isinstance(on_block, list) and "pull_request_target" in on_block:
        errors.append(f"{path.name}: pull_request_target trigger is not allowed")
    elif on_block == "pull_request_target":
        errors.append(f"{path.name}: pull_request_target trigger is not allowed")

    jobs = data.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        errors.append(f"{path.name}: jobs must be a non-empty mapping")
        return errors

    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            errors.append(f"{path.name}:{job_name}: job must be a mapping")
            continue

        strategy = job.get("strategy")
        if strategy is not None and not isinstance(strategy, dict):
            errors.append(f"{path.name}:{job_name}: strategy must be a mapping when set")
        elif isinstance(strategy, dict):
            if "fail-fast" in strategy and type(strategy["fail-fast"]) is not bool:
                errors.append(f"{path.name}:{job_name}: strategy.fail-fast must be a boolean")
            if "max-parallel" in strategy:
                max_parallel = strategy["max-parallel"]
                if type(max_parallel) is not int or max_parallel <= 0:
                    errors.append(
                        f"{path.name}:{job_name}: strategy.max-parallel must be a positive integer"
                    )
            if "matrix" in strategy and not isinstance(strategy["matrix"], dict):
                errors.append(f"{path.name}:{job_name}: strategy.matrix must be a mapping")
            elif isinstance(strategy.get("matrix"), dict):
                matrix = strategy["matrix"]
                for matrix_key in ("include", "exclude"):
                    matrix_value = matrix.get(matrix_key)
                    if matrix_value is None:
                        continue
                    if not isinstance(matrix_value, list):
                        errors.append(
                            f"{path.name}:{job_name}: strategy.matrix.{matrix_key} must be a list"
                        )
                        continue
                    for entry in matrix_value:
                        if not isinstance(entry, dict):
                            errors.append(
                                f"{path.name}:{job_name}: strategy.matrix.{matrix_key} entries must be mappings"
                            )
                            break
                for axis_name, axis_values in matrix.items():
                    if axis_name in ("include", "exclude"):
                        continue
                    if not isinstance(axis_values, list):
                        errors.append(
                            f"{path.name}:{job_name}: strategy.matrix.{axis_name} must be a list"
                        )

        if job.get("continue-on-error") is True:
            errors.append(f"{path.name}:{job_name}: continue-on-error: true is not allowed")

        if job.get("runs-on") != "ubuntu-latest":
            errors.append(f"{path.name}:{job_name}: runs-on must be ubuntu-latest")

        timeout = job.get("timeout-minutes")
        if type(timeout) is not int:
            errors.append(f"{path.name}:{job_name}: timeout-minutes must be an integer")
        elif timeout <= 0:
            errors.append(f"{path.name}:{job_name}: timeout-minutes must be greater than 0")
        elif timeout > 60:
            errors.append(f"{path.name}:{job_name}: timeout-minutes must be <= 60")

        job_permissions = job.get("permissions")
        if job_permissions is not None and not isinstance(job_permissions, dict):
            errors.append(f"{path.name}:{job_name}: permissions must be a mapping when set")
        elif isinstance(job_permissions, dict):
            for perm_name, perm_value in job_permissions.items():
                if perm_value not in ALLOWED_PERMISSION_VALUES:
                    errors.append(
                        f"{path.name}:{job_name}: permission {perm_name} must be one of {sorted(ALLOWED_PERMISSION_VALUES)}"
                    )
                if perm_value == "write":
                    if not (
                        path.name == "release.yml"
                        and job_name == "publish-release"
                        and perm_name == "contents"
                    ):
                        errors.append(
                            f"{path.name}:{job_name}: write permission {perm_name}=write is not allowed"
                        )

        steps = job.get("steps", [])
        if not isinstance(steps, list):
            errors.append(f"{path.name}:{job_name}: steps must be a list")
            continue

        for idx, step in enumerate(steps):
            if not isinstance(step, dict):
                continue

            if step.get("continue-on-error") is True:
                errors.append(
                    f"{path.name}:{job_name}:step#{idx + 1}: continue-on-error: true is not allowed"
                )

            uses = iter_uses(step)
            if not uses:
                continue

            if uses.startswith("./") or uses.startswith("docker://"):
                continue

            if "@" not in uses:
                errors.append(
                    f"{path.name}:{job_name}:step#{idx + 1}: uses must include an immutable ref"
                )
                continue

            _, ref = uses.rsplit("@", 1)
            if ref.lower() in FLOATING_REFS:
                errors.append(
                    f"{path.name}:{job_name}:step#{idx + 1}: floating ref @{ref} is not allowed"
                )

            if not SHA40_RE.fullmatch(ref):
                errors.append(
                    f"{path.name}:{job_name}:step#{idx + 1}: action ref must be a 40-char SHA"
                )

            if uses.startswith("actions/checkout@"):
                with_block = step.get("with")
                if not isinstance(with_block, dict) or with_block.get("persist-credentials") is not False:
                    errors.append(
                        f"{path.name}:{job_name}:step#{idx + 1}: checkout must set with.persist-credentials: false"
                    )

    return errors


def main() -> int:
    target_path = WORKFLOW_DIR
    if len(sys.argv) > 2:
        print("Usage: validate-workflows.py [WORKFLOW_DIR_OR_FILE]")
        return 1
    if len(sys.argv) == 2:
        target_path = Path(sys.argv[1])

    if target_path.is_file():
        workflow_files = [target_path]
    elif target_path.is_dir():
        workflow_files = sorted(target_path.glob("*.yml"))
    else:
        print(f"Path not found: {target_path}")
        return 1

    if not workflow_files:
        print("No workflow files found.")
        return 1

    all_errors: list[str] = []
    for workflow in workflow_files:
        all_errors.extend(validate(workflow))

    if all_errors:
        print("Workflow policy violations found:")
        for error in all_errors:
            print(f"- {error}")
        return 1

    print(f"Validated {len(workflow_files)} workflows: all checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

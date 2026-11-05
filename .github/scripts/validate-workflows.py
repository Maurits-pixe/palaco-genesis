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


def collect_workflow_files(path: Path) -> list[Path]:
    workflow_files = {wf for pattern in ("*.yml", "*.yaml") for wf in path.glob(pattern)}
    return sorted(workflow_files)


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

    top_env = data.get("env")
    if top_env is not None and not isinstance(top_env, dict):
        errors.append(f"{path.name}: top-level env must be a mapping when set")
    elif isinstance(top_env, dict):
        for env_key in top_env.keys():
            if not isinstance(env_key, str) or not env_key.strip():
                errors.append(f"{path.name}: top-level env keys must be non-empty strings")
                break

    top_defaults = data.get("defaults")
    if top_defaults is not None and not isinstance(top_defaults, dict):
        errors.append(f"{path.name}: top-level defaults must be a mapping when set")
    elif isinstance(top_defaults, dict):
        top_defaults_run = top_defaults.get("run")
        if top_defaults_run is not None and not isinstance(top_defaults_run, dict):
            errors.append(f"{path.name}: top-level defaults.run must be a mapping when set")
        elif isinstance(top_defaults_run, dict):
            top_shell = top_defaults_run.get("shell")
            if top_shell is not None and (not isinstance(top_shell, str) or not top_shell.strip()):
                errors.append(
                    f"{path.name}: top-level defaults.run.shell must be a non-empty string when set"
                )
            top_workdir = top_defaults_run.get("working-directory")
            if top_workdir is not None and (
                not isinstance(top_workdir, str) or not top_workdir.strip()
            ):
                errors.append(
                    f"{path.name}: top-level defaults.run.working-directory must be a non-empty string when set"
                )

    permissions = data.get("permissions")
    if not isinstance(permissions, dict) or permissions.get("contents") != "read":
        errors.append(f"{path.name}: top-level permissions.contents must be read")
    else:
        for perm_name, perm_value in permissions.items():
            if not isinstance(perm_name, str) or not perm_name.strip():
                errors.append(f"{path.name}: top-level permission names must be non-empty strings")
                continue
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
    if on_block is None:
        errors.append(f"{path.name}: missing top-level on trigger block")
    elif isinstance(on_block, dict) and not on_block:
        errors.append(f"{path.name}: top-level on trigger mapping must not be empty")
    elif isinstance(on_block, dict):
        for trigger_name, trigger_config in on_block.items():
            if not isinstance(trigger_name, str) or not trigger_name.strip():
                errors.append(
                    f"{path.name}: top-level on trigger mapping keys must be non-empty strings"
                )
                break
            if trigger_config is not None and not isinstance(trigger_config, (dict, list, str)):
                errors.append(
                    f"{path.name}: top-level on trigger mapping values must be mapping, list, string, or null"
                )
                break
    elif isinstance(on_block, list) and not on_block:
        errors.append(f"{path.name}: top-level on trigger list must not be empty")
    elif isinstance(on_block, list):
        for trigger in on_block:
            if not isinstance(trigger, str) or not trigger.strip():
                errors.append(f"{path.name}: top-level on trigger list entries must be non-empty strings")
                break
    elif isinstance(on_block, str) and not on_block.strip():
        errors.append(f"{path.name}: top-level on trigger string must not be empty")
    elif not isinstance(on_block, (dict, list, str)):
        errors.append(f"{path.name}: top-level on trigger must be a mapping, list, or string")

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

    valid_job_names = {name for name in jobs.keys() if isinstance(name, str) and name.strip()}

    for job_name, job in jobs.items():
        if not isinstance(job_name, str) or not job_name.strip():
            errors.append(f"{path.name}: job names must be non-empty strings")
            continue
        if not isinstance(job, dict):
            errors.append(f"{path.name}:{job_name}: job must be a mapping")
            continue

        job_display_name = job.get("name")
        if job_display_name is not None and (
            not isinstance(job_display_name, str) or not job_display_name.strip()
        ):
            errors.append(f"{path.name}:{job_name}: job name must be a non-empty string when set")

        job_if = job.get("if")
        if job_if is not None and (not isinstance(job_if, str) or not job_if.strip()):
            errors.append(f"{path.name}:{job_name}: job if must be a non-empty string when set")

        job_env = job.get("env")
        if job_env is not None and not isinstance(job_env, dict):
            errors.append(f"{path.name}:{job_name}: job env must be a mapping when set")
        elif isinstance(job_env, dict):
            for env_key in job_env.keys():
                if not isinstance(env_key, str) or not env_key.strip():
                    errors.append(f"{path.name}:{job_name}: job env keys must be non-empty strings")
                    break

        job_defaults = job.get("defaults")
        if job_defaults is not None and not isinstance(job_defaults, dict):
            errors.append(f"{path.name}:{job_name}: job defaults must be a mapping when set")
        elif isinstance(job_defaults, dict):
            job_defaults_run = job_defaults.get("run")
            if job_defaults_run is not None and not isinstance(job_defaults_run, dict):
                errors.append(
                    f"{path.name}:{job_name}: job defaults.run must be a mapping when set"
                )
            elif isinstance(job_defaults_run, dict):
                job_shell = job_defaults_run.get("shell")
                if job_shell is not None and (not isinstance(job_shell, str) or not job_shell.strip()):
                    errors.append(
                        f"{path.name}:{job_name}: job defaults.run.shell must be a non-empty string when set"
                    )
                job_workdir = job_defaults_run.get("working-directory")
                if job_workdir is not None and (
                    not isinstance(job_workdir, str) or not job_workdir.strip()
                ):
                    errors.append(
                        f"{path.name}:{job_name}: job defaults.run.working-directory must be a non-empty string when set"
                    )

        job_outputs = job.get("outputs")
        if job_outputs is not None:
            if not isinstance(job_outputs, dict):
                errors.append(f"{path.name}:{job_name}: job outputs must be a mapping when set")
            else:
                for output_name, output_value in job_outputs.items():
                    if not isinstance(output_name, str) or not output_name.strip():
                        errors.append(
                            f"{path.name}:{job_name}: output names must be non-empty strings"
                        )
                        break
                    if not isinstance(output_value, str) or not output_value.strip():
                        errors.append(
                            f"{path.name}:{job_name}: output values must be non-empty strings"
                        )
                        break

        needs = job.get("needs")
        if needs is not None:
            if isinstance(needs, str):
                if not needs.strip():
                    errors.append(f"{path.name}:{job_name}: needs must not be an empty string")
                elif needs == job_name:
                    errors.append(f"{path.name}:{job_name}: needs must not reference the same job")
                elif needs not in valid_job_names:
                    errors.append(f"{path.name}:{job_name}: needs references unknown job {needs!r}")
            elif isinstance(needs, list):
                if not needs:
                    errors.append(f"{path.name}:{job_name}: needs list must not be empty")
                seen_needs: set[str] = set()
                for dep in needs:
                    if not isinstance(dep, str) or not dep.strip():
                        errors.append(
                            f"{path.name}:{job_name}: needs list entries must be non-empty strings"
                        )
                        break
                    if dep in seen_needs:
                        errors.append(f"{path.name}:{job_name}: needs list entries must be unique")
                        break
                    if dep == job_name:
                        errors.append(
                            f"{path.name}:{job_name}: needs list must not reference the same job"
                        )
                        break
                    if dep not in valid_job_names:
                        errors.append(
                            f"{path.name}:{job_name}: needs list references unknown job {dep!r}"
                        )
                        break
                    seen_needs.add(dep)
            else:
                errors.append(
                    f"{path.name}:{job_name}: needs must be a string or list of strings when set"
                )

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
                        for entry_key in entry.keys():
                            if not isinstance(entry_key, str) or not entry_key.strip():
                                errors.append(
                                    f"{path.name}:{job_name}: strategy.matrix.{matrix_key} entry keys must be non-empty strings"
                                )
                                break
                for axis_name, axis_values in matrix.items():
                    if axis_name in ("include", "exclude"):
                        continue
                    if not isinstance(axis_name, str) or not axis_name.strip():
                        errors.append(
                            f"{path.name}:{job_name}: strategy.matrix axis names must be non-empty strings"
                        )
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
                if not isinstance(perm_name, str) or not perm_name.strip():
                    errors.append(
                        f"{path.name}:{job_name}: permission names must be non-empty strings"
                    )
                    continue
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

        steps = job.get("steps")
        if steps is None:
            errors.append(f"{path.name}:{job_name}: steps are required")
            continue
        if not isinstance(steps, list):
            errors.append(f"{path.name}:{job_name}: steps must be a list")
            continue
        if not steps:
            errors.append(f"{path.name}:{job_name}: steps must be a non-empty list")
            continue

        uses_checkout = False
        for idx, step in enumerate(steps):
            if not isinstance(step, dict):
                errors.append(
                    f"{path.name}:{job_name}:step#{idx + 1}: step must be a mapping"
                )
                continue

            step_name = step.get("name")
            if step_name is not None and (not isinstance(step_name, str) or not step_name.strip()):
                errors.append(
                    f"{path.name}:{job_name}:step#{idx + 1}: step name must be a non-empty string when set"
                )

            step_id = step.get("id")
            if step_id is not None and (not isinstance(step_id, str) or not step_id.strip()):
                errors.append(
                    f"{path.name}:{job_name}:step#{idx + 1}: step id must be a non-empty string when set"
                )

            step_if = step.get("if")
            if step_if is not None and (not isinstance(step_if, str) or not step_if.strip()):
                errors.append(
                    f"{path.name}:{job_name}:step#{idx + 1}: step if must be a non-empty string when set"
                )

            step_env = step.get("env")
            if step_env is not None and not isinstance(step_env, dict):
                errors.append(
                    f"{path.name}:{job_name}:step#{idx + 1}: step env must be a mapping when set"
                )
            elif isinstance(step_env, dict):
                for env_key in step_env.keys():
                    if not isinstance(env_key, str) or not env_key.strip():
                        errors.append(
                            f"{path.name}:{job_name}:step#{idx + 1}: step env keys must be non-empty strings"
                        )
                        break

            step_with = step.get("with")
            if step_with is not None and not isinstance(step_with, dict):
                errors.append(
                    f"{path.name}:{job_name}:step#{idx + 1}: step with must be a mapping when set"
                )
            elif isinstance(step_with, dict):
                for with_key in step_with.keys():
                    if not isinstance(with_key, str) or not with_key.strip():
                        errors.append(
                            f"{path.name}:{job_name}:step#{idx + 1}: step with keys must be non-empty strings"
                        )
                        break

            step_timeout = step.get("timeout-minutes")
            if step_timeout is not None:
                if type(step_timeout) is not int:
                    errors.append(
                        f"{path.name}:{job_name}:step#{idx + 1}: timeout-minutes must be an integer when set"
                    )
                elif step_timeout <= 0:
                    errors.append(
                        f"{path.name}:{job_name}:step#{idx + 1}: timeout-minutes must be greater than 0"
                    )
                elif step_timeout > 60:
                    errors.append(
                        f"{path.name}:{job_name}:step#{idx + 1}: timeout-minutes must be <= 60"
                    )

            has_run = "run" in step
            has_uses = "uses" in step
            if has_run == has_uses:
                errors.append(
                    f"{path.name}:{job_name}:step#{idx + 1}: step must define exactly one of run or uses"
                )
            else:
                if has_run and not isinstance(step.get("run"), str):
                    errors.append(
                        f"{path.name}:{job_name}:step#{idx + 1}: run must be a string when set"
                    )
                if has_uses and not isinstance(step.get("uses"), str):
                    errors.append(
                        f"{path.name}:{job_name}:step#{idx + 1}: uses must be a string when set"
                    )

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
                uses_checkout = True
                with_block = step.get("with")
                if not isinstance(with_block, dict) or with_block.get("persist-credentials") is not False:
                    errors.append(
                        f"{path.name}:{job_name}:step#{idx + 1}: checkout must set with.persist-credentials: false"
                    )

        if isinstance(job_permissions, dict) and uses_checkout and "contents" not in job_permissions:
            errors.append(
                f"{path.name}:{job_name}: jobs using checkout with job-level permissions must set permissions.contents"
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
        workflow_files = collect_workflow_files(target_path)
    else:
        print(f"Path not found: {target_path}")
        return 1

    if not workflow_files:
        print("No workflow files found (*.yml or *.yaml).")
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

#!/usr/bin/env python3

import glob
import os
import sys

import yaml


def validate_env_mapping(
    errors: list[str], path: str, scope: str, env_value: object
) -> None:
    if env_value is None:
        return
    if not isinstance(env_value, dict):
        errors.append(f"{path}: {scope} env must be a mapping when provided")
        return
    for key, value in env_value.items():
        if not isinstance(key, str) or not key.strip():
            errors.append(f"{path}: {scope} env keys must be non-empty strings")
        if not isinstance(value, str):
            errors.append(f"{path}: {scope} env value for '{key}' must be a string")


def validate_defaults_run(
    errors: list[str], path: str, scope: str, defaults_value: object
) -> None:
    if defaults_value is None:
        return
    if not isinstance(defaults_value, dict):
        errors.append(f"{path}: {scope} defaults must be a mapping when provided")
        return
    run_defaults = defaults_value.get("run")
    if run_defaults is None:
        return
    if not isinstance(run_defaults, dict):
        errors.append(f"{path}: {scope} defaults.run must be a mapping when provided")
        return
    run_working_directory = run_defaults.get("working-directory")
    if run_working_directory is not None and (
        not isinstance(run_working_directory, str) or not run_working_directory.strip()
    ):
        errors.append(
            f"{path}: {scope} defaults.run.working-directory must be a non-empty string when provided"
        )
    run_shell = run_defaults.get("shell")
    if run_shell is not None and (not isinstance(run_shell, str) or not run_shell.strip()):
        errors.append(
            f"{path}: {scope} defaults.run.shell must be a non-empty string when provided"
        )


def main() -> int:
    files = sorted(glob.glob(".github/workflows/*.yml"))
    errors: list[str] = []
    workflow_name_to_paths: dict[str, list[str]] = {}

    for path in files:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)

        if not isinstance(data, dict):
            errors.append(f"{path}: workflow root must be a mapping")
            continue

        workflow_name = data.get("name")
        if not isinstance(workflow_name, str) or not workflow_name.strip():
            errors.append(f"{path}: top-level workflow name must be a non-empty string")
        else:
            normalized_name = workflow_name.strip()
            workflow_name_to_paths.setdefault(normalized_name, []).append(path)

        validate_env_mapping(errors, path, "workflow", data.get("env"))
        validate_defaults_run(errors, path, "workflow", data.get("defaults"))

        trigger_config = data.get("on", data.get(True))
        if trigger_config is None:
            errors.append(f"{path}: top-level workflow 'on' trigger definition is required")
        elif isinstance(trigger_config, str):
            if not trigger_config.strip():
                errors.append(f"{path}: top-level workflow 'on' trigger must not be empty")
        elif isinstance(trigger_config, list):
            if not trigger_config:
                errors.append(f"{path}: top-level workflow 'on' trigger list must not be empty")
        elif isinstance(trigger_config, dict):
            if not trigger_config:
                errors.append(f"{path}: top-level workflow 'on' trigger mapping must not be empty")
        else:
            errors.append(
                f"{path}: top-level workflow 'on' trigger must be string, list, or mapping"
            )

        if isinstance(trigger_config, str):
            if trigger_config == "schedule":
                errors.append(
                    f"{path}: schedule trigger must be a non-empty list of mappings with non-empty cron strings"
                )
            if trigger_config == "workflow_dispatch":
                errors.append(
                    f"{path}: workflow_dispatch trigger must be a mapping (use '{{}}' when no inputs are needed)"
                )
            if trigger_config == "push":
                errors.append(
                    f"{path}: push trigger must be a mapping with explicit branches"
                )
            if trigger_config == "pull_request":
                errors.append(
                    f"{path}: pull_request trigger must be a mapping with explicit branches"
                )
            if trigger_config == "pull_request_target":
                errors.append(f"{path}: pull_request_target trigger is not allowed")
        elif isinstance(trigger_config, list):
            if "schedule" in trigger_config:
                errors.append(
                    f"{path}: schedule trigger must be a non-empty list of mappings with non-empty cron strings"
                )
            if "workflow_dispatch" in trigger_config:
                errors.append(
                    f"{path}: workflow_dispatch trigger must be a mapping (use '{{}}' when no inputs are needed)"
                )
            if "push" in trigger_config:
                errors.append(
                    f"{path}: push trigger must be a mapping with explicit branches"
                )
            if "pull_request" in trigger_config:
                errors.append(
                    f"{path}: pull_request trigger must be a mapping with explicit branches"
                )
            if "pull_request_target" in trigger_config:
                errors.append(f"{path}: pull_request_target trigger is not allowed")
        elif isinstance(trigger_config, dict):
            if "schedule" in trigger_config:
                schedule_trigger = trigger_config.get("schedule")
                if not isinstance(schedule_trigger, list) or not schedule_trigger:
                    errors.append(
                        f"{path}: schedule trigger must be a non-empty list of mappings with non-empty cron strings"
                    )
                else:
                    for schedule_index, schedule_entry in enumerate(schedule_trigger):
                        if not isinstance(schedule_entry, dict):
                            errors.append(
                                f"{path}: schedule entry #{schedule_index} must be a mapping with a non-empty cron"
                            )
                            continue
                        extra_schedule_keys = set(schedule_entry.keys()) - {"cron"}
                        if extra_schedule_keys:
                            errors.append(
                                f"{path}: schedule entry #{schedule_index} has unsupported keys: {sorted(extra_schedule_keys)}"
                            )
                        cron_value = schedule_entry.get("cron")
                        if not isinstance(cron_value, str) or not cron_value.strip():
                            errors.append(
                                f"{path}: schedule entry #{schedule_index} must define a non-empty cron string"
                            )
                        elif len(cron_value.split()) != 5:
                            errors.append(
                                f"{path}: schedule entry #{schedule_index} cron must contain exactly 5 fields"
                            )
            if "workflow_dispatch" in trigger_config:
                workflow_dispatch_trigger = trigger_config.get("workflow_dispatch")
                if not isinstance(workflow_dispatch_trigger, dict):
                    errors.append(
                        f"{path}: workflow_dispatch trigger must be a mapping (use '{{}}' when no inputs are needed)"
                    )
                else:
                    workflow_inputs = workflow_dispatch_trigger.get("inputs")
                    if workflow_inputs is not None:
                        if not isinstance(workflow_inputs, dict) or not workflow_inputs:
                            errors.append(
                                f"{path}: workflow_dispatch.inputs must be a non-empty mapping when provided"
                            )
                        else:
                            allowed_dispatch_types = {
                                "string",
                                "boolean",
                                "choice",
                                "environment",
                                "number",
                            }
                            for input_name, input_config in workflow_inputs.items():
                                if (
                                    not isinstance(input_name, str)
                                    or not input_name.strip()
                                ):
                                    errors.append(
                                        f"{path}: workflow_dispatch.inputs keys must be non-empty strings"
                                    )
                                    continue
                                if not isinstance(input_config, dict):
                                    errors.append(
                                        f"{path}: workflow_dispatch input '{input_name}' must be a mapping"
                                    )
                                    continue
                                unsupported_input_keys = set(input_config.keys()) - {
                                    "description",
                                    "required",
                                    "default",
                                    "type",
                                    "options",
                                }
                                if unsupported_input_keys:
                                    errors.append(
                                        f"{path}: workflow_dispatch input '{input_name}' has unsupported keys: {sorted(unsupported_input_keys)}"
                                    )
                                description = input_config.get("description")
                                if (
                                    not isinstance(description, str)
                                    or not description.strip()
                                ):
                                    errors.append(
                                        f"{path}: workflow_dispatch input '{input_name}' must define a non-empty description"
                                    )
                                required_value = input_config.get("required")
                                if (
                                    required_value is not None
                                    and type(required_value) is not bool
                                ):
                                    errors.append(
                                        f"{path}: workflow_dispatch input '{input_name}' required must be boolean when provided"
                                    )
                                default_value = input_config.get("default")
                                if default_value is not None:
                                    if isinstance(default_value, str):
                                        if not default_value.strip():
                                            errors.append(
                                                f"{path}: workflow_dispatch input '{input_name}' default must not be an empty string"
                                            )
                                    elif (
                                        type(default_value) is not bool
                                        and not isinstance(default_value, (int, float))
                                    ):
                                        errors.append(
                                            f"{path}: workflow_dispatch input '{input_name}' default must be a scalar (string, number, or boolean) when provided"
                                        )
                                input_type = input_config.get("type")
                                if (
                                    not isinstance(input_type, str)
                                    or input_type not in allowed_dispatch_types
                                ):
                                    errors.append(
                                        f"{path}: workflow_dispatch input '{input_name}' type must be one of {sorted(allowed_dispatch_types)}"
                                    )
                                elif input_type == "choice":
                                    options = input_config.get("options")
                                    if not isinstance(options, list) or not options:
                                        errors.append(
                                            f"{path}: workflow_dispatch choice input '{input_name}' must define a non-empty options list"
                                        )
                                    else:
                                        normalized_options = [
                                            option.strip()
                                            for option in options
                                            if isinstance(option, str)
                                            and option.strip()
                                        ]
                                        if len(normalized_options) != len(options):
                                            errors.append(
                                                f"{path}: workflow_dispatch choice input '{input_name}' options must contain only non-empty strings"
                                            )
                                        elif len(set(normalized_options)) != len(
                                            normalized_options
                                        ):
                                            errors.append(
                                                f"{path}: workflow_dispatch choice input '{input_name}' options must be unique"
                                            )
                                        elif default_value is not None:
                                            if not isinstance(default_value, str):
                                                errors.append(
                                                    f"{path}: workflow_dispatch choice input '{input_name}' default must be a string when provided"
                                                )
                                            elif (
                                                default_value.strip()
                                                not in normalized_options
                                            ):
                                                errors.append(
                                                    f"{path}: workflow_dispatch choice input '{input_name}' default must be one of options"
                                                )
                                elif "options" in input_config:
                                    errors.append(
                                        f"{path}: workflow_dispatch input '{input_name}' may define options only when type is 'choice'"
                                    )
                                if default_value is not None:
                                    if input_type == "boolean" and type(default_value) is not bool:
                                        errors.append(
                                            f"{path}: workflow_dispatch input '{input_name}' default must be boolean for type 'boolean'"
                                        )
                                    elif input_type == "number" and (
                                        type(default_value) is bool
                                        or not isinstance(default_value, (int, float))
                                    ):
                                        errors.append(
                                            f"{path}: workflow_dispatch input '{input_name}' default must be numeric for type 'number'"
                                        )
                                    elif input_type in {"string", "environment"} and not isinstance(
                                        default_value, str
                                    ):
                                        errors.append(
                                            f"{path}: workflow_dispatch input '{input_name}' default must be a string for type '{input_type}'"
                                        )
            if "push" in trigger_config:
                push_trigger = trigger_config.get("push")
                if not isinstance(push_trigger, dict):
                    errors.append(
                        f"{path}: push trigger must be a mapping with explicit branches"
                    )
                else:
                    branches = push_trigger.get("branches")
                    if not isinstance(branches, list) or not branches:
                        errors.append(
                            f"{path}: push.branches must be a non-empty list"
                        )
                    else:
                        normalized_branches = [
                            b.strip() for b in branches if isinstance(b, str) and b.strip()
                        ]
                        if len(normalized_branches) != len(branches):
                            errors.append(
                                f"{path}: push.branches must contain only non-empty strings"
                            )
                        elif not {"main", "master"} & set(normalized_branches):
                            errors.append(
                                f"{path}: push.branches must include 'main' or 'master'"
                            )
            if "pull_request" in trigger_config:
                pr_trigger = trigger_config.get("pull_request")
                if not isinstance(pr_trigger, dict):
                    errors.append(
                        f"{path}: pull_request trigger must be a mapping with explicit branches"
                    )
                else:
                    branches = pr_trigger.get("branches")
                    if not isinstance(branches, list) or not branches:
                        errors.append(
                            f"{path}: pull_request.branches must be a non-empty list"
                        )
                    else:
                        normalized_branches = [
                            b.strip() for b in branches if isinstance(b, str) and b.strip()
                        ]
                        if len(normalized_branches) != len(branches):
                            errors.append(
                                f"{path}: pull_request.branches must contain only non-empty strings"
                            )
                        elif not {"main", "master"} & set(normalized_branches):
                            errors.append(
                                f"{path}: pull_request.branches must include 'main' or 'master'"
                            )
            if "pull_request_target" in trigger_config:
                errors.append(f"{path}: pull_request_target trigger is not allowed")

        concurrency = data.get("concurrency")
        if not isinstance(concurrency, dict):
            errors.append(f"{path}: missing top-level concurrency mapping")
        else:
            group = concurrency.get("group")
            cancel = concurrency.get("cancel-in-progress")
            if not group:
                errors.append(f"{path}: concurrency.group is missing or empty")
            else:
                filename = os.path.basename(path)
                if filename == "pages.yml":
                    if group != "pages":
                        errors.append(
                            f"{path}: pages workflow must use concurrency.group 'pages'"
                        )
                elif (
                    "${{ github.workflow }}" not in group
                    or "${{ github.ref }}" not in group
                ):
                    errors.append(
                        f"{path}: concurrency.group must include '${{ github.workflow }}' and '${{ github.ref }}'"
                    )
            if cancel is not True:
                errors.append(f"{path}: concurrency.cancel-in-progress must be true")

        permissions = data.get("permissions")
        if not isinstance(permissions, dict):
            errors.append(f"{path}: missing top-level permissions mapping")
        else:
            filename = os.path.basename(path)
            contents_permission = permissions.get("contents")
            if contents_permission != "read":
                errors.append(
                    f"{path}: permissions.contents must be explicitly set to 'read'"
                )
            if filename == "pages.yml":
                if permissions.get("pages") != "write":
                    errors.append(
                        f"{path}: pages workflow must set top-level permissions.pages to 'write'"
                    )
                if permissions.get("id-token") != "write":
                    errors.append(
                        f"{path}: pages workflow must set top-level permissions.id-token to 'write'"
                    )
                extra_permissions = set(permissions.keys()) - {
                    "contents",
                    "pages",
                    "id-token",
                }
                if extra_permissions:
                    errors.append(
                        f"{path}: pages workflow has unsupported top-level permissions: {sorted(extra_permissions)}"
                    )
            else:
                extra_permissions = set(permissions.keys()) - {"contents"}
                if extra_permissions:
                    errors.append(
                        f"{path}: only permissions.contents is allowed at top-level for non-pages workflows, found: {sorted(extra_permissions)}"
                    )

        jobs = data.get("jobs")
        if not isinstance(jobs, dict) or not jobs:
            errors.append(f"{path}: jobs mapping is missing or empty")
            continue

        job_display_name_to_ids: dict[str, list[str]] = {}
        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                errors.append(f"{path}: job '{job_name}' must be a mapping")
                continue

            display_name = job.get("name")
            if not isinstance(display_name, str) or not display_name.strip():
                errors.append(
                    f"{path}: job '{job_name}' must define a non-empty name"
                )
            else:
                normalized_display_name = display_name.strip()
                job_display_name_to_ids.setdefault(normalized_display_name, []).append(
                    job_name
                )

            validate_env_mapping(errors, path, f"job '{job_name}'", job.get("env"))
            validate_defaults_run(errors, path, f"job '{job_name}'", job.get("defaults"))

            runs_on = job.get("runs-on")
            if runs_on != "ubuntu-latest":
                errors.append(
                    f"{path}: job '{job_name}' must set runs-on to 'ubuntu-latest'"
                )
            job_strategy = job.get("strategy")
            if job_strategy is not None:
                if not isinstance(job_strategy, dict):
                    errors.append(
                        f"{path}: job '{job_name}' strategy must be a mapping when provided"
                    )
                else:
                    unsupported_strategy_keys = set(job_strategy.keys()) - {
                        "fail-fast",
                        "max-parallel",
                        "matrix",
                    }
                    if unsupported_strategy_keys:
                        errors.append(
                            f"{path}: job '{job_name}' strategy has unsupported keys: {sorted(unsupported_strategy_keys)}"
                        )
                    strategy_fail_fast = job_strategy.get("fail-fast")
                    if strategy_fail_fast is not None and type(strategy_fail_fast) is not bool:
                        errors.append(
                            f"{path}: job '{job_name}' strategy.fail-fast must be boolean when provided"
                        )
                    strategy_max_parallel = job_strategy.get("max-parallel")
                    if strategy_max_parallel is not None and (
                        type(strategy_max_parallel) is not int or strategy_max_parallel <= 0
                    ):
                        errors.append(
                            f"{path}: job '{job_name}' strategy.max-parallel must be a positive integer when provided"
                        )
                    strategy_matrix = job_strategy.get("matrix")
                    if strategy_matrix is not None and (
                        not isinstance(strategy_matrix, dict) or not strategy_matrix
                    ):
                        errors.append(
                            f"{path}: job '{job_name}' strategy.matrix must be a non-empty mapping when provided"
                        )
                    elif isinstance(strategy_matrix, dict):
                        for matrix_key, matrix_value in strategy_matrix.items():
                            if matrix_key in {"include", "exclude"}:
                                continue
                            if not isinstance(matrix_value, list) or not matrix_value:
                                errors.append(
                                    f"{path}: job '{job_name}' strategy.matrix.{matrix_key} must be a non-empty list"
                                )
                                continue
                            for value_index, matrix_dimension_value in enumerate(matrix_value):
                                if isinstance(matrix_dimension_value, str):
                                    if not matrix_dimension_value.strip():
                                        errors.append(
                                            f"{path}: job '{job_name}' strategy.matrix.{matrix_key}[{value_index}] must not be an empty string"
                                        )
                                elif (
                                    type(matrix_dimension_value) is not bool
                                    and not isinstance(matrix_dimension_value, (int, float))
                                ):
                                    errors.append(
                                        f"{path}: job '{job_name}' strategy.matrix.{matrix_key}[{value_index}] must be a scalar (string, number, or boolean)"
                                    )
                        for matrix_list_key in ("include", "exclude"):
                            matrix_list_value = strategy_matrix.get(matrix_list_key)
                            if matrix_list_value is None:
                                continue
                            if not isinstance(matrix_list_value, list):
                                errors.append(
                                    f"{path}: job '{job_name}' strategy.matrix.{matrix_list_key} must be a list when provided"
                                )
                                continue
                            if not matrix_list_value:
                                errors.append(
                                    f"{path}: job '{job_name}' strategy.matrix.{matrix_list_key} must not be an empty list when provided"
                                )
                                continue
                            for matrix_index, matrix_item in enumerate(matrix_list_value):
                                if not isinstance(matrix_item, dict) or not matrix_item:
                                    errors.append(
                                        f"{path}: job '{job_name}' strategy.matrix.{matrix_list_key}[{matrix_index}] must be a non-empty mapping"
                                    )
                                    continue
                                for entry_key, entry_value in matrix_item.items():
                                    if not isinstance(entry_key, str) or not entry_key.strip():
                                        errors.append(
                                            f"{path}: job '{job_name}' strategy.matrix.{matrix_list_key}[{matrix_index}] keys must be non-empty strings"
                                        )
                                    if isinstance(entry_value, str):
                                        if not entry_value.strip():
                                            errors.append(
                                                f"{path}: job '{job_name}' strategy.matrix.{matrix_list_key}[{matrix_index}]['{entry_key}'] must not be an empty string"
                                            )
                                    elif (
                                        type(entry_value) is not bool
                                        and not isinstance(entry_value, (int, float))
                                    ):
                                        errors.append(
                                            f"{path}: job '{job_name}' strategy.matrix.{matrix_list_key}[{matrix_index}]['{entry_key}'] must be a scalar (string, number, or boolean)"
                                        )
            job_needs = job.get("needs")
            if isinstance(job_needs, str):
                normalized_need = job_needs.strip()
                if not normalized_need:
                    errors.append(
                        f"{path}: job '{job_name}' needs must be a non-empty string when provided as a string"
                    )
                elif normalized_need == job_name:
                    errors.append(
                        f"{path}: job '{job_name}' must not depend on itself via needs"
                    )
            elif isinstance(job_needs, list):
                if not job_needs:
                    errors.append(
                        f"{path}: job '{job_name}' needs must not be an empty list"
                    )
                else:
                    normalized_needs: list[str] = []
                    for need_index, need_value in enumerate(job_needs):
                        if not isinstance(need_value, str) or not need_value.strip():
                            errors.append(
                                f"{path}: job '{job_name}' needs[{need_index}] must be a non-empty string"
                            )
                            continue
                        normalized_need = need_value.strip()
                        if normalized_need == job_name:
                            errors.append(
                                f"{path}: job '{job_name}' must not depend on itself via needs[{need_index}]"
                            )
                        normalized_needs.append(normalized_need)
                    if len(set(normalized_needs)) != len(normalized_needs):
                        errors.append(
                            f"{path}: job '{job_name}' needs list must not contain duplicates"
                        )
            elif job_needs is not None:
                errors.append(
                    f"{path}: job '{job_name}' needs must be a string or a list of strings"
                )
            job_if = job.get("if")
            if job_if is not None and (not isinstance(job_if, str) or not job_if.strip()):
                errors.append(
                    f"{path}: job '{job_name}' if must be a non-empty string when provided"
                )

            job_continue_on_error = job.get("continue-on-error")
            if job_continue_on_error is not None and type(job_continue_on_error) is not bool:
                errors.append(
                    f"{path}: job '{job_name}' continue-on-error must be boolean when provided"
                )
            if job_continue_on_error is True:
                errors.append(
                    f"{path}: job '{job_name}' must not set continue-on-error to true"
                )

            job_permissions = job.get("permissions")
            filename = os.path.basename(path)
            if job_permissions is not None:
                if filename == "release.yml" and job_name == "publish-release":
                    if (
                        not isinstance(job_permissions, dict)
                        or job_permissions.get("contents") != "write"
                    ):
                        errors.append(
                            f"{path}: job '{job_name}' must set permissions.contents to 'write'"
                        )
                    elif set(job_permissions.keys()) != {"contents"}:
                        errors.append(
                            f"{path}: job '{job_name}' may only define permissions.contents"
                        )
                else:
                    errors.append(
                        f"{path}: job '{job_name}' must not define job-level permissions"
                    )

            timeout = job.get("timeout-minutes")
            if type(timeout) is not int or timeout <= 0:
                errors.append(
                    f"{path}: job '{job_name}' must define positive integer timeout-minutes"
                )
            elif timeout > 60:
                errors.append(
                    f"{path}: job '{job_name}' timeout-minutes must be <= 60"
                )
            job_working_directory = job.get("working-directory")
            if job_working_directory is not None and (
                not isinstance(job_working_directory, str)
                or not job_working_directory.strip()
            ):
                errors.append(
                    f"{path}: job '{job_name}' working-directory must be a non-empty string when provided"
                )

            steps = job.get("steps", [])
            if not isinstance(steps, list):
                errors.append(f"{path}: job '{job_name}' steps must be a list")
                continue
            step_display_name_to_indexes: dict[str, list[int]] = {}
            for step_index, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue
                validate_env_mapping(
                    errors,
                    path,
                    f"job '{job_name}' step #{step_index}",
                    step.get("env"),
                )
                step_name = step.get("name")
                if not isinstance(step_name, str) or not step_name.strip():
                    errors.append(
                        f"{path}: job '{job_name}' step #{step_index} must define a non-empty name"
                    )
                else:
                    normalized_step_name = step_name.strip()
                    step_display_name_to_indexes.setdefault(
                        normalized_step_name, []
                    ).append(step_index)
                step_if = step.get("if")
                if step_if is not None and (not isinstance(step_if, str) or not step_if.strip()):
                    errors.append(
                        f"{path}: job '{job_name}' step #{step_index} if must be a non-empty string when provided"
                    )
                step_continue_on_error = step.get("continue-on-error")
                if (
                    step_continue_on_error is not None
                    and type(step_continue_on_error) is not bool
                ):
                    errors.append(
                        f"{path}: job '{job_name}' step #{step_index} continue-on-error must be boolean when provided"
                    )
                if step_continue_on_error is True:
                    errors.append(
                        f"{path}: job '{job_name}' step #{step_index} must not set continue-on-error to true"
                    )
                step_uses = step.get("uses")
                step_run = step.get("run")
                step_with = step.get("with")
                if step_with is not None:
                    if not isinstance(step_with, dict):
                        errors.append(
                            f"{path}: job '{job_name}' step #{step_index} with must be a mapping when provided"
                        )
                    else:
                        for with_key, with_value in step_with.items():
                            if not isinstance(with_key, str) or not with_key.strip():
                                errors.append(
                                    f"{path}: job '{job_name}' step #{step_index} with keys must be non-empty strings"
                                )
                            if isinstance(with_value, str):
                                if not with_value.strip():
                                    errors.append(
                                        f"{path}: job '{job_name}' step #{step_index} with['{with_key}'] must not be an empty string"
                                    )
                            elif (
                                type(with_value) is not bool
                                and not isinstance(with_value, (int, float))
                            ):
                                errors.append(
                                    f"{path}: job '{job_name}' step #{step_index} with['{with_key}'] must be a scalar (string, number, or boolean)"
                                )
                if step_uses is None and step_run is None:
                    errors.append(
                        f"{path}: job '{job_name}' step #{step_index} must define exactly one of 'uses' or 'run'"
                    )
                if step_uses is not None and step_run is not None:
                    errors.append(
                        f"{path}: job '{job_name}' step #{step_index} must not define both 'uses' and 'run'"
                    )
                if step_uses is not None and (
                    not isinstance(step_uses, str) or not step_uses.strip()
                ):
                    errors.append(
                        f"{path}: job '{job_name}' step #{step_index} uses must be a non-empty string when provided"
                    )
                if step_run is not None and (
                    not isinstance(step_run, str) or not step_run.strip()
                ):
                    errors.append(
                        f"{path}: job '{job_name}' step #{step_index} run must be a non-empty string when provided"
                    )
                step_working_directory = step.get("working-directory")
                if step_working_directory is not None and (
                    not isinstance(step_working_directory, str)
                    or not step_working_directory.strip()
                ):
                    errors.append(
                        f"{path}: job '{job_name}' step #{step_index} working-directory must be a non-empty string when provided"
                    )
                if (
                    isinstance(step_uses, str)
                    and not step_uses.startswith("./")
                    and not step_uses.startswith("docker://")
                    and "@" not in step_uses
                ):
                    errors.append(
                        f"{path}: job '{job_name}' step #{step_index} external action uses must include an explicit '@ref'"
                    )
                if (
                    isinstance(step_uses, str)
                    and "@" in step_uses
                    and not step_uses.startswith("./")
                ):
                    action_ref = step_uses.rsplit("@", 1)[1]
                    if action_ref in {"main", "master", "HEAD", "latest"}:
                        errors.append(
                            f"{path}: job '{job_name}' step #{step_index} uses disallowed floating action ref '{action_ref}'"
                        )
                if isinstance(step_uses, str) and step_uses.startswith(
                    "actions/checkout@"
                ):
                    if step_uses != "actions/checkout@v4":
                        errors.append(
                            f"{path}: job '{job_name}' checkout step #{step_index} must use actions/checkout@v4"
                        )
                    with_cfg = step_with
                    persist = (
                        with_cfg.get("persist-credentials")
                        if isinstance(with_cfg, dict)
                        else None
                    )
                    if persist is not False:
                        errors.append(
                            f"{path}: job '{job_name}' checkout step #{step_index} must set with.persist-credentials to false"
                        )
            for step_display_name, step_indexes in step_display_name_to_indexes.items():
                if len(step_indexes) > 1:
                    errors.append(
                        f"{path}: job '{job_name}' step name '{step_display_name}' must be unique within the job (used at indexes: {step_indexes})"
                    )

        for display_name, job_ids in job_display_name_to_ids.items():
            if len(job_ids) > 1:
                errors.append(
                    f"{path}: job display name '{display_name}' must be unique within a workflow (used by jobs: {job_ids})"
                )

        print(f"OK {path}")

    for workflow_name, paths in workflow_name_to_paths.items():
        if len(paths) > 1:
            for path in paths:
                errors.append(
                    f"{path}: top-level workflow name '{workflow_name}' must be unique across .github/workflows"
                )

    if errors:
        for err in errors:
            print(err)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

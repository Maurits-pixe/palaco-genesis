#!/usr/bin/env python3

import glob
import os
import re
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
    unsupported_defaults_keys = set(defaults_value.keys()) - {"run"}
    if unsupported_defaults_keys:
        errors.append(
            f"{path}: {scope} defaults has unsupported keys: {sorted(unsupported_defaults_keys)}"
        )
    run_defaults = defaults_value.get("run")
    if run_defaults is None:
        return
    if not isinstance(run_defaults, dict):
        errors.append(f"{path}: {scope} defaults.run must be a mapping when provided")
        return
    unsupported_run_defaults_keys = set(run_defaults.keys()) - {
        "working-directory",
        "shell",
    }
    if unsupported_run_defaults_keys:
        errors.append(
            f"{path}: {scope} defaults.run has unsupported keys: {sorted(unsupported_run_defaults_keys)}"
        )
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


def validate_non_empty_string_list(
    errors: list[str], path: str, field_name: str, field_value: object
) -> list[str] | None:
    if not isinstance(field_value, list) or not field_value:
        errors.append(f"{path}: {field_name} must be a non-empty list")
        return None
    normalized_values: list[str] = []
    for value_index, value in enumerate(field_value):
        if not isinstance(value, str) or not value.strip():
            errors.append(
                f"{path}: {field_name}[{value_index}] must be a non-empty string"
            )
            continue
        normalized_values.append(value.strip())
    if len(set(normalized_values)) != len(normalized_values):
        errors.append(f"{path}: {field_name} must not contain duplicates")
    return normalized_values


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
        unsupported_top_level_keys = set(data.keys()) - {
            "name",
            "on",
            True,
            "permissions",
            "concurrency",
            "jobs",
            "env",
            "defaults",
        }
        if unsupported_top_level_keys:
            errors.append(
                f"{path}: workflow root has unsupported top-level keys: {sorted(unsupported_top_level_keys, key=str)}"
            )

        workflow_name = data.get("name")
        if not isinstance(workflow_name, str) or not workflow_name.strip():
            errors.append(f"{path}: top-level workflow name must be a non-empty string")
        else:
            normalized_name = workflow_name.strip()
            workflow_name_to_paths.setdefault(normalized_name, []).append(path)

        validate_env_mapping(errors, path, "workflow", data.get("env"))
        validate_defaults_run(errors, path, "workflow", data.get("defaults"))
        if os.path.basename(path) == "release.yml":
            workflow_env = data.get("env")
            if (
                not isinstance(workflow_env, dict)
                or workflow_env.get("CARGO_TERM_COLOR") != "always"
            ):
                errors.append(
                    f"{path}: release workflow must set env.CARGO_TERM_COLOR to 'always'"
                )
            elif set(workflow_env.keys()) != {"CARGO_TERM_COLOR"}:
                errors.append(
                    f"{path}: release workflow env may only define CARGO_TERM_COLOR"
                )

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

        allowed_top_level_triggers = {
            "workflow_dispatch",
            "push",
            "pull_request",
            "schedule",
        }

        if isinstance(trigger_config, str):
            normalized_trigger = trigger_config.strip()
            if normalized_trigger and normalized_trigger not in allowed_top_level_triggers:
                errors.append(
                    f"{path}: top-level workflow 'on' string trigger '{normalized_trigger}' is not allowed"
                )
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
            normalized_triggers: list[str] = []
            for trigger_index, trigger_name in enumerate(trigger_config):
                if not isinstance(trigger_name, str) or not trigger_name.strip():
                    errors.append(
                        f"{path}: top-level workflow 'on' trigger list item #{trigger_index} must be a non-empty string"
                    )
                    continue
                normalized_triggers.append(trigger_name.strip())
            if len(set(normalized_triggers)) != len(normalized_triggers):
                errors.append(
                    f"{path}: top-level workflow 'on' trigger list must not contain duplicates"
                )
            unsupported_list_triggers = sorted(
                trigger_name
                for trigger_name in set(normalized_triggers)
                if trigger_name not in allowed_top_level_triggers
            )
            if unsupported_list_triggers:
                errors.append(
                    f"{path}: top-level workflow 'on' trigger list has unsupported triggers: {unsupported_list_triggers}"
                )
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
            unsupported_trigger_keys = set(trigger_config.keys()) - allowed_top_level_triggers
            if unsupported_trigger_keys:
                errors.append(
                    f"{path}: top-level workflow 'on' mapping has unsupported triggers: {sorted(unsupported_trigger_keys)}"
                )
            if os.path.basename(path) == "release.yml" and "workflow_dispatch" not in trigger_config:
                errors.append(
                    f"{path}: release workflow must define workflow_dispatch trigger"
                )
            if os.path.basename(path) == "release.yml":
                unsupported_release_triggers = set(trigger_config.keys()) - {
                    "workflow_dispatch"
                }
                if unsupported_release_triggers:
                    errors.append(
                        f"{path}: release workflow supports only workflow_dispatch trigger, found: {sorted(unsupported_release_triggers)}"
                    )
            if "schedule" in trigger_config:
                schedule_trigger = trigger_config.get("schedule")
                if not isinstance(schedule_trigger, list) or not schedule_trigger:
                    errors.append(
                        f"{path}: schedule trigger must be a non-empty list of mappings with non-empty cron strings"
                    )
                else:
                    normalized_schedule_crons: list[str] = []
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
                        else:
                            normalized_schedule_crons.append(cron_value.strip())
                    if len(set(normalized_schedule_crons)) != len(normalized_schedule_crons):
                        errors.append(
                            f"{path}: schedule trigger must not contain duplicate cron entries"
                        )
            if "workflow_dispatch" in trigger_config:
                workflow_dispatch_trigger = trigger_config.get("workflow_dispatch")
                if not isinstance(workflow_dispatch_trigger, dict):
                    errors.append(
                        f"{path}: workflow_dispatch trigger must be a mapping (use '{{}}' when no inputs are needed)"
                    )
                else:
                    unsupported_dispatch_trigger_keys = set(
                        workflow_dispatch_trigger.keys()
                    ) - {"inputs"}
                    if unsupported_dispatch_trigger_keys:
                        errors.append(
                            f"{path}: workflow_dispatch trigger has unsupported keys: {sorted(unsupported_dispatch_trigger_keys)}"
                        )
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
                                if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", input_name):
                                    errors.append(
                                        f"{path}: workflow_dispatch input '{input_name}' must match ^[A-Za-z_][A-Za-z0-9_-]*$"
                                    )
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
                    if os.path.basename(path) == "release.yml":
                        if not isinstance(workflow_inputs, dict) or "release_tag" not in workflow_inputs:
                            errors.append(
                                f"{path}: release workflow must define workflow_dispatch input 'release_tag'"
                            )
                        else:
                            unsupported_release_inputs = set(workflow_inputs.keys()) - {
                                "release_tag"
                            }
                            if unsupported_release_inputs:
                                errors.append(
                                    f"{path}: release workflow_dispatch inputs has unsupported keys: {sorted(unsupported_release_inputs)}"
                                )
                            release_tag_input = workflow_inputs.get("release_tag")
                            if not isinstance(release_tag_input, dict):
                                errors.append(
                                    f"{path}: workflow_dispatch input 'release_tag' must be a mapping"
                                )
                            else:
                                if release_tag_input.get("type") != "string":
                                    errors.append(
                                        f"{path}: workflow_dispatch input 'release_tag' must set type to 'string'"
                                    )
                                if release_tag_input.get("required") is not False:
                                    errors.append(
                                        f"{path}: workflow_dispatch input 'release_tag' must set required to false"
                                    )
                                if "default" in release_tag_input:
                                    errors.append(
                                        f"{path}: workflow_dispatch input 'release_tag' must not define default"
                                    )
            if "push" in trigger_config:
                push_trigger = trigger_config.get("push")
                if not isinstance(push_trigger, dict):
                    errors.append(
                        f"{path}: push trigger must be a mapping with explicit branches"
                    )
                else:
                    unsupported_push_trigger_keys = set(push_trigger.keys()) - {
                        "branches",
                        "branches-ignore",
                        "tags",
                        "tags-ignore",
                        "paths",
                        "paths-ignore",
                    }
                    if unsupported_push_trigger_keys:
                        errors.append(
                            f"{path}: push trigger has unsupported keys: {sorted(unsupported_push_trigger_keys)}"
                        )
                    if "branches" in push_trigger and "branches-ignore" in push_trigger:
                        errors.append(
                            f"{path}: push trigger must not define both branches and branches-ignore"
                        )
                    if "tags" in push_trigger and "tags-ignore" in push_trigger:
                        errors.append(
                            f"{path}: push trigger must not define both tags and tags-ignore"
                        )
                    if "paths" in push_trigger and "paths-ignore" in push_trigger:
                        errors.append(
                            f"{path}: push trigger must not define both paths and paths-ignore"
                        )
                    for push_list_key in (
                        "branches-ignore",
                        "tags",
                        "tags-ignore",
                        "paths",
                        "paths-ignore",
                    ):
                        if push_list_key in push_trigger:
                            validate_non_empty_string_list(
                                errors,
                                path,
                                f"push.{push_list_key}",
                                push_trigger.get(push_list_key),
                            )
                    branches = push_trigger.get("branches")
                    if branches is None:
                        errors.append(
                            f"{path}: push.branches must be a non-empty list"
                        )
                    else:
                        normalized_branches = validate_non_empty_string_list(
                            errors, path, "push.branches", branches
                        )
                        if normalized_branches and not {"main", "master"} & set(
                            normalized_branches
                        ):
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
                    unsupported_pr_trigger_keys = set(pr_trigger.keys()) - {
                        "branches",
                        "branches-ignore",
                        "paths",
                        "paths-ignore",
                        "types",
                    }
                    if unsupported_pr_trigger_keys:
                        errors.append(
                            f"{path}: pull_request trigger has unsupported keys: {sorted(unsupported_pr_trigger_keys)}"
                        )
                    if "branches" in pr_trigger and "branches-ignore" in pr_trigger:
                        errors.append(
                            f"{path}: pull_request trigger must not define both branches and branches-ignore"
                        )
                    if "paths" in pr_trigger and "paths-ignore" in pr_trigger:
                        errors.append(
                            f"{path}: pull_request trigger must not define both paths and paths-ignore"
                        )
                    for pr_list_key in ("branches-ignore", "paths", "paths-ignore", "types"):
                        if pr_list_key in pr_trigger:
                            normalized_values = validate_non_empty_string_list(
                                errors,
                                path,
                                f"pull_request.{pr_list_key}",
                                pr_trigger.get(pr_list_key),
                            )
                            if pr_list_key == "types" and normalized_values:
                                allowed_pr_types = {
                                    "assigned",
                                    "unassigned",
                                    "labeled",
                                    "unlabeled",
                                    "opened",
                                    "edited",
                                    "closed",
                                    "reopened",
                                    "synchronize",
                                    "converted_to_draft",
                                    "ready_for_review",
                                    "locked",
                                    "unlocked",
                                    "review_requested",
                                    "review_request_removed",
                                    "auto_merge_enabled",
                                    "auto_merge_disabled",
                                    "milestoned",
                                    "demilestoned",
                                    "enqueued",
                                    "dequeued",
                                }
                                invalid_pr_types = sorted(
                                    pr_type
                                    for pr_type in normalized_values
                                    if pr_type not in allowed_pr_types
                                )
                                if invalid_pr_types:
                                    errors.append(
                                        f"{path}: pull_request.types contains unsupported events: {invalid_pr_types}"
                                    )
                    branches = pr_trigger.get("branches")
                    if branches is None:
                        errors.append(
                            f"{path}: pull_request.branches must be a non-empty list"
                        )
                    else:
                        normalized_branches = validate_non_empty_string_list(
                            errors, path, "pull_request.branches", branches
                        )
                        if normalized_branches and not {"main", "master"} & set(
                            normalized_branches
                        ):
                            errors.append(
                                f"{path}: pull_request.branches must include 'main' or 'master'"
                            )
            if "pull_request_target" in trigger_config:
                errors.append(f"{path}: pull_request_target trigger is not allowed")

        concurrency = data.get("concurrency")
        if not isinstance(concurrency, dict):
            errors.append(f"{path}: missing top-level concurrency mapping")
        else:
            unsupported_concurrency_keys = set(concurrency.keys()) - {
                "group",
                "cancel-in-progress",
            }
            if unsupported_concurrency_keys:
                errors.append(
                    f"{path}: concurrency has unsupported keys: {sorted(unsupported_concurrency_keys)}"
                )
            group = concurrency.get("group")
            cancel = concurrency.get("cancel-in-progress")
            if not isinstance(group, str) or not group.strip():
                errors.append(
                    f"{path}: concurrency.group must be a non-empty string"
                )
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
            for permission_key, permission_value in permissions.items():
                if not isinstance(permission_key, str) or not permission_key.strip():
                    errors.append(
                        f"{path}: permissions keys must be non-empty strings"
                    )
                if not isinstance(permission_value, str) or not permission_value.strip():
                    errors.append(
                        f"{path}: permissions['{permission_key}'] must be a non-empty string"
                    )
                elif permission_value not in {"read", "write", "none"}:
                    errors.append(
                        f"{path}: permissions['{permission_key}'] must be one of 'read', 'write', or 'none'"
                    )
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
        workflow_filename = os.path.basename(path)
        if workflow_filename == "release.yml" and "release-readiness" not in jobs:
            errors.append(f"{path}: release workflow must define job 'release-readiness'")
        if workflow_filename == "release.yml" and "build-binaries" not in jobs:
            errors.append(f"{path}: release workflow must define job 'build-binaries'")
        if workflow_filename == "release.yml" and "publish-release" not in jobs:
            errors.append(f"{path}: release workflow must define job 'publish-release'")

        known_job_ids = set(jobs.keys())
        job_display_name_to_ids: dict[str, list[str]] = {}
        for job_name, job in jobs.items():
            if not isinstance(job_name, str) or not job_name.strip():
                errors.append(f"{path}: jobs keys must be non-empty strings")
                continue
            normalized_job_name = job_name.strip()
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", normalized_job_name):
                errors.append(
                    f"{path}: job id '{normalized_job_name}' must match ^[A-Za-z_][A-Za-z0-9_-]*$"
                )
            if not isinstance(job, dict):
                errors.append(f"{path}: job '{job_name}' must be a mapping")
                continue
            unsupported_job_keys = set(job.keys()) - {
                "name",
                "runs-on",
                "steps",
                "timeout-minutes",
                "needs",
                "if",
                "permissions",
                "strategy",
                "env",
                "defaults",
                "continue-on-error",
                "environment",
            }
            if unsupported_job_keys:
                errors.append(
                    f"{path}: job '{job_name}' has unsupported keys: {sorted(unsupported_job_keys)}"
                )

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
                if (
                    workflow_filename == "release.yml"
                    and job_name == "release-readiness"
                    and normalized_display_name != "Release readiness checks"
                ):
                    errors.append(
                        f"{path}: job '{job_name}' must set name to 'Release readiness checks'"
                    )
                if (
                    workflow_filename == "release.yml"
                    and job_name == "build-binaries"
                    and normalized_display_name != "Build release binaries"
                ):
                    errors.append(
                        f"{path}: job '{job_name}' must set name to 'Build release binaries'"
                    )
                if (
                    workflow_filename == "release.yml"
                    and job_name == "publish-release"
                    and normalized_display_name != "Publish GitHub release"
                ):
                    errors.append(
                        f"{path}: job '{job_name}' must set name to 'Publish GitHub release'"
                    )

            validate_env_mapping(errors, path, f"job '{job_name}'", job.get("env"))
            if (
                workflow_filename == "release.yml"
                and job_name == "publish-release"
                and job.get("env") is not None
            ):
                errors.append(
                    f"{path}: job '{job_name}' must not define job-level env"
                )
            if (
                workflow_filename == "release.yml"
                and job_name == "publish-release"
                and job.get("defaults") is not None
            ):
                errors.append(
                    f"{path}: job '{job_name}' must not define job-level defaults"
                )
            if (
                workflow_filename == "release.yml"
                and job_name == "publish-release"
                and job.get("environment") is not None
            ):
                errors.append(
                    f"{path}: job '{job_name}' must not define job-level environment"
                )
            validate_defaults_run(errors, path, f"job '{job_name}'", job.get("defaults"))

            runs_on = job.get("runs-on")
            if runs_on != "ubuntu-latest":
                errors.append(
                    f"{path}: job '{job_name}' must set runs-on to 'ubuntu-latest'"
                )
            job_strategy = job.get("strategy")
            if (
                workflow_filename == "release.yml"
                and job_name == "publish-release"
                and job_strategy is not None
            ):
                errors.append(
                    f"{path}: job '{job_name}' must not define job-level strategy"
                )
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
            normalized_job_needs: set[str] = set()
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
                elif normalized_need not in known_job_ids:
                    errors.append(
                        f"{path}: job '{job_name}' needs references unknown job '{normalized_need}'"
                    )
                else:
                    normalized_job_needs.add(normalized_need)
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
                        elif normalized_need not in known_job_ids:
                            errors.append(
                                f"{path}: job '{job_name}' needs[{need_index}] references unknown job '{normalized_need}'"
                            )
                        normalized_needs.append(normalized_need)
                    if len(set(normalized_needs)) != len(normalized_needs):
                        errors.append(
                            f"{path}: job '{job_name}' needs list must not contain duplicates"
                        )
                    normalized_job_needs.update(normalized_needs)
            elif job_needs is not None:
                errors.append(
                    f"{path}: job '{job_name}' needs must be a string or a list of strings"
                )
            if (
                workflow_filename == "release.yml"
                and job_name == "publish-release"
                and "build-binaries" not in normalized_job_needs
            ):
                errors.append(
                    f"{path}: job '{job_name}' must depend on 'build-binaries' via needs"
                )
            if workflow_filename == "release.yml" and job_name == "publish-release":
                if not isinstance(job_needs, str) or job_needs.strip() != "build-binaries":
                    errors.append(
                        f"{path}: job '{job_name}' must set needs to exactly 'build-binaries'"
                    )
            if workflow_filename == "release.yml" and job_name == "build-binaries":
                if not isinstance(job_needs, str) or job_needs.strip() != "release-readiness":
                    errors.append(
                        f"{path}: job '{job_name}' must set needs to exactly 'release-readiness'"
                    )
            if workflow_filename == "release.yml" and job_name == "release-readiness":
                if job_needs is not None:
                    errors.append(
                        f"{path}: job '{job_name}' must not define needs"
                    )
            job_if = job.get("if")
            if job_if is not None and (not isinstance(job_if, str) or not job_if.strip()):
                errors.append(
                    f"{path}: job '{job_name}' if must be a non-empty string when provided"
                )
            if workflow_filename == "release.yml" and job_name == "build-binaries":
                if job_if is not None:
                    errors.append(
                        f"{path}: job '{job_name}' must not define if"
                    )
            if workflow_filename == "release.yml" and job_name == "release-readiness":
                if job_if is not None:
                    errors.append(
                        f"{path}: job '{job_name}' must not define if"
                    )
            if workflow_filename == "release.yml" and job_name == "publish-release":
                if not isinstance(job_if, str) or not job_if.strip():
                    errors.append(
                        f"{path}: job '{job_name}' must define an if guard referencing github.event.inputs.release_tag"
                    )
                elif "github.event.inputs.release_tag" not in job_if:
                    errors.append(
                        f"{path}: job '{job_name}' if must reference github.event.inputs.release_tag"
                    )
                elif job_if.replace(" ", "") not in {
                    "github.event.inputs.release_tag!=''",
                    "${{github.event.inputs.release_tag!=''}}",
                }:
                    errors.append(
                        f"{path}: job '{job_name}' if must be exactly github.event.inputs.release_tag != '' (optionally wrapped in ${{ }})"
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
            if (
                filename == "release.yml"
                and job_name == "publish-release"
                and job_permissions is None
            ):
                errors.append(
                    f"{path}: job '{job_name}' must define permissions.contents as 'write'"
                )
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
            if workflow_filename == "release.yml" and timeout != 30:
                errors.append(
                    f"{path}: job '{job_name}' in release workflow must set timeout-minutes to 30"
                )
            job_environment = job.get("environment")
            if job_environment is not None:
                if isinstance(job_environment, str):
                    if not job_environment.strip():
                        errors.append(
                            f"{path}: job '{job_name}' environment must be a non-empty string when provided as a string"
                        )
                elif isinstance(job_environment, dict):
                    unsupported_environment_keys = set(job_environment.keys()) - {
                        "name",
                        "url",
                    }
                    if unsupported_environment_keys:
                        errors.append(
                            f"{path}: job '{job_name}' environment has unsupported keys: {sorted(unsupported_environment_keys)}"
                        )
                    environment_name = job_environment.get("name")
                    if not isinstance(environment_name, str) or not environment_name.strip():
                        errors.append(
                            f"{path}: job '{job_name}' environment.name must be a non-empty string"
                        )
                    environment_url = job_environment.get("url")
                    if environment_url is not None and (
                        not isinstance(environment_url, str) or not environment_url.strip()
                    ):
                        errors.append(
                            f"{path}: job '{job_name}' environment.url must be a non-empty string when provided"
                        )
                else:
                    errors.append(
                        f"{path}: job '{job_name}' environment must be a string or mapping when provided"
                    )
            steps = job.get("steps", [])
            if not isinstance(steps, list):
                errors.append(f"{path}: job '{job_name}' steps must be a list")
                continue
            if not steps:
                errors.append(f"{path}: job '{job_name}' steps must not be empty")
                continue
            step_display_name_to_indexes: dict[str, list[int]] = {}
            step_id_to_indexes: dict[str, list[int]] = {}
            release_readiness_upload_steps = 0
            release_readiness_upload_step_index: int | None = None
            release_readiness_capture_steps = 0
            release_readiness_capture_step_index: int | None = None
            build_binaries_upload_steps = 0
            build_binaries_upload_step_index: int | None = None
            build_binaries_build_steps = 0
            build_binaries_build_step_index: int | None = None
            build_binaries_prepare_steps = 0
            build_binaries_prepare_step_index: int | None = None
            build_binaries_manifest_steps = 0
            build_binaries_manifest_step_index: int | None = None
            publish_release_action_steps = 0
            publish_release_download_steps = 0
            publish_release_download_step_index: int | None = None
            publish_release_action_step_index: int | None = None
            for step_index, step in enumerate(steps):
                if not isinstance(step, dict):
                    errors.append(
                        f"{path}: job '{job_name}' step #{step_index} must be a mapping"
                    )
                    continue
                unsupported_step_keys = set(step.keys()) - {
                    "name",
                    "id",
                    "if",
                    "continue-on-error",
                    "uses",
                    "run",
                    "with",
                    "env",
                    "working-directory",
                    "shell",
                }
                if unsupported_step_keys:
                    errors.append(
                        f"{path}: job '{job_name}' step #{step_index} has unsupported keys: {sorted(unsupported_step_keys)}"
                    )
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
                step_id = step.get("id")
                if step_id is not None:
                    if not isinstance(step_id, str) or not step_id.strip():
                        errors.append(
                            f"{path}: job '{job_name}' step #{step_index} id must be a non-empty string when provided"
                        )
                    else:
                        normalized_step_id = step_id.strip()
                        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", normalized_step_id):
                            errors.append(
                                f"{path}: job '{job_name}' step #{step_index} id '{normalized_step_id}' must match ^[A-Za-z_][A-Za-z0-9_-]*$"
                            )
                        step_id_to_indexes.setdefault(normalized_step_id, []).append(
                            step_index
                        )
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
                step_shell = step.get("shell")
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
                if step_with is not None and step_uses is None:
                    errors.append(
                        f"{path}: job '{job_name}' step #{step_index} with is only allowed on uses steps"
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
                if (
                    workflow_filename == "release.yml"
                    and job_name == "publish-release"
                    and step_run is not None
                ):
                    errors.append(
                        f"{path}: job '{job_name}' step #{step_index} must use 'uses' and must not define 'run'"
                    )
                if step_shell is not None and (
                    not isinstance(step_shell, str) or not step_shell.strip()
                ):
                    errors.append(
                        f"{path}: job '{job_name}' step #{step_index} shell must be a non-empty string when provided"
                    )
                if step_shell is not None and step_run is None:
                    errors.append(
                        f"{path}: job '{job_name}' step #{step_index} shell is only allowed on run steps"
                    )
                step_working_directory = step.get("working-directory")
                if step_working_directory is not None and (
                    not isinstance(step_working_directory, str)
                    or not step_working_directory.strip()
                ):
                    errors.append(
                        f"{path}: job '{job_name}' step #{step_index} working-directory must be a non-empty string when provided"
                    )
                if step_working_directory is not None and step_run is None:
                    errors.append(
                        f"{path}: job '{job_name}' step #{step_index} working-directory is only allowed on run steps"
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
                if (
                    workflow_filename == "release.yml"
                    and job_name == "release-readiness"
                    and step_name == "Capture release context"
                ):
                    release_readiness_capture_steps += 1
                    release_readiness_capture_step_index = step_index
                    if step_run is None:
                        errors.append(
                            f"{path}: job '{job_name}' step #{step_index} named 'Capture release context' must define run"
                        )
                    elif isinstance(step_run, str):
                        normalized_capture_commands = [
                            line.strip()
                            for line in step_run.splitlines()
                            if line.strip()
                        ]
                        required_capture_commands = [
                            "mkdir -p release-evidence",
                            "{",
                            'echo "release_tag=${{ github.event.inputs.release_tag }}"',
                            'echo "commit=${{ github.sha }}"',
                            'echo "run_id=${{ github.run_id }}"',
                            "} > release-evidence/context.txt",
                        ]
                        if normalized_capture_commands != required_capture_commands:
                            errors.append(
                                f"{path}: job '{job_name}' step #{step_index} named 'Capture release context' must set run to exactly {required_capture_commands}"
                            )
                if (
                    workflow_filename == "release.yml"
                    and job_name == "release-readiness"
                    and isinstance(step_uses, str)
                    and step_uses.strip() == "actions/upload-artifact@v4"
                ):
                    release_readiness_upload_steps += 1
                    release_readiness_upload_step_index = step_index
                    if step_id is not None:
                        errors.append(
                            f"{path}: job '{job_name}' actions/upload-artifact@v4 step #{step_index} must not define id"
                        )
                    if step_continue_on_error is not None:
                        errors.append(
                            f"{path}: job '{job_name}' actions/upload-artifact@v4 step #{step_index} must not define continue-on-error"
                        )
                    if step.get("env") is not None:
                        errors.append(
                            f"{path}: job '{job_name}' actions/upload-artifact@v4 step #{step_index} must not define env"
                        )
                    if step_if is not None:
                        errors.append(
                            f"{path}: job '{job_name}' actions/upload-artifact@v4 step #{step_index} must not define if"
                        )
                    if step_name != "Upload release evidence":
                        errors.append(
                            f"{path}: job '{job_name}' actions/upload-artifact@v4 step #{step_index} must set name to 'Upload release evidence'"
                        )
                    if not isinstance(step_with, dict):
                        errors.append(
                            f"{path}: job '{job_name}' actions/upload-artifact@v4 step #{step_index} must define with.name and with.path"
                        )
                    else:
                        unsupported_upload_with_keys = set(step_with.keys()) - {
                            "name",
                            "path",
                        }
                        if unsupported_upload_with_keys:
                            errors.append(
                                f"{path}: job '{job_name}' actions/upload-artifact@v4 step #{step_index} has unsupported with keys: {sorted(unsupported_upload_with_keys)}"
                            )
                        if step_with.get("name") != "release-evidence":
                            errors.append(
                                f"{path}: job '{job_name}' actions/upload-artifact@v4 step #{step_index} must set with.name to 'release-evidence'"
                            )
                        if step_with.get("path") != "release-evidence/":
                            errors.append(
                                f"{path}: job '{job_name}' actions/upload-artifact@v4 step #{step_index} must set with.path to 'release-evidence/'"
                            )
                if (
                    workflow_filename == "release.yml"
                    and job_name == "build-binaries"
                    and step_name == "Build palaco-citadel-contracts binaries"
                ):
                    build_binaries_build_steps += 1
                    build_binaries_build_step_index = step_index
                    if step_run is None:
                        errors.append(
                            f"{path}: job '{job_name}' step #{step_index} named 'Build palaco-citadel-contracts binaries' must define run"
                        )
                    elif step_run.strip() != "cargo build --release -p palaco-citadel-contracts --bins":
                        errors.append(
                            f"{path}: job '{job_name}' step #{step_index} named 'Build palaco-citadel-contracts binaries' must set run to 'cargo build --release -p palaco-citadel-contracts --bins'"
                        )
                    if step_id is not None:
                        errors.append(
                            f"{path}: job '{job_name}' step #{step_index} named 'Build palaco-citadel-contracts binaries' must not define id"
                        )
                    if step_working_directory is not None:
                        errors.append(
                            f"{path}: job '{job_name}' step #{step_index} named 'Build palaco-citadel-contracts binaries' must not define working-directory"
                        )
                    if step_shell is not None:
                        errors.append(
                            f"{path}: job '{job_name}' step #{step_index} named 'Build palaco-citadel-contracts binaries' must not define shell"
                        )
                    if step.get("env") is not None:
                        errors.append(
                            f"{path}: job '{job_name}' step #{step_index} named 'Build palaco-citadel-contracts binaries' must not define env"
                        )
                    if step_continue_on_error is not None:
                        errors.append(
                            f"{path}: job '{job_name}' step #{step_index} named 'Build palaco-citadel-contracts binaries' must not define continue-on-error"
                        )
                    if step_if is not None:
                        errors.append(
                            f"{path}: job '{job_name}' step #{step_index} named 'Build palaco-citadel-contracts binaries' must not define if"
                        )
                if (
                    workflow_filename == "release.yml"
                    and job_name == "build-binaries"
                    and step_name == "Prepare release binaries"
                ):
                    build_binaries_prepare_steps += 1
                    build_binaries_prepare_step_index = step_index
                    if step_run is None:
                        errors.append(
                            f"{path}: job '{job_name}' step #{step_index} named 'Prepare release binaries' must define run"
                        )
                    elif isinstance(step_run, str):
                        normalized_prepare_commands = [
                            line.strip()
                            for line in step_run.splitlines()
                            if line.strip()
                        ]
                        required_prepare_commands = [
                            "mkdir -p release-binaries",
                            "cp target/release/citadel-a1 release-binaries/",
                            "cp target/release/citadel-a1-canonical release-binaries/",
                        ]
                        if normalized_prepare_commands != required_prepare_commands:
                            errors.append(
                                f"{path}: job '{job_name}' step #{step_index} named 'Prepare release binaries' must set run to exactly {required_prepare_commands}"
                            )
                    if step_id is not None:
                        errors.append(
                            f"{path}: job '{job_name}' step #{step_index} named 'Prepare release binaries' must not define id"
                        )
                    if step_working_directory is not None:
                        errors.append(
                            f"{path}: job '{job_name}' step #{step_index} named 'Prepare release binaries' must not define working-directory"
                        )
                    if step_shell is not None:
                        errors.append(
                            f"{path}: job '{job_name}' step #{step_index} named 'Prepare release binaries' must not define shell"
                        )
                    if step.get("env") is not None:
                        errors.append(
                            f"{path}: job '{job_name}' step #{step_index} named 'Prepare release binaries' must not define env"
                        )
                    if step_continue_on_error is not None:
                        errors.append(
                            f"{path}: job '{job_name}' step #{step_index} named 'Prepare release binaries' must not define continue-on-error"
                        )
                    if step_if is not None:
                        errors.append(
                            f"{path}: job '{job_name}' step #{step_index} named 'Prepare release binaries' must not define if"
                        )
                if (
                    workflow_filename == "release.yml"
                    and job_name == "build-binaries"
                    and step_name == "Generate checksums and manifest"
                ):
                    build_binaries_manifest_steps += 1
                    build_binaries_manifest_step_index = step_index
                    if step_run is None:
                        errors.append(
                            f"{path}: job '{job_name}' step #{step_index} named 'Generate checksums and manifest' must define run"
                        )
                    elif isinstance(step_run, str):
                        normalized_manifest_commands = [
                            line.strip()
                            for line in step_run.splitlines()
                            if line.strip()
                        ]
                        required_manifest_commands = [
                            "sha256sum release-binaries/citadel-a1 > release-binaries/SHA256SUMS",
                            "sha256sum release-binaries/citadel-a1-canonical >> release-binaries/SHA256SUMS",
                            "cat > release-binaries/release-manifest.json <<'JSON'",
                            "{",
                            '"artifacts": [',
                            '"citadel-a1",',
                            '"citadel-a1-canonical",',
                            '"SHA256SUMS"',
                            "],",
                            '"source_package": "palaco-citadel-contracts",',
                            '"workflow": "release.yml"',
                            "}",
                            "JSON",
                        ]
                        if normalized_manifest_commands != required_manifest_commands:
                            errors.append(
                                f"{path}: job '{job_name}' step #{step_index} named 'Generate checksums and manifest' must set run to exactly {required_manifest_commands}"
                            )
                    if step_id is not None:
                        errors.append(
                            f"{path}: job '{job_name}' step #{step_index} named 'Generate checksums and manifest' must not define id"
                        )
                    if step_working_directory is not None:
                        errors.append(
                            f"{path}: job '{job_name}' step #{step_index} named 'Generate checksums and manifest' must not define working-directory"
                        )
                if (
                    workflow_filename == "release.yml"
                    and job_name == "build-binaries"
                    and isinstance(step_uses, str)
                    and step_uses.strip() == "actions/upload-artifact@v4"
                ):
                    build_binaries_upload_steps += 1
                    build_binaries_upload_step_index = step_index
                    if step_id is not None:
                        errors.append(
                            f"{path}: job '{job_name}' actions/upload-artifact@v4 step #{step_index} must not define id"
                        )
                    if step_continue_on_error is not None:
                        errors.append(
                            f"{path}: job '{job_name}' actions/upload-artifact@v4 step #{step_index} must not define continue-on-error"
                        )
                    if step.get("env") is not None:
                        errors.append(
                            f"{path}: job '{job_name}' actions/upload-artifact@v4 step #{step_index} must not define env"
                        )
                    if step_if is not None:
                        errors.append(
                            f"{path}: job '{job_name}' actions/upload-artifact@v4 step #{step_index} must not define if"
                        )
                    if step_name != "Upload release binaries":
                        errors.append(
                            f"{path}: job '{job_name}' actions/upload-artifact@v4 step #{step_index} must set name to 'Upload release binaries'"
                        )
                    if not isinstance(step_with, dict):
                        errors.append(
                            f"{path}: job '{job_name}' actions/upload-artifact@v4 step #{step_index} must define with.name and with.path"
                        )
                    else:
                        unsupported_upload_with_keys = set(step_with.keys()) - {
                            "name",
                            "path",
                        }
                        if unsupported_upload_with_keys:
                            errors.append(
                                f"{path}: job '{job_name}' actions/upload-artifact@v4 step #{step_index} has unsupported with keys: {sorted(unsupported_upload_with_keys)}"
                            )
                        if step_with.get("name") != "release-binaries":
                            errors.append(
                                f"{path}: job '{job_name}' actions/upload-artifact@v4 step #{step_index} must set with.name to 'release-binaries'"
                            )
                        if step_with.get("path") != "release-binaries/":
                            errors.append(
                                f"{path}: job '{job_name}' actions/upload-artifact@v4 step #{step_index} must set with.path to 'release-binaries/'"
                            )
                if (
                    workflow_filename == "release.yml"
                    and job_name == "publish-release"
                    and isinstance(step_uses, str)
                    and step_uses.strip() == "actions/download-artifact@v4"
                ):
                    publish_release_download_steps += 1
                    publish_release_download_step_index = step_index
                    if step_id is not None:
                        errors.append(
                            f"{path}: job '{job_name}' actions/download-artifact@v4 step #{step_index} must not define id"
                        )
                    if step_continue_on_error is not None:
                        errors.append(
                            f"{path}: job '{job_name}' actions/download-artifact@v4 step #{step_index} must not define continue-on-error"
                        )
                    if step.get("env") is not None:
                        errors.append(
                            f"{path}: job '{job_name}' actions/download-artifact@v4 step #{step_index} must not define env"
                        )
                    if step_if is not None:
                        errors.append(
                            f"{path}: job '{job_name}' actions/download-artifact@v4 step #{step_index} must not define if"
                        )
                    if step_name != "Download release binaries":
                        errors.append(
                            f"{path}: job '{job_name}' actions/download-artifact@v4 step #{step_index} must set name to 'Download release binaries'"
                        )
                    if not isinstance(step_with, dict):
                        errors.append(
                            f"{path}: job '{job_name}' actions/download-artifact@v4 step #{step_index} must define with.name and with.path"
                        )
                    else:
                        unsupported_download_with_keys = set(step_with.keys()) - {
                            "name",
                            "path",
                        }
                        if unsupported_download_with_keys:
                            errors.append(
                                f"{path}: job '{job_name}' actions/download-artifact@v4 step #{step_index} has unsupported with keys: {sorted(unsupported_download_with_keys)}"
                            )
                        if step_with.get("name") != "release-binaries":
                            errors.append(
                                f"{path}: job '{job_name}' actions/download-artifact@v4 step #{step_index} must set with.name to 'release-binaries'"
                            )
                        if step_with.get("path") != "release-binaries":
                            errors.append(
                                f"{path}: job '{job_name}' actions/download-artifact@v4 step #{step_index} must set with.path to 'release-binaries'"
                            )
                if (
                    workflow_filename == "release.yml"
                    and job_name == "publish-release"
                    and isinstance(step_uses, str)
                    and step_uses.strip() == "softprops/action-gh-release@v2"
                ):
                    publish_release_action_steps += 1
                    publish_release_action_step_index = step_index
                    if step_id is not None:
                        errors.append(
                            f"{path}: job '{job_name}' softprops/action-gh-release@v2 step #{step_index} must not define id"
                        )
                    if step_continue_on_error is not None:
                        errors.append(
                            f"{path}: job '{job_name}' softprops/action-gh-release@v2 step #{step_index} must not define continue-on-error"
                        )
                    if step.get("env") is not None:
                        errors.append(
                            f"{path}: job '{job_name}' softprops/action-gh-release@v2 step #{step_index} must not define env"
                        )
                    if step_if is not None:
                        errors.append(
                            f"{path}: job '{job_name}' softprops/action-gh-release@v2 step #{step_index} must not define if"
                        )
                    if step_name != "Publish release":
                        errors.append(
                            f"{path}: job '{job_name}' softprops/action-gh-release@v2 step #{step_index} must set name to 'Publish release'"
                        )
                    required_release_files = [
                        "release-binaries/citadel-a1",
                        "release-binaries/citadel-a1-canonical",
                        "release-binaries/SHA256SUMS",
                        "release-binaries/release-manifest.json",
                    ]
                    if not isinstance(step_with, dict):
                        errors.append(
                            f"{path}: job '{job_name}' softprops/action-gh-release@v2 step #{step_index} must define with.tag_name and with.files"
                        )
                    else:
                        unsupported_release_with_keys = set(step_with.keys()) - {
                            "tag_name",
                            "files",
                        }
                        if unsupported_release_with_keys:
                            errors.append(
                                f"{path}: job '{job_name}' softprops/action-gh-release@v2 step #{step_index} has unsupported with keys: {sorted(unsupported_release_with_keys)}"
                            )
                        if (
                            step_with.get("tag_name")
                            != "${{ github.event.inputs.release_tag }}"
                        ):
                            errors.append(
                                f"{path}: job '{job_name}' softprops/action-gh-release@v2 step #{step_index} must set with.tag_name to '${{ github.event.inputs.release_tag }}'"
                            )
                        files_value = step_with.get("files")
                        if not isinstance(files_value, str) or not files_value.strip():
                            errors.append(
                                f"{path}: job '{job_name}' softprops/action-gh-release@v2 step #{step_index} must define with.files with all release artifacts"
                            )
                        else:
                            normalized_files = [
                                line.strip()
                                for line in files_value.splitlines()
                                if line.strip()
                            ]
                            if normalized_files != required_release_files:
                                errors.append(
                                    f"{path}: job '{job_name}' softprops/action-gh-release@v2 step #{step_index} must set with.files to exactly {required_release_files}"
                                )
                if isinstance(step_uses, str) and step_uses.startswith(
                    "actions/checkout@"
                ):
                    if (
                        workflow_filename == "release.yml"
                        and job_name == "publish-release"
                    ):
                        errors.append(
                            f"{path}: job '{job_name}' must not use actions/checkout steps"
                        )
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
            for step_id, step_indexes in step_id_to_indexes.items():
                if len(step_indexes) > 1:
                    errors.append(
                        f"{path}: job '{job_name}' step id '{step_id}' must be unique within the job (used at indexes: {step_indexes})"
                    )
            if (
                workflow_filename == "release.yml"
                and job_name == "release-readiness"
                and release_readiness_capture_steps != 1
            ):
                errors.append(
                    f"{path}: job '{job_name}' must contain exactly one step named 'Capture release context'"
                )
            if (
                workflow_filename == "release.yml"
                and job_name == "release-readiness"
                and release_readiness_upload_steps != 1
            ):
                errors.append(
                    f"{path}: job '{job_name}' must contain exactly one step using actions/upload-artifact@v4"
                )
            if (
                workflow_filename == "release.yml"
                and job_name == "release-readiness"
                and release_readiness_upload_step_index is not None
                and release_readiness_upload_step_index != len(steps) - 1
            ):
                errors.append(
                    f"{path}: job '{job_name}' must place actions/upload-artifact@v4 as the last step"
                )
            if (
                workflow_filename == "release.yml"
                and job_name == "release-readiness"
                and release_readiness_capture_step_index is not None
                and release_readiness_upload_step_index is not None
                and release_readiness_capture_step_index
                != release_readiness_upload_step_index - 1
            ):
                errors.append(
                    f"{path}: job '{job_name}' must place step 'Capture release context' directly before actions/upload-artifact@v4"
                )
            if (
                workflow_filename == "release.yml"
                and job_name == "build-binaries"
                and build_binaries_build_steps != 1
            ):
                errors.append(
                    f"{path}: job '{job_name}' must contain exactly one step named 'Build palaco-citadel-contracts binaries'"
                )
            if (
                workflow_filename == "release.yml"
                and job_name == "build-binaries"
                and build_binaries_prepare_steps != 1
            ):
                errors.append(
                    f"{path}: job '{job_name}' must contain exactly one step named 'Prepare release binaries'"
                )
            if (
                workflow_filename == "release.yml"
                and job_name == "build-binaries"
                and build_binaries_manifest_steps != 1
            ):
                errors.append(
                    f"{path}: job '{job_name}' must contain exactly one step named 'Generate checksums and manifest'"
                )
            if (
                workflow_filename == "release.yml"
                and job_name == "build-binaries"
                and build_binaries_upload_steps != 1
            ):
                errors.append(
                    f"{path}: job '{job_name}' must contain exactly one step using actions/upload-artifact@v4"
                )
            if (
                workflow_filename == "release.yml"
                and job_name == "build-binaries"
                and build_binaries_upload_step_index is not None
                and build_binaries_upload_step_index != len(steps) - 1
            ):
                errors.append(
                    f"{path}: job '{job_name}' must place actions/upload-artifact@v4 as the last step"
                )
            if (
                workflow_filename == "release.yml"
                and job_name == "build-binaries"
                and build_binaries_manifest_step_index is not None
                and build_binaries_upload_step_index is not None
                and build_binaries_manifest_step_index
                != build_binaries_upload_step_index - 1
            ):
                errors.append(
                    f"{path}: job '{job_name}' must place step 'Generate checksums and manifest' directly before actions/upload-artifact@v4"
                )
            if (
                workflow_filename == "release.yml"
                and job_name == "build-binaries"
                and build_binaries_prepare_step_index is not None
                and build_binaries_manifest_step_index is not None
                and build_binaries_prepare_step_index
                != build_binaries_manifest_step_index - 1
            ):
                errors.append(
                    f"{path}: job '{job_name}' must place step 'Prepare release binaries' directly before step 'Generate checksums and manifest'"
                )
            if (
                workflow_filename == "release.yml"
                and job_name == "build-binaries"
                and build_binaries_build_step_index is not None
                and build_binaries_prepare_step_index is not None
                and build_binaries_build_step_index
                != build_binaries_prepare_step_index - 1
            ):
                errors.append(
                    f"{path}: job '{job_name}' must place step 'Build palaco-citadel-contracts binaries' directly before step 'Prepare release binaries'"
                )
            if (
                workflow_filename == "release.yml"
                and job_name == "publish-release"
                and len(steps) != 2
            ):
                errors.append(
                    f"{path}: job '{job_name}' must define exactly 2 steps"
                )
            if (
                workflow_filename == "release.yml"
                and job_name == "publish-release"
                and publish_release_download_steps != 1
            ):
                errors.append(
                    f"{path}: job '{job_name}' must contain exactly one step using actions/download-artifact@v4"
                )
            if (
                workflow_filename == "release.yml"
                and job_name == "publish-release"
                and publish_release_action_steps != 1
            ):
                errors.append(
                    f"{path}: job '{job_name}' must contain exactly one step using softprops/action-gh-release@v2"
                )
            if (
                workflow_filename == "release.yml"
                and job_name == "publish-release"
                and publish_release_download_step_index is not None
                and publish_release_action_step_index is not None
                and publish_release_download_step_index > publish_release_action_step_index
            ):
                errors.append(
                    f"{path}: job '{job_name}' must place actions/download-artifact@v4 before softprops/action-gh-release@v2"
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

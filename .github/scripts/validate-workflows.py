#!/usr/bin/env python3

import glob
import os
import sys

import yaml


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

        trigger_config = data.get("on", data.get(True))
        if isinstance(trigger_config, str):
            if trigger_config == "pull_request_target":
                errors.append(f"{path}: pull_request_target trigger is not allowed")
        elif isinstance(trigger_config, list):
            if "pull_request_target" in trigger_config:
                errors.append(f"{path}: pull_request_target trigger is not allowed")
        elif isinstance(trigger_config, dict):
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

            runs_on = job.get("runs-on")
            if runs_on != "ubuntu-latest":
                errors.append(
                    f"{path}: job '{job_name}' must set runs-on to 'ubuntu-latest'"
                )

            if job.get("continue-on-error") is True:
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
            if not isinstance(timeout, int) or timeout <= 0:
                errors.append(
                    f"{path}: job '{job_name}' must define positive timeout-minutes"
                )
            elif timeout > 60:
                errors.append(
                    f"{path}: job '{job_name}' timeout-minutes must be <= 60"
                )

            steps = job.get("steps", [])
            if not isinstance(steps, list):
                errors.append(f"{path}: job '{job_name}' steps must be a list")
                continue

            for step_index, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue
                if step.get("continue-on-error") is True:
                    errors.append(
                        f"{path}: job '{job_name}' step #{step_index} must not set continue-on-error to true"
                    )
                step_uses = step.get("uses")
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
                    with_cfg = step.get("with")
                    persist = (
                        with_cfg.get("persist-credentials")
                        if isinstance(with_cfg, dict)
                        else None
                    )
                    if persist is not False:
                        errors.append(
                            f"{path}: job '{job_name}' checkout step #{step_index} must set with.persist-credentials to false"
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

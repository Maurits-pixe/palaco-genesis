"""PALACO v6.8: read-only independent GitHub Actions run metadata comparison.

The verifier uses GitHub's HTTPS REST API, not merely GITHUB_RUN_ID claims.
Requires read-only GITHUB_TOKEN and permission actions:read. It compares
repository, run ID, event type, run attempt and the run's head commit against
the checkout SHA or (for PR builds) the event's PR head SHA. API metadata
remains a TLS/API observation, NOT a cryptographically signed attestation.
No artifact release, GitHub writes, credentials in output or ALLOW path.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import urllib.error
import urllib.parse
import urllib.request

from verify_scm_ci_incident import EvidenceRejected
from witness_continuity_v63 import strictly_parse

REQUIRED_RUN_FIELDS = {"id", "run_attempt", "event", "head_sha", "repository"}
REQUIRED_CONTEXT = ("GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
                    "GITHUB_EVENT_NAME", "GITHUB_SHA")


def verify_run_payload(remote: dict, context: dict[str, str],
                       event: dict) -> dict[str, str]:
    if not REQUIRED_RUN_FIELDS.issubset(remote):
        raise EvidenceRejected("incomplete GitHub Actions response")
    repository = remote["repository"]
    if type(repository) is not dict or repository.get("full_name") != context["GITHUB_REPOSITORY"]:
        raise EvidenceRejected("GitHub run repository mismatch")
    try:
        run_number = int(context["GITHUB_RUN_ID"])
        attempt = int(context["GITHUB_RUN_ATTEMPT"])
    except (ValueError, TypeError) as exc:
        raise EvidenceRejected("invalid GitHub run identity") from exc
    if (type(remote["id"]) is not int or remote["id"] != run_number or
            type(remote["run_attempt"]) is not int or remote["run_attempt"] != attempt or
            remote["event"] != context["GITHUB_EVENT_NAME"]):
        raise EvidenceRejected("GitHub run identity/event mismatch")
    sha = context["GITHUB_SHA"]
    head = remote["head_sha"]
    if (type(head) is not str or len(head) != 40 or
            any(ch not in "0123456789abcdef" for ch in head) or
            type(sha) is not str or len(sha) != 40 or
            any(ch not in "0123456789abcdef" for ch in sha)):
        raise EvidenceRejected("invalid source or checkout SHA")
    known = {sha}
    if context["GITHUB_EVENT_NAME"] == "pull_request":
        pr = event.get("pull_request")
        if type(pr) is not dict or type(pr.get("head")) is not dict:
            raise EvidenceRejected("missing PR source commit")
        pr_head = pr["head"].get("sha")
        if type(pr_head) is not str or len(pr_head) != 40:
            raise EvidenceRejected("invalid PR source commit")
        known.add(pr_head)
    if head not in known:
        raise EvidenceRejected("GitHub run head differs from event/checkout")
    return {"repository": context["GITHUB_REPOSITORY"], "run_id": str(run_number),
            "run_attempt": str(attempt), "event": remote["event"],
            "checkout_sha": sha, "api_head_sha": head}


def fetch_and_verify(context: dict[str, str], event_path: Path,
                     token: str) -> dict[str, str]:
    if not token or any(key not in context for key in REQUIRED_CONTEXT):
        raise EvidenceRejected("GitHub verification inputs missing")
    repo = context["GITHUB_REPOSITORY"]
    if (repo.count("/") != 1 or not all(
            part.replace("-", "").replace("_", "").replace(".", "").isalnum()
            for part in repo.split("/"))):
        raise EvidenceRejected("unsafe repository name")
    run_id = context["GITHUB_RUN_ID"]
    if not run_id.isascii() or not run_id.isdecimal() or not run_id or len(run_id) > 20:
        raise EvidenceRejected("invalid run ID")
    try:
        event = json.loads(event_path.read_text(encoding="utf-8"))
        if type(event) is not dict:
            raise ValueError("event not object")
        request = urllib.request.Request(
            "https://api.github.com/repos/" + repo + "/actions/runs/" + run_id,
            headers={"Authorization": "Bearer " + token,
                     "Accept": "application/vnd.github+json",
                     "X-GitHub-Api-Version": "2022-11-28",
                     "User-Agent": "palaco-ci-provenance-read-only"},
            method="GET")
        with urllib.request.urlopen(request, timeout=12) as response:
            if response.status != 200:
                raise EvidenceRejected("GitHub API response was not 200")
            raw = response.read(256 * 1024 + 1)
        if len(raw) > 256 * 1024:
            raise EvidenceRejected("GitHub response oversized")
        remote = json.loads(raw)
        if type(remote) is not dict:
            raise ValueError("run metadata not object")
    except (OSError, urllib.error.URLError, ValueError, json.JSONDecodeError) as exc:
        raise EvidenceRejected("independent GitHub read unavailable") from exc
    return verify_run_payload(remote, context, event)


def main() -> int:
    if os.environ.get("GITHUB_ACTIONS") != "true":
        print("PALACO v6.8 PROVENANCE DENY: not GitHub Actions")
        return 1
    try:
        context = {key: os.environ.get(key, "") for key in REQUIRED_CONTEXT}
        result = fetch_and_verify(context, Path(os.environ.get("GITHUB_EVENT_PATH", "")),
                                  os.environ.get("GITHUB_TOKEN", ""))
    except EvidenceRejected as exc:
        print("PALACO v6.8 PROVENANCE DENY: " + str(exc))
        return 1
    # Deliberately omit access tokens and arbitrary API metadata.
    print("PALACO v6.8 PROVENANCE PASS (independent GitHub REST read; "
          + result["repository"] + "; run " + result["run_id"]
          + " attempt " + result["run_attempt"]
          + "; TLS metadata, NOT a cryptographic attestation)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

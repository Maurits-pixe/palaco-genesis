"""WNRA-06S: fail-closed candidate evidence contract for process-specific access denials.

Pure Python deterministic validation. No collector, signing authority, root
cause certification, authorization, or policy change is implemented.
"""
from dataclasses import dataclass
from typing import Optional

DENY = "DENY"
ALLOWED_PROVIDERS = frozenset({"kernel_file_event", "security_audit_event"})
ALLOWED_OPERATIONS = frozenset({
    "file_open", "image_section_map", "directory_traverse",
})


@dataclass(frozen=True)
class WorkerContext:
    pid: int
    image: str
    created_ms: int
    exited_ms: int
    exit_status: int
    token_verified: bool
    job_before_resume: bool


@dataclass(frozen=True)
class FailureEvent:
    pid: int
    image: str
    occurred_ms: int
    provider: str
    operation: str
    object_path: str
    status: int
    event_id: str
    source_record_id: str
    externally_verified: bool = False


@dataclass(frozen=True)
class GateDecision:
    candidate_for_review: bool
    reasons: tuple
    authorization: str = DENY
    root_cause: str = "UNKNOWN"


def evaluate_candidate(worker: WorkerContext, event: Optional[FailureEvent]):
    """Determine only review eligibility; never certify causality or authorize."""
    reasons = []
    if not isinstance(worker.pid, int) or worker.pid <= 0:
        reasons.append("worker_pid_invalid")
    if not isinstance(worker.image, str) or not worker.image.strip():
        reasons.append("worker_image_invalid")
    if not isinstance(worker.created_ms, int) or not isinstance(worker.exited_ms, int):
        reasons.append("worker_time_invalid")
    elif worker.created_ms < 0 or worker.exited_ms < worker.created_ms:
        reasons.append("worker_time_invalid")
    if worker.exit_status != 0xC0000022:
        reasons.append("worker_exit_not_access_denied")
    if worker.token_verified is not True:
        reasons.append("worker_token_unverified")
    if worker.job_before_resume is not True:
        reasons.append("worker_job_unverified")
    if event is None:
        reasons.append("no_process_specific_failure_event")
        return GateDecision(False, tuple(reasons))
    if not isinstance(event.pid, int) or event.pid != worker.pid:
        reasons.append("event_pid_mismatch")
    if not isinstance(event.image, str) or event.image.casefold() != worker.image.casefold():
        reasons.append("event_image_mismatch")
    if not isinstance(event.occurred_ms, int) or not (
        isinstance(worker.created_ms, int) and
        isinstance(worker.exited_ms, int) and
        worker.created_ms <= event.occurred_ms <= worker.exited_ms
    ):
        reasons.append("event_outside_worker_lifetime")
    if event.provider not in ALLOWED_PROVIDERS:
        reasons.append("event_provider_unrecognized")
    if event.operation not in ALLOWED_OPERATIONS:
        reasons.append("event_operation_unrecognized")
    if not isinstance(event.object_path, str) or not event.object_path.strip():
        reasons.append("event_object_missing")
    if event.status != 0xC0000022:
        reasons.append("event_status_not_access_denied")
    if not isinstance(event.event_id, str) or not event.event_id.strip():
        reasons.append("event_id_missing")
    if not isinstance(event.source_record_id, str) or not event.source_record_id.strip():
        reasons.append("event_source_record_missing")
    if event.externally_verified is not True:
        reasons.append("event_provenance_unverified")
    # The gate checks the claimed fields, not source authenticity; even a
    # syntactically eligible event remains UNVERIFIED as causal evidence.
    return GateDecision(not reasons, tuple(reasons))


def classify_legacy_observation(kind):
    """Legacy indirect observations alone cannot pass the causal gate."""
    if kind not in (
        "exit_code", "thread_exit", "module_snapshot",
        "controller_createfile", "static_pe_import", "timeline",
    ):
        raise ValueError("unknown legacy observation")
    return GateDecision(False, ("indirect_observation_not_causal",))

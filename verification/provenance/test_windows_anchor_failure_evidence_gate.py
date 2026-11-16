"""WNRA-06S: negative and controlled-candidate evidence gate regressions."""
from dataclasses import replace
import unittest

from windows_anchor_failure_evidence_gate import (
    DENY, FailureEvent, WorkerContext,
    classify_legacy_observation, evaluate_candidate,
)


class FailureEvidenceGateTests(unittest.TestCase):
    def setUp(self):
        self.worker = WorkerContext(
            pid=4316, image=r"C:\test\python.exe",
            created_ms=1000, exited_ms=1100, exit_status=0xC0000022,
            token_verified=True, job_before_resume=True,
        )
        self.event = FailureEvent(
            pid=4316, image=r"C:\test\python.exe",
            occurred_ms=1050, provider="kernel_file_event",
            operation="image_section_map", object_path=r"C:\test\python312.dll",
            status=0xC0000022, event_id="event-4316-7",
            source_record_id="trace-123/record-7", externally_verified=True,
        )

    def assert_denied(self, decision, why):
        self.assertFalse(decision.candidate_for_review, why)
        self.assertEqual(decision.authorization, DENY)
        self.assertEqual(decision.root_cause, "UNKNOWN")
        self.assertTrue(decision.reasons)

    def test_no_trace_and_legacy_indirect_evidence_denied(self):
        self.assert_denied(evaluate_candidate(self.worker, None), "missing event")
        for kind in (
            "exit_code", "thread_exit", "module_snapshot",
            "controller_createfile", "static_pe_import", "timeline",
        ):
            with self.subTest(kind=kind):
                self.assert_denied(classify_legacy_observation(kind), kind)
        with self.assertRaises(ValueError):
            classify_legacy_observation("unknown")
        print("WNRA06S_NEGATIVE legacy=6 missing_event=true authorization=DENY")

    def test_mismatch_and_unverified_provenance_denied(self):
        changes = (
            {"pid": 9999},
            {"image": r"C:\test\cmd.exe"},
            {"occurred_ms": 999},
            {"occurred_ms": 1101},
            {"provider": "controller_direct_open"},
            {"operation": "unknown"},
            {"object_path": ""},
            {"status": 5},
            {"event_id": ""},
            {"source_record_id": ""},
            {"externally_verified": False},
        )
        for change in changes:
            with self.subTest(change=change):
                decision = evaluate_candidate(self.worker, replace(self.event, **change))
                self.assert_denied(decision, str(change))
        print("WNRA06S_NEGATIVE event_mutations=11 authorization=DENY")

    def test_worker_mismatch_and_negative_status_denied(self):
        changes = (
            {"pid": 0},
            {"image": ""},
            {"created_ms": 2000},
            {"exit_status": 0},
            {"token_verified": False},
            {"job_before_resume": False},
        )
        for change in changes:
            with self.subTest(change=change):
                self.assert_denied(
                    evaluate_candidate(replace(self.worker, **change), self.event),
                    str(change),
                )
        print("WNRA06S_NEGATIVE worker_mutations=6 authorization=DENY")

    def test_well_formed_claim_is_only_review_candidate(self):
        candidate = evaluate_candidate(self.worker, self.event)
        self.assertTrue(candidate.candidate_for_review)
        self.assertEqual(candidate.reasons, ())
        self.assertEqual(candidate.authorization, DENY)
        self.assertEqual(candidate.root_cause, "UNKNOWN")
        # A forged in-memory object with externally_verified=True is indistinguishable
        # from a genuine event to this pure validator. It is never certification.
        print(
            "WNRA06S_CANDIDATE eligible_for_review=true"
            " provenance_authenticity_verified_by_gate=false"
            " root_cause=UNKNOWN authorization=DENY"
        )


if __name__ == "__main__":
    unittest.main()

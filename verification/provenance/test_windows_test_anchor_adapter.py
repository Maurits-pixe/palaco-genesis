"""Negative and boundary tests for WNRA-04Z simulated anchors."""
from dataclasses import replace
import unittest

from windows_test_anchor_adapter import (
    AnchorRequest, AnchorObservation, SimulatedAnchorAdapter,
    make_simulated_response, PROTOCOL,
)


def request(**changes: object) -> AnchorRequest:
    base = AnchorRequest(
        protocol=PROTOCOL,
        request_id="REQ-001",
        fixture_domain="TEST-WINDOWS",
        source_commit="a" * 40,
        record_digest="b" * 64,
        predecessor_anchor_id="GENESIS",
        sequence=1,
        evidence_ref="fixture:001",
        actor_id="local-test-actor",
    )
    return replace(base, **changes)


class SimulatedAnchorAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.adapter = SimulatedAnchorAdapter()
        self.req = request()
        self.reply = make_simulated_response(self.req)

    def assert_denied(self, observation: AnchorObservation, reason: str) -> None:
        self.assertFalse(observation.fixture_valid)
        self.assertEqual(observation.reason, reason)
        self.assertEqual(observation.authorization, "DENY")
        self.assertEqual(observation.independent_verification, "NOT_EXECUTED")

    def test_matched_fixture_never_authorizes(self) -> None:
        result = self.adapter.verify(self.req, self.reply)
        self.assertTrue(result.fixture_valid)
        self.assertEqual(result.reason, "SIMULATED_FIXTURE_MATCH_ONLY")
        self.assertEqual(result.authorization, "DENY")
        self.assertEqual(result.independent_verification, "NOT_EXECUTED")

    def test_missing_response_denied(self) -> None:
        self.assert_denied(self.adapter.verify(self.req, None), "MISSING_RESPONSE")

    def test_unavailable_denied_even_with_accept(self) -> None:
        self.assert_denied(
            self.adapter.verify(self.req, self.reply, available=False),
            "CUSTODIAN_UNAVAILABLE",
        )

    def test_denial_and_unknown_decisions_denied(self) -> None:
        for decision in ("DENIED", "UNAVAILABLE", "UNKNOWN", ""):
            with self.subTest(decision=decision):
                self.assert_denied(
                    SimulatedAnchorAdapter().verify(
                        self.req, replace(self.reply, decision=decision)
                    ),
                    "RESPONSE_NOT_ACCEPTED",
                )

    def test_untrusted_mock_key_denied(self) -> None:
        self.assert_denied(
            self.adapter.verify(self.req, self.reply, mock_key_trusted=False),
            "UNTRUSTED_MOCK_KEY",
        )

    def test_tampered_binding_fields_denied(self) -> None:
        fields = {
            "fixture_domain": "TEST-OTHER",
            "source_commit": "c" * 40,
            "record_digest": "d" * 64,
            "predecessor_anchor_id": "OTHER",
            "sequence": 2,
            "request_id": "REQ-OTHER",
            "anchor_digest": "f" * 64,
            "signature": "SIMULATED-NOT-A-SIGNATURE:fake",
            "custodian_id": "SELF-ISSUED",
            "key_id": "UNKNOWN",
            "policy_version": "UNKNOWN",
            "evidence_ref": "other",
            "anchor_id": "other",
        }
        for field, value in fields.items():
            with self.subTest(field=field):
                self.assert_denied(
                    SimulatedAnchorAdapter().verify(
                        self.req, replace(self.reply, **{field: value})
                    ),
                    "INVALID_OR_UNBOUND_RESPONSE",
                )

    def test_conflicting_request_id_replay_denied(self) -> None:
        self.assertTrue(self.adapter.verify(self.req, self.reply).fixture_valid)
        changed = request(record_digest="c" * 64, sequence=2)
        result = self.adapter.verify(changed, make_simulated_response(changed))
        self.assert_denied(result, "REPLAY_OR_CONFLICT")

    def test_identical_request_replay_denied(self) -> None:
        self.assertTrue(self.adapter.verify(self.req, self.reply).fixture_valid)
        self.assert_denied(
            self.adapter.verify(self.req, self.reply), "REPLAY_OR_CONFLICT"
        )

    def test_sequence_rollback_denied(self) -> None:
        later = request(request_id="REQ-002", sequence=3)
        self.assertTrue(
            self.adapter.verify(later, make_simulated_response(later)).fixture_valid
        )
        self.assert_denied(
            self.adapter.verify(self.req, self.reply),
            "ROLLBACK_OR_DUPLICATE_SEQUENCE",
        )

    def test_invalid_request_denied(self) -> None:
        for changes in (
            {"fixture_domain": "PRODUCTION"},
            {"source_commit": "not-a-commit"},
            {"record_digest": "invalid"},
            {"sequence": 0},
            {"sequence": True},
            {"request_id": ""},
            {"protocol": "unknown"},
        ):
            with self.subTest(changes=changes):
                invalid = request(**changes)
                self.assert_denied(
                    SimulatedAnchorAdapter().verify(invalid, self.reply),
                    "INVALID_REQUEST",
                )
                with self.assertRaises(ValueError):
                    make_simulated_response(invalid)

    def test_malformed_non_response_denied(self) -> None:
        self.assert_denied(
            self.adapter.verify(self.req, {"decision": "ACCEPTED"}),
            "MISSING_RESPONSE",
        )


if __name__ == "__main__":
    unittest.main()

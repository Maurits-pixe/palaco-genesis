"""v18 distributed replay reconciliation: synthetic authority fixtures only."""
import copy
import hashlib
import unittest

from distributed_replay_v18 import (
    CoordinationError, candidate, prepare_batch, read_batch,
    receipt_statement, inspect_decisions, RECEIPT_SCHEMA,
)


class DistributedReplayTests(unittest.TestCase):
    def setUp(self):
        self.a = candidate("alice", "bob", "msg-1", hashlib.sha256(b"one").hexdigest(), "phone")
        self.b = candidate("alice", "bob", "msg-2", hashlib.sha256(b"two").hexdigest(), "tablet")

    def receipts(self, claims, decisions=None):
        if decisions is None:
            decisions = ["first-claim"] * len(claims)
        return [
            {"schema": RECEIPT_SCHEMA, "authority_sequence": i + 1,
             "decision": verdict, "proof": "synthetic"}
            for i, verdict in enumerate(decisions)
        ]

    def inspect(self, claims=None, receipts=None, **kwargs):
        claims = [self.a] if claims is None else claims
        receipts = self.receipts(claims) if receipts is None else receipts
        options = {"verify_authority": lambda *_: True,
                   "get_trusted_watermark": lambda: len(claims)}
        options.update(kwargs)
        return inspect_decisions(claims, receipts, **options)

    def test_batch_roundtrip(self):
        self.assertEqual(read_batch(prepare_batch([self.a, self.b])), (self.a, self.b))

    def test_queue_empty_valid(self):
        self.assertEqual(read_batch(prepare_batch([])), ())

    def test_duplicate_same_record_rejected(self):
        with self.assertRaisesRegex(CoordinationError, "DUPLICATE_CANDIDATE"):
            prepare_batch([self.a, self.a])

    def test_malformed_candidate_rejected(self):
        bad = dict(self.a, authorized=True)
        with self.assertRaises(CoordinationError):
            prepare_batch([bad])

    def test_boolean_digest_rejected(self):
        with self.assertRaises(CoordinationError):
            candidate("a", "b", "c", True, "d")

    def test_noncanonical_batch_rejected(self):
        with self.assertRaises(CoordinationError):
            read_batch(prepare_batch([self.a]) + b" ")

    def test_unverified_authority_rejected(self):
        with self.assertRaisesRegex(CoordinationError, "AUTHORITY_UNVERIFIED"):
            self.inspect(verify_authority=lambda *_: False)

    def test_truthy_nonboolean_rejected(self):
        with self.assertRaisesRegex(CoordinationError, "AUTHORITY_UNVERIFIED"):
            self.inspect(verify_authority=lambda *_: 1)

    def test_unavailable_authority_rejected(self):
        def fail(*_):
            raise ConnectionError("offline")
        with self.assertRaisesRegex(CoordinationError, "AUTHORITY_UNAVAILABLE"):
            self.inspect(verify_authority=fail)

    def test_missing_authority_rejected(self):
        with self.assertRaisesRegex(CoordinationError, "EXTERNAL_AUTHORITY_REQUIRED"):
            self.inspect(verify_authority=None)

    def test_missing_watermark_rejected(self):
        with self.assertRaisesRegex(CoordinationError, "EXTERNAL_AUTHORITY_REQUIRED"):
            self.inspect(get_trusted_watermark=None)

    def test_rollback_watermark_rejected(self):
        receipts = self.receipts([self.a])
        receipts[0]["authority_sequence"] = 2
        with self.assertRaisesRegex(CoordinationError, "UNANCHORED_DECISION"):
            self.inspect(receipts=receipts, get_trusted_watermark=lambda: 1)

    def test_zero_watermark_rejected(self):
        with self.assertRaisesRegex(CoordinationError, "INVALID_WATERMARK"):
            self.inspect(get_trusted_watermark=lambda: 0)

    def test_boolean_watermark_rejected(self):
        with self.assertRaisesRegex(CoordinationError, "INVALID_WATERMARK"):
            self.inspect(get_trusted_watermark=lambda: True)

    def test_receipt_decision_tampering_rejected(self):
        def strict_verifier(statement, receipt):
            return b'"decision":"first-claim"' in statement
        receipts = self.receipts([self.a], ["duplicate"])
        with self.assertRaisesRegex(CoordinationError, "AUTHORITY_UNVERIFIED"):
            self.inspect(receipts=receipts, verify_authority=strict_verifier)

    def test_duplicate_sequence_rejected(self):
        receipts = self.receipts([self.a, self.b])
        receipts[1]["authority_sequence"] = 1
        with self.assertRaisesRegex(CoordinationError, "DUPLICATE_AUTHORITY_SEQUENCE"):
            self.inspect([self.a, self.b], receipts)

    def test_conflict_keeps_hold(self):
        second = dict(self.a, device_id="tablet", package_sha256=hashlib.sha256(b"another").hexdigest())
        report = self.inspect([self.a, second],
                              self.receipts([self.a, second], ["first-claim", "conflict"]))
        self.assertEqual([item["decision"] for item in report["outcomes"]],
                         ["first-claim", "conflict"])
        self.assertEqual(report["authorization"], "DENY")
        self.assertEqual(report["release"], "HOLD")

    def test_multiple_first_claims_rejected(self):
        second = dict(self.a, device_id="tablet")
        with self.assertRaisesRegex(CoordinationError, "MULTIPLE_FIRST_CLAIMS"):
            self.inspect([self.a, second])

    def test_one_decision_never_authorizes(self):
        report = self.inspect()
        self.assertEqual(report["authorization"], "DENY")
        self.assertIs(report["production_release_enabled"], False)

    def test_empty_inspection_rejected(self):
        with self.assertRaisesRegex(CoordinationError, "INVALID_INPUT"):
            self.inspect(claims=[], receipts=[])

    def test_receipt_binding_is_domain_separated(self):
        one = receipt_statement(self.a, authority_sequence=1, decision="first-claim")
        two = receipt_statement(self.a, authority_sequence=1, decision="duplicate")
        self.assertNotEqual(one, two)

    def test_missing_receipt_proof_rejected(self):
        receipt = self.receipts([self.a])[0]
        receipt["proof"] = ""
        with self.assertRaisesRegex(CoordinationError, "INVALID_PROOF"):
            self.inspect(receipts=[receipt])


if __name__ == "__main__":
    unittest.main()

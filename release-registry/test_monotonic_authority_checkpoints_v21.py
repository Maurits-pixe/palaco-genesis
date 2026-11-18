"""v21 monotonic checkpoint regression tests: ephemeral, synthetic trust."""
import hashlib
from pathlib import Path
import sqlite3
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from atomic_replay_authority_v19 import AtomicReplayAuthority
from distributed_replay_v18 import candidate, receipt_statement
from ed25519_trust_v7 import Ed25519TrustAdapter
from monotonic_authority_checkpoints_v21 import (
    GENESIS, CheckpointError, checkpoint_candidate, verify_checkpoint,
    AnchoredCommitInspector,
)
from signed_authority_receipts_v20 import SignedReceiptIssuer, SignedReceiptVerifier


class CheckpointTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "authority.sqlite"
        key = Ed25519PrivateKey.generate()
        public = key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw)
        self.issuer = SignedReceiptIssuer(
            key, key_id="fixture-root", authorize_sign=lambda *_: True)
        self.verify_sig = Ed25519TrustAdapter(
            {"fixture-root": public}, verify_policy=lambda *_: True)
        def verify_receipt(statement, opaque):
            import json
            proof = json.loads(opaque)
            return self.verify_sig(statement, proof["signature_b64"],
                                   proof["key_id"])
        self.verify_receipt = verify_receipt
        self.authority = AtomicReplayAuthority(
            self.path, authorize_candidate=lambda _: True,
            sign_receipt=self.issuer)
        self.a = candidate("s", "r", "m1", hashlib.sha256(b"a").hexdigest(), "phone")
        self.b = candidate("s", "r", "m2", hashlib.sha256(b"b").hexdigest(), "tablet")
        self.authority.decide(self.a)
        self.claims, self.receipts = self.authority.read_decisions()
        self.root = checkpoint_candidate(self.claims, self.receipts)

    def inspect(self, *, claims=None, receipts=None, root=None,
                verify_receipt=None, get_trusted_checkpoint=None):
        claims = self.claims if claims is None else claims
        receipts = self.receipts if receipts is None else receipts
        expected = self.root if root is None else root
        return verify_checkpoint(
            claims, receipts,
            get_trusted_checkpoint=(
                (lambda: (expected["sequence"], expected["head"]))
                if get_trusted_checkpoint is None else get_trusted_checkpoint),
            verify_receipt=(
                self.verify_receipt if verify_receipt is None else verify_receipt))

    def test_one_valid_synthetic_checkpoint(self):
        result = self.inspect()
        self.assertEqual(result["head"], self.root["head"])
        self.assertEqual(result["authorization"], "DENY")
        self.assertEqual(result["release"], "HOLD")

    def test_deterministic_candidate(self):
        self.assertEqual(checkpoint_candidate(self.claims, self.receipts), self.root)

    def test_second_decision_changes_head(self):
        self.authority.decide(self.b)
        claims, receipts = self.authority.read_decisions()
        next_root = checkpoint_candidate(claims, receipts)
        self.assertNotEqual(self.root["head"], next_root["head"])
        self.assertEqual(next_root["sequence"], 2)

    def test_stale_checkpoint_denied(self):
        self.authority.decide(self.b)
        claims, receipts = self.authority.read_decisions()
        with self.assertRaisesRegex(CheckpointError, "CHECKPOINT_MISMATCH"):
            self.inspect(claims=claims, receipts=receipts)

    def test_modified_receipt_denied(self):
        receipts = [dict(self.receipts[0], proof="forged")]
        with self.assertRaises(CheckpointError):
            self.inspect(receipts=receipts)

    def test_modified_claim_denied(self):
        claims = [dict(self.a, package_sha256="f"*64)]
        with self.assertRaisesRegex(CheckpointError, "UNVERIFIED_SIGNATURE"):
            self.inspect(claims=claims)

    def test_deleted_history_denied(self):
        with self.assertRaisesRegex(CheckpointError, "EMPTY_HISTORY_NOT_TRUSTED"):
            self.inspect(claims=[], receipts=[])

    def test_future_anchor_denied(self):
        with self.assertRaisesRegex(CheckpointError, "CHECKPOINT_MISMATCH"):
            self.inspect(get_trusted_checkpoint=lambda: (2, self.root["head"]))

    def test_boolean_anchor_denied(self):
        with self.assertRaisesRegex(CheckpointError, "CHECKPOINT_MISMATCH"):
            self.inspect(get_trusted_checkpoint=lambda: (True, self.root["head"]))

    def test_missing_anchor_denied(self):
        with self.assertRaisesRegex(CheckpointError, "EXTERNAL_TRUST_REQUIRED"):
            verify_checkpoint(self.claims, self.receipts,
                get_trusted_checkpoint=None, verify_receipt=self.verify_receipt)

    def test_missing_receipt_verifier_denied(self):
        with self.assertRaisesRegex(CheckpointError, "EXTERNAL_TRUST_REQUIRED"):
            verify_checkpoint(self.claims, self.receipts,
                get_trusted_checkpoint=lambda: (1, self.root["head"]),
                verify_receipt=None)

    def test_revoked_signer_denied(self):
        with self.assertRaisesRegex(CheckpointError, "UNVERIFIED_SIGNATURE"):
            self.inspect(verify_receipt=lambda *_: False)

    def test_truthy_nonboolean_denied(self):
        with self.assertRaisesRegex(CheckpointError, "UNVERIFIED_SIGNATURE"):
            self.inspect(verify_receipt=lambda *_: 1)

    def test_verifier_exception_denied(self):
        def broken(*_):
            raise ConnectionError("unavailable")
        with self.assertRaisesRegex(CheckpointError, "RECEIPT_PROVIDER_UNAVAILABLE"):
            self.inspect(verify_receipt=broken)

    def test_anchor_exception_denied(self):
        def broken():
            raise ConnectionError("unavailable")
        with self.assertRaisesRegex(CheckpointError, "CHECKPOINT_PROVIDER_UNAVAILABLE"):
            self.inspect(get_trusted_checkpoint=broken)

    def test_duplicate_first_claim_denied(self):
        duplicate = dict(self.receipts[0], authority_sequence=2)
        with self.assertRaisesRegex(CheckpointError, "INCONSISTENT_FIRST_CLAIM"):
            checkpoint_candidate((self.a, self.a), (self.receipts[0], duplicate))

    def test_sequence_gap_denied(self):
        receipt = dict(self.receipts[0], authority_sequence=3)
        with self.assertRaisesRegex(CheckpointError, "NONMONOTONIC_SEQUENCE"):
            checkpoint_candidate((self.a,), (receipt,))

    def test_inspector_fresh_positive(self):
        inspector = AnchoredCommitInspector(
            self.authority, get_trusted_checkpoint=lambda: (1, self.root["head"]),
            verify_receipt=self.verify_receipt)
        statement = receipt_statement(
            self.a, authority_sequence=1, decision="first-claim")
        self.assertIs(inspector(statement), True)

    def test_inspector_stale_denies_after_append(self):
        inspector = AnchoredCommitInspector(
            self.authority, get_trusted_checkpoint=lambda: (1, self.root["head"]),
            verify_receipt=self.verify_receipt)
        statement = receipt_statement(
            self.a, authority_sequence=1, decision="first-claim")
        self.authority.decide(self.b)
        self.assertIs(inspector(statement), False)

    def test_v20_commit_gate_interop(self):
        inspector = AnchoredCommitInspector(
            self.authority, get_trusted_checkpoint=lambda: (1, self.root["head"]),
            verify_receipt=self.verify_receipt)
        verifier = SignedReceiptVerifier(
            {"fixture-root": self.verify_sig._pinned_keys["fixture-root"]},
            verify_key_policy=lambda *_: True, verify_committed=inspector)
        statement = receipt_statement(
            self.a, authority_sequence=1, decision="first-claim")
        self.assertIs(verifier(statement, self.receipts[0]["proof"]), True)
        self.assertIs(verifier(statement, "tampered"), False)

    def test_inspector_rejects_unknown_statement(self):
        inspector = AnchoredCommitInspector(
            self.authority, get_trusted_checkpoint=lambda: (1, self.root["head"]),
            verify_receipt=self.verify_receipt)
        self.assertIs(inspector(b"unrecognized"), False)

    def test_replay_database_replacement_not_trust(self):
        inspector = AnchoredCommitInspector(
            self.authority, get_trusted_checkpoint=lambda: (2, "0"*64),
            verify_receipt=self.verify_receipt)
        statement = receipt_statement(
            self.a, authority_sequence=1, decision="first-claim")
        self.assertIs(inspector(statement), False)


if __name__ == "__main__":
    unittest.main()

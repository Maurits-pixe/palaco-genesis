"""Ed25519 signed incident evidence tests; private keys ephemeral and test-only."""
from dataclasses import replace
import json
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from anchored_challenges import EMPTY_ROOT
from fencing_incident_evidence import (
    _build, FencingIncidentEvidence,
)
from native_checkpoint_scope import NativeCheckpoint
from native_fencing_gate import FencedSnapshot
from protocol import TransferError
from signed_fencing_incident import (
    SignedFencingIncidentEvidence, attach_incident_signature, signing_message,
    verify_signed_fencing_incident,
)
from witnessed_sqlite_fencing import FencingWitnessState

NS = b"s" * 32
NONCE = b"n" * 32
OTHER_NONCE = b"m" * 32
SIGNER = "palaco-review-evidence-1"


class SignedFencingIncidentTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.other_key = Ed25519PrivateKey.generate()
        self.pub = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.keys = {SIGNER: self.pub}
        self.sqlite = FencedSnapshot(
            NS, 1, False, NativeCheckpoint(NS, 0, EMPTY_ROOT),
        )
        self.witness = FencingWitnessState(NS, 0, 1, False, 0, EMPTY_ROOT)
        self.evidence = _build(NS, self.sqlite, self.witness, "match")

    def signed(self, evidence=None, nonce=NONCE, signer=SIGNER, key=None):
        evidence = self.evidence if evidence is None else evidence
        key = self.key if key is None else key
        sig = key.sign(signing_message(evidence, signer, nonce))
        return attach_incident_signature(evidence, signer, nonce, sig)

    def test_signed_match_valid_but_still_hold_deny(self):
        package = self.signed()
        self.assertTrue(verify_signed_fencing_incident(package, self.keys, NONCE))
        record = json.loads(package.evidence.canonical_json)
        self.assertEqual((record["decision"], record["authorization"]), ("HOLD", "DENY"))

    def test_signed_mismatch_valid_but_hold(self):
        witness = replace(self.witness, revision=1, count=1, root="a" * 64)
        evidence = _build(NS, self.sqlite, witness, "mismatch")
        package = self.signed(evidence)
        self.assertTrue(verify_signed_fencing_incident(package, self.keys, NONCE))
        self.assertEqual(json.loads(evidence.canonical_json)["decision"], "HOLD")

    def test_other_nonce_rejected(self):
        self.assertFalse(verify_signed_fencing_incident(self.signed(),
                                                       self.keys, OTHER_NONCE))

    def test_stale_signed_nonce_rejected(self):
        package = self.signed(nonce=OTHER_NONCE)
        self.assertFalse(verify_signed_fencing_incident(package, self.keys, NONCE))

    def test_wrong_signer_key_rejected(self):
        self.assertFalse(verify_signed_fencing_incident(
            self.signed(key=self.other_key), self.keys, NONCE,
        ))

    def test_missing_signer_entry_rejected(self):
        self.assertFalse(verify_signed_fencing_incident(
            self.signed(), {}, NONCE,
        ))

    def test_swapped_signer_id_rejected(self):
        package = replace(self.signed(), signer_id="other")
        self.assertFalse(verify_signed_fencing_incident(
            package, self.keys, NONCE,
        ))

    def test_forged_signature_bit_rejected(self):
        package = self.signed()
        sig = bytearray(package.signature)
        sig[0] ^= 1
        self.assertFalse(verify_signed_fencing_incident(
            replace(package, signature=bytes(sig)), self.keys, NONCE,
        ))

    def test_tampered_report_rejected(self):
        package = self.signed()
        wrong = FencingIncidentEvidence(
            package.evidence.canonical_json.replace('"HOLD"', '"ALLOW"'),
            package.evidence.sha256,
        )
        self.assertFalse(verify_signed_fencing_incident(
            replace(package, evidence=wrong), self.keys, NONCE,
        ))

    def test_signed_other_report_cannot_be_substituted(self):
        package = self.signed()
        another = _build(NS, self.sqlite, replace(
            self.witness, revision=1, count=1, root="a" * 64,
        ), "mismatch")
        self.assertFalse(verify_signed_fencing_incident(
            replace(package, evidence=another), self.keys, NONCE,
        ))

    def test_signature_wrong_length_rejected(self):
        package = replace(self.signed(), signature=b"s" * 63)
        self.assertFalse(verify_signed_fencing_incident(package, self.keys, NONCE))

    def test_signing_rejects_unsafe_signer_id(self):
        with self.assertRaises(TransferError):
            signing_message(self.evidence, "../invalid path", NONCE)

    def test_signing_rejects_missing_nonce(self):
        with self.assertRaises(TransferError):
            signing_message(self.evidence, SIGNER, b"short")

    def test_attach_rejects_invalid_signature_size(self):
        with self.assertRaises(TransferError):
            attach_incident_signature(self.evidence, SIGNER, NONCE, b"fake")

    def test_verifier_rejects_nonbytes_key(self):
        self.assertFalse(verify_signed_fencing_incident(
            self.signed(), {SIGNER: "untrusted"}, NONCE,
        ))

    def test_valid_signature_cannot_prove_truth_of_fake_sources(self):
        forged = _build(NS, self.sqlite, self.witness, "match")
        self.assertTrue(verify_signed_fencing_incident(
            self.signed(forged), self.keys, NONCE,
        ))
        # Even a valid signature is NOT native attestation / source authenticity.
        self.assertEqual(json.loads(forged.canonical_json)["authorization"], "DENY")


if __name__ == "__main__":
    unittest.main()

"""Publisher rotation testing with mutable fake stores and ephemeral keys."""
from dataclasses import replace
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from incident_reviewer_registry import IncidentKeyPolicy, INCIDENT_REVIEWER_ROLE
from protocol import TransferError
from publisher_rotation_gate import (
    IssuerKeyRecord, IssuerRotationSnapshot, RotationPinnedPolicySource,
    issuer_rotation_digest,
)
from signed_policy_distribution import SignedPolicyEnvelope, policy_signature_message
from versioned_incident_policy import (
    PolicyPin, PolicySnapshot, VersionedIncidentReviewerGate, policy_digest,
)

OLD = "old-publisher"
NEW = "new-publisher"
REVIEWER = "only-inspection"


class MutableRead:
    def __init__(self, value):
        self.value = value
        self.offline = False
        self.on_read = None

    def read(self):
        if self.offline:
            raise OSError("unavailable")
        if self.on_read is not None:
            self.on_read()
        return self.value


class PublisherRotationTests(unittest.TestCase):
    def setUp(self):
        self.old_key = Ed25519PrivateKey.generate()
        self.new_key = Ed25519PrivateKey.generate()
        pub = lambda key: key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.policy = PolicySnapshot(1, {
            REVIEWER: IncidentKeyPolicy(pub(self.new_key), INCIDENT_REVIEWER_ROLE,
                                        False, 1, 500),
        })
        self.snapshot = IssuerRotationSnapshot(1, {
            OLD: IssuerKeyRecord(pub(self.old_key), False),
            NEW: IssuerKeyRecord(pub(self.new_key), False),
        })
        self.issuers = MutableRead(self.snapshot)
        self.pin = MutableRead(PolicyPin(1, issuer_rotation_digest(self.snapshot)))
        self.transport = MutableRead(self.envelope(self.old_key, OLD))
        self.source = self.open_source()

    def envelope(self, key, name):
        return SignedPolicyEnvelope(
            self.policy, name, key.sign(policy_signature_message(self.policy, name)),
        )

    def open_source(self):
        return RotationPinnedPolicySource(self.transport, self.issuers, self.pin)

    def rotate(self):
        changed = dict(self.snapshot.keys)
        changed[OLD] = replace(changed[OLD], revoked=True)
        snap = IssuerRotationSnapshot(2, changed)
        self.issuers.value = snap
        self.pin.value = PolicyPin(2, issuer_rotation_digest(snap))

    def test_initial_old_publisher_valid(self):
        self.assertEqual(self.source.read().revision, 1)

    def test_rotation_invalidates_existing_source(self):
        self.rotate()
        with self.assertRaises(TransferError):
            self.source.read()
        self.assertTrue(self.source.is_held)

    def test_revoked_old_key_denied_new_instance(self):
        self.rotate()
        with self.assertRaises(TransferError):
            self.open_source().read()

    def test_new_key_accepted_after_rotation(self):
        self.rotate()
        self.transport.value = self.envelope(self.new_key, NEW)
        self.assertEqual(self.open_source().read().revision, 1)

    def test_old_signed_policy_with_revoked_issuer_denied(self):
        self.rotate()
        with self.assertRaises(TransferError):
            self.open_source().read()

    def test_rotation_pin_not_updated_denied(self):
        altered = dict(self.snapshot.keys)
        altered[OLD] = replace(altered[OLD], revoked=True)
        self.issuers.value = IssuerRotationSnapshot(2, altered)
        with self.assertRaises(TransferError):
            self.open_source()

    def test_pin_ahead_of_issuers_denied(self):
        self.pin.value = PolicyPin(2, self.pin.value.digest)
        with self.assertRaises(TransferError):
            self.open_source()

    def test_tampered_key_same_revision_denied(self):
        altered = dict(self.snapshot.keys)
        altered[OLD] = replace(altered[OLD], public_key=b"x" * 32)
        self.issuers.value = IssuerRotationSnapshot(1, altered)
        with self.assertRaises(TransferError):
            self.source.read()

    def test_pin_unavailable_fail_closed(self):
        self.pin.offline = True
        with self.assertRaises(TransferError):
            self.source.read()
        self.pin.offline = False
        with self.assertRaises(TransferError):
            self.source.read()

    def test_issuer_source_unavailable_denied(self):
        self.issuers.offline = True
        with self.assertRaises(TransferError):
            self.source.read()

    def test_transport_unavailable_denied(self):
        self.transport.offline = True
        with self.assertRaises(TransferError):
            self.source.read()

    def test_wrong_signer_key_denied(self):
        self.transport.value = SignedPolicyEnvelope(
            self.policy, OLD,
            self.new_key.sign(policy_signature_message(self.policy, OLD)),
        )
        with self.assertRaises(TransferError):
            self.source.read()

    def test_only_revoked_issuers_denied(self):
        keys = {key: replace(value, revoked=True)
                for key, value in self.snapshot.keys.items()}
        snap = IssuerRotationSnapshot(2, keys)
        self.issuers.value = snap
        self.pin.value = PolicyPin(2, issuer_rotation_digest(snap))
        with self.assertRaises(TransferError):
            self.open_source()

    def test_changed_pin_during_read_denied(self):
        counter = [0]
        def change():
            counter[0] += 1
            if counter[0] == 3:
                self.pin.value = PolicyPin(2, "a" * 64)
        self.pin.on_read = change
        with self.assertRaises(TransferError):
            self.source.read()

    def test_reviewer_gate_integration(self):
        incident_pin = MutableRead(PolicyPin(1, policy_digest(self.policy)))
        review = VersionedIncidentReviewerGate(
            self.source, incident_pin, lambda: 50,
        )
        self.assertTrue(review.reviewer_can_inspect(REVIEWER))
        self.rotate()
        self.transport.value = self.envelope(self.new_key, NEW)
        self.assertFalse(review.reviewer_can_inspect(REVIEWER))
        self.assertTrue(review.is_held)

    def test_fake_issuer_and_pin_rollback_defeats_fresh_instance(self):
        self.rotate()
        self.transport.value = self.envelope(self.new_key, NEW)
        self.assertEqual(self.open_source().read().revision, 1)
        self.issuers.value = self.snapshot
        self.pin.value = PolicyPin(1, issuer_rotation_digest(self.snapshot))
        self.transport.value = self.envelope(self.old_key, OLD)
        self.assertEqual(self.open_source().read().revision, 1)

    def test_invalid_issuer_record_denied(self):
        with self.assertRaises(TransferError):
            IssuerKeyRecord(b"x" * 31, False)

    def test_invalid_revision_denied(self):
        with self.assertRaises(TransferError):
            IssuerRotationSnapshot(True, self.snapshot.keys)

    def test_digest_detects_revocation(self):
        self.rotate()
        self.assertNotEqual(issuer_rotation_digest(self.snapshot),
                            issuer_rotation_digest(self.issuers.value))

    def test_policy_source_has_no_unlock(self):
        self.assertFalse(hasattr(self.source, "unlock"))
        self.assertFalse(hasattr(self.source, "deploy"))


if __name__ == "__main__":
    unittest.main()

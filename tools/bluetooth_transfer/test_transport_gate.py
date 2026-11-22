"""Synthetic admission-policy tests. Flags are mocked, NOT cryptographic evidence."""
from dataclasses import replace
import unittest

from protocol import Receiver, TransferError, make_offer
from transport_gate import (
    VerifiedTransportEvidence, admit_receive_session, assess_transport,
    offer_binding_digest,
)

IDENTIFIER = "abcd" * 8
PAYLOAD = b"PALACO-CITADEL-OFFLINE-EXPORT"


class TransportGateTests(unittest.TestCase):
    def setUp(self):
        self.offer = make_offer("citadel", IDENTIFIER, PAYLOAD)
        self.evidence = VerifiedTransportEvidence(
            peer_identity_verified=True,
            local_identity_verified=True,
            authenticated_key_agreement=True,
            encrypted_channel_verified=True,
            offer_authenticated=True,
            consent_for_exact_offer=True,
            revocation_current=True,
            trusted_time_current=True,
            peer_key_fingerprint="1" * 64,
            bound_offer_digest=offer_binding_digest(self.offer),
        )

    def test_complete_mock_evidence_admits_for_untrusted_receipt_only(self):
        session = admit_receive_session(self.offer, Receiver(), self.evidence)
        self.assertFalse(session.closed)
        self.assertEqual(session.offered_bytes, len(PAYLOAD))
        session.abort()

    def test_missing_peer_identity_denied(self):
        self.assert_denied(peer_identity_verified=False)

    def test_missing_local_identity_denied(self):
        self.assert_denied(local_identity_verified=False)

    def test_missing_key_agreement_denied(self):
        self.assert_denied(authenticated_key_agreement=False)

    def test_unencrypted_channel_denied(self):
        self.assert_denied(encrypted_channel_verified=False)

    def test_unauthenticated_offer_denied(self):
        self.assert_denied(offer_authenticated=False)

    def test_missing_consent_denied(self):
        self.assert_denied(consent_for_exact_offer=False)

    def test_revocation_unknown_denied(self):
        self.assert_denied(revocation_current=False)

    def test_time_unknown_denied(self):
        self.assert_denied(trusted_time_current=False)

    def test_non_boolean_truthy_denied(self):
        self.assert_denied(consent_for_exact_offer=1)

    def test_missing_key_fingerprint_denied(self):
        self.assert_denied(peer_key_fingerprint="")

    def test_uppercase_key_fingerprint_denied(self):
        self.assert_denied(peer_key_fingerprint="A" * 64)

    def test_other_offer_digest_denied(self):
        other = make_offer("mundo", IDENTIFIER, PAYLOAD)
        self.assert_denied(bound_offer_digest=offer_binding_digest(other))

    def test_empty_digest_denied(self):
        self.assert_denied(bound_offer_digest="")

    def test_malformed_evidence_denied(self):
        with self.assertRaises(TransferError):
            assess_transport(self.offer, None)

    def test_malformed_offer_denied(self):
        bad = replace(self.offer, payload_size=0)
        with self.assertRaises(TransferError):
            assess_transport(bad, self.evidence)

    def test_offer_binding_changes_when_id_changes(self):
        other = make_offer("citadel", "f" * 32, PAYLOAD)
        self.assertNotEqual(offer_binding_digest(self.offer), offer_binding_digest(other))

    def test_offer_binding_changes_when_payload_changes(self):
        other = make_offer("citadel", IDENTIFIER, PAYLOAD + b"x")
        self.assertNotEqual(offer_binding_digest(self.offer), offer_binding_digest(other))

    def test_session_refuses_already_consumed_id(self):
        guard = Receiver()
        guard.accept(self.offer, (PAYLOAD,), user_approved=True, identity_verified=True)
        with self.assertRaises(TransferError):
            admit_receive_session(self.offer, guard, self.evidence)

    def assert_denied(self, **changes):
        with self.assertRaises(TransferError):
            assess_transport(self.offer, replace(self.evidence, **changes))


if __name__ == "__main__":
    unittest.main()

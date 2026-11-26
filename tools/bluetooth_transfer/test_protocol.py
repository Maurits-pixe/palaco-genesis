"""Standard-library regression tests for PALACO offline transfer framing."""
import unittest

from protocol import (
    CHUNK_BYTES, MAX_BYTES, Receiver, TransferError, chunks,
    make_offer, offer_json, parse_offer,
)

TRANSFER_ID = "0123456789abcdef0123456789abcdef"


class BluetoothTransferTests(unittest.TestCase):
    def setUp(self):
        self.payload = b"PALACO Citadel " * 1200
        self.offer = make_offer("citadel", TRANSFER_ID, self.payload)
        self.parts = chunks(self.payload)

    def receive(self, **overrides):
        kwargs = {"user_approved": True, "identity_verified": True}
        kwargs.update(overrides)
        return Receiver().accept(self.offer, self.parts, **kwargs)

    def test_roundtrip(self):
        self.assertEqual(self.receive(), self.payload)
        self.assertEqual(parse_offer(offer_json(self.offer)), self.offer)

    def test_mundo(self):
        payload = b"world"
        offer = make_offer("mundo", TRANSFER_ID, payload)
        self.assertEqual(Receiver().accept(
            offer, chunks(payload), user_approved=True, identity_verified=True,
        ), payload)

    def test_no_consent(self):
        with self.assertRaises(TransferError):
            self.receive(user_approved=False)

    def test_no_identity(self):
        with self.assertRaises(TransferError):
            self.receive(identity_verified=False)

    def test_replay_rejected(self):
        receiver = Receiver()
        receiver.accept(self.offer, self.parts, user_approved=True, identity_verified=True)
        self.assertTrue(receiver.has_seen(TRANSFER_ID))
        with self.assertRaises(TransferError):
            receiver.accept(self.offer, self.parts, user_approved=True, identity_verified=True)

    def test_tampered_chunk(self):
        bad = (b"X" + self.parts[0][1:],) + self.parts[1:]
        with self.assertRaises(TransferError):
            Receiver().accept(self.offer, bad, user_approved=True, identity_verified=True)

    def test_wrong_order(self):
        payload = b"A" * CHUNK_BYTES + b"B" * CHUNK_BYTES
        offer = make_offer("citadel", TRANSFER_ID, payload)
        with self.assertRaises(TransferError):
            Receiver().accept(offer, tuple(reversed(chunks(payload))),
                              user_approved=True, identity_verified=True)

    def test_missing_chunk(self):
        with self.assertRaises(TransferError):
            Receiver().accept(self.offer, self.parts[:-1],
                              user_approved=True, identity_verified=True)

    def test_oversized_payload(self):
        with self.assertRaises(TransferError):
            make_offer("mundo", TRANSFER_ID, b"x" * (MAX_BYTES + 1))

    def test_invalid_kind(self):
        with self.assertRaises(TransferError):
            make_offer("authority", TRANSFER_ID, b"x")

    def test_duplicate_offer_key(self):
        raw = offer_json(self.offer).replace('"kind":"citadel"', '"kind":"citadel","kind":"mundo"')
        with self.assertRaises(TransferError):
            parse_offer(raw)

    def test_extra_offer_field(self):
        raw = offer_json(self.offer).replace(',"kind":', ',"authorized":true,"kind":')
        with self.assertRaises(TransferError):
            parse_offer(raw)

    def test_noncanonical_offer(self):
        with self.assertRaises(TransferError):
            parse_offer(offer_json(self.offer) + " ")

    def test_empty_payload(self):
        with self.assertRaises(TransferError):
            make_offer("citadel", TRANSFER_ID, b"")

    def test_transfer_id_validation(self):
        with self.assertRaises(TransferError):
            make_offer("citadel", "notrandom", b"x")


if __name__ == "__main__":
    unittest.main()

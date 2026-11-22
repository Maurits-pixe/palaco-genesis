"""Incremental transfer session regressions; no Bluetooth radio needed."""
import unittest

from protocol import CHUNK_BYTES, Receiver, TransferError, chunks, make_offer
from session import TransferSession

ID = "1234567890abcdef1234567890abcdef"


class TransferSessionTests(unittest.TestCase):
    def setUp(self):
        self.payload = b"A" * CHUNK_BYTES + b"B" * 11
        self.offer = make_offer("mundo", ID, self.payload)
        self.guard = Receiver()

    def session(self, **flags):
        kwargs = {"user_approved": True, "identity_verified": True}
        kwargs.update(flags)
        return TransferSession(self.offer, self.guard, **kwargs)

    def test_streaming_roundtrip(self):
        current = self.session()
        self.assertEqual(current.next_index, 0)
        for i, frame in enumerate(chunks(self.payload)):
            current.push(i, frame)
        self.assertEqual(current.received_bytes, len(self.payload))
        self.assertEqual(current.finish(), self.payload)
        self.assertTrue(current.closed)
        self.assertEqual(current.received_bytes, 0)

    def test_no_user_consent(self):
        with self.assertRaises(TransferError):
            self.session(user_approved=False)

    def test_no_authenticated_peer(self):
        with self.assertRaises(TransferError):
            self.session(identity_verified=False)

    def test_no_truthy_shortcut(self):
        with self.assertRaises(TransferError):
            self.session(identity_verified=1)

    def test_duplicate_packet_aborts(self):
        current = self.session()
        current.push(0, chunks(self.payload)[0])
        with self.assertRaises(TransferError):
            current.push(0, chunks(self.payload)[0])
        self.assertTrue(current.closed)
        self.assertEqual(current.received_bytes, 0)

    def test_future_packet_aborts(self):
        current = self.session()
        with self.assertRaises(TransferError):
            current.push(1, chunks(self.payload)[1])
        self.assertTrue(current.closed)

    def test_boolean_index_aborts(self):
        current = self.session()
        with self.assertRaises(TransferError):
            current.push(False, chunks(self.payload)[0])

    def test_oversized_packet_aborts(self):
        current = self.session()
        with self.assertRaises(TransferError):
            current.push(0, b"X" * (CHUNK_BYTES + 1))

    def test_short_packet_aborts(self):
        current = self.session()
        with self.assertRaises(TransferError):
            current.push(0, b"X")

    def test_finish_incomplete_aborts(self):
        current = self.session()
        current.push(0, chunks(self.payload)[0])
        with self.assertRaises(TransferError):
            current.finish()
        self.assertTrue(current.closed)

    def test_tamper_detected_at_finish(self):
        current = self.session()
        current.push(0, b"Z" * CHUNK_BYTES)
        current.push(1, chunks(self.payload)[1])
        with self.assertRaises(TransferError):
            current.finish()
        self.assertTrue(current.closed)

    def test_disconnect_discards(self):
        current = self.session()
        current.push(0, chunks(self.payload)[0])
        current.disconnect()
        self.assertTrue(current.closed)
        self.assertEqual(current.received_bytes, 0)
        with self.assertRaises(TransferError):
            current.push(1, chunks(self.payload)[1])

    def test_cancel_before_finish(self):
        current = self.session()
        current.abort()
        with self.assertRaises(TransferError):
            current.finish()

    def test_completed_replay_blocked(self):
        first = self.session()
        for i, part in enumerate(chunks(self.payload)):
            first.push(i, part)
        first.finish()
        with self.assertRaises(TransferError):
            self.session()

    def test_closed_session_rejects_further_packets(self):
        current = self.session()
        current.abort()
        with self.assertRaises(TransferError):
            current.push(0, chunks(self.payload)[0])


if __name__ == "__main__":
    unittest.main()

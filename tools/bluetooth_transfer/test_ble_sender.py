"""Deterministic, synthetic stop-and-wait BLE sender regressions."""
import unittest
from session import TransferSession

from ble_sender import AckingBleReceiver, StopAndWaitSender, ack_for_frame
from ble_frames import BleChunkReassembler, BleTransferBridge, encode_chunk
from protocol import Receiver, TransferError, make_offer


class SenderTests(unittest.TestCase):
    def test_single_packet_success(self):
        sender = StopAndWaitSender(b"hello", 20)
        frame = sender.pending()
        self.assertEqual(BleChunkReassembler(0, 5, 20).push(frame), b"hello")
        sender.acknowledge(ack_for_frame(frame))
        self.assertTrue(sender.done)
        self.assertTrue(sender.closed)
        self.assertEqual(sender.acknowledged_frames, 1)

    def test_multiple_packets(self):
        payload = b"x" * 40
        sender = StopAndWaitSender(payload, 20)
        expected = encode_chunk(0, payload, 20)
        for frame in expected:
            self.assertEqual(sender.pending(), frame)
            sender.acknowledge(ack_for_frame(frame))
        self.assertTrue(sender.done)
        self.assertEqual(sender.acknowledged_frames, len(expected))

    def test_timeout_repeats_same_packet(self):
        sender = StopAndWaitSender(b"hello", 20)
        self.assertEqual(sender.on_timeout(), sender.pending())
        sender.acknowledge(ack_for_frame(sender.pending()))
        self.assertTrue(sender.done)

    def test_timeout_budget(self):
        sender = StopAndWaitSender(b"hello", 20, max_retries=2)
        first = sender.pending()
        self.assertEqual(sender.on_timeout(), first)
        self.assertEqual(sender.on_timeout(), first)
        with self.assertRaises(TransferError):
            sender.on_timeout()
        self.assertTrue(sender.closed)
        self.assertFalse(sender.done)

    def test_zero_retry_budget(self):
        sender = StopAndWaitSender(b"x", 20, max_retries=0)
        with self.assertRaises(TransferError):
            sender.on_timeout()
        self.assertTrue(sender.closed)

    def test_wrong_ack_closes(self):
        sender = StopAndWaitSender(b"x", 20)
        with self.assertRaises(TransferError):
            sender.acknowledge(b"bad")
        self.assertTrue(sender.closed)

    def test_ack_for_later_frame_rejected(self):
        sender = StopAndWaitSender(b"x" * 40, 20)
        later = encode_chunk(0, b"x" * 40, 20)[1]
        with self.assertRaises(TransferError):
            sender.acknowledge(ack_for_frame(later))
        self.assertTrue(sender.closed)

    def test_duplicate_ack_rejected(self):
        sender = StopAndWaitSender(b"x" * 40, 20)
        first = ack_for_frame(sender.pending())
        sender.acknowledge(first)
        with self.assertRaises(TransferError):
            sender.acknowledge(first)
        self.assertTrue(sender.closed)

    def test_no_more_packets_after_completion(self):
        sender = StopAndWaitSender(b"x", 20)
        sender.acknowledge(ack_for_frame(sender.pending()))
        with self.assertRaises(TransferError):
            sender.pending()

    def test_cancel_discards(self):
        sender = StopAndWaitSender(b"x" * 100, 20)
        sender.cancel()
        with self.assertRaises(TransferError):
            sender.pending()
        self.assertFalse(sender.done)

    def test_invalid_retry_cap(self):
        with self.assertRaises(TransferError):
            StopAndWaitSender(b"x", 20, max_retries=9)
        with self.assertRaises(TransferError):
            StopAndWaitSender(b"x", 20, max_retries=True)

    def test_bad_frame_not_acknowledged(self):
        with self.assertRaises(TransferError):
            ack_for_frame(b"")
        frame = bytearray(encode_chunk(0, b"x", 20)[0])
        frame[1] = 99
        with self.assertRaises(TransferError):
            ack_for_frame(bytes(frame))

    def test_sender_advances_between_chunks(self):
        payload = b"Q" * 16384 + b"R" * 3
        sender = StopAndWaitSender(payload, 512)
        seen_chunks = set()
        while not sender.done:
            frame = sender.pending()
            seen_chunks.add(int.from_bytes(frame[2:4], "big"))
            sender.acknowledge(ack_for_frame(frame))
        self.assertEqual(seen_chunks, {0, 1})

    def test_maximum_chunk_sender(self):
        sender = StopAndWaitSender(b"a" * 16384, 512)
        count = 0
        while not sender.done:
            frame = sender.pending()
            sender.acknowledge(ack_for_frame(frame))
            count += 1
        self.assertEqual(count, 33)

    def test_retry_count_resets_on_ack(self):
        sender = StopAndWaitSender(b"x" * 40, 20, max_retries=1)
        sender.on_timeout()
        sender.acknowledge(ack_for_frame(sender.pending()))
        self.assertEqual(sender.on_timeout(), sender.pending())

    def test_ack_not_sender_authentication(self):
        sender = StopAndWaitSender(b"x", 20)
        # A synthetic ACK works: production MUST authenticate the BLE channel.
        sender.acknowledge(ack_for_frame(sender.pending()))
        self.assertTrue(sender.done)


class AckingReceiverTests(unittest.TestCase):
    def make_receiver(self, payload: bytes):
        offer = make_offer("citadel", "a" * 32, payload)
        session = TransferSession(
            offer, Receiver(), user_approved=True, identity_verified=True
        )
        return AckingBleReceiver(BleTransferBridge(session, len(payload), 20))

    def test_lost_ack_immediate_retry(self):
        payload = b"x" * 25
        receiver = self.make_receiver(payload)
        frames = encode_chunk(0, payload, 20)
        ack = receiver.receive(frames[0])
        self.assertEqual(receiver.receive(frames[0]), ack)
        for frame in frames[1:]:
            receiver.receive(frame)
        self.assertEqual(receiver.finish(), payload)

    def test_full_sender_receiver_with_lost_ack(self):
        payload = b"y" * 50
        sender = StopAndWaitSender(payload, 20)
        receiver = self.make_receiver(payload)
        frame = sender.pending()
        first_ack = receiver.receive(frame)
        self.assertEqual(receiver.receive(sender.on_timeout()), first_ack)
        sender.acknowledge(first_ack)
        while not sender.done:
            sender.acknowledge(receiver.receive(sender.pending()))
        self.assertEqual(receiver.finish(), payload)

    def test_modified_duplicate_aborts(self):
        payload = b"A" * 30
        receiver = self.make_receiver(payload)
        first = encode_chunk(0, payload, 20)[0]
        receiver.receive(first)
        corrupted = bytearray(first)
        corrupted[-1] ^= 1
        with self.assertRaises(TransferError):
            receiver.receive(bytes(corrupted))
        with self.assertRaises(TransferError):
            receiver.finish()

    def test_post_finish_replay_rejected(self):
        receiver = self.make_receiver(b"x")
        frame = encode_chunk(0, b"x", 20)[0]
        receiver.receive(frame)
        self.assertEqual(receiver.finish(), b"x")
        with self.assertRaises(TransferError):
            receiver.receive(frame)

    def test_abort_rejects_retransmit(self):
        receiver = self.make_receiver(b"x")
        frame = encode_chunk(0, b"x", 20)[0]
        receiver.receive(frame)
        receiver.abort()
        with self.assertRaises(TransferError):
            receiver.receive(frame)


if __name__ == "__main__":
    unittest.main()

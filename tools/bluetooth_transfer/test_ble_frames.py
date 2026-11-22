"""BLE framing regressions, using synthetic packets rather than radio hardware."""
import unittest

from ble_frames import BleChunkReassembler, BleTransferBridge, encode_chunk
from protocol import CHUNK_BYTES, Receiver, TransferError, chunks, make_offer
from session import TransferSession

ID = "abcdef0123456789abcdef0123456789"


class FrameTests(unittest.TestCase):
    def test_small_gatt_value_roundtrip(self):
        payload = bytes(range(256)) * 3
        frames = encode_chunk(4, payload, 20)
        receiver = BleChunkReassembler(4, len(payload), 20)
        self.assertTrue(all(len(frame) <= 20 for frame in frames))
        self.assertEqual([receiver.push(f) for f in frames][:-1], [None] * (len(frames) - 1))
        self.assertTrue(receiver.closed)

    def test_single_packet_roundtrip(self):
        frame, = encode_chunk(0, b"Hello", 20)
        self.assertEqual(BleChunkReassembler(0, 5, 20).push(frame), b"Hello")

    def test_max_chunk_roundtrip(self):
        source = b"X" * CHUNK_BYTES
        frames = encode_chunk(63, source, 512)
        receiver = BleChunkReassembler(63, len(source), 512)
        outcome = [receiver.push(frame) for frame in frames]
        self.assertEqual(outcome[-1], source)

    def test_wrong_index(self):
        receiver = BleChunkReassembler(0, 3, 20)
        with self.assertRaises(TransferError):
            receiver.push(encode_chunk(1, b"ABC", 20)[0])
        self.assertTrue(receiver.closed)

    def test_duplicate_segment(self):
        frames = encode_chunk(0, b"A" * 30, 20)
        receiver = BleChunkReassembler(0, 30, 20)
        receiver.push(frames[0])
        with self.assertRaises(TransferError):
            receiver.push(frames[0])

    def test_out_of_order_segment(self):
        frames = encode_chunk(0, b"A" * 30, 20)
        with self.assertRaises(TransferError):
            BleChunkReassembler(0, 30, 20).push(frames[1])

    def test_invalid_terminal_flag(self):
        frame = bytearray(encode_chunk(0, b"abc", 20)[0])
        frame[6] = 0
        with self.assertRaises(TransferError):
            BleChunkReassembler(0, 3, 20).push(bytes(frame))

    def test_oversized_frame(self):
        with self.assertRaises(TransferError):
            BleChunkReassembler(0, 1, 20).push(b"X" * 21)

    def test_wrong_protocol(self):
        frame = bytearray(encode_chunk(0, b"ab", 20)[0])
        frame[1] = 2
        with self.assertRaises(TransferError):
            BleChunkReassembler(0, 2, 20).push(bytes(frame))

    def test_invalid_gatt_value_limit(self):
        with self.assertRaises(TransferError):
            encode_chunk(0, b"x", 7)
        with self.assertRaises(TransferError):
            encode_chunk(0, b"x", True)

    def test_premature_short_segment(self):
        frame = bytes((80, 1, 0, 0, 0, 0, 0)) + b"A"
        with self.assertRaises(TransferError):
            BleChunkReassembler(0, 20, 20).push(frame)

    def test_reject_after_completion(self):
        frame, = encode_chunk(0, b"abc", 20)
        receiver = BleChunkReassembler(0, 3, 20)
        self.assertEqual(receiver.push(frame), b"abc")
        with self.assertRaises(TransferError):
            receiver.push(frame)


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.payload = b"C" * CHUNK_BYTES + b"D" * 71
        self.offer = make_offer("citadel", ID, self.payload)
        self.guard = Receiver()
        self.session = TransferSession(
            self.offer, self.guard, user_approved=True, identity_verified=True,
        )

    def test_full_transfer(self):
        bridge = BleTransferBridge(self.session, len(self.payload), 77)
        for chunk_index, data in enumerate(chunks(self.payload)):
            for frame in encode_chunk(chunk_index, data, 77):
                bridge.push(frame)
        self.assertEqual(bridge.finish(), self.payload)
        self.assertTrue(self.session.closed)

    def test_disconnect(self):
        bridge = BleTransferBridge(self.session, len(self.payload), 20)
        bridge.push(encode_chunk(0, chunks(self.payload)[0], 20)[0])
        bridge.abort()
        self.assertTrue(self.session.closed)
        with self.assertRaises(TransferError):
            bridge.finish()

    def test_corrupted_frame_aborts_all(self):
        bridge = BleTransferBridge(self.session, len(self.payload), 20)
        frame = bytearray(encode_chunk(0, chunks(self.payload)[0], 20)[0])
        frame[0] = 0
        with self.assertRaises(TransferError):
            bridge.push(bytes(frame))
        self.assertTrue(self.session.closed)

    def test_early_finish_aborts(self):
        bridge = BleTransferBridge(self.session, len(self.payload), 20)
        bridge.push(encode_chunk(0, chunks(self.payload)[0], 20)[0])
        with self.assertRaises(TransferError):
            bridge.finish()
        self.assertTrue(self.session.closed)

    def test_payload_digest_failure(self):
        bridge = BleTransferBridge(self.session, len(self.payload), 512)
        tampered = b"Z" * len(self.payload)
        for index, data in enumerate(chunks(tampered)):
            for frame in encode_chunk(index, data, 512):
                bridge.push(frame)
        with self.assertRaises(TransferError):
            bridge.finish()
        self.assertTrue(self.session.closed)


if __name__ == "__main__":
    unittest.main()

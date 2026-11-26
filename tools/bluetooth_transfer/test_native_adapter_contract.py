"""Native-adapter lifecycle tests using deliberately synthetic secure evidence."""
from dataclasses import replace
import unittest

from ble_frames import encode_chunk
from ble_sender import ack_for_frame
from native_adapter_contract import NativeReceiveController, ReceiveState
from protocol import Receiver, TransferError, chunks, make_offer
from transport_gate import VerifiedTransportEvidence, offer_binding_digest

TRANSFER_ID = "98abcdef" * 4


class AdapterLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.payload = b"A" * 16384 + b"B" * 17
        self.offer = make_offer("mundo", TRANSFER_ID, self.payload)
        self.guard = Receiver()
        self.controller = NativeReceiveController(self.guard)
        self.evidence = VerifiedTransportEvidence(
            peer_identity_verified=True,
            local_identity_verified=True,
            authenticated_key_agreement=True,
            encrypted_channel_verified=True,
            offer_authenticated=True,
            consent_for_exact_offer=True,
            revocation_current=True,
            trusted_time_current=True,
            peer_key_fingerprint="a" * 64,
            bound_offer_digest=offer_binding_digest(self.offer),
        )

    def begin(self):
        self.controller.begin(self.offer, self.evidence, 77)

    def send_all(self):
        for index, part in enumerate(chunks(self.payload)):
            for frame in encode_chunk(index, part, 77):
                self.assertEqual(self.controller.on_notification(frame), ack_for_frame(frame))

    def test_complete_transfer(self):
        self.begin()
        self.assertEqual(self.controller.state, ReceiveState.RECEIVING)
        self.send_all()
        self.assertEqual(self.controller.complete(), self.payload)
        self.assertEqual(self.controller.state, ReceiveState.RECEIVED_UNTRUSTED)

    def test_initial_state(self):
        self.assertEqual(self.controller.state, ReceiveState.IDLE)

    def test_before_begin_denied(self):
        with self.assertRaises(TransferError):
            self.controller.on_notification(b"x")

    def test_complete_before_begin_denied(self):
        with self.assertRaises(TransferError):
            self.controller.complete()

    def test_missing_encryption_denied(self):
        with self.assertRaises(TransferError):
            self.controller.begin(self.offer, replace(
                self.evidence, encrypted_channel_verified=False), 77)
        self.assertEqual(self.controller.state, ReceiveState.IDLE)

    def test_wrong_offer_binding_denied(self):
        with self.assertRaises(TransferError):
            self.controller.begin(self.offer, replace(
                self.evidence, bound_offer_digest="0" * 64), 77)

    def test_invalid_gatt_value_denied(self):
        with self.assertRaises(TransferError):
            self.controller.begin(self.offer, self.evidence, 7)

    def test_successful_begin_cannot_repeat(self):
        self.begin()
        with self.assertRaises(TransferError):
            self.begin()

    def test_disconnect_aborts_buffered_data(self):
        self.begin()
        frame = encode_chunk(0, chunks(self.payload)[0], 77)[0]
        self.controller.on_notification(frame)
        self.controller.disconnect()
        self.assertEqual(self.controller.state, ReceiveState.ABORTED)
        with self.assertRaises(TransferError):
            self.controller.complete()

    def test_permission_revoked_aborts(self):
        self.begin()
        self.controller.permission_revoked()
        self.assertEqual(self.controller.state, ReceiveState.ABORTED)

    def test_corrupt_packet_aborts(self):
        self.begin()
        with self.assertRaises(TransferError):
            self.controller.on_notification(b"garbage")
        self.assertEqual(self.controller.state, ReceiveState.ABORTED)

    def test_early_complete_aborts(self):
        self.begin()
        with self.assertRaises(TransferError):
            self.controller.complete()
        self.assertEqual(self.controller.state, ReceiveState.ABORTED)

    def test_no_restart_after_abort(self):
        self.begin()
        self.controller.abort()
        with self.assertRaises(TransferError):
            self.begin()

    def test_replay_rejected_by_new_controller(self):
        self.begin()
        self.send_all()
        self.controller.complete()
        another = NativeReceiveController(self.guard)
        with self.assertRaises(TransferError):
            another.begin(self.offer, self.evidence, 77)

    def test_no_frames_after_completion(self):
        self.begin()
        self.send_all()
        self.controller.complete()
        with self.assertRaises(TransferError):
            self.controller.on_notification(encode_chunk(0, b"A", 77)[0])

    def test_abort_is_idempotent(self):
        self.begin()
        self.controller.abort()
        self.controller.abort()
        self.assertEqual(self.controller.state, ReceiveState.ABORTED)

    def test_duplicate_immediate_frame_reacked(self):
        self.begin()
        first = encode_chunk(0, chunks(self.payload)[0], 77)[0]
        ack = self.controller.on_notification(first)
        self.assertEqual(self.controller.on_notification(first), ack)


if __name__ == "__main__":
    unittest.main()

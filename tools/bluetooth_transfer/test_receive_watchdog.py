"""Deterministic monotonic watchdog regressions, no Bluetooth hardware."""
from dataclasses import replace
import unittest

from ble_frames import encode_chunk
from native_adapter_contract import NativeReceiveController, ReceiveState
from protocol import Receiver, TransferError, chunks, make_offer
from receive_watchdog import ReceiveWatchdog
from transport_gate import VerifiedTransportEvidence, offer_binding_digest


class FakeClock:
    def __init__(self):
        self.value = 100.0

    def __call__(self):
        return self.value


class WatchdogTests(unittest.TestCase):
    def setUp(self):
        self.payload = b"A" * 40
        self.offer = make_offer("citadel", "a" * 32, self.payload)
        self.evidence = VerifiedTransportEvidence(
            peer_identity_verified=True,
            local_identity_verified=True,
            authenticated_key_agreement=True,
            encrypted_channel_verified=True,
            offer_authenticated=True,
            consent_for_exact_offer=True,
            revocation_current=True,
            trusted_time_current=True,
            peer_key_fingerprint="b" * 64,
            bound_offer_digest=offer_binding_digest(self.offer),
        )
        self.clock = FakeClock()
        self.controller = NativeReceiveController(Receiver())
        self.guard = ReceiveWatchdog(
            self.controller, self.clock, idle_seconds=10, total_seconds=30,
        )

    def start(self):
        self.guard.begin(self.offer, self.evidence, 20)

    def test_complete_before_deadline(self):
        self.start()
        for packet in encode_chunk(0, self.payload, 20):
            self.guard.on_notification(packet)
        self.assertEqual(self.guard.complete(), self.payload)
        self.assertEqual(self.guard.state, ReceiveState.RECEIVED_UNTRUSTED)

    def test_idle_timeout(self):
        self.start()
        self.clock.value += 10
        with self.assertRaises(TransferError):
            self.guard.poll()
        self.assertEqual(self.guard.state, ReceiveState.ABORTED)

    def test_total_timeout_despite_progress(self):
        self.start()
        packets = encode_chunk(0, self.payload, 20)
        self.clock.value = 109
        self.guard.on_notification(packets[0])
        self.clock.value = 118
        self.guard.on_notification(packets[1])
        self.clock.value = 130
        with self.assertRaises(TransferError):
            self.guard.poll()
        self.assertEqual(self.guard.state, ReceiveState.ABORTED)

    def test_duplicate_packet_does_not_reset_idle(self):
        self.start()
        frame = encode_chunk(0, self.payload, 20)[0]
        self.guard.on_notification(frame)
        self.clock.value = 109
        self.guard.on_notification(frame)
        self.clock.value = 110
        with self.assertRaises(TransferError):
            self.guard.poll()

    def test_progress_resets_idle(self):
        self.start()
        packets = encode_chunk(0, self.payload, 20)
        self.clock.value = 109
        self.guard.on_notification(packets[0])
        self.clock.value = 118
        self.guard.on_notification(packets[1])
        self.clock.value = 119
        self.guard.poll()
        self.assertEqual(self.guard.state, ReceiveState.RECEIVING)

    def test_clock_regression(self):
        self.start()
        self.clock.value = 99
        with self.assertRaises(TransferError):
            self.guard.poll()
        self.assertEqual(self.guard.state, ReceiveState.ABORTED)

    def test_non_finite_clock(self):
        self.start()
        self.clock.value = float("nan")
        with self.assertRaises(TransferError):
            self.guard.poll()
        self.assertEqual(self.guard.state, ReceiveState.ABORTED)

    def test_boolean_clock_rejected(self):
        self.clock.value = True
        with self.assertRaises(TransferError):
            self.start()
        self.assertEqual(self.guard.state, ReceiveState.ABORTED)

    def test_clock_failure_aborts(self):
        self.start()
        self.guard._clock = lambda: 1 / 0
        with self.assertRaises(TransferError):
            self.guard.poll()
        self.assertEqual(self.guard.state, ReceiveState.ABORTED)

    def test_complete_checks_timeout(self):
        self.start()
        for packet in encode_chunk(0, self.payload, 20):
            self.guard.on_notification(packet)
        self.clock.value = 130
        with self.assertRaises(TransferError):
            self.guard.complete()

    def test_no_pre_begin_notification(self):
        with self.assertRaises(TransferError):
            self.guard.on_notification(b"x")

    def test_no_pre_begin_poll(self):
        with self.assertRaises(TransferError):
            self.guard.poll()

    def test_reopen_denied(self):
        self.start()
        with self.assertRaises(TransferError):
            self.start()

    def test_invalid_idle_limit(self):
        with self.assertRaises(TransferError):
            ReceiveWatchdog(self.controller, self.clock, idle_seconds=0)

    def test_invalid_total_limit(self):
        with self.assertRaises(TransferError):
            ReceiveWatchdog(self.controller, self.clock, total_seconds=3601)

    def test_idle_longer_than_total_denied(self):
        with self.assertRaises(TransferError):
            ReceiveWatchdog(self.controller, self.clock, idle_seconds=20,
                            total_seconds=10)

    def test_boolean_limits_denied(self):
        with self.assertRaises(TransferError):
            ReceiveWatchdog(self.controller, self.clock, idle_seconds=True)

    def test_bad_security_evidence_rejected(self):
        with self.assertRaises(TransferError):
            self.guard.begin(
                self.offer,
                replace(self.evidence, encrypted_channel_verified=False), 20,
            )
        self.assertEqual(self.guard.state, ReceiveState.IDLE)

    def test_manual_abort(self):
        self.start()
        self.guard.abort()
        with self.assertRaises(TransferError):
            self.guard.poll()
        self.assertEqual(self.guard.state, ReceiveState.ABORTED)

    def test_bad_packet_aborts(self):
        self.start()
        with self.assertRaises(TransferError):
            self.guard.on_notification(b"bad")
        self.assertEqual(self.guard.state, ReceiveState.ABORTED)


if __name__ == "__main__":
    unittest.main()

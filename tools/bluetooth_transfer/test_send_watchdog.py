"""Synthetic sender deadline regressions (no Bluetooth device required)."""
import unittest

from ble_sender import StopAndWaitSender, ack_for_frame
from protocol import TransferError
from send_watchdog import SendWatchdog


class Clock:
    def __init__(self):
        self.value = 100.0

    def __call__(self):
        return self.value


class SendDeadlineTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.sender = StopAndWaitSender(b"X" * 27, 20, max_retries=2)
        self.watchdog = SendWatchdog(
            self.sender, self.clock, ack_seconds=5, total_seconds=30,
        )

    def test_start_returns_first_frame(self):
        self.assertEqual(self.watchdog.start(), self.sender.pending())

    def test_start_twice_denied(self):
        self.watchdog.start()
        with self.assertRaises(TransferError):
            self.watchdog.start()

    def test_poll_before_start_denied(self):
        with self.assertRaises(TransferError):
            self.watchdog.poll()

    def test_no_retransmit_before_deadline(self):
        self.watchdog.start()
        self.clock.value = 104
        self.assertIsNone(self.watchdog.poll())

    def test_exact_deadline_retransmit(self):
        first = self.watchdog.start()
        self.clock.value = 105
        self.assertEqual(self.watchdog.poll(), first)

    def test_ack_then_next_frame(self):
        first = self.watchdog.start()
        next_frame = self.watchdog.acknowledge(ack_for_frame(first))
        self.assertIsNotNone(next_frame)
        self.assertNotEqual(next_frame, first)

    def test_full_transfer_completion(self):
        current = self.watchdog.start()
        while current is not None:
            current = self.watchdog.acknowledge(ack_for_frame(current))
        self.assertTrue(self.watchdog.done)
        self.assertTrue(self.watchdog.closed)

    def test_lost_ack_retried(self):
        first = self.watchdog.start()
        self.clock.value = 105
        self.assertEqual(self.watchdog.poll(), first)
        self.clock.value = 106
        self.assertIsNotNone(self.watchdog.acknowledge(ack_for_frame(first)))

    def test_retry_exhaustion_closes(self):
        self.watchdog.start()
        for now in (105, 110):
            self.clock.value = now
            self.assertIsNotNone(self.watchdog.poll())
        self.clock.value = 115
        with self.assertRaises(TransferError):
            self.watchdog.poll()
        self.assertTrue(self.watchdog.closed)

    def test_late_ack_denied(self):
        first = self.watchdog.start()
        self.clock.value = 105
        with self.assertRaises(TransferError):
            self.watchdog.acknowledge(ack_for_frame(first))
        self.assertTrue(self.watchdog.closed)

    def test_total_deadline_denied(self):
        self.watchdog.start()
        self.clock.value = 130
        with self.assertRaises(TransferError):
            self.watchdog.poll()
        self.assertTrue(self.watchdog.closed)

    def test_clock_regression_denied(self):
        self.watchdog.start()
        self.clock.value = 99
        with self.assertRaises(TransferError):
            self.watchdog.poll()
        self.assertTrue(self.watchdog.closed)

    def test_invalid_clock_denied(self):
        self.watchdog.start()
        self.clock.value = float("nan")
        with self.assertRaises(TransferError):
            self.watchdog.poll()
        self.assertTrue(self.watchdog.closed)

    def test_clock_exception_denied(self):
        self.watchdog.start()
        self.watchdog._clock = lambda: 1 / 0
        with self.assertRaises(TransferError):
            self.watchdog.poll()
        self.assertTrue(self.watchdog.closed)

    def test_invalid_deadline_denied(self):
        with self.assertRaises(TransferError):
            SendWatchdog(self.sender, self.clock, ack_seconds=0)
        with self.assertRaises(TransferError):
            SendWatchdog(self.sender, self.clock, total_seconds=True)

    def test_disconnect_cancels(self):
        self.watchdog.start()
        self.watchdog.disconnect()
        with self.assertRaises(TransferError):
            self.watchdog.poll()

    def test_bad_ack_aborts(self):
        self.watchdog.start()
        with self.assertRaises(TransferError):
            self.watchdog.acknowledge(b"wrong")
        self.assertTrue(self.watchdog.closed)

    def test_ack_deadline_resets_on_valid_progress(self):
        first = self.watchdog.start()
        self.clock.value = 104
        self.watchdog.acknowledge(ack_for_frame(first))
        self.clock.value = 108
        self.assertIsNone(self.watchdog.poll())
        self.clock.value = 109
        self.assertIsNotNone(self.watchdog.poll())

    def test_manual_abort(self):
        self.watchdog.start()
        self.watchdog.abort()
        self.assertTrue(self.watchdog.closed)
        self.assertFalse(self.watchdog.done)


if __name__ == "__main__":
    unittest.main()

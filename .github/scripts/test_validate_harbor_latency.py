#!/usr/bin/env python3
"""Negative regression cases for the Harbor latency evidence parser."""
import unittest
from validate_harbor_latency import validate

A = "HARBOR_RECOVER frames=1 runs=7 min_us=10 median_us=11 max_us=12"
B = "HARBOR_RECOVER frames=16 runs=7 min_us=20 median_us=21 max_us=22"
C = "HARBOR_RECOVER frames=64 runs=7 min_us=30 median_us=31 max_us=32"


class ValidatorTests(unittest.TestCase):
    def test_valid_input(self):
        self.assertEqual(validate("\n".join([A, B, C])), "\n".join([A, B, C]) + "\n")

    def test_duplicate_frame(self):
        self.assertRaises(ValueError, validate, "\n".join([A, A, C]))

    def test_missing_frame(self):
        self.assertRaises(ValueError, validate, "\n".join([A, B]))

    def test_out_of_order_durations(self):
        self.assertRaises(ValueError, validate, "\n".join([A, B.replace("median_us=21", "median_us=19"), C]))

    def test_malformed_result(self):
        self.assertRaises(ValueError, validate, "\n".join([A, B.replace("runs=7", "runs=6"), C]))

    def test_extra_result(self):
        self.assertRaises(ValueError, validate, "\n".join([A, B, C, C]))

    def test_reject_trailing_garbage(self):
        self.assertRaises(ValueError, validate, "\n".join([A, B + " junk", C]))


if __name__ == "__main__":
    unittest.main()

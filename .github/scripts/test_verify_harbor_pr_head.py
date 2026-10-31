#!/usr/bin/env python3
"""Exercise both success and rejection paths for Harbor PR-head verification."""
import unittest
from verify_harbor_pr_head import matches

A = "0ff05fd9ce63e78818a6de0b41e17f96f1c052f7"
B = "e389b2a05900f3b34ae78f450361e6180e280cc7"


class HeadGuardTests(unittest.TestCase):
    def test_accept_exact_sha(self):
        self.assertTrue(matches(A, A))

    def test_reject_different_valid_sha(self):
        self.assertFalse(matches(A, B))

    def test_reject_empty_expected(self):
        self.assertFalse(matches("", A))

    def test_reject_empty_actual(self):
        self.assertFalse(matches(A, ""))

    def test_reject_short_sha(self):
        self.assertFalse(matches(A[:7], A))

    def test_reject_uppercase(self):
        self.assertFalse(matches(A.upper(), A))

    def test_reject_non_hex(self):
        self.assertFalse(matches("z" + A[1:], A))

    def test_reject_whitespace(self):
        self.assertFalse(matches(A + "\n", A))


if __name__ == "__main__":
    unittest.main()

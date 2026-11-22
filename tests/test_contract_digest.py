"""Tests for the review-only PALACO-CJSON-v0 digest convention."""
import tempfile
import unittest
from pathlib import Path

from tools.contract_digest import MAX_NESTING_DEPTH, MAX_SAFE_INTEGER, canonical_bytes, digest_contract, digest_contract_file


class ContractDigestTests(unittest.TestCase):
    def test_exact_depth_limit_is_accepted(self):
        nested = 0
        for _ in range(MAX_NESTING_DEPTH):
            nested = [nested]
        self.assertTrue(canonical_bytes(nested).startswith(b"["))

    def test_depth_over_limit_rejected(self):
        nested = 0
        for _ in range(MAX_NESTING_DEPTH + 1):
            nested = [nested]
        with self.assertRaisesRegex(ValueError, "nesting depth"):
            canonical_bytes(nested)

    def test_safe_integer_boundaries(self):
        self.assertEqual(canonical_bytes({"max": MAX_SAFE_INTEGER}),
                         ('{"max":' + str(MAX_SAFE_INTEGER) + '}').encode())
        self.assertEqual(canonical_bytes({"min": -MAX_SAFE_INTEGER}),
                         ('{"min":-' + str(MAX_SAFE_INTEGER) + '}').encode())

    def test_rejects_positive_integer_outside_safe_range(self):
        with self.assertRaisesRegex(ValueError, "safe range"):
            canonical_bytes({"counter": MAX_SAFE_INTEGER + 1})

    def test_rejects_negative_integer_outside_safe_range(self):
        with self.assertRaisesRegex(ValueError, "safe range"):
            canonical_bytes({"counter": -MAX_SAFE_INTEGER - 1})

    def test_rejects_nested_oversized_integer(self):
        with self.assertRaisesRegex(ValueError, "safe range"):
            canonical_bytes({"values": [0, {"counter": 2 ** 70}]})

    def test_file_digest_rejects_oversized_integer(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.json"
            path.write_text('{"counter":9007199254740992}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "safe range"):
                digest_contract_file(path)

    def test_key_order_is_deterministic(self):
        first = {"z": 1, "a": {"b": True, "a": None}}
        second = {"a": {"a": None, "b": True}, "z": 1}
        self.assertEqual(canonical_bytes(first), canonical_bytes(second))
        self.assertEqual(digest_contract(first), digest_contract(second))

    def test_compact_canonical_encoding(self):
        self.assertEqual(canonical_bytes({"b": 2, "a": 1}), b'{"a":1,"b":2}')

    def test_changes_change_digest(self):
        self.assertNotEqual(digest_contract({"release_gate": "HOLD"}),
                            digest_contract({"release_gate": "GO"}))

    def test_reject_floats(self):
        with self.assertRaisesRegex(ValueError, "unsupported"):
            canonical_bytes({"value": 1.0})

    def test_reject_decomposed_unicode(self):
        with self.assertRaisesRegex(ValueError, "non-NFC"):
            canonical_bytes({"name": "e\u0301"})

    def test_accept_nfc_unicode(self):
        self.assertIn("é".encode(), canonical_bytes({"name": "é"}))

    def test_reject_nonstring_keys(self):
        with self.assertRaisesRegex(ValueError, "keys must be strings"):
            canonical_bytes({1: "one"})

    def test_reject_unpaired_surrogate(self):
        with self.assertRaisesRegex(ValueError, "unpaired"):
            canonical_bytes({"name": "\ud800"})

    def test_file_digest_rejects_duplicate_members(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.json"
            path.write_text('{"gate":"HOLD","gate":"GO"}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                digest_contract_file(path)

    def test_file_digest_matches_in_memory_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.json"
            path.write_text('{"b":2,"a":1}', encoding="utf-8")
            self.assertEqual(digest_contract_file(path), digest_contract({"a": 1, "b": 2}))


if __name__ == "__main__":
    unittest.main()

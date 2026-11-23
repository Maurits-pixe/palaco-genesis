"""Tests for the review-only PALACO-CJSON-v0 digest convention."""
import hashlib
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

    def test_digest_uses_domain_separator_and_eight_byte_length(self):
        payload = b'{"gate":"HOLD"}'
        expected = hashlib.sha256(
            b"PALACO-CJSON-v0" + bytes.fromhex("00")
            + len(payload).to_bytes(8, "big")
            + payload
        ).hexdigest()
        self.assertEqual(digest_contract({"gate": "HOLD"}), expected)

    def test_digest_differs_from_unframed_sha256(self):
        payload = canonical_bytes({"gate": "HOLD"})
        self.assertNotEqual(digest_contract({"gate": "HOLD"}),
                            hashlib.sha256(payload).hexdigest())
        self.assertNotEqual(
            digest_contract({"gate": "HOLD"}),
            hashlib.sha256(b"PALACO-CJSON-v0" + bytes.fromhex("00") + payload).hexdigest(),
        )

    def test_file_digest_ignores_whitespace_and_member_order(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.json"
            path.write_text('  {"b":2, "a":{"y":true,"x":null}}' + chr(10), encoding="utf-8")
            first = digest_contract_file(path)
            path.write_text('{"a":{"x":null,"y":true},"b":2}', encoding="utf-8")
            self.assertEqual(first, digest_contract_file(path))
            self.assertEqual(first, digest_contract({"a":{"x":None,"y":True},"b":2}))

    def test_file_digest_detects_semantic_value_change(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.json"
            path.write_text('{"release_gate":"HOLD"}', encoding="utf-8")
            baseline = digest_contract_file(path)
            path.write_text('{"release_gate":"DENY"}', encoding="utf-8")
            self.assertNotEqual(baseline, digest_contract_file(path))

    def test_unicode_key_order_uses_codepoints_not_utf16_units(self):
        # U+E000 sorts before U+1F680 by code point, unlike UTF-16 order.
        obj = {chr(0x1f680): 2, chr(0xe000): 1}
        expected = ('{"' + chr(0xe000) + '":1,"' + chr(0x1f680) + '":2}').encode("utf-8")
        self.assertEqual(canonical_bytes(obj), expected)

    def test_astral_unicode_uses_literal_four_byte_utf8(self):
        value = {"symbol": chr(0x1f680)}
        canonical = canonical_bytes(value)
        self.assertEqual(canonical, b'{"symbol":"' + bytes.fromhex("f09f9a80") + b'"}')
        self.assertNotIn(b"\\\\ud83d", canonical)

    def test_control_characters_canonicalize_as_json_escapes(self):
        value = {"control": chr(0) + chr(10) + chr(9)}
        expected = b'{"control":"' + bytes.fromhex("5c7530303030") + b'\\\\n\\\\t"}'
        self.assertEqual(canonical_bytes(value), expected)

    def test_escaped_and_literal_astral_json_have_same_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "astral.json"
            path.write_text('{"symbol":"' + chr(0x1f680) + '"}', encoding="utf-8")
            literal = digest_contract_file(path)
            path.write_text('{"symbol":"' + chr(92) + 'ud83d' + chr(92) + 'ude80"}',
                            encoding="utf-8")
            self.assertEqual(literal, digest_contract_file(path))

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

    def test_file_digest_rejects_finite_decimal_even_when_parser_accepts_it(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fraction.json"
            path.write_text('{"value":1.25}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unsupported"):
                digest_contract_file(path)

    def test_file_digest_rejects_nonzero_decimal_underflow(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "underflow.json"
            path.write_text('{"value":1e-999}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "underflow"):
                digest_contract_file(path)

    def test_file_digest_rejects_utf8_bom(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bom.json"
            path.write_bytes(bytes.fromhex("efbbbf") + b'{"gate":"HOLD"}')
            with self.assertRaisesRegex(ValueError, "byte-order mark"):
                digest_contract_file(path)

    def test_file_digest_rejects_decomposed_unicode_text(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "decomposed.json"
            path.write_text('{"name":"e' + chr(0x301) + '"}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "non-NFC"):
                digest_contract_file(path)

    def test_file_digest_rejects_escaped_duplicate_members(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "aliases.json"
            path.write_text(r'{"gate":"HOLD","g\u0061te":"GO"}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                digest_contract_file(path)

    def test_file_digest_matches_in_memory_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.json"
            path.write_text('{"b":2,"a":1}', encoding="utf-8")
            self.assertEqual(digest_contract_file(path), digest_contract({"a": 1, "b": 2}))


if __name__ == "__main__":
    unittest.main()

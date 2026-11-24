"""Tests for the review-only PALACO-CJSON-v0 digest convention."""
import hashlib
import tempfile
import unittest
from pathlib import Path

from tools.contract_digest import MAX_NESTING_DEPTH, MAX_SAFE_INTEGER, canonical_bytes, digest_contract, digest_contract_file
from tools.strict_contract_json import load_strict_json


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

    def test_multibyte_utf8_framing_counts_bytes_not_characters(self):
        obj = {"symbol": chr(0x1f680)}
        canonical = canonical_bytes(obj)
        self.assertEqual(len(canonical), 17)
        self.assertEqual(len(canonical.decode("utf-8")), 14)
        expected = hashlib.sha256(
            b"PALACO-CJSON-v0" + bytes.fromhex("00")
            + bytes.fromhex("0000000000000011")
            + canonical
        ).hexdigest()
        wrong_character_length = hashlib.sha256(
            b"PALACO-CJSON-v0" + bytes.fromhex("00")
            + bytes.fromhex("000000000000000e")
            + canonical
        ).hexdigest()
        self.assertEqual(digest_contract(obj), expected)
        self.assertNotEqual(digest_contract(obj), wrong_character_length)

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
        expected = b'{"control":"' + bytes.fromhex("5c75303030305c6e5c74") + b'"}'
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

    def test_special_javascript_property_names_are_ordinary_json_keys(self):
        source = '{"prototype":"HOLD","constructor":7,"__proto__":{"polluted":true}}'
        expected = b'{"__proto__":{"polluted":true},"constructor":7,"prototype":"HOLD"}'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "properties.json"
            path.write_text(source, encoding="utf-8")
            parsed = load_strict_json(path)
            self.assertEqual(canonical_bytes(parsed), expected)
            self.assertEqual(digest_contract_file(path), digest_contract(parsed))

    def test_escaped_proto_alias_is_rejected_as_duplicate_member(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "proto-alias.json"
            path.write_text('{"__proto__":1,"__pro' + chr(92) + 'u0074o__":2}',
                            encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                digest_contract_file(path)

    def test_integer_negative_zero_matches_zero_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "negative-zero.json"
            path.write_text('{"counter":-0}', encoding="utf-8")
            self.assertEqual(digest_contract_file(path), digest_contract({"counter": 0}))
            path.write_text('{"counter":0}', encoding="utf-8")
            self.assertEqual(digest_contract_file(path), digest_contract({"counter": 0}))

    def test_decimal_negative_zero_rejected_by_digest_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "decimal-negative-zero.json"
            path.write_text('{"counter":-0.0}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unsupported"):
                digest_contract_file(path)

    def test_exponent_zero_rejected_by_digest_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "exponent-zero.json"
            path.write_text('{"counter":0e999}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unsupported"):
                digest_contract_file(path)

    def test_reordered_negative_integer_members_digest_identically(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "integers.json"
            path.write_text('{"b":-9007199254740991,"a":0}', encoding="utf-8")
            first = digest_contract_file(path)
            path.write_text('{"a":-0,"b":-9007199254740991}', encoding="utf-8")
            self.assertEqual(digest_contract_file(path), first)

    def test_array_order_changes_digest(self):
        first = {"items": ["HOLD", "DENY", 0]}
        second = {"items": ["DENY", "HOLD", 0]}
        self.assertNotEqual(canonical_bytes(first), canonical_bytes(second))
        self.assertNotEqual(digest_contract(first), digest_contract(second))

    def test_boolean_and_integer_values_have_distinct_digests(self):
        self.assertEqual(canonical_bytes({"flag": True}), b'{"flag":true}')
        self.assertEqual(canonical_bytes({"flag": 1}), b'{"flag":1}')
        self.assertNotEqual(digest_contract({"flag": True}),
                            digest_contract({"flag": 1}))
        self.assertNotEqual(digest_contract({"flag": False}),
                            digest_contract({"flag": 0}))

    def test_null_and_missing_member_have_distinct_digests(self):
        self.assertNotEqual(digest_contract({"value": None}), digest_contract({}))
        self.assertEqual(canonical_bytes({"value": None}), b'{"value":null}')

    def test_file_digest_preserves_array_order(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ordered.json"
            path.write_text('{"items":[0,1,2]}', encoding="utf-8")
            first = digest_contract_file(path)
            path.write_text('{"items":[2,1,0]}', encoding="utf-8")
            self.assertNotEqual(first, digest_contract_file(path))

    def test_rejects_direct_python_object_cycle(self):
        obj = {}
        obj["self"] = obj
        with self.assertRaisesRegex(ValueError, "cyclic JSON reference"):
            canonical_bytes(obj)

    def test_rejects_direct_python_array_cycle(self):
        values = []
        values.append(values)
        with self.assertRaisesRegex(ValueError, "cyclic JSON reference"):
            canonical_bytes(values)

    def test_rejects_mixed_object_array_cycle(self):
        obj = {"child": []}
        obj["child"].append(obj)
        with self.assertRaisesRegex(ValueError, "cyclic JSON reference"):
            digest_contract(obj)

    def test_accepts_shared_acyclic_subtree(self):
        child = {"gate": "HOLD"}
        value = [child, child]
        expected = b'[{"gate":"HOLD"},{"gate":"HOLD"}]'
        self.assertEqual(canonical_bytes(value), expected)
        self.assertEqual(digest_contract(value),
                         digest_contract([{"gate": "HOLD"}, {"gate": "HOLD"}]))

    def test_rejects_custom_dict_subclass(self):
        class CustomDict(dict):
            def values(self):
                raise AssertionError("custom values() must not execute")
        with self.assertRaisesRegex(ValueError, "unsupported canonical JSON"):
            canonical_bytes(CustomDict({"gate": "HOLD"}))

    def test_rejects_custom_list_subclass(self):
        class CustomList(list):
            def __iter__(self):
                raise AssertionError("custom iterator must not execute")
        with self.assertRaisesRegex(ValueError, "unsupported canonical JSON"):
            canonical_bytes(CustomList([1, 2]))

    def test_rejects_custom_string_subclass(self):
        class CustomString(str):
            pass
        with self.assertRaisesRegex(ValueError, "unsupported canonical JSON"):
            canonical_bytes({"gate": CustomString("HOLD")})

    def test_rejects_string_subclass_as_object_key(self):
        class CustomKey(str):
            pass
        with self.assertRaisesRegex(ValueError, "keys must be strings"):
            canonical_bytes({CustomKey("gate"): "HOLD"})

    def test_plain_json_values_still_canonicalize(self):
        self.assertEqual(canonical_bytes({"items": [True, None, 0, "HOLD"]}),
                         b'{"items":[true,null,0,"HOLD"]}')

    def test_rejects_non_json_python_collections(self):
        for candidate in ((1, 2), {1, 2}, frozenset((1, 2))):
            with self.subTest(candidate_type=type(candidate).__name__):
                with self.assertRaisesRegex(ValueError, "unsupported canonical JSON"):
                    canonical_bytes({"value": candidate})

    def test_rejects_nonfinite_and_fractional_python_numbers(self):
        for candidate in (float("nan"), float("inf"), -float("inf"), 0.5):
            with self.subTest(candidate=repr(candidate)):
                with self.assertRaisesRegex(ValueError, "unsupported canonical JSON"):
                    canonical_bytes({"value": candidate})

    def test_rejects_out_of_range_int_while_allowing_boundaries(self):
        for value in (MAX_SAFE_INTEGER + 1, -(MAX_SAFE_INTEGER + 1)):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "safe range"):
                    canonical_bytes({"value": value})
        self.assertEqual(canonical_bytes({"value": MAX_SAFE_INTEGER}),
                         ('{"value":' + str(MAX_SAFE_INTEGER) + '}').encode())
        self.assertEqual(canonical_bytes({"value": -MAX_SAFE_INTEGER}),
                         ('{"value":-' + str(MAX_SAFE_INTEGER) + '}').encode())

    def test_rejects_shared_dag_expansion_before_serialization(self):
        child = [0]
        for _ in range(18):
            child = [child, child]
        with self.assertRaisesRegex(ValueError, "node budget"):
            canonical_bytes(child)

    def test_rejects_oversized_canonical_utf8_output(self):
        with self.assertRaisesRegex(ValueError, "byte budget"):
            canonical_bytes({"value": "x" * (1024 * 1024)})

    def test_accepts_small_shared_dag_under_budget(self):
        child = [0]
        for _ in range(8):
            child = [child, child]
        self.assertTrue(canonical_bytes(child).startswith(b"["))

    def test_file_digest_matches_in_memory_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.json"
            path.write_text('{"b":2,"a":1}', encoding="utf-8")
            self.assertEqual(digest_contract_file(path), digest_contract({"a": 1, "b": 2}))


if __name__ == "__main__":
    unittest.main()

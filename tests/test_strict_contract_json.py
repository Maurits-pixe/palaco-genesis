"""Direct regression checks for the shared strict JSON loader."""
import tempfile
import unittest
from pathlib import Path

from tools.strict_contract_json import (
    MAX_DOCUMENT_BYTES,
    MAX_NESTING_DEPTH,
    load_strict_json,
)


class StrictContractJsonTests(unittest.TestCase):
    def load_raw(self, payload):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.json"
            path.write_text(payload, encoding="utf-8")
            return load_strict_json(path)

    def test_maximum_document_size_accepted(self):
        self.assertEqual(self.load_raw("0" + " " * (MAX_DOCUMENT_BYTES - 1)), 0)

    def test_document_exceeding_size_rejected(self):
        with self.assertRaisesRegex(ValueError, "size limit"):
            self.load_raw(" " * (MAX_DOCUMENT_BYTES + 1))

    def test_maximum_depth_accepted(self):
        document = "[" * MAX_NESTING_DEPTH + "0" + "]" * MAX_NESTING_DEPTH
        self.assertIsInstance(self.load_raw(document), list)

    def test_excessive_depth_rejected(self):
        depth = MAX_NESTING_DEPTH + 1
        document = "[" * depth + "0" + "]" * depth
        with self.assertRaisesRegex(ValueError, "nesting depth"):
            self.load_raw(document)

    def test_brackets_inside_json_string_are_not_nesting(self):
        document = '{"note":"' + ("[{" * 100) + '"}'
        self.assertEqual(len(self.load_raw(document)["note"]), 200)

    def test_escaped_quote_does_not_end_string(self):
        document = '{"note":"a\\\"' + ("[{" * 100) + '"}'
        self.assertEqual(len(self.load_raw(document)["note"]), 202)

    def test_truncated_nested_json_rejected(self):
        with self.assertRaises(ValueError):
            self.load_raw('{"a":[1,2}')

    def test_invalid_utf8_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_bytes(b"\xff")
            with self.assertRaises(UnicodeDecodeError):
                load_strict_json(path)

    def test_unpaired_high_surrogate_value_rejected(self):
        with self.assertRaisesRegex(ValueError, "unpaired Unicode surrogate"):
            self.load_raw(r'{"name":"\ud800"}')

    def test_unpaired_low_surrogate_value_rejected(self):
        with self.assertRaisesRegex(ValueError, "unpaired Unicode surrogate"):
            self.load_raw(r'{"name":"\udfff"}')

    def test_unpaired_surrogate_key_rejected(self):
        with self.assertRaisesRegex(ValueError, "unpaired Unicode surrogate"):
            self.load_raw(r'{"\ud800":"value"}')

    def test_valid_surrogate_pair_accepted(self):
        self.assertEqual(self.load_raw(r'{"symbol":"\ud83d\ude80"}'), {"symbol": "🚀"})

    def test_valid_utf8_non_ascii_accepted(self):
        self.assertEqual(self.load_raw('{"name":"Citadél"}'), {"name": "Citadél"})

    def test_decomposed_unicode_value_rejected(self):
        with self.assertRaisesRegex(ValueError, "non-NFC"):
            self.load_raw('{"name":"e\u0301"}')

    def test_decomposed_unicode_key_rejected(self):
        with self.assertRaisesRegex(ValueError, "non-NFC"):
            self.load_raw('{"e\u0301":"value"}')

    def test_escaped_decomposed_unicode_rejected(self):
        with self.assertRaisesRegex(ValueError, "non-NFC"):
            self.load_raw(r'{"name":"e\u0301"}')

    def test_duplicate_alias_via_unicode_escape_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            self.load_raw(r'{"release_gate":"HOLD","release_\u0067ate":"GO"}')

    def test_nested_duplicate_alias_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            self.load_raw(r'{"edges":[{"authorization":"deny","authoriz\u0061tion":"allow"}]}')

    def test_valid_nfc_escaped_value_accepted(self):
        self.assertEqual(self.load_raw(r'{"name":"Citad\u00e9l"}'),
                         {"name": "Citadél"})

    def test_valid_nested_document(self):
        self.assertEqual(
            self.load_raw('{"release_gate":"HOLD","edges":[{"runtime_enabled":false}]}'),
            {"release_gate": "HOLD", "edges": [{"runtime_enabled": False}]},
        )

    def test_duplicate_top_level_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            self.load_raw('{"release_gate":"HOLD","release_gate":"GO"}')

    def test_duplicate_nested_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            self.load_raw('{"edges":[{"authorization":"deny","authorization":"allow"}]}')

    def test_nan_rejected(self):
        with self.assertRaisesRegex(ValueError, "non-finite"):
            self.load_raw('{"value":NaN}')

    def test_positive_infinity_rejected(self):
        with self.assertRaisesRegex(ValueError, "non-finite"):
            self.load_raw('{"value":Infinity}')

    def test_negative_infinity_rejected(self):
        with self.assertRaisesRegex(ValueError, "non-finite"):
            self.load_raw('{"value":-Infinity}')

    def test_positive_exponent_overflow_rejected(self):
        with self.assertRaisesRegex(ValueError, "non-finite"):
            self.load_raw('{"ratio":1e400}')

    def test_negative_exponent_overflow_rejected(self):
        with self.assertRaisesRegex(ValueError, "non-finite"):
            self.load_raw('{"ratio":-1e400}')

    def test_nested_exponent_overflow_rejected(self):
        with self.assertRaisesRegex(ValueError, "non-finite"):
            self.load_raw('{"edges":[{"ratio":9.99e999}]}')

    def test_finite_exponent_accepted(self):
        self.assertEqual(self.load_raw('{"ratio":1.25e2}'), {"ratio": 125.0})

    def test_truncated_json_rejected(self):
        with self.assertRaises(ValueError):
            self.load_raw('{"release_gate":"HOLD"')

    def test_missing_file_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(OSError):
                load_strict_json(Path(directory) / "missing.json")


if __name__ == "__main__":
    unittest.main()

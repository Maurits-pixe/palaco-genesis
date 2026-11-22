"""Direct regression checks for the shared strict JSON loader."""
import tempfile
import unittest
from pathlib import Path

from tools.strict_contract_json import load_strict_json


class StrictContractJsonTests(unittest.TestCase):
    def load_raw(self, payload):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.json"
            path.write_text(payload, encoding="utf-8")
            return load_strict_json(path)

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

    def test_truncated_json_rejected(self):
        with self.assertRaises(ValueError):
            self.load_raw('{"release_gate":"HOLD"')

    def test_missing_file_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(OSError):
                load_strict_json(Path(directory) / "missing.json")


if __name__ == "__main__":
    unittest.main()

"""Curated raw JSON escape variants must yield the same pinned CJSON digest."""
import json
import tempfile
import unittest
from pathlib import Path

from tools.contract_digest import digest_contract, digest_contract_file
from tools.strict_contract_json import load_strict_json

ROOT = Path(__file__).resolve().parents[1]
VARIANTS = ROOT / "verification" / "contract-digest-v0-raw-variants.json"
VECTORS = ROOT / "verification" / "contract-digest-v0-vectors.json"


class ContractDigestRawVariantTests(unittest.TestCase):
    def test_equivalent_raw_json_variants(self):
        variants = json.loads(VARIANTS.read_text(encoding="utf-8"))
        vectors = json.loads(VECTORS.read_text(encoding="utf-8"))
        self.assertEqual(variants["profile"], vectors["profile"])
        self.assertEqual(len(variants["cases"]), 6)
        by_name = {vector["name"]: vector for vector in vectors["vectors"]}
        for variant in variants["cases"]:
            with self.subTest(case=variant["name"]):
                expected = by_name[variant["reference"]]
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "raw.json"
                    path.write_text(variant["raw"], encoding="utf-8")
                    parsed = load_strict_json(path)
                    self.assertEqual(parsed, expected["value"])
                    self.assertEqual(digest_contract(parsed), expected["sha256"])
                    self.assertEqual(digest_contract_file(path), expected["sha256"])

    def test_duplicate_decoded_key_rejected(self):
        # Different JSON spellings decode to the same key; no last-wins.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ambiguous.json"
            path.write_text(r'{"release_gate":"HOLD","release_\u0067ate":"GO"}',
                            encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                load_strict_json(path)

    def test_invalid_escape_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.json"
            path.write_text(r'{"key":"\x41"}', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_strict_json(path)


if __name__ == "__main__":
    unittest.main()

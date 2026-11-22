"""Shared negative PALACO-CJSON-v0 corpus consumed by Python and Node.js."""
import json
import unittest
from pathlib import Path

from tools.contract_digest import canonical_bytes

CORPUS = Path(__file__).resolve().parents[1] / "verification" / "contract-digest-v0-negative.json"
PATTERNS = {
    "non_integer": "unsupported canonical JSON value type",
    "unsafe_integer": "safe range",
    "non_nfc": "non-NFC",
    "surrogate": "surrogate",
    "depth": "nesting depth",
}


def make_case(case):
    if case["kind"] == "literal":
        return case["value"]
    if case["kind"] == "nested_arrays":
        item = 0
        for _ in range(case["depth"]):
            item = [item]
        return item
    if case["kind"] == "nested_objects":
        item = 0
        for _ in range(case["depth"]):
            item = {"child": item}
        return item
    raise AssertionError("unknown negative vector kind")


class ContractDigestNegativeCorpusTests(unittest.TestCase):
    def test_shared_negative_corpus(self):
        corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        self.assertEqual(corpus["profile"], "PALACO-CJSON-v0")
        self.assertEqual(len(corpus["cases"]), 10)
        for case in corpus["cases"]:
            with self.subTest(case=case["name"]):
                self.assertIn(case["reason"], PATTERNS)
                with self.assertRaisesRegex(ValueError, PATTERNS[case["reason"]]):
                    canonical_bytes(make_case(case))


if __name__ == "__main__":
    unittest.main()

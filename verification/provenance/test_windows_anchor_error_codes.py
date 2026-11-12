"""WNRA-05H executable Python/Node local error-code comparison; no authority."""
import json
from pathlib import Path
import subprocess
import unittest

from windows_test_anchor_raw_bytes import (
    FixtureByteRejected, parse_simulated_request_bytes,
)

HERE = Path(__file__).parent
EXPECTED = {
    "duplicate-key": ("DUPLICATE_KEY", "DUPLICATE_KEY"),
    "nested-duplicate": ("DUPLICATE_KEY", "INVALID_JSON_SCOPE"),
    "float": ("FRACTION_OR_EXPONENT", "NONCANONICAL_TEST_BYTES"),
    "exponent": ("FRACTION_OR_EXPONENT", "NONCANONICAL_TEST_BYTES"),
    "negative-zero": ("NEGATIVE_ZERO", "INVALID_SEQUENCE"),
    "unsafe-number": ("UNSAFE_INTEGER", "INVALID_SEQUENCE"),
    "boolean-sequence": ("INVALID_SEQUENCE_TYPE", "INVALID_SEQUENCE"),
    "null-sequence": ("INVALID_SEQUENCE_TYPE", "INVALID_SEQUENCE"),
    "unknown-field": ("SCHEMA_MISMATCH", "SCHEMA_MISMATCH"),
    "missing-field": ("SCHEMA_MISMATCH", "SCHEMA_MISMATCH"),
    "surrogate": ("INVALID_UNICODE_SCALAR", "INVALID_UNICODE_SCALAR"),
    "unicode-literal": ("NONCANONICAL_TEST_BYTES", "NONCANONICAL_TEST_BYTES"),
    "leading-space": ("NONCANONICAL_TEST_BYTES", "INVALID_JSON_SCOPE"),
    "trailing-newline": ("NONCANONICAL_TEST_BYTES", "NONCANONICAL_TEST_BYTES"),
    "utf8-bom": ("UTF8_BOM", "UTF8_BOM"),
    "invalid-utf8": ("INVALID_UTF8", "INVALID_UTF8"),
    "array-scope": ("SCHEMA_MISMATCH", "INVALID_JSON_SCOPE"),
}
NODE_SCRIPT = r"""
const fs = require('node:fs');
const {parseTestRequest} = require(process.argv[1]);
const hexList = JSON.parse(fs.readFileSync(0, 'utf8'));
const results = hexList.map(hex => {
  try {
    parseTestRequest(Buffer.from(hex, 'hex'));
    return 'ACCEPTED';
  } catch (error) {
    return error.message;
  }
});
process.stdout.write('WNRA05H_CODES=' + JSON.stringify(results) + '\n');
"""


def raw_cases():
    corpus = json.loads(
        (HERE / "WNRA_05F_SHARED_DENY_CORPUS.json").read_text(encoding="utf-8")
    )
    vectors = json.loads(
        (HERE / "WNRA_05A_ANCHOR_VECTORS.json").read_text(encoding="utf-8")
    )["vectors"]
    result = []
    for case in corpus["cases"]:
        if "literal" in case:
            raw = case["literal"].encode("utf-8")
        else:
            source = vectors[case["vector"]]["canonical_json"]
            if "replace" in case:
                old, new = case["replace"]
                if old not in source:
                    raise AssertionError("missing mutation source: " + case["id"])
                source = source.replace(old, new, 1)
            raw = (
                bytes.fromhex(case.get("prefix_hex", ""))
                + case.get("prefix", "").encode("utf-8")
                + source.encode("utf-8")
                + case.get("suffix", "").encode("utf-8")
                + bytes.fromhex(case.get("suffix_hex", ""))
            )
        result.append((case["id"], raw))
    return result


class ExactCodeComparison(unittest.TestCase):
    def test_python_and_node_exact_rejection_codes(self):
        cases = raw_cases()
        self.assertEqual({case_id for case_id, _ in cases}, set(EXPECTED))
        process = subprocess.run(
            ["node", "-e", NODE_SCRIPT,
             str(HERE / "test_windows_anchor_raw_bytes_node.cjs")],
            input=json.dumps([raw.hex() for _, raw in cases]),
            text=True,
            capture_output=True,
            check=False,
            timeout=45,
        )
        self.assertEqual(
            process.returncode, 0,
            msg="Node test process failed: " + process.stderr[-1000:],
        )
        output = [
            line.partition("WNRA05H_CODES=")[2]
            for line in process.stdout.splitlines()
            if line.startswith("WNRA05H_CODES=")
        ]
        self.assertEqual(len(output), 1, msg=process.stdout[-1000:])
        node_codes = json.loads(output[0])
        self.assertEqual(len(node_codes), len(cases))
        for (case_id, raw), node_code in zip(cases, node_codes):
            with self.subTest(case_id=case_id):
                with self.assertRaises(FixtureByteRejected) as error:
                    parse_simulated_request_bytes(raw)
                self.assertEqual(
                    (str(error.exception), node_code), EXPECTED[case_id],
                )
                print(
                    "WNRA05H_CASE " + case_id
                    + " python=" + str(error.exception)
                    + " node=" + node_code
                    + " authorization=DENY"
                )




# WNRA-05M — numeric boundary probes. Local DENY-only fixtures, not protocol canon.
NUMERIC_BOUNDARIES = (
    ("negative-zero", "-0", "NEGATIVE_ZERO", "INVALID_SEQUENCE"),
    ("zero", "0", "INVALID_REQUEST", "INVALID_SEQUENCE"),
    ("negative-one", "-1", "INVALID_REQUEST", "INVALID_SEQUENCE"),
    ("one", "1", "DENY_ONLY", "DENY_ONLY"),
    ("two", "2", "DENY_ONLY", "DENY_ONLY"),
    ("near-max-safe", "9007199254740990", "DENY_ONLY", "DENY_ONLY"),
    ("max-safe", "9007199254740991", "DENY_ONLY", "DENY_ONLY"),
    ("over-max-safe", "9007199254740992", "UNSAFE_INTEGER", "INVALID_SEQUENCE"),
    ("precision-loss", "9007199254740993", "UNSAFE_INTEGER", "INVALID_SEQUENCE"),
    ("negative-unsafe", "-9007199254740992", "UNSAFE_INTEGER", "INVALID_SEQUENCE"),
    ("fraction", "1.0", "FRACTION_OR_EXPONENT", "NONCANONICAL_TEST_BYTES"),
    ("exponent", "1e0", "FRACTION_OR_EXPONENT", "NONCANONICAL_TEST_BYTES"),
    ("boolean", "true", "INVALID_SEQUENCE_TYPE", "INVALID_SEQUENCE"),
    ("null", "null", "INVALID_SEQUENCE_TYPE", "INVALID_SEQUENCE"),
)

NODE_BOUNDARY_SCRIPT = r"""
const fs = require('node:fs');
const {parseTestRequest} = require(process.argv[1]);
const hexList = JSON.parse(fs.readFileSync(0, 'utf8'));
const results = hexList.map(hex => {
  try {
    const result = parseTestRequest(Buffer.from(hex, 'hex'));
    return result.authorization === 'DENY' &&
      result.independent_verification === 'NOT_EXECUTED'
      ? 'DENY_ONLY' : 'UNEXPECTED_AUTHORITY';
  } catch (error) {
    return error.message;
  }
});
process.stdout.write('WNRA05M_BOUNDARIES=' + JSON.stringify(results) + '\n');
"""

class NumericBoundaryComparison(unittest.TestCase):
    def test_cross_language_numeric_boundaries_never_authorize(self):
        original = json.loads(
            (HERE / "WNRA_05A_ANCHOR_VECTORS.json").read_text(encoding="utf-8")
        )["vectors"][0]["canonical_json"]
        self.assertIn('"sequence":1,', original)
        raw_cases = [
            original.replace('"sequence":1,', '"sequence":' + token + ',', 1)
            .encode("utf-8")
            for _, token, _, _ in NUMERIC_BOUNDARIES
        ]
        completed = subprocess.run(
            ["node", "-e", NODE_BOUNDARY_SCRIPT,
             str(HERE / "test_windows_anchor_raw_bytes_node.cjs")],
            input=json.dumps([raw.hex() for raw in raw_cases]),
            text=True, capture_output=True, check=False, timeout=45,
        )
        self.assertEqual(completed.returncode, 0, msg=completed.stderr[-1000:])
        lines = [
            line.split("WNRA05M_BOUNDARIES=", 1)[1]
            for line in completed.stdout.splitlines()
            if line.startswith("WNRA05M_BOUNDARIES=")
        ]
        self.assertEqual(len(lines), 1, msg=completed.stdout[-1000:])
        node_codes = json.loads(lines[0])
        self.assertEqual(len(node_codes), len(NUMERIC_BOUNDARIES))
        for (name, token, expected_python, expected_node), raw, node_code in zip(
            NUMERIC_BOUNDARIES, raw_cases, node_codes
        ):
            with self.subTest(boundary=name):
                try:
                    parsed = parse_simulated_request_bytes(raw)
                except FixtureByteRejected as exc:
                    python_code = str(exc)
                else:
                    self.assertGreater(parsed.sequence, 0)
                    python_code = "DENY_ONLY"  # Successful parse is NOT authorization.
                self.assertEqual(python_code, expected_python)
                self.assertEqual(node_code, expected_node)
                self.assertNotEqual(node_code, "UNEXPECTED_AUTHORITY")
                print(
                    "WNRA05M_CASE " + name + " token=" + token
                    + " python=" + python_code + " node=" + node_code
                    + " authorization=DENY"
                )

if __name__ == "__main__":
    unittest.main()

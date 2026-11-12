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
    "negative-zero": ("NEGATIVE_ZERO", "NEGATIVE_ZERO"),
    "unsafe-number": ("UNSAFE_INTEGER", "UNSAFE_INTEGER"),
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
    ("negative-zero", "-0", "NEGATIVE_ZERO", "NEGATIVE_ZERO"),
    ("zero", "0", "INVALID_REQUEST", "INVALID_SEQUENCE"),
    ("negative-one", "-1", "INVALID_REQUEST", "INVALID_SEQUENCE"),
    ("one", "1", "DENY_ONLY", "DENY_ONLY"),
    ("two", "2", "DENY_ONLY", "DENY_ONLY"),
    ("near-max-safe", "9007199254740990", "DENY_ONLY", "DENY_ONLY"),
    ("max-safe", "9007199254740991", "DENY_ONLY", "DENY_ONLY"),
    ("over-max-safe", "9007199254740992", "UNSAFE_INTEGER", "UNSAFE_INTEGER"),
    ("precision-loss", "9007199254740993", "UNSAFE_INTEGER", "UNSAFE_INTEGER"),
    ("negative-unsafe", "-9007199254740992", "UNSAFE_INTEGER", "UNSAFE_INTEGER"),
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


# WNRA-05O — targeted invalid numeric lexical forms. No public wire canon.
NUMERIC_ADVERSARIAL = (
    ("leading-zero", "01"),
    ("negative-leading-zero", "-01"),
    ("plus-sign", "+1"),
    ("trailing-decimal-point", "1."),
    ("leading-decimal-point", ".1"),
    ("double-sign", "--1"),
    ("digit-separator", "1_0"),
    ("hexadecimal", "0x1"),
    ("positive-exponent", "1e+0"),
    ("huge-exponent", "1e309"),
    ("negative-exponent", "-1e-0"),
    ("fractional-half", "0.5"),
    ("negative-fraction-zero", "-0.0"),
    ("string-number", '"1"'),
    ("nan-literal", "NaN"),
    ("infinity-literal", "Infinity"),
    ("large-integer", "9" * 70),
    ("unicode-digit", "１"),
    ("missing-number", ""),
    ("duplicated-sequence", '1,"sequence":2'),
)
NODE_ADVERSARIAL_SCRIPT = r"""
const fs = require('node:fs');
const {parseTestRequest} = require(process.argv[1]);
const hexList = JSON.parse(fs.readFileSync(0, 'utf8'));
const codes = hexList.map(hex => {
  try {
    const result = parseTestRequest(Buffer.from(hex, 'hex'));
    return result.authorization === 'DENY' &&
      result.independent_verification === 'NOT_EXECUTED'
      ? 'UNEXPECTED_PARSE' : 'UNEXPECTED_AUTHORITY';
  } catch (error) {
    return error.message;
  }
});
process.stdout.write('WNRA05O_REJECTIONS=' + JSON.stringify(codes) + '\n');
"""

class AdversarialNumericComparison(unittest.TestCase):
    def test_cross_language_noncanonical_numeric_forms_reject(self):
        vectors = json.loads(
            (HERE / "WNRA_05A_ANCHOR_VECTORS.json").read_text(encoding="utf-8")
        )["vectors"]
        original = vectors[0]["canonical_json"]
        self.assertIn('"sequence":1,', original)
        raw_cases = [
            original.replace('"sequence":1,', '"sequence":' + token + ',', 1)
            .encode("utf-8") for _, token in NUMERIC_ADVERSARIAL
        ]
        process = subprocess.run(
            ["node", "-e", NODE_ADVERSARIAL_SCRIPT,
             str(HERE / "test_windows_anchor_raw_bytes_node.cjs")],
            input=json.dumps([raw.hex() for raw in raw_cases]),
            text=True, capture_output=True, check=False, timeout=45,
        )
        self.assertEqual(process.returncode, 0, msg=process.stderr[-1000:])
        lines = [
            line.split("WNRA05O_REJECTIONS=", 1)[1]
            for line in process.stdout.splitlines()
            if line.startswith("WNRA05O_REJECTIONS=")
        ]
        self.assertEqual(len(lines), 1, msg=process.stdout[-1000:])
        codes = json.loads(lines[0])
        self.assertEqual(len(codes), len(NUMERIC_ADVERSARIAL))
        for (case_id, _), raw, code in zip(NUMERIC_ADVERSARIAL, raw_cases, codes):
            with self.subTest(case_id=case_id):
                with self.assertRaises(FixtureByteRejected) as reason:
                    parse_simulated_request_bytes(raw)
                self.assertRegex(str(reason.exception), r"^[A-Z][A-Z0-9_]*$")
                self.assertRegex(code, r"^[A-Z][A-Z0-9_]*$")
                self.assertNotIn(code, ("UNEXPECTED_PARSE", "UNEXPECTED_AUTHORITY"))
                print(
                    "WNRA05O_CASE " + case_id
                    + " python=" + str(reason.exception)
                    + " node=" + code + " authorization=DENY"
                )

    def test_three_frozen_canonical_vectors_stay_test_only(self):
        vectors = json.loads(
            (HERE / "WNRA_05A_ANCHOR_VECTORS.json").read_text(encoding="utf-8")
        )["vectors"]
        for vector in vectors:
            with self.subTest(vector=vector["name"]):
                result = parse_simulated_request_bytes(
                    vector["canonical_json"].encode("utf-8")
                )
                self.assertGreater(result.sequence, 0)
        # The existing Node test checks all three positive fixture vectors
        # with authorization=DENY and independent_verification=NOT_EXECUTED.


# WNRA-05P — bounded input and combined-negative fixtures.
# 64 KiB is a LOCAL TEST PROFILE, not a published wire protocol limit.
MAX_05P_BYTES = 64 * 1024
NODE_05P_SCRIPT = r"""
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
process.stdout.write('WNRA05P_CODES=' + JSON.stringify(results) + '\n');
"""

class BoundedInputAndCombinedFailures(unittest.TestCase):
    def test_exact_size_limit_and_compound_malformed_inputs(self):
        original = json.loads(
            (HERE / "WNRA_05A_ANCHOR_VECTORS.json").read_text(encoding="utf-8")
        )["vectors"][0]["canonical_json"]
        self.assertIn("local-test-actor", original)
        stripped = original.replace("local-test-actor", "", 1)
        exact = stripped.replace(
            '"actor_id":""',
            '"actor_id":"' + ("x" * (MAX_05P_BYTES - len(stripped.encode("utf-8")))) + '"',
            1,
        ).encode("utf-8")
        # Replacing the empty actor adds exactly MAX_05P_BYTES - baseline bytes.
        self.assertEqual(len(exact), MAX_05P_BYTES)
        one_over = exact.replace(b'"actor_id":"', b'"actor_id":"x', 1)
        self.assertEqual(len(one_over), MAX_05P_BYTES + 1)
        negative_zero = original.replace('"sequence":1,', '"sequence":-0,', 1)
        oversized_digits = original.replace(
            '"sequence":1,', '"sequence":' + "9" * 5000 + ',', 1
        )
        negative_oversized = original.replace(
            '"sequence":1,', '"sequence":-' + "9" * 5000 + ',', 1
        )
        cases = [
            ("exact-limit-valid-fixture", exact, "DENY_ONLY", "DENY_ONLY"),
            ("one-byte-over", one_over, "REQUEST_TOO_LARGE", "REQUEST_TOO_LARGE"),
            ("oversized-bom", b"\xef\xbb\xbf" + one_over, "REQUEST_TOO_LARGE", "REQUEST_TOO_LARGE"),
            ("oversized-bad-utf8", one_over + b"\xff", "REQUEST_TOO_LARGE", "REQUEST_TOO_LARGE"),
            ("five-thousand-digits", oversized_digits.encode("utf-8"), "UNSAFE_INTEGER", "UNSAFE_INTEGER"),
            ("negative-five-thousand-digits", negative_oversized.encode("utf-8"), "UNSAFE_INTEGER", "UNSAFE_INTEGER"),
            ("bom-and-negative-zero", b"\xef\xbb\xbf" + negative_zero.encode("utf-8"), "UTF8_BOM", "UTF8_BOM"),
            ("bad-utf8-and-negative-zero", negative_zero.encode("utf-8") + b"\xff", "INVALID_UTF8", "INVALID_UTF8"),
            ("duplicate-and-unsafe", original.replace(
                '"sequence":1,', '"sequence":9007199254740993,"sequence":1,', 1
            ).encode("utf-8"), None, None),
            ("nested-and-long-digit", original.replace(
                '"sequence":1,', '"sequence":' + "9" * 5000 + ',"extra":{"a":1,"a":1},', 1
            ).encode("utf-8"), None, None),
        ]
        process = subprocess.run(
            ["node", "-e", NODE_05P_SCRIPT,
             str(HERE / "test_windows_anchor_raw_bytes_node.cjs")],
            input=json.dumps([raw.hex() for _, raw, _, _ in cases]),
            text=True, capture_output=True, check=False, timeout=45,
        )
        self.assertEqual(process.returncode, 0, msg=process.stderr[-1000:])
        lines = [
            line.split("WNRA05P_CODES=", 1)[1]
            for line in process.stdout.splitlines()
            if line.startswith("WNRA05P_CODES=")
        ]
        self.assertEqual(len(lines), 1, msg=process.stdout[-1000:])
        node_results = json.loads(lines[0])
        self.assertEqual(len(node_results), len(cases))
        for (case_id, raw, python_expected, node_expected), node_code in zip(cases, node_results):
            with self.subTest(case_id=case_id):
                if case_id == "exact-limit-valid-fixture":
                    parsed = parse_simulated_request_bytes(raw)
                    self.assertTrue(parsed.actor_id.startswith("x"))
                    python_code = "DENY_ONLY"  # a parse is never authorization
                else:
                    with self.assertRaises(FixtureByteRejected) as exc:
                        parse_simulated_request_bytes(raw)
                    python_code = str(exc.exception)
                    self.assertNotEqual(node_code, "DENY_ONLY")
                self.assertNotEqual(node_code, "UNEXPECTED_AUTHORITY")
                if python_expected is not None:
                    self.assertEqual(python_code, python_expected)
                if node_expected is not None:
                    self.assertEqual(node_code, node_expected)
                print(
                    "WNRA05P_CASE " + case_id
                    + " python=" + python_code
                    + " node=" + node_code + " authorization=DENY"
                )


# WNRA-05Q -- bounded workload observation in the local test profile only.
# A subprocess timeout is a test-harness constraint, not production CPU isolation.
import time

WNRA05Q_SCENARIOS = (
    ("canonical-repeated", "canonical", 16, "DENY_ONLY"),
    ("max-64k-repeated", "max", 16, "DENY_ONLY"),
    ("over-64k-repeated", "over", 16, "REQUEST_TOO_LARGE"),
    ("bom-and-negative-zero-repeated", "bom_zero", 16, "UTF8_BOM"),
    ("long-integer-repeated", "long_integer", 16, "UNSAFE_INTEGER"),
    ("oversized-2m", "two_megabytes", 1, "REQUEST_TOO_LARGE"),
    ("oversized-8m", "eight_megabytes", 1, "REQUEST_TOO_LARGE"),
    ("oversized-invalid-utf8", "oversized_invalid_utf8", 1, "REQUEST_TOO_LARGE"),
    ("oversized-nested-json", "oversized_nested_json", 1, "REQUEST_TOO_LARGE"),
)

NODE_05Q_SCRIPT = r"""
const fs = require('node:fs');
const {performance} = require('node:perf_hooks');
const {parseTestRequest} = require(process.argv[1]);
const spec = JSON.parse(fs.readFileSync(0, 'utf8'));
const original = spec.original;
const base = Buffer.from(original, 'utf8');
const limit = 64 * 1024;
const stripped = original.replace('local-test-actor', '');
const full = stripped.replace(
  '"actor_id":""',
  '"actor_id":"' + 'x'.repeat(limit - Buffer.byteLength(stripped)) + '"'
);
if (Buffer.byteLength(full) !== limit) throw new Error('BAD_BOUNDARY_FIXTURE');
const exact = Buffer.from(full, 'utf8');
function make(mode) {
  switch(mode) {
    case 'canonical': return base;
    case 'max': return exact;
    case 'over': return Buffer.concat([exact, Buffer.from(' ')]);
    case 'bom_zero': return Buffer.concat([
      Buffer.from([0xef, 0xbb, 0xbf]),
      Buffer.from(original.replace('"sequence":1,', '"sequence":-0,'), 'utf8')
    ]);
    case 'long_integer': return Buffer.from(
      original.replace('"sequence":1,', '"sequence":' + '9'.repeat(5000) + ',')
    );
    case 'two_megabytes': return Buffer.alloc(2 * 1024 * 1024, 0x78);
    case 'eight_megabytes': return Buffer.alloc(8 * 1024 * 1024, 0x78);
    case 'oversized_invalid_utf8': return Buffer.concat([
      Buffer.alloc(2 * 1024 * 1024, 0x78), Buffer.from([0xff])
    ]);
    case 'oversized_nested_json': return Buffer.from(
      '{"data":[' + '0,'.repeat(40000) + 'null]}', 'utf8'
    );
    default: throw new Error('BAD_TEST_MODE');
  }
}
const start = performance.now();
const result = [];
for (const [name, mode, repeat, expected] of spec.scenarios) {
  const raw = make(mode);
  const observed = [];
  for (let i = 0; i < repeat; i++) {
    try {
      const parsed = parseTestRequest(raw);
      observed.push(parsed.authorization === 'DENY' &&
        parsed.independent_verification === 'NOT_EXECUTED'
        ? 'DENY_ONLY' : 'UNEXPECTED_AUTHORITY');
    } catch (error) {
      observed.push(error.message);
    }
  }
  result.push({name, size: raw.length, observed});
}
process.stdout.write('WNRA05Q_OBSERVATIONS=' + JSON.stringify({
  cases: result, elapsed_ms: performance.now() - start
}) + '\n');
"""

class BoundedWorkloadObservations(unittest.TestCase):
    def test_cross_runtime_bounded_repeated_workloads(self):
        original = json.loads(
            (HERE / "WNRA_05A_ANCHOR_VECTORS.json").read_text(encoding="utf-8")
        )["vectors"][0]["canonical_json"]
        stripped = original.replace("local-test-actor", "", 1)
        exact = stripped.replace(
            '"actor_id":""',
            '"actor_id":"' + ("x" * (65536 - len(stripped.encode("utf-8")))) + '"',
            1,
        ).encode("utf-8")
        self.assertEqual(len(exact), 65536)
        base = original.encode("utf-8")
        def make(mode):
            if mode == "canonical":
                return base
            if mode == "max":
                return exact
            if mode == "over":
                return exact + b" "
            if mode == "bom_zero":
                return b"\xef\xbb\xbf" + original.replace(
                    '"sequence":1,', '"sequence":-0,', 1
                ).encode("utf-8")
            if mode == "long_integer":
                return original.replace(
                    '"sequence":1,', '"sequence":' + "9" * 5000 + ',', 1
                ).encode("utf-8")
            if mode == "two_megabytes":
                return b"x" * (2 * 1024 * 1024)
            if mode == "eight_megabytes":
                return b"x" * (8 * 1024 * 1024)
            if mode == "oversized_invalid_utf8":
                return b"x" * (2 * 1024 * 1024) + b"\xff"
            if mode == "oversized_nested_json":
                return ('{"data":[' + "0," * 40000 + "null]}").encode("utf-8")
            raise AssertionError("BAD_TEST_MODE")
        start = time.perf_counter()
        python_cases = []
        for name, mode, repeat, expected in WNRA05Q_SCENARIOS:
            raw = make(mode)
            results = []
            for _ in range(repeat):
                try:
                    parsed = parse_simulated_request_bytes(raw)
                    result = "DENY_ONLY" if parsed.sequence > 0 else "UNEXPECTED_STATE"
                except FixtureByteRejected as err:
                    result = str(err)
                results.append(result)
                self.assertEqual(result, expected, msg=name)
            python_cases.append((name, len(raw), results))
        python_ms = (time.perf_counter() - start) * 1000
        process = subprocess.run(
            ["node", "-e", NODE_05Q_SCRIPT,
             str(HERE / "test_windows_anchor_raw_bytes_node.cjs")],
            input=json.dumps({
                "original": original, "scenarios": WNRA05Q_SCENARIOS
            }),
            text=True, capture_output=True, check=False, timeout=25,
        )
        self.assertEqual(process.returncode, 0, msg=process.stderr[-1500:])
        matches = [
            line.split("WNRA05Q_OBSERVATIONS=", 1)[1]
            for line in process.stdout.splitlines()
            if line.startswith("WNRA05Q_OBSERVATIONS=")
        ]
        self.assertEqual(len(matches), 1, msg=process.stdout[-1500:])
        parsed = json.loads(matches[0])
        self.assertEqual(len(parsed["cases"]), len(WNRA05Q_SCENARIOS))
        self.assertGreaterEqual(parsed["elapsed_ms"], 0)
        for (name, size, python_results), node_case, (_, _, repeats, expected) in zip(
            python_cases, parsed["cases"], WNRA05Q_SCENARIOS
        ):
            with self.subTest(case=name):
                self.assertEqual(node_case["name"], name)
                self.assertEqual(node_case["size"], size)
                self.assertEqual(len(node_case["observed"]), repeats)
                self.assertEqual(set(node_case["observed"]), {expected})
                self.assertEqual(set(python_results), {expected})
                print(
                    "WNRA05Q_CASE " + name + " bytes=" + str(size)
                    + " repeats=" + str(repeats)
                    + " python=" + expected + " node=" + expected
                    + " authorization=DENY"
                )
        print(
            "WNRA05Q_DIAGNOSTIC_TIMING python_ms=%.3f node_ms=%.3f"
            % (python_ms, parsed["elapsed_ms"])
        )

if __name__ == "__main__":
    unittest.main()

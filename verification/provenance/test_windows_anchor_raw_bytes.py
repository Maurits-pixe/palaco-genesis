"""WNRA-05D negative raw JSON byte fixtures; test-only, no wire authority."""
import json
from pathlib import Path
import unittest

from windows_test_anchor_raw_bytes import (
    FixtureByteRejected, parse_simulated_request_bytes,
)
from windows_test_anchor_adapter import (
    SimulatedAnchorAdapter, make_simulated_response,
)


VECTOR_PATH = Path(__file__).with_name("WNRA_05A_ANCHOR_VECTORS.json")


class RawAnchorByteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.vectors = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))["vectors"]
        cls.raw = cls.vectors[0]["canonical_json"].encode("utf-8")

    def assert_reject(self, raw: bytes, reason: str) -> None:
        with self.assertRaises(FixtureByteRejected) as captured:
            parse_simulated_request_bytes(raw)
        self.assertEqual(str(captured.exception), reason)

    def test_three_existing_vectors_decode_without_authority(self) -> None:
        for vector in self.vectors:
            with self.subTest(vector=vector["name"]):
                request = parse_simulated_request_bytes(
                    vector["canonical_json"].encode("utf-8")
                )
                self.assertEqual(request.request_id, vector["request"]["request_id"])
                result = SimulatedAnchorAdapter().verify(
                    request, make_simulated_response(request)
                )
                self.assertTrue(result.fixture_valid)
                self.assertEqual(result.authorization, "DENY")
                self.assertEqual(result.independent_verification, "NOT_EXECUTED")

    def test_duplicate_request_id_is_rejected_before_last_wins(self) -> None:
        raw = self.raw.replace(
            b'"request_id":"REQ-001"',
            b'"request_id":"REQ-001","request_id":"CONFLICT"',
        )
        self.assert_reject(raw, "DUPLICATE_KEY")

    def test_duplicate_nested_unknown_key_fails(self) -> None:
        raw = self.raw.replace(
            b'"sequence":1',
            b'"sequence":1,"extra":{"a":1,"a":2}',
        )
        self.assert_reject(raw, "DUPLICATE_KEY")

    def test_numeric_ambiguity_rejected(self) -> None:
        cases = (
            (b"1.0", "FRACTION_OR_EXPONENT"),
            (b"1e0", "FRACTION_OR_EXPONENT"),
            (b"-0", "NEGATIVE_ZERO"),
            (b"9007199254740993", "UNSAFE_INTEGER"),
            (b"true", "INVALID_SEQUENCE_TYPE"),
            (b"null", "INVALID_SEQUENCE_TYPE"),
        )
        for value, reason in cases:
            with self.subTest(value=value):
                self.assert_reject(
                    self.raw.replace(b'"sequence":1', b'"sequence":' + value),
                    reason,
                )

    def test_noncanonical_whitespace_and_order_rejected(self) -> None:
        payload = self.vectors[0]["request"]
        alternatives = (
            json.dumps(payload, sort_keys=True).encode("utf-8"),
            json.dumps(payload, sort_keys=False, separators=(",", ":")).encode("utf-8"),
            b" " + self.raw,
            self.raw + b"\n",
        )
        for raw in alternatives:
            with self.subTest(raw=raw[:30]):
                self.assert_reject(raw, "NONCANONICAL_TEST_BYTES")

    def test_unicode_alternatives_do_not_silently_normalize(self) -> None:
        unicode_raw = self.vectors[1]["canonical_json"].encode("utf-8")
        self.assert_reject(
            unicode_raw.replace(b"\\u00e9\\u00e9", "éé".encode("utf-8")),
            "NONCANONICAL_TEST_BYTES",
        )
        # Combining mark and precomposed character remain distinct inputs.
        combining = self.vectors[1]["request"].copy()
        combining["actor_id"] = "e\u0301e\u0301n-agent"
        canonical = json.dumps(
            combining, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        decoded = parse_simulated_request_bytes(canonical)
        self.assertNotEqual(decoded.actor_id, self.vectors[1]["request"]["actor_id"])

    def test_lone_surrogate_and_bad_utf8_rejected(self) -> None:
        self.assert_reject(
            self.raw.replace(b"local-test-actor", b"\\ud800"),
            "INVALID_UNICODE_SCALAR",
        )
        self.assert_reject(self.raw + b"\xff", "INVALID_UTF8")

    def test_bom_unknown_and_missing_fields_rejected(self) -> None:
        self.assert_reject(b"\xef\xbb\xbf" + self.raw, "UTF8_BOM")
        unknown = self.raw.replace(b'"sequence":1', b'"unknown":1,"sequence":1')
        self.assert_reject(unknown, "SCHEMA_MISMATCH")
        missing = self.raw.replace(b'"sequence":1,', b"")
        self.assert_reject(missing, "SCHEMA_MISMATCH")

    def test_non_json_or_wrong_type_rejected(self) -> None:
        self.assert_reject(b"{", "INVALID_JSON")
        self.assert_reject(b"[]", "SCHEMA_MISMATCH")
        self.assert_reject("string not bytes", "NOT_BYTES")

    def test_shared_wnra05f_negative_corpus_denies_every_case(self) -> None:
        corpus = json.loads(
            Path(__file__).with_name("WNRA_05F_SHARED_DENY_CORPUS.json")
            .read_text(encoding="utf-8")
        )
        self.assertEqual(corpus["profile"], "WNRA-05F-SHARED-NEGATIVE-v0.1")
        self.assertEqual(corpus["expected_authorization"], "DENY")
        for case in corpus["cases"]:
            with self.subTest(case=case["id"]):
                if "literal" in case:
                    raw = case["literal"].encode("utf-8")
                else:
                    source = self.vectors[case["vector"]]["canonical_json"]
                    if "replace" in case:
                        old, new = case["replace"]
                        self.assertIn(old, source)
                        source = source.replace(old, new, 1)
                    raw = source.encode("utf-8")
                    raw = bytes.fromhex(case.get("prefix_hex", "")) + (
                        case.get("prefix", "").encode("utf-8") + raw
                        + case.get("suffix", "").encode("utf-8")
                    ) + bytes.fromhex(case.get("suffix_hex", ""))
                with self.assertRaises(FixtureByteRejected):
                    parse_simulated_request_bytes(raw)


if __name__ == "__main__":
    unittest.main()

"""WNRA-05A fixed, independently recalculated Python serialization vectors.

These are DERIVED TEST FIXTURES only, not a governed wire format or signature.
"""
import hashlib
import json
from pathlib import Path
import unittest

from windows_test_anchor_adapter import (
    AnchorRequest, SimulatedAnchorAdapter, make_simulated_response,
)


FIXTURE = Path(__file__).with_name("WNRA_05A_ANCHOR_VECTORS.json")


class AnchorCanonicalVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_all_fixed_utf8_bytes_and_sha256(self) -> None:
        self.assertEqual(
            self.document["classification"],
            "DERIVED_TEST_VECTOR_NOT_PROTOCOL_CANON",
        )
        self.assertEqual(len(self.document["vectors"]), 3)
        for vector in self.document["vectors"]:
            with self.subTest(vector=vector["name"]):
                payload = vector["request"]
                canonical = json.dumps(
                    payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
                )
                self.assertEqual(canonical, vector["canonical_json"])
                self.assertEqual(
                    hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
                    vector["sha256"],
                )
                self.assertTrue(canonical.isascii())
                req = AnchorRequest(**payload)
                response = make_simulated_response(req)
                self.assertEqual(response.anchor_digest, vector["sha256"])
                self.assertEqual(
                    response.signature,
                    "SIMULATED-NOT-A-SIGNATURE:" + vector["sha256"],
                )
                observation = SimulatedAnchorAdapter().verify(req, response)
                self.assertTrue(observation.fixture_valid)
                self.assertEqual(observation.authorization, "DENY")
                self.assertEqual(observation.independent_verification, "NOT_EXECUTED")

    def test_object_key_order_does_not_change_canonical_bytes(self) -> None:
        for vector in self.document["vectors"]:
            with self.subTest(vector=vector["name"]):
                reversed_order = dict(reversed(list(vector["request"].items())))
                self.assertEqual(
                    json.dumps(reversed_order, sort_keys=True, separators=(",", ":")),
                    vector["canonical_json"],
                )

    def test_whitespace_and_unescaped_unicode_are_not_same_bytes(self) -> None:
        vector = next(
            v for v in self.document["vectors"] if v["name"] == "unicode_actor"
        )
        payload = vector["request"]
        alternatives = (
            json.dumps(payload, sort_keys=True),
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
        )
        for alternative in alternatives:
            self.assertNotEqual(alternative.encode("utf-8"), vector["canonical_json"].encode("utf-8"))
            self.assertNotEqual(
                hashlib.sha256(alternative.encode("utf-8")).hexdigest(),
                vector["sha256"],
            )

    def test_changed_record_digest_changes_bound_digest(self) -> None:
        vectors = {v["name"]: v for v in self.document["vectors"]}
        self.assertNotEqual(vectors["genesis"]["sha256"], vectors["different_record"]["sha256"])
        self.assertEqual(
            vectors["genesis"]["request"]["request_id"],
            vectors["different_record"]["request"]["request_id"],
        )

    def test_substituted_expected_hash_is_detected(self) -> None:
        vector = self.document["vectors"][0]
        self.assertNotEqual(
            hashlib.sha256(vector["canonical_json"].encode("utf-8")).hexdigest(),
            "0" * 64,
        )


if __name__ == "__main__":
    unittest.main()

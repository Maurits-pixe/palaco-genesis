"""Pinned PALACO-CJSON-v0 byte and digest vectors; no authority granted."""
import hashlib
import json
import unittest
from pathlib import Path

from tools.contract_digest import DOMAIN, canonical_bytes, digest_contract

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "verification" / "contract-digest-v0-vectors.json"


class ContractDigestVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads(VECTORS.read_text(encoding="utf-8"))

    def test_profile_and_domain(self):
        self.assertEqual(self.fixture["profile"], "PALACO-CJSON-v0")
        self.assertEqual(DOMAIN.hex(), self.fixture["domain_hex"])
        self.assertGreaterEqual(len(self.fixture["vectors"]), 5)

    def test_all_pinned_vectors(self):
        for vector in self.fixture["vectors"]:
            with self.subTest(vector=vector["name"]):
                canonical = canonical_bytes(vector["value"])
                self.assertEqual(canonical.hex(), vector["canonical_hex"])
                self.assertEqual(digest_contract(vector["value"]), vector["sha256"])
                # Independent recheck of the explicit length-bound digest preimage.
                preimage = DOMAIN + len(canonical).to_bytes(8, "big") + canonical
                self.assertEqual(hashlib.sha256(preimage).hexdigest(), vector["sha256"])

    def test_each_digest_is_distinct(self):
        values = [vector["sha256"] for vector in self.fixture["vectors"]]
        self.assertEqual(len(values), len(set(values)))

    def test_reordered_object_preserves_vector(self):
        vector = next(v for v in self.fixture["vectors"] if v["name"] == "nested_keys")
        different_order = {"a": {"a": None, "b": True}, "z": 1}
        self.assertEqual(digest_contract(different_order), vector["sha256"])


if __name__ == "__main__":
    unittest.main()

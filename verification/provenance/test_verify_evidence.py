"""Tamper rejection tests for offline evidence verification."""

import hashlib
import json
import unittest

from generate_sbom import canonical, generate
from verify_evidence import verify


COMMIT = "b" * 40
METADATA = {"packages": [{"id": "root", "name": "root", "version": "1.0.0"}], "workspace_members": ["root"], "resolve": {"nodes": [{"id": "root", "dependencies": []}]}}


def sample():
    sbom = canonical(generate(METADATA, COMMIT, 0))
    metadata = canonical(METADATA)
    evidence = canonical({
        "schema": "palaco-unsigned-sbom-evidence-v0.1",
        "commit": COMMIT,
        "sbom_sha256": hashlib.sha256(sbom).hexdigest(),
        "metadata_sha256": hashlib.sha256(metadata).hexdigest(),
        "signed": False,
        "release_authorized": False,
    })
    return sbom, evidence, metadata


class VerifyEvidenceTests(unittest.TestCase):
    def test_valid_unsigned_candidate(self):
        sbom, evidence, metadata = sample()
        self.assertTrue(verify(sbom, evidence, COMMIT, metadata))

    def test_modified_sbom_or_wrong_commit_rejected(self):
        sbom, evidence, metadata = sample()
        with self.assertRaises(ValueError):
            verify(sbom + b" ", evidence, COMMIT, metadata)
        with self.assertRaises(ValueError):
            verify(sbom, evidence, "c" * 40, metadata)

    def test_false_authority_claim_rejected(self):
        sbom, evidence, metadata = sample()
        altered = json.loads(evidence)
        altered["signed"] = True
        with self.assertRaises(ValueError):
            verify(sbom, canonical(altered), COMMIT, metadata)

    def test_rehashed_forged_inventory_rejected(self):
        sbom, evidence, metadata = sample()
        forged = json.loads(sbom)
        forged["packages"][0]["versionInfo"] = "999.0.0"
        altered_sbom = canonical(forged)
        altered_evidence = json.loads(evidence)
        altered_evidence["sbom_sha256"] = hashlib.sha256(altered_sbom).hexdigest()
        with self.assertRaisesRegex(ValueError, "reconstruction"):
            verify(altered_sbom, canonical(altered_evidence), COMMIT, metadata)

    def test_rehashed_removed_dependency_rejected(self):
        sbom, evidence, metadata = sample()
        forged = json.loads(sbom)
        forged["relationships"] = []
        altered_sbom = canonical(forged)
        altered_evidence = json.loads(evidence)
        altered_evidence["sbom_sha256"] = hashlib.sha256(altered_sbom).hexdigest()
        with self.assertRaisesRegex(ValueError, "reconstruction"):
            verify(altered_sbom, canonical(altered_evidence), COMMIT, metadata)

    def test_duplicate_json_keys_fail_closed_even_with_matching_digests(self):
        sbom, evidence, metadata = sample()
        duplicate_evidence = evidence.rstrip()[:-1] + b',"signed":false}'
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            verify(sbom, duplicate_evidence, COMMIT, metadata)

        duplicate_sbom = sbom.rstrip()[:-1] + b',"SPDXID":"SPDXRef-DOCUMENT"}'
        modified_evidence = json.loads(evidence)
        modified_evidence["sbom_sha256"] = hashlib.sha256(duplicate_sbom).hexdigest()
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            verify(duplicate_sbom, canonical(modified_evidence), COMMIT, metadata)

        duplicate_metadata = metadata.rstrip()[:-1] + b',"workspace_members":["root"]}'
        modified_evidence = json.loads(evidence)
        modified_evidence["metadata_sha256"] = hashlib.sha256(duplicate_metadata).hexdigest()
        with self.assertRaisesRegex(ValueError, "invalid source metadata"):
            verify(sbom, canonical(modified_evidence), COMMIT, duplicate_metadata)

    def test_non_finite_evidence_value_rejected(self):
        sbom, evidence, metadata = sample()
        invalid_evidence = evidence.rstrip()[:-1] + b',"untrusted":NaN}'
        with self.assertRaisesRegex(ValueError, "non-finite JSON"):
            verify(sbom, invalid_evidence, COMMIT, metadata)


if __name__ == "__main__":
    unittest.main()


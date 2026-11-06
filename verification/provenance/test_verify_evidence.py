"""Tamper rejection tests for offline evidence verification."""

import hashlib
import json
import unittest

from generate_sbom import canonical, generate
from verify_evidence import verify


COMMIT = "b" * 40
METADATA = {"packages": [{"id": "root", "name": "root", "version": "1.0.0"}], "workspace_members": ["root"]}


def sample():
    sbom = canonical(generate(METADATA, COMMIT, 0))
    evidence = canonical({
        "schema": "palaco-unsigned-sbom-evidence-v0.1",
        "commit": COMMIT,
        "sbom_sha256": hashlib.sha256(sbom).hexdigest(),
        "signed": False,
        "release_authorized": False,
    })
    return sbom, evidence


class VerifyEvidenceTests(unittest.TestCase):
    def test_valid_unsigned_candidate(self):
        self.assertTrue(verify(*sample(), COMMIT))

    def test_modified_sbom_or_wrong_commit_rejected(self):
        sbom, evidence = sample()
        with self.assertRaises(ValueError):
            verify(sbom + b" ", evidence, COMMIT)
        with self.assertRaises(ValueError):
            verify(sbom, evidence, "c" * 40)

    def test_false_authority_claim_rejected(self):
        sbom, evidence = sample()
        altered = json.loads(evidence)
        altered["signed"] = True
        with self.assertRaises(ValueError):
            verify(sbom, canonical(altered), COMMIT)


if __name__ == "__main__":
    unittest.main()

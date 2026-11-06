"""Negative and positive downloaded-artifact checks (no network required)."""

import hashlib
import io
import unittest
import warnings
import zipfile

from generate_sbom import canonical, generate
from verify_artifact import verify_artifact


COMMIT = "d" * 40
METADATA = {"packages": [{"id": "root", "name": "root", "version": "1.0.0"}], "workspace_members": ["root"]}


def archive_bytes(extra=None):
    metadata = canonical(METADATA)
    sbom = canonical(generate(METADATA, COMMIT, 0))
    evidence = canonical({
        "schema": "palaco-unsigned-sbom-evidence-v0.1",
        "commit": COMMIT,
        "metadata_sha256": hashlib.sha256(metadata).hexdigest(),
        "sbom_sha256": hashlib.sha256(sbom).hexdigest(),
        "signed": False,
        "release_authorized": False,
    })
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as result:
        for name, value in {
            "sbom.spdx.json": sbom,
            "evidence.json": evidence,
            "cargo-metadata.json": metadata,
            **(extra or {}),
        }.items():
            result.writestr(name, value)
    return output.getvalue()


class ArtifactTests(unittest.TestCase):
    def test_valid_artifact(self):
        data = archive_bytes()
        self.assertTrue(verify_artifact(data, hashlib.sha256(data).hexdigest(), COMMIT))

    def test_wrong_archive_digest_or_commit_rejected(self):
        data = archive_bytes()
        with self.assertRaisesRegex(ValueError, "archive SHA-256 mismatch"):
            verify_artifact(data, "0" * 64, COMMIT)
        with self.assertRaisesRegex(ValueError, "commit mismatch"):
            verify_artifact(data, hashlib.sha256(data).hexdigest(), "e" * 40)

    def test_unexpected_entry_and_duplicate_rejected(self):
        data = archive_bytes({"../note": b"bad"})
        with self.assertRaisesRegex(ValueError, "unexpected or duplicate"):
            verify_artifact(data, hashlib.sha256(data).hexdigest(), COMMIT)
        duplicate = io.BytesIO(archive_bytes())
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(duplicate, "a") as result:
                result.writestr("evidence.json", b"bad")
        data = duplicate.getvalue()
        with self.assertRaisesRegex(ValueError, "unexpected or duplicate"):
            verify_artifact(data, hashlib.sha256(data).hexdigest(), COMMIT)

    def test_rehashed_inconsistent_metadata_rejected(self):
        data = archive_bytes({"cargo-metadata.json": canonical({"packages": [{"id": "evil"}]})})
        with self.assertRaises(ValueError):
            verify_artifact(data, hashlib.sha256(data).hexdigest(), COMMIT)


if __name__ == "__main__":
    unittest.main()

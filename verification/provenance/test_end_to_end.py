"""End-to-end offline proof of unsigned Cargo SBOM generation and verification."""

import hashlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from generate_sbom import canonical
from verify_artifact import verify_artifact


COMMIT = "f" * 40
HERE = Path(__file__).resolve().parent
METADATA = {
    "format_version": 1,
    "packages": [
        {"id": "workspace-root", "name": "root", "version": "0.1.0", "license": "MIT"},
        {"id": "registry-dep", "name": "dependency", "version": "2.3.4", "license": "Apache-2.0"},
    ],
    "workspace_members": ["workspace-root"],
    "resolve": {
        "root": "workspace-root",
        "nodes": [
            {"id": "workspace-root", "dependencies": ["registry-dep"],
             "deps": [{"name": "renamed_dep", "pkg": "registry-dep", "dep_kinds": [{"kind": None, "target": None}]}]},
            {"id": "registry-dep", "dependencies": [], "deps": []},
        ],
    },
}


def archive_of(files):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(files):
            archive.writestr(name, files[name])
    return output.getvalue()


class EndToEndTests(unittest.TestCase):
    def test_cli_generation_zip_verification_and_tamper_rejection(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            metadata_path = directory / "cargo-metadata.json"
            output = directory / "output"
            metadata_path.write_bytes(canonical(METADATA))
            subprocess.run([
                sys.executable, str(HERE / "generate_sbom.py"),
                "--metadata", str(metadata_path), "--commit", COMMIT,
                "--source-epoch", "0", "--output-dir", str(output),
            ], check=True, capture_output=True)
            subprocess.run([
                sys.executable, str(HERE / "verify_evidence.py"),
                "--output-dir", str(output), "--commit", COMMIT,
                "--metadata", str(metadata_path),
            ], check=True, capture_output=True)
            files = {
                "cargo-metadata.json": metadata_path.read_bytes(),
                "sbom.spdx.json": (output / "sbom.spdx.json").read_bytes(),
                "evidence.json": (output / "evidence.json").read_bytes(),
            }
            archive = archive_of(files)
            self.assertTrue(verify_artifact(archive, hashlib.sha256(archive).hexdigest(), COMMIT))

            # An attacker can recalculate archive and manifest digests, but
            # cannot forge consistency with the unchanged SPDX inventory.
            modified = dict(files)
            poisoned = json.loads(files["cargo-metadata.json"])
            poisoned["packages"][1]["version"] = "999.0.0"
            modified["cargo-metadata.json"] = canonical(poisoned)
            manifest = json.loads(files["evidence.json"])
            manifest["metadata_sha256"] = hashlib.sha256(modified["cargo-metadata.json"]).hexdigest()
            modified["evidence.json"] = canonical(manifest)
            forged = archive_of(modified)
            with self.assertRaisesRegex(ValueError, "reconstruction"):
                verify_artifact(forged, hashlib.sha256(forged).hexdigest(), COMMIT)


if __name__ == "__main__":
    unittest.main()

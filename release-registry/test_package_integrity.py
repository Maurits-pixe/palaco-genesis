"""Negative controls for the read-only PALACO offline package verifier."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from package_integrity import IntegrityError, verify_package, SCHEMA


class PackageIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "asset.txt").write_bytes(b"palaco")
        self.entries = [{"path": "asset.txt", "sha256": hashlib.sha256(b"palaco").hexdigest()}]
        self.save()

    def save(self):
        (self.root / "package-integrity.json").write_text(
            json.dumps({"schema": SCHEMA, "files": self.entries}), encoding="utf-8")

    def rejects(self):
        with self.assertRaises(IntegrityError):
            verify_package(self.root)

    def test_valid(self):
        self.assertEqual(verify_package(self.root), ("asset.txt",))

    def test_modified_bytes(self):
        (self.root / "asset.txt").write_bytes(b"changed")
        self.rejects()

    def test_parent_traversal(self):
        self.entries[0]["path"] = "../asset.txt"
        self.save()
        self.rejects()

    def test_duplicate_entry(self):
        self.entries.append(dict(self.entries[0]))
        self.save()
        self.rejects()

    def test_unknown_field(self):
        data = {"schema": SCHEMA, "files": self.entries, "authorized": True}
        (self.root / "package-integrity.json").write_text(json.dumps(data))
        self.rejects()

    def test_missing_file(self):
        (self.root / "asset.txt").unlink()
        self.rejects()

    def test_uppercase_digest(self):
        self.entries[0]["sha256"] = self.entries[0]["sha256"].upper()
        self.save()
        self.rejects()

    def test_symlink(self):
        (self.root / "asset.txt").unlink()
        outside = self.root.parent / (self.root.name + ".outside")
        outside.write_bytes(b"palaco")
        self.addCleanup(lambda: outside.unlink(missing_ok=True))
        try:
            (self.root / "asset.txt").symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        self.rejects()


if __name__ == "__main__":
    unittest.main()

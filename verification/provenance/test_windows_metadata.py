"""Windows-native metadata handle contract tests (never mocked on Windows)."""

import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from generate_sbom import read_bounded_metadata


@unittest.skipUnless(os.name == "nt", "Windows-native checks require Windows")
class WindowsMetadataTests(unittest.TestCase):
    def test_native_regular_and_size_boundary(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "metadata.json"
            path.write_bytes(b"12345678")
            with patch("generate_sbom.MAX_METADATA_BYTES", 8):
                self.assertEqual(read_bounded_metadata(path), b"12345678")
            with patch("generate_sbom.MAX_METADATA_BYTES", 7):
                with self.assertRaisesRegex(ValueError, "oversized"):
                    read_bounded_metadata(path)

    def test_native_directory_denied(self):
        with TemporaryDirectory() as directory:
            with self.assertRaises((OSError, ValueError)):
                read_bounded_metadata(Path(directory))

    def test_native_final_symlink_denied(self):
        with TemporaryDirectory() as directory:
            target = Path(directory) / "target.json"
            link = Path(directory) / "link.json"
            target.write_bytes(b"secret")
            try:
                link.symlink_to(target)
            except OSError as exc:
                self.fail(f"Windows symlink test setup required: {exc}")
            with self.assertRaises((OSError, ValueError)):
                read_bounded_metadata(link)

    def test_native_open_error_denied(self):
        with TemporaryDirectory() as directory:
            with self.assertRaises(OSError):
                read_bounded_metadata(Path(directory) / "absent.json")

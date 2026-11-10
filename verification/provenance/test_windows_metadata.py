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

    def test_native_path_replaced_after_open_reads_original_handle(self):
        """A deterministic rename during inspection must not redirect the bytes."""
        from windows_metadata import _GET_INFO

        with TemporaryDirectory() as directory:
            path = Path(directory) / "metadata.json"
            moved = Path(directory) / "original.json"
            path.write_bytes(b"original")
            inspected = []

            def replace_during_inspection(*args):
                result = _GET_INFO(*args)
                if not inspected:
                    inspected.append(True)
                    os.replace(path, moved)
                    path.write_bytes(b"substitute")
                return result

            with patch("windows_metadata._GET_INFO", side_effect=replace_during_inspection):
                self.assertEqual(read_bounded_metadata(path), b"original")
            self.assertEqual(path.read_bytes(), b"substitute")
            self.assertEqual(moved.read_bytes(), b"original")

    def test_native_reparse_rejection_closes_original_handle(self):
        """A final symlink is denied and the native handle is closed."""
        import windows_metadata

        with TemporaryDirectory() as directory:
            target = Path(directory) / "target.json"
            link = Path(directory) / "link.json"
            target.write_bytes(b"secret")
            link.symlink_to(target)
            native_close = windows_metadata._CLOSE
            closed = []

            def tracking_close(handle):
                closed.append(handle)
                return native_close(handle)

            with patch("windows_metadata._CLOSE", side_effect=tracking_close):
                with self.assertRaises((OSError, ValueError)):
                    read_bounded_metadata(link)
            self.assertEqual(len(closed), 1)

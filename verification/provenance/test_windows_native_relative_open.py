"""Native Windows-only experimental fixture tests; no production authorization."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from windows_build_root_test_adapter import BuildRootTestAdapter

if os.name == "nt":
    from windows_native_relative_test_open import read_fixture_metadata_relative


@unittest.skipUnless(os.name == "nt", "native Windows test opener requires Windows")
class WindowsNativeRelativeFixtureTests(unittest.TestCase):
    def test_valid_root_relative_file(self):
        with BuildRootTestAdapter() as fixture:
            (fixture.root / "meta.json").write_bytes(b'{"safe":true}')
            self.assertEqual(read_fixture_metadata_relative(fixture, "meta.json"),
                             b'{"safe":true}')

    def test_reject_parent_and_absolute_path_before_open(self):
        with BuildRootTestAdapter() as fixture:
            for name in (r"..\\outside.json", "../outside.json", r"C:\\outside.json",
                         r"subdir\\meta.json", "meta.json:ads"):
                with self.subTest(name=name):
                    with self.assertRaises(ValueError):
                        read_fixture_metadata_relative(fixture, name)

    def test_reject_root_handle_lifetime_and_root_type(self):
        with BuildRootTestAdapter() as fixture:
            pass
        with self.assertRaises(RuntimeError):
            read_fixture_metadata_relative(fixture, "meta.json")
        with self.assertRaises(TypeError):
            read_fixture_metadata_relative(Path("."), "meta.json")

    def test_regular_file_swap_after_open_is_not_path_reread(self):
        # Only checks that a prior read returns the original bytes; a real
        # deterministic in-open swap still needs a separate synchronized hook.
        with BuildRootTestAdapter() as fixture:
            path = fixture.root / "meta.json"
            path.write_bytes(b"before")
            self.assertEqual(read_fixture_metadata_relative(fixture, "meta.json"), b"before")
            path.write_bytes(b"after")
            self.assertEqual(read_fixture_metadata_relative(fixture, "meta.json"), b"after")

    def test_final_symlink_or_junction_rejected(self):
        with BuildRootTestAdapter() as fixture, tempfile.TemporaryDirectory() as outside:
            outside_path = Path(outside)
            (outside_path / "sentinel.json").write_bytes(b"OUTSIDE")
            # A directory junction with a *basename* is still a directory,
            # which the native FILE_NON_DIRECTORY_FILE gate must reject.
            junction = fixture.root / "jump"
            result = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(junction), str(outside_path)],
                capture_output=True, text=True, check=False, timeout=15,
            )
            if result.returncode != 0:
                self.skipTest("Windows junction creation unavailable")
            with self.assertRaises((OSError, ValueError)):
                read_fixture_metadata_relative(fixture, "jump")
            with self.assertRaises(ValueError):
                read_fixture_metadata_relative(fixture, r"jump\\sentinel.json")

    def test_missing_name_does_not_fallback_to_path(self):
        with BuildRootTestAdapter() as fixture:
            with self.assertRaises(OSError):
                read_fixture_metadata_relative(fixture, "missing.json")


if __name__ == "__main__":
    unittest.main()

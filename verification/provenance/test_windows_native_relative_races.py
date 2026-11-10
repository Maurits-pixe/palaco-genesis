"""Deterministic Windows race fixtures for the test-only NT root-relative opener.

These are scoped to disposable build roots. They do not authorize deployment
or prove behavior for roots supplied by untrusted callers.
"""

import os
import shutil
import unittest
from unittest import mock

from windows_build_root_test_adapter import BuildRootTestAdapter

if os.name == "nt":
    import windows_native_relative_test_open as native


@unittest.skipUnless(os.name == "nt", "requires Windows NT handle-relative open")
class RootRelativeRaceTests(unittest.TestCase):
    def test_child_path_replaced_between_nt_open_and_handle_validation(self):
        with BuildRootTestAdapter() as fixture:
            original = fixture.root / "metadata.json"
            moved = fixture.root / "held-original.json"
            original.write_bytes(b"ORIGINAL")
            real_nt_open = native._NT_CREATE
            observed = []

            def open_then_swap(*args):
                result = real_nt_open(*args)
                if result >= 0:
                    os.replace(original, moved)
                    original.write_bytes(b"ATTACKER")
                    observed.append(True)
                return result

            with mock.patch.object(native, "_NT_CREATE", side_effect=open_then_swap):
                data = native.read_fixture_metadata_relative(fixture, "metadata.json")
            self.assertEqual(observed, [True])
            self.assertEqual(data, b"ORIGINAL")
            self.assertEqual(original.read_bytes(), b"ATTACKER")

    def test_root_path_replaced_after_root_handle_acquisition(self):
        with BuildRootTestAdapter() as fixture:
            original_root = fixture.root
            moved_root = original_root.with_name(original_root.name + "-held")
            (original_root / "metadata.json").write_bytes(b"ORIGINAL_ROOT")
            real_nt_open = native._NT_CREATE
            observed = []
            try:
                def swap_root_before_relative_open(*args):
                    original_root.rename(moved_root)
                    original_root.mkdir()
                    (original_root / "metadata.json").write_bytes(b"ATTACKER_ROOT")
                    observed.append(True)
                    return real_nt_open(*args)

                with mock.patch.object(native, "_NT_CREATE",
                                       side_effect=swap_root_before_relative_open):
                    data = native.read_fixture_metadata_relative(fixture, "metadata.json")
                self.assertEqual(observed, [True])
                self.assertEqual(data, b"ORIGINAL_ROOT")
                self.assertEqual((original_root / "metadata.json").read_bytes(),
                                 b"ATTACKER_ROOT")
            finally:
                # Restore the fixture-owned path for TemporaryDirectory cleanup.
                if moved_root.exists():
                    if original_root.exists():
                        shutil.rmtree(original_root)
                    moved_root.rename(original_root)


if __name__ == "__main__":
    unittest.main()

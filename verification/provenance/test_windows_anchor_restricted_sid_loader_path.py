"""WNRA-06G: read-only Windows path and supplementary loader-file probes.

This probes explicit CreateFileW opens under restricted impersonation, not
the failed worker's own loader operations. No ACL/audit policy changes.
"""
import os
import pathlib
import sys
import unittest

from test_windows_anchor_restricted_sid_object_open import (
    RestrictedSidObjectOpenTests, FILE_ATTRIBUTE_NORMAL,
)
from test_windows_anchor_restricted_token import LOW_INTEGRITY_RID

FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_TRAVERSE = 0x0020
FILE_READ_ATTRIBUTES = 0x0080
FILE_GENERIC_READ = 0x00120089
FILE_GENERIC_EXECUTE = 0x001200A0


@unittest.skipUnless(sys.platform == "win32", "Windows path access required")
class RestrictedSidLoaderPathTests(unittest.TestCase):
    def setUp(self):
        self.probe = RestrictedSidObjectOpenTests(
            "test_actual_read_and_execute_opens_match_recorded_dacl_probes"
        )
        self.probe.setUp()
        self.fx = self.probe.fx

    def test_directory_and_supplemental_loader_file_access(self):
        system_root = pathlib.Path(os.environ.get("SystemRoot", r"C:\Windows"))
        python_directory = pathlib.Path(sys.executable).parent
        directories = {
            "windows_root": system_root,
            "system32": system_root / "System32",
            "python_directory": python_directory,
        }
        files = {
            "kernelbase": system_root / "System32" / "kernelbase.dll",
            "ucrtbase": system_root / "System32" / "ucrtbase.dll",
        }
        for name, directory in directories.items():
            self.assertTrue(directory.is_dir(), "missing directory: " + name)
        for name, path in files.items():
            self.assertTrue(path.is_file(), "missing supplemental DLL: " + name)

        source = self.fx._source()
        try:
            for variant in ("user", "builtin_users"):
                token = None
                try:
                    token = self.probe.fixture._token(source, variant)
                    self.fx.token_fixture._lower_integrity(token)
                    observed = self.fx.audit._observed(token)
                    self.assertEqual(observed["integrity_rid"], LOW_INTEGRITY_RID)
                    self.assertEqual(observed["restricted"], 1)
                    for name, path in directories.items():
                        for operation, desired in (
                            ("attributes", FILE_READ_ATTRIBUTES),
                            ("traverse", FILE_TRAVERSE),
                        ):
                            opened, code = self.probe._object_open(
                                token, path, desired,
                                FILE_FLAG_BACKUP_SEMANTICS,
                            )
                            if not opened:
                                self.assertNotEqual(code, 0)
                            print(
                                "WNRA06G_PATH variant=" + variant
                                + " resource=" + name
                                + " kind=directory operation=" + operation
                                + " opened=" + str(opened).lower()
                                + " winerror=" + str(code)
                                + " actual_open=true authorization=DENY"
                            )
                    for name, path in files.items():
                        for operation, desired in (
                            ("read", FILE_GENERIC_READ),
                            ("execute", FILE_GENERIC_EXECUTE),
                        ):
                            opened, code = self.probe._object_open(
                                token, path, desired, FILE_ATTRIBUTE_NORMAL,
                            )
                            if not opened:
                                self.assertNotEqual(code, 0)
                            print(
                                "WNRA06G_PATH variant=" + variant
                                + " resource=" + name
                                + " kind=file operation=" + operation
                                + " opened=" + str(opened).lower()
                                + " winerror=" + str(code)
                                + " actual_open=true authorization=DENY"
                            )
                finally:
                    if token:
                        self.fx.fx._close(token)
        finally:
            self.fx.fx._close(source)


if __name__ == "__main__":
    unittest.main()

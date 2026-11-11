"""WNRA-04X: native filesystem identity regressions, no custody authority."""
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from windows_test_pin_custody_model import CustodyDenied, authorization_from_test_result
from windows_test_custody_file_identity import (
    observe_local_identity, require_same_local_identity,
)


class LocalIdentityTests(unittest.TestCase):
    def test_unchanged_file_matches_and_missing_fails_closed(self):
        with TemporaryDirectory() as root:
            path = Path(root) / "custody.sqlite3"
            path.write_bytes(b"test-only")
            expected = observe_local_identity(str(path))
            require_same_local_identity(str(path), expected)
            path.unlink()
            with self.assertRaises(CustodyDenied):
                require_same_local_identity(str(path), expected)
            self.assertEqual("DENY", authorization_from_test_result(True))

    def test_equal_content_replacement_has_different_file_identity(self):
        with TemporaryDirectory() as root:
            active = Path(root) / "custody.sqlite3"
            other = Path(root) / "new.sqlite3"
            active.write_bytes(b"identical bytes")
            expected = observe_local_identity(str(active))
            other.write_bytes(active.read_bytes())
            os.replace(other, active)
            self.assertEqual(b"identical bytes", active.read_bytes())
            with self.assertRaises(CustodyDenied):
                require_same_local_identity(str(active), expected)

    def test_unusable_expected_identity_is_denied(self):
        with TemporaryDirectory() as root:
            path = Path(root) / "custody.sqlite3"
            path.write_bytes(b"local fixture")
            with self.assertRaises(CustodyDenied):
                require_same_local_identity(str(path), None)


if __name__ == "__main__":
    unittest.main()

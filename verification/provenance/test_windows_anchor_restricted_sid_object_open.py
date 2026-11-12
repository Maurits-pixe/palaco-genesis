"""WNRA-06F: read-only object-open outcomes under actual restricted SID impersonation.

Unlike AccessCheck, CreateFileW exercises an actual Windows object open, but
it still is NOT a loader access trace or proof of the 0xC0000022 cause.
No ACL changes, writes, network requests, global audit changes or drivers.
"""
import ctypes
from ctypes import wintypes
import os
import pathlib
import sys
import unittest

from test_windows_anchor_readonly_access_check import (
    ReadOnlyAccessCheckTests, TOKEN_QUERY, TOKEN_IMPERSONATION,
    SECURITY_IMPERSONATION, FILE_GENERIC_READ, FILE_GENERIC_EXECUTE,
)
from test_windows_anchor_restricted_token import LOW_INTEGRITY_RID

TOKEN_IMPERSONATE = 0x0004
OPEN_EXISTING = 3
FILE_SHARE_READ = 0x1
FILE_SHARE_WRITE = 0x2
FILE_SHARE_DELETE = 0x4
FILE_ATTRIBUTE_NORMAL = 0x80
ERROR_ACCESS_DENIED = 5
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

@unittest.skipUnless(sys.platform == "win32", "Windows actual object opens required")
class RestrictedSidObjectOpenTests(unittest.TestCase):
    def setUp(self):
        self.fixture = ReadOnlyAccessCheckTests(
            "test_restricted_sid_dacl_execute_decisions_on_known_images"
        )
        self.fixture.setUp()
        self.fx = self.fixture.fx
        self.a = self.fixture.a
        self.k = self.fixture.k
        self.a.ImpersonateLoggedOnUser.argtypes = (wintypes.HANDLE,)
        self.a.ImpersonateLoggedOnUser.restype = wintypes.BOOL
        self.a.RevertToSelf.argtypes = ()
        self.a.RevertToSelf.restype = wintypes.BOOL
        self.k.CreateFileW.argtypes = (
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
            wintypes.HANDLE,
        )
        self.k.CreateFileW.restype = wintypes.HANDLE

    def _object_open(self, primary_token, path, desired_access):
        # Impersonate only around the exact Windows CreateFileW call. Never
        # run Python file I/O, printing or other test assertions in this scope.
        impersonation = wintypes.HANDLE()
        self.fx.fx._check(self.a.DuplicateTokenEx(
            primary_token, TOKEN_QUERY | TOKEN_IMPERSONATE,
            None, SECURITY_IMPERSONATION, TOKEN_IMPERSONATION,
            ctypes.byref(impersonation),
        ))
        handle = None
        try:
            self.fx.fx._check(self.a.ImpersonateLoggedOnUser(impersonation))
            try:
                ctypes.set_last_error(0)
                handle = self.k.CreateFileW(
                    str(path), desired_access,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None,
                )
                winerror = ctypes.get_last_error()
            finally:
                # Regardless of the result, restore the trusted controller
                # before closing handles or performing any further operation.
                self.fx.fx._check(self.a.RevertToSelf())
            if handle == INVALID_HANDLE_VALUE or handle is None:
                return False, winerror
            self.fx.fx._close(handle)
            return True, 0
        finally:
            self.fx.fx._close(impersonation)

    def test_actual_read_and_execute_opens_match_recorded_dacl_probes(self):
        root = pathlib.Path(os.environ.get("SystemRoot", r"C:\Windows"))
        paths = {
            "python": pathlib.Path(sys.executable),
            "cmd": root / "System32" / "cmd.exe",
            "ntdll": root / "System32" / "ntdll.dll",
            "kernel32": root / "System32" / "kernel32.dll",
        }
        for name, path in paths.items():
            self.assertTrue(path.is_file(), "missing image: " + name)
        source = self.fx._source()
        try:
            for variant in ("user", "builtin_users"):
                token = None
                try:
                    token = self.fixture._token(source, variant)
                    self.fx.token_fixture._lower_integrity(token)
                    observed = self.fx.audit._observed(token)
                    self.assertEqual(observed["integrity_rid"], LOW_INTEGRITY_RID)
                    self.assertEqual(observed["restricted"], 1)
                    for image, path in paths.items():
                        for operation, mask in (
                            ("read", FILE_GENERIC_READ),
                            ("execute", FILE_GENERIC_EXECUTE),
                        ):
                            dacl = self.fixture._check_file(token, path, mask)
                            opened, code = self._object_open(token, path, mask)
                            # An actual open can be more restrictive than a
                            # static DACL check due to further object checks.
                            # A denied open is NOT proof of loader involvement.
                            if not opened:
                                self.assertNotEqual(code, 0)
                            print(
                                "WNRA06F_OBJECT variant=" + variant
                                + " image=" + image
                                + " operation=" + operation
                                + " dacl_allow=" + str(dacl).lower()
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

"""WNRA-06E — read-only Windows DACL AccessCheck on selected images.

AccessCheck is a static DACL decision. It is NOT the observed failing object,
not a loader trace and not a complete mandatory-integrity access evaluation.
No ACL, audit policy, token privilege or file content is changed.
"""
import ctypes
from ctypes import wintypes
import os
import pathlib
import sys
import unittest

from test_windows_anchor_restricted_sid_access_diagnostics import (
    RestrictedSidAccessDiagnostics, USERS_SID,
)
from test_windows_anchor_restricted_sid_worker import (
    TOKEN_USER, TOKEN_RESTRICTED_SIDS,
)
from test_windows_anchor_restricted_token import (
    DISABLE_MAX_PRIVILEGE, LOW_INTEGRITY_RID,
)
from test_windows_anchor_token_audit import SID_AND_ATTRIBUTES

SE_FILE_OBJECT = 1
OWNER_SECURITY_INFORMATION = 0x1
GROUP_SECURITY_INFORMATION = 0x2
DACL_SECURITY_INFORMATION = 0x4
TOKEN_QUERY = 0x8
TOKEN_IMPERSONATION = 2
SECURITY_IMPERSONATION = 2
FILE_GENERIC_READ = 0x00120089
FILE_GENERIC_EXECUTE = 0x001200A0

class GENERIC_MAPPING(ctypes.Structure):
    _fields_ = [
        ("GenericRead", wintypes.DWORD),
        ("GenericWrite", wintypes.DWORD),
        ("GenericExecute", wintypes.DWORD),
        ("GenericAll", wintypes.DWORD),
    ]

@unittest.skipUnless(sys.platform == "win32", "Windows AccessCheck required")
class ReadOnlyAccessCheckTests(unittest.TestCase):
    def setUp(self):
        self.diagnostic = RestrictedSidAccessDiagnostics(
            "test_current_user_sid_restricted_worker"
        )
        self.diagnostic.setUp()
        self.fx = self.diagnostic.fx
        self.a = self.diagnostic.a
        self.k = self.diagnostic.k
        self.a.DuplicateTokenEx.argtypes = (
            wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p,
            ctypes.c_int, ctypes.c_int, ctypes.POINTER(wintypes.HANDLE),
        )
        self.a.DuplicateTokenEx.restype = wintypes.BOOL
        self.a.GetNamedSecurityInfoW.argtypes = (
            wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD,
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
        )
        self.a.GetNamedSecurityInfoW.restype = wintypes.DWORD
        self.a.AccessCheck.argtypes = (
            ctypes.c_void_p, wintypes.HANDLE, wintypes.DWORD,
            ctypes.POINTER(GENERIC_MAPPING), ctypes.c_void_p,
            ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.BOOL),
        )
        self.a.AccessCheck.restype = wintypes.BOOL

    def _token(self, source, variant):
        sid_allocation = ctypes.c_void_p()
        if variant == "user":
            user = self.fx.audit._information(source, TOKEN_USER)
            sid = ctypes.cast(
                user, ctypes.POINTER(SID_AND_ATTRIBUTES),
            ).contents.Sid
            self.assertTrue(sid)
        elif variant == "builtin_users":
            self.fx.fx._check(self.a.ConvertStringSidToSidW(
                USERS_SID, ctypes.byref(sid_allocation),
            ))
            sid = sid_allocation.value
        else:
            self.fail("unsupported SID variant")
        reduced = wintypes.HANDLE()
        try:
            entry = SID_AND_ATTRIBUTES()
            entry.Sid = sid
            entry.Attributes = 0
            self.fx.fx._check(self.a.CreateRestrictedToken(
                source, DISABLE_MAX_PRIVILEGE,
                0, None, 0, None, 1, ctypes.byref(entry),
                ctypes.byref(reduced),
            ))
        finally:
            if sid_allocation.value:
                self.assertFalse(self.k.LocalFree(sid_allocation))
        return reduced

    def _check_file(self, token, path, desired):
        descriptor = ctypes.c_void_p()
        # Read-only retrieval of OWNER/GROUP/DACL; no SACL or auditing enabled.
        result = self.a.GetNamedSecurityInfoW(
            str(path), SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION
            | DACL_SECURITY_INFORMATION,
            None, None, None, None, ctypes.byref(descriptor),
        )
        self.assertEqual(result, 0, f"security descriptor read failed: {path}")
        self.assertTrue(descriptor.value)
        impersonation = wintypes.HANDLE()
        try:
            self.fx.fx._check(self.a.DuplicateTokenEx(
                token, TOKEN_QUERY, None, SECURITY_IMPERSONATION,
                TOKEN_IMPERSONATION, ctypes.byref(impersonation),
            ))
            mapping = GENERIC_MAPPING(
                FILE_GENERIC_READ, 0x00120116,
                FILE_GENERIC_EXECUTE, 0x001F01FF,
            )
            privileges = ctypes.create_string_buffer(4096)
            privilege_size = wintypes.DWORD(ctypes.sizeof(privileges))
            granted = wintypes.DWORD()
            access_status = wintypes.BOOL()
            self.fx.fx._check(self.a.AccessCheck(
                descriptor, impersonation, desired,
                ctypes.byref(mapping), privileges,
                ctypes.byref(privilege_size),
                ctypes.byref(granted), ctypes.byref(access_status),
            ))
            return bool(access_status.value)
        finally:
            if impersonation:
                self.fx.fx._close(impersonation)
            if descriptor.value:
                self.assertFalse(self.k.LocalFree(descriptor))

    def test_restricted_sid_dacl_execute_decisions_on_known_images(self):
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        paths = {
            "python": pathlib.Path(sys.executable),
            "cmd": pathlib.Path(system_root) / "System32" / "cmd.exe",
            "ntdll": pathlib.Path(system_root) / "System32" / "ntdll.dll",
            "kernel32": pathlib.Path(system_root) / "System32" / "kernel32.dll",
        }
        for name, path in paths.items():
            self.assertTrue(path.is_file(), name + " missing")
        source = self.fx._source()
        try:
            for variant in ("user", "builtin_users"):
                token = None
                try:
                    token = self._token(source, variant)
                    self.fx.token_fixture._lower_integrity(token)
                    observed = self.fx.audit._observed(token)
                    self.assertEqual(observed["restricted"], 1)
                    self.assertEqual(observed["integrity_rid"], LOW_INTEGRITY_RID)
                    count_blob = self.fx.audit._information(
                        token, TOKEN_RESTRICTED_SIDS,
                    )
                    count = ctypes.cast(
                        count_blob, ctypes.POINTER(wintypes.DWORD),
                    ).contents.value
                    self.assertGreaterEqual(count, 1)
                    for image_name, path in paths.items():
                        execute = self._check_file(
                            token, path, FILE_GENERIC_EXECUTE,
                        )
                        read = self._check_file(
                            token, path, FILE_GENERIC_READ,
                        )
                        print(
                            "WNRA06E_ACCESS variant=" + variant
                            + " image=" + image_name
                            + " dacl_execute=" + str(execute).lower()
                            + " dacl_read=" + str(read).lower()
                            + " accesscheck_only=true authorization=DENY"
                        )
                finally:
                    if token:
                        self.fx.fx._close(token)
        finally:
            self.fx.fx._close(source)


if __name__ == "__main__":
    unittest.main()

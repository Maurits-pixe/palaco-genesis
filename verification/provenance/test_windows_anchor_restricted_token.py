"""WNRA-05Z: Windows-only restricted token and low-integrity label fixture.

Never starts a process with this token; this is not a production sandbox.
"""
import ctypes
from ctypes import wintypes
import sys
import unittest

from test_windows_anchor_token_audit import (
    TokenAuditTests, TOKEN_QUERY, TOKEN_INTEGRITY_LEVEL,
    SID_AND_ATTRIBUTES,
)

TOKEN_DUPLICATE = 0x0002
TOKEN_ADJUST_DEFAULT = 0x0080
DISABLE_MAX_PRIVILEGE = 0x00000001
SE_PRIVILEGE_ENABLED = 0x00000002
LOW_INTEGRITY_RID = 0x1000
ERROR_ACCESS_DENIED = 5

class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

@unittest.skipUnless(sys.platform == "win32", "native Windows tokens required")
class RestrictedTokenFixtureTests(unittest.TestCase):
    def setUp(self):
        self.audit = TokenAuditTests(
            "test_suspended_worker_token_does_not_gain_integrity_or_privileges"
        )
        self.audit.setUp()
        self.k = self.audit.k
        self.a = self.audit.a
        self.a.CreateRestrictedToken.argtypes = (
            wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
            ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p,
            wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(wintypes.HANDLE),
        )
        self.a.CreateRestrictedToken.restype = wintypes.BOOL
        self.a.ConvertStringSidToSidW.argtypes = (
            wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p),
        )
        self.a.ConvertStringSidToSidW.restype = wintypes.BOOL
        self.a.SetTokenInformation.argtypes = (
            wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
        )
        self.a.SetTokenInformation.restype = wintypes.BOOL
        self.k.LocalFree.argtypes = (ctypes.c_void_p,)
        self.k.LocalFree.restype = ctypes.c_void_p

    def _parent(self, access):
        handle = wintypes.HANDLE()
        self.audit.fixture._check(self.a.OpenProcessToken(
            self.k.GetCurrentProcess(), access, ctypes.byref(handle),
        ))
        return handle

    def _enabled_count(self, token):
        buffer = self.audit._information(token, 3)
        number = ctypes.cast(
            buffer, ctypes.POINTER(wintypes.DWORD),
        ).contents.value
        array_type = LUID_AND_ATTRIBUTES * number
        # TOKEN_PRIVILEGES holds a DWORD followed by aligned LUID entries.
        offset = ctypes.sizeof(wintypes.DWORD)
        privileges = array_type.from_buffer_copy(
            buffer.raw[offset:offset + ctypes.sizeof(array_type)]
        )
        return sum(
            1 for privilege in privileges
            if privilege.Attributes & SE_PRIVILEGE_ENABLED
        )

    def _restricted(self, original):
        reduced = wintypes.HANDLE()
        self.audit.fixture._check(self.a.CreateRestrictedToken(
            original, DISABLE_MAX_PRIVILEGE, 0, None, 0, None,
            0, None, ctypes.byref(reduced),
        ))
        return reduced

    def _lower_integrity(self, token):
        sid = ctypes.c_void_p()
        self.audit.fixture._check(self.a.ConvertStringSidToSidW(
            "S-1-16-4096", ctypes.byref(sid),
        ))
        try:
            count = self.a.GetSidSubAuthorityCount(sid)[0]
            self.assertEqual(
                self.a.GetSidSubAuthority(sid, count - 1)[0],
                LOW_INTEGRITY_RID,
            )
            label = SID_AND_ATTRIBUTES()
            label.Sid = sid.value
            label.Attributes = 0x20  # SE_GROUP_INTEGRITY
            sid_size = ctypes.WinDLL("advapi32", use_last_error=True).GetLengthSid
            sid_size.argtypes = (ctypes.c_void_p,)
            sid_size.restype = wintypes.DWORD
            length = ctypes.sizeof(label) + sid_size(sid)
            self.audit.fixture._check(self.a.SetTokenInformation(
                token, TOKEN_INTEGRITY_LEVEL, ctypes.byref(label), length,
            ))
        finally:
            self.assertFalse(self.k.LocalFree(sid))

    def test_reduced_token_has_lower_integrity_and_no_privilege_gain(self):
        original = self._parent(TOKEN_QUERY | TOKEN_DUPLICATE)
        reduced = None
        try:
            parent = self.audit._observed(original)
            enabled_parent = self._enabled_count(original)
            reduced = self._restricted(original)
            self._lower_integrity(reduced)
            child = self.audit._observed(reduced)
            enabled_child = self._enabled_count(reduced)
            self.assertEqual(child["integrity_rid"], LOW_INTEGRITY_RID)
            self.assertLess(child["integrity_rid"], parent["integrity_rid"])
            self.assertLessEqual(enabled_child, enabled_parent)
            self.assertLessEqual(
                child["privilege_count"], parent["privilege_count"],
            )
            print(
                "WNRA05Z_RESTRICTED integrity_rid="
                + str(child["integrity_rid"])
                + " below_parent=true enabled_privileges_not_increased=true"
                + " created_token_only=true authorization=DENY"
            )
            print(
                "WNRA05Z_DIAGNOSTICS parent_enabled=" + str(enabled_parent)
                + " child_enabled=" + str(enabled_child)
                + " token_restricted_flag=" + str(child["restricted"])
                + " authorization=DENY"
            )
        finally:
            if reduced:
                self.audit.fixture._close(reduced)
            self.audit.fixture._close(original)

    def test_query_only_handle_cannot_modify_integrity(self):
        restricted_source = self._parent(TOKEN_QUERY | TOKEN_DUPLICATE)
        query_only = None
        reduced = None
        sid = ctypes.c_void_p()
        try:
            reduced = self._restricted(restricted_source)
            query_only = wintypes.HANDLE()
            self.audit.fixture._check(self.k.DuplicateHandle(
                self.k.GetCurrentProcess(), reduced,
                self.k.GetCurrentProcess(), ctypes.byref(query_only),
                TOKEN_QUERY, False, 0,
            ))
            self.audit.fixture._check(self.a.ConvertStringSidToSidW(
                "S-1-16-4096", ctypes.byref(sid),
            ))
            label = SID_AND_ATTRIBUTES()
            label.Sid = sid.value
            label.Attributes = 0x20
            ctypes.set_last_error(0)
            self.assertFalse(self.a.SetTokenInformation(
                query_only, TOKEN_INTEGRITY_LEVEL,
                ctypes.byref(label), ctypes.sizeof(label),
            ))
            self.assertEqual(ctypes.get_last_error(), ERROR_ACCESS_DENIED)
            print(
                "WNRA05Z_QUERY_ONLY change_integrity_denied=true"
                " token_not_launched=true authorization=DENY"
            )
        finally:
            if sid.value:
                self.assertFalse(self.k.LocalFree(sid))
            if query_only:
                self.audit.fixture._close(query_only)
            if reduced:
                self.audit.fixture._close(reduced)
            self.audit.fixture._close(restricted_source)


if __name__ == "__main__":
    unittest.main()

"""WNRA-06B: Windows restricted-SID token and low-integrity process test.

CI-only. Explicitly distinguishes restricted-SID token creation, successful
Job Object process execution, and a fail-closed OS process-creation refusal.
"""
import ctypes
from ctypes import wintypes
import subprocess
import sys
import time
import unittest

from test_windows_anchor_low_token_job_launch import (
    RestrictedProcessLaunchTests,
    TOKEN_ASSIGN_PRIMARY,
    ERROR_PRIVILEGE_NOT_HELD,
    ERROR_ACCESS_DENIED,
    ERROR_BAD_TOKEN_TYPE,
)
from test_windows_anchor_restricted_token import (
    TOKEN_DUPLICATE, TOKEN_ADJUST_DEFAULT, DISABLE_MAX_PRIVILEGE,
    LOW_INTEGRITY_RID,
)
from test_windows_anchor_token_audit import TOKEN_QUERY, SID_AND_ATTRIBUTES
from test_windows_anchor_suspended_job_launch import (
    STARTUPINFOW, PROCESS_INFORMATION, CREATE_SUSPENDED, CREATE_NO_WINDOW,
    WAIT_TIMEOUT, WAIT_OBJECT_0, RESUME_FAILED,
)

TOKEN_USER = 1
TOKEN_RESTRICTED_SIDS = 11
ERROR_BAD_IMPERSONATION_LEVEL = 1346

@unittest.skipUnless(sys.platform == "win32", "Windows restricted SIDs required")
class RestrictedSidWorkerTests(RestrictedProcessLaunchTests):
    # Prevent inherited base-case test discovery; tests of the base suite
    # already run in the separate WNRA-06A file.
    __test__ = False

    def _restricted_user_sid_token(self, source):
        user_info = self.audit._information(source, TOKEN_USER)
        user_sid = ctypes.cast(
            user_info, ctypes.POINTER(SID_AND_ATTRIBUTES),
        ).contents.Sid
        self.assertTrue(user_sid)
        restriction = SID_AND_ATTRIBUTES()
        restriction.Sid = user_sid
        restriction.Attributes = 0
        token = wintypes.HANDLE()
        self.fx._check(self.a.CreateRestrictedToken(
            source, DISABLE_MAX_PRIVILEGE,
            0, None, 0, None, 1, ctypes.byref(restriction),
            ctypes.byref(token),
        ))
        return token

    def _assert_token_restriction(self, source, token):
        self.token_fixture._lower_integrity(token)
        observed = self.audit._observed(token)
        self.assertEqual(observed["integrity_rid"], LOW_INTEGRITY_RID)
        self.assertEqual(observed["restricted"], 1)
        restriction_info = self.audit._information(token, TOKEN_RESTRICTED_SIDS)
        restricted_count = ctypes.cast(
            restriction_info, ctypes.POINTER(wintypes.DWORD),
        ).contents.value
        self.assertGreaterEqual(restricted_count, 1)
        enabled = self.token_fixture._enabled_count(token)
        original = self.token_fixture._enabled_count(source)
        self.assertLessEqual(enabled, original)
        return restricted_count, enabled, original

    def _source(self):
        return self.token_fixture._parent(
            TOKEN_QUERY | TOKEN_DUPLICATE |
            TOKEN_ADJUST_DEFAULT | TOKEN_ASSIGN_PRIMARY
        )

    def test_restricted_user_sid_is_present_and_low_integrity(self):
        source = self._source()
        restricted = None
        try:
            restricted = self._restricted_user_sid_token(source)
            count, enabled, original = self._assert_token_restriction(
                source, restricted,
            )
            print(
                "WNRA06B_TOKEN restricted_sid_count=" + str(count)
                + " restricted_flag=true integrity_rid="
                + str(LOW_INTEGRITY_RID)
                + " enabled_privileges_not_increased=true"
                + " token_object_only=true authorization=DENY"
            )
            print(
                "WNRA06B_PRIVILEGES source_enabled=" + str(original)
                + " restricted_enabled=" + str(enabled)
                + " authorization=DENY"
            )
        finally:
            if restricted:
                self.fx._close(restricted)
            self.fx._close(source)

    def test_restricted_sid_worker_launch_or_explicit_deny(self):
        source = self._source()
        token = None
        job = None
        info = PROCESS_INFORMATION()
        try:
            token = self._restricted_user_sid_token(source)
            count, _, _ = self._assert_token_restriction(source, token)
            job = self.fx._job()
            command = subprocess.list2cmdline([
                sys.executable, "-u", "-c", "import time; time.sleep(30)",
            ])
            buffer = ctypes.create_unicode_buffer(command)
            startup = STARTUPINFOW()
            startup.cb = ctypes.sizeof(startup)
            ctypes.set_last_error(0)
            created = bool(self.a.CreateProcessAsUserW(
                token, sys.executable, buffer, None, None, False,
                CREATE_SUSPENDED | CREATE_NO_WINDOW, None, None,
                ctypes.byref(startup), ctypes.byref(info),
            ))
            if not created:
                error = ctypes.get_last_error()
                self.assertIn(
                    error, (ERROR_ACCESS_DENIED, ERROR_PRIVILEGE_NOT_HELD,
                            ERROR_BAD_TOKEN_TYPE, ERROR_BAD_IMPERSONATION_LEVEL),
                )
                self.assertFalse(info.hProcess)
                self.assertFalse(info.hThread)
                print(
                    "WNRA06B_CREATE blocked=true winerror=" + str(error)
                    + " restricted_sids_verified=true"
                    + " child_created=false resume_attempted=false"
                    + " authorization=DENY"
                )
                return
            self.assertTrue(info.hProcess)
            self.assertTrue(info.hThread)
            self.assertEqual(
                self.k.WaitForSingleObject(info.hProcess, 0), WAIT_TIMEOUT,
            )
            self.fx._check(
                self.k.AssignProcessToJobObject(job, info.hProcess),
            )
            member = wintypes.BOOL()
            self.fx._check(self.k.IsProcessInJob(
                info.hProcess, job, ctypes.byref(member),
            ))
            self.assertTrue(member.value)
            child_token = None
            try:
                child_token = self.audit._token(info.hProcess)
                child = self.audit._observed(child_token)
                self.assertEqual(child["integrity_rid"], LOW_INTEGRITY_RID)
                self.assertEqual(child["restricted"], 1)
                child_restricted_info = self.audit._information(
                    child_token, TOKEN_RESTRICTED_SIDS,
                )
                child_count = ctypes.cast(
                    child_restricted_info, ctypes.POINTER(wintypes.DWORD),
                ).contents.value
                self.assertGreaterEqual(child_count, 1)
                self.assertLessEqual(
                    self.token_fixture._enabled_count(child_token),
                    self.token_fixture._enabled_count(source),
                )
            finally:
                if child_token:
                    self.fx._close(child_token)
            self.assertNotEqual(
                self.k.ResumeThread(info.hThread), RESUME_FAILED,
            )
            time.sleep(0.5)
            self.assertEqual(
                self.k.WaitForSingleObject(info.hProcess, 0), WAIT_TIMEOUT,
                "worker must execute and remain alive after resume",
            )
            self.fx._close(job)
            job = None
            self.assertEqual(
                self.k.WaitForSingleObject(info.hProcess, 5000),
                WAIT_OBJECT_0,
            )
            print(
                "WNRA06B_LAUNCH restricted_sid_count=" + str(count)
                + " child_token_restricted=true"
                + " child_integrity_low=true"
                + " job_assigned_before_resume=true"
                + " worker_alive_after_resume=true"
                + " job_close_terminated=true authorization=DENY"
            )
        finally:
            if job:
                self.fx._close(job)
            if info.hProcess:
                if self.k.WaitForSingleObject(info.hProcess, 0) == WAIT_TIMEOUT:
                    self.k.TerminateProcess(info.hProcess, 1)
                    self.k.WaitForSingleObject(info.hProcess, 5000)
                self.fx._close(info.hProcess)
            if info.hThread:
                self.fx._close(info.hThread)
            if token:
                self.fx._close(token)
            self.fx._close(source)


if __name__ == "__main__":
    unittest.main()

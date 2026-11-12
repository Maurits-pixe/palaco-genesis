"""WNRA-05T: Windows-only suspended process -> Job Object assignment fixture.

No production launcher, privilege boundary, independent authority or release gate.
"""
import ctypes
from ctypes import wintypes
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest

from test_windows_anchor_job_objects import (
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION as JobLimitStructure,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
)

CREATE_SUSPENDED = 0x00000004
CREATE_NO_WINDOW = 0x08000000
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 0x102
RESUME_FAILED = 0xFFFFFFFF
PROCESS_SYNCHRONIZE = 0x00100000
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
HANDLE_FLAG_INHERIT = 0x00000001
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002
JOB_OBJECT_LIMIT_BREAKAWAY_OK = 0x00000800
JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK = 0x00001000
EVENT_MODIFY_STATE = 0x0002
WAIT_FAILED = 0xFFFFFFFF
ERROR_ACCESS_DENIED = 5

class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_ubyte)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]

class STARTUPINFOEXW(ctypes.Structure):
    _fields_ = [
        ("StartupInfo", STARTUPINFOW),
        ("lpAttributeList", ctypes.c_void_p),
    ]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]

@unittest.skipUnless(sys.platform == "win32", "Windows native Job Object required")
class SuspendedJobLaunchTests(unittest.TestCase):
    def setUp(self):
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        self.k = k
        k.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
        k.CreateJobObjectW.restype = wintypes.HANDLE
        k.SetInformationJobObject.argtypes = (
            wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
        )
        k.SetInformationJobObject.restype = wintypes.BOOL
        k.CreateProcessW.argtypes = (
            wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p,
            ctypes.c_void_p, wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p,
            wintypes.LPCWSTR, ctypes.POINTER(STARTUPINFOW),
            ctypes.POINTER(PROCESS_INFORMATION),
        )
        k.CreateProcessW.restype = wintypes.BOOL
        k.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
        k.AssignProcessToJobObject.restype = wintypes.BOOL
        k.ResumeThread.argtypes = (wintypes.HANDLE,)
        k.ResumeThread.restype = wintypes.DWORD
        k.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        k.WaitForSingleObject.restype = wintypes.DWORD
        k.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        k.OpenProcess.restype = wintypes.HANDLE
        k.TerminateProcess.argtypes = (wintypes.HANDLE, wintypes.UINT)
        k.TerminateProcess.restype = wintypes.BOOL
        k.IsProcessInJob.argtypes = (
            wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL),
        )
        k.IsProcessInJob.restype = wintypes.BOOL
        k.CreateEventW.argtypes = (
            ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR,
        )
        k.CreateEventW.restype = wintypes.HANDLE
        k.SetHandleInformation.argtypes = (
            wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
        )
        k.SetHandleInformation.restype = wintypes.BOOL
        k.GetHandleInformation.argtypes = (
            wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD),
        )
        k.GetHandleInformation.restype = wintypes.BOOL
        k.InitializeProcThreadAttributeList.argtypes = (
            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
            ctypes.POINTER(ctypes.c_size_t),
        )
        k.InitializeProcThreadAttributeList.restype = wintypes.BOOL
        k.UpdateProcThreadAttribute.argtypes = (
            ctypes.c_void_p, wintypes.DWORD, ctypes.c_size_t,
            ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p,
        )
        k.UpdateProcThreadAttribute.restype = wintypes.BOOL
        k.DeleteProcThreadAttributeList.argtypes = (ctypes.c_void_p,)
        k.DeleteProcThreadAttributeList.restype = None
        k.QueryInformationJobObject.argtypes = (
            wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
            wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
        )
        k.QueryInformationJobObject.restype = wintypes.BOOL
        k.GetCurrentProcess.argtypes = ()
        k.GetCurrentProcess.restype = wintypes.HANDLE
        k.DuplicateHandle.argtypes = (
            wintypes.HANDLE, wintypes.HANDLE, wintypes.HANDLE,
            ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD, wintypes.BOOL,
            wintypes.DWORD,
        )
        k.DuplicateHandle.restype = wintypes.BOOL
        k.SetEvent.argtypes = (wintypes.HANDLE,)
        k.SetEvent.restype = wintypes.BOOL
        k.CloseHandle.argtypes = (wintypes.HANDLE,)
        k.CloseHandle.restype = wintypes.BOOL

    def _check(self, success):
        if not success:
            raise ctypes.WinError(ctypes.get_last_error())

    def _job(self):
        job = self.k.CreateJobObjectW(None, None)
        self._check(job)
        limits = JobLimitStructure()
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        try:
            self._check(self.k.SetInformationJobObject(
                job, 9, ctypes.byref(limits), ctypes.sizeof(limits),
            ))
        except BaseException:
            self.k.CloseHandle(job)
            raise
        return job

    def _suspended_python(self, script, directory):
        startup = STARTUPINFOW()
        startup.cb = ctypes.sizeof(startup)
        info = PROCESS_INFORMATION()
        # list2cmdline is Windows-specific; mutable buffer is required by CreateProcessW.
        command = subprocess.list2cmdline([
            sys.executable, "-u", "-c", script, str(directory),
        ])
        command_buffer = ctypes.create_unicode_buffer(command)
        self._check(self.k.CreateProcessW(
            sys.executable, command_buffer, None, None, False,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            None, None, ctypes.byref(startup), ctypes.byref(info),
        ))
        return info

    def _suspended_python_allowlist(self, script, directory, handles):
        # STARTUPINFOEXW allowlists only these explicitly inheritable handles.
        # The attribute list must remain allocated through CreateProcessW.
        required = ctypes.c_size_t()
        self.k.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(required))
        self.assertGreater(required.value, 0)
        storage = ctypes.create_string_buffer(required.value)
        attribute_list = ctypes.cast(storage, ctypes.c_void_p)
        self._check(self.k.InitializeProcThreadAttributeList(
            attribute_list, 1, 0, ctypes.byref(required),
        ))
        try:
            allowed = (wintypes.HANDLE * len(handles))(*handles)
            self._check(self.k.UpdateProcThreadAttribute(
                attribute_list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                ctypes.cast(allowed, ctypes.c_void_p),
                ctypes.sizeof(allowed), None, None,
            ))
            extended = STARTUPINFOEXW()
            extended.StartupInfo.cb = ctypes.sizeof(extended)
            extended.lpAttributeList = attribute_list
            info = PROCESS_INFORMATION()
            command = subprocess.list2cmdline(
                [sys.executable, "-u", "-c", script, str(directory)]
            )
            command_buffer = ctypes.create_unicode_buffer(command)
            self._check(self.k.CreateProcessW(
                sys.executable, command_buffer, None, None, True,
                CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
                None, None, ctypes.byref(extended.StartupInfo), ctypes.byref(info),
            ))
            return info
        finally:
            self.k.DeleteProcThreadAttributeList(attribute_list)

    def _wait_for_marker(self, root, name, info):
        marker = root / name
        deadline = time.monotonic() + 12
        while True:
            if marker.exists():
                value = marker.read_text(encoding="ascii").strip()
                if value.endswith(";DONE"):
                    return value
            if self.k.WaitForSingleObject(info.hProcess, 0) == WAIT_OBJECT_0:
                self.fail(name + " worker exited before complete marker")
            if time.monotonic() >= deadline:
                self.fail(name + " marker deadline expired")
            time.sleep(0.025)

    def _close(self, handle):
        if handle:
            self._check(self.k.CloseHandle(handle))

    def _assert_unstarted(self, marker, info):
        self.assertFalse(marker.exists(), "suspended worker executed before resume")
        self.assertEqual(
            self.k.WaitForSingleObject(info.hProcess, 0), WAIT_TIMEOUT,
        )

    def test_assign_before_resume_and_close_job_kills_descendant(self):
        script = (
            "from pathlib import Path\n"
            "import subprocess,sys,time\n"
            "root=Path(sys.argv[1])\n"
            "(root/'started').write_text('started',encoding='utf-8')\n"
            "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'],"
            "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,"
            "stderr=subprocess.DEVNULL)\n"
            "(root/'descendant_pid').write_text(str(child.pid),encoding='ascii')\n"
            "time.sleep(30)\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            job = self._job()
            info = None
            descendant = None
            try:
                info = self._suspended_python(script, root)
                self._assert_unstarted(root / "started", info)
                self._check(self.k.AssignProcessToJobObject(job, info.hProcess))
                self._assert_unstarted(root / "started", info)
                self.assertNotEqual(
                    self.k.ResumeThread(info.hThread), RESUME_FAILED,
                )
                deadline = time.monotonic() + 12
                pid_file = root / "descendant_pid"
                pid_text = ""
                while not pid_text.isdecimal():
                    if pid_file.exists():
                        # write_text creates a file before the PID bytes are flushed.
                        pid_text = pid_file.read_text(encoding="ascii").strip()
                    if pid_text.isdecimal():
                        break
                    if self.k.WaitForSingleObject(info.hProcess, 0) == WAIT_OBJECT_0:
                        self.fail("worker exited before complete descendant PID")
                    if time.monotonic() >= deadline:
                        self.fail("complete descendant PID timed out")
                    time.sleep(0.025)
                self.assertTrue((root / "started").exists())
                descendant = self.k.OpenProcess(
                    PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                    False, int(pid_text),
                )
                self._check(descendant)
                parent_in_job = wintypes.BOOL()
                child_in_job = wintypes.BOOL()
                self._check(self.k.IsProcessInJob(
                    info.hProcess, job, ctypes.byref(parent_in_job),
                ))
                self._check(self.k.IsProcessInJob(
                    descendant, job, ctypes.byref(child_in_job),
                ))
                self.assertTrue(parent_in_job.value)
                self.assertTrue(child_in_job.value)
                print(
                    "WNRA05U_MEMBERSHIP parent_in_job=true "
                    "descendant_in_job=true authorization=DENY"
                )
                self.assertEqual(
                    self.k.WaitForSingleObject(descendant, 0), WAIT_TIMEOUT,
                )
                self.assertEqual(
                    self.k.WaitForSingleObject(info.hProcess, 0), WAIT_TIMEOUT,
                )
                self._close(job)
                job = None
                self.assertEqual(
                    self.k.WaitForSingleObject(descendant, 5000), WAIT_OBJECT_0,
                )
                self.assertEqual(
                    self.k.WaitForSingleObject(info.hProcess, 5000), WAIT_OBJECT_0,
                )
                print(
                    "WNRA05T_SUSPENDED assign_before_resume=true "
                    "descendant_terminated=true authorization=DENY"
                )
            finally:
                if job:
                    self._close(job)
                if info:
                    if self.k.WaitForSingleObject(info.hProcess, 0) == WAIT_TIMEOUT:
                        self.k.TerminateProcess(info.hProcess, 1)
                        self.k.WaitForSingleObject(info.hProcess, 5000)
                    self._close(info.hThread)
                    self._close(info.hProcess)
                if descendant:
                    self._close(descendant)

    def test_inheritable_parent_handle_not_leaked_to_suspended_worker(self):
        # The event is intentionally inheritable in the test parent. The fixture
        # launcher passes bInheritHandles=False to CreateProcessW.
        event = self.k.CreateEventW(None, False, False, None)
        self._check(event)
        job = None
        info = None
        try:
            self._check(self.k.SetHandleInformation(
                event, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT,
            ))
            flags = wintypes.DWORD()
            self._check(self.k.GetHandleInformation(event, ctypes.byref(flags)))
            self.assertTrue(flags.value & HANDLE_FLAG_INHERIT)
            script = (
                "import ctypes,sys,time\n"
                "from ctypes import wintypes\n"
                "from pathlib import Path\n"
                f"handle={int(event)}\n"
                "k=ctypes.WinDLL('kernel32',use_last_error=True)\n"
                "k.SetEvent.argtypes=(ctypes.c_void_p,)\n"
                "k.SetEvent.restype=wintypes.BOOL\n"
                "# Numeric handles are process-local; another object can reuse the same value.\n"
                "k.SetEvent(handle)\n"
                "Path(sys.argv[1]).joinpath('handle_probe').write_text('PROBE_COMPLETE',encoding='ascii')\n"
                "time.sleep(30)\n"
            )
            with tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary)
                job = self._job()
                info = self._suspended_python(script, root)
                self._assert_unstarted(root / "handle_probe", info)
                self._check(self.k.AssignProcessToJobObject(job, info.hProcess))
                self._assert_unstarted(root / "handle_probe", info)
                self.assertNotEqual(
                    self.k.ResumeThread(info.hThread), RESUME_FAILED,
                )
                marker = root / "handle_probe"
                deadline = time.monotonic() + 12
                observed = ""
                while observed != "PROBE_COMPLETE":
                    if marker.exists():
                        observed = marker.read_text(encoding="ascii").strip()
                    if observed == "PROBE_COMPLETE":
                        break
                    if self.k.WaitForSingleObject(info.hProcess, 0) == WAIT_OBJECT_0:
                        self.fail("worker exited before handle probe")
                    if time.monotonic() >= deadline:
                        self.fail("handle probe timed out")
                    time.sleep(0.025)
                self.assertEqual(observed, "PROBE_COMPLETE")
                # The parent's ORIGINAL event must remain unsignaled even after
                # the worker tried SetEvent with the same numeric handle value.
                self.assertEqual(
                    self.k.WaitForSingleObject(event, 0), WAIT_TIMEOUT,
                )
                self._close(job)
                job = None
                self.assertEqual(
                    self.k.WaitForSingleObject(info.hProcess, 5000),
                    WAIT_OBJECT_0,
                )
                print(
                    "WNRA05U_HANDLE inheritable_parent_handle=true "
                    "child_inherited=false authorization=DENY"
                )
        finally:
            if job:
                self._close(job)
            if info:
                if self.k.WaitForSingleObject(info.hProcess, 0) == WAIT_TIMEOUT:
                    self.k.TerminateProcess(info.hProcess, 1)
                    self.k.WaitForSingleObject(info.hProcess, 5000)
                self._close(info.hThread)
                self._close(info.hProcess)
            self._close(event)

    def test_allowlisted_handle_inherits_but_unlisted_handle_does_not(self):
        allowed = self.k.CreateEventW(None, False, False, None)
        self._check(allowed)
        forbidden = self.k.CreateEventW(None, False, False, None)
        self._check(forbidden)
        job = None
        info = None
        try:
            for handle in (allowed, forbidden):
                self._check(self.k.SetHandleInformation(
                    handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT,
                ))
            script = (
                "import ctypes,sys,time\n"
                "from ctypes import wintypes\n"
                "from pathlib import Path\n"
                f"allowed={int(allowed)}\n"
                f"forbidden={int(forbidden)}\n"
                "k=ctypes.WinDLL('kernel32',use_last_error=True)\n"
                "k.SetEvent.argtypes=(ctypes.c_void_p,)\n"
                "k.SetEvent.restype=wintypes.BOOL\n"
                "# Probe the actual event objects, not process-local numeric handles.\n"
                "k.SetEvent(allowed)\n"
                "k.SetEvent(forbidden)\n"
                "Path(sys.argv[1]).joinpath('allowlist_probe').write_text('PROBED;DONE',encoding='ascii')\n"
                "time.sleep(30)\n"
            )
            with tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary)
                job = self._job()
                info = self._suspended_python_allowlist(
                    script, root, [allowed],
                )
                self._assert_unstarted(root / "allowlist_probe", info)
                self._check(self.k.AssignProcessToJobObject(job, info.hProcess))
                self._assert_unstarted(root / "allowlist_probe", info)
                self.assertNotEqual(
                    self.k.ResumeThread(info.hThread), RESUME_FAILED,
                )
                value = self._wait_for_marker(root, "allowlist_probe", info)
                self.assertEqual(value, "PROBED;DONE")
                self.assertEqual(
                    self.k.WaitForSingleObject(allowed, 0), WAIT_OBJECT_0,
                )
                self.assertEqual(
                    self.k.WaitForSingleObject(forbidden, 0), WAIT_TIMEOUT,
                )
                self._close(job)
                job = None
                self.assertEqual(
                    self.k.WaitForSingleObject(info.hProcess, 5000),
                    WAIT_OBJECT_0,
                )
                print(
                    "WNRA05V_ALLOWLIST allowed_inherited=true "
                    "unlisted_inherited=false authorization=DENY"
                )
        finally:
            if job:
                self._close(job)
            if info:
                if self.k.WaitForSingleObject(info.hProcess, 0) == WAIT_TIMEOUT:
                    self.k.TerminateProcess(info.hProcess, 1)
                    self.k.WaitForSingleObject(info.hProcess, 5000)
                self._close(info.hThread)
                self._close(info.hProcess)
            self._close(forbidden)
            self._close(allowed)

    def test_explicit_job_breakaway_creation_is_denied(self):
        script = (
            "import subprocess,sys,time\n"
            "from pathlib import Path\n"
            "try:\n"
            " p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'],"
            "creationflags=0x01000000,stdin=subprocess.DEVNULL,"
            "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
            " p.kill();p.wait(timeout=5)\n"
            " outcome='UNEXPECTED_BREAKAWAY'\n"
            "except OSError as error:\n"
            " outcome=f'DENIED:{error.winerror}'\n"
            "Path(sys.argv[1]).joinpath('breakaway_probe').write_text("
            "outcome+';DONE',encoding='ascii')\n"
            "time.sleep(30)\n"
        )
        job = self._job()
        info = None
        try:
            observed = JobLimitStructure()
            length = wintypes.DWORD()
            self._check(self.k.QueryInformationJobObject(
                job, 9, ctypes.byref(observed), ctypes.sizeof(observed),
                ctypes.byref(length),
            ))
            flags = observed.BasicLimitInformation.LimitFlags
            self.assertFalse(flags & JOB_OBJECT_LIMIT_BREAKAWAY_OK)
            self.assertFalse(flags & JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK)
            with tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary)
                info = self._suspended_python(script, root)
                self._assert_unstarted(root / "breakaway_probe", info)
                self._check(self.k.AssignProcessToJobObject(job, info.hProcess))
                self._assert_unstarted(root / "breakaway_probe", info)
                self.assertNotEqual(
                    self.k.ResumeThread(info.hThread), RESUME_FAILED,
                )
                outcome = self._wait_for_marker(root, "breakaway_probe", info)
                self.assertEqual(outcome, "DENIED:5;DONE")
                self._close(job)
                job = None
                self.assertEqual(
                    self.k.WaitForSingleObject(info.hProcess, 5000),
                    WAIT_OBJECT_0,
                )
                print(
                    "WNRA05V_BREAKAWAY flags_disabled=true "
                    "explicit_breakaway_denied=true authorization=DENY"
                )
        finally:
            if job:
                self._close(job)
            if info:
                if self.k.WaitForSingleObject(info.hProcess, 0) == WAIT_TIMEOUT:
                    self.k.TerminateProcess(info.hProcess, 1)
                    self.k.WaitForSingleObject(info.hProcess, 5000)
                self._close(info.hThread)
                self._close(info.hProcess)

    def test_minimal_event_rights_survive_explicit_transfer(self):
        original = self.k.CreateEventW(None, False, False, None)
        self._check(original)
        restricted = wintypes.HANDLE()
        job = None
        info = None
        try:
            current = self.k.GetCurrentProcess()
            self._check(self.k.DuplicateHandle(
                current, original, current, ctypes.byref(restricted),
                EVENT_MODIFY_STATE, True, 0,
            ))
            self.assertTrue(restricted.value)
            flags = wintypes.DWORD()
            self._check(self.k.GetHandleInformation(
                restricted, ctypes.byref(flags),
            ))
            self.assertTrue(flags.value & HANDLE_FLAG_INHERIT)
            script = (
                "import ctypes,sys,time\n"
                "from ctypes import wintypes\n"
                "from pathlib import Path\n"
                f"restricted={int(restricted.value)}\n"
                f"original={int(original)}\n"
                "k=ctypes.WinDLL('kernel32',use_last_error=True)\n"
                "k.SetEvent.argtypes=(ctypes.c_void_p,)\n"
                "k.SetEvent.restype=wintypes.BOOL\n"
                "k.WaitForSingleObject.argtypes=(ctypes.c_void_p,wintypes.DWORD)\n"
                "k.WaitForSingleObject.restype=wintypes.DWORD\n"
                "k.GetHandleInformation.argtypes=(ctypes.c_void_p,ctypes.POINTER(wintypes.DWORD))\n"
                "k.GetHandleInformation.restype=wintypes.BOOL\n"
                "set_ok=int(bool(k.SetEvent(restricted)))\n"
                "wait_code=k.WaitForSingleObject(restricted,0)\n"
                "# Try to consume the signal using the unlisted full-access handle.\n"
                "k.WaitForSingleObject(original,0)\n"
                "Path(sys.argv[1]).joinpath('rights_probe').write_text("
                "f'set={set_ok};wait={wait_code};DONE',"
                "encoding='ascii')\n"
                "time.sleep(30)\n"
            )
            with tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary)
                job = self._job()
                info = self._suspended_python_allowlist(
                    script, root, [restricted.value],
                )
                self._assert_unstarted(root / "rights_probe", info)
                self._check(self.k.AssignProcessToJobObject(
                    job, info.hProcess,
                ))
                self._assert_unstarted(root / "rights_probe", info)
                self.assertNotEqual(
                    self.k.ResumeThread(info.hThread), RESUME_FAILED,
                )
                observation = self._wait_for_marker(root, "rights_probe", info)
                self.assertEqual(
                    observation,
                    f"set=1;wait={WAIT_FAILED};DONE",
                )
                # The signal on the parent's real event must remain unconsumed.
                self.assertEqual(
                    self.k.WaitForSingleObject(original, 0), WAIT_OBJECT_0,
                )
                self._close(job)
                job = None
                self.assertEqual(
                    self.k.WaitForSingleObject(info.hProcess, 5000),
                    WAIT_OBJECT_0,
                )
                print(
                    "WNRA05W_RIGHTS event_modify=true "
                    "synchronize_denied=true unlisted_original=false "
                    "authorization=DENY"
                )
        finally:
            if job:
                self._close(job)
            if info:
                if self.k.WaitForSingleObject(info.hProcess, 0) == WAIT_TIMEOUT:
                    self.k.TerminateProcess(info.hProcess, 1)
                    self.k.WaitForSingleObject(info.hProcess, 5000)
                self._close(info.hThread)
                self._close(info.hProcess)
            if restricted.value:
                self._close(restricted)
            self._close(original)

    def test_sync_only_event_handle_cannot_signal(self):
        # Negative rights matrix complement to WNRA-05W EVENT_MODIFY_STATE only:
        # the child may synchronize but cannot mutate the event state.
        original = self.k.CreateEventW(None, False, False, None)
        self._check(original)
        restricted = wintypes.HANDLE()
        job = None
        info = None
        try:
            current = self.k.GetCurrentProcess()
            self._check(self.k.DuplicateHandle(
                current, original, current, ctypes.byref(restricted),
                PROCESS_SYNCHRONIZE, True, 0,
            ))
            flags = wintypes.DWORD()
            self._check(self.k.GetHandleInformation(
                restricted, ctypes.byref(flags),
            ))
            self.assertTrue(flags.value & HANDLE_FLAG_INHERIT)
            script = (
                "import ctypes,sys,time\n"
                "from ctypes import wintypes\n"
                "from pathlib import Path\n"
                f"restricted={int(restricted.value)}\n"
                f"original={int(original)}\n"
                "k=ctypes.WinDLL('kernel32',use_last_error=True)\n"
                "k.WaitForSingleObject.argtypes=(ctypes.c_void_p,wintypes.DWORD)\n"
                "k.WaitForSingleObject.restype=wintypes.DWORD\n"
                "k.SetEvent.argtypes=(ctypes.c_void_p,)\n"
                "k.SetEvent.restype=wintypes.BOOL\n"
                "k.GetHandleInformation.argtypes=(ctypes.c_void_p,ctypes.POINTER(wintypes.DWORD))\n"
                "k.GetHandleInformation.restype=wintypes.BOOL\n"
                "wait_code=k.WaitForSingleObject(restricted,0)\n"
                "ctypes.set_last_error(0)\n"
                "set_ok=int(bool(k.SetEvent(restricted)))\n"
                "set_error=ctypes.get_last_error()\n"
                "# The unlisted original must not be able to signal the parent.\n"
                "k.SetEvent(original)\n"
                "Path(sys.argv[1]).joinpath('sync_only_probe').write_text("
                "f'wait={wait_code};set={set_ok};error={set_error};DONE',"
                "encoding='ascii')\n"
                "time.sleep(30)\n"
            )
            with tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary)
                job = self._job()
                info = self._suspended_python_allowlist(
                    script, root, [restricted.value],
                )
                self._assert_unstarted(root / "sync_only_probe", info)
                self._check(self.k.AssignProcessToJobObject(job, info.hProcess))
                self._assert_unstarted(root / "sync_only_probe", info)
                self.assertNotEqual(
                    self.k.ResumeThread(info.hThread), RESUME_FAILED,
                )
                observation = self._wait_for_marker(root, "sync_only_probe", info)
                self.assertEqual(
                    observation,
                    f"wait={WAIT_TIMEOUT};set=0;error={ERROR_ACCESS_DENIED};DONE",
                )
                self.assertEqual(
                    self.k.WaitForSingleObject(original, 0), WAIT_TIMEOUT,
                )
                self._close(job)
                job = None
                self.assertEqual(
                    self.k.WaitForSingleObject(info.hProcess, 5000),
                    WAIT_OBJECT_0,
                )
                print(
                    "WNRA05X_EVENT synchronize_allowed=true "
                    "modify_denied=true unlisted_original=false authorization=DENY"
                )
        finally:
            if job:
                self._close(job)
            if info:
                if self.k.WaitForSingleObject(info.hProcess, 0) == WAIT_TIMEOUT:
                    self.k.TerminateProcess(info.hProcess, 1)
                    self.k.WaitForSingleObject(info.hProcess, 5000)
                self._close(info.hThread)
                self._close(info.hProcess)
            if restricted.value:
                self._close(restricted)
            self._close(original)

    def test_query_only_process_handle_cannot_terminate_job_worker(self):
        script = (
            "from pathlib import Path\n"
            "import sys,time\n"
            "Path(sys.argv[1]).joinpath('worker_ready').write_text('READY;DONE')\n"
            "time.sleep(30)\n"
        )
        job = self._job()
        info = None
        query_handle = None
        try:
            with tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary)
                info = self._suspended_python(script, root)
                self._check(self.k.AssignProcessToJobObject(
                    job, info.hProcess,
                ))
                self._assert_unstarted(root / "worker_ready", info)
                query_handle = self.k.OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION,
                    False, info.dwProcessId,
                )
                self._check(query_handle)
                self.assertNotEqual(
                    self.k.ResumeThread(info.hThread), RESUME_FAILED,
                )
                self.assertEqual(
                    self._wait_for_marker(root, "worker_ready", info),
                    "READY;DONE",
                )
                ctypes.set_last_error(0)
                self.assertFalse(self.k.TerminateProcess(query_handle, 1))
                self.assertEqual(ctypes.get_last_error(), ERROR_ACCESS_DENIED)
                ctypes.set_last_error(0)
                self.assertEqual(
                    self.k.WaitForSingleObject(query_handle, 0), WAIT_FAILED,
                )
                self.assertEqual(ctypes.get_last_error(), ERROR_ACCESS_DENIED)
                self.assertEqual(
                    self.k.WaitForSingleObject(info.hProcess, 0), WAIT_TIMEOUT,
                )
                self._close(job)
                job = None
                self.assertEqual(
                    self.k.WaitForSingleObject(info.hProcess, 5000),
                    WAIT_OBJECT_0,
                )
                print(
                    "WNRA05W_PROCESS query_only=true "
                    "terminate_access_denied=true wait_access_denied=true "
                    "job_close_terminated=true "
                    "authorization=DENY"
                )
        finally:
            if job:
                self._close(job)
            if info:
                if self.k.WaitForSingleObject(info.hProcess, 0) == WAIT_TIMEOUT:
                    self.k.TerminateProcess(info.hProcess, 1)
                    self.k.WaitForSingleObject(info.hProcess, 5000)
                self._close(info.hThread)
                self._close(info.hProcess)
            if query_handle:
                self._close(query_handle)

    def test_abort_before_resume_never_runs_worker(self):
        script = (
            "from pathlib import Path\n"
            "import sys,time\n"
            "Path(sys.argv[1]).joinpath('unexpected').write_text('BAD')\n"
            "time.sleep(30)\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            job = self._job()
            info = None
            try:
                info = self._suspended_python(script, root)
                self._check(self.k.AssignProcessToJobObject(job, info.hProcess))
                self._assert_unstarted(root / "unexpected", info)
                # Abort path: never resume. Closing the last job handle terminates it.
                self._close(job)
                job = None
                self.assertEqual(
                    self.k.WaitForSingleObject(info.hProcess, 5000), WAIT_OBJECT_0,
                )
                self.assertFalse((root / "unexpected").exists())
                print(
                    "WNRA05T_ABORT no_resume=true worker_never_executed=true "
                    "authorization=DENY"
                )
            finally:
                if job:
                    self._close(job)
                if info:
                    if self.k.WaitForSingleObject(info.hProcess, 0) == WAIT_TIMEOUT:
                        self.k.TerminateProcess(info.hProcess, 1)
                        self.k.WaitForSingleObject(info.hProcess, 5000)
                    self._close(info.hThread)
                    self._close(info.hProcess)


if __name__ == "__main__":
    unittest.main()

"""Experimental native Windows relative-open for disposable PALACO test fixtures ONLY.

NOT imported by generate_sbom.py or any production entry point.
A caller with arbitrary root-path control must never be considered authorized.
"""

import ctypes
import msvcrt
import os
from ctypes import wintypes

from windows_metadata_name import validate_windows_metadata_basename

if os.name != "nt":
    raise ImportError("native Windows test opener is Windows-only")

_kernel = ctypes.WinDLL("kernel32", use_last_error=True)
_ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

_CREATE = _kernel.CreateFileW
_CREATE.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                    wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
_CREATE.restype = wintypes.HANDLE
_CLOSE = _kernel.CloseHandle
_CLOSE.argtypes = (wintypes.HANDLE,)
_CLOSE.restype = wintypes.BOOL
_INFO = _kernel.GetFileInformationByHandleEx
_INFO.argtypes = (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD)
_INFO.restype = wintypes.BOOL
_TYPE = _kernel.GetFileType
_TYPE.argtypes = (wintypes.HANDLE,)
_TYPE.restype = wintypes.DWORD

class _UnicodeString(ctypes.Structure):
    _fields_ = [("Length", wintypes.USHORT),
                ("MaximumLength", wintypes.USHORT),
                ("Buffer", wintypes.LPWSTR)]

class _ObjectAttributes(ctypes.Structure):
    _fields_ = [("Length", wintypes.ULONG),
                ("RootDirectory", wintypes.HANDLE),
                ("ObjectName", ctypes.POINTER(_UnicodeString)),
                ("Attributes", wintypes.ULONG),
                ("SecurityDescriptor", wintypes.LPVOID),
                ("SecurityQualityOfService", wintypes.LPVOID)]

class _IoStatusBlock(ctypes.Structure):
    _fields_ = [("Status", ctypes.c_void_p),
                ("Information", ctypes.c_size_t)]

class _AttributeTagInfo(ctypes.Structure):
    _fields_ = [("FileAttributes", wintypes.DWORD), ("ReparseTag", wintypes.DWORD)]

_NT_CREATE = _ntdll.NtCreateFile
_NT_CREATE.argtypes = (
    ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD,
    ctypes.POINTER(_ObjectAttributes), ctypes.POINTER(_IoStatusBlock),
    ctypes.c_void_p, wintypes.ULONG, wintypes.ULONG, wintypes.ULONG,
    wintypes.ULONG, ctypes.c_void_p, wintypes.ULONG,
)
_NT_CREATE.restype = ctypes.c_long

_READ = 0x80000000
_SYNCHRONIZE = 0x00100000
_SHARE = 0x1 | 0x2 | 0x4  # test-only: allow concurrent replacement to exercise race gates
_EXISTING = 3
_OPEN_REPARSE = 0x00200000
_BACKUP = 0x02000000
_DISK = 1
_DIR = 0x10
_REPARSE = 0x400
_INVALID = ctypes.c_void_p(-1).value
_NATIVE_FILE_OPEN = 1
_NATIVE_NON_DIR = 0x40
_NATIVE_SYNC = 0x20
_NATIVE_REPARSE = 0x00200000
_TAG_INFO_CLASS = 9
_MAX_BYTES = 20 * 1024 * 1024


def _check_regular_not_reparse(handle, directory=False):
    if _TYPE(handle) != _DISK:
        raise ValueError("test file must be on disk")
    info = _AttributeTagInfo()
    if not _INFO(handle, _TAG_INFO_CLASS, ctypes.byref(info), ctypes.sizeof(info)):
        raise ctypes.WinError(ctypes.get_last_error())
    if info.FileAttributes & _REPARSE:
        raise ValueError("test fixture reparse point rejected")
    is_dir = bool(info.FileAttributes & _DIR)
    if is_dir != directory:
        raise ValueError("test fixture object has wrong directory type")


def read_fixture_metadata_relative(fixture, name):
    """Open a single basename relative to the fixture root HANDLE; close on all exits.

    Caller MUST supply an active disposable BuildRootTestAdapter. No generic root
    path parameter is accepted. This is not a production authorization boundary.
    """
    from windows_build_root_test_adapter import BuildRootTestAdapter

    if type(fixture) is not BuildRootTestAdapter:
        raise TypeError("only disposable build-root test adapter is supported")
    basename = fixture.candidate_name(name)
    root_handle = _CREATE(str(fixture.root), _READ, _SHARE, None,
                          _EXISTING, _BACKUP | _OPEN_REPARSE, None)
    if root_handle in (None, _INVALID):
        raise ctypes.WinError(ctypes.get_last_error())
    child_handle = None
    try:
        _check_regular_not_reparse(root_handle, directory=True)
        # UNICODE_STRING lengths are UTF-16 byte counts, not Python code points.
        # Keep the mutable buffer alive until NtCreateFile has returned.
        encoded_name = basename.encode("utf-16-le")
        name_bytes = len(encoded_name)
        buffer_bytes = name_bytes + 2  # terminating UTF-16 NUL
        if buffer_bytes > 0xffff:
            raise ValueError("metadata basename exceeds native UNICODE_STRING limit")
        buffer = ctypes.create_unicode_buffer(basename)
        u_name = _UnicodeString(name_bytes, buffer_bytes,
                                ctypes.cast(buffer, wintypes.LPWSTR))
        attrs = _ObjectAttributes(ctypes.sizeof(_ObjectAttributes), root_handle,
                                  ctypes.pointer(u_name), 0, None, None)
        io_status = _IoStatusBlock()
        child = wintypes.HANDLE()
        status = _NT_CREATE(
            ctypes.byref(child), _READ | _SYNCHRONIZE, ctypes.byref(attrs),
            ctypes.byref(io_status), None, 0, _SHARE, _NATIVE_FILE_OPEN,
            _NATIVE_NON_DIR | _NATIVE_SYNC | _NATIVE_REPARSE, None, 0
        )
        if status < 0:
            raise OSError("NtCreateFile denied relative test open: NTSTATUS 0x%08x" % (status & 0xffffffff))
        child_handle = child.value
        _check_regular_not_reparse(child_handle, directory=False)
        fd = msvcrt.open_osfhandle(child_handle, os.O_RDONLY | os.O_BINARY)
        if fd == -1:
            raise OSError("could not transfer test child handle")
        child_handle = None
        # open_osfhandle transfers the native HANDLE to the CRT descriptor.
        # If fdopen fails before taking ownership, explicitly close that fd.
        try:
            reader = os.fdopen(fd, "rb")
        except BaseException:
            os.close(fd)
            raise
        with reader:
            data = reader.read(_MAX_BYTES + 1)
        if len(data) > _MAX_BYTES:
            raise ValueError("oversized test metadata")
        return data
    finally:
        if child_handle is not None:
            _CLOSE(child_handle)
        _CLOSE(root_handle)

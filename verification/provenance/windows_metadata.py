"""Fail-closed Windows handle boundary for untrusted Cargo metadata files.

This module is imported only on Windows. Parent-directory containment is not
established here; callers must use an independently trusted parent path.
"""

import ctypes
import msvcrt
import os
from ctypes import wintypes


_KERNEL = ctypes.WinDLL("kernel32", use_last_error=True)
_CREATE = _KERNEL.CreateFileW
_CREATE.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                    wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
_CREATE.restype = wintypes.HANDLE
_GET_TYPE = _KERNEL.GetFileType
_GET_TYPE.argtypes = [wintypes.HANDLE]
_GET_TYPE.restype = wintypes.DWORD
_GET_INFO = _KERNEL.GetFileInformationByHandleEx
_GET_INFO.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
_GET_INFO.restype = wintypes.BOOL
_CLOSE = _KERNEL.CloseHandle
_CLOSE.argtypes = [wintypes.HANDLE]
_CLOSE.restype = wintypes.BOOL

_READ = 0x80000000
_SHARE_READ = 0x1
_SHARE_DELETE = 0x4
_OPEN_EXISTING = 3
_OPEN_REPARSE = 0x00200000
_NORMAL = 0x80
_FILE_TYPE_DISK = 1
_REPARSE_ATTRIBUTE = 0x400
_DIRECTORY_ATTRIBUTE = 0x10
_FILE_ATTRIBUTE_TAG_INFO = 9
_INVALID_HANDLE = ctypes.c_void_p(-1).value


class _AttributeTagInfo(ctypes.Structure):
    _fields_ = [("FileAttributes", wintypes.DWORD),
                ("ReparseTag", wintypes.DWORD)]


def _win_error():
    return ctypes.WinError(ctypes.get_last_error())


def open_regular_file(path):
    """Return an owned binary fd to a non-reparse disk file, or fail closed.

    No path-based security checks are made after opening. The native handle is
    transferred to the CRT only after its attributes have been checked.
    """
    handle = _CREATE(os.fspath(path), _READ, _SHARE_READ | _SHARE_DELETE,
                     None, _OPEN_EXISTING, _OPEN_REPARSE | _NORMAL, None)
    if handle in (None, _INVALID_HANDLE):
        raise _win_error()
    try:
        if _GET_TYPE(handle) != _FILE_TYPE_DISK:
            raise ValueError("Cargo metadata must be a regular disk file")
        info = _AttributeTagInfo()
        if not _GET_INFO(handle, _FILE_ATTRIBUTE_TAG_INFO, ctypes.byref(info),
                         ctypes.sizeof(info)):
            raise _win_error()
        if info.FileAttributes & (_REPARSE_ATTRIBUTE | _DIRECTORY_ATTRIBUTE):
            raise ValueError("Cargo metadata must not be a reparse point or directory")
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
        if fd == -1:
            raise OSError("could not transfer Windows metadata handle")
        # open_osfhandle transfers ownership of the OS handle to the CRT.
        handle = None
        return fd
    finally:
        if handle is not None:
            _CLOSE(handle)

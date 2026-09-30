"""Fail-closed Windows handle backend for local NTFS only.

No path check is followed by a path reopen: every component is opened relative
 to a retained directory handle. Native workers remain separately unsupported.
"""
from __future__ import annotations

import contextlib
import ctypes as _ctypes
import os
import re
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any, ClassVar

ctypes: Any = _ctypes

if os.name == "nt":
    import msvcrt as _msvcrt
    msvcrt: Any = _msvcrt
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll")

    class UnicodeString(ctypes.Structure):
        _fields_: ClassVar[list[tuple[str, Any]]] = [("Length", wintypes.USHORT), ("MaximumLength", wintypes.USHORT), ("Buffer", wintypes.LPWSTR)]

    class ObjectAttributes(ctypes.Structure):
        _fields_: ClassVar[list[tuple[str, Any]]] = [("Length", wintypes.ULONG), ("RootDirectory", wintypes.HANDLE),
                    ("ObjectName", ctypes.POINTER(UnicodeString)), ("Attributes", wintypes.ULONG),
                    ("SecurityDescriptor", wintypes.LPVOID), ("SecurityQualityOfService", wintypes.LPVOID)]

    class IoStatus(ctypes.Structure):
        _fields_: ClassVar[list[tuple[str, Any]]] = [("Status", ctypes.c_void_p), ("Information", ctypes.c_size_t)]

    class FileInfo(ctypes.Structure):
        _fields_: ClassVar[list[tuple[str, Any]]] = [("attributes", wintypes.DWORD), ("creation", wintypes.FILETIME),
                    ("access", wintypes.FILETIME), ("write", wintypes.FILETIME),
                    ("volume", wintypes.DWORD), ("size_high", wintypes.DWORD), ("size_low", wintypes.DWORD),
                    ("links", wintypes.DWORD), ("index_high", wintypes.DWORD), ("index_low", wintypes.DWORD)]

    class Overlapped(ctypes.Structure):
        _fields_: ClassVar[list[tuple[str, Any]]] = [("Internal", ctypes.c_size_t), ("InternalHigh", ctypes.c_size_t),
                    ("Offset", wintypes.DWORD), ("OffsetHigh", wintypes.DWORD), ("event", wintypes.HANDLE)]

    def _api(dll: Any, name: str, args: list[Any], result: Any) -> Any:
        function = getattr(dll, name)
        function.argtypes, function.restype = args, result
        return function

    close = _api(kernel, "CloseHandle", [wintypes.HANDLE], wintypes.BOOL)
    create = _api(kernel, "CreateFileW", [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                   wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE], wintypes.HANDLE)
    ntcreate = _api(ntdll, "NtCreateFile", [ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD,
                   ctypes.POINTER(ObjectAttributes), ctypes.POINTER(IoStatus), wintypes.LPVOID,
                   wintypes.ULONG, wintypes.ULONG, wintypes.ULONG, wintypes.ULONG,
                   wintypes.LPVOID, wintypes.ULONG], ctypes.c_long)
    nt_error = _api(ntdll, "RtlNtStatusToDosError", [wintypes.ULONG], wintypes.ULONG)
    info = _api(kernel, "GetFileInformationByHandle", [wintypes.HANDLE, ctypes.POINTER(FileInfo)], wintypes.BOOL)
    volume_info = _api(kernel, "GetVolumeInformationByHandleW", [wintypes.HANDLE, wintypes.LPWSTR,
                       wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
                       ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR, wintypes.DWORD], wintypes.BOOL)
    drive_type = _api(kernel, "GetDriveTypeW", [wintypes.LPCWSTR], wintypes.UINT)
    lock_file = _api(kernel, "LockFileEx", [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
                     wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(Overlapped)], wintypes.BOOL)
    unlock_file = _api(kernel, "UnlockFileEx", [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
                       wintypes.DWORD, ctypes.POINTER(Overlapped)], wintypes.BOOL)
    flush_file = _api(kernel, "FlushFileBuffers", [wintypes.HANDLE], wintypes.BOOL)


_RESERVED = re.compile(r"^(CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)", re.IGNORECASE)


def components(raw: str) -> list[str]:
    """Windows has aliases and namespaces that POSIX does not."""
    if not raw or "\\" in raw or any(c in raw for c in '\x00:<>"|?*'):
        raise ValueError("unsupported Windows path")
    parts = raw.split("/")
    if any(not p or p in {".", ".."} or p.endswith((".", " ")) or _RESERVED.match(p)
           or any(ord(c) < 32 for c in p) for p in parts):
        raise ValueError("unsupported Windows path component")
    return parts


def _require() -> None:
    if os.name != "nt":
        raise OSError("Windows backend requires native Windows")


def _check(handle: Any, directory: bool) -> None:
    details = FileInfo()
    if not info(handle, ctypes.byref(details)):
        raise ctypes.WinError(ctypes.get_last_error())
    if details.attributes & 0x400 or bool(details.attributes & 0x10) != directory:
        raise ValueError("reparse point or unexpected file type")
    if not directory and details.links != 1:
        raise ValueError("hard-linked files are unsupported")
    filesystem = ctypes.create_unicode_buffer(32)
    if not volume_info(handle, None, 0, None, None, None, filesystem, len(filesystem)):
        raise ctypes.WinError(ctypes.get_last_error())
    if filesystem.value != "NTFS":
        raise ValueError("native Windows backend supports local NTFS only")


def _relative(parent: Any, name: str, *, directory: bool, write: bool = False,
              create_missing: bool = False, audit: bool = False) -> Any:
    # One validated component, never a multi-component path.
    components(name)
    buffer = ctypes.create_unicode_buffer(name)
    encoded_length = len(name.encode("utf-16-le"))
    if encoded_length > 65532:
        raise ValueError("Windows component too long")
    text = UnicodeString(encoded_length, encoded_length + 2, ctypes.cast(buffer, wintypes.LPWSTR))
    attrs = ObjectAttributes(ctypes.sizeof(ObjectAttributes), parent, ctypes.pointer(text), 0x40, None, None)
    result, status = wintypes.HANDLE(), IoStatus()
    # Directories are pinned without write/delete sharing. A reparse mutation
    # or ancestor rename is refused while the operation holds these handles.
    access = 0x100000 | 0x80 | (0x21 if directory else (0x3 if write else 0x1))
    share = 0x3 if audit else (0x1 if directory or not write else 0)
    options = 0x200000 | 0x20 | (0x1 if directory else 0x40)
    code = ntcreate(ctypes.byref(result), access, ctypes.byref(attrs), ctypes.byref(status),
                    None, 0x80, share, 3 if create_missing else 1, options, None, 0)
    if code < 0:
        raise ctypes.WinError(nt_error(code & 0xffffffff))
    try:
        _check(result, directory)
        return result
    except BaseException:
        close(result)
        raise


@contextlib.contextmanager
def directory_handles(path: Path, *, create_missing: bool = False) -> Iterator[list[Any]]:
    """Anchor at a fixed local drive, then retain every directory handle."""
    _require()
    absolute = os.path.abspath(path)
    if not re.match(r"^[A-Za-z]:\\", absolute) or absolute.startswith("\\"):
        raise ValueError("UNC and device namespace workspaces are unsupported")
    drive = absolute[:3]
    if drive_type(drive) != 3:
        raise ValueError("workspace must be on a fixed local drive")
    tail = absolute[3:].replace("\\", "/")
    parts = components(tail) if tail else []
    root = create(drive, 0x100000 | 0x80 | 0x21, 1, None, 3, 0x2200000, None)
    if root == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    held = [root]
    try:
        _check(root, True)
        for part in parts:
            held.append(_relative(held[-1], part, directory=True, create_missing=create_missing))
        yield held
    finally:
        for handle in reversed(held):
            close(handle)


@contextlib.contextmanager
def file_handle(workspace: Path, raw: str, *, write: bool = False,
                audit: bool = False) -> Iterator[Any]:
    parts = components(raw)
    with directory_handles(workspace, create_missing=audit) as held:
        try:
            for part in parts[:-1]:
                held.append(_relative(held[-1], part, directory=True, create_missing=write))
            handle = _relative(held[-1], parts[-1], directory=False, write=write,
                               create_missing=write, audit=audit)
            try:
                yield handle
            finally:
                close(handle)
        finally:
            # directory_handles owns the complete retained list, including
            # components appended here. No pathname is reopened after checks.
            pass


def _duplicate_fd(handle: Any) -> int:
    # Transfer a duplicate to the CRT, leaving the original context-owned.
    duplicate = wintypes.HANDLE()
    duplicate_api = _api(kernel, "DuplicateHandle", [wintypes.HANDLE, wintypes.HANDLE,
                         wintypes.HANDLE, ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD,
                         wintypes.BOOL, wintypes.DWORD], wintypes.BOOL)
    process = _api(kernel, "GetCurrentProcess", [], wintypes.HANDLE)()
    if not duplicate_api(process, handle, process, ctypes.byref(duplicate), 0, False, 2):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return msvcrt.open_osfhandle(duplicate.value, getattr(os, "O_BINARY", 0x8000) | os.O_RDWR)
    except BaseException:
        close(duplicate)
        raise


def read_text(workspace: Path, raw: str) -> str:
    with file_handle(workspace, raw) as handle, os.fdopen(_duplicate_fd(handle), "r", encoding="utf-8") as stream:
        return stream.read()


def write_text(workspace: Path, raw: str, content: str) -> str:
    with file_handle(workspace, raw, write=True) as handle, os.fdopen(_duplicate_fd(handle), "r+b") as stream:
        # Handle is validated and exclusive before destructive work.
        stream.truncate(0)
        stream.write(content.encode("utf-8"))
        stream.flush()
        if not flush_file(handle):
            raise ctypes.WinError(ctypes.get_last_error())
    return f"wrote {raw}"


@contextlib.contextmanager
def audit_stream(path: Path, timeout: float = 10) -> Iterator[Any]:
    with file_handle(path.parent, path.name, write=True, audit=True) as handle:
        overlap = Overlapped()
        deadline = time.monotonic() + timeout
        while not lock_file(handle, 3, 0, 0xffffffff, 0xffffffff, ctypes.byref(overlap)):
            error = ctypes.get_last_error()
            if error != 33:
                raise ctypes.WinError(error)
            if time.monotonic() >= deadline:
                raise TimeoutError("audit lock timed out")
            time.sleep(min(0.01, max(0, deadline - time.monotonic())))
        try:
            with os.fdopen(_duplicate_fd(handle), "r+b") as stream:
                yield stream
                stream.flush()
                if not flush_file(handle):
                    raise ctypes.WinError(ctypes.get_last_error())
        finally:
            if not unlock_file(handle, 0, 0xffffffff, 0xffffffff, ctypes.byref(overlap)):
                raise ctypes.WinError(ctypes.get_last_error())

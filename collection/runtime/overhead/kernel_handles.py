"""Use Linux process handles through Python or the host libc interface."""

from __future__ import annotations

import ctypes
import os
import signal


def open_handle(pid: int) -> int:
    native = getattr(os, "pidfd_open", None)
    if native is not None:
        return int(native(pid))
    function = ctypes.CDLL(None, use_errno=True).pidfd_open
    function.argtypes = (ctypes.c_int, ctypes.c_uint)
    function.restype = ctypes.c_int
    result = function(pid, 0)
    if result < 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    return int(result)


def send_handle(descriptor: int, number: int) -> None:
    native = getattr(signal, "pidfd_send_signal", None)
    if native is not None:
        native(descriptor, number)
        return
    function = ctypes.CDLL(None, use_errno=True).pidfd_send_signal
    function.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint)
    function.restype = ctypes.c_int
    if function(descriptor, number, None, 0) < 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


def probe() -> None:
    descriptor = open_handle(os.getpid())
    try:
        send_handle(descriptor, 0)
    finally:
        os.close(descriptor)

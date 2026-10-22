"""Fast Windows process stats: ONE NtQuerySystemInformation call for all processes.

psutil asks per process; for protected system processes it falls back to a full system
scan each time (O(n^2), ~2.5 s per sample on a busy PC). This reads everything once (~10 ms).
Layout: SYSTEM_PROCESS_INFORMATION (x64), as used by psutil / Process Hacker.
"""
import ctypes
import struct
import sys
from typing import NamedTuple

SystemProcessInformation = 5
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004


class ProcStat(NamedTuple):
    name: str
    cpu_time: float      # user + kernel seconds
    rss: int             # working set bytes (same as psutil memory_info().rss)
    io_bytes: int        # read + write transfer bytes
    create_time: int     # raw FILETIME (only used to detect PID reuse)


_ntdll = None
if sys.platform == "win32" and struct.calcsize("P") == 8:
    try:
        _ntdll = ctypes.WinDLL("ntdll")
        _ntdll.NtQuerySystemInformation.restype = ctypes.c_ulong
    except OSError:
        _ntdll = None

_buf_size = 1 << 20


def available() -> bool:
    return _ntdll is not None


def snapshot() -> dict[int, ProcStat] | None:
    """{pid: ProcStat} for every process, or None if not supported here."""
    global _buf_size
    if _ntdll is None:
        return None
    for _ in range(5):
        buf = ctypes.create_string_buffer(_buf_size)
        ret_len = ctypes.c_ulong(0)
        status = _ntdll.NtQuerySystemInformation(SystemProcessInformation, buf, _buf_size,
                                                 ctypes.byref(ret_len))
        if status == STATUS_INFO_LENGTH_MISMATCH:
            _buf_size = max(_buf_size * 2, ret_len.value + 65536)
            continue
        if status != 0:
            return None
        break
    else:
        return None

    raw = buf.raw
    base = ctypes.addressof(buf)
    out: dict[int, ProcStat] = {}
    offset = 0
    while True:
        (next_off,) = struct.unpack_from("<I", raw, offset)
        create, user, kernel = struct.unpack_from("<qqq", raw, offset + 32)
        name_len, _, name_ptr = struct.unpack_from("<HHxxxxQ", raw, offset + 56)
        (pid,) = struct.unpack_from("<Q", raw, offset + 80)
        (rss,) = struct.unpack_from("<Q", raw, offset + 144)
        read_b, write_b = struct.unpack_from("<QQ", raw, offset + 232)
        name = ""
        if name_ptr and name_len:
            start = name_ptr - base           # pointer into our own buffer
            if 0 <= start < len(raw):
                name = raw[start:start + name_len].decode("utf-16-le", errors="replace")
        out[pid] = ProcStat(name, (user + kernel) / 1e7, rss, read_b + write_b, create)
        if next_off == 0:
            break
        offset += next_off
    return out

"""検査プロセスの資源の守り（Windows の Job Object と空きメモリ）。

- 検査プロセス（ワーカー）は起動直後に自分を Job Object に入れる。時間切れ・中止でワーカーが打ち切られると
  Job の最後のハンドルが閉じ、子の 7-Zip・pg_restore・32bit 補助なども一緒に終わる（元のファイルや一時フォルダを
  開いたまま残らない）。
- 同じ Job で1プロセスあたりのメモリに上限を掛ける。大きすぎるファイルはそのファイルだけ「メモリ不足」で
  検査不能になり、他のワーカーや画面・結果の保存を巻き込まない。
- ワーカー数は CPU の数だけでなく空きメモリからも決める（上限×ワーカー数が空きの7割に収まるように）。
"""

from __future__ import annotations

import os

GB = 1024**3
MIN_LIMIT = int(1.5 * GB)
MAX_LIMIT = 4 * GB

_job_handle = None  # ワーカーが生きている間は閉じない（閉じると自分ごと終わる）


def memory_status() -> tuple[int, int]:
    """(物理メモリの合計, いま使える量)。分からなければ (0, 0)。"""
    if os.name != "nt":
        return 0, 0
    import ctypes
    from ctypes import wintypes

    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ("dwLength", wintypes.DWORD),
            ("dwMemoryLoad", wintypes.DWORD),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    st = MEMORYSTATUSEX()
    st.dwLength = ctypes.sizeof(st)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st)):
        return 0, 0
    return int(st.ullTotalPhys), int(st.ullAvailPhys)


def per_worker_limit(total: int | None = None) -> int:
    """1ワーカーのメモリ上限（物理メモリの1/4を 1.5GB〜4GB に収める）。"""
    if total is None:
        total, _ = memory_status()
    if not total:
        return MAX_LIMIT
    return max(MIN_LIMIT, min(MAX_LIMIT, total // 4))


def plan_workers(requested: int | None = None) -> tuple[int, int]:
    """(ワーカー数, 1ワーカーのメモリ上限) を決める。指定があっても空きメモリで収まる数までにする。"""
    cpu = max(1, min(8, (os.cpu_count() or 2) - 1))
    total, avail = memory_status()
    limit = per_worker_limit(total)
    by_memory = max(1, int(avail * 0.7) // limit) if avail else cpu
    want = requested or cpu
    return max(1, min(want, by_memory)), limit


def worker_init(memory_limit: int) -> None:
    """ワーカーの起動時に呼ぶ（pebble の initializer）。失敗しても検査は続ける。"""
    global _job_handle
    if os.name != "nt" or _job_handle is not None:
        return
    import ctypes
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [(n, ctypes.c_ulonglong) for n in ("r_ops", "w_ops", "o_ops", "r_bytes", "w_bytes", "o_bytes")]

    class BASIC(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class EXTENDED(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BASIC),
            ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x100
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
    JobObjectExtendedLimitInformation = 9

    k32.CreateJobObjectW.restype = wintypes.HANDLE
    k32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    k32.GetCurrentProcess.restype = wintypes.HANDLE
    job = k32.CreateJobObjectW(None, None)
    if not job:
        return
    info = EXTENDED()
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if memory_limit:
        info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY
        info.ProcessMemoryLimit = memory_limit
    if not k32.SetInformationJobObject(job, JobObjectExtendedLimitInformation, ctypes.byref(info), ctypes.sizeof(info)):
        k32.CloseHandle(job)
        return
    if not k32.AssignProcessToJobObject(job, k32.GetCurrentProcess()):
        k32.CloseHandle(job)
        return
    _job_handle = job

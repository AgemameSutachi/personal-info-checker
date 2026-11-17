"""検査プロセスの守り（procguard）の、Windows の関数を偽物に差し替えた試験。

本物の Job Object に入れる試験（tests/test_procguard.py）は別のプロセスで走るので網羅率に出ない。ここでは
試験のプロセス自身を Job に入れずに、失敗したときに作った Job のハンドルを閉じて検査を続けることを確かめる。
"""

import ctypes
import os

import pytest

from pii_checker import procguard

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows の Job Object の試験")

GB = 1024**3


class FakeKernel32:
    """worker_init が呼ぶ関数の偽物（restype・argtypes を付けられるように、関数を属性として持つ）。"""

    def __init__(self, create=77, set_ok=1, assign_ok=1):
        self.calls = []
        self.limits = []

        def create_job(attrs, name):
            self.calls.append("create")
            return create

        def set_info(job, cls, info, size):
            self.calls.append("set")
            ext = ctypes.cast(info, ctypes.POINTER(ctypes.c_char * size)).contents
            self.limits.append(bytes(ext))
            return set_ok

        def assign(job, proc):
            self.calls.append("assign")
            return assign_ok

        def close(h):
            self.calls.append(("close", h))
            return 1

        self.CreateJobObjectW = create_job
        self.SetInformationJobObject = set_info
        self.AssignProcessToJobObject = assign
        self.GetCurrentProcess = lambda: -1
        self.CloseHandle = close


@pytest.fixture
def k32(monkeypatch):
    holder = {}

    def windll(name, use_last_error=False):
        assert name == "kernel32"
        return holder["fake"]

    monkeypatch.setattr(ctypes, "WinDLL", windll)
    monkeypatch.setattr(procguard, "_job_handle", None)

    def use(**kw):
        holder["fake"] = FakeKernel32(**kw)
        return holder["fake"]

    return use


def test_worker_init_keeps_job_handle(k32):
    fake = k32()
    procguard.worker_init(2 * GB)
    assert procguard._job_handle == 77
    assert fake.calls == ["create", "set", "assign"]  # 閉じない（閉じると自分ごと終わる）


def test_worker_init_sets_memory_limit_only_when_given(k32):
    with_limit = k32()
    procguard.worker_init(2 * GB)
    procguard._job_handle = None
    without = k32()
    procguard.worker_init(0)
    # 上限の旗（0x100）と上限の値の分だけ、渡した構造体が違う
    assert with_limit.limits[0] != without.limits[0]
    assert (2 * GB).to_bytes(8, "little") in with_limit.limits[0]
    assert (2 * GB).to_bytes(8, "little") not in without.limits[0]


def test_worker_init_gives_up_when_job_cannot_be_created(k32):
    fake = k32(create=0)
    procguard.worker_init(GB)
    assert procguard._job_handle is None
    assert fake.calls == ["create"]


def test_worker_init_closes_job_when_limit_cannot_be_set(k32):
    fake = k32(set_ok=0)
    procguard.worker_init(GB)
    assert procguard._job_handle is None
    assert fake.calls == ["create", "set", ("close", 77)]


def test_worker_init_closes_job_when_process_cannot_join(k32):
    fake = k32(assign_ok=0)
    procguard.worker_init(GB)
    assert procguard._job_handle is None
    assert fake.calls == ["create", "set", "assign", ("close", 77)]


def test_worker_init_runs_only_once(k32):
    fake = k32()
    procguard._job_handle = 5  # 既に Job に入っている
    procguard.worker_init(GB)
    assert fake.calls == []
    assert procguard._job_handle == 5


def test_memory_status_reads_this_pc():
    total, avail = procguard.memory_status()
    assert total > 0 and 0 < avail <= total


def test_memory_status_failure_is_unknown(monkeypatch):
    class K32:
        @staticmethod
        def GlobalMemoryStatusEx(p):  # noqa: N802
            return 0

    class Dll:
        kernel32 = K32()

    monkeypatch.setattr(ctypes, "windll", Dll())
    assert procguard.memory_status() == (0, 0)


@pytest.mark.parametrize(
    "total,limit",
    [(0, 4 * GB), (4 * GB, int(1.5 * GB)), (8 * GB, 2 * GB), (64 * GB, 4 * GB)],
)
def test_per_worker_limit(total, limit):
    assert procguard.per_worker_limit(total) == limit


def test_per_worker_limit_reads_memory_when_not_given(monkeypatch):
    monkeypatch.setattr(procguard, "memory_status", lambda: (12 * GB, 1))
    assert procguard.per_worker_limit() == 3 * GB

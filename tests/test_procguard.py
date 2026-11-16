"""検査プロセスの守り（Job Object・メモリ上限・ワーカー数）の試験。"""

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from pii_checker import procguard

ROOT = str(Path(__file__).resolve().parent.parent)
pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows の Job Object の試験")


def _run(code: str, **kw) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, "-c", f"import sys; sys.path.insert(0, {ROOT!r}); " + code],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        **kw,
    )


def test_memory_limit_raises_memory_error():
    p = _run(
        "from pii_checker import procguard; procguard.worker_init(300 * 1024**2)\n"
        "try:\n    b = bytearray(600 * 1024**2)\n    print('ALLOCATED')\n"
        "except MemoryError:\n    print('MEMERR')\n"
    )
    out, err = p.communicate(timeout=60)
    assert "MEMERR" in out, (out, err)


def test_without_limit_allocates():
    """陽性対照: 上限を掛けなければ同じ量を確保できる（上の試験が上限のおかげで落ちていることの確かめ）。"""
    p = _run("b = bytearray(600 * 1024**2); print('ALLOCATED')")
    out, err = p.communicate(timeout=60)
    assert "ALLOCATED" in out, (out, err)


def _alive(pid: int) -> bool:
    out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"], capture_output=True, text=True).stdout
    return str(pid) in out


def test_children_die_with_worker():
    p = _run(
        "import subprocess, sys, time\n"
        "from pii_checker import procguard; procguard.worker_init(0)\n"
        "c = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])\n"
        "print(c.pid, flush=True)\n"
        "time.sleep(120)\n"
    )
    child = int(p.stdout.readline())
    assert _alive(child)
    p.kill()  # 時間切れの打ち切りと同じ（TerminateProcess）
    p.wait(timeout=30)
    for _ in range(50):
        if not _alive(child):
            break
        time.sleep(0.2)
    assert not _alive(child)


def test_plan_workers_respects_memory(monkeypatch):
    gb = 1024**3
    monkeypatch.setattr(procguard, "memory_status", lambda: (16 * gb, 6 * gb))
    workers, limit = procguard.plan_workers(8)
    assert limit == 4 * gb
    assert workers == 1  # 6GB の7割 = 4.2GB に 4GB のワーカーは1つだけ
    monkeypatch.setattr(procguard, "memory_status", lambda: (64 * gb, 60 * gb))
    workers, _ = procguard.plan_workers(None)
    assert 1 <= workers <= procguard.MAX_AUTO_WORKERS


def test_plan_workers_counts_full_limit_only_for_big_files(monkeypatch):
    """上限を丸ごと見込むのは大きなファイルの本数分だけ。残りはふつうの使用量で見込む。"""
    gb = 1024**3
    monkeypatch.setattr(procguard.os, "cpu_count", lambda: 16)
    # 空き 28GB の7割 = 19.6GB: 4GB×2本 + 1GB×11本 = 13本 → 自動の上限 12 本
    monkeypatch.setattr(procguard, "memory_status", lambda: (64 * gb, 28 * gb))
    assert procguard.plan_workers(None) == (12, 4 * gb)
    assert procguard.plan_workers(16) == (13, 4 * gb)  # 指定は自動の上限を超えてよいが空きメモリで絞る
    # 空き 10GB の7割 = 7GB: 4GB×1本 + 1GB×3本 = 4本だが、4本だと大きなファイルを2本配るので3本（前は1本だった）
    monkeypatch.setattr(procguard, "memory_status", lambda: (16 * gb, 10 * gb))
    assert procguard.plan_workers(8) == (3, 4 * gb)
    # 空き 12GB の7割 = 8.4GB: 4GB×2本 + 0本では4本に届かないので、大きなファイルを1本ずつにして3本（空きが増えて本数が減らない）
    monkeypatch.setattr(procguard, "memory_status", lambda: (16 * gb, 12 * gb))
    assert procguard.plan_workers(8) == (3, 4 * gb)
    # 空き 20GB の7割 = 14GB: 4GB×2本 + 1GB×6本 = 8本
    monkeypatch.setattr(procguard, "memory_status", lambda: (32 * gb, 20 * gb))
    assert procguard.plan_workers(None) == (8, 4 * gb)
    # 空きが上限1本分に満たなければ1本
    monkeypatch.setattr(procguard, "memory_status", lambda: (16 * gb, 5 * gb))
    assert procguard.plan_workers(8) == (1, 4 * gb)
    # 分からなければ CPU の数から
    monkeypatch.setattr(procguard, "memory_status", lambda: (0, 0))
    assert procguard.plan_workers(None)[0] == 12


def test_plan_workers_small_memory_pc(monkeypatch):
    """物理メモリが少ない PC（上限が 4GB より小さい）でも、大きなファイルを1本ずつにして本数を出す。"""
    gb = 1024**3
    monkeypatch.setattr(procguard.os, "cpu_count", lambda: 8)
    # 物理 8GB → 上限 2GB。空き 6GB の7割 = 4.2GB: 2GB×2本 + 1GB×0本では4本に届かないので、2GB×1本 + 1GB×2本 = 3本
    monkeypatch.setattr(procguard, "memory_status", lambda: (8 * gb, 6 * gb))
    assert procguard.plan_workers(None) == (3, 2 * gb)
    # 空き 3GB の7割 = 2.1GB: 上限1本分だけ
    monkeypatch.setattr(procguard, "memory_status", lambda: (8 * gb, 3 * gb))
    assert procguard.plan_workers(None) == (1, 2 * gb)


def test_full_limit_workers_matches_runner():
    from pii_checker import runner

    assert procguard.FULL_LIMIT_WORKERS == runner.BIG_FILE_CONCURRENCY

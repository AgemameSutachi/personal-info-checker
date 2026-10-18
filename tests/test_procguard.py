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
    assert 1 <= workers <= 8

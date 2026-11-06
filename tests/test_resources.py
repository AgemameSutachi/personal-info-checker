"""資源不足（一時フォルダ・結果 DB のドライブ）と、残った一時フォルダの片付けの試験。"""

import os
import sqlite3

import pytest

from pii_checker import engine, runner, safeio
from pii_checker.engine import OWNER_MARK, TEMP_PREFIX, ScanContext
from pii_checker.models import ScanOptions, Status
from pii_checker.store import Store


def _tempdir(base, name, marker_open=False, marker=True):
    d = base / f"{TEMP_PREFIX}{name}"
    d.mkdir()
    (d / "member.bin").write_bytes(b"x")
    f = None
    if marker:
        f = open(d / OWNER_MARK, "wb")
        if not marker_open:
            f.close()
            f = None
    return d, f


@pytest.fixture(autouse=True)
def _own_system_temp(tmp_path, monkeypatch):
    """片付けはシステムの一時フォルダも見るので、試験ごとの空のフォルダに差し替える。

    差し替えないと、その PC に残っていた本物の一時フォルダまで数え（数が合わずに落ちる）、片付けてしまう。
    """
    import tempfile

    own = tmp_path / "systemp"
    own.mkdir()
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(own))


def test_cleanup_keeps_live_owner_and_removes_dead(tmp_path):
    live, handle = _tempdir(tmp_path, "live", marker_open=True)
    dead, _ = _tempdir(tmp_path, "dead")
    fresh_nomark, _ = _tempdir(tmp_path, "fresh", marker=False)
    other = tmp_path / "keep_me"
    other.mkdir()
    try:
        removed = runner.cleanup_stale_temp([str(tmp_path)])
        assert live.exists() and (live / "member.bin").exists()  # 動いているジョブのものは消さない
        assert not dead.exists()
        assert fresh_nomark.exists()  # 目印を置く前かもしれないので猶予の間は残す
        assert other.exists()  # 名前の頭が違うものは触らない
        assert removed == 1
    finally:
        handle.close()
    runner.cleanup_stale_temp([str(tmp_path)], no_mark_grace=0)
    assert not live.exists() and not fresh_nomark.exists()


def test_cleanup_removes_read_only_members(tmp_path):
    """展開した中身の読み取り専用のファイルがあっても片付け、消せたものだけを数える（Windows で残っていた不具合）。"""
    import stat

    dead, _ = _tempdir(tmp_path, "readonly")
    (dead / "sub").mkdir()
    for p in (dead / "member.bin", dead / "sub" / "a.txt"):
        p.write_bytes(b"x")
        os.chmod(p, stat.S_IREAD)
    assert runner.cleanup_stale_temp([str(tmp_path)]) == 1
    assert not dead.exists()


def test_context_marks_and_cleans(tmp_path):
    ctx = ScanContext("x", ScanOptions(temp_dir=str(tmp_path)), [])
    d = ctx.tmpdir
    assert os.path.exists(os.path.join(d, OWNER_MARK))
    assert runner.cleanup_stale_temp([str(tmp_path)]) == 0  # 持ち主がいる間は消せない
    ctx.cleanup()
    assert not os.path.exists(d)


def test_nested_without_space_is_uncheckable(tmp_path, monkeypatch):
    monkeypatch.setattr(engine, "IN_MEMORY_LIMIT", 10)
    monkeypatch.setattr(safeio, "free_bytes", lambda folder: 1)
    ctx = ScanContext("top", ScanOptions(temp_dir=str(tmp_path)), [])
    try:
        item = ctx.scan_nested("top!big.txt", data=b"y" * 100, depth=1)
        small = ctx.scan_nested("top!small.txt", data=b"abc", depth=1)
    finally:
        ctx.cleanup()
    assert item.status == Status.UNCHECKABLE and "空きが足りない" in item.reason
    assert small.status == Status.SCANNED  # 残りの中身は続けて検査する


def test_scan_file_temp_full(tmp_path, monkeypatch):
    src = tmp_path / "a.txt"
    src.write_text("山田太郎", encoding="utf-8")
    monkeypatch.setattr(safeio, "free_bytes", lambda folder: 1)
    res = engine.scan_file(str(src), ScanOptions(temp_dir=str(tmp_path)))
    assert res.items[0].status == Status.UNCHECKABLE
    assert "空きが足りない" in res.items[0].reason


def _job(tmp_path, n=3):
    folder = tmp_path / "data"
    folder.mkdir()
    for i in range(n):
        (folder / f"f{i}.txt").write_text(f"電話 090-1234-56{i:02d}", encoding="utf-8")
    store = Store(str(tmp_path / "jobs.sqlite3"))
    job_id = store.create_job([str(folder)], ScanOptions(temp_dir=str(tmp_path)))
    return store, job_id


def test_db_full_halts_and_resumes(tmp_path, monkeypatch):
    store, job_id = _job(tmp_path)

    def full(*a, **k):
        raise sqlite3.OperationalError("database or disk is full")

    monkeypatch.setattr(store, "save_result", full)
    r = runner.JobRunner(store, job_id, workers=1)
    r.start()
    r.wait(120)
    job = store.job(job_id)
    assert job["state"] == "interrupted"
    assert "空きが無くなった" in job["message"]
    assert store.summary(job_id)["files_done"] == 0  # 未検査のまま残る（再開で続きから）

    monkeypatch.undo()
    r2 = runner.JobRunner(store, job_id, workers=1)
    r2.start()
    r2.wait(120)
    assert store.job(job_id)["state"] == "done"
    assert store.summary(job_id)["files_done"] == 3


def test_low_db_space_stops_before_full(tmp_path, monkeypatch):
    store, job_id = _job(tmp_path)
    monkeypatch.setattr(runner, "free_bytes", lambda folder: 1)
    r = runner.JobRunner(store, job_id, workers=1)
    r.start()
    r.wait(120)
    job = store.job(job_id)
    assert job["state"] == "interrupted" and "空きが無くなった" in job["message"]
    assert store.summary(job_id)["files_done"] == 0


def test_run_starts_scanning_before_cleanup_finishes(tmp_path, monkeypatch):
    """前の検査の残りの片付けが長くても、終わるのを待たずに検査を始め、ジョブの終わりまでには片付け終える。

    以前は片付けが終わるまで検査を始めず、86万ファイルの検査の再開で7分「待機」のままだった（2026-11-06 の実測）。
    """
    import threading

    release = threading.Event()
    begun = threading.Event()
    events = []

    def slow_cleanup(dirs, no_mark_grace=600.0):
        events.append("cleanup-start")
        begun.set()
        release.wait(10)
        events.append("cleanup-end")
        return 0

    store = Store(str(tmp_path / "jobs.sqlite3"))
    job = store.create_job([str(tmp_path)], ScanOptions(temp_dir=str(tmp_path)))
    store.set_job(job, enum_done=1)
    r = runner.JobRunner(store, job, workers=1)
    monkeypatch.setattr(runner, "cleanup_stale_temp", slow_cleanup)
    monkeypatch.setattr(r, "_low_space", lambda: False)

    def fake_scan():
        begun.wait(5)  # 片付けのスレッドが走り出してから記録する（記録の順の揺れを無くす）
        events.append("scan")
        release.set()  # 検査が始まってから片付けを終わらせる（待っていたらここに来ない）

    monkeypatch.setattr(r, "_scan_pending", fake_scan)
    r.start()
    r.wait(20)
    assert not r.running  # 片付けの終わりを待たずにジョブは終わる（再開・パスワードでの再検査を受け付ける）
    r._cleanup.wait(20)
    assert events == ["cleanup-start", "scan", "cleanup-end"], events
    assert store.job(job)["state"] == "done"


def test_job_end_does_not_wait_for_cleanup(tmp_path, monkeypatch):
    """片付けが長引いても、ジョブが終われば running は False になり、すぐ次の開始（再開）を受け付ける（評価の指摘）。"""
    import threading

    release = threading.Event()
    runs = []

    def slow_cleanup(dirs, no_mark_grace=600.0):
        release.wait(10)
        return 0

    store = Store(str(tmp_path / "jobs.sqlite3"))
    job = store.create_job([str(tmp_path)], ScanOptions(temp_dir=str(tmp_path)))
    store.set_job(job, enum_done=1)
    r = runner.JobRunner(store, job, workers=1)
    monkeypatch.setattr(runner, "cleanup_stale_temp", slow_cleanup)
    monkeypatch.setattr(r, "_low_space", lambda: False)
    monkeypatch.setattr(r, "_scan_pending", lambda: runs.append("scan"))
    r.start()
    r.wait(5)
    assert not r.running
    r.start()  # 片付けはまだ終わっていない
    r.wait(5)
    assert runs == ["scan", "scan"]
    release.set()
    r._cleanup.wait(10)


def test_run_waits_for_cleanup_when_space_is_low(tmp_path, monkeypatch):
    """空きが少ないときは、片付けで空くのを待ってから始める（満杯と判断して止めないため）。"""
    events = []
    store = Store(str(tmp_path / "jobs.sqlite3"))
    job = store.create_job([str(tmp_path)], ScanOptions(temp_dir=str(tmp_path)))
    store.set_job(job, enum_done=1)
    r = runner.JobRunner(store, job, workers=1)
    monkeypatch.setattr(runner, "cleanup_stale_temp", lambda dirs, no_mark_grace=600.0: events.append("cleanup") or 0)
    monkeypatch.setattr(r, "_low_space", lambda: True)
    monkeypatch.setattr(r, "_scan_pending", lambda: events.append("scan"))
    r.start()
    r.wait(20)
    assert events == ["cleanup", "scan"]


def test_background_cleanup_reruns_when_asked_during_run(tmp_path, monkeypatch):
    """片付けの最中に頼まれたら、終わった後にもう1回走らせる（打ち切ったワーカーの残りを取りこぼさない）。"""
    import threading

    started = threading.Event()
    release = threading.Event()
    calls = []

    def fake(dirs, no_mark_grace=600.0):
        calls.append(list(dirs))
        if len(calls) == 1:
            started.set()
            release.wait(10)
        return 1

    monkeypatch.setattr(runner, "cleanup_stale_temp", fake)
    bg = runner.BackgroundCleanup()
    bg.request(["a"])
    assert started.wait(5)
    bg.request(["b"])
    bg.request(["c"])  # 走っている間に何回頼まれても、後で1回だけ
    release.set()
    bg.wait(10)
    assert calls == [["a"], ["c"]] and bg.removed == 2

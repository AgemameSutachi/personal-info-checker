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

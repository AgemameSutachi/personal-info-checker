"""進捗の軽い集計（Store.progress）と、検査中の summary の使い回し（Store.summary_cached）の試験。"""

from __future__ import annotations

import time

import pytest

from pii_checker import runner
from pii_checker.models import ScanOptions
from pii_checker.store import Store


@pytest.fixture
def done_job(tmp_path):
    folder = tmp_path / "data"
    folder.mkdir()
    for i in range(4):
        (folder / f"f{i}.txt").write_text(f"顧客 電話 090-1234-56{i:02d}", encoding="utf-8")
    (folder / "empty.txt").write_text("特に何もない文書", encoding="utf-8")
    store = Store(str(tmp_path / "jobs.sqlite3"))
    job = store.create_job([str(folder)], ScanOptions(temp_dir=str(tmp_path)))
    r = runner.JobRunner(store, job, workers=1)
    r.start()
    r.wait(180)
    assert store.job(job)["state"] == "done"
    return store, job


def test_progress_matches_summary(done_job):
    """progress が返す項目は、summary の同名の項目と同じ値（コマンドの1行表示はこれを使う）。"""
    store, job = done_job
    full = store.summary(job)
    light = store.progress(job)
    assert set(light) == {"files_total", "files_done", "item_status", "files_with_findings"}
    for key, value in light.items():
        assert value == full[key], key
    assert light["files_done"] == light["files_total"] == 5
    assert light["files_with_findings"] == 4


def test_summary_cached_reuses_and_expires(done_job, monkeypatch):
    store, job = done_job
    calls = []
    real = store.summary

    def counting(job_id):
        calls.append(job_id)
        return real(job_id)

    monkeypatch.setattr(store, "summary", counting)
    a = store.summary_cached(job, min_age=60)
    b = store.summary_cached(job, min_age=60)
    assert len(calls) == 1  # 2回目は使い回し
    assert a == b == real(job)
    # 返した値を書き換えても、覚えている値は変わらない
    a["files_total"] = -1
    assert store.summary_cached(job, min_age=60)["files_total"] == 5
    # 期限が切れたら数え直す（min_age=0 でも、直前の集計にかかった時間の4倍は使い回す）
    time.sleep(0.01)
    store._summary_cache[job] = (time.monotonic() - 100, 0.0, store._summary_cache[job][2])
    store.summary_cached(job, min_age=0)
    assert len(calls) == 2


def test_summary_cached_is_bounded(done_job):
    store, job = done_job
    for i in range(40):
        store._summary_cache[f"fake{i}"] = (time.monotonic(), 0.0, {})
    store.summary_cached(job)
    assert len(store._summary_cache) <= 16
    assert job in store._summary_cache  # 直近に呼んだものは残る

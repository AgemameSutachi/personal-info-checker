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


def test_job_view_does_not_reuse_summary_after_finish(done_job):
    """状態が「終わり」なら、スレッドの後片付けが残っていても古い要約で判定しない（画面の API で確かめる）。"""
    import json
    import socket
    import threading
    import urllib.request

    import uvicorn

    from pii_checker.web.server import create_app

    store, job = done_job
    app = create_app(db=store.path, token="t0ken")

    class StillCleaningUp:
        """状態は done を書いた後、FTP の片付けなどでスレッドがまだ生きている runner の代わり。"""

        running = True
        phase = "後片付け"
        current = ""

        def __getattr__(self, name):
            return None

    app.state.registry._runners[job] = StillCleaningUp()
    # 検査中に覚えた古い要約（まだ何も数えていない）を仕込む。これが使われると「検出なし」の判定になる
    stale = app.state.store.summary(job)
    stale.update(files_done=0, files_with_findings=0, item_status={})
    app.state.store._summary_cache[job] = (time.monotonic(), 10.0, stale)

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    th = threading.Thread(target=srv.run, daemon=True)
    th.start()
    try:
        for _ in range(100):
            if srv.started:
                break
            time.sleep(0.05)
        req = urllib.request.Request(f"http://127.0.0.1:{port}/api/jobs/{job}", headers={"X-Token": "t0ken"})
        with urllib.request.urlopen(req, timeout=30) as r:
            view = json.loads(r.read())
    finally:
        srv.should_exit = True
        th.join(timeout=10)
    assert view["state"] == "done"
    assert view["summary"]["files_done"] == 5  # 古い 0 ではなく数え直した値
    assert view["summary"]["files_with_findings"] == 4


def test_summary_cached_is_bounded(done_job):
    store, job = done_job
    for i in range(40):
        store._summary_cache[f"fake{i}"] = (time.monotonic(), 0.0, {})
    store.summary_cached(job)
    assert len(store._summary_cache) <= 16
    assert job in store._summary_cache  # 直近に呼んだものは残る

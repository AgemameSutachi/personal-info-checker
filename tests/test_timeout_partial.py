"""時間切れ（打ち切り）でも途中までの検出を残す作りと、時間制限を大きさに合わせる作りの試験。"""

from __future__ import annotations

import os

from pii_checker import engine, runner
from pii_checker.models import ItemResult, ScanOptions, Status
from pii_checker.store import Store


def _ctx_with_findings(tmp_path):
    opts = ScanOptions(temp_dir=str(tmp_path))
    ctx = engine.ScanContext(str(tmp_path / "big.dmp"), opts, [])
    ctx.checkpoint_file = engine.checkpoint_path(opts, str(tmp_path / "big.dmp"))
    item = ItemResult(path=str(tmp_path / "big.dmp"), kind="Oracle ダンプ", status=Status.PENDING)
    ctx.items.append(item)
    col = engine.Collector(item, 20)
    col.add_text("携帯 090-1234-5678", "生データ")
    return opts, ctx, item


def test_checkpoint_written_and_read_back(tmp_path, monkeypatch):
    """途中経過は CHECKPOINT_SECONDS ごとに書き出され、読むと検出の件数が戻る（読んだら消える）。"""
    opts, ctx, item = _ctx_with_findings(tmp_path)
    assert item.finding_counts.get("phone") == 1
    ctx.maybe_checkpoint()  # まだ間隔が経っていない
    assert not os.path.exists(ctx.checkpoint_file)
    monkeypatch.setattr(engine, "CHECKPOINT_SECONDS", 0)
    ctx.maybe_checkpoint()
    assert os.path.exists(ctx.checkpoint_file) and not os.path.exists(ctx.checkpoint_file + ".tmp")
    items = engine.read_checkpoint(ctx.checkpoint_file)
    assert items[0].finding_counts.get("phone") == 1
    assert not os.path.exists(ctx.checkpoint_file)
    assert engine.read_checkpoint(ctx.checkpoint_file) is None  # 無いときは None


def test_collector_ticks_call_checkpoint(tmp_path, monkeypatch):
    """add_text を CHECKPOINT_EVERY 回呼ぶごとに途中経過の書き出しを試みる。"""
    calls = []
    monkeypatch.setattr(engine, "CHECKPOINT_EVERY", 3)
    col = engine.Collector(ItemResult(path="x", kind="", status=Status.PENDING), 20, on_tick=lambda: calls.append(1))
    for _ in range(7):
        col.add_text("会議", "本文")
    assert len(calls) == 2


def test_scan_file_removes_checkpoint_when_finished(tmp_path, monkeypatch):
    """最後まで読めたら途中経過のファイルは残らない（打ち切られたときだけ残る）。"""
    monkeypatch.setattr(engine, "CHECKPOINT_SECONDS", 0)
    monkeypatch.setattr(engine, "CHECKPOINT_EVERY", 1)
    p = tmp_path / "a.txt"
    p.write_text("携帯 090-1234-5678\n" * 50, encoding="utf-8")
    opts = ScanOptions(temp_dir=str(tmp_path / "t"))
    (tmp_path / "t").mkdir()
    res = engine.scan_file(str(p), opts)
    assert res.items[0].finding_counts.get("phone")
    assert not os.path.exists(engine.checkpoint_path(opts, str(p)))


def test_save_failure_keeps_partial_findings(tmp_path):
    """時間切れのとき、途中までの検出を残したまま検査不能として記録する（「なし」に見えない）。"""
    opts, ctx, item = _ctx_with_findings(tmp_path)
    inner = ItemResult(path=item.path + "!x", kind="", status=Status.PENDING, depth=1)
    store = Store(str(tmp_path / "jobs.sqlite3"))
    job = store.create_job([str(tmp_path)], opts)
    store.add_files(job, [(item.path, 3 * 1024**3, None)])
    store.save_failure(
        job, item.path, "時間切れ（107分）で打ち切った。途中までに見つけた分は記録した", 1.0, partial=[item, inner]
    )
    rows = store.query("SELECT status, reason, counts FROM items WHERE job_id=? ORDER BY seq", (job,))
    assert rows[0]["status"] == Status.UNCHECKABLE.value and "途中まで" in rows[0]["reason"]
    assert '"phone": 1' in rows[0]["counts"]
    assert rows[1]["status"] == Status.UNCHECKABLE.value
    f = store.query("SELECT n_findings, risk FROM files WHERE job_id=?", (job,))[0]
    assert f["n_findings"] == 1


def test_timeout_grows_with_file_size(tmp_path):
    """時間制限は設定の値を最低限として、大きなファイルは大きさに合わせて延びる（3GB なら 30 分では足りない）。"""
    store = Store(str(tmp_path / "jobs.sqlite3"))
    job = store.create_job([str(tmp_path)], ScanOptions(temp_dir=str(tmp_path)))
    small, big = str(tmp_path / "s.txt"), str(tmp_path / "big.dmp")
    store.add_files(job, [(small, 1000, None), (big, 3 * 1024**3, None)])
    r = runner.JobRunner(store, job, timeout=1800)
    assert r._timeout_for(small) == 1800
    assert r._timeout_for(big) == int(3 * 1024**3 / runner.TIMEOUT_MIN_BYTES_PER_SEC) > 1800
    assert r._timeout_for(str(tmp_path / "unknown")) == 1800

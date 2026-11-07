"""再検査で、前回から変わっていないファイルの結果を使い回す試験。"""

import os

import pytest

from pii_checker import runner
from pii_checker.models import ScanOptions
from pii_checker.store import Store


@pytest.fixture
def env(tmp_path):
    folder = tmp_path / "data"
    folder.mkdir()
    for i in range(3):
        (folder / f"f{i}.txt").write_text(f"顧客 電話 090-1234-56{i:02d}", encoding="utf-8")
    # 検査不能になる形式（HEIC）は使い回さない
    (folder / "photo.heic").write_bytes(b"\x00\x00\x00\x18ftypheic" + b"\x00" * 64)
    store = Store(str(tmp_path / "jobs.sqlite3"))
    return folder, store, tmp_path


def _run(store, folder, tmp_path, **opts):
    job = store.create_job([str(folder)], ScanOptions(temp_dir=str(tmp_path), **opts))
    r = runner.JobRunner(store, job, workers=1)
    r.start()
    r.wait(180)
    assert store.job(job)["state"] == "done"
    return job


def _reused(store, job):
    return {
        os.path.basename(r["top_path"]): r["reused_from"]
        for r in store.query("SELECT top_path, reused_from FROM files WHERE job_id=?", (job,))
    }


def _findings(store, job):
    return store.query("SELECT COUNT(*) FROM findings WHERE job_id=?", (job,))[0][0]


def test_unchanged_files_are_reused(env):
    folder, store, tmp = env
    j1 = _run(store, folder, tmp)
    j2 = _run(store, folder, tmp)
    used = _reused(store, j2)
    assert all(used[f"f{i}.txt"] == j1 for i in range(3))
    assert used["photo.heic"] is None  # 検査不能だったものは毎回読み直す
    assert store.summary(j2)["reused"] == 3
    assert _findings(store, j2) == _findings(store, j1) > 0

    # 使い回した結果は行ごと写してあるので、元のジョブを消しても残る
    store.delete_job(j1)
    assert _findings(store, j2) > 0
    # 3回目は、2回目に写した結果を使い回せる（元のジョブは最初に検査したジョブとして残る）
    j3 = _run(store, folder, tmp)
    assert _reused(store, j3)["f0.txt"] == j1


def test_time_breakdown_is_recorded(env):
    """検査したファイルには保存の時間と配ってから受け取るまでの時間が残り、使い回したものには残らない。"""
    folder, store, tmp = env
    j1 = _run(store, folder, tmp)
    rows = store.query("SELECT elapsed, save_elapsed, wall_elapsed FROM files WHERE job_id=?", (j1,))
    assert len(rows) == 4
    for elapsed, save_elapsed, wall_elapsed in rows:
        assert save_elapsed is not None and save_elapsed >= 0
        # 配ってから受け取るまでは、ワーカーの中の検査の時間を含む（時計が違うので少しの誤差は許す）
        assert wall_elapsed is not None and wall_elapsed >= elapsed - 0.5
    j2 = _run(store, folder, tmp)
    for name, save_elapsed, wall_elapsed in (
        (os.path.basename(r[0]), r[1], r[2])
        for r in store.query("SELECT top_path, save_elapsed, wall_elapsed FROM files WHERE job_id=?", (j2,))
    ):
        if name == "photo.heic":
            assert save_elapsed is not None  # 検査不能だったものは毎回読み直す
        else:
            assert save_elapsed is None and wall_elapsed is None


def _one_file_job(store, tmp_path):
    job = store.create_job([str(tmp_path)], ScanOptions(temp_dir=str(tmp_path)))
    store.add_files(job, [("a.txt", 10, 0.0)])
    return job


def _times(store, job):
    return tuple(
        store.query(
            "SELECT elapsed, save_elapsed, wall_elapsed FROM files WHERE job_id=? AND top_path='a.txt'", (job,)
        )[0]
    )


def test_save_result_writes_given_wall_and_rewrites_slow_saves(tmp_path, monkeypatch):
    """渡した wall_elapsed がそのまま入る。遅い保存だけ、確定を含めた時間で書き直す（確定が1回増える）。"""
    import pii_checker.store as store_mod
    from pii_checker.models import FileResult, ItemResult, Status

    store = Store(str(tmp_path / "jobs.sqlite3"))
    job = _one_file_job(store, tmp_path)
    calls = []
    real_tx = store.tx

    def counting_tx():
        calls.append(1)
        return real_tx()

    monkeypatch.setattr(store, "tx", counting_tx)
    result = FileResult(
        top_path="a.txt", items=[ItemResult(path="a.txt", kind="", status=Status.SCANNED)], elapsed=0.25
    )
    store.save_result(job, result, wall_elapsed=1.5)
    elapsed, save_elapsed, wall_elapsed = _times(store, job)
    assert (elapsed, wall_elapsed) == (0.25, 1.5)
    assert 0 <= save_elapsed < store_mod.SAVE_RECHECK_SECONDS
    assert len(calls) == 1  # 速い保存では確定を増やさない

    calls.clear()
    monkeypatch.setattr(store_mod, "SAVE_RECHECK_SECONDS", 0.0)
    store.save_result(job, result, wall_elapsed=2.0)
    assert len(calls) == 2  # 確定まで含めた時間で書き直した
    assert _times(store, job)[1] > 0


def test_slow_save_records_detail_and_lock_wait(tmp_path, monkeypatch):
    """遅い保存だけ内訳を残す。別のスレッドが鍵を持っていた分は lock に出て、CPU 時間は小さい（待っていた）。"""
    import json
    import threading

    import pii_checker.store as store_mod
    from pii_checker.models import FileResult, ItemResult, Status

    store = Store(str(tmp_path / "jobs.sqlite3"))
    job = _one_file_job(store, tmp_path)
    result = FileResult(top_path="a.txt", items=[ItemResult(path="a.txt", kind="", status=Status.SCANNED)])

    def detail():
        return store.query("SELECT save_detail FROM files WHERE job_id=? AND top_path='a.txt'", (job,))[0][0]

    # 速い保存の側は、遅いディスクでも 0.5 秒を超えて揺れないよう閾値を上げて見る
    monkeypatch.setattr(store_mod, "SAVE_RECHECK_SECONDS", 30.0)
    store.save_result(job, result)
    assert detail() is None  # 速い保存は内訳を残さない
    monkeypatch.setattr(store_mod, "SAVE_RECHECK_SECONDS", 0.5)

    held, release = threading.Event(), threading.Event()

    def holder():
        with store._lock:
            held.set()
            release.wait(5)

    t = threading.Thread(target=holder)
    t.start()
    held.wait(5)
    threading.Timer(0.8, release.set).start()
    store.save_result(job, result)
    t.join()
    d = json.loads(detail())
    assert set(d) == {"prep", "lock", "write", "commit", "total", "cpu", "retried"}
    assert d["lock"] >= 0.6 and d["retried"] is False
    assert d["cpu"] < d["lock"]
    assert _times(store, job)[1] == pytest.approx(d["total"])

    monkeypatch.setattr(store_mod, "SAVE_RECHECK_SECONDS", 30.0)
    store.save_result(job, result)
    assert detail() is None  # 次の速い保存で前の内訳を消す（古い内訳が残らない）


def test_failure_records_wall_elapsed(tmp_path):
    """時間切れ・異常終了の行にも、配ってから受け取るまでの時間を残す（遅さの調べで一番知りたい行）。"""
    store = Store(str(tmp_path / "jobs.sqlite3"))
    job = _one_file_job(store, tmp_path)
    store.save_failure(job, "a.txt", "時間切れ", 120.0)
    assert _times(store, job)[2] == 120.0


def test_old_db_gets_time_columns(tmp_path):
    """列の無い古い版の DB を開くと、時間の内訳の列が足される。"""
    import sqlite3

    path = str(tmp_path / "old.sqlite3")
    con = sqlite3.connect(path)
    con.execute(
        "CREATE TABLE files (job_id TEXT, top_path TEXT, state TEXT, worst_status TEXT, risk TEXT, size INTEGER,"
        " mtime REAL, elapsed REAL, n_findings INTEGER DEFAULT 0, PRIMARY KEY (job_id, top_path))"
    )
    con.execute("INSERT INTO files (job_id, top_path, state) VALUES ('j', 'x', 'done')")
    con.commit()
    con.close()
    store = Store(path)
    cols = {r[1] for r in store.query("PRAGMA table_info(files)")}
    assert {"save_elapsed", "wall_elapsed"} <= cols
    assert tuple(store.query("SELECT save_elapsed, wall_elapsed FROM files")[0]) == (None, None)


def test_changed_files_are_rescanned(env):
    folder, store, tmp = env
    _run(store, folder, tmp)
    # 中身を変える
    with open(folder / "f0.txt", "a", encoding="utf-8") as f:
        f.write(" 追記")
    # 中身を変えて更新日時だけ元に戻す（robocopy 等）→ 変更日時（ChangeTime）は戻せないので見抜く
    st = os.stat(folder / "f1.txt")
    (folder / "f1.txt").write_text("顧客 電話 090-9999-0000", encoding="utf-8")
    os.utime(folder / "f1.txt", ns=(st.st_atime_ns, st.st_mtime_ns))
    if os.name == "nt":
        # 代替データストリームにだけ書く
        with open(str(folder / "f2.txt") + ":hidden", "w", encoding="utf-8") as f:
            f.write("マイナンバー 123456789018")
    j2 = _run(store, folder, tmp)
    used = _reused(store, j2)
    assert used["f0.txt"] is None
    assert used["f1.txt"] is None
    if os.name == "nt":
        assert used["f2.txt"] is None


def test_reuse_can_be_turned_off(env):
    folder, store, tmp = env
    _run(store, folder, tmp)
    j2 = _run(store, folder, tmp, reuse=False)
    assert all(v is None for v in _reused(store, j2).values())


def test_different_settings_are_not_reused(env):
    folder, store, tmp = env
    _run(store, folder, tmp)
    j2 = _run(store, folder, tmp, ocr=False)  # 結果に効く設定が違う
    assert all(v is None for v in _reused(store, j2).values())


def test_split_archive_first_volume_not_reused(tmp_path):
    folder = tmp_path / "s"
    folder.mkdir()
    (folder / "a.7z.001").write_bytes(b"x")
    (folder / "a.7z.002").write_bytes(b"y")
    assert runner.depends_on_neighbors(str(folder / "a.7z.001"))
    assert runner.depends_on_neighbors(str(folder / "a.7z.002"))  # 続きも1つ目の有無で結果が変わる
    for name in ("b.z01", "c.part2.rar", "d.r00"):
        assert runner.depends_on_neighbors(str(folder / name)), name
    assert not runner.depends_on_neighbors(str(folder / "a.txt"))


def test_old_style_rar_continuation_finds_first(tmp_path):
    """古い形式の RAR 分割（.rar＋.r00）は、1つ目があれば続きを「1つ目が無い」で検査不能にしない（不具合の修正）。"""
    from pii_checker.engine import scan_file

    (tmp_path / "c.rar").write_bytes(b"Rar!\x1a\x07\x00" + os.urandom(64))
    (tmp_path / "c.r00").write_bytes(os.urandom(64))
    res = scan_file(str(tmp_path / "c.r00"), ScanOptions(temp_dir=str(tmp_path)))
    assert "1つ目のファイルが同じフォルダに無い" not in res.items[0].reason
    os.remove(tmp_path / "c.rar")
    res = scan_file(str(tmp_path / "c.r00"), ScanOptions(temp_dir=str(tmp_path)))
    assert "1つ目のファイルが同じフォルダに無い" in res.items[0].reason  # 陽性対照
    assert "同じフォルダに置いて再検査してください" in res.items[0].reason  # 次の手


def test_split_continuation_not_declared_clean_after_first_removed(tmp_path):
    """1つ目を消した後の再検査で、続き（.002）の前回の「対象外」を使い回して言い切らない（不具合の修正）。"""
    from pii_checker.verdict import decide

    folder = tmp_path / "data"
    folder.mkdir()
    (folder / "a.7z.001").write_bytes(b"7z\xbc\xaf\x27\x1c" + os.urandom(64))
    (folder / "a.7z.002").write_bytes(os.urandom(256))
    store = Store(str(tmp_path / "jobs.sqlite3"))
    _run(store, folder, tmp_path)
    os.remove(folder / "a.7z.001")
    j2 = _run(store, folder, tmp_path)
    assert _reused(store, j2)["a.7z.002"] is None
    v = decide(store.summary(j2), "done")
    assert not v.can_declare_clean

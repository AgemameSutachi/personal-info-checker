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

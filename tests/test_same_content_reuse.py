"""同じ検査の中で、中身が同じファイルの結果を写す（SameContentReuse）試験。

見落としを出さないことが絶対条件なので、「写さないこと」の確かめ（名前が違う・失敗・ストリーム・隣に左右される・
読めない）を、写すことの確かめと同じ数だけ置く。
"""

import os
import time
import zipfile

import pytest

from pii_checker import runner
from pii_checker.engine import ATIME_NOTE_NO_PERMISSION
from pii_checker.models import FileResult, ItemResult, ScanOptions, Status
from pii_checker.safeio import SourceInfo
from pii_checker.store import Store

PII = "顧客名簿 電話 090-1234-5678 メール taro@example.com\n"


@pytest.fixture(autouse=True)
def small_threshold(monkeypatch):
    """試験では小さなファイルでも同じ中身を調べる（閾値の値そのものは別に試す）。"""
    monkeypatch.setattr(runner, "SAME_CONTENT_MIN_BYTES", 1)


@pytest.fixture
def store(tmp_path):
    return Store(str(tmp_path / "jobs.sqlite3"))


def make(folder, rel, content=PII, mtime=None):
    p = folder / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        p.write_bytes(content)
    else:
        p.write_text(content, encoding="utf-8")
    if mtime:
        os.utime(p, (mtime, mtime))
    return p


def run(store, folder, tmp_path, workers=1, **opts):
    job = store.create_job([str(folder)], ScanOptions(temp_dir=str(tmp_path), **opts))
    r = runner.JobRunner(store, job, workers=workers)
    r.start()
    r.wait(240)
    assert store.job(job)["state"] == "done", store.job(job)
    return job, r


def rows(store, job):
    return {r["top_path"]: dict(r) for r in store.query("SELECT * FROM files WHERE job_id=?", (job,))}


def kinds(store, job):
    """相対パス → reuse_kind（None=実際に検査した）。"""
    return {
        os.path.basename(os.path.dirname(r["top_path"])) + "/" + os.path.basename(r["top_path"]): r["reuse_kind"]
        for r in store.query("SELECT top_path, reuse_kind FROM files WHERE job_id=?", (job,))
    }


def n_same(store, job):
    return store.query("SELECT COUNT(*) FROM files WHERE job_id=? AND reuse_kind='same'", (job,))[0][0]


def counts(store, job, top):
    return store.query("SELECT COUNT(*) FROM findings WHERE job_id=? AND top_path=?", (job, top))[0][0]


# ---------------------------------------------------------------- 写すこと


def test_same_content_same_name_is_copied(tmp_path, store):
    """名前も中身も同じ2つ: 片方だけ検査し、もう片方は結果を写す（パスは自分のもの・日時も自分の値）。"""
    folder = tmp_path / "data"
    a = make(folder, "a/名簿.txt", mtime=1_600_000_000)
    b = make(folder, "b/名簿.txt", mtime=1_700_000_000)
    job, r = run(store, folder, tmp_path)
    k = kinds(store, job)
    assert sorted(k.values(), key=str) == [None, "same"]
    assert store.summary(job)["reused_same"] == 1 and store.summary(job)["reused"] == 0
    for p in (a, b):
        top = str(p)
        row = store.query("SELECT * FROM files WHERE job_id=? AND top_path=?", (job, top))[0]
        assert row["state"] == "done" and row["n_findings"] > 0
        assert row["mtime_ns"] == p.stat().st_mtime_ns  # 識別情報はそのファイル自身の値
        assert row["sha256"]
        items = store.query("SELECT path, mtime FROM items WHERE job_id=? AND top_path=?", (job, top))
        assert [i["path"] for i in items] == [top]  # パスは写した先のもの（元のパスが残らない）
        assert abs(items[0]["mtime"] - p.stat().st_mtime) < 1e-3
        assert counts(store, job, top) == counts(store, job, str(a)) > 0
    copy = next(x for x in rows(store, job).values() if x["reuse_kind"] == "same")
    assert copy["reused_from"].startswith("同じ中身")
    assert copy["elapsed"] == 0 and copy["reusable"] == 1


def test_parallel_copies_wait_for_first(tmp_path, store):
    """同時に配られる5つの写し: 1つだけ検査し、残りは先頭の検査が済むまで待ってから写す。"""
    folder = tmp_path / "data"
    for i in range(5):
        make(folder, f"d{i}/データ.csv", "氏名,電話\n山田太郎,090-1234-5678\n" * 3)
    job, r = run(store, folder, tmp_path, workers=2)
    assert n_same(store, job) == 4
    assert (
        r.same_content is not None and r.same_content.waited >= 1 and r.same_content.waited + r.same_content.copied >= 4
    )
    assert store.query("SELECT COUNT(*) FROM files WHERE job_id=? AND state='done'", (job,))[0][0] == 5
    tops = [x["top_path"] for x in store.query("SELECT top_path FROM files WHERE job_id=?", (job,))]
    assert len({counts(store, job, t) for t in tops}) == 1  # 検出の数は全員同じ


def test_archive_member_paths_are_rewritten(tmp_path, store):
    """zip の中身の項目のパス（外側!内側）も、写した先の外側のパスへ書き換わる。"""
    folder = tmp_path / "data"
    for d in ("x", "y"):
        zp = folder / d / "pack.zip"
        zp.parent.mkdir(parents=True)
        with zipfile.ZipFile(zp, "w") as z:
            z.writestr("inner/list.txt", PII)
    job, _ = run(store, folder, tmp_path)
    assert n_same(store, job) == 1
    for d in ("x", "y"):
        top = str(folder / d / "pack.zip")
        paths = [r["path"] for r in store.query("SELECT path FROM items WHERE job_id=? AND top_path=?", (job, top))]
        assert top in paths and any(p.startswith(top + "!") for p in paths), paths
        assert all(p.startswith(top) for p in paths)  # 相手のフォルダのパスが混ざらない
        assert counts(store, job, top) > 0


def test_second_job_reuses_copies_as_previous_result(tmp_path, store):
    """写した結果も、次のジョブの前回の使い回しの元になる（元として同じ中身の写し元のパスではなくジョブを残す）。"""
    folder = tmp_path / "data"
    make(folder, "a/名簿.txt")
    make(folder, "b/名簿.txt")
    j1, _ = run(store, folder, tmp_path)
    j2, _ = run(store, folder, tmp_path)
    for r in store.query("SELECT reused_from, reuse_kind FROM files WHERE job_id=?", (j2,)):
        assert r["reuse_kind"] is None and r["reused_from"] == j1
    s = store.summary(j2)
    assert s["reused"] == 2 and s["reused_same"] == 0


# ---------------------------------------------------------------- 写さないこと


def test_different_name_is_not_copied(tmp_path, store):
    """中身が同じでも名前が違えば写さない（ファイル名も検査する・拡張子で読み方が変わる）。"""
    folder = tmp_path / "data"
    make(folder, "a/one.txt")
    make(folder, "b/two.txt")
    make(folder, "c/ONE.TXT")  # 大文字小文字だけ違うのも別扱い
    make(folder, "d/one.csv")  # 拡張子だけ違う
    job, _ = run(store, folder, tmp_path)
    assert n_same(store, job) == 0
    assert store.query("SELECT COUNT(*) FROM files WHERE job_id=? AND state='done'", (job,))[0][0] == 4


def test_name_with_pii_is_found_in_each_copy(tmp_path, store):
    """名前そのものの検出（ファイル名も検査する）は、写すと落ちる形。名前が違う写しは、それぞれ検査される。"""
    folder = tmp_path / "data"
    make(folder, "a/090-1234-5678.txt", "本文なし\n")
    make(folder, "b/plain.txt", "本文なし\n")
    job, _ = run(store, folder, tmp_path)
    assert n_same(store, job) == 0
    a = store.query("SELECT n_findings FROM files WHERE job_id=? AND top_path LIKE '%090-1234-5678.txt'", (job,))[0][0]
    b = store.query("SELECT n_findings FROM files WHERE job_id=? AND top_path LIKE '%plain.txt'", (job,))[0][0]
    assert a > 0 and b == 0


def test_same_size_different_content_is_not_copied(tmp_path, store):
    folder = tmp_path / "data"
    make(folder, "a/名簿.txt", "電話 090-1234-5678 です\n")
    make(folder, "b/名簿.txt", "電話 090-1234-5679 です\n")
    make(folder, "c/名簿.txt", "ただの文章を書いた物です。\n")
    job, _ = run(store, folder, tmp_path)
    assert n_same(store, job) == 0


def test_unique_size_files_are_not_read(tmp_path, store, monkeypatch):
    """大きさが他と被らないファイルの中身は、調べるために読まない。"""
    calls = []
    real = runner.hash_file

    def spy(path, *a, **kw):
        calls.append(path)
        return real(path, *a, **kw)

    monkeypatch.setattr(runner, "hash_file", spy)
    folder = tmp_path / "data"
    make(folder, "a/one.txt", "a" * 100)
    make(folder, "b/two.txt", "b" * 200)
    make(folder, "c/three.txt", "c" * 300)
    job, _ = run(store, folder, tmp_path)
    assert calls == []
    make(folder, "d/one.txt", "a" * 100)  # 大きさが被ったので、読んで調べる
    job2, _ = run(store, folder, tmp_path, reuse=True)
    # 2回目は前回の結果を使い回せるものが多いが、被った大きさのファイルだけは調べる対象になる
    assert calls and all(os.path.basename(c) == "one.txt" for c in calls)


def test_below_threshold_is_not_read(tmp_path, store, monkeypatch):
    monkeypatch.setattr(runner, "SAME_CONTENT_MIN_BYTES", 10_000)
    calls = []
    monkeypatch.setattr(runner, "hash_file", lambda *a, **k: calls.append(a[0]))
    folder = tmp_path / "data"
    make(folder, "a/名簿.txt")
    make(folder, "b/名簿.txt")
    job, _ = run(store, folder, tmp_path)
    assert calls == [] and n_same(store, job) == 0


def test_failed_first_is_not_copied(tmp_path, store):
    """先頭が検査不能（言い切れない）で終わったら、写さずにそれぞれ検査する。"""
    folder = tmp_path / "data"
    heic = b"\x00\x00\x00\x18ftypheic" + b"\x00" * 64  # 検査不能になる形式
    make(folder, "a/photo.heic", heic)
    make(folder, "b/photo.heic", heic)
    make(folder, "c/photo.heic", heic)
    job, _ = run(store, folder, tmp_path, workers=2)
    assert n_same(store, job) == 0
    sts = {r["worst_status"] for r in store.query("SELECT worst_status FROM files WHERE job_id=?", (job,))}
    assert sts == {Status.UNCHECKABLE.value}
    assert store.query("SELECT COUNT(*) FROM files WHERE job_id=? AND state='done'", (job,))[0][0] == 3


def test_reuse_off_does_not_copy(tmp_path, store):
    folder = tmp_path / "data"
    make(folder, "a/名簿.txt")
    make(folder, "b/名簿.txt")
    job, r = run(store, folder, tmp_path, reuse=False)
    assert n_same(store, job) == 0 and r.same_content is None


def test_neighbor_dependent_is_not_copied(tmp_path, store):
    """隣のファイルに左右される形（分割アーカイブの続き）は写さない。"""
    folder = tmp_path / "data"
    make(folder, "a/data.002", PII)
    make(folder, "b/data.002", PII)
    job, _ = run(store, folder, tmp_path)
    assert n_same(store, job) == 0


def test_unreadable_hash_falls_back_to_scan(tmp_path, store, monkeypatch):
    """中身を読めなかった（同じ中身か確かめられない）ときは、ふつうに検査する。"""

    def boom(*a, **k):
        raise PermissionError("読めない")

    monkeypatch.setattr(runner, "hash_file", boom)
    folder = tmp_path / "data"
    make(folder, "a/名簿.txt")
    make(folder, "b/名簿.txt")
    job, _ = run(store, folder, tmp_path)
    assert n_same(store, job) == 0
    assert store.query("SELECT COUNT(*) FROM files WHERE job_id=? AND state='done'", (job,))[0][0] == 2


@pytest.mark.skipif(os.name != "nt", reason="代替データストリームは NTFS だけ")
def test_file_with_alternate_stream_is_scanned_itself(tmp_path, store):
    """隠しストリームを持つファイルは写さず、ストリームも自分で検査する（持たない側へストリームの結果を写さない）。"""
    folder = tmp_path / "data"
    a = make(folder, "a/名簿.txt", "ただの本文です。\n")
    b = make(folder, "b/名簿.txt", "ただの本文です。\n")
    with open(str(b) + ":secret", "w", encoding="utf-8") as f:
        f.write(PII)
    job, _ = run(store, folder, tmp_path)
    assert n_same(store, job) == 0
    nb = store.query("SELECT n_findings FROM files WHERE job_id=? AND top_path=?", (job, str(b)))[0][0]
    na = store.query("SELECT n_findings FROM files WHERE job_id=? AND top_path=?", (job, str(a)))[0][0]
    assert nb > 0 and na == 0
    assert any(
        r["path"] == str(b) + ":secret"
        for r in store.query("SELECT path FROM items WHERE job_id=? AND top_path=?", (job, str(b)))
    )


def test_resumed_job_copies_from_done_file(tmp_path, store):
    """再開した検査: 前の回に検査済みのファイルが先頭になり、残りへ写す（先頭の再検査はしない）。"""
    folder = tmp_path / "data"
    make(folder, "a/名簿.txt")
    make(folder, "b/名簿.txt")
    job = store.create_job([str(folder)], ScanOptions(temp_dir=str(tmp_path)))
    r1 = runner.JobRunner(store, job, workers=1)
    r1._enumerate()
    # a だけ検査済みにした状態（再開の想定）
    from pii_checker.engine import scan_file

    a = str(folder / "a" / "名簿.txt")
    res = scan_file(a, ScanOptions(temp_dir=str(tmp_path)))
    store.save_result(job, res, r1.engine_sig)
    r2 = runner.JobRunner(store, job, workers=1)
    r2.start()
    r2.wait(120)
    assert store.job(job)["state"] == "done"
    k = kinds(store, job)
    assert k["a/名簿.txt"] is None and k["b/名簿.txt"] == "same"


# ---------------------------------------------------------------- 保存の確かさ（store）


def _result(top, notes=None, reason=""):
    item = ItemResult(path=top, kind="テキスト", status=Status.SCANNED, size=10, mtime=1.0)
    item.notes = notes or []
    item.reason = reason
    inner = ItemResult(
        path=top + "!in.txt", kind="テキスト", status=Status.SCANNED, size=5, depth=1, reason=f"元 {top}"
    )
    return FileResult(
        top_path=top,
        items=[item, inner],
        source={"mtime_ns": 5, "change_ns": 6, "file_id": "f1", "sha256": "ab" * 32, "size": 10, "atime_kept": False},
    )


def test_copy_rewrites_paths_and_atime_note(tmp_path, store):
    job = store.create_job([str(tmp_path)], ScanOptions())
    src_top, dst_top = "C:\\data\\a\\x.txt", "C:\\data\\b\\x.txt"
    store.add_files(job, [(src_top, 10, 1.0), (dst_top, 10, 2.0)])
    store.save_result(job, _result(src_top, notes=[ATIME_NOTE_NO_PERMISSION, f"参照 {src_top}"]), "SIG")
    src = store.find_same_content(job, "ab" * 32, "x.txt", "SIG", exclude=dst_top)
    assert src and src["top_path"] == src_top
    info = SourceInfo(size=10, mtime_ns=99, change_ns=98, file_id="f2", sha256="ab" * 32, atime_kept=True)
    store.copy_same_content(src, job, dst_top, info, "SIG")
    items = store.query("SELECT * FROM items WHERE job_id=? AND top_path=? ORDER BY seq", (job, dst_top))
    assert [i["path"] for i in items] == [dst_top, dst_top + "!in.txt"]
    assert items[1]["reason"] == f"元 {dst_top}"
    assert abs(items[0]["mtime"] - 99 / 1e9) < 1e-12  # 実ファイル自身の項目の更新日時は写す先のもの
    assert items[1]["mtime"] is None  # 内側の項目は写し元のまま
    import json

    notes = json.loads(items[0]["notes"])
    assert ATIME_NOTE_NO_PERMISSION not in notes  # 写し元の最終アクセス日時の補足は写さない（写す先は保てた）
    assert f"参照 {dst_top}" in notes  # JSON の中のバックスラッシュ入りのパスも書き換わる
    row = store.query("SELECT * FROM files WHERE job_id=? AND top_path=?", (job, dst_top))[0]
    assert (row["mtime_ns"], row["change_ns"], row["file_id"], row["atime_kept"]) == (99, 98, "f2", 1)
    assert row["reuse_kind"] == "same" and row["reused_from"] == f"同じ中身: {src_top}"
    # 写し元の行は変わらない
    assert store.query("SELECT COUNT(*) FROM items WHERE job_id=? AND top_path=?", (job, src_top))[0][0] == 2


def test_failed_copy_leaves_nothing_done(tmp_path, store, monkeypatch):
    """写す途中で失敗したら全部巻き戻り、写した先が「検査済み」だけ残ることはない。"""
    from pii_checker import reportflags

    job = store.create_job([str(tmp_path)], ScanOptions())
    src_top, dst_top = str(tmp_path / "a" / "x.txt"), str(tmp_path / "b" / "x.txt")
    store.add_files(job, [(src_top, 10, 1.0), (dst_top, 10, 2.0)])
    store.save_result(job, _result(src_top), "SIG")
    src = store.find_same_content(job, "ab" * 32, "x.txt", "SIG", exclude=dst_top)

    def boom(*a, **k):
        raise RuntimeError("途中で失敗")

    monkeypatch.setattr(reportflags, "compute", boom)
    info = SourceInfo(size=10, mtime_ns=1, change_ns=1, file_id="f", sha256="ab" * 32)
    with pytest.raises(RuntimeError):
        store.copy_same_content(src, job, dst_top, info, "SIG")
    assert store.query("SELECT state FROM files WHERE job_id=? AND top_path=?", (job, dst_top))[0][0] == "pending"
    assert store.query("SELECT COUNT(*) FROM items WHERE job_id=? AND top_path=?", (job, dst_top))[0][0] == 0


def test_find_same_content_skips_unsafe_sources(tmp_path, store):
    job = store.create_job([str(tmp_path)], ScanOptions())
    top = str(tmp_path / "a" / "x.txt")
    store.add_files(job, [(top, 10, 1.0)])
    res = _result(top)
    res.items[1].path = top + ":secret"  # 隠しストリームの項目を持つ
    res.items[1].depth = 1
    store.save_result(job, res, "SIG")
    assert store.find_same_content(job, "ab" * 32, "x.txt", "SIG") is None  # ストリームを持つ結果は写さない
    top2 = str(tmp_path / "c" / "x.txt")
    store.add_files(job, [(top2, 10, 1.0)])
    res2 = _result(top2)
    res2.items[0].status = Status.UNCHECKABLE
    res2.items[0].reason = "壊れている"
    store.save_result(job, res2, "SIG")
    assert store.find_same_content(job, "ab" * 32, "x.txt", "SIG") is None  # 言い切れない状態の結果は写さない
    assert store.find_same_content(job, "ab" * 32, "y.txt", "SIG") is None  # 名前が違う
    top3 = str(tmp_path / "d" / "x.txt")
    store.add_files(job, [(top3, 10, 1.0)])
    store.save_result(job, _result(top3), "SIG")
    assert store.find_same_content(job, "ab" * 32, "x.txt", "SIG")["top_path"] == top3
    assert store.find_same_content(job, "ab" * 32, "x.txt", "OTHER") is None  # 検査器の版が違う


def test_hash_file_matches_snapshot_and_is_stopped(tmp_path):
    """hash_file は snapshot と同じ SHA-256 を返し、止める指示で中断する。"""
    from pii_checker import safeio

    p = make(tmp_path, "f.bin", b"abc" * 100_000)
    info = safeio.hash_file(str(p))
    snap = safeio.snapshot(str(p), str(tmp_path / "copy.bin"), str(tmp_path))
    assert info.sha256 == snap.sha256 and info.same_as(snap)
    with pytest.raises(safeio.HashStopped):
        safeio.hash_file(str(p), should_stop=lambda: True)


def test_atime_is_kept_when_hashing(tmp_path):
    """中身を読んで調べても、最終アクセス日時は変わらない（読み取りの約束は検査と同じ）。"""
    from pii_checker import safeio

    p = make(tmp_path, "f.bin", b"abc" * 1000)
    old = time.time() - 86400 * 30
    os.utime(p, (old, old))
    before = p.stat().st_atime
    info = safeio.hash_file(str(p))
    if info.atime_kept:
        assert abs(p.stat().st_atime - before) < 2


# ---------------------------------------------------------------- 要パスワードの結果の写し


def make_encrypted_7z(path, password="pw123"):
    import py7zr

    path.parent.mkdir(parents=True, exist_ok=True)
    with py7zr.SevenZipFile(str(path), "w", password=password) as z:
        z.writestr(PII, "inner.txt")
    return path


def test_needs_password_result_is_copied_and_rechecked_after_password(tmp_path, store):
    """要パスワードの結果も、同じパスワードの版の間は写す。写した側の reusable は 0 のまま、
    パスワードを足すと写した側も各自で検査し直される。"""
    folder = tmp_path / "data"
    a = make_encrypted_7z(folder / "a" / "秘密.7z")
    b = make_encrypted_7z(folder / "b" / "秘密.7z")
    b.write_bytes(a.read_bytes())  # 同じ中身にそろえる
    job, r = run(store, folder, tmp_path)
    assert n_same(store, job) == 1
    for row in store.query("SELECT worst_status, reusable, state FROM files WHERE job_id=?", (job,)):
        assert row["worst_status"] == "needs_password" and row["reusable"] == 0 and row["state"] == "done"
    assert store.summary(job)["item_status"].get("needs_password") == 2  # 写した側も数える
    assert len(store.files_with_status(job, ["needs_password"])) == 2

    # パスワードを足すと、写した側も含めて検査し直される（写しのまま残らない）
    assert r.add_password("pw123") == 2
    r.wait(240)
    assert store.job(job)["state"] == "done"
    for row in store.query("SELECT worst_status, reuse_kind, state FROM files WHERE job_id=?", (job,)):
        assert row["state"] == "done" and row["worst_status"] != "needs_password" and row["reuse_kind"] is None
    assert store.files_with_status(job, ["needs_password"]) == []


def test_needs_password_not_copied_after_version_change(tmp_path, store):
    """パスワードの版が変わった後は、要パスワードの結果を写さない（新しいパスワードで検査すべきなので）。"""
    folder = tmp_path / "data"
    a = make_encrypted_7z(folder / "a" / "秘密.7z")
    b = folder / "b" / "秘密.7z"
    b.parent.mkdir(parents=True)
    b.write_bytes(a.read_bytes())
    job = store.create_job([str(folder)], ScanOptions(temp_dir=str(tmp_path)))
    r = runner.JobRunner(store, job, workers=1)
    r._enumerate()
    from pii_checker.engine import scan_file

    res = scan_file(str(a), ScanOptions(temp_dir=str(tmp_path)))
    store.save_result(job, res, r.engine_sig)
    r._sizes = {str(b): b.stat().st_size}
    same = runner.SameContentReuse(r, set())
    key = (res.source["sha256"], "秘密.7z")
    same._leader_key[str(a)] = key
    same._leaders[key] = str(a)
    same._waiters[key] = [(str(b), SourceInfo(size=1, mtime_ns=1, change_ns=1, file_id="x", sha256=key[0]))]
    r.password_version += 1  # 配った後にパスワードを受け取った
    assert same.finished(str(a), 0) == [(str(b), "scan")]
    same.close()

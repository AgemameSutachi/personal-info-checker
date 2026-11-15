"""大きな zip の中を区切りに分けて、複数のワーカーへ並べて検査する（S4・splitscan）の試験。

見落としを出さないことが条件なので、分けたときと分けないときで結果（明細・件数・順・異なる値の数）が一致すること、
区切りが落ちたときにその区切りの項目だけが検査不能になること、写しが必ず消えること、上限が同じ理由で効くことを確かめる。
試験では runner.BIG_FILE_BYTES などの定数を小さくして、小さな zip を「大きな zip」として扱わせる
（定数は配る側のプロセスだけが読むので、本物のワーカーのプロセスでも動く）。
"""

from __future__ import annotations

import hashlib
import io
import os
import subprocess
import sys
import time
import zipfile
from pathlib import Path

import pytest

from pii_checker import engine, runner, splitscan
from pii_checker.models import ScanOptions, Status
from pii_checker.store import Store

N_ENTRIES = 40


# ------------------------------------------------------------------ 本物のワーカーの中で動かす差し替え（試験の仕込み）
# 本物のワーカーのプロセスは、この試験のモジュールを名前で読み込んで使う（tests のフォルダは sys.path に入っている）


def crash_part_task(spec, options, book):
    """区切り1番のワーカーだけ、検査の途中で異常終了させる。"""
    if spec.index == 1:
        os._exit(7)
    return splitscan.scan_part(spec, options, book)


def slow_part_task(spec, options, book):
    """どの区切りも終わらない（停止の試験用）。"""
    time.sleep(120)
    return splitscan.scan_part(spec, options, book)


def crash_plan_task(path, options, book, split=None, shared_tmp=None):
    """計画を返す仕事が、写しの途中で異常終了する（一時フォルダにファイルを置いたまま落ちる）。"""
    if shared_tmp:
        with open(os.path.join(shared_tmp, "partial_copy.bin"), "wb") as f:
            f.write(b"x" * 1000)
        os._exit(9)
    return runner._scan_task(path, options, book)


# ------------------------------------------------------------------ 道具


def make_zip(path: Path, n: int = N_ENTRIES, nested: bool = True) -> Path:
    """分け方・値の重なり・入れ子・個人情報の無い項目をそろえた zip（項目はディレクトリを除いて n 件）。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for i in range(n):
            d = f"d{i // 10}"
            if nested and i % 13 == 5:
                buf = io.BytesIO()
                with zipfile.ZipFile(buf, "w") as zz:
                    for j in range(3):
                        zz.writestr(f"in{j}.txt", f"携帯 090-7{i:03d}-{j:04d}\n")
                z.writestr(f"{d}/nested{i}.zip", buf.getvalue())
            elif i % 7 == 3:
                z.writestr(f"{d}/clean{i}.txt", "会議の議事録です。特になし。\n")
            elif i % 11 == 4:
                z.writestr(f"{d}/t{i}.csv", f"氏名,電話\n山田太郎,090-2222-{i:04d}\n")
            else:
                # 値は区切りをまたいで重なる（i % 9・i % 5）。同じ番号を別の確度でも書く
                z.writestr(
                    f"{d}/f{i}.txt",
                    f"顧客 携帯 090-1234-{i % 9:04d} メール user{i % 5}@example.com\n電話 090-9999-{i:04d}\n"
                    f"090-1234-{i % 9:04d}\n",
                )
    return path


@pytest.fixture
def small_split(monkeypatch):
    """小さな zip を「大きな zip」として、10項目ずつの区切りに分ける設定にする。"""
    monkeypatch.setattr(runner, "BIG_FILE_BYTES", 1)
    monkeypatch.setattr(runner, "ARCHIVE_SPLIT_MIN_ENTRIES", 20)
    monkeypatch.setattr(runner, "ARCHIVE_SPLIT_PART_ENTRIES", 10)
    monkeypatch.setattr(runner, "ARCHIVE_SPLIT_MIN_WORKERS", 2)


@pytest.fixture
def store(tmp_path):
    return Store(str(tmp_path / "jobs.sqlite3"))


def temp_dir(tmp_path) -> str:
    d = tmp_path / "t"
    d.mkdir(exist_ok=True)
    return str(d)


def run(store, folder, tmp_path, workers=3, wait=300, **opts):
    opts.setdefault("reuse", False)
    job = store.create_job([str(folder)], ScanOptions(temp_dir=temp_dir(tmp_path), **opts))
    r = runner.JobRunner(store, job, workers=workers)
    r.workers = workers  # 空きメモリの少ない機械でも、並べる本数を試験の指定どおりにする
    r.start()
    r.wait(wait)
    return job, r


def dump(store, job, top: str) -> dict:
    """1ファイルの保存結果（明細・件数・順・異なる値の数）。分けたときと分けないときの比べ方。"""
    items = [
        tuple(r)
        for r in store.query(
            "SELECT seq, path, kind, status, reason, method, size, depth, counts, conf_counts, distinct_counts, notes"
            " FROM items WHERE job_id=? AND top_path=? ORDER BY seq",
            (job, top),
        )
    ]
    findings = [
        tuple(r)
        for r in store.query(
            "SELECT item_seq, pii_type, confidence, masked_value, location, context, rule, method FROM findings"
            " WHERE job_id=? AND top_path=? ORDER BY item_seq, rowid",
            (job, top),
        )
    ]
    f = store.query(
        "SELECT state, worst_status, n_findings, distinct_counts, sha256 FROM files WHERE job_id=? AND top_path=?",
        (job, top),
    )[0]
    return {"items": items, "findings": findings, "file": tuple(f)}


def clean_temp(tmp_path) -> list[str]:
    """一時フォルダに残った、この道具の名前のもの（写し・展開・途中経過）。"""
    return [n for n in os.listdir(temp_dir(tmp_path)) if n.startswith(engine.TEMP_PREFIX)]


# ------------------------------------------------------------------ (1) 分けたときと分けないときの一致


def test_split_matches_unsplit(tmp_path, store, small_split, monkeypatch):
    """区切りに分けた検査と、分けない検査で、明細・件数・順・異なる値の数が一致する（本物のワーカーで）。"""
    folder = tmp_path / "data"
    z = make_zip(folder / "big.zip")
    job_split, r1 = run(store, folder, tmp_path)
    assert store.job(job_split)["state"] == "done", store.job(job_split)
    assert r1.splits_done == [(str(z), 4)]  # 40項目を10項目ずつの4区切り
    monkeypatch.setattr(runner, "ARCHIVE_SPLIT_MIN_WORKERS", 99)  # 分けない
    job_plain, r2 = run(store, folder, tmp_path)
    assert store.job(job_plain)["state"] == "done"
    assert r2.splits_done == []
    a, b = dump(store, job_split, str(z)), dump(store, job_plain, str(z))
    assert a["findings"] and a["file"][2] > 0  # 陽性対照: 検出がある
    assert len(a["items"]) > N_ENTRIES  # 入れ子の項目も並ぶ
    assert a["items"] == b["items"]
    assert a["findings"] == b["findings"]
    assert a["file"] == b["file"]  # 状態・件数・ファイル全体の異なる値の数・SHA-256 まで同じ
    assert a["file"][4]  # SHA-256 が付く（同じ中身の使い回しの元になれる）
    assert clean_temp(tmp_path) == []


def test_not_split_cases_still_scan(tmp_path, store, small_split, monkeypatch):
    """項目が少ない・ワーカーが足りない zip は分けずに、今までどおり検査する。"""
    folder = tmp_path / "data"
    few = make_zip(folder / "few.zip", n=15)  # 項目数が ARCHIVE_SPLIT_MIN_ENTRIES 未満
    job, r = run(store, folder, tmp_path)
    assert r.splits_done == [] and store.job(job)["state"] == "done"
    assert dump(store, job, str(few))["file"][2] > 0
    monkeypatch.setattr(runner, "ARCHIVE_SPLIT_MIN_WORKERS", 4)
    many = make_zip(folder / "many.zip")
    job, r = run(store, folder, tmp_path, workers=3)  # ワーカーが4本未満
    assert r.splits_done == [] and dump(store, job, str(many))["file"][2] > 0


def test_plan_only_for_big_zip(tmp_path):
    """scan_file は、指示（policy）と一時フォルダが渡された大きな zip だけ計画を返す。それ以外は結果を返す。"""
    z = make_zip(tmp_path / "x.zip")
    opts = ScanOptions(temp_dir=temp_dir(tmp_path), reuse=False)
    policy = splitscan.SplitPolicy(min_entries=20, part_bytes=10**9, part_entries=10, parallel=2)
    res = engine.scan_file(str(z), opts)
    assert isinstance(res, engine.FileResult)
    res = engine.scan_file(str(z), opts, None, policy, None)  # 一時フォルダが無ければ分けない
    assert isinstance(res, engine.FileResult)
    tmp = splitscan.SharedTemp(opts.temp_dir)
    try:
        plan = engine.scan_file(str(z), opts, None, policy, tmp.path)
        assert isinstance(plan, splitscan.SplitPlan)
        assert [p[:2] for p in plan.parts] == [(0, 10), (10, 20), (20, 30), (30, 40)]
        assert plan.top_item.status == Status.SCANNED and plan.source["sha256"]
        assert os.path.exists(plan.local_zip)  # 計画を返す仕事は写しを消さない
    finally:
        tmp.release()
    assert not os.path.exists(tmp.path)
    # 拡張子が zip でないもの（中身が zip）は分けない
    other = tmp_path / "x.dat"
    other.write_bytes(z.read_bytes())
    tmp = splitscan.SharedTemp(opts.temp_dir)
    try:
        assert isinstance(engine.scan_file(str(other), opts, None, policy, tmp.path), engine.FileResult)
    finally:
        tmp.release()


def test_make_parts():
    """区切りは順を保ち、大きさか項目数のどちらか先に届いた所で切る。1項目で超えるものは1区切り。"""
    assert splitscan.make_parts([1] * 25, 10**9, 10) == [(0, 10, 10), (10, 20, 10), (20, 25, 5)]
    assert splitscan.make_parts([4, 4, 4, 4, 4], 10, 100) == [(0, 2, 8), (2, 4, 8), (4, 5, 4)]
    assert splitscan.make_parts([1, 100, 1, 1], 10, 100) == [(0, 1, 1), (1, 2, 100), (2, 4, 2)]
    assert splitscan.make_parts([100], 10, 100) == [(0, 1, 100)]
    assert splitscan.make_parts([], 10, 10) == []


# ------------------------------------------------------------------ (2) 区切りの1つが落ちたとき


def test_crashed_part_makes_only_its_entries_uncheckable(tmp_path, store, small_split, monkeypatch):
    """区切り1（11〜20件目）のワーカーが異常終了しても、その区切りの項目だけが検査不能で、ほかの区切りの結果は残る。"""
    folder = tmp_path / "data"
    z = make_zip(folder / "big.zip", nested=False)
    monkeypatch.setattr(runner, "_scan_part_task", crash_part_task)
    job, r = run(store, folder, tmp_path)
    assert store.job(job)["state"] == "done", store.job(job)
    assert r.splits_done == [(str(z), 4)]
    rows = store.query("SELECT seq, path, status, reason FROM items WHERE job_id=? ORDER BY seq", (job,))
    assert len(rows) == N_ENTRIES + 1
    # 最上位も検査不能（分けない経路の save_failure と同じ考え方）で、落ちた区切りが理由に出る
    assert rows[0]["status"] == Status.UNCHECKABLE.value
    assert (
        "全 40 項目のうち 10 項目（1 区切り）" in rows[0]["reason"] and "区切り 2/4（11〜20件目）" in rows[0]["reason"]
    )
    assert "異常終了" in rows[0]["reason"]
    for k, row in enumerate(rows[1:]):
        if 10 <= k < 20:
            assert row["status"] == Status.UNCHECKABLE.value, row["path"]
            assert "区切り 2/4" in row["reason"] and "異常終了" in row["reason"]
        else:
            assert row["status"] == Status.SCANNED.value, row["path"]
    assert [r_["path"] for r_ in rows[1:]] == [f"{z}!{n}" for n in zipfile.ZipFile(z).namelist()]  # 並びは目次の順
    assert store.query("SELECT n_findings FROM files WHERE job_id=?", (job,))[0][0] > 0  # ほかの区切りの検出は残る
    assert clean_temp(tmp_path) == []


def test_failed_part_keeps_checkpoint_items():
    """途中経過のある区切りは、書き出された項目を残し、途中の項目と無い項目だけを検査不能にする。"""
    from pii_checker.models import ItemResult

    plan = splitscan.SplitPlan(
        top_path="T.zip",
        entries=[(f"e{i}", 5) for i in range(6)],
        parts=[(0, 3, 15), (3, 6, 15)],
        torch_dirs=[],
        space_extra=0,
    )
    done = ItemResult(path="T.zip!e3", kind="テキスト", status=Status.SCANNED, depth=1)
    inflight = ItemResult(path="T.zip!e4", kind="", status=Status.PENDING, depth=1)
    inner = ItemResult(path="T.zip!e4!x", kind="", status=Status.PENDING, depth=2)
    out = splitscan.failed_part(plan, 1, "時間切れ", [done, inflight, inner])
    assert [(i.path, i.status) for i in out.items] == [
        ("T.zip!e3", Status.SCANNED),
        ("T.zip!e4", Status.UNCHECKABLE),
        ("T.zip!e4!x", Status.UNCHECKABLE),
        ("T.zip!e5", Status.UNCHECKABLE),
    ]
    assert out.failed and "区切り 2/2" in out.items[-1].reason and "時間切れ" in out.items[-1].reason


# ------------------------------------------------------------------ (3) 写しが消える


def test_stop_removes_shared_copy(tmp_path, store, small_split, monkeypatch):
    """検査を止めても、写し（一時フォルダ）は残らない。親は保存されず、再開でやり直せる。"""
    folder = tmp_path / "data"
    z = make_zip(folder / "big.zip")
    monkeypatch.setattr(runner, "_scan_part_task", slow_part_task)
    job = store.create_job([str(folder)], ScanOptions(temp_dir=temp_dir(tmp_path), reuse=False))
    r = runner.JobRunner(store, job, workers=3)
    r.workers = 3
    r.start()
    seen_running = False
    for _ in range(600):  # 区切りが配られるまで（計画が戻って、配る側が写しを持った状態）
        if r.split_runs:
            seen_running = True
            break
        time.sleep(0.1)
    assert seen_running
    assert [n for n in os.listdir(temp_dir(tmp_path)) if n.startswith(engine.TEMP_PREFIX)]  # 動いている間は写しがある
    r.cancel()
    r.wait(120)
    assert not r.running
    assert store.job(job)["state"] == "cancelled"
    assert clean_temp(tmp_path) == []
    row = store.query("SELECT state FROM files WHERE job_id=? AND top_path=?", (job, str(z)))[0]
    assert row["state"] != "done"  # 中途半端な親を保存していない


def test_cleanup_does_not_remove_shared_copy(tmp_path):
    """持ち主の目印を配る側が開いている間は、後始末の掃除が写しを消さない。release の後は消える。"""
    tmp = splitscan.SharedTemp(temp_dir(tmp_path))
    with open(os.path.join(tmp.path, "copy.zip"), "wb") as f:
        f.write(b"x")
    os.utime(tmp.path, (1, 1))  # 古いものとみなされても、目印が開いている間は消えない
    runner.cleanup_stale_temp([temp_dir(tmp_path)], no_mark_grace=0)
    assert os.path.exists(os.path.join(tmp.path, "copy.zip"))
    tmp.release()
    assert not os.path.exists(tmp.path)


def test_plan_task_crash_removes_shared_copy(tmp_path, store, small_split, monkeypatch):
    """計画を返す仕事が写しの途中で異常終了しても、配る側が一時フォルダを消す。ファイルは検査不能として残る。"""
    folder = tmp_path / "data"
    z = make_zip(folder / "big.zip")
    monkeypatch.setattr(runner, "_scan_task", crash_plan_task)
    job, r = run(store, folder, tmp_path)
    assert store.job(job)["state"] == "done"
    row = store.query("SELECT worst_status, state FROM files WHERE job_id=? AND top_path=?", (job, str(z)))[0]
    assert row["state"] == "done" and row["worst_status"] == Status.UNCHECKABLE.value
    assert "異常終了" in store.query("SELECT reason FROM items WHERE job_id=?", (job,))[0][0]
    assert clean_temp(tmp_path) == []


def test_unsplit_big_zip_removes_shared_copy(tmp_path, store, monkeypatch):
    """分けないと決まった大きな zip（項目が少ない）も、先に作った一時フォルダは終わりに消える。"""
    monkeypatch.setattr(runner, "BIG_FILE_BYTES", 1)
    monkeypatch.setattr(runner, "ARCHIVE_SPLIT_MIN_WORKERS", 2)
    folder = tmp_path / "data"
    z = make_zip(folder / "big.zip", n=12)
    job, r = run(store, folder, tmp_path)
    assert r.splits_done == [] and dump(store, job, str(z))["file"][2] > 0
    assert clean_temp(tmp_path) == []


# ------------------------------------------------------------------ (4) 上限


def scan_both(store, folder, tmp_path, monkeypatch, z, **opts):
    """分けた検査と分けない検査の保存結果。"""
    job_s, r1 = run(store, folder, tmp_path, **opts)
    monkeypatch.setattr(runner, "ARCHIVE_SPLIT_MIN_WORKERS", 99)
    job_p, r2 = run(store, folder, tmp_path, **opts)
    monkeypatch.setattr(runner, "ARCHIVE_SPLIT_MIN_WORKERS", 2)
    return (job_s, r1), (job_p, r2)


def test_toc_over_limit_is_not_split_and_stops_the_same(tmp_path, store, small_split, monkeypatch):
    """目次の合計が上限（項目数・展開の合計）を超える書庫は分けず、分けないときと同じ理由で打ち切る。"""
    folder = tmp_path / "data"
    z = make_zip(folder / "big.zip", nested=False)
    for opts in ({"max_entries": 25}, {"max_expand_bytes": 1000}):
        (js, rs), (jp, rp) = scan_both(store, folder, tmp_path, monkeypatch, z, **opts)
        assert rs.splits_done == [] and rp.splits_done == []
        a, b = dump(store, js, str(z)), dump(store, jp, str(z))
        assert a == b
        top = a["items"][0]
        assert top[3] == Status.UNCHECKABLE.value and ("上限" in top[4])


def test_nested_over_limit_stops_the_same_reason(tmp_path, store, small_split, monkeypatch):
    """目次では収まるが、内側の書庫の分まで合わせると上限を超えるものは、分けたうえで同じ理由で親を打ち切る。"""
    folder = tmp_path / "data"
    z = make_zip(folder / "big.zip")  # 40項目＋入れ子の3項目×3つ
    (js, rs), (jp, rp) = scan_both(store, folder, tmp_path, monkeypatch, z, max_entries=46)
    assert rs.splits_done == [(str(z), 4)] and rp.splits_done == []
    a, b = dump(store, js, str(z)), dump(store, jp, str(z))
    ta, tb = a["items"][0], b["items"][0]
    assert ta[3] == tb[3] == Status.UNCHECKABLE.value
    assert ta[4] == tb[4] and "内側のファイル数が上限" in ta[4]
    # 分けた側は、打ち切るまでに検査できた分を捨てない（分けないときより少なくならない）
    assert len(a["items"]) >= len(b["items"]) and a["file"][2] >= b["file"][2]


# ------------------------------------------------------------------ (5) 異なる値が SEEN_LIMIT を超える


def many_values_zip(path: Path) -> Path:
    """区切りをまたいで値が重なり、異なる値が多い zip（1項目30個の電話番号）。"""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for i in range(40):
            lines = [f"携帯 090-{(i * 17 + k * 3) % 400:04d}-{(k * 7) % 100:04d}" for k in range(30)]
            z.writestr(f"d/f{i}.txt", "\n".join(lines) + "\n")
    return path


def split_in_process(path: Path, opts: ScanOptions, part_entries: int = 10):
    policy = splitscan.SplitPolicy(min_entries=10, part_bytes=10**12, part_entries=part_entries, parallel=2)
    tmp = splitscan.SharedTemp(opts.temp_dir)
    try:
        plan = engine.scan_file(str(path), opts, None, policy, tmp.path)
        assert isinstance(plan, splitscan.SplitPlan)
        outcomes = {}
        for idx, (start, end, _) in enumerate(plan.parts):
            spec = splitscan.PartSpec(idx, plan.top_path, plan.local_zip, start, end, len(plan.entries), [], 0)
            outcomes[idx] = splitscan.scan_part(spec, opts)
        return splitscan.assemble(plan, outcomes, opts)
    finally:
        tmp.release()


@pytest.mark.parametrize("limit", [None, 150, 40, 5])
def test_distinct_counts_match_over_seen_limit(tmp_path, monkeypatch, limit):
    """異なる値が SEEN_LIMIT を超えても、分けたときの数が分けないときと一致する（超えない場合も）。"""
    if limit is not None:
        monkeypatch.setattr(engine, "SEEN_LIMIT", limit)
    z = many_values_zip(tmp_path / "v.zip")
    opts = ScanOptions(temp_dir=temp_dir(tmp_path), reuse=False)
    plain = engine.scan_file(str(z), opts)
    split = split_in_process(z, opts)
    assert plain.distinct_counts and sum(plain.distinct_counts.values()) > 0
    assert split.distinct_counts == plain.distinct_counts
    assert [(i.path, i.finding_counts, i.conf_counts, i.distinct_counts) for i in split.items] == [
        (i.path, i.finding_counts, i.conf_counts, i.distinct_counts) for i in plain.items
    ]
    if limit == 40:
        assert sum(plain.distinct_counts.values()) == 40  # 上限で止まっている（陽性対照）


def test_merge_distinct_upgrades_existing_values_after_limit(monkeypatch):
    """上限に届いた後も、既にある値の確度は上げ続け、新しい値は足さない。"""
    from array import array

    monkeypatch.setattr(engine, "SEEN_LIMIT", 3)
    sink = {"phone": {1: 1, 2: 1, 3: 1}}
    splitscan.merge_distinct(
        sink, {"phone": (array("q", [3, 4, 1]), array("b", [3, 3, 2])), "email": (array("q", [9]), array("b", [1]))}
    )
    assert sink == {"phone": {1: 2, 2: 1, 3: 3}, "email": {}}


# ------------------------------------------------------------------ (6) 安定な hash


def test_stable_hash_is_same_across_processes():
    """異なる値の hash は、プロセスごとの種に依らず同じ（区切りをまたいで合わせられる）。"""
    expect = int.from_bytes(hashlib.blake2b("山田太郎".encode(), digest_size=8).digest(), "little", signed=True)
    assert engine.stable_hash("山田太郎") == expect and -(2**63) <= expect < 2**63
    code = "from pii_checker import engine; print(engine.stable_hash('山田太郎'))"
    root = str(Path(__file__).resolve().parent.parent)
    for seed in ("1", "2"):
        env = dict(os.environ, PYTHONHASHSEED=seed, PYTHONPATH=root, PYTHONIOENCODING="utf-8")
        out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, cwd=root)
        assert out.stdout.strip() == str(expect), out.stderr


# ------------------------------------------------------------------ (7) 同じ中身の使い回し（S5）との組み合わせ


def test_same_content_copy_of_split_parent(tmp_path, store, small_split, monkeypatch):
    """同じ中身の別のパスの zip は、分けて検査した親の結果を写せる（SHA-256 が親に付いている）。"""
    monkeypatch.setattr(runner, "SAME_CONTENT_MIN_BYTES", 1)
    folder = tmp_path / "data"
    a = make_zip(folder / "x" / "pack.zip")
    b = folder / "y" / "pack.zip"
    b.parent.mkdir(parents=True)
    b.write_bytes(a.read_bytes())
    job, r = run(store, folder, tmp_path, reuse=True)  # 同じ中身の使い回しを効かせる
    assert store.job(job)["state"] == "done", store.job(job)
    assert len(r.splits_done) == 1  # 分けて検査したのは1つだけ
    kinds = {
        x["top_path"]: x["reuse_kind"]
        for x in store.query("SELECT top_path, reuse_kind FROM files WHERE job_id=?", (job,))
    }
    assert sorted(kinds.values(), key=str) == [None, "same"]
    da, db = dump(store, job, str(a)), dump(store, job, str(b))
    assert da["file"][4] and da["file"][4] == db["file"][4]
    strip = lambda d, top: [(x[0],) + (x[1].replace(top, "<TOP>"),) + x[2:] for x in d["items"]]  # noqa: E731
    assert strip(da, str(a)) == strip(db, str(b))
    assert da["findings"] == db["findings"] and da["file"][2] == db["file"][2] > 0
    assert clean_temp(tmp_path) == []


# ------------------------------------------------------------------ 区切りの時間切れ・パスワード・停止と再開

PASSWORD = "secret-pw-1"


def zipcrypto_zip(name: str, data: bytes, password: str) -> bytes:
    """中身1件を ZipCrypto（従来の PKWARE 暗号）・無圧縮で格納した zip（標準の zipfile は暗号化して書けないので手で組む）。"""
    import struct
    import zlib

    table = []
    for i in range(256):
        v = i
        for _ in range(8):
            v = (v >> 1) ^ 0xEDB88320 if v & 1 else v >> 1
        table.append(v)
    keys = [0x12345678, 0x23456789, 0x34567890]

    def crc_byte(crc, b):
        return (crc >> 8) ^ table[(crc ^ b) & 0xFF]

    def update(b):
        keys[0] = crc_byte(keys[0], b)
        keys[1] = ((keys[1] + (keys[0] & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        keys[2] = crc_byte(keys[2], (keys[1] >> 24) & 0xFF)

    for b in password.encode():
        update(b)
    crc = zlib.crc32(data)
    plain = bytes(range(11)) + bytes([crc >> 24]) + data
    out = bytearray()
    for b in plain:
        t = (keys[2] | 2) & 0xFFFF
        out.append(b ^ (((t * (t ^ 1)) >> 8) & 0xFF))
        update(b)
    fname = name.encode()
    fixed = struct.pack("<HHHHHIII", 20, 1, 0, 0, 0x21, crc, len(out), len(data))
    local = b"PK\x03\x04" + fixed + struct.pack("<HH", len(fname), 0) + fname + bytes(out)
    central = (
        b"PK\x01\x02" + struct.pack("<H", 20) + fixed + struct.pack("<HHHHHII", len(fname), 0, 0, 0, 0, 0, 0) + fname
    )
    end = b"PK\x05\x06" + struct.pack("<HHHHIIH", 0, 0, 1, 1, len(central), len(local), 0)
    return local + central + end


def make_zip_with_locked(path: Path) -> Path:
    """make_zip に、パスワード付きの入れ子の zip（区切り1に入る）を足した zip。"""
    make_zip(path, nested=False)
    src = zipfile.ZipFile(path).namelist()
    locked = zipcrypto_zip("secret.txt", "携帯 090-5555-6666\n".encode(), PASSWORD)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for i, n in enumerate(src):
            z.writestr(n, f"顧客 携帯 090-1234-{i % 9:04d}\n")
            if i == 12:
                z.writestr("d1/locked.zip", locked)
    return path


def sleepy_part_task(spec, options, book):
    """区切り1番だけ終わらない（区切りの時間切れの試験用）。"""
    if spec.index == 1:
        time.sleep(120)
    return splitscan.scan_part(spec, options, book)


def test_part_timeout_makes_only_its_entries_uncheckable(tmp_path, store, small_split, monkeypatch):
    """区切りの時間制限（試験では2秒）を超えた区切りは、その区切りの項目と最上位だけが検査不能になる。"""
    folder = tmp_path / "data"
    z = make_zip(folder / "big.zip", nested=False)
    real = runner.JobRunner._timeout_for

    def short_for_parts(self, path, expanded=None):
        return 2 if expanded is not None else real(self, path)

    monkeypatch.setattr(runner.JobRunner, "_timeout_for", short_for_parts)
    monkeypatch.setattr(runner, "_scan_part_task", sleepy_part_task)
    job, r = run(store, folder, tmp_path)
    assert store.job(job)["state"] == "done", store.job(job)
    rows = store.query("SELECT status, reason FROM items WHERE job_id=? ORDER BY seq", (job,))
    assert rows[0]["status"] == Status.UNCHECKABLE.value
    assert "時間切れ（2秒）" in rows[0]["reason"] and "区切り 2/4（11〜20件目）" in rows[0]["reason"]
    assert [x["status"] for x in rows[11:21]] == [Status.UNCHECKABLE.value] * 10
    assert all(x["status"] == Status.SCANNED.value for x in rows[1:11] + rows[21:])
    assert clean_temp(tmp_path) == []


def test_locked_nested_zip_matches_unsplit(tmp_path, store, small_split, monkeypatch):
    """区切りの中の入れ子の zip が要パスワードになる場合も、分けたときと分けないときで状態・明細が一致する。"""
    folder = tmp_path / "data"
    z = make_zip_with_locked(folder / "big.zip")
    (js, rs), (jp, rp) = scan_both(store, folder, tmp_path, monkeypatch, z)
    assert rs.splits_done and not rp.splits_done
    a, b = dump(store, js, str(z)), dump(store, jp, str(z))
    assert a["file"][1] == b["file"][1] == Status.NEEDS_PASSWORD.value  # worst_status
    assert a == b


def test_password_after_split_scan_rechecks(tmp_path, store, small_split, monkeypatch):
    """要パスワードで終わった後にパスワードを足すと、分けた親も再検査され、分けない場合と同じ結果になる。"""
    folder = tmp_path / "data"
    z = make_zip_with_locked(folder / "big.zip")
    job, r = run(store, folder, tmp_path)
    assert store.job(job)["state"] == "done" and r.splits_done
    assert dump(store, job, str(z))["file"][1] == Status.NEEDS_PASSWORD.value
    r.add_password(PASSWORD)
    r.wait(300)
    assert store.job(job)["state"] == "done", store.job(job)
    after = dump(store, job, str(z))
    monkeypatch.setattr(runner, "ARCHIVE_SPLIT_MIN_WORKERS", 99)
    job2, r2 = run(store, folder, tmp_path)
    r2.add_password(PASSWORD)
    r2.wait(300)
    plain = dump(store, job2, str(z))
    assert after["file"][1] != Status.NEEDS_PASSWORD.value
    assert after == plain


def test_save_split_marks_pending_when_password_arrived_during_scan(tmp_path, store):
    """区切りを検査している間にパスワードを受け取ったら、要パスワードのまま済みにせず、検査し直しに回す。"""
    z = make_zip_with_locked(tmp_path / "big.zip")
    opts = ScanOptions(temp_dir=temp_dir(tmp_path), reuse=False)
    job = store.create_job([str(tmp_path)], opts)
    store.add_files(job, [(str(z), z.stat().st_size, None)])
    policy = splitscan.SplitPolicy(min_entries=10, part_bytes=10**12, part_entries=10, parallel=2)
    tmp = splitscan.SharedTemp(opts.temp_dir)
    r = runner.JobRunner(store, job, workers=1)
    try:
        plan = engine.scan_file(str(z), opts, None, policy, tmp.path)
        run_ = splitscan.SplitRun(plan, str(z), 0, time.time(), None, 2)
        for idx, (start, end, _) in enumerate(plan.parts):
            spec = splitscan.PartSpec(idx, plan.top_path, plan.local_zip, start, end, len(plan.entries), [], 0)
            run_.outcomes[idx] = splitscan.scan_part(spec, opts)
        r.password_version = 1  # 配った後でパスワードを受け取った
        r._save_split(run_)
    finally:
        tmp.release()
    state = store.query("SELECT state FROM files WHERE job_id=?", (job,))[0][0]
    assert state == "pending"  # 保存した後で、あらためて検査に回した
    assert store.job(job)["state"] != "error"


def test_stop_then_resume_redoes_parent_and_matches(tmp_path, store, small_split, monkeypatch):
    """停止した検査を再開すると、親ごとやり直して終わり、分けない検査と一致する（親は停止の間は done にならない）。"""
    folder = tmp_path / "data"
    z = make_zip(folder / "big.zip")
    real_part = runner._scan_part_task
    monkeypatch.setattr(runner, "_scan_part_task", slow_part_task)
    job = store.create_job([str(folder)], ScanOptions(temp_dir=temp_dir(tmp_path), reuse=False))
    r = runner.JobRunner(store, job, workers=3)
    r.workers = 3
    r.start()
    for _ in range(600):
        if r.split_runs:
            break
        time.sleep(0.1)
    assert r.split_runs
    r.cancel()
    r.wait(120)
    assert store.query("SELECT state FROM files WHERE job_id=?", (job,))[0][0] != "done"
    assert store.query("SELECT COUNT(*) FROM items WHERE job_id=?", (job,))[0][0] == 0  # 区切りごとには保存しない
    monkeypatch.setattr(runner, "_scan_part_task", real_part)
    r2 = runner.JobRunner(store, job, workers=3)
    r2.workers = 3
    r2.start()
    r2.wait(300)
    assert store.job(job)["state"] == "done", store.job(job)
    assert r2.splits_done == [(str(z), 4)]
    monkeypatch.setattr(runner, "ARCHIVE_SPLIT_MIN_WORKERS", 99)
    job_p, _ = run(store, folder, tmp_path)
    assert dump(store, job, str(z)) == dump(store, job_p, str(z))
    assert clean_temp(tmp_path) == []

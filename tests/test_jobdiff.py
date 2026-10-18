"""前回の検査との違いの試験（保存した件数どうしを比べる）。"""

from __future__ import annotations

import time

from openpyxl import load_workbook

from pii_checker import jobdiff
from pii_checker.models import FileResult, ItemResult, ScanOptions, Status
from pii_checker.report import write_xlsx
from pii_checker.store import Store


def _job(store: Store, roots: list[str], files: dict[str, tuple[int, Status]], done: bool = True, **opts) -> str:
    """files: パス → (検出件数, 状態)。件数 0 は検出なし。件数 None はまだ調べていない。"""
    job = store.create_job(roots, ScanOptions(**opts))
    store.add_files(job, [(p, 1, 1.0) for p in files])
    for p, (n, status) in files.items():
        if n is None:
            continue
        item = ItemResult(path=p, kind="テキスト", status=status)
        if n:
            item.finding_counts = {"phone": n}
            item.conf_counts = {"phone:medium": n}
        store.save_result(job, FileResult(top_path=p, items=[item]))
    store.set_job(job, state="done" if done else "interrupted", finished=time.time())
    time.sleep(0.01)  # 作った順（created）で前後を決めるので、同じ時刻にしない
    return job


def test_no_previous(tmp_path):
    store = Store(str(tmp_path / "db.sqlite3"))
    j = _job(store, [r"C:\共有"], {r"C:\共有\a.txt": (1, Status.SCANNED)})
    d = jobdiff.compute(store, j)
    assert d["previous"] is None and d["rows"] == []
    assert jobdiff.summary_text(d) == jobdiff.NO_PREVIOUS


def test_diff_kinds_and_notes(tmp_path):
    store = Store(str(tmp_path / "db.sqlite3"))
    root = r"C:\共有"
    S = Status.SCANNED
    prev = _job(
        store,
        [root],
        {
            root + r"\same.txt": (2, S),
            root + r"\more.txt": (1, S),
            root + r"\less.txt": (5, S),
            root + r"\fixed.txt": (3, S),
            root + r"\deleted.txt": (1, S),
            root + r"\locked.zip": (1, S),
            root + r"\was_clean.txt": (0, S),
        },
    )
    # 途中で止めた検査・別の場所の検査は「前回」にしない
    _job(store, [root], {root + r"\same.txt": (9, S)}, done=False)
    _job(store, [r"C:\別"], {r"C:\別\x.txt": (1, S)})
    cur = _job(
        store,
        [root.lower() + "\\"],  # 大小文字・末尾の区切りの違いは同じ場所とみなす
        {
            root + r"\same.txt": (2, S),
            root + r"\more.txt": (4, S),
            root + r"\less.txt": (2, S),
            root + r"\fixed.txt": (0, S),
            root + r"\locked.zip": (0, Status.NEEDS_PASSWORD),
            root + r"\was_clean.txt": (1, S),
            root + r"\brand_new.txt": (1, S),
        },
    )
    d = jobdiff.compute(store, cur)
    assert d["previous"]["id"] == prev
    got = {(r["kind"], r["top_path"].rsplit("\\", 1)[-1]): r for r in d["rows"]}
    assert set(got) == {
        ("new", "was_clean.txt"),
        ("new", "brand_new.txt"),
        ("gone", "fixed.txt"),
        ("gone", "deleted.txt"),
        ("gone", "locked.zip"),
        ("increased", "more.txt"),
        ("decreased", "less.txt"),
    }
    assert got[("new", "was_clean.txt")]["note"] == "前回は検出なし"
    assert got[("new", "brand_new.txt")]["note"] == "前回は無かったファイル"
    assert got[("gone", "fixed.txt")]["note"].startswith("検出が無くなった")
    assert got[("gone", "deleted.txt")]["note"].startswith("今回は見つからない")
    assert got[("gone", "locked.zip")]["note"] == "今回は調べられなかった（要パスワード）"
    assert (got[("increased", "more.txt")]["n_prev"], got[("increased", "more.txt")]["n_now"]) == (1, 4)
    assert d["counts"] == {"new": 2, "gone": 3, "increased": 1, "decreased": 1}
    text = jobdiff.summary_text(d, "「前回との違い」シート")
    assert "新しく見つかった 2 件" in text and "無くなった 3 件" in text and "シート" in text

    out = tmp_path / "r.xlsx"
    write_xlsx(store, cur, str(out))
    wb = load_workbook(out, read_only=True)
    rows = list(wb["前回との違い"].iter_rows(values_only=True))
    # 要約は表の上（絞り込みの範囲の外）に置き、3行目が見出し
    assert rows[0][0] == "要約" and "新しく見つかった 2 件" in rows[0][1]
    assert rows[2][0] == "違い" and len(rows) == 3 + 7
    assert load_workbook(out)["前回との違い"].auto_filter.ref == "A3:G10"
    assert {r[0] for r in rows[3:]} >= {"無くなった", "新しく見つかった"}
    overview = {r[0]: r[1] for r in wb["判定"].iter_rows(values_only=True) if r and r[0] and len(r) > 1}
    assert "新しく見つかった 2 件" in overview["前回との違い"]


def test_connection_target_ignores_user(tmp_path):
    store = Store(str(tmp_path / "db.sqlite3"))
    root = r"\\nas01\総務"
    conn = {"kind": "smb", "host": "NAS01", "share": "総務", "path": "", "user": "taro", "port": None}
    prev = _job(store, [root], {root + r"\a.txt": (1, Status.SCANNED)}, connection=conn)
    other = dict(conn, user="hanako", host="nas01")
    cur = _job(store, [root], {root + r"\a.txt": (1, Status.SCANNED)}, connection=other)
    assert jobdiff.previous_job(store, cur)["id"] == prev
    # 共有が違えば別の検査先
    third = _job(store, [root], {}, connection=dict(conn, share="経理"))
    assert jobdiff.previous_job(store, third) is None
    # フォルダの指定（接続方式でない）とも別
    folder_job = _job(store, [root], {})
    assert jobdiff.previous_job(store, folder_job) is None


def test_case_only_difference_is_same_file(tmp_path):
    """大小文字だけ違うパスは同じファイルとみなす（FTP 以外）。FTP は大小文字を区別する。"""
    store = Store(str(tmp_path / "db.sqlite3"))
    root = r"C:\共有"
    S = Status.SCANNED
    _job(store, [root], {root + r"\Meibo.TXT": (2, S), root + r"\Same.txt": (1, S)})
    cur = _job(store, [root], {root + r"\meibo.txt": (3, S), root + r"\SAME.TXT": (1, S)})
    d = jobdiff.compute(store, cur)
    assert [(r["kind"], r["top_path"]) for r in d["rows"]] == [("increased", root + r"\meibo.txt")]

    ftp = "ftp://192.0.2.1/共有"
    conn = {"kind": "ftp", "host": "192.0.2.1", "port": None, "share": "", "path": "共有"}
    _job(store, [ftp], {ftp + "/A.txt": (1, S)}, connection=conn)
    cur2 = _job(store, [ftp], {ftp + "/a.txt": (1, S)}, connection=conn)
    kinds = sorted(r["kind"] for r in jobdiff.compute(store, cur2)["rows"])
    assert kinds == ["gone", "new"]


def test_settings_or_version_change_is_noted(tmp_path):
    """結果に効く設定・検査器の版が違うときは比べたうえで、要約にその旨と何が違うかを添える。"""
    store = Store(str(tmp_path / "db.sqlite3"))
    root = r"C:\共有"
    S = Status.SCANNED
    _job(store, [root], {root + r"\a.txt": (2, S)})
    cur = _job(store, [root], {root + r"\a.txt": (1, S)}, allow_values=["03-1234-5678"], ocr=False)
    d = jobdiff.compute(store, cur)
    assert d["settings_changed"] == ["拾わない値（許可リスト）", "OCR"]
    text = jobdiff.summary_text(d)
    assert "件数が減った 1 件" in text
    assert "前回と設定（または検査器の版）が違うため、違いにはファイルの変化でないものを含みます" in text
    assert "拾わない値（許可リスト）・OCR" in text
    # 使い回しの指定・一時フォルダの違いは結果に効かないので添えない
    same = _job(store, [root], {root + r"\a.txt": (1, S)}, allow_values=["03 1234 5678"], ocr=False, reuse=False)
    assert jobdiff.compute(store, same)["settings_changed"] == []

    # 設定が同じでも、検査器の版（engine_sig）が違えば添える
    store2 = Store(str(tmp_path / "db2.sqlite3"))
    for sig in ("aaa", "bbb"):
        job = store2.create_job([root], ScanOptions())
        store2.add_files(job, [(root + r"\a.txt", 1, 1.0)])
        item = ItemResult(path=root + r"\a.txt", kind="テキスト", status=S)
        item.finding_counts, item.conf_counts = {"phone": 1}, {"phone:medium": 1}
        store2.save_result(job, FileResult(top_path=root + r"\a.txt", items=[item]), engine_sig=sig)
        store2.set_job(job, state="done", finished=time.time())
        time.sleep(0.01)
    d2 = jobdiff.compute(store2, job)
    assert d2["settings_changed"] == [jobdiff.VERSION_NAME]
    assert "検査器の版" in jobdiff.summary_text(d2) and "違いはありません" in jobdiff.summary_text(d2)


def test_gone_under_unreadable_folder_is_not_called_deleted(tmp_path):
    """今回開けなかったフォルダ・辿らなかったリンクの下のファイルは「調べられなかった」とし、消したと言い切らない。"""
    store = Store(str(tmp_path / "db.sqlite3"))
    root = r"C:\共有"
    S = Status.SCANNED
    _job(
        store,
        [root],
        {root + r"\人事\名簿.xlsx": (3, S), root + r"\link\x.csv": (1, S), root + r"\old.txt": (1, S)},
    )
    cur = store.create_job([root], ScanOptions())
    store.add_folder_error(cur, root + r"\人事", "error", "アクセスが拒否された")
    store.add_folder_error(cur, root + r"\LINK", "link", "リンクは辿らない")
    store.set_job(cur, state="done", finished=time.time())
    d = jobdiff.compute(store, cur)
    got = {r["top_path"].rsplit("\\", 1)[-1]: r for r in d["rows"]}
    assert got["名簿.xlsx"]["note"] == "今回は調べられなかった（フォルダを開けなかった）"
    assert got["名簿.xlsx"]["gone_reason"] == jobdiff.GONE_UNCHECKED
    assert got["名簿.xlsx"]["kind_label"] == "無くなった（調べられなかった）"
    assert got["x.csv"]["note"] == "今回は調べられなかった（リンクを辿らなかった）"
    assert got["old.txt"]["note"] == "今回は見つからない（消した・移した・名前を変えた、または今回は見えなかった）"
    assert got["old.txt"]["gone_reason"] == jobdiff.GONE_MISSING and got["old.txt"]["kind_label"] == "無くなった"
    assert d["gone_unchecked"] == 2
    assert "無くなった 3 件（うち調べられなかった 2 件）" in jobdiff.summary_text(d)


def test_previous_is_shown_by_time_not_job_id(tmp_path):
    store = Store(str(tmp_path / "db.sqlite3"))
    prev = _job(store, [r"C:\共有"], {r"C:\共有\a.txt": (1, Status.SCANNED)})
    cur = _job(store, [r"C:\共有"], {r"C:\共有\a.txt": (1, Status.SCANNED)})
    text = jobdiff.previous_text(jobdiff.compute(store, cur)["previous"])
    assert text.startswith("前回の検査（") and "に終了）" in text and prev not in text

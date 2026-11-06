"""DB へ UTF-8 にできない文字（はぐれたサロゲート）を含む結果を書く試験。

実物の F の検査で、7.8GB の zip の中の名前にサロゲートが混ざり、sqlite3 の UnicodeEncodeError で
そのファイルの結果（約1時間分）が丸ごと「検査に失敗した」になった。
"""

from __future__ import annotations

import json

from pii_checker.models import Confidence, Finding, FileResult, ItemResult, ScanOptions, Status
from pii_checker.store import Store, db_text


def test_db_text_keeps_normal_and_escapes_broken():
    assert db_text("普通の名前.txt") == "普通の名前.txt"
    assert db_text(12) == 12 and db_text(None) is None
    assert db_text("a\udc81b") == "a\\x81b"  # surrogateescape で読んだ壊れたバイトは \xNN で残す
    fixed = db_text("x\ud800y")  # 対の無い上位サロゲートは置き換える
    fixed.encode("utf-8")
    assert fixed.startswith("x") and fixed.endswith("y")


def test_save_result_with_surrogate_names(tmp_path):
    store = Store(str(tmp_path / "jobs.sqlite3"))
    top = str(tmp_path / "big.zip")
    job = store.create_job([str(tmp_path)], ScanOptions(temp_dir=str(tmp_path)))
    store.add_files(job, [(top, 10, 0.0)])
    inner = ItemResult(path=f"{top}!dir/\udc82\udca0.txt", kind="テキスト", status=Status.SCANNED, depth=1)
    inner.findings.append(
        Finding(
            pii_type="phone",
            confidence=Confidence.HIGH,
            masked_value="090-****-5678",
            location="1行目 \ud800",
            context="電話 090-****-5678",
            rule="電話番号",
        )
    )
    inner.finding_counts = {"phone": 1}
    inner.notes.append("名前 \udc82 を読めなかった")
    res = FileResult(top_path=top, items=[ItemResult(path=top, kind="zip", status=Status.SCANNED), inner], elapsed=1.0)
    store.save_result(job, res)
    paths = [r[0] for r in store.query("SELECT path FROM items WHERE job_id=? ORDER BY seq", (job,))]
    assert paths[0] == top and paths[1].endswith("dir/\\x82\\xa0.txt")
    locs = [r[0] for r in store.query("SELECT location FROM findings WHERE job_id=?", (job,))]
    assert len(locs) == 1 and locs[0].startswith("1行目 ")
    state = store.query("SELECT state, n_findings FROM files WHERE job_id=?", (job,))[0]
    assert (state[0], state[1]) == ("done", 1)
    # JSON の列（注記）も、読み戻して JSON として読める（直した後の文字が JSON の書き方を壊さない・評価の指摘）
    notes = json.loads(store.query("SELECT notes FROM items WHERE job_id=? AND seq=1", (job,))[0][0])
    assert notes == ["名前 \\x82 を読めなかった"]
    for (text,) in store.query("SELECT counts FROM items WHERE job_id=?", (job,)):
        json.loads(text)
    # 書き直しても重ならない（最初の失敗した書き込みは巻き戻っている）
    assert store.query("SELECT COUNT(*) FROM items WHERE job_id=?", (job,))[0][0] == 2

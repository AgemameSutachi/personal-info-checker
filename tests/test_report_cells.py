"""Excel のレポートに書くセルの守り（数式として扱わせない）と、「要対応」の未検査・フォルダの行の試験。"""

from __future__ import annotations

import pytest
from openpyxl import load_workbook

from pii_checker import cli
from pii_checker.report import _safe, write_xlsx
from pii_checker.store import Store


def test_safe_keeps_formula_like_text_as_text():
    """= + - @ で始まる文字列は先頭に ' を足し、Excel に数式として読ませない（1文字だけのものは数式にならないので触らない）。"""
    assert _safe('=HYPERLINK("http://192.0.2.1/","開く")') == '\'=HYPERLINK("http://192.0.2.1/","開く")'
    assert _safe("+81-90-1234-5678") == "'+81-90-1234-5678"
    assert _safe("-1+2") == "'-1+2"
    assert _safe("@SUM(A1)") == "'@SUM(A1)"
    assert _safe("-") == "-" and _safe("=") == "="
    assert _safe("山田=太郎") == "山田=太郎"  # 先頭でなければそのまま


def test_safe_drops_control_chars_and_keeps_numbers():
    """制御文字を除き、長すぎる文字を切り、None は空、数はそのまま返す。"""
    assert _safe(None) == ""
    assert _safe("a\x00b\x07c") == "abc"
    assert len(_safe("あ" * 40000)) == 32000
    long_formula = _safe("=" + "1" * 40000)
    assert long_formula.startswith("'=") and len(long_formula) == 32000  # ' を足してから切る
    assert _safe(12) == 12 and _safe(1.5) == 1.5


def _scan(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.txt").write_text("携帯 090-1234-5678\n", encoding="utf-8")
    (root / "b.txt").write_text("会議の議題\n", encoding="utf-8")
    db = tmp_path / "jobs.sqlite3"
    out = tmp_path / "out" / "r.xlsx"
    out.parent.mkdir()
    cli.main(["--db", str(db), "scan", str(root), "--no-ask", "-o", str(out)])
    store = Store(str(db))
    return store, store.jobs()[0]["id"], root


def test_needs_action_sheet_lists_pending_files_and_folder_errors(tmp_path):
    """「要対応」に、まだ検査していないファイル・読めなかったフォルダ・リンクが1行ずつ出る（フォルダのパスも数式にしない）。"""
    store, job_id, root = _scan(tmp_path)
    top = store.query("SELECT top_path FROM files WHERE job_id=? ORDER BY top_path", (job_id,))[0]["top_path"]
    store.mark_pending(job_id, [top])
    store.add_folder_error(job_id, str(root / "locked"), "error", "アクセスが拒否された")
    store.add_folder_error(job_id, "=cmd|' /C calc'!A0", "link", "リンクの先はたどらない")
    out = tmp_path / "out" / "r2.xlsx"
    write_xlsx(store, job_id, str(out))

    ws = load_workbook(out)["要対応"]
    rows = list(ws.iter_rows(min_row=2, values_only=True))
    by_kind = {}
    for r in rows:
        by_kind.setdefault(r[0], []).append(r)
    assert [r[1] for r in by_kind["未検査"]] == [top]
    assert "再開すると検査する" in by_kind["未検査"][0][3]
    locked = by_kind["読めなかったフォルダ"]
    assert [r[1] for r in locked] == [str(root / "locked")] and locked[0][3] == "アクセスが拒否された"
    assert [r[1] for r in by_kind["リンク"]] == ["'=cmd|' /C calc'!A0"]
    # 読めなかったフォルダの行だけ色を付ける
    cells = {c[0].value: c[0].fill.fgColor.rgb for c in ws.iter_rows(min_row=2)}
    assert cells["読めなかったフォルダ"].endswith("F8CBAD")
    assert cells["リンク"] == "00000000"  # 塗りなし


def test_write_xlsx_reports_unknown_job(tmp_path):
    """無いジョブを指したら、何が無いかが分かる文で止める（空のレポートを作らない）。"""
    store, _, _ = _scan(tmp_path)
    out = tmp_path / "out" / "none.xlsx"
    with pytest.raises(ValueError, match="no-such-job"):
        write_xlsx(store, "no-such-job", str(out))
    assert not out.exists()

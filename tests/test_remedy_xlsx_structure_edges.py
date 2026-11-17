"""対処の xlsx の行・列・シートの削除（remedy_write の rewrite_xlsx_structure まわり）の細かい枝の試験（実際の検査は使わない）。

test_remediate_safety.py は表（ListObject）の通しの動き（行・列の削除に表が付いてくる・見出し行は消せない）を確かめる。
ここでは、メモリの上の小さなブックで次のことを確かめる。
- 削除する行が表の外にあるとき、表が上へずれること
- 集計行のある表の範囲とオートフィルタ、集計行を消す選びの断り
- 並べ替えの状態（sortState）を外すこと（表・シートのオートフィルタ）
- シートのオートフィルタの範囲が詰まること、全部消えたら外れること
- 列の削除で、表の列が全部消えたら表ごと取り除くこと・フィルタの列の番号を付け替えること
- 列の幅の範囲（B:C のようなまとめ）と、結合が1つのセルに縮むとき・全部消えるとき
- 読めないブック・全シートの削除・選べない方法・保存できない場所の断り
"""

from __future__ import annotations

import sys
from array import array
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import openpyxl  # noqa: E402
from openpyxl.worksheet.filters import AutoFilter, FilterColumn, Filters, SortCondition, SortState  # noqa: E402
from openpyxl.worksheet.table import Table  # noqa: E402

from pii_checker import remedy_write  # noqa: E402
from pii_checker.remedy_write import RemedyError, Selection  # noqa: E402


def make_sheet(n_rows: int, n_cols: int):
    """r{行}c{列} の値で埋めた1枚のシートのブック。"""
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "名簿"
    for r in range(1, n_rows + 1):
        ws.append([f"r{r}c{c}" for c in range(1, n_cols + 1)])
    return wb, ws


def add_table(ws, ref: str, name: str = "T1", totals: int = 0) -> Table:
    """表を足す（オートフィルタと列の定義つき。集計行の数は totals）。"""
    tab = Table(displayName=name, ref=ref)
    tab.totalsRowCount = totals or None
    tab._initialise_columns()
    af_end = ref
    if totals:
        lo, hi = ref.split(":")
        col = "".join(ch for ch in hi if ch.isalpha())
        row = int("".join(ch for ch in hi if ch.isdigit()))
        af_end = f"{lo}:{col}{row - totals}"
    tab.autoFilter = AutoFilter(ref=af_end)
    ws.add_table(tab)
    return tab


def round_trip(wb, tmp_path: Path):
    """保存して読み直す（直した範囲で壊れたブックにならないことを確かめる）。"""
    p = tmp_path / "out.xlsx"
    wb.save(p)
    wb.close()
    return openpyxl.load_workbook(p)


def sel_rows(sheet: str, rows: list[int], cols: list[int] | None = None) -> Selection:
    """(行, 列) の位置を手で作った選び（行は 1 始まり・列は 0 始まり）。"""
    cols = cols or [0] * len(rows)
    arr = array("q")
    for r, c in zip(rows, cols):
        arr.extend([r, c, 0, 1])
    return Selection(groups={(sheet, "email", 0): arr})


# ---------------------------------------------------------------- 行の削除と表


def test_rows_above_table_shift_table_up(tmp_path):
    wb, ws = make_sheet(10, 2)
    tab = add_table(ws, "A5:B8")
    tab.sortState = SortState(ref="A6:B8")
    remedy_write._delete_rows(ws, [2, 3])
    assert tab.ref == "A3:B6" and tab.autoFilter.ref == "A3:B6"
    assert tab.sortState is None  # 並べ替えの範囲は古い行番号のままなので外す
    wb2 = round_trip(wb, tmp_path)
    try:
        ws2 = wb2["名簿"]
        assert ws2.tables["T1"].ref == "A3:B6" and ws2["A3"].value == "r5c1"
    finally:
        wb2.close()


def test_rows_below_table_leave_table_as_is():
    wb, ws = make_sheet(10, 2)
    tab = add_table(ws, "A1:B4")
    remedy_write._delete_rows(ws, [7, 9])
    assert tab.ref == "A1:B4" and tab.autoFilter.ref == "A1:B4"
    wb.close()


def test_table_with_totals_row_keeps_filter_above_totals(tmp_path):
    wb, ws = make_sheet(6, 2)
    tab = add_table(ws, "A1:B6", totals=1)
    remedy_write._delete_rows(ws, [3])
    assert tab.ref == "A1:B5" and tab.autoFilter.ref == "A1:B4"  # オートフィルタは集計行を含まない
    wb2 = round_trip(wb, tmp_path)
    try:
        assert wb2["名簿"].tables["T1"].ref == "A1:B5"
    finally:
        wb2.close()


def test_totals_row_cannot_be_deleted():
    wb, ws = make_sheet(6, 2)
    tab = add_table(ws, "A1:B6", totals=1)
    with pytest.raises(RemedyError, match="集計行"):
        remedy_write._delete_rows(ws, [6])
    with pytest.raises(RemedyError, match="データ行がすべて"):
        remedy_write._delete_rows(ws, [2, 3, 4, 5])  # 見出しと集計行だけの表は作れない
    assert tab.ref == "A1:B6" and ws["A6"].value == "r6c1"  # 断ったときはシートを変えない
    wb.close()


def test_sheet_autofilter_follows_row_deletion():
    wb, ws = make_sheet(6, 3)
    ws.auto_filter.ref = "A1:C6"
    ws.auto_filter.sortState = SortState(ref="A2:C6", sortCondition=[SortCondition(ref="B2:B6")])
    remedy_write._delete_rows(ws, [2, 4])
    assert ws.auto_filter.ref == "A1:C4"
    assert ws.auto_filter.sortState is not None  # 範囲が残るときは並べ替えの状態は残す
    remedy_write._delete_rows(ws, [1, 2, 3, 4])
    assert ws.auto_filter.ref is None and ws.auto_filter.sortState is None  # 範囲が全部消えたら外す
    wb.close()


def test_fix_ref_helpers():
    assert remedy_write._fix_ref_rows(None, [1]) is None
    assert remedy_write._fix_ref_rows("", [1]) == ""
    assert remedy_write._fix_ref_cols(None, [1]) is None
    assert remedy_write._fix_ref_cols("B2:D5", [2, 3, 4]) is None
    assert remedy_write._fix_ref_cols("B2:D5", [1, 3]) == "A2:B5"


# ---------------------------------------------------------------- 列の削除と表


def test_table_removed_when_all_its_columns_deleted(tmp_path):
    wb, ws = make_sheet(4, 4)
    add_table(ws, "B1:C4", name="Gone")
    add_table(ws, "D1:D4", name="Kept")
    remedy_write._delete_cols(ws, [2, 3])
    assert "Gone" not in ws.tables and ws.tables["Kept"].ref == "B1:B4"
    wb2 = round_trip(wb, tmp_path)
    try:
        ws2 = wb2["名簿"]
        assert list(ws2.tables) == ["Kept"] and ws2["B1"].value == "r1c4"
    finally:
        wb2.close()


def test_filter_columns_renumbered_after_column_deletion():
    wb, ws = make_sheet(4, 3)
    tab = add_table(ws, "A1:C4")
    tab.autoFilter.filterColumn = [
        FilterColumn(colId=0, filters=Filters(filter=["r2c1"])),
        FilterColumn(colId=1, filters=Filters(filter=["r2c2"])),
        FilterColumn(colId=2, filters=Filters(filter=["r2c3"])),
    ]
    tab.sortState = SortState(ref="A2:C4")
    remedy_write._delete_cols(ws, [2])
    assert tab.ref == "A1:B4" and tab.autoFilter.ref == "A1:B4"
    got = [(fc.colId, fc.filters.filter) for fc in tab.autoFilter.filterColumn]
    assert got == [(0, ["r2c1"]), (1, ["r2c3"])]  # 消した列のフィルタは外れ、右の列の番号が詰まる
    assert [tc.name for tc in tab.tableColumns] == ["Column1", "Column3"]
    assert tab.sortState is None
    wb.close()


def test_table_with_totals_column_deletion_keeps_filter_above_totals():
    wb, ws = make_sheet(5, 3)
    tab = add_table(ws, "A1:C5", totals=1)
    remedy_write._delete_cols(ws, [1])
    assert tab.ref == "A1:B5" and tab.autoFilter.ref == "A1:B4"
    wb.close()


def test_sheet_autofilter_follows_column_deletion():
    wb, ws = make_sheet(3, 4)
    ws.auto_filter.ref = "A1:D3"
    remedy_write._delete_cols(ws, [2])
    assert ws.auto_filter.ref == "A1:C3"
    remedy_write._delete_cols(ws, [1, 2, 3])
    assert ws.auto_filter.ref is None
    wb.close()


def test_column_width_ranges_shrink_or_vanish():
    wb, ws = make_sheet(2, 5)
    ws.column_dimensions["B"].min, ws.column_dimensions["B"].max = 2, 3
    ws.column_dimensions["B"].width = 20
    ws.column_dimensions["E"].width = 9
    remedy_write._delete_cols(ws, [3])
    assert ws.column_dimensions["B"].min == 2 and ws.column_dimensions["B"].max == 2  # B:C のまとめが B だけに
    assert ws.column_dimensions["B"].width == 20 and ws.column_dimensions["D"].width == 9
    remedy_write._delete_cols(ws, [2])
    assert ws.column_dimensions["C"].width == 9
    assert all(d.width != 20 for d in ws.column_dimensions.values())  # まとめの列が全部消えたら幅の定義も消える
    wb.close()


def test_merges_that_collapse_or_vanish():
    wb, ws = make_sheet(6, 4)
    ws.merge_cells("A2:A3")  # 行を1つ消すと1つのセルに縮む → 結合を外す
    ws.merge_cells("B5:B6")  # 行が全部消える
    ws.merge_cells("C1:D1")  # 列を1つ消すと1つのセルに縮む（列の削除のほう）
    remedy_write._delete_rows(ws, [3, 5, 6])
    assert [str(r) for r in ws.merged_cells.ranges] == ["C1:D1"]
    remedy_write._delete_cols(ws, [4])
    assert list(ws.merged_cells.ranges) == []
    ws.merge_cells("A1:B1")
    remedy_write._delete_cols(ws, [1, 2])  # 結合の列が全部消える
    assert list(ws.merged_cells.ranges) == []
    wb.close()


# ---------------------------------------------------------------- rewrite_xlsx_structure の断り


def test_structure_refuses_unreadable_book(tmp_path):
    src = tmp_path / "bad.xlsx"
    src.write_bytes(b"not a zip")
    with pytest.raises(RemedyError, match="読み込めませんでした"):
        remedy_write.rewrite_xlsx_structure(str(src), str(tmp_path / "o.xlsx"), "delete_rows", Selection(), False)


def _book(tmp_path: Path, sheets: list[str]) -> Path:
    wb = openpyxl.Workbook()
    wb.active.title = sheets[0]
    for name in sheets[1:]:
        wb.create_sheet(name)
    for ws in wb.worksheets:
        ws.append(["a", "b"])
        ws.append(["c", "d"])
    p = tmp_path / "src.xlsx"
    wb.save(p)
    wb.close()
    return p


def test_structure_refuses_deleting_every_sheet(tmp_path):
    src = _book(tmp_path, ["一", "二"])
    sel = Selection(groups={("一", "email", 0): array("q", [1, 0, 0, 1]), ("二", "email", 0): array("q", [1, 0, 0, 1])})
    with pytest.raises(RemedyError, match="すべてのシートは削除できません"):
        remedy_write.rewrite_xlsx_structure(str(src), str(tmp_path / "o.xlsx"), "delete_sheet", sel, False)
    assert not (tmp_path / "o.xlsx").exists()


def test_structure_deletes_sheets_and_skips_unknown_ones(tmp_path):
    src = _book(tmp_path, ["一", "二"])
    sel = Selection(
        groups={("一", "email", 0): array("q", [1, 0, 0, 1]), ("無い", "email", 0): array("q", [1, 0, 0, 1])}
    )
    dst = tmp_path / "o.xlsx"
    stats = remedy_write.rewrite_xlsx_structure(str(src), str(dst), "delete_sheet", sel, False)
    assert stats["sheets"] == 1
    wb = openpyxl.load_workbook(dst)
    try:
        assert wb.sheetnames == ["二"]
    finally:
        wb.close()


def test_structure_rows_and_cols_skip_missing_sheet(tmp_path):
    src = _book(tmp_path, ["一"])
    sel = sel_rows("無い", [1])
    for method in ("delete_rows", "delete_columns"):
        dst = tmp_path / f"{method}.xlsx"
        stats = remedy_write.rewrite_xlsx_structure(str(src), str(dst), method, sel, False)
        assert stats["rows"] == 0 and stats["cols"] == 0 and dst.exists()


def test_structure_refuses_unknown_method(tmp_path):
    src = _book(tmp_path, ["一"])
    with pytest.raises(RemedyError, match="この方法は選べません"):
        remedy_write.rewrite_xlsx_structure(str(src), str(tmp_path / "o.xlsx"), "dummy", Selection(), False)


def test_structure_reports_save_failure(tmp_path):
    src = _book(tmp_path, ["一"])
    dst = tmp_path / "無いフォルダ" / "o.xlsx"
    with pytest.raises(RemedyError, match="保存できませんでした"):
        remedy_write.rewrite_xlsx_structure(str(src), str(dst), "delete_rows", sel_rows("一", [2]), False)

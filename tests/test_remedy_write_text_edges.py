"""対処の書き換え（remedy_write）の、文字コード・csv・txt と xlsx のダミー置換の細かい枝の試験（実際の検査は使わない）。

test_remediate*.py は検査から対処までの通しの動きを確かめる。ここでは、関数を直に呼んで次のことを確かめる。
- 位置の絞り込み（確度）・ダミーの作り方の断り・重なる位置のまとめ・元の文字へ位置を直せないときの丸ごとの置き換え
- 文字コードの断り（BOM の後が読めない・対応しない文字コード・戻すと元と違う・戻せない文字）
- csv の欄の分け方（空の行・閉じた引用符の後の文字・行末の区切り）と、書き換えの断り・何もしない枝
- txt・ファイルの書き換えの断り（選べない方法・大きすぎる・特殊な改行・対応しない形式）
- xlsx のダミー置換で、数式のセル・中身の無いセル・変わらないセル・型の印の無いセル・無いシートを扱うこと
"""

from __future__ import annotations

import csv
import sys
import zipfile
from array import array
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import openpyxl  # noqa: E402

from pii_checker import remedy_write, textdecode  # noqa: E402
from pii_checker.remedy_write import DummyMaker, RemedyError, Selection  # noqa: E402


def sel_spans(sheet: str, spans: list[tuple[int, int, int, int]], pii_type: str = "email") -> Selection:
    """(行, 列, 開始, 終了) の位置を手で作った選び（行は 1 始まり・列は 0 始まり）。"""
    arr = array("q")
    for s in spans:
        arr.extend(s)
    return Selection(groups={(sheet, pii_type, 0): arr})


# ---------------------------------------------------------------- 位置とダミー


def test_select_positions_filters_by_rank():
    positions = {("", "email", 0): array("q", [1, 0, 0, 1]), ("", "email", 2): array("q", [2, 0, 0, 1])}
    sel = remedy_write.select_positions(positions, ranks={2})
    assert list(sel.groups) == [("", "email", 2)]


def test_dummy_maker_refuses_unknown_mode():
    with pytest.raises(RemedyError, match="ダミーの作り方"):
        DummyMaker("bad")


def test_overlapping_spans_take_the_longer_type():
    maker = DummyMaker("same", key=b"k" * 32)
    out = remedy_write.replace_spans("abcdefgh", [(0, 3, "email"), (1, 8, "phone")], maker)
    # 重なる2つは1つにまとめ、長いほう（phone）の種類でダミーを作る
    assert out == maker.make("phone", "abcdefgh")


def test_unmappable_positions_replace_whole_text():
    # 半角の「ｶﾞ」は文字ごとの NFKC（カ＋濁点）と全体の NFKC（ガ）が違い、位置を元の文字へ直せない
    out = remedy_write.replace_spans("ｶﾞ", [(0, 1, "name")], DummyMaker("fixed"))
    assert out == remedy_write.FIXED_DUMMY


def test_col_letters():
    assert [remedy_write._col_letters(i) for i in (0, 25, 26, 27, 701, 702)] == ["A", "Z", "AA", "AB", "ZZ", "AAA"]


# ---------------------------------------------------------------- 文字コード


def test_decode_refuses_broken_text_after_bom():
    with pytest.raises(RemedyError, match="文字コードを読み取れない"):
        remedy_write.decode_for_rewrite(b"\xef\xbb\xbf\xff\xfe")


def test_decode_refuses_unsupported_encoding(monkeypatch):
    monkeypatch.setattr(textdecode, "decode_text", lambda data: ("abc", "latin-1"))
    with pytest.raises(RemedyError, match="latin-1"):
        remedy_write.decode_for_rewrite(b"abc")


def test_decode_refuses_text_that_cannot_round_trip(monkeypatch):
    # 戻すときに符号化できない文字（孤立したサロゲート）が出たら、元と同じ中身にならないとして断る
    monkeypatch.setattr(textdecode, "decode_text", lambda data: ("\udc80", "utf-8"))
    with pytest.raises(RemedyError, match="元と同じ中身にならない"):
        remedy_write.decode_for_rewrite(b"\x80")


def test_encode_refuses_unencodable_text():
    with pytest.raises(RemedyError, match="元の文字コードに直せません"):
        remedy_write.encode_for_rewrite("\udc80", "utf-8", b"")


# ---------------------------------------------------------------- csv の欄の分け方


def test_split_raw_fields_edges():
    assert remedy_write.split_raw_fields("", ",") == []
    # 閉じた引用符の後の文字は、csv モジュールと同じく同じ欄に続く
    assert remedy_write.split_raw_fields('"a"b,c', ",") == [('"a"b', True), ("c", False)]
    assert remedy_write.split_raw_fields("a,", ",") == [("a", False), ("", False)]
    assert remedy_write._split_terminator("abc") == ("abc", "")


# ---------------------------------------------------------------- csv の書き換え


def test_delimited_reports_csv_error(monkeypatch):
    # 引用符を開いたままの行などでも csv モジュールは例外を出さないことがあるので、読み手を差し替えて確かめる
    class BrokenReader:
        def __iter__(self):
            return self

        def __next__(self):
            raise csv.Error("壊れた行")

    def broken_reader(*args, **kwargs):
        return BrokenReader()

    monkeypatch.setattr(csv, "reader", broken_reader)
    with pytest.raises(RemedyError, match="csv として読み取れない行"):
        remedy_write.rewrite_delimited("a,b\n", ",", "delete_rows", Selection(), None)


def test_delete_columns_keeps_rows_without_change():
    text = "a,b\n\nc,d\n"
    # 選びが空なら（消す列が無いので）空の行も含めて全部の行をそのまま写す
    out, stats = remedy_write.rewrite_delimited(text, ",", "delete_columns", Selection(), None)
    assert out == text and stats["cols"] == 0
    # 列の番号が行の欄の数より大きいと、その行は元のまま（空の行は欄が無いので元のまま）
    out, stats = remedy_write.rewrite_delimited(text, ",", "delete_columns", sel_spans("", [(1, 5, 0, 1)]), None)
    assert out == text and stats["cols"] == 1


def test_delimited_refuses_unsplittable_record(monkeypatch):
    monkeypatch.setattr(remedy_write, "split_raw_fields", lambda raw, delim: [("x", False)])
    for method in ("delete_columns", "dummy"):
        with pytest.raises(RemedyError, match="1 行目の区切り"):
            remedy_write.rewrite_delimited("a,b\n", ",", method, sel_spans("", [(1, 1, 0, 1)]), DummyMaker("fixed"))


@pytest.mark.parametrize(
    "spans",
    [
        [(1, 5, 0, 1)],  # 列 5 は行に無い
        [(1, 0, 10, 12)],  # 列 0 の位置 (10, 12) は文字の外なので変わらない
    ],
)
def test_dummy_skips_columns_out_of_range_and_unchanged_values(spans):
    text = "ab,cd\n"
    out, stats = remedy_write.rewrite_delimited(text, ",", "dummy", sel_spans("", spans), DummyMaker("fixed"))
    # 行は元のまま
    assert out == text and stats["cells"] == 0


def test_delimited_refuses_unknown_method():
    with pytest.raises(RemedyError, match="csv に使えません"):
        remedy_write.rewrite_delimited("a\n", ",", "delete_sheet", Selection(), None)


# ---------------------------------------------------------------- txt とファイル


def test_lines_refuses_unknown_method():
    with pytest.raises(RemedyError, match="テキストに使えません"):
        remedy_write.rewrite_lines("a\n", "delete_columns", Selection(), None)


def test_text_file_refuses_too_large(tmp_path, monkeypatch):
    src = tmp_path / "a.txt"
    src.write_bytes(b"abc\n")
    monkeypatch.setattr(remedy_write, "TEXT_REWRITE_LIMIT", 1)
    with pytest.raises(RemedyError, match="大きすぎる"):
        remedy_write.rewrite_text_file(str(src), str(tmp_path / "o.txt"), "lines", "delete_rows", Selection(), None)
    assert not (tmp_path / "o.txt").exists()


def test_text_file_refuses_exotic_breaks_in_huge_text(tmp_path, monkeypatch):
    src = tmp_path / "a.txt"
    src.write_bytes(b"abc\x0cdef\n")
    monkeypatch.setattr(remedy_write, "HUGE_TEXT_BYTES", 1)
    with pytest.raises(RemedyError, match="特殊な改行文字"):
        remedy_write.rewrite_text_file(str(src), str(tmp_path / "o.txt"), "lines", "delete_rows", Selection(), None)
    # csv の読み方には、この断りは当てはまらない
    remedy_write.rewrite_text_file(str(src), str(tmp_path / "o.csv"), "csv,", "delete_rows", Selection(), None)
    assert (tmp_path / "o.csv").read_bytes() == b"abc\x0cdef\n"


def test_text_file_refuses_unknown_layout(tmp_path):
    src = tmp_path / "a.txt"
    src.write_bytes(b"abc\n")
    with pytest.raises(RemedyError, match="この形式の中身の書き換えには対応していません"):
        remedy_write.rewrite_text_file(str(src), str(tmp_path / "o.txt"), "json", "dummy", Selection(), None)


# ---------------------------------------------------------------- xlsx のダミー置換


def test_xlsx_dummy_handles_formula_empty_untyped_and_unchanged_cells(tmp_path):
    src = tmp_path / "src.xlsx"
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "名簿"
    ws["A1"] = "abcdef"
    ws["B1"] = "=1+1"
    ws["C1"] = 12345
    ws["A2"] = "ab"
    wb.save(src)
    wb.close()
    # openpyxl は数のセルに t="n" を付け、空のセルは書かない。Excel の出す形（t の無い数のセル・中身の無い
    # セルの要素）にするため、シートの XML を直に書き換える
    with zipfile.ZipFile(src) as z:
        members = {name: z.read(name) for name in z.namelist()}
    sheet_xml = members["xl/worksheets/sheet1.xml"].decode("utf-8")
    before = '<c r="C1" t="n"><v>12345</v></c>'
    assert before in sheet_xml
    sheet_xml = sheet_xml.replace(before, '<c r="C1"><v>12345</v></c><c r="D1"/>')
    members["xl/worksheets/sheet1.xml"] = sheet_xml.encode("utf-8")
    with zipfile.ZipFile(src, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in members.items():
            z.writestr(name, data)
    sel = Selection(
        groups={
            ("名簿", "email", 0): array(
                "q",
                [1, 0, 0, 3]  # 文字のセル → 置き換える
                + [1, 1, 0, 3]  # 数式のセル → 触らない
                + [1, 2, 0, 3]  # 数のセル（型の印 t が無い）→ 型の印を足して文字のセルにする
                + [1, 3, 0, 3]  # 中身の無いセル → 何もしない
                + [2, 0, 10, 12],  # 文字の外の位置 → 変わらない
            ),
            ("無い", "email", 0): array("q", [1, 0, 0, 3]),
        }
    )
    dst = tmp_path / "dst.xlsx"
    stats = remedy_write.rewrite_xlsx_dummy(str(src), str(dst), sel, DummyMaker("fixed"))
    assert stats["cells"] == 2 and stats["detections"] == 2 and stats["skipped_formula"] == 1
    with zipfile.ZipFile(dst) as z:
        out_xml = z.read("xl/worksheets/sheet1.xml").decode("utf-8")
    assert '<c r="C1" t="inlineStr">' in out_xml and '<c r="D1"/>' in out_xml
    wb2 = openpyxl.load_workbook(dst)
    try:
        ws2 = wb2["名簿"]
        assert ws2["A1"].value == "＊＊＊def"
        assert ws2["B1"].value == "=1+1"
        assert ws2["C1"].value == "＊＊＊45"
        assert ws2["A2"].value == "ab"
    finally:
        wb2.close()

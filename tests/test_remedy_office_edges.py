"""対処の docx・pptx の書き換え（remedy_office）の細かい枝の試験（実際の検査は使わない）。

test_remediate_office.py は実際の検査の位置で、ダミー化・行や列の削除・スライドの削除の通しの動きを確かめる。ここでは、
位置を手で作り、軽い材料（tmp_path に作る小さな zip・lxml の小さな木）で次のことを確かめる。
- zip の読み書きの断り（zip でない・部品が大きすぎる・先頭に余分なデータがある）
- 位置の食い違い・表の外の検出・書き換える箇所が無いときの断り
- tab・改行の上から始まる値の置き換え、表の格子の列の削除（結合・行頭と行末の空き）
- スライドの削除で、区画（セクション）の参照も外れること
- 段落の外の掃除（プロパティ以外の部品・読めない部品・大きすぎる部品・縮小画像）の境界
"""

from __future__ import annotations

import sys
import zipfile
from array import array
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lxml import etree  # noqa: E402

from pii_checker import remedy_office  # noqa: E402
from pii_checker.ooxml_text import A, W, docx_atoms, pptx_atoms, pptx_para_text, atom_text  # noqa: E402
from pii_checker.remedy_write import DummyMaker, RemedyError, Selection  # noqa: E402

MAIL = "taro@example.com"
NS_W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
NS_A = 'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"'
NS_P = 'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"'
NS_R = 'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"'
DECL = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
REL_TYPE = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"


def write_zip(path: Path, parts: dict[str, str | bytes]) -> Path:
    """部品の名前 → 中身 の辞書から zip（deflate）を作る。"""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in parts.items():
            z.writestr(name, data)
    return path


@pytest.fixture
def open_package():
    """Package を開いて返す関数。試験のあとに全部閉じる（Windows でファイルを掴んだままにしない）。"""
    opened = []

    def _open(path: Path) -> remedy_office.Package:
        pkg = remedy_office.Package(str(path))
        opened.append(pkg)
        return pkg

    yield _open
    for pkg in opened:
        pkg.close()


def sel_of(sheet: str, *pos: tuple[int, int, int, int], pii_type: str = "email") -> Selection:
    """位置（段落の通し番号, 列, 開始, 終了）の並びから Selection を作る。"""
    flat = [v for p in pos for v in p]
    return Selection({(sheet, pii_type, 0): array("q", flat)})


def docx_with_body(tmp_path: Path, body: str, name: str = "a.docx") -> Path:
    doc = f"{DECL}<w:document {NS_W}><w:body>{body}</w:body></w:document>"
    return write_zip(tmp_path / name, {"word/document.xml": doc})


def mail_para() -> str:
    return f"<w:p><w:r><w:t>{MAIL}</w:t></w:r></w:p>"


# ---------------------------------------------------------------- zip の読み書き


def test_package_refuses_non_zip_and_missing_file(tmp_path):
    """zip でないファイル・無いファイルは、元を変えない旨の断りになる（例外の型名は出すが生の中身は出さない）。"""
    bad = tmp_path / "bad.docx"
    bad.write_bytes(b"not a zip at all")
    with pytest.raises(RemedyError, match="zip として読み取れませんでした.*BadZipFile"):
        remedy_office.Package(str(bad))
    with pytest.raises(RemedyError, match="zip として読み取れませんでした"):
        remedy_office.Package(str(tmp_path / "missing.docx"))


def test_package_read_edges(tmp_path, open_package, monkeypatch):
    """取り除いた部品・無い部品は KeyError、差し替えた部品はその中身、大きすぎる部品は断る。"""
    path = write_zip(tmp_path / "a.docx", {"a.xml": "<r/>", "b.xml": "<r/>"})
    pkg = open_package(path)
    pkg.remove("a.xml")
    assert not pkg.has("a.xml")
    with pytest.raises(KeyError):
        pkg.read("a.xml")
    with pytest.raises(KeyError):
        pkg.read("nothing.xml")
    pkg.set_bytes("b.xml", b"<new/>")
    assert pkg.read("b.xml") == b"<new/>"
    # 差し替えを覚えていない新しい Package で、大きさの上限を超える部品は木にも読まない
    pkg2 = open_package(path)
    monkeypatch.setattr(remedy_office, "PART_LIMIT", 2)
    with pytest.raises(RemedyError, match="大きすぎる"):
        pkg2.read("b.xml")


def test_rewrite_zip_refuses_data_before_the_first_entry(tmp_path):
    """zip の先頭に余分なデータがあるファイルは、書き換えを断り、新しいファイルを作らない。"""
    src = write_zip(tmp_path / "plain.zip", {"a.xml": "<r/>"})
    junk = tmp_path / "junk.docx"
    junk.write_bytes(b"JUNKJUNK" + src.read_bytes())
    dst = tmp_path / "out.docx"
    with pytest.raises(RemedyError, match="先頭に余分なデータ"):
        remedy_office.rewrite_zip(str(junk), str(dst), {}, set())
    assert not dst.exists()


# ---------------------------------------------------------------- 段落の範囲・置き換え


def test_orig_spans_empty_and_out_of_range():
    """範囲が空・文字の外・開始が終了以上のものは、位置として数えない。"""
    assert remedy_office.orig_spans("abc", []) == []
    assert remedy_office.orig_spans("abc", [(5, 9, "email")]) == []
    assert remedy_office.orig_spans("abc", [(2, 2, "email")]) == []


def test_orig_spans_falls_back_to_whole_paragraph_when_nfkc_cannot_map():
    """半角のかなと濁点は、1文字ずつ正規化した結果と全体の結果が食い違う。直せないときは段落全体にする。"""
    text = "ｶﾞ"
    assert remedy_office.orig_spans(text, [(0, 1, "email")]) == [(0, len(text), "email")]


def test_orig_spans_merges_overlaps_and_keeps_the_longer_type():
    """重なる範囲は1つにまとめ、長いほうの種類を残す（短いほうが後に来ても長いほうの種類のまま）。"""
    text = "x" * 12
    assert remedy_office.orig_spans(text, [(0, 5, "a"), (3, 10, "b")]) == [(0, 10, "b")]
    assert remedy_office.orig_spans(text, [(0, 8, "a"), (3, 5, "b")]) == [(0, 8, "a")]
    assert remedy_office.orig_spans(text, [(0, 3, "a"), (6, 9, "b")]) == [(0, 3, "a"), (6, 9, "b")]


def test_apply_edits_starting_on_a_tab_inserts_a_text_element_first():
    """値が tab の上から始まるとき、その前に新しい文字要素を置き、tab と値の残りを取り除く。"""
    p = etree.fromstring(f"<w:p {NS_W}><w:r><w:t>ab</w:t><w:tab/><w:t>cd</w:t></w:r></w:p>")
    atoms = docx_atoms(p)
    remedy_office.apply_edits(atoms, [(2, 4, "X")], W + "t", None)
    assert "".join(atom_text(el, k) for el, k in docx_atoms(p)) == "abXd"
    assert p.find(f".//{W}tab") is None


def test_apply_edits_covering_text_then_tab_keeps_one_replacement():
    """文字の上から始まった値が tab をまたぐときは、tab を取り除くだけで新しい文字は二重に置かない。"""
    p = etree.fromstring(f"<w:p {NS_W}><w:r><w:t>ab</w:t><w:tab/><w:t>cd</w:t></w:r></w:p>")
    remedy_office.apply_edits(docx_atoms(p), [(1, 4, "X")], W + "t", None)
    assert "".join(atom_text(el, k) for el, k in docx_atoms(p)) == "aXd"


def test_apply_edits_on_pptx_line_break_wraps_a_new_run_and_drops_bad_chars():
    """pptx は改行の上から始まる値の前に run ごと置く。XML に書けない制御文字は新しい文字から除く。"""
    p = etree.fromstring(f"<a:p {NS_A}><a:r><a:t>ab</a:t></a:r><a:br/><a:r><a:t>cd</a:t></a:r></a:p>")
    remedy_office.apply_edits(pptx_atoms(p), [(2, 4, "X\x01Y")], A + "t", A + "r")
    assert pptx_para_text(p) == "abXYd"
    assert p.find(A + "br") is None


class SameMaker:
    """置き換え先が元と同じ値を返すダミーの作り手（変わらない場合の試験用）。"""

    produced: set = set()

    def make(self, pii_type: str, value: str) -> str:
        return value


def test_dummy_paragraph_returns_false_when_nothing_changes():
    """検出の位置が無い・置き換え先が元と同じなら、段落は変えず False を返し、件数も数えない。"""
    p = etree.fromstring(f"<w:p {NS_W}><w:r><w:t>{MAIL}</w:t></w:r></w:p>")
    edited = remedy_office.Edited()
    assert not remedy_office.dummy_paragraph(p, docx_atoms, W + "t", None, W + "pPr", [], SameMaker(), edited)
    spans = [(0, len(MAIL), "email")]
    assert not remedy_office.dummy_paragraph(p, docx_atoms, W + "t", None, W + "pPr", spans, SameMaker(), edited)
    assert edited.stats == {} and edited.known == {}
    assert p.find(f".//{W}t").text == MAIL


# ---------------------------------------------------------------- 表・段落の取り除き


def body_of(inner: str):
    return etree.fromstring(f"<w:body {NS_W}>{inner}</w:body>")


def tc(span: int = 1) -> str:
    pr = f'<w:tcPr><w:gridSpan w:val="{span}"/></w:tcPr>' if span > 1 else ""
    return f"<w:tc>{pr}<w:p/></w:tc>"


def tr(*cells: str, before: int = 0, after: int = 0) -> str:
    pr = ""
    if before:
        pr += f'<w:gridBefore w:val="{before}"/>'
    if after:
        pr += f'<w:gridAfter w:val="{after}"/>'
    return f"<w:tr>{'<w:trPr>' + pr + '</w:trPr>' if pr else ''}{''.join(cells)}</w:tr>"


def tbl(*rows: str, grid: int = 2) -> str:
    return "<w:tbl><w:tblGrid>" + "<w:gridCol/>" * grid + "</w:tblGrid>" + "".join(rows) + "</w:tbl>"


def test_fix_cell_adds_a_paragraph_only_when_a_cell_does_not_end_with_one():
    """セルは段落で終わる決まり。段落で終わっていれば何もせず、表で終わる・空ならば空の段落を足す。"""
    remedy_office.fix_cell(None)
    body = body_of("<w:p/>")
    remedy_office.fix_cell(body)  # セルでない入れ物には足さない
    assert len(body) == 1
    cell = etree.fromstring(f"<w:tc {NS_W}><w:p/></w:tc>")
    remedy_office.fix_cell(cell)
    assert len(cell) == 1
    ends_with_table = etree.fromstring(f"<w:tc {NS_W}><w:tcPr/><w:tbl/></w:tc>")
    remedy_office.fix_cell(ends_with_table)
    assert ends_with_table[-1].tag == W + "p"
    only_props = etree.fromstring(f"<w:tc {NS_W}><w:tcPr/></w:tc>")
    remedy_office.fix_cell(only_props)
    assert [c.tag for c in only_props] == [W + "tcPr", W + "p"]


def test_remove_last_row_removes_the_whole_table():
    """最後の行を消すと行の無い表が残らないよう、表ごと取り除く。"""
    body = body_of(tbl(tr(tc(), tc())) + "<w:p/>")
    row = body.find(f".//{W}tr")
    remedy_office.remove_row(row)
    assert body.find(f".//{W}tbl") is None
    assert body.find(W + "p") is not None


def test_remove_table_inside_a_cell_leaves_an_empty_paragraph():
    """セルの中の表を取り除いたあと、セルが段落で終わるよう空の段落を足す。"""
    inner = tbl(tr(tc()), grid=1)
    body = body_of(tbl(tr(f"<w:tc>{inner}</w:tc>"), grid=1))
    outer_cell = body.find(f"{W}tbl/{W}tr/{W}tc")
    remedy_office.remove_table(outer_cell.find(W + "tbl"))
    assert [c.tag for c in outer_cell] == [W + "p"]


def test_int_val_falls_back_to_default_for_missing_or_broken_values():
    """gridSpan・gridBefore の値が無い・数でないときは、既定の値にする（壊れた文書でも落ちない）。"""
    broken = etree.fromstring(f'<w:gridSpan {NS_W} w:val="x"/>')
    missing = etree.fromstring(f"<w:gridSpan {NS_W}/>")
    assert remedy_office._int_val(broken) == 1
    assert remedy_office._int_val(missing, 0) == 0
    assert remedy_office._int_val(None, 7) == 7


def test_grid_start_counts_grid_before_and_merged_cells():
    """セルが始まる格子の列は、行頭の空き（gridBefore）と、手前の結合したセルの幅を数える。"""
    body = body_of(tbl(tr(tc(2), tc(), before=2), grid=5))
    row = body.find(f".//{W}tr")
    cells = [c for c in row if c.tag == W + "tc"]
    assert remedy_office.grid_start(row, cells[0]) == 2
    assert remedy_office.grid_start(row, cells[1]) == 4
    stranger = etree.fromstring(f"<w:tc {NS_W}/>")
    with pytest.raises(RemedyError, match="セルの位置を求められません"):
        remedy_office.grid_start(row, stranger)


def test_delete_grid_column_before_the_first_cell_shrinks_grid_before():
    """行頭の空きの中の列を消すと、その行は空きを1つ減らし、ほかの行はその列のセルを取り除く。"""
    body = body_of(tbl(tr(tc(), tc(), before=1), tr(tc(), tc(), tc()), grid=3))
    table = body.find(W + "tbl")
    remedy_office.delete_grid_column(table, 0)
    rows = [r for r in table if r.tag == W + "tr"]
    assert rows[0].find(f"{W}trPr/{W}gridBefore").get(W + "val") == "0"
    assert len([c for c in rows[0] if c.tag == W + "tc"]) == 2
    assert len([c for c in rows[1] if c.tag == W + "tc"]) == 2
    assert len(table.find(W + "tblGrid")) == 2


def test_delete_grid_column_narrows_a_merged_cell():
    """結合したセルの下の列を消すと、セルは取り除かず幅（gridSpan）を1つ減らす。"""
    body = body_of(tbl(tr(tc(2), tc()), tr(tc(), tc(), tc()), grid=3))
    table = body.find(W + "tbl")
    remedy_office.delete_grid_column(table, 0)
    merged = table.find(f"{W}tr/{W}tc/{W}tcPr/{W}gridSpan")
    assert merged.get(W + "val") == "1"
    assert len(table.find(W + "tblGrid")) == 2


def test_delete_grid_column_in_the_trailing_gap_shrinks_grid_after():
    """行末の空き（gridAfter）の中の列を消すと、その行は空きを1つ減らし、セルは取り除かない。"""
    body = body_of(tbl(tr(tc(), after=1), tr(tc(), tc())))
    table = body.find(W + "tbl")
    remedy_office.delete_grid_column(table, 1)
    rows = [r for r in table if r.tag == W + "tr"]
    assert rows[0].find(f"{W}trPr/{W}gridAfter").get(W + "val") == "0"
    assert len([c for c in rows[0] if c.tag == W + "tc"]) == 1
    assert len([c for c in rows[1] if c.tag == W + "tc"]) == 1


def test_delete_grid_column_drops_rows_left_without_cells_and_empty_tables():
    """セルが無くなった行は取り除き、行が1つも無くなった表は表ごと取り除く（入れ子の表ならセルへ空の段落を足す）。"""
    body = body_of(tbl(tr(tc(), tc()), tr(tc())))
    table = body.find(W + "tbl")
    remedy_office.delete_grid_column(table, 0)
    assert len([r for r in table if r.tag == W + "tr"]) == 1
    nested = body_of(tbl(tr(f"<w:tc>{tbl(tr(tc()), grid=1)}</w:tc>"), grid=1))
    outer_cell = nested.find(f"{W}tbl/{W}tr/{W}tc")
    remedy_office.delete_grid_column(outer_cell.find(W + "tbl"), 0)
    assert nested.find(f".//{W}tbl/{W}tr/{W}tc/{W}tbl") is None
    assert [c.tag for c in outer_cell] == [W + "p"]


# ---------------------------------------------------------------- docx の位置の食い違い・表の外


def test_docx_rewrite_refuses_unknown_part_and_missing_paragraph(tmp_path, open_package):
    """位置の部品が無い・段落の番号が範囲の外のときは、検査し直す旨の断りになる。"""
    path = docx_with_body(tmp_path, mail_para())
    edited = remedy_office.Edited()
    maker = DummyMaker("fixed")
    with pytest.raises(RemedyError, match="文書の位置が検査と食い違います"):
        remedy_office.rewrite_docx_package(
            open_package(path), "dummy", sel_of("word/other.xml", (1, 0, 0, 5)), maker, edited
        )
    with pytest.raises(RemedyError, match="文書の段落の位置が検査と食い違います"):
        remedy_office.rewrite_docx_package(
            open_package(path), "dummy", sel_of("word/document.xml", (99, 0, 0, 5)), maker, edited
        )
    with pytest.raises(RemedyError, match="文書の段落の位置が検査と食い違います"):
        remedy_office.rewrite_docx_package(
            open_package(path), "dummy", sel_of("word/document.xml", (0, 0, 0, 5)), maker, edited
        )


@pytest.mark.parametrize("method", ["delete_rows", "delete_columns"])
def test_docx_detection_outside_a_table_is_counted_not_deleted(tmp_path, open_package, method):
    """セルが行・表の中に無い検出は、行・列の削除では変わらず、件数だけ数える。何も変わらなければ理由つきで断る。"""
    # セルが本文の直下にある（行の中に無い）壊れた並び
    path = docx_with_body(tmp_path, f"<w:tc><w:p><w:r><w:t>{MAIL}</w:t></w:r></w:p></w:tc>")
    sel = sel_of("word/document.xml", (1, 0, 0, len(MAIL)))
    edited = remedy_office.Edited()
    remedy_office.rewrite_docx_package(open_package(path), method, sel, None, edited)
    assert edited.stats == {"outside_table": 1}
    dst = tmp_path / "out.docx"
    with pytest.raises(RemedyError, match="表の外の検出は、行・列の削除では変わりません"):
        remedy_office.rewrite_office_file(str(path), str(dst), "docx", method, sel, None)
    assert not dst.exists()


def test_dummy_that_changes_nothing_is_refused_without_writing(tmp_path):
    """置き換え先が元と同じで何も変わらないときは、書き換える箇所が無い旨の断りになり、新しいファイルを作らない。"""
    path = docx_with_body(tmp_path, mail_para())
    dst = tmp_path / "out.docx"
    sel = sel_of("word/document.xml", (1, 0, 0, len(MAIL)))
    with pytest.raises(RemedyError, match="^書き換える箇所が見つかりませんでした。元のファイルは変えていません$"):
        remedy_office.rewrite_office_file(str(path), str(dst), "docx", "dummy", sel, SameMaker())
    assert not dst.exists()


# ---------------------------------------------------------------- pptx


def slide_xml(text: str) -> str:
    return (
        f"{DECL}<p:sld {NS_A} {NS_P}><p:cSld><p:spTree><p:sp><p:txBody><a:bodyPr/>"
        f"<a:p><a:r><a:t>{text}</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>"
    )


def build_small_pptx(tmp_path: Path, name: str = "deck.pptx") -> Path:
    """2枚のスライドと、区画（セクション）の一覧を持つ、関係の部品だけの小さな pptx（app.xml・[Content_Types].xml は無い）。"""
    section = (
        '<p:extLst><p:ext uri="x"><p14:sectionLst xmlns:p14="http://schemas.microsoft.com/office/powerpoint/2010/main">'
        '<p14:section name="s" id="{1}"><p14:sldIdLst><p14:sldId id="256"/><p14:sldId id="257"/></p14:sldIdLst>'
        "</p14:section></p14:sectionLst></p:ext></p:extLst>"
    )
    pres = (
        f'{DECL}<p:presentation {NS_P} {NS_R}><p:sldIdLst><p:sldId id="256" r:id="rId1"/>'
        f'<p:sldId id="257" r:id="rId2"/></p:sldIdLst>{section}</p:presentation>'
    )
    pres_rels = (
        f'{DECL}<Relationships xmlns="{REL_NS}">'
        f'<Relationship Id="rId1" Type="{REL_TYPE}/slide" Target="slides/slide1.xml"/>'
        f'<Relationship Id="rId2" Type="{REL_TYPE}/slide" Target="slides/slide2.xml"/></Relationships>'
    )
    root_rels = (
        f'{DECL}<Relationships xmlns="{REL_NS}">'
        f'<Relationship Id="rId1" Type="{REL_TYPE}/officeDocument" Target="ppt/presentation.xml"/></Relationships>'
    )
    return write_zip(
        tmp_path / name,
        {
            "_rels/.rels": root_rels,
            "ppt/presentation.xml": pres,
            "ppt/_rels/presentation.xml.rels": pres_rels,
            "ppt/slides/slide1.xml": slide_xml(MAIL),
            "ppt/slides/slide2.xml": slide_xml("関係のない文章です"),
        },
    )


SLIDE1 = "スライド1:ppt/slides/slide1.xml"


@pytest.mark.parametrize(
    ("sheet", "row"),
    [
        ("見出しなし:ppt/slides/slide1.xml", 1),  # 見出しが「スライドN」の形でない
        ("スライド1:ppt/slides/missing.xml", 1),  # 部品が無い
        ("スライド1:ppt/slides/slide2.xml", 1),  # 番号と部品が合わない
        ("スライド9:ppt/slides/slide1.xml", 1),  # 無い番号
        (SLIDE1, 99),  # 段落の番号が範囲の外
        (SLIDE1, 0),
    ],
)
def test_pptx_refuses_positions_that_do_not_match_the_file(tmp_path, sheet, row):
    """スライドの位置（見出し・部品・番号・段落）が食い違うときは、検査し直す旨の断りで、新しいファイルを作らない。"""
    path = build_small_pptx(tmp_path)
    dst = tmp_path / "out.pptx"
    sel = sel_of(sheet, (row, 0, 0, len(MAIL)))
    with pytest.raises(RemedyError, match="スライドの(段落の)?位置が検査と食い違います"):
        remedy_office.rewrite_office_file(str(path), str(dst), "pptx", "dummy", sel, DummyMaker("fixed"))
    assert not dst.exists()


def test_pptx_delete_slide_also_clears_section_lists_without_optional_parts(tmp_path):
    """スライドを消すと、区画の一覧に残った番号も外れる。app.xml・[Content_Types].xml が無い文書でも落ちない。"""
    path = build_small_pptx(tmp_path)
    dst = tmp_path / "out.pptx"
    stats = remedy_office.rewrite_office_file(
        str(path), str(dst), "pptx", "delete_slides", sel_of(SLIDE1, (1, 0, 0, len(MAIL))), None
    )
    assert stats["slides"] == 1
    with zipfile.ZipFile(dst) as z:
        names = z.namelist()
        pres = z.read("ppt/presentation.xml").decode("utf-8")
        assert z.testzip() is None
    assert "ppt/slides/slide1.xml" not in names and "ppt/slides/slide2.xml" in names
    assert 'id="256"' not in pres and 'id="257"' in pres
    assert 'r:id="rId1"' not in pres


# ---------------------------------------------------------------- 段落の外の掃除


def test_drop_thumbnail_without_root_rels_or_thumbnail_does_nothing(tmp_path, open_package):
    """_rels/.rels が無い・縮小画像への関係が無い（外部のものは数えない）文書では、何も取り除かず件数も付けない。"""
    stats: dict = {}
    remedy_office.drop_thumbnail(open_package(write_zip(tmp_path / "a.zip", {"x.xml": "<r/>"})), stats)
    external = (
        f'{DECL}<Relationships xmlns="{REL_NS}"><Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/thumbnail" '
        'Target="http://example.com/t.jpeg" TargetMode="External"/></Relationships>'
    )
    pkg = open_package(write_zip(tmp_path / "b.zip", {"_rels/.rels": external}))
    remedy_office.drop_thumbnail(pkg, stats)
    assert stats == {} and not pkg.dirty


def scrub_package(tmp_path: Path, open_package, parts: dict[str, str | bytes]) -> remedy_office.Package:
    return open_package(write_zip(tmp_path / "s.zip", parts))


def test_scrub_other_parts_without_usable_values_does_nothing(tmp_path, open_package):
    """消した値が無い・短すぎて偶然の一致が多い値だけのときは、どの部品も読まずに戻る。"""
    pkg = scrub_package(tmp_path, open_package, {"customXml/item1.xml": f"<r>{MAIL}</r>"})
    stats: dict = {}
    remedy_office.scrub_other_parts(pkg, {}, set(), stats)
    remedy_office.scrub_other_parts(pkg, {"ab": "X"}, set(), stats)
    assert stats == {} and not pkg.dirty and not pkg.trees


def test_scrub_other_parts_skips_oversized_and_undecodable_parts(tmp_path, open_package, monkeypatch):
    """大きすぎる部品・UTF-8 として読めない部品は飛ばし、ほかの部品の掃除は続ける。"""
    pkg = scrub_package(
        tmp_path,
        open_package,
        {
            "customXml/bad.xml": b"\xff\xfe\x00" + MAIL.encode(),
            "customXml/ok.xml": f"<r>{MAIL}</r>",
        },
    )
    stats: dict = {}
    remedy_office.scrub_other_parts(pkg, {MAIL: "DUMMY"}, set(), stats)
    assert stats == {"cleaned_other": 1}
    assert pkg.dirty == {"customXml/ok.xml"}
    # 大きさの上限を超える部品は、読まずに飛ばす
    pkg2 = scrub_package(tmp_path, open_package, {"customXml/ok.xml": f"<r>{MAIL}</r>"})
    monkeypatch.setattr(remedy_office, "PART_LIMIT", 3)
    stats2: dict = {}
    remedy_office.scrub_other_parts(pkg2, {MAIL: "DUMMY"}, set(), stats2)
    assert stats2 == {} and not pkg2.dirty


def test_scrub_other_parts_leaves_broken_paragraph_part_alone(tmp_path, open_package):
    """段落を持つ部品（ヘッダーなど）が XML として読めないときは、文字列の置き換えをせずそのまま残す。"""
    broken = f"<w:hdr {NS_W}>{MAIL}"  # 閉じていない
    pkg = scrub_package(tmp_path, open_package, {"word/header1.xml": broken, "word/vmlDrawing1.vml": f"<x>{MAIL}"})
    stats: dict = {}
    remedy_office.scrub_other_parts(pkg, {MAIL: "DUMMY"}, set(), stats)
    # .vml は段落の部品ではないので、文字列のまま置き換える。ヘッダーは触らない
    assert stats == {"cleaned_other": 1}
    assert "word/header1.xml" not in pkg.replaced
    assert pkg.replaced["word/vmlDrawing1.vml"] == b"<x>DUMMY"


def test_replace_in_tree_handles_comments_text_tail_and_uri_attributes():
    """コメントは飛ばし、文字・文字の後ろ・属性の値を置き換える。関係の Target（URI）は置き換え先を URL の形にする。"""
    root = etree.fromstring(f'<r a="{MAIL}"><!-- {MAIL} --><v>{MAIL}</v>{MAIL}</r>')
    n = remedy_office._replace_in_tree(root, [MAIL], {MAIL: "ダミー 1"}, True, False)
    assert n == 3  # 属性・v の文字・v の後ろの文字
    assert root.get("a") == "ダミー 1"
    assert root.find("v").text == "ダミー 1" and root.find("v").tail == "ダミー 1"
    assert MAIL in root[0].text  # コメントは変えない
    uri = etree.fromstring(f'<r Target="mailto:{MAIL}"/>')
    remedy_office._replace_in_tree(uri, [MAIL], {MAIL: "ダミー 1"}, False, True)
    assert uri.get("Target") == "mailto:%E3%83%80%E3%83%9F%E3%83%BC%201"

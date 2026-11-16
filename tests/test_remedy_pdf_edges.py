"""対処の PDF の書き換え（remedy_pdf）の細かい枝の試験（実際の検査は使わない）。

test_remediate_pdf.py は実際の検査の位置で黒塗り・ページの削除・暗号化の扱いを確かめる。ここでは、位置を手で作って
断りの文（形式の違うシート名・行の食い違い・場所を特定できない・OCR が使えない・壊れたファイル・パスワードが無い・保存の失敗）と、
本文の外に残った値の掃除（XMP・添付の注釈・リンク・フォーム欄・縮小画像・しおり・埋め込み・独自の文書情報）の失敗時の振る舞いを、
tmp_path に作る小さな PDF で確かめる。
"""

from __future__ import annotations

import sys
import types
from array import array
from pathlib import Path

import pymupdf as fitz
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pii_checker import ocr, remedy_pdf  # noqa: E402
from pii_checker.remedy_common import Residue  # noqa: E402
from pii_checker.remedy_write import RemedyError, Selection, sha256_file  # noqa: E402

MAIL = "taro@example.com"
LINE = f"Contact: {MAIL} now"
MAIL_START = LINE.index(MAIL)
MAIL_END = MAIL_START + len(MAIL)


def sel_of(sheet: str, *pos: tuple[int, int, int, int], pii_type: str = "email") -> Selection:
    """位置（行, 列, 開始, 終了）の並びから Selection を作る。"""
    flat = [v for p in pos for v in p]
    return Selection({(sheet, pii_type, 0): array("q", flat)})


def make_pdf(path: Path, *page_texts: str, password: str | None = None) -> Path:
    """ページごとに 1 行の文字を置いた小さな PDF を作る（password があれば AES-256 で暗号化する）。"""
    doc = fitz.open()
    for text in page_texts or ("blank",):
        doc.new_page().insert_text((72, 100), text, fontsize=12)
    if password is None:
        doc.save(str(path))
    else:
        doc.save(str(path), encryption=fitz.PDF_ENCRYPT_AES_256, user_pw=password, owner_pw=password)
    doc.close()
    return path


def rewrite(tmp_path: Path, src: Path, method: str, selection: Selection) -> dict:
    return remedy_pdf.rewrite_pdf_file(str(src), str(tmp_path / "out.pdf"), method, selection, None)


def refused(tmp_path: Path, src: Path, method: str, selection: Selection) -> str:
    """書き換えが断られ、元が変わらず出力も残らないことを確かめて、断りの文を返す。"""
    before = sha256_file(str(src))
    with pytest.raises(RemedyError) as e:
        rewrite(tmp_path, src, method, selection)
    assert sha256_file(str(src)) == before
    assert not (tmp_path / "out.pdf").exists()
    return str(e.value)


class FakePage:
    """文字の箱が取れず、検索でも見つからないページ（場所を特定できない状況）。"""

    def get_text(self, kind="text"):
        return "abc" if kind == "text" else {"blocks": []}

    def search_for(self, needle):
        return []


# ---------------------------------------------------------------- 位置の読み取り・範囲


def test_parse_targets_splits_text_and_ocr_by_sheet_name():
    selection = Selection(
        {
            ("2ページ", "email", 0): array("q", [3, 0, 5, 9]),
            ("2ページ（OCR）", "phone", 0): array("q", [1, 0, 0, 4]),
        }
    )
    got = remedy_pdf.parse_targets(selection)
    assert got == {2: {"text": [(3, 5, 9, "email")], "ocr": [(1, 0, 4, "phone")]}}


def test_parse_targets_rejects_a_sheet_name_that_is_not_a_page():
    with pytest.raises(RemedyError, match="位置の形式"):
        remedy_pdf.parse_targets(sel_of("Sheet1", (1, 0, 0, 3)))


def test_orig_range_is_none_for_an_empty_or_inverted_range():
    assert remedy_pdf.orig_range("abc", 2, 2) is None
    assert remedy_pdf.orig_range("abc", 3, 1) is None
    assert remedy_pdf.orig_range("abc", -1, 2) is None
    assert remedy_pdf.orig_range("abc", 1, 99) == (1, 3)  # 終わりは正規化後の長さに丸める


def test_orig_range_falls_back_to_the_whole_line_when_positions_cannot_be_mapped(monkeypatch):
    """正規化前後の位置の対応が取れないときは、行全体を指す（取り残すより多く消す側）。"""
    monkeypatch.setattr(remedy_pdf, "_orig_bounds", lambda text, norm: None)
    assert remedy_pdf.orig_range("０９０", 0, 2) == (0, 3)


def test_shrunk_keeps_a_very_narrow_rect_horizontally_intact():
    """幅が縮める量より小さい矩形は、横には縮めない（潰れて空にならない）。縦は縮める。"""
    rect = fitz.Rect(10, 10, 10.5, 20)
    out = remedy_pdf.shrunk(fitz, rect, 1)
    assert (out.x0, out.x1) == (10, 10.5)
    assert out.y0 > 10 and out.y1 < 20
    wide = remedy_pdf.shrunk(fitz, fitz.Rect(10, 10, 110, 20), 10)
    assert wide.x0 > 10 and wide.x1 < 110


# ---------------------------------------------------------------- 文字の層の黒塗り


def test_text_values_refuses_a_line_number_beyond_the_page(tmp_path):
    p = make_pdf(tmp_path / "a.pdf", LINE)
    with fitz.open(str(p)) as doc:
        with pytest.raises(RemedyError, match="行の位置が検査と食い違"):
            remedy_pdf.text_values(doc[0], [(5, 0, 3, "email")])


def test_text_values_skips_an_empty_range(tmp_path):
    p = make_pdf(tmp_path / "a.pdf", LINE)
    with fitz.open(str(p)) as doc:
        spans, text, _boxes = remedy_pdf.text_values(doc[0], [(1, 4, 4, "email"), (1, MAIL_START, MAIL_END, "email")])
    assert [v for _a, _b, v, _t in spans] == [MAIL]  # 空の範囲は飛ばし、残りは拾う
    assert LINE in text


def test_redact_text_layer_refuses_when_the_place_cannot_be_found():
    pt = remedy_pdf.PageTargets()
    with pytest.raises(RemedyError, match="黒塗りする場所を特定できません"):
        remedy_pdf.redact_text_layer(fitz, FakePage(), [(1, 0, 3, "email")], pt)
    assert pt.rects == []


# ---------------------------------------------------------------- 画像の中の文字（OCR の読み取りは差し替える）


def test_ocr_redaction_is_refused_with_the_reason_when_ocr_is_unavailable(monkeypatch):
    monkeypatch.setattr(ocr, "is_available", lambda: False)
    monkeypatch.setattr(ocr, "unavailable_reason", lambda: "エンジンが見つかりません")
    with pytest.raises(RemedyError, match="OCR が必要ですが、使えません: エンジンが見つかりません"):
        remedy_pdf.redact_ocr_lines(fitz, None, [(1, 0, 3, "email")], remedy_pdf.PageTargets())


def test_ocr_redaction_ignores_a_missing_unavailable_reason(monkeypatch):
    monkeypatch.setattr(ocr, "is_available", lambda: False)
    monkeypatch.setattr(ocr, "unavailable_reason", lambda: None)
    with pytest.raises(RemedyError) as e:
        remedy_pdf.redact_ocr_lines(fitz, None, [(1, 0, 3, "email")], remedy_pdf.PageTargets())
    assert str(e.value).endswith("使えません: ")


def ocr_page(tmp_path: Path, monkeypatch, lines: list[dict]):
    """OCR が使え、読み取りの結果が lines になるよう差し替えて、白紙のページを返す（文書も返す）。"""
    monkeypatch.setattr(ocr, "is_available", lambda: True)
    monkeypatch.setattr(ocr, "ocr_pil_image_lines", lambda img: lines)
    doc = fitz.open(str(make_pdf(tmp_path / "blank.pdf")))
    return doc, doc[0]


def test_ocr_redaction_refuses_when_the_line_count_changed(tmp_path, monkeypatch):
    doc, page = ocr_page(tmp_path, monkeypatch, [])
    with doc:
        with pytest.raises(RemedyError, match="OCR の行の位置が検査と食い違"):
            remedy_pdf.redact_ocr_lines(fitz, page, [(1, 0, 3, "email")], remedy_pdf.PageTargets())


def test_ocr_redaction_skips_an_empty_range_and_a_line_without_boxes(tmp_path, monkeypatch):
    """範囲が空の対象と、文字の箱が無い行は、塗らずに飛ばす（矩形を付けず、画素の塗りつぶしも要求しない）。"""
    lines = [
        {"text": "abc", "chars": [(0, 5), (5, 10), (10, 15)], "top": 10, "bottom": 30},
        {"text": "abc", "chars": [], "top": 40, "bottom": 60},
    ]
    doc, page = ocr_page(tmp_path, monkeypatch, lines)
    pt = remedy_pdf.PageTargets()
    with doc:
        n = remedy_pdf.redact_ocr_lines(fitz, page, [(1, 2, 2, "email"), (2, 0, 3, "email")], pt)
    assert n == 0 and pt.rects == [] and pt.ocr is False


# ---------------------------------------------------------------- 開く・パスワード・暗号化の方式


def test_open_pdf_refuses_a_broken_file(tmp_path):
    p = tmp_path / "broken.pdf"
    p.write_bytes(b"this is not a pdf at all")
    with pytest.raises(RemedyError, match="PDF を開けませんでした"):
        remedy_pdf.open_pdf(fitz, str(p), [])


def test_open_pdf_needs_the_password_from_the_scan(tmp_path):
    p = make_pdf(tmp_path / "enc.pdf", LINE, password="pw-1")
    for given in (None, [], ["wrong"]):
        with pytest.raises(RemedyError, match="パスワードが手元に無い"):
            remedy_pdf.open_pdf(fitz, str(p), given)
    doc, used = remedy_pdf.open_pdf(fitz, str(p), ["wrong", "pw-1"])
    with doc:
        assert used == "pw-1" and doc.page_count == 1


@pytest.mark.parametrize(
    "label, attr",
    [
        ("Standard V4 R4 128-bit AES", "PDF_ENCRYPT_AES_128"),
        ("Standard V6 R6 256-bit AES", "PDF_ENCRYPT_AES_256"),
        ("Standard V2 R3 128-bit RC4", "PDF_ENCRYPT_RC4_128"),
        ("Standard V1 R2 40-bit RC4", "PDF_ENCRYPT_RC4_40"),
        ("", "PDF_ENCRYPT_AES_256"),
        (None, "PDF_ENCRYPT_AES_256"),
    ],
)
def test_encryption_method_follows_the_original(label, attr):
    doc = types.SimpleNamespace(metadata={"encryption": label})
    assert remedy_pdf.encryption_method(fitz, doc) == getattr(fitz, attr)


def test_encryption_method_defaults_to_aes256_without_metadata():
    assert remedy_pdf.encryption_method(fitz, types.SimpleNamespace(metadata=None)) == fitz.PDF_ENCRYPT_AES_256


# ---------------------------------------------------------------- 本文の外の掃除


def reopen(path: Path):
    return fitz.open(str(path))


def save_reopen(doc, path: Path):
    doc.save(str(path))
    doc.close()
    return reopen(path)


def test_clean_residue_removes_a_matching_xmp(tmp_path):
    p = make_pdf(tmp_path / "x.pdf", "plain")
    doc = reopen(p)
    doc.set_xml_metadata(f"<x:xmpmeta xmlns:x='adobe:ns:meta/'><dc:creator>{MAIL}</dc:creator></x:xmpmeta>")
    done = remedy_pdf.clean_residue(fitz, doc, Residue([MAIL], ["email"], [0]))
    assert done["metadata"] == 1 and not doc.get_xml_metadata()
    doc.close()


def test_clean_residue_removes_a_file_attachment_annotation_with_the_value(tmp_path):
    p = make_pdf(tmp_path / "x.pdf", "plain")
    doc = reopen(p)
    doc[0].add_file_annot((100, 200), f"mail: {MAIL}".encode(), "memo.txt")
    done = remedy_pdf.clean_residue(fitz, doc, Residue([MAIL], ["email"], [0]))
    assert done["annotations"] == 1 and not list(doc[0].annots() or [])
    doc.close()


def test_clean_residue_keeps_an_attachment_annotation_it_cannot_read(tmp_path, monkeypatch):
    """添付を取り出せない注釈は、判定できないので触らない（掃除は止めない）。"""
    p = make_pdf(tmp_path / "x.pdf", "plain")
    doc = reopen(p)
    doc[0].add_file_annot((100, 200), f"mail: {MAIL}".encode(), "memo.txt")

    def broken(self):
        raise RuntimeError("壊れた添付")

    monkeypatch.setattr(fitz.Annot, "get_file", broken)
    done = remedy_pdf.clean_residue(fitz, doc, Residue([MAIL], ["email"], [0]))
    assert done["annotations"] == 0 and len(list(doc[0].annots())) == 1
    doc.close()


def test_clean_residue_removes_a_link_whose_uri_holds_the_value_url_encoded(tmp_path):
    p = make_pdf(tmp_path / "x.pdf", "plain")
    doc = reopen(p)
    doc[0].insert_link({"kind": fitz.LINK_URI, "from": fitz.Rect(10, 10, 100, 30), "uri": "mailto:taro%40example.com"})
    doc[0].insert_link({"kind": fitz.LINK_URI, "from": fitz.Rect(10, 50, 100, 70), "uri": "https://example.com/"})
    done = remedy_pdf.clean_residue(fitz, doc, Residue([MAIL], ["email"], [0]))
    assert done["links"] == 1
    assert [x["uri"] for x in doc[0].get_links()] == ["https://example.com/"]  # 関係ないリンクは残る
    doc.close()


def add_text_widget(page, value: str):
    w = fitz.Widget()
    w.field_type = fitz.PDF_WIDGET_TYPE_TEXT
    w.field_name = "f1"
    w.field_value = value
    w.rect = fitz.Rect(72, 200, 300, 220)
    page.add_widget(w)


def test_clean_residue_clears_a_form_field_with_the_value(tmp_path):
    p = make_pdf(tmp_path / "x.pdf", "plain")
    doc = reopen(p)
    add_text_widget(doc[0], MAIL)
    doc = save_reopen(doc, tmp_path / "w.pdf")
    done = remedy_pdf.clean_residue(fitz, doc, Residue([MAIL], ["email"], [0]))
    # 数えることだけを見る。値が本当に消えたかは下の試験が見る
    assert done["widgets"] == 1
    doc.close()


def with_default_value(doc, xref: int) -> None:
    """欄の既定値（/DV）にも同じ値を持たせる。"""
    doc.xref_set_key(xref, "DV", f"({MAIL})")


def with_parent_field(doc, xref: int) -> None:
    """値を親のフィールドに持たせ、欄（ウィジェット）は親から値を継ぐ形にする。"""
    parent = doc.get_new_xref()
    doc.update_object(parent, f"<< /FT /Tx /T (f1) /V ({MAIL}) /Kids [{xref} 0 R] >>")
    doc.xref_set_key(xref, "Parent", f"{parent} 0 R")
    doc.xref_set_key(xref, "V", "null")
    doc.xref_set_key(xref, "T", "null")


@pytest.mark.parametrize("shape", [None, with_default_value, with_parent_field], ids=["value", "default", "parent"])
def test_clean_residue_really_empties_the_form_field_value(tmp_path, shape):
    """掃除が「消した」と数えた欄の値が、本体と同じ保存（garbage=4）の後に、値にも見た目のストリームにも残らないこと。

    PyMuPDF は field_value を空文字にしても /V を書き換えないので、本体は /V・/DV を親までたどって直に空にしている。
    """
    p = make_pdf(tmp_path / "x.pdf", "plain")
    doc = reopen(p)
    add_text_widget(doc[0], MAIL)
    doc = save_reopen(doc, tmp_path / "w.pdf")
    if shape:
        shape(doc, next(doc[0].widgets()).xref)
        doc = save_reopen(doc, tmp_path / "w1.pdf")
    assert [w.field_value for w in doc[0].widgets()] == [MAIL]  # 形を変えても値が読めること
    done = remedy_pdf.clean_residue(fitz, doc, Residue([MAIL], ["email"], [0]))
    assert done["widgets"] == 1
    assert_no_mail_after_save(doc, tmp_path / "w2.pdf")


def assert_no_mail_after_save(doc, out: Path) -> None:
    """本体と同じ保存（garbage=4）の後、欄の値が空で、どのオブジェクト・ストリームにも値が残らないこと。"""
    doc.save(str(out), garbage=4, deflate=True)
    doc.close()
    doc = reopen(out)
    try:
        assert [w.field_value for page in doc for w in page.widgets()] == [""] * sum(
            len(list(page.widgets())) for page in doc
        )
        for xref in range(1, doc.xref_length()):
            assert MAIL not in doc.xref_object(xref)
            if doc.xref_is_stream(xref):
                assert MAIL.encode() not in (doc.xref_stream(xref) or b"")
    finally:
        doc.close()


def test_clean_residue_empties_sibling_fields_on_other_pages(tmp_path):
    """同じ親から値を継ぐ欄が2ページに分かれていても、どちらの見た目にも値が残らないこと。

    1つ目の欄で親の値を空にすると2つ目の欄の値が読めなくなるので、当たる欄を先に集めておく必要がある。
    """
    doc = reopen(make_pdf(tmp_path / "x.pdf", "plain", "plain"))
    add_text_widget(doc[0], MAIL)
    add_text_widget(doc[1], MAIL)
    doc = save_reopen(doc, tmp_path / "w.pdf")
    kids = [next(doc[i].widgets()).xref for i in (0, 1)]
    parent = doc.get_new_xref()
    doc.update_object(parent, f"<< /FT /Tx /T (f1) /V ({MAIL}) /Kids [{kids[0]} 0 R {kids[1]} 0 R] >>")
    for kid in kids:
        doc.xref_set_key(kid, "Parent", f"{parent} 0 R")
        doc.xref_set_key(kid, "V", "null")
        doc.xref_set_key(kid, "T", "null")
    doc = save_reopen(doc, tmp_path / "w1.pdf")
    assert [w.field_value for page in doc for w in page.widgets()] == [MAIL, MAIL]
    done = remedy_pdf.clean_residue(fitz, doc, Residue([MAIL], ["email"], [0]))
    assert done["widgets"] == 2
    assert_no_mail_after_save(doc, tmp_path / "w2.pdf")


def test_clear_field_values_stops_at_a_broken_parent(tmp_path):
    """親が無い番号を指していても、欄の値は空にし、例外を出さずに打ち切ること。"""
    doc = reopen(make_pdf(tmp_path / "x.pdf", "plain"))
    add_text_widget(doc[0], MAIL)
    doc = save_reopen(doc, tmp_path / "w.pdf")
    xref = next(doc[0].widgets()).xref
    doc.xref_set_key(xref, "Parent", f"{doc.xref_length() + 50} 0 R")
    remedy_pdf._clear_field_values(doc, xref)
    assert doc.xref_get_key(xref, "V") == ("string", "")
    doc.close()


def test_clean_residue_goes_on_when_a_form_field_cannot_be_rewritten(tmp_path, monkeypatch):
    p = make_pdf(tmp_path / "x.pdf", "plain")
    doc = reopen(p)
    add_text_widget(doc[0], MAIL)
    doc = save_reopen(doc, tmp_path / "w.pdf")

    def broken(self):
        raise RuntimeError("更新できない欄")

    monkeypatch.setattr(fitz.Widget, "update", broken)
    done = remedy_pdf.clean_residue(fitz, doc, Residue([MAIL], ["email"], [0]))
    assert done["widgets"] == 0  # 数えない（検査し直しの残りに出る）
    doc.close()


def test_clean_residue_goes_on_when_thumbnails_cannot_be_checked(tmp_path, monkeypatch):
    p = make_pdf(tmp_path / "x.pdf", "plain")
    doc = reopen(p)

    def broken(self, xref, key):
        raise RuntimeError("読めない")

    monkeypatch.setattr(fitz.Document, "xref_get_key", broken)
    done = remedy_pdf.clean_residue(fitz, doc, Residue([MAIL], ["email"], [0]))
    assert done["thumbnails"] == 0
    doc.close()


def test_clean_residue_treats_an_unreadable_toc_as_empty(tmp_path, monkeypatch):
    p = make_pdf(tmp_path / "x.pdf", "plain")
    doc = reopen(p)

    def broken(self, *a, **k):
        raise RuntimeError("しおりが壊れている")

    monkeypatch.setattr(fitz.Document, "get_toc", broken)
    done = remedy_pdf.clean_residue(fitz, doc, Residue([MAIL], ["email"], [0]))
    assert done["bookmarks"] == 0
    doc.close()


def test_clean_residue_drops_every_bookmark_when_they_cannot_be_replaced(tmp_path, monkeypatch):
    """しおりを付け替えられないときは、値を残さない側に倒して全部外す。"""
    p = make_pdf(tmp_path / "x.pdf", "plain")
    doc = reopen(p)
    doc.set_toc([[1, f"連絡 {MAIL}", 1], [1, "Clean chapter", 1]])
    real = fitz.Document.set_toc

    def flaky(self, toc, *a, **k):
        if toc:
            raise RuntimeError("付け替えられない")
        return real(self, toc, *a, **k)

    monkeypatch.setattr(fitz.Document, "set_toc", flaky)
    done = remedy_pdf.clean_residue(fitz, doc, Residue([MAIL], ["email"], [0]))
    assert done["bookmarks"] == 2 and doc.get_toc() == []
    doc.close()


def test_clean_residue_skips_an_embedded_file_it_cannot_read(tmp_path, monkeypatch):
    p = make_pdf(tmp_path / "x.pdf", "plain")
    doc = reopen(p)
    doc.embfile_add("a.txt", f"mail: {MAIL}".encode(), filename="a.txt")

    def broken(self, name):
        raise RuntimeError("取り出せない")

    monkeypatch.setattr(fitz.Document, "embfile_get", broken)
    done = remedy_pdf.clean_residue(fitz, doc, Residue([MAIL], ["email"], [0]))
    assert done["attachments"] == 0 and doc.embfile_names() == ["a.txt"]
    doc.close()


def doc_with_company(tmp_path: Path, raw: str):
    """文書情報に独自の項目（/Company）を足した文書を返す。raw は PDF の表記。"""
    p = make_pdf(tmp_path / "x.pdf", "plain")
    doc = reopen(p)
    doc.set_metadata({"title": "Form"})
    kind, ref = doc.xref_get_key(-1, "Info")
    assert kind == "xref"  # 陽性対照（文書情報の辞書がある）
    doc.xref_set_key(int(ref.split()[0]), "Company", raw)
    return doc, int(ref.split()[0])


def test_clean_residue_nulls_a_custom_info_entry_with_the_value(tmp_path):
    doc, xref = doc_with_company(tmp_path, f"({MAIL})")
    done = remedy_pdf.clean_residue(fitz, doc, Residue([MAIL], ["email"], [0]))
    assert done["metadata"] == 1 and doc.xref_get_key(xref, "Company")[0] in ("null", "null ")
    assert doc.metadata["title"] == "Form"  # 標準の項目は触らない
    doc.close()


def test_clean_residue_keeps_a_custom_info_entry_without_the_value(tmp_path):
    doc, xref = doc_with_company(tmp_path, "(Example Corp)")
    done = remedy_pdf.clean_residue(fitz, doc, Residue([MAIL], ["email"], [0]))
    assert done["metadata"] == 0 and doc.xref_get_key(xref, "Company")[0] == "string"
    doc.close()


def test_custom_info_without_an_info_dictionary_is_zero(tmp_path):
    p = make_pdf(tmp_path / "x.pdf", "plain")
    doc = reopen(p)
    doc.xref_set_key(-1, "Info", "null")
    assert remedy_pdf._clean_custom_info(doc, Residue([MAIL], ["email"], [0])) == 0
    doc.close()


def test_custom_info_that_cannot_be_read_is_zero(tmp_path, monkeypatch):
    doc, _xref = doc_with_company(tmp_path, f"({MAIL})")

    def broken(self, xref):
        raise RuntimeError("読めない")

    monkeypatch.setattr(fitz.Document, "xref_get_keys", broken)
    assert remedy_pdf._clean_custom_info(doc, Residue([MAIL], ["email"], [0])) == 0
    doc.close()


def test_pdf_string_reads_literal_hex_and_utf16_forms():
    assert remedy_pdf._pdf_string(f"  ({MAIL})  ") == MAIL
    assert remedy_pdf._pdf_string("<" + MAIL.encode("latin-1").hex() + ">") == MAIL
    utf16 = remedy_pdf._pdf_string("<" + (b"\xfe\xff" + "連絡".encode("utf-16-be")).hex() + ">")
    assert utf16.lstrip("﻿") == "連絡"  # 先頭の BOM が残っても、値の判定には響かない
    assert remedy_pdf._pdf_string("<zz>") == "<zz>"  # 16 進として読めなければ、そのまま返す
    assert remedy_pdf._pdf_string("/SomeName") == "/SomeName"


def test_unquote_decodes_percent_escapes():
    assert remedy_pdf._unquote("mailto:taro%40example.com") == "mailto:taro@example.com"


# ---------------------------------------------------------------- rewrite_pdf_file の断り・保存の失敗


def test_rewrite_refuses_an_empty_selection(tmp_path):
    p = make_pdf(tmp_path / "a.pdf", LINE)
    assert "対象の位置がありません" in refused(tmp_path, p, "redact", Selection({}))


def test_rewrite_refuses_a_page_beyond_the_document(tmp_path):
    p = make_pdf(tmp_path / "a.pdf", LINE)
    msg = refused(tmp_path, p, "redact", sel_of("5ページ", (1, 0, MAIL_START, MAIL_END)))
    assert "ページの位置が検査と食い違" in msg
    msg = refused(tmp_path, p, "delete_pages", sel_of("0ページ", (1, 0, 0, 3)))
    assert "ページの位置が検査と食い違" in msg


def test_rewrite_refuses_a_method_that_pdf_does_not_support(tmp_path):
    p = make_pdf(tmp_path / "a.pdf", LINE)
    msg = refused(tmp_path, p, "dummy", sel_of("1ページ", (1, 0, MAIL_START, MAIL_END)))
    assert "この方法は PDF に使えません" in msg


def test_rewrite_failure_to_save_keeps_the_original_and_writes_nothing(tmp_path, monkeypatch):
    p = make_pdf(tmp_path / "a.pdf", LINE)

    def broken(self, *a, **k):
        raise OSError("ディスクがいっぱい")

    monkeypatch.setattr(fitz.Document, "save", broken)
    msg = refused(tmp_path, p, "redact", sel_of("1ページ", (1, 0, MAIL_START, MAIL_END)))
    assert "PDF を保存できませんでした（OSError）" in msg and "ディスク" not in msg  # 例外の中身は文に出さない


def test_rewrite_redact_succeeds_on_a_light_pdf_and_writes_only_the_output(tmp_path):
    """陽性対照: 同じ材料で、保存を壊さなければ黒塗りできる（上の断りが材料の不備でないことを確かめる）。"""
    p = make_pdf(tmp_path / "a.pdf", LINE)
    before = sha256_file(str(p))
    stats = rewrite(tmp_path, p, "redact", sel_of("1ページ", (1, 0, MAIL_START, MAIL_END)))
    assert sha256_file(str(p)) == before
    assert stats["pages"] == 1 and stats["regions"] == 1 and stats["detections"] == 1
    with reopen(tmp_path / "out.pdf") as doc:
        text = doc[0].get_text("text")
    assert MAIL not in text and "Contact:" in text and "now" in text

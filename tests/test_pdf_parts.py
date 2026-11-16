"""PDF の本文以外の置き場（文書情報・しおり・注釈・注釈の添付・フォーム欄・添付）と、パスワード・OCR の判定の試験。"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pii_checker import engine
from pii_checker.formats import pdf as pdf_mod
from pii_checker.models import PasswordBook, ScanOptions, Status

fitz = pytest.importorskip("pymupdf")

PHONE = "090-1234-5678"
PHONE2 = "03-1234-5678"
EMAIL = "hanako.suzuki@example.com"


def _scan(tmp_path, name: str, data: bytes, passwords: PasswordBook | None = None, **opts):
    p = tmp_path / name
    p.write_bytes(data)
    return engine.scan_file(str(p), ScanOptions(temp_dir=str(tmp_path), reuse=False, **opts), passwords).items


def _locations(item, pii_type: str) -> list[str]:
    return [f.location for f in item.findings if f.pii_type == pii_type]


def _doc_bytes(build, **save) -> bytes:
    doc = fitz.open()
    build(doc)
    data = doc.tobytes(**save)
    doc.close()
    return data


def test_metadata_bookmarks_and_annotation_text(tmp_path):
    def build(doc):
        page = doc.new_page()
        page.insert_text((60, 80), "本文は空でない")
        # 注釈にはしおりと別の値を入れる（同じ値は1件目の場所でだけ数える）
        annot = page.add_text_annot((100, 100), f"注釈の電話 {PHONE2}")
        annot.update()
        doc.new_page()
        doc.set_metadata({"author": f"作成 {EMAIL}"})
        doc.set_toc([[1, f"連絡先 {PHONE}", 2]])

    item = _scan(tmp_path, "parts.pdf", _doc_bytes(build))[0]
    assert item.status == Status.SCANNED, item.reason
    assert "文書情報 author" in _locations(item, "email")
    phone = _locations(item, "phone")
    assert "しおり（2ページ）" in phone, phone
    assert "1ページ 注釈" in phone, phone
    assert item.method == "2ページの本文・注釈・フォーム欄・しおり・文書情報"


def test_file_attachment_annotation_is_scanned_as_nested(tmp_path):
    def build(doc):
        page = doc.new_page()
        page.insert_text((60, 80), "添付あり")
        page.add_file_annot((100, 200), f"控え {PHONE}\n".encode(), "memo.txt")

    items = _scan(tmp_path, "annot.pdf", _doc_bytes(build))
    child = [it for it in items if it.path.endswith("annot.pdf!memo.txt")]
    assert child, [it.path for it in items]
    assert "phone" in child[0].finding_counts


def test_form_field_value_is_scanned_with_field_name_as_header(tmp_path, monkeypatch):
    def build(doc):
        page = doc.new_page()
        w = fitz.Widget()
        w.field_type = fitz.PDF_WIDGET_TYPE_TEXT
        w.field_name = "電話番号"
        w.field_value = "未記入"
        w.rect = fitz.Rect(50, 50, 300, 80)
        added = page.add_widget(w)
        # 値（/V）だけを書き換え、見た目（本文として読める文字）は「未記入」のままにする。
        # 見た目にも値が出ると本文として先に数えられ、フォーム欄の読み取りを確かめられない
        doc.xref_set_key(added.xref, "V", f"({PHONE})")
        off = fitz.Widget()
        off.field_type = fitz.PDF_WIDGET_TYPE_CHECKBOX
        off.field_name = "同意"
        off.rect = fitz.Rect(50, 100, 70, 120)
        page.add_widget(off)

    # 読んだフォーム欄を記録する（チェックボックスの「Off」は個人情報にならないので、結果からは読んだか分からない）
    read_fields = []
    real_add_text = engine.Collector.add_text

    def recording_add_text(self, text, location, *args, **kwargs):
        if kwargs.get("method") == "フォーム欄":
            read_fields.append((kwargs.get("header"), text))
        return real_add_text(self, text, location, *args, **kwargs)

    monkeypatch.setattr(engine.Collector, "add_text", recording_add_text)
    item = _scan(tmp_path, "form.pdf", _doc_bytes(build))[0]
    assert not any(f.method == "本文" for f in item.findings), item.findings  # 前提: 値は本文に出ていない
    assert "1ページ フォーム欄「電話番号」" in _locations(item, "phone"), item.findings
    assert read_fields == [("電話番号", PHONE)]  # 「Off」の欄（同意）は読まない


def test_embedded_file_that_cannot_be_extracted_is_recorded(tmp_path, monkeypatch):
    def build(doc):
        doc.new_page().insert_text((60, 80), "添付あり")
        doc.embfile_add("list.csv", f"電話\n{PHONE}\n".encode())

    def broken(self, name):
        raise RuntimeError("壊れた添付")

    monkeypatch.setattr(fitz.Document, "embfile_get", broken)
    items = _scan(tmp_path, "emb.pdf", _doc_bytes(build))
    bad = [it for it in items if it.path.endswith("emb.pdf!list.csv")]
    assert bad and bad[0].status == Status.UNCHECKABLE
    assert bad[0].kind == "PDF の添付"
    assert bad[0].reason.startswith("添付を取り出せなかった（壊れている可能性）。")
    assert bad[0].reason.endswith("（詳細: RuntimeError: 壊れた添付）")
    assert "添付" not in items[0].method  # 取り出せなかった添付は数えない


def test_embedded_file_counted_in_method(tmp_path):
    def build(doc):
        doc.new_page().insert_text((60, 80), "添付あり")
        doc.embfile_add("list.csv", f"電話\n{PHONE}\n".encode())

    items = _scan(tmp_path, "emb_ok.pdf", _doc_bytes(build))
    assert items[0].method.startswith("1ページの本文・添付 1件・"), items[0].method
    assert any(it.path.endswith("!list.csv") and "phone" in it.finding_counts for it in items)


def test_password_protected_pdf(tmp_path):
    data = _doc_bytes(
        lambda doc: doc.new_page().insert_text((60, 80), f"電話 {PHONE}"),
        encryption=fitz.PDF_ENCRYPT_AES_256,
        owner_pw="owner-pw",
        user_pw="user-pw",
    )
    item = _scan(tmp_path, "locked.pdf", data)[0]
    assert item.status == Status.NEEDS_PASSWORD, item.reason
    assert item.password_kind == "pdf"
    item = _scan(tmp_path, "locked2.pdf", data, PasswordBook(common=["nope", "user-pw"]))[0]
    assert item.status == Status.SCANNED, item.reason
    assert "パスワードで開いた" in item.notes
    assert "phone" in item.finding_counts


def test_owner_password_only_opens_without_note(tmp_path):
    """開くパスワードが無い（権限のパスワードだけの）PDF は、空のパスワードで開けて補足を付けない。"""
    data = _doc_bytes(
        lambda doc: doc.new_page().insert_text((60, 80), f"電話 {PHONE}"),
        encryption=fitz.PDF_ENCRYPT_AES_256,
        owner_pw="owner-pw",
        user_pw="",
    )
    item = _scan(tmp_path, "owner_only.pdf", data)[0]
    assert item.status == Status.SCANNED, item.reason
    assert "パスワードで開いた" not in item.notes


def _image_only_pdf(pages: int) -> bytes:
    from PIL import Image
    import io

    buf = io.BytesIO()
    Image.new("RGB", (200, 100), "white").save(buf, "PNG")

    def build(doc):
        for _ in range(pages):
            doc.new_page().insert_image(fitz.Rect(50, 50, 450, 250), stream=buf.getvalue())

    return _doc_bytes(build)


def test_image_only_page_without_ocr_is_uncheckable_with_hint(tmp_path):
    item = _scan(tmp_path, "scan.pdf", _image_only_pdf(1))[0]
    assert item.status == Status.UNCHECKABLE
    assert item.reason.startswith(
        "画像だけのページ（1）を OCR できず検査できていない（要目視）。OCR を無効にして実行した。"
    )


def test_image_only_pages_when_ocr_is_unavailable(tmp_path, monkeypatch):
    from pii_checker import ocr

    monkeypatch.setattr(ocr, "is_available", lambda: False)
    monkeypatch.setattr(ocr, "unavailable_reason", lambda: "OCR の部品が無い（試験）")
    item = _scan(tmp_path, "scan17.pdf", _image_only_pdf(17), ocr=True)[0]
    assert item.status == Status.UNCHECKABLE
    assert "1、2、3、4、5、6、7、8、9、10、11、12、13、14、15 ほか計17ページ" in item.reason
    assert item.reason.endswith("OCR の部品が無い（試験）")


def test_encrypted_pdf_with_separate_encrypt_object_cut_before_xref(tmp_path):
    """暗号化の辞書を別の object に置く PDF（Acrobat 等の形）が途中で切れると、MuPDF は暗号化されていない PDF として
    組み直す。辞書の印が残っているので、読んでも暗号のままと分かり「検査済み」と黙らない。

    検体は、PyMuPDF の暗号化 PDF を相互参照表の前で切り、暗号化の辞書の印（/Filter/Standard）を持つ object を
    後ろに足しただけの最小の再現（実物の辞書にある /O・/U や、trailer の /Encrypt N 0 R は無い）。"""
    data = _doc_bytes(
        lambda doc: doc.new_page().insert_text((60, 80), f"電話 {PHONE}"),
        encryption=fitz.PDF_ENCRYPT_AES_256,
        owner_pw="o",
        user_pw="u",
    )
    cut = data[: data.rfind(b"\nxref")] + b"\n99 0 obj\n<</Filter/Standard/V 5/R 6/Length 256>>\nendobj\n"
    with fitz.open(stream=cut, filetype="pdf") as d:
        assert d.is_repaired and not d.is_encrypted  # 前提
    item = _scan(tmp_path, "acrobat_cut.pdf", cut)[0]
    assert item.status == Status.UNCHECKABLE
    assert item.reason.startswith("暗号化された PDF が壊れていて（途中で切れている等）、復号できないため")
    assert not item.finding_counts


# ------------------------------------------------------------------ OCR するかの判定（ページの偽物で）


class _Rect:
    """abs() でページの面積を返すだけの長方形。"""

    def __init__(self, area: float):
        self.area = area

    def __abs__(self):
        return self.area


def _fake_page(images=(), image_info_error=False, drawings=0, area=10000.0):
    def get_image_info():
        if image_info_error:
            raise RuntimeError("画像の情報を読めない")
        return [{"bbox": b} for b in images]

    return SimpleNamespace(
        rect=_Rect(area),
        get_image_info=get_image_info,
        get_images=lambda: [],
        get_drawings=lambda: [None] * drawings,
    )


def test_needs_ocr_reasons():
    assert pdf_mod._needs_ocr(_fake_page(), " abc") == "文字化け"
    # 文字のあるページでも、大きな画像（身分証の写し等）が貼ってあれば OCR する
    assert pdf_mod._needs_ocr(_fake_page(images=[(0, 0, 80, 80)]), "申込書の本文") == "画像あり"
    # 小さな画像（ロゴ等）は OCR しない
    assert pdf_mod._needs_ocr(_fake_page(images=[(0, 0, 20, 20)]), "申込書の本文") == ""
    # 文字が少なく図形が多い（文字をアウトライン化した）ページ
    assert pdf_mod._needs_ocr(_fake_page(drawings=51), "表題") == "アウトライン化"
    assert pdf_mod._needs_ocr(_fake_page(drawings=50), "表題") == ""
    # 画像の情報が読めなくても落ちない（画像なしとして判定を続ける）
    assert pdf_mod._needs_ocr(_fake_page(image_info_error=True), "十分に長い本文" * 10) == ""


def test_needs_ocr_survives_drawings_error():
    page = _fake_page()

    def boom():
        raise RuntimeError("図形を読めない")

    page.get_drawings = boom
    assert pdf_mod._needs_ocr(page, "表題") == ""

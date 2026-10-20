"""PDF への対処（T2-c: 黒塗り・ページの削除）の試験。

守ること: T2-a と同じ（検査は何も書き込まない・書き換えは一時の名前の新ファイルから確定・失敗で元を壊さない・記録とジョブの DB に生の値を入れない）に加えて、
黒塗りのあと、検査し直して消え・ページのテキストの抽出にも生のバイト列（全オブジェクトを展開して）にも値が無く・関係ない文字は残り・
メタデータ（作成者・題・XMP）・注釈・しおり・埋め込みファイルの値も消え・増分保存にならず・暗号化された PDF は同じパスワードで暗号化し直す。
検体はすべて pytest の tmp_path に作る。本物のごみ箱へは送らない（送る関数を差し替える）。画面・Acrobat は開かない。
"""

from __future__ import annotations

import io
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from pii_checker import remediate  # noqa: E402
from pii_checker.models import PasswordBook, ScanOptions  # noqa: E402
from pii_checker.remedy_write import RemedyError  # noqa: E402
from test_remediate import ALL_RANKS, FakeTrash, analyze, make_service, new_tmp_files, run  # noqa: E402


def ocr_available() -> bool:
    try:
        from pii_checker import ocr

        return ocr.is_available()
    except Exception:  # noqa: BLE001
        return False


PDF_MAIL = "taro.yamada@example.com"
PDF_PHONE = "090-1234-5678"
PDF_JP_PHONE = "080-7777-6666"
PDF_META_MAIL = "meta.author@example.com"
PDF_TOC_PHONE = "070-3030-4040"
PDF_ANNOT_MAIL = "annot.note@example.com"
PDF_EMBED_MAIL = "embedded.person@example.com"
PDF_PAGE2_MAIL = "second.page@example.com"
PDF_NEEDLES = [
    PDF_MAIL,
    PDF_PHONE,
    PDF_JP_PHONE,
    PDF_META_MAIL,
    PDF_TOC_PHONE,
    PDF_ANNOT_MAIL,
    PDF_EMBED_MAIL,
    PDF_PAGE2_MAIL,
]


@pytest.fixture(autouse=True)
def trash(tmp_path, monkeypatch):
    """どの試験でも、ごみ箱へ送る関数を差し替える（本物のごみ箱へ送らない）。ごみ箱のある場所として扱う。"""
    t = FakeTrash(tmp_path / "_trash")
    monkeypatch.setattr(remediate, "send_to_recycle_bin", t)
    monkeypatch.setattr(remediate, "has_recycle_bin", lambda path: True)
    return t


def build_pdf(tmp_path: Path, name: str = "form.pdf", with_extras: bool = True) -> Path:
    """本文・メタデータ・しおり・注釈・埋め込みファイルに値を散らした PDF（増分保存で、古い版も残してある）。"""
    import pymupdf as fitz

    p = tmp_path / "src" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((72, 100), f"Contact: {PDF_MAIL} now", fontsize=12)
    page.insert_text((72, 114), f"Phone {PDF_PHONE} and more text", fontsize=12)
    page.insert_text((72, 140), "This line has nothing personal.", fontsize=12)
    page.insert_text((72, 170), f"電話 {PDF_JP_PHONE} です", fontsize=12, fontname="japan")
    page2 = doc.new_page()
    page2.insert_text((72, 100), f"Second page {PDF_PAGE2_MAIL} end", fontsize=12)
    page3 = doc.new_page()
    page3.insert_text((72, 100), "Third page is clean.", fontsize=12)
    if with_extras:
        doc.set_metadata({"author": PDF_META_MAIL, "title": "Application form", "creator": "tester"})
        doc.set_toc([[1, f"連絡 {PDF_TOC_PHONE}", 1], [1, "Clean chapter", 3]])
        annot = doc[0].add_text_annot((300, 300), f"memo {PDF_ANNOT_MAIL}")
        annot.update()
        doc.embfile_add("note.txt", f"mail: {PDF_EMBED_MAIL}\n".encode(), filename="note.txt")
    doc.save(str(p))
    doc.close()
    if with_extras:
        # 増分保存: 古い版（変える前の中身）がファイルに残る状態にする
        doc = fitz.open(str(p))
        doc[2].insert_text((72, 140), "Added later.", fontsize=12)
        doc.saveIncr()
        doc.close()
    return p


def encrypt_pdf(src: Path, password: str) -> None:
    """src を、同じ名前のまま AES-256 で暗号化し直す。"""
    import pymupdf as fitz

    out = src.with_name("enc-" + src.name)
    with fitz.open(str(src)) as doc:
        doc.save(str(out), encryption=fitz.PDF_ENCRYPT_AES_256, user_pw=password, owner_pw=password)
    src.unlink()
    out.rename(src)


def pdf_text(path: Path, password: str | None = None) -> str:
    import pymupdf as fitz

    with fitz.open(str(path)) as doc:
        if doc.needs_pass:
            assert doc.authenticate(password or "")
        return "\n".join(pg.get_text("text") for pg in doc)


def pdf_dump(path: Path, password: str | None = None) -> bytes:
    """ファイルの生のバイト列と、全オブジェクト（ストリームは展開して）をつないだもの。値が残っていないかを探す。"""
    import pymupdf as fitz

    out = [path.read_bytes()]
    with fitz.open(str(path)) as doc:
        if doc.needs_pass:
            assert doc.authenticate(password or "")
        for x in range(1, doc.xref_length()):
            try:
                out.append(doc.xref_object(x, compressed=False).encode("utf-8", "replace"))
                s = doc.xref_stream(x)
                if s:
                    out.append(s)
            except Exception:  # noqa: BLE001
                pass
    return b"\n".join(out)


def has_bytes(blob: bytes, needle: str) -> bool:
    """値が生のバイト列にあるか。文字として（主な文字コード）だけでなく、PDF の 16 進文字列（<…>）としても探す。"""
    low = blob.lower()
    for enc in ("utf-8", "utf-16-be", "utf-16-le", "cp932"):
        raw = needle.encode(enc)
        if raw in blob or raw.hex().encode() in low:
            return True
    return False


def test_pdf_positions_use_page_and_line(tmp_path):
    p = build_pdf(tmp_path)
    got = remediate.collect_task({"path": str(p), "options": ScanOptions(temp_dir=str(tmp_path))})
    assert got["layout"] == "pdf" and got["status"] == "scanned"
    assert {k[0] for k in got["positions"]} == {"1ページ", "2ページ"}
    assert all(isinstance(v, int) for arr in got["positions"].values() for v in arr)
    assert "example.com" not in repr(got["positions"])


def test_pdf_redact_removes_text_everywhere_and_keeps_the_rest(tmp_path, trash):
    p = build_pdf(tmp_path)
    original = p.read_bytes()
    dump = pdf_dump(p)
    assert all(has_bytes(dump, n) for n in PDF_NEEDLES)  # 陽性対照（本文は 16 進文字列として入っている）
    assert all(n in pdf_text(p) for n in (PDF_MAIL, PDF_PHONE, PDF_JP_PHONE, PDF_PAGE2_MAIL))
    assert original.count(b"%%EOF") >= 2  # 増分保存の古い版がある
    svc, store, job = make_service(tmp_path, [p])
    a = analyze(svc, job, p)
    assert a.info["methods"]["redact"]["available"] and a.info["methods"]["delete_pages"]["available"]
    assert "delete_rows" not in a.info["methods"] and "dummy" not in a.info["methods"] and a.view()["sheets"] == []
    pv = svc.preview(job, str(p), {"method": "redact", "confidences": ALL_RANKS})
    assert "文字そのもの" in pv["summary"] and any("元に戻せません" in w for w in pv["warnings"] + pv["notes"])
    r = run(svc, job, p, method="redact", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    # 検査し直して消えている・文字の抽出にも生のバイト列にも値が無い
    assert r["remaining"]["total"] == 0
    text = pdf_text(p)
    for needle in (PDF_MAIL, PDF_PHONE, PDF_JP_PHONE, PDF_PAGE2_MAIL):
        assert needle not in text, needle
    blob = pdf_dump(p)
    for needle in PDF_NEEDLES:
        assert not has_bytes(blob, needle), needle  # メタデータ・しおり・注釈・埋め込みファイル・古い版にも残らない
    assert p.read_bytes().count(b"%%EOF") == 1  # 増分保存にしない
    # 関係ない文字は残る（隣の文字を巻き込まない）
    assert "Contact:" in text and "now" in text and "Phone" in text and "and more text" in text
    assert "This line has nothing personal." in text and "Third page is clean." in text
    assert "Second page" in text and "end" in text and "電話" in text and "です" in text
    import pymupdf as fitz

    with fitz.open(str(p)) as doc:
        assert doc.page_count == 3 and doc.metadata["author"] == "" and doc.metadata["creator"] == "tester"
        assert [t[1] for t in doc.get_toc()] == ["－", "Clean chapter"] and doc.embfile_names() == []
        assert not list(doc[0].annots() or [])
    assert r["changed"]["pages"] == 2 and r["changed"]["regions"] >= 4 and r["changed"]["cleaned"] >= 4
    assert [f.read_bytes() for f in trash.files()] == [original]  # 元はごみ箱へ
    assert not new_tmp_files(p.parent)


def test_pdf_redact_drops_page_thumbnail(tmp_path):
    """ページの縮小画像（/Thumb。変える前のページが写っている）も外す。"""
    import pymupdf as fitz
    from PIL import Image

    p = build_pdf(tmp_path, with_extras=False)
    buf = io.BytesIO()
    Image.new("RGB", (20, 20), (10, 20, 30)).save(buf, "PNG")
    with fitz.open(str(p)) as doc:
        xref = doc[0].insert_image(fitz.Rect(400, 400, 420, 420), stream=buf.getvalue())
        doc.xref_set_key(doc[0].xref, "Thumb", f"{xref} 0 R")
        doc.saveIncr()
    with fitz.open(str(p)) as doc:
        assert doc.xref_get_key(doc[0].xref, "Thumb")[0] == "xref"  # 陽性対照
    svc, store, job = make_service(tmp_path, [p])
    r = run(svc, job, p, method="redact", confidences=ALL_RANKS)
    assert r["state"] == "done" and r["changed"]["cleaned_thumbnails"] == 1, r
    with fitz.open(str(p)) as doc:
        assert all(doc.xref_get_key(pg.xref, "Thumb")[0] != "xref" for pg in doc)  # 参照が外れている（null か無し）


def test_pdf_redact_only_selected_types(tmp_path):
    p = build_pdf(tmp_path)
    svc, store, job = make_service(tmp_path, [p])
    r = run(svc, job, p, method="redact", types=["phone"], confidences=ALL_RANKS)
    assert r["state"] == "done", r
    text = pdf_text(p)
    assert PDF_PHONE not in text and PDF_JP_PHONE not in text and PDF_MAIL in text  # 選ばなかった種類は残る


def test_pdf_delete_pages(tmp_path):
    p = build_pdf(tmp_path)
    svc, store, job = make_service(tmp_path, [p])
    analyze(svc, job, p)
    pv = svc.preview(job, str(p), {"method": "delete_pages", "confidences": ALL_RANKS})
    assert "1、2" in pv["summary"]
    r = run(svc, job, p, method="delete_pages", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    import pymupdf as fitz

    with fitz.open(str(p)) as doc:
        assert doc.page_count == 1 and "Third page is clean." in doc[0].get_text("text")
    blob = pdf_dump(p)
    for needle in PDF_NEEDLES:
        assert not has_bytes(blob, needle), needle
    assert r["changed"]["pages_removed"] == 2


def test_pdf_delete_all_pages_is_refused(tmp_path):
    import pymupdf as fitz

    p = tmp_path / "src" / "all.pdf"
    p.parent.mkdir()
    doc = fitz.open()
    doc.new_page().insert_text((72, 100), f"only {PDF_MAIL}", fontsize=12)
    doc.save(str(p))
    doc.close()
    original = p.read_bytes()
    svc, store, job = make_service(tmp_path, [p])
    r = run(svc, job, p, method="delete_pages", confidences=ALL_RANKS)
    assert r["state"] == "error" and "すべてのページ" in r["message"]
    assert p.read_bytes() == original and not new_tmp_files(p.parent) and store.remediations(job) == []


def build_rotated_pdf(tmp_path: Path) -> Path:
    """4 方向に回したページ。本文に半角のメールと全角の電話（正規化すると別の長さの文字になる）がある。"""
    import pymupdf as fitz

    p = tmp_path / "src" / "rot.pdf"
    p.parent.mkdir(parents=True, exist_ok=True)
    doc = fitz.open()
    for rot in (0, 90, 180, 270):
        page = doc.new_page()
        page.insert_text((72, 100), "Keep before taro.yamada@example.com keep after", fontsize=12)
        page.insert_text((72, 130), "Full width ０９０－１２３４－５６７８ end", fontsize=12, fontname="japan")
        page.set_rotation(rot)
    doc.save(str(p))
    doc.close()
    return p


def test_pdf_redact_rotated_pages_and_full_width_values(tmp_path):
    p = build_rotated_pdf(tmp_path)
    svc, store, job = make_service(tmp_path, [p])
    r = run(svc, job, p, method="redact", confidences=ALL_RANKS)
    assert r["state"] == "done" and r["remaining"]["total"] == 0, r
    import pymupdf as fitz

    with fitz.open(str(p)) as doc:
        assert [pg.rotation for pg in doc] == [0, 90, 180, 270]
        for pg in doc:
            text = pg.get_text("text")
            assert "taro" not in text and "１２３４" not in text and "1234" not in text
            assert "Keep before" in text and "keep after" in text and "Full width" in text and "end" in text
    assert r["changed"]["pages"] == 4 and r["changed"]["regions"] == 8


def test_pdf_redact_falls_back_to_text_search_when_char_boxes_do_not_match(tmp_path, monkeypatch):
    """文字ごとの箱を、ページの文字列と1文字ずつ対応づけられないときは、ページの検索で場所を探して塗る。"""
    from pii_checker import remedy_pdf

    real = remedy_pdf.page_chars
    monkeypatch.setattr(remedy_pdf, "page_chars", lambda page: (real(page)[0], None))
    p = build_pdf(tmp_path, with_extras=False)
    svc, store, job = make_service(tmp_path, [p])
    r = run(svc, job, p, method="redact", confidences=ALL_RANKS)
    assert r["state"] == "done" and r["remaining"]["total"] == 0, r
    text = pdf_text(p)
    for needle in (PDF_MAIL, PDF_PHONE, PDF_JP_PHONE, PDF_PAGE2_MAIL):
        assert needle not in text
    assert "Contact:" in text and "This line has nothing personal." in text


def test_pdf_redact_that_cannot_remove_the_text_keeps_the_original(tmp_path, monkeypatch):
    """黒塗りで文字が消えなかったとき（確かめで見つかる）は、何も確定せず元のまま。"""
    import pymupdf as fitz

    monkeypatch.setattr(fitz.Page, "apply_redactions", lambda self, *a, **k: True)  # 何もしない
    p = build_pdf(tmp_path, with_extras=False)
    original = p.read_bytes()
    svc, store, job = make_service(tmp_path, [p])
    r = run(svc, job, p, method="redact", confidences=ALL_RANKS)
    assert r["state"] == "error" and "消えませんでした" in r["message"]
    assert p.read_bytes() == original and not new_tmp_files(p.parent) and store.remediations(job) == []


# ---------------------------------------------------------------- 暗号化された PDF


class FakeRegistry:
    """検査を動かしているメモリのパスワード（RemedyService が引く先）の代わり。"""

    def __init__(self, book: PasswordBook):
        self.book = book

    def get(self, job_id, create=False):
        return types.SimpleNamespace(passwords=self.book)


def test_real_worker_process_gets_the_password_for_an_encrypted_pdf(tmp_path):
    """本番と同じ別プロセスへ、検査で入れたパスワードが渡り、暗号化された PDF を黒塗りして同じパスワードで保存できる。"""
    import pymupdf as fitz

    p = build_pdf(tmp_path, with_extras=False)
    encrypt_pdf(p, "pw-ひみつ")
    svc, store, job = make_service(tmp_path, [p], runner=remediate._run_in_process)
    svc.registry = FakeRegistry(PasswordBook(common=["pw-ひみつ"]))
    r = run(svc, job, p, method="redact", confidences=ALL_RANKS)
    assert r["state"] == "done" and r["remaining"]["total"] == 0, r
    with fitz.open(str(p)) as doc:
        assert doc.needs_pass and doc.authenticate("pw-ひみつ")
        assert PDF_MAIL not in doc[0].get_text("text") and "Contact:" in doc[0].get_text("text")


def test_owner_password_only_pdf_is_saved_without_the_restriction_and_says_so(tmp_path):
    import pymupdf as fitz

    p = build_pdf(tmp_path, with_extras=False)
    out = p.with_name("owner-" + p.name)
    with fitz.open(str(p)) as doc:
        doc.save(str(out), encryption=fitz.PDF_ENCRYPT_AES_256, owner_pw="owner-pw", user_pw="")
    p.unlink()
    out.rename(p)
    svc, store, job = make_service(tmp_path, [p])
    r = run(svc, job, p, method="redact", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    assert any("所有者のパスワード" in n for n in r["notes"])
    with fitz.open(str(p)) as doc:
        assert not doc.needs_pass and PDF_MAIL not in doc[0].get_text("text")


def test_encrypted_pdf_is_redacted_and_encrypted_again_with_the_same_password(tmp_path):
    import pymupdf as fitz

    p = build_pdf(tmp_path)
    encrypt_pdf(p, "secret")
    svc, store, job = make_service(tmp_path, [p])
    # パスワードが手元に無いときは断る（元のファイルは変えない）
    a = analyze(svc, job, p)
    assert not a.info["methods"]["redact"]["available"] and "パスワード" in a.info["methods"]["redact"]["reason"]
    original = p.read_bytes()
    with pytest.raises(RemedyError, match="パスワード"):
        svc.preview(job, str(p), {"method": "redact", "confidences": ALL_RANKS})
    assert p.read_bytes() == original and not new_tmp_files(p.parent)
    # 検査で入れたパスワードがあれば、同じパスワードで暗号化し直して保存する
    svc.registry = FakeRegistry(PasswordBook(common=["secret"]))
    r = run(svc, job, p, method="redact", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    with fitz.open(str(p)) as doc:
        assert doc.needs_pass and not doc.authenticate("wrong") and doc.authenticate("secret")
        text = "\n".join(pg.get_text("text") for pg in doc)
    for needle in (PDF_MAIL, PDF_PHONE, PDF_PAGE2_MAIL):
        assert needle not in text
    assert "Contact:" in text and "Third page is clean." in text
    assert b"Encrypt" in p.read_bytes() and r["remaining"]["total"] == 0
    assert not has_bytes(pdf_dump(p, "secret"), PDF_META_MAIL)


# ---------------------------------------------------------------- 画像の中の文字（OCR）


def text_image():
    """文字を描いた画像（1行目にメールアドレス）。"""
    from PIL import Image, ImageDraw, ImageFont

    font = ImageFont.truetype("arial.ttf", 56)
    img = Image.new("RGB", (1000, 300), "white")
    draw = ImageDraw.Draw(img)
    draw.text((20, 20), "Mail ocr.test@example.com", fill="black", font=font)
    draw.text((20, 150), "Hello World keep this", fill="black", font=font)
    return img


@pytest.mark.skipif(not ocr_available(), reason="OCR が使えない環境")
def test_ocr_lines_have_the_same_text_as_ocr_pil_image_and_one_box_per_character():
    from pii_checker import ocr

    img = text_image()
    lines = ocr.ocr_pil_image_lines(img)
    assert "\n".join(x["text"] for x in lines) == ocr.ocr_pil_image(img)
    for x in lines:
        assert len(x["chars"]) == len(x["text"]) and x["top"] < x["bottom"]
        assert all(a <= b for a, b in x["chars"]) and all(0 <= a and b <= img.width for a, b in x["chars"])
        assert [a for a, _b in x["chars"]] == sorted(a for a, _b in x["chars"])  # 左から右へ並ぶ


def build_scanned_pdf(tmp_path: Path) -> Path:
    """文字の層が無く、画像（文字を描いたもの）が貼ってあるだけの PDF。"""
    import pymupdf as fitz

    img = text_image()
    buf = io.BytesIO()
    img.save(buf, "PNG")
    p = tmp_path / "src" / "scan.pdf"
    p.parent.mkdir(parents=True, exist_ok=True)
    doc = fitz.open()
    page = doc.new_page()
    page.insert_image(fitz.Rect(50, 100, 550, 250), stream=buf.getvalue())
    doc.save(str(p))
    doc.close()
    return p


def render_ocr_text(path: Path) -> str:
    import pymupdf as fitz
    from PIL import Image

    from pii_checker import ocr

    with fitz.open(str(path)) as doc:
        pix = doc[0].get_pixmap(dpi=200)
    return ocr.ocr_pil_image(Image.frombytes("RGB", (pix.width, pix.height), pix.samples))


@pytest.mark.skipif(not ocr_available(), reason="OCR が使えない環境")
def test_pdf_redact_blanks_the_image_pixels_for_text_found_by_ocr(tmp_path):
    import pymupdf as fitz

    p = build_scanned_pdf(tmp_path)
    before = render_ocr_text(p)
    assert "example.com" in before and "keep this" in before  # 陽性対照
    got = remediate.collect_task({"path": str(p), "options": ScanOptions(temp_dir=str(tmp_path))})
    assert got["layout"] == "pdf" and {k[0] for k in got["positions"]} == {"1ページ（OCR）"}
    svc, store, job = make_service(tmp_path, [p])
    pv = analyze(svc, job, p) and svc.preview(job, str(p), {"method": "redact", "confidences": ALL_RANKS})
    assert any("OCR" in w for w in pv["warnings"] + pv["notes"])
    r = run(svc, job, p, method="redact", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    seen = render_ocr_text(p)
    assert "example.com" not in seen and "ocr.test" not in seen and "keep this" in seen
    with fitz.open(str(p)) as doc:
        assert doc.page_count == 1 and doc[0].get_images()  # 画像は残り、その一部の画素が塗りつぶされている
        pix = doc[0].get_pixmap(dpi=72)
    samples = pix.samples
    dark = sum(1 for i in range(0, len(samples) - 2, pix.n) if samples[i] < 30 and samples[i + 1] < 30)
    assert dark > 300  # 黒く塗った面がある
    assert r["changed"]["regions"] >= 1 and r["remaining"]["total"] == 0

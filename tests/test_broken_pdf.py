"""壊れた PDF（途中で切れた・中身の圧縮が壊れた・暗号化の情報が消えた）を「検査済み」と黙らない試験。

PyMuPDF は壊れた PDF を黙って修復して開くため、読めた分だけで「検査済み・0件」になっていた（N5 の下調べ）。
"""

from __future__ import annotations

import pytest

from pii_checker import engine
from pii_checker.models import ScanOptions, Status

fitz = pytest.importorskip("pymupdf")

TEXT = "連絡先 yamada.taro@example.com 電話 090-1234-5678"


def _scan(tmp_path, name: str, data: bytes):
    p = tmp_path / name
    p.write_bytes(data)
    res = engine.scan_file(str(p), ScanOptions(temp_dir=str(tmp_path), reuse=False))
    return res.items[0]


def _pdf(**save) -> bytes:
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((60, 80), TEXT, fontname="japan", fontsize=11)
    data = doc.tobytes(**save)
    doc.close()
    return data


def test_intact_pdf_is_scanned(tmp_path):
    it = _scan(tmp_path, "ok.pdf", _pdf())
    assert it.status == Status.SCANNED
    assert it.finding_counts


def test_pdf_without_xref_is_partial(tmp_path):
    data = _pdf()
    cut = data[: data.rfind(b"\nxref")]  # 末尾の相互参照表と trailer を失った（書き込みの途中で切れた形）
    it = _scan(tmp_path, "cut.pdf", cut)
    assert it.status == Status.PARTIAL
    assert "修復" in it.reason
    assert it.finding_counts  # 読めた部分は検査している


@pytest.mark.parametrize("where", ["half", "before_xref"])
def test_truncated_encrypted_pdf_is_uncheckable(tmp_path, where):
    data = _pdf(encryption=fitz.PDF_ENCRYPT_AES_256, owner_pw="owner-pw-1", user_pw="user-pw-1")
    # half: 暗号化の辞書ごと消える。before_xref: 辞書は残るが trailer が消えて参照されない
    cut = data[: len(data) // 2] if where == "half" else data[: data.rfind(b"\nxref")]
    with fitz.open(stream=cut, filetype="pdf") as d:
        assert d.is_repaired and not d.is_encrypted  # 前提: 修復で暗号化の情報が失われる
    it = _scan(tmp_path, "enc_cut.pdf", cut)
    assert it.status == Status.UNCHECKABLE
    assert "暗号化" in it.reason
    assert not it.finding_counts


def test_corrupt_content_stream_is_partial(tmp_path):
    data = bytearray(_pdf(deflate=True))
    s = data.find(b"stream", data.find(b"/Filter")) + len(b"stream\n")
    for i in range(s + 4, s + 40):  # 圧縮した内容のストリームの途中を壊す
        data[i] ^= 0x5A
    it = _scan(tmp_path, "zlib.pdf", bytes(data))
    assert it.status == Status.PARTIAL
    assert "読めなかった部分" in it.reason
    assert any("zlib" in n for n in it.notes)  # MuPDF の生の警告は理由ではなく補足に出す


def test_plain_encrypt_word_does_not_make_uncheckable(tmp_path):
    # 本文・文書情報に「/Encrypt」という字が書いてあるだけの、暗号化していない PDF を途中で切った
    doc = fitz.open()
    doc.new_page().insert_text((60, 80), TEXT, fontname="japan", fontsize=11)
    doc.set_metadata({"title": "about /Encrypt dictionary"})
    data = doc.tobytes()
    doc.close()
    cut = data[: data.rfind(b"\nxref")]
    it = _scan(tmp_path, "cut_with_word.pdf", cut)
    assert it.status == Status.PARTIAL
    assert it.finding_counts


def test_encrypt_mark_across_chunk_boundary(tmp_path):
    from pii_checker.formats import pdf as pdf_mod

    p = tmp_path / "mark.bin"
    mark = b"/Encrypt 12 0 R"
    p.write_bytes(b"x" * ((1 << 20) - 5) + mark + b"y" * 10)  # 1MB の塊の境目をまたぐ
    assert pdf_mod._has_encrypt_mark(engine.Blob(display=str(p), path=str(p)))
    assert pdf_mod._has_encrypt_mark(engine.Blob(display="m", data=b"1 0 obj<</Filter /Standard /V 5>>"))
    assert not pdf_mod._has_encrypt_mark(engine.Blob(display="m", data=b"(about /Encrypt dictionary)"))


def test_broken_pdf_attached_to_intact_pdf(tmp_path):
    inner = _pdf()
    inner = inner[: inner.rfind(b"\nxref")]
    doc = fitz.open()
    doc.new_page().insert_text((60, 80), "attachment test")
    doc.embfile_add("broken.pdf", inner)
    outer = doc.tobytes()
    doc.close()
    p = tmp_path / "outer.pdf"
    p.write_bytes(outer)
    res = engine.scan_file(str(p), ScanOptions(temp_dir=str(tmp_path), reuse=False))
    by_path = {it.path.rsplit("!", 1)[-1] if "!" in it.path else ".": it for it in res.items}
    assert by_path["."].status == Status.SCANNED  # 外側は壊れていない（添付の警告が漏れない）
    assert by_path["broken.pdf"].status == Status.PARTIAL

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
    assert "壊れていて読めなかった" in it.reason

"""メモリへ丸ごと読まない上限の試験（上限を小さくして、大きなファイルの扱いを確かめる）。"""

import io
import zipfile

from pii_checker import engine
from pii_checker.formats import office
from pii_checker.models import ScanOptions, Status

PHONE = "090-1234-5678"


def _scan(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return engine.scan_file(str(p), ScanOptions(temp_dir=str(tmp_path)))


def _types(res):
    return {k for it in res.items for k in it.finding_counts}


def test_too_large_falls_back_to_string_sweep(tmp_path, monkeypatch):
    html = ("<html><body>" + "<p>あいうえお</p>" * 50 + f"<p>電話 {PHONE}</p></body></html>").encode("utf-8")
    monkeypatch.setattr(engine, "READ_ALL_LIMIT", 100)
    res = _scan(tmp_path, "big.html", html)
    top = res.items[0]
    assert top.status == Status.PARTIAL
    assert "大きすぎる" in top.reason
    assert "phone" in _types(res)  # 文字列の走査でも見つける


def test_under_limit_reads_structurally(tmp_path):
    """陽性対照: 上限の内なら形式どおりに読む（検査済み）。"""
    html = f"<html><body><p>電話 {PHONE}</p></body></html>".encode("utf-8")
    res = _scan(tmp_path, "small.html", html)
    assert res.items[0].status == Status.SCANNED
    assert "phone" in _types(res)


def test_too_large_image_is_uncheckable(tmp_path, monkeypatch):
    """大きすぎる画像は OCR していないので「簡易検査」ではなく「検査不能」（不具合の修正）。"""
    import struct
    import zlib

    def png(w, h):
        raw = b"".join(b"\x00" + b"\xff" * (w * 3) for _ in range(h))
        chunk = lambda t, d: struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))  # noqa: E731
        ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)
        return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")

    monkeypatch.setattr(engine, "READ_ALL_LIMIT", 100)
    res = _scan(tmp_path, "big.png", png(200, 200))
    top = res.items[0]
    assert top.status == Status.UNCHECKABLE and "OCR" in top.reason


def _docx_with_big_part(text: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types/>')
        z.writestr(
            "word/document.xml",
            '<?xml version="1.0"?><w:document xmlns:w="w"><w:body>'
            + "<w:p><w:r><w:t>本文です</w:t></w:r></w:p>" * 200
            + f"<w:p><w:r><w:t>電話 {text}</w:t></w:r></w:p></w:body></w:document>",
        )
    return buf.getvalue()


def test_big_office_part_is_swept(tmp_path, monkeypatch):
    """本文として読んでいない大きな部品は、文字を拾ったうえで「途中まで」にする。"""
    monkeypatch.setattr(office, "READ_ALL_LIMIT", 1000)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types/>')
        z.writestr("word/document.xml", '<?xml version="1.0"?><w:document xmlns:w="w"><w:body/></w:document>')
        z.writestr("customXml/item1.xml", "<a>" + "<b>本文です</b>" * 200 + f"<b>電話 {PHONE}</b></a>")
    res = _scan(tmp_path, "big.docx", buf.getvalue())
    assert "phone" in _types(res)
    assert any(it.status == Status.PARTIAL and "大きすぎる" in it.reason for it in res.items)


def test_big_main_part_read_as_body_is_not_partial(tmp_path, monkeypatch):
    """本文として読み終えた本文の部品は、大きくても「途中まで」にせず、残留の確かめの注記だけ残す。"""
    monkeypatch.setattr(office, "READ_ALL_LIMIT", 1000)
    res = _scan(tmp_path, "big.docx", _docx_with_big_part(PHONE))
    assert "phone" in _types(res)
    assert not any(it.status == Status.PARTIAL for it in res.items)
    assert any("残留の確かめ" in n for it in res.items for n in it.notes)

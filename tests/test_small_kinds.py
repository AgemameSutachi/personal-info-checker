"""実物の F の検査で検査不能になっていた小さな型（CHM・アイコン・PyInstaller の部品・証明書・書きかけの parquet）の試験。"""

from __future__ import annotations

import io
import os

from pii_checker import engine, sniff
from pii_checker.engine import Blob
from pii_checker.formats.archive import _drop_parent_dirs
from pii_checker.models import ScanOptions, Status


def _scan(tmp_path, p):
    return engine.scan_file(str(p), ScanOptions(temp_dir=str(tmp_path)))


def _types(res):
    return {k for it in res.items for k in it.finding_counts}


def _kind(p) -> str:
    return sniff.sniff(Blob(display=str(p), path=str(p), name_hint=os.path.basename(str(p))))


def test_chm_is_sniffed(tmp_path):
    p = tmp_path / "help.chm"
    p.write_bytes(b"ITSF\x03\x00\x00\x00" + os.urandom(4096))
    assert _kind(p) == "chm"
    q = tmp_path / "other.bin"
    q.write_bytes(b"ITSF\x09\x00\x00\x00" + os.urandom(4096))  # 版の値が違うものは CHM としない
    assert _kind(q) != "chm"


def test_drop_parent_dirs_keeps_files_only():
    entries = [
        {"Path": "html", "Size": "0"},
        {"Path": "html\\about", "Size": "0"},
        {"Path": "html\\about\\index.htm", "Size": "120"},
        {"Path": "$WWKeywordLinks", "Size": "0"},
        {"Path": "$WWKeywordLinks/Property", "Size": "4"},
        {"Path": "empty.txt", "Size": "0"},  # 子の無い大きさ 0 の項目は本物の空のファイルなので残す
    ]
    kept = [e["Path"] for e in _drop_parent_dirs(entries)]
    assert kept == ["html\\about\\index.htm", "$WWKeywordLinks/Property", "empty.txt"]


def test_icon_is_read_as_image(tmp_path):
    from PIL import Image

    buf = io.BytesIO()
    Image.new("RGB", (32, 32), "white").save(buf, format="ICO", sizes=[(32, 32)])
    p = tmp_path / "app.ico"
    p.write_bytes(buf.getvalue())
    assert _kind(p) == "image"
    res = _scan(tmp_path, p)
    top = res.items[0]
    assert top.status == Status.SCANNED, (top.status, top.reason)
    assert "小さな画像" in top.method


def test_icon_like_bytes_with_bad_offset_are_not_image(tmp_path):
    p = tmp_path / "x.dat"
    # 頭は ICO の形だが、画像の位置が目次の中を指す
    p.write_bytes(
        b"\x00\x00\x01\x00\x01\x00"
        + b"\x20\x20\x00\x00\x01\x00\x20\x00"
        + b"\x10\x00\x00\x00"
        + b"\x02\x00\x00\x00"
        + os.urandom(64)
    )
    assert _kind(p) != "image"


def test_pyinstaller_pyz_is_out_of_scope(tmp_path):
    p = tmp_path / "PYZ-00.pyz"
    p.write_bytes(b"PYZ\x00" + b"\xa7\x0d\x0d\x0a" + os.urandom(8192))
    res = _scan(tmp_path, p)
    top = res.items[0]
    assert top.status == Status.OUT_OF_SCOPE, (top.status, top.reason)
    assert "PyInstaller" in top.reason


def _carchive(body: bytes, length: int | None = None) -> bytes:
    size = len(body) + 88
    cookie = b"MEI\x0c\x0b\x0a\x0b\x0e" + (length if length is not None else size).to_bytes(4, "big")
    cookie += (len(body) - 100).to_bytes(4, "big") + (100).to_bytes(4, "big") + (311).to_bytes(4, "big")
    cookie += b"python311.dll".ljust(64, b"\x00")
    return body + cookie


def test_pyinstaller_carchive_is_out_of_scope(tmp_path):
    p = tmp_path / "app.pkg"
    p.write_bytes(_carchive(b"x\xda" + os.urandom(16384)))
    res = _scan(tmp_path, p)
    top = res.items[0]
    assert top.status == Status.OUT_OF_SCOPE, (top.status, top.reason)


def test_carchive_cookie_with_wrong_length_is_not_trusted(tmp_path):
    p = tmp_path / "app.pkg"
    p.write_bytes(_carchive(b"x\xda" + os.urandom(16384), length=12345))
    assert _kind(p) != "pyinstaller"


def _der(body: bytes) -> bytes:
    return b"\x30\x82" + len(body).to_bytes(2, "big") + body


def test_der_certificate_text_is_scanned(tmp_path):
    # 鍵と署名に当たる乱数の間に、名前とメールが文字のまま入っている（エントロピーが高くても読む）
    body = os.urandom(3000) + b"\x0c\x17taro.yamada@example.com" + os.urandom(3000)
    p = tmp_path / "sign.p7s"
    p.write_bytes(_der(body))
    assert _kind(p) == "der"
    res = _scan(tmp_path, p)
    top = res.items[0]
    assert top.status == Status.SCANNED, (top.status, top.reason)
    assert "email" in _types(res)


def test_der_long_form_is_scanned(tmp_path):
    body = os.urandom(70000) + b"\x0c\x17taro.yamada@example.com"
    p = tmp_path / "big.cer"
    p.write_bytes(b"\x30\x83" + len(body).to_bytes(3, "big") + body)
    assert _kind(p) == "der"
    assert "email" in _types(_scan(tmp_path, p))


def test_pfx_is_uncheckable_not_scanned(tmp_path):
    # PKCS#12 は SEQUENCE の直後に版 3（02 01 03）が来る。中身は暗号化されているので「検査した」にしない
    body = b"\x02\x01\x03" + os.urandom(3000)
    p = tmp_path / "key.pfx"
    p.write_bytes(_der(body))
    top = _scan(tmp_path, p).items[0]
    assert top.status == Status.UNCHECKABLE, (top.status, top.reason)
    assert ".pfx" in top.reason


def test_enveloped_data_is_uncheckable(tmp_path):
    body = bytes.fromhex("06092a864886f70d010703") + os.urandom(3000)
    p = tmp_path / "mail.p7m"
    p.write_bytes(_der(body))
    top = _scan(tmp_path, p).items[0]
    assert top.status == Status.UNCHECKABLE, (top.status, top.reason)


def test_drop_parent_dirs_keeps_sized_entry_with_same_name_as_parent():
    entries = [{"Path": "A", "Size": "120"}, {"Path": "A\\x", "Size": "5"}]
    assert [e["Path"] for e in _drop_parent_dirs(entries)] == ["A", "A\\x"]


def test_cursor_is_read_as_image(tmp_path):
    from PIL import Image

    buf = io.BytesIO()
    Image.new("RGB", (32, 32), "white").save(buf, format="ICO", sizes=[(32, 32)])
    data = bytearray(buf.getvalue())
    data[2] = 2  # 種類の値を 2（カーソル）に
    p = tmp_path / "arrow.cur"
    p.write_bytes(bytes(data))
    assert _kind(p) == "image"


def test_der_length_must_fill_the_file(tmp_path):
    body = os.urandom(6000)
    p = tmp_path / "x.bin"
    p.write_bytes(_der(body) + b"\x00")  # 後ろに1バイト余る
    assert _kind(p) != "der"
    res = _scan(tmp_path, p)
    assert res.items[0].status == Status.UNCHECKABLE  # 今までどおり形式不明の高いエントロピー


def test_truncated_parquet_says_so(tmp_path):
    p = tmp_path / "part-0000.parquet.part"
    p.write_bytes(b"PAR1\x15\x04" + os.urandom(16384))  # 尾の PAR1 と定義が無い
    res = _scan(tmp_path, p)
    top = res.items[0]
    assert top.status == Status.UNCHECKABLE
    assert "書きかけ" in top.reason

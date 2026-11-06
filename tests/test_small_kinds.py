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


def _stl(header: bytes, triangles: int) -> bytes:
    import struct

    body = b"".join(struct.pack("<12fH", *([0.5 + i] * 12), 0) for i in range(triangles))
    return header.ljust(80, b"\x00") + triangles.to_bytes(4, "little") + body


def test_binary_stl_header_is_scanned(tmp_path):
    p = tmp_path / "city.stl"
    p.write_bytes(_stl(b"exported by taro.yamada@example.com", 300))
    assert _kind(p) == "stl"
    res = _scan(tmp_path, p)
    top = res.items[0]
    assert top.status == Status.SCANNED, (top.status, top.reason)
    assert "email" in _types(res)
    assert "300" in top.method


def test_stl_size_must_match_triangle_count(tmp_path):
    p = tmp_path / "x.stl"
    p.write_bytes(_stl(b"", 300) + b"\x00")  # 三角形の数と大きさが合わないものは STL としない
    assert _kind(p) != "stl"


def _region(chunks: dict[int, tuple[int, bytes]]) -> bytes:
    """塊の番号 → (圧縮の種類, 圧縮済みの中身) から region を組み立てる。"""
    table = bytearray(8192)
    body = b""
    sector = 2
    for index, (kind, payload) in chunks.items():
        data = (len(payload) + 1).to_bytes(4, "big") + bytes([kind]) + payload
        count = -(-len(data) // 4096)
        table[index * 4 : index * 4 + 4] = sector.to_bytes(3, "big") + bytes([count])
        body += data.ljust(count * 4096, b"\x00")
        sector += count
    return bytes(table) + body


def _nbt_name(s: str) -> bytes:
    raw = s.encode("utf-8")
    return len(raw).to_bytes(2, "big") + raw


def _nbt_chunk(text: str) -> bytes:
    """根の複合の中に、看板の文字（TAG_String）・数の配列（TAG_Long_Array）・文字の一覧（TAG_List）を持つ NBT。"""
    longs = b"3333333333333333" * 64  # ブロックの並びの数（文字として読むと番号の形に見える）
    return (
        b"\x0a"
        + _nbt_name("")
        + b"\x08"
        + _nbt_name("Text")
        + _nbt_name(text)
        + b"\x0c"
        + _nbt_name("data")
        + (len(longs) // 8).to_bytes(4, "big")
        + longs
        + b"\x09"
        + _nbt_name("palette")
        + b"\x0a"
        + (2).to_bytes(4, "big")
        + b"\x08"
        + _nbt_name("Name")
        + _nbt_name("minecraft:stone")
        + b"\x00"
        + b"\x03"
        + _nbt_name("n")
        + (7).to_bytes(4, "big")
        + b"\x00"
        + b"\x00"
    )


def test_region_chunks_are_read(tmp_path):
    import gzip
    import zlib

    p = tmp_path / "r.0.0.mca"
    chunks = {0: (2, zlib.compress(_nbt_chunk("taro.yamada@example.com"))), 33: (1, gzip.compress(_nbt_chunk("看板")))}
    p.write_bytes(_region(chunks))
    assert _kind(p) == "mca"
    res = _scan(tmp_path, p)
    top = res.items[0]
    assert top.status == Status.SCANNED, (top.status, top.reason)
    assert "2/2" in top.method
    # 看板の文字は拾い、数の配列（3333…）からは番号を拾わない
    assert _types(res) == {"email"}


def test_nbt_strings_reads_only_text_values():
    from pii_checker.formats.misc import nbt_strings

    assert list(nbt_strings(_nbt_chunk("hello"))) == ["hello", "minecraft:stone"]


def test_broken_nbt_chunk_is_partial(tmp_path):
    import zlib

    p = tmp_path / "r.2.0.mca"
    p.write_bytes(_region({0: (2, zlib.compress(_nbt_chunk("ok"))), 1: (2, zlib.compress(_nbt_chunk("x")[:-9]))}))
    top = _scan(tmp_path, p).items[0]
    assert top.status == Status.PARTIAL, (top.status, top.reason)
    assert "壊れた塊 1 個" in top.reason


def test_region_with_unreadable_chunk_is_partial(tmp_path):
    import zlib

    p = tmp_path / "r.1.0.mca"
    p.write_bytes(_region({0: (2, zlib.compress(_nbt_chunk("hello world text"))), 1: (4, os.urandom(300))}))
    top = _scan(tmp_path, p).items[0]
    assert top.status == Status.PARTIAL, (top.status, top.reason)
    assert "LZ4" in top.reason


def test_random_bytes_are_not_region(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(os.urandom(16384))
    assert _kind(p) != "mca"
    q = tmp_path / "y.bin"
    q.write_bytes(b"\x00\x00\x02\x01" + b"\x00" * 8188 + os.urandom(4096))  # 表は正しいが塊の頭が壊れている
    assert _kind(q) != "mca"


def test_region_with_no_readable_chunk_is_uncheckable(tmp_path):
    p = tmp_path / "r.3.0.mca"
    p.write_bytes(_region({0: (4, os.urandom(300)), 1: (4, os.urandom(300))}))
    top = _scan(tmp_path, p).items[0]
    assert top.status == Status.UNCHECKABLE, (top.status, top.reason)
    assert "1つも読めなかった" in top.reason


def test_broken_nbt_chunk_still_checks_text_before_break(tmp_path):
    import zlib

    nbt = _nbt_chunk("taro.yamada@example.com")[:-9]  # 看板の文字の後ろで切れた塊
    p = tmp_path / "r.4.0.mca"
    p.write_bytes(_region({0: (2, zlib.compress(_nbt_chunk("ok"))), 1: (2, zlib.compress(nbt))}))
    res = _scan(tmp_path, p)
    assert res.items[0].status == Status.PARTIAL
    assert "email" in _types(res)


def test_nbt_number_list_is_skipped_at_once():
    import time

    from pii_checker.formats.misc import nbt_strings

    count = 5_000_000  # 細工した大きな byte の一覧（1要素ずつ歩くと数秒かかる）
    data = b"\x0a\x00\x00\x09\x00\x01L\x01" + count.to_bytes(4, "big") + b"\x00" * count + b"\x00"
    start = time.perf_counter()
    assert list(nbt_strings(data)) == []
    assert time.perf_counter() - start < 1.0

"""単体の圧縮ファイル（gzip・lzip）の展開の試験: 複数メンバー・末尾の余分・途中で切れたもの・壊れたもの。

lzip はこれまで Docker で作る検体でしか確かめていなかった。Python の lzma で生の LZMA1 を作って組み立てる。
"""

from __future__ import annotations

import gzip
import io
import lzma
import struct
import tarfile
import zlib

from pii_checker.engine import scan_file
from pii_checker.formats.archive import _GzipStream, _LzipReader
from pii_checker.models import ScanOptions, Status

TEXT = "".join(f"{i:05d} 山田 090-1234-{i % 10000:04d}\n" for i in range(3000)).encode()


def _lzip_member(data: bytes) -> bytes:
    """lzip のメンバー1つ（見出し「LZIP」・版1・辞書の大きさ 1MB＋生の LZMA1＋末尾 20 バイト）。"""
    filters = [{"id": lzma.FILTER_LZMA1, "dict_size": 1 << 20, "lc": 3, "lp": 0, "pb": 2}]
    body = lzma.compress(data, format=lzma.FORMAT_RAW, filters=filters)
    return b"LZIP\x01" + bytes([20]) + body + struct.pack("<IQQ", zlib.crc32(data), len(data), 26 + len(body))


def _scan(tmp_path, name: str, data: bytes):
    p = tmp_path / name
    p.write_bytes(data)
    return scan_file(str(p), ScanOptions(temp_dir=str(tmp_path), reuse=False)).items


def _phones(items) -> int:
    return sum(it.finding_counts.get("phone", 0) for it in items)


# ------------------------------------------------------------------ lzip


def test_lzip_reader_single_and_multiple_members():
    one = _lzip_member(b"first\n")
    assert _LzipReader(io.BytesIO(one)).read() == b"first\n"
    reader = _LzipReader(io.BytesIO(one + _lzip_member(b"second\n")))
    assert reader.read(3) == b"fir"  # 少しずつ読んでも続きが読める
    assert reader.read() == b"st\nsecond\n"
    assert not reader.truncated


def test_lzip_reader_ignores_trailing_bytes_that_are_not_a_member():
    reader = _LzipReader(io.BytesIO(_lzip_member(b"body\n") + b"\x00" * 16))
    assert reader.read() == b"body\n"
    assert not reader.truncated


def test_lzip_scanned_with_inner_name(tmp_path):
    items = _scan(tmp_path, "list.csv.lz", _lzip_member(TEXT))
    assert items[0].status == Status.SCANNED, items[0].reason
    assert items[0].method == f"展開（{len(TEXT):,}バイト）"
    assert items[1].path.endswith("list.csv.lz!list.csv")
    assert _phones(items) == 3000


def test_truncated_lzip_is_partial_not_silently_scanned(tmp_path):
    """途中で切れた lzip を、読めた分だけで「検査済み」と黙らない（gzip・xz と同じ扱い）。"""
    items = _scan(tmp_path, "cut.csv.lz", _lzip_member(TEXT)[:2000])
    assert items[0].status == Status.PARTIAL, (items[0].status, items[0].reason)
    assert items[0].reason.startswith("圧縮データが途中で切れていた。展開できた ")
    assert 0 < _phones(items) < 3000  # 読めた分は検査している


def test_lzip_cut_inside_second_member():
    first, second = _lzip_member(b"first\n"), _lzip_member(TEXT)
    reader = _LzipReader(io.BytesIO(first + second[:2000]))
    out = reader.read()
    assert out.startswith(b"first\n") and len(out) < 6 + len(TEXT)  # 1つ目は全部・2つ目は読めた分だけ
    assert reader.truncated


def test_lzip_missing_trailer_is_partial(tmp_path):
    """本体は終わりの印まで読めても、末尾（検査値と大きさ）が欠けていれば切れたファイルとして扱う。"""
    items = _scan(tmp_path, "notail.csv.lz", _lzip_member(TEXT)[:-10])
    assert items[0].status == Status.PARTIAL, (items[0].status, items[0].reason)
    assert _phones(items) == 3000


def test_corrupt_lzip_is_reported(tmp_path):
    data = bytearray(_lzip_member(TEXT))
    for i in range(200, 260):
        data[i] ^= 0xFF
    items = _scan(tmp_path, "bad.csv.lz", bytes(data))
    assert items[0].status in (Status.PARTIAL, Status.UNCHECKABLE), (items[0].status, items[0].reason)
    assert "圧縮データが" in items[0].reason


# ------------------------------------------------------------------ gzip


def test_gzip_concatenated_members_are_all_read(tmp_path):
    half = len(TEXT) // 2
    data = gzip.compress(TEXT[:half]) + gzip.compress(TEXT[half:])
    items = _scan(tmp_path, "joined.csv.gz", data)
    assert items[0].status == Status.SCANNED, items[0].reason
    assert items[0].method == f"展開（{len(TEXT):,}バイト）"
    assert _phones(items) == 3000


def test_gzip_member_header_split_across_read_boundary():
    """次のメンバーの見出しが読み込みの境目で切れていても、続けて読む。"""

    class OneByteAtBoundary(io.BytesIO):
        def __init__(self, data, first):
            super().__init__(data)
            self._first = first

        def read(self, n=-1):
            if self._first:
                n, self._first = self._first, 0
            return super().read(n)

    a, b = gzip.compress(b"first\n"), gzip.compress(b"second\n")
    stream = _GzipStream(OneByteAtBoundary(a + b, len(a) + 1))  # 2つ目の見出しの1バイト目で切る
    assert stream.read() == b"first\nsecond\n"
    assert not stream.truncated


def test_gzip_trailing_garbage_is_ignored(tmp_path):
    items = _scan(tmp_path, "tail.csv.gz", gzip.compress(TEXT) + b"\x00" * 100)
    assert items[0].status == Status.SCANNED, items[0].reason
    assert _phones(items) == 3000


def test_corrupt_gzip_reports_the_damage(tmp_path):
    data = bytearray(gzip.compress(TEXT))
    for i in range(400, 440):
        data[i] ^= 0x5A
    items = _scan(tmp_path, "bad.csv.gz", bytes(data))
    assert items[0].status in (Status.PARTIAL, Status.UNCHECKABLE), (items[0].status, items[0].reason)
    assert "圧縮データが壊れている" in items[0].reason


def test_tgz_inner_name_becomes_tar(tmp_path):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        info = tarfile.TarInfo("list.csv")
        info.size = len(TEXT)
        t.addfile(info, io.BytesIO(TEXT))
    items = _scan(tmp_path, "pack.tgz", gzip.compress(buf.getvalue()))
    assert any(it.path.endswith("pack.tgz!pack.tar") for it in items), [it.path for it in items]
    assert _phones(items) == 3000

"""形式不明のバイナリに埋まった、BOM の無い UTF-16BE の日本語を生データ走査で拾う試験。

今までの生データ走査は UTF-16LE しか読まず、ビッグエンディアンの日本語（かな漢字）は何も拾えなかった。
乱れた漢字の並びを拾わないこと（陰性対照）も確かめる。名前・住所・番号は試験のために作ったもの。
"""

import random

import pytest

from pii_checker import textdecode
from pii_checker.engine import scan_file
from pii_checker.models import ScanOptions, Status

BODY = "氏名：山田太郎\n住所：東京都千代田区丸の内9-9-9\n電話：03-1234-5678\n"


def _binary_with(payload: bytes, pad: bytes = b"") -> bytes:
    """独自形式のバイナリの見本（頭・数の表・末尾の間に payload を挟む）。"""
    head = b"\x89XDT\x00\x01\x02\x03" + bytes(range(32)) * 8
    table = b"".join(i.to_bytes(4, "little") for i in range(512))
    return head + pad + payload + b"\x00\x00\xfe\xff" + table


@pytest.mark.parametrize("pad", [b"", b"\x01", b"\x00\x07\xff"], ids=["ずれ0", "ずれ1", "ずれ3"])
def test_iter_strings_finds_big_endian_japanese(pad):
    data = _binary_with(BODY.encode("utf-16-be"), pad)
    le_only = set(textdecode.iter_strings(data))
    both = set(textdecode.iter_strings(data, big_endian=True))
    assert not any("山田太郎" in s for s in le_only)  # 今までの読み方では拾えない
    assert any("山田太郎" in s for s in both), both
    assert any("千代田区" in s for s in both), both
    assert le_only <= both


def test_chunked_passes_big_endian():
    data = _binary_with(BODY.encode("utf-16-be"))
    reader = iter([data, b""])
    got = list(textdecode.iter_strings_chunked(lambda n: next(reader), big_endian=True))
    assert any("山田太郎" in s for s in got), got


def test_unknown_binary_reports_big_endian_findings(tmp_path):
    p = tmp_path / "record.xdt"
    p.write_bytes(_binary_with(BODY.encode("utf-16-be")))
    item = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path))).items[0]
    assert item.status == Status.PARTIAL, (item.status, item.method)
    assert "UTF-16LE/BE" in item.method, item.method
    assert {"name", "address"} <= set(item.finding_counts), item.finding_counts


def test_big_endian_skips_noise():
    """ASCII・数の表・乱数のバイナリを BE で読んでも、乱れた漢字の並びは拾わない。"""
    rnd = random.Random(20261119)
    samples = [
        b"The quick brown fox 0123456789 0A0B0C0D0E zzzz" * 50,
        b"".join(i.to_bytes(2, "big") for i in range(0x4E00, 0x5E00)),  # 連番（漢字の並びになる）
        bytes(rnd.getrandbits(8) for _ in range(200_000)),
    ]
    for data in samples:
        le_only = set(textdecode.iter_strings(data))
        extra = set(textdecode.iter_strings(data, big_endian=True)) - le_only
        assert not extra, sorted(extra)[:5]


@pytest.mark.parametrize(
    "text, expected",
    [
        ("氏名：山田太郎", True),
        ("電話：03-1234", True),
        ("堀堀堀堀堀堀", False),  # 同じ字の繰り返し
        ("氏名：渡邊太郎", False),  # 第2水準の字（邊）を含む並びは拾えない（限界）
        ("氏名：腕太郎", True),  # 第1水準の最後の字（cp932 0x9872）
        ("氏名：弌太郎", False),  # 第2水準の最初の字（cp932 0x989F）
        ("ABCD", False),  # ASCII だけ（LE の1バイトずらしで拾える）
    ],
)
def test_be_plausible(text, expected):
    assert textdecode._be_plausible(text) is expected

"""BOM も ASCII の間の 0x00 も無い UTF-16（日本語だけの文・罫線の多い表）を、テキストとして読む試験。

0x00 の偏りで見分けられない UTF-16 は、生データ走査（簡易検査）になり、ビッグエンディアンでは何も拾えなかった。
バイナリ・ほかの文字コードの文を UTF-16 と誤らないこと（陰性対照）も確かめる。名前・住所・番号は試験のために作ったもの。
"""

import importlib.util
import marshal
import random
import zlib

import pytest

from pii_checker import sniff, textdecode
from pii_checker.engine import scan_file
from pii_checker.models import ScanOptions, Status

JA_ONLY = "氏名　山田太郎　電話　〇九〇―一二三四―五六七八　住所　東京都千代田区丸の内九丁目\r\n" * 20
BOX = "┌────────┐\r\n│氏名：山田太郎　電話：090-1234-5678│\r\n└────────┘\r\n" * 20
PROSE = "わたしのなまえはやまだたろうです。でんわばんごうはぜろきゅうぜろのいちにさんよんです。\r\n" * 20
MIXED = "氏名：山田太郎　電話：090-1234-5678\r\n" * 20  # ASCII の間に 0x00 が多い（今までどおりの見分けで読めていた形）


@pytest.mark.parametrize("enc", ["utf-16-le", "utf-16-be"])
@pytest.mark.parametrize(
    "text, expected",
    [(JA_ONLY, {"name", "address"}), (BOX, {"name", "phone"}), (MIXED, {"name", "phone"})],
    ids=["日本語だけ", "罫線の表", "ASCII混じり"],
)
def test_utf16_without_bom_is_read_as_text(tmp_path, enc, text, expected):
    p = tmp_path / "memo.txt"
    p.write_bytes(text.encode(enc))
    item = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path))).items[0]
    assert item.status == Status.SCANNED, (item.status, item.method)
    assert enc in item.method, item.method
    assert expected <= set(item.finding_counts), item.finding_counts


@pytest.mark.parametrize("enc", ["utf-16-le", "utf-16-be"])
@pytest.mark.parametrize("text", [JA_ONLY, BOX, PROSE], ids=["日本語だけ", "罫線の表", "ひらがなの文"])
def test_decode_text_picks_utf16(enc, text):
    data = text.encode(enc)
    assert sniff._looks_like_text(data[:8192])
    assert textdecode.utf16_without_bom(data) == enc
    assert textdecode.decode_text(data) == (text, enc)


def _pyc() -> bytes:
    """ASCII の多いバイナリの見本（.pyc）。2バイトずつ読むと、どちらの向きでも漢字などの文字になる。"""
    src = "\n".join(f"CONSTANT_NAME_{i} = 'value_{i}_abcdefghijklmnop'" for i in range(400))
    return importlib.util.MAGIC_NUMBER + b"\x00" * 12 + marshal.dumps(compile(src, "m.py", "exec"))


def _not_utf16_samples() -> dict[str, bytes]:
    rnd = random.Random(1)
    ja = JA_ONLY * 3
    return {
        "乱数": bytes(rnd.randrange(256) for _ in range(8192)),
        "圧縮": zlib.compress(ja.encode("utf-8") * 5, 9)[:8192],
        "16bitの数": b"".join(rnd.randrange(0, 3000).to_bytes(2, "little") for _ in range(4096)),
        "pyc": _pyc(),
        "cp932": ja.encode("cp932"),
        "euc_jp": ja.encode("euc_jp"),
        "utf8": ja.encode("utf-8"),
        "utf8_末尾で切れた": ja.encode("utf-8")[:8191],
        "ASCII": ("CONSTANT_NAME = 'abcdefghijklmnop' " * 300).encode("ascii"),
        "短い": "氏名".encode("utf-16-le"),
    }


@pytest.mark.parametrize("name", list(_not_utf16_samples()))
def test_not_utf16_is_not_taken_as_utf16(name):
    data = _not_utf16_samples()[name]
    assert textdecode.utf16_without_bom(data) is None
    if name in ("cp932", "euc_jp", "utf8", "utf8_末尾で切れた", "ASCII"):
        assert textdecode.decode_text(data)[1] in ("cp932", "euc_jp", "utf-8"), name


def test_pyc_is_not_text():
    """ASCII の多いバイナリ（.pyc）は、今までどおりテキストとみなさない（2バイトずつ読んでも逆の向きでも文字になる）。"""
    data = _pyc()
    assert not sniff._looks_like_text(data[:8192])


def test_single_line_without_newline_is_not_utf16():
    """改行の文字が1つも無いものは、この見分けでは UTF-16 にしない（バイナリと誤らない側に倒す）。"""
    assert textdecode.utf16_without_bom(JA_ONLY.replace("\r\n", "　").encode("utf-16-le")) is None

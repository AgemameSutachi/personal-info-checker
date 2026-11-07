"""プログラムのソースを「区切り文字の表」と読み違えない試験（英語の識別子を列の見出しと取って大量に拾っていた）。

陽性対照: 本物の表（.csv・拡張子が .txt の表）は、これまでどおり表として読み、見出しの列で拾う。
"""

from __future__ import annotations

import pytest

from pii_checker import engine
from pii_checker.formats import misc
from pii_checker.models import ItemResult, ScanOptions, Status

# 同梱ライブラリの enums.py の形（__all__ の識別子の並び・列の見出しに見える Address・Name）
ENUMS_PY = (
    "from __future__ import annotations\n"
    "__all__ = [\n"
    + "".join(
        f"    '{n}',\n"
        for n in ["AddressBookType", "ContactAddressIndex", "DisplayName", "ElectronicAddressProperties"] * 8
    )
    + "]\n"
)
# webview の android の __init__.py の形（name, value = …）
COOKIE_PY = (
    "import json\n"
    "from http import cookies\n"
    "\n"
    "def parse(raw):\n"
    "    result = {}\n"
    "    for cookie_pair in raw.split(';'):\n"
    "        name, value = cookie_pair.split('=', 1)\n"
    "        result[name.strip()] = value\n"
    "    return result\n"
    "\n"
    "class Handler(object):\n"
    "    def on_cookie(self, name, value, domain):\n"
    "        return parse(value), name, domain\n"
)
CSV_TABLE = "氏名,住所,備考\n山田 太郎,東京都千代田区丸の内9-9-9,なし\n佐藤 花子,大阪府大阪市北区梅田9-9-9,なし\n"


def _scan(tmp_path, name: str, text: str, monkeypatch=None, limit=None) -> ItemResult:
    if limit is not None:
        monkeypatch.setattr(misc, "TEXT_READ_ALL_LIMIT", limit)
    p = tmp_path / name
    p.write_bytes(text.encode("utf-8"))
    ctx = engine.ScanContext(str(p), ScanOptions(temp_dir=str(tmp_path)), [])
    item = ItemResult(path=str(p), kind="テキスト", status=Status.PENDING)
    col = engine.Collector(item, 20)
    blob = engine.Blob(display=str(p), path=str(p))
    misc.handle_text(ctx, blob, item, col, 0)
    return item


@pytest.mark.parametrize("name", ["enums.py", "enums.txt"])
def test_identifier_list_is_not_a_table(tmp_path, name):
    """識別子の並び（.py も、拡張子の無いソースを写した .txt も）を表と読まず、何も拾わない。"""
    item = _scan(tmp_path, name, ENUMS_PY)
    assert "表として" not in item.method
    assert dict(item.finding_counts) == {}


@pytest.mark.parametrize("name", ["cookie.py", "cookie.txt"])
def test_source_with_commas_is_not_a_table(tmp_path, name):
    item = _scan(tmp_path, name, COOKIE_PY)
    assert "表として" not in item.method
    assert dict(item.finding_counts) == {}


def test_huge_source_is_read_as_lines(tmp_path, monkeypatch):
    """少しずつ読む経路でも、.py は表として読まない。"""
    item = _scan(tmp_path, "enums.py", ENUMS_PY, monkeypatch, limit=10)
    assert "巨大な表" not in item.method and "行）" in item.method
    assert dict(item.finding_counts) == {}


def test_pii_in_source_still_found(tmp_path):
    """ソースの中に書かれた個人情報は、本文として拾う（表として読まないだけ）。"""
    src = "def contact():\n    return '東京都千代田区丸の内9-9-9', 'yamada@example.co.jp'\n"
    item = _scan(tmp_path, "contact.py", src)
    assert "表として" not in item.method
    assert item.finding_counts.get("address") and item.finding_counts.get("email")


@pytest.mark.parametrize("name", ["members.csv", "members.txt"])
def test_real_table_still_read_as_table(tmp_path, name):
    """陽性対照: 本物の表は（拡張子が .txt でも）表として読み、住所の列で拾う。"""
    item = _scan(tmp_path, name, CSV_TABLE)
    if name.endswith(".txt"):
        assert "表として読み取り" in item.method
    assert any("B列" in f.location for f in item.findings if f.pii_type == "address")


def test_english_header_table_in_txt_still_table(tmp_path):
    """陽性対照: 英語の見出しの表（Name,Address）も、ソースの形の行が無ければ表として読む。"""
    text = "Name,Address,Phone\nTaro Yamada,9-9-9 Marunouchi,090-1234-5678\nHanako Sato,9-9-9 Umeda,080-1234-5678\n"
    item = _scan(tmp_path, "list.txt", text)
    assert "表として読み取り" in item.method


@pytest.mark.parametrize(
    "line,expected",
    [
        ("    'AddressBookType',", True),
        ('    "DisplayName"', True),
        ("import os", True),
        ("from a.b import c", True),
        ("def f(x):", True),
        ("    return x", True),
        ("};", True),
        ('"Smith",', False),  # 字下げの無い1列の CSV は表のまま
        ("山田 太郎,東京都千代田区丸の内9-9-9", False),
        ("    '山田',", False),  # 英語の識別子でない値
        ("Name,Address,Phone", False),
    ],
)
def test_source_line_pattern(line, expected):
    assert bool(misc._RE_SOURCE_LINE.match(line)) is expected

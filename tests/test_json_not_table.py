"""整形した JSON・JSON Lines を「区切り文字の表」と読み違えない試験。

整形した JSON は各行に「"キー": "値",」とカンマが1つずつあるため表と判定され、どこかの行の「氏名」を列の見出しと
見なして、A列の「"キー": "値"」の行を丸ごと「氏名の列の値」として拾っていた。
陽性対照: .json の名の本物の CSV は表のまま読み、JSON の中の個人情報は本文として拾う。
"""

from __future__ import annotations

import json

import pytest

from pii_checker import engine
from pii_checker.formats import misc
from pii_checker.models import ItemResult, ScanOptions, Status

RECORDS = [
    {"id": i, "氏名": "山田 太郎", "電話": f"090-1234-567{i}", "住所": "東京都千代田区丸の内9-9-9", "memo": "なし"}
    for i in range(5)
]
# 画面の文言の辞書（キーの1つの値が「氏名」）。旧来はこれが列の見出しになり、ほかの行を丸ごと氏名と取っていた
LABELS = json.dumps(
    {
        "title": "名簿の画面",
        "label_name": "氏名",
        "label_tel": "電話番号",
        **{f"msg{i}": f"メッセージ {i} です" for i in range(12)},
    },
    ensure_ascii=False,
    indent=2,
)
# 配列の文字列の要素が並ぶ形（字下げした「"…",」の行）
STRING_LIST = json.dumps(
    {"氏名": ["説明の文 その1", "説明の文 その2", "説明の文 その3"] * 4}, ensure_ascii=False, indent=2
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


@pytest.mark.parametrize("text", [LABELS, STRING_LIST], ids=["labels", "string-list"])
def test_pretty_json_is_not_a_table(tmp_path, text):
    """整形した JSON を表と読まず、列の見出しの読み違いで氏名を拾わない。"""
    item = _scan(tmp_path, "ui.json", text)
    assert "表として" not in item.method
    assert not any("列" in f.location for f in item.findings)
    assert dict(item.finding_counts) == {}


def test_json_lines_read_as_body(tmp_path):
    """JSON Lines（1行に {…}）は本文として読み、氏名・電話・住所を1行に1件ずつ拾う（列の読み違いで重ねない）。"""
    text = "\n".join(json.dumps(r, ensure_ascii=False) for r in RECORDS)
    item = _scan(tmp_path, "records.jsonl", text)
    assert "表として" not in item.method
    assert dict(item.finding_counts) == {"name": 5, "phone": 5, "address": 5}


def test_pretty_records_found_as_body(tmp_path):
    """陽性対照: 整形した JSON の中の個人情報は、見出し語つきの本文として拾う。"""
    item = _scan(tmp_path, "records.json", json.dumps(RECORDS, ensure_ascii=False, indent=2))
    assert "表として" not in item.method
    assert dict(item.finding_counts) == {"name": 5, "phone": 5, "address": 5}


def test_array_of_arrays_read_as_body(tmp_path):
    """配列の配列（1行に […]）も本文として読み、電話・住所を拾う。"""
    text = "[\n" + ",\n".join("  " + json.dumps(list(r.values()), ensure_ascii=False) for r in RECORDS) + "\n]"
    item = _scan(tmp_path, "rows.json", text)
    assert "表として" not in item.method
    assert item.finding_counts.get("phone") == 5 and item.finding_counts.get("address") == 5


def test_csv_named_json_still_table(tmp_path):
    """陽性対照: .json の名でも中身が CSV なら表として読み、住所の列で拾う。"""
    item = _scan(tmp_path, "export.json", CSV_TABLE)
    assert "表として読み取り" in item.method
    assert any("B列" in f.location for f in item.findings if f.pii_type == "address")


def test_huge_pretty_json_is_read_as_lines(tmp_path, monkeypatch):
    """少しずつ読む経路でも、整形した JSON は表として読まない。"""
    item = _scan(tmp_path, "ui.json", LABELS, monkeypatch, limit=10)
    assert "巨大な表" not in item.method and "行）" in item.method
    assert dict(item.finding_counts) == {}


@pytest.mark.parametrize(
    "line,expected",
    [
        ("{", True),
        ("  },", True),
        ("]", True),
        ('  "氏名": "山田 太郎",', True),
        ('"key": {', True),
        ('{"a": 1, "b": "x,y"}', True),
        ('  ["山田", "090-1234-5678"],', True),
        ('    "説明の文",', True),
        ("    123,", True),
        ("    true", True),
        ('"Smith",', False),  # 字下げの無い1列の CSV は表のまま
        ("山田 太郎,東京都千代田区丸の内9-9-9", False),
        ('"山田","東京都"', False),
        ("氏名,住所,備考", False),
        ('{"a":1},x', False),
        ("1,2,3", False),
    ],
)
def test_json_line_pattern(line, expected):
    assert bool(misc._RE_JSON_LINE.match(line)) is expected


def test_half_json_lines_stay_table():
    """JSON の形の行がちょうど半分なら（過半でないので）表のまま読む。"""
    text = '"a": 1,\n{"b": 2}\n山田 太郎,東京都千代田区丸の内9-9-9\n佐藤 花子,大阪府大阪市北区梅田9-9-9\n'
    assert misc._looks_tabular(text)

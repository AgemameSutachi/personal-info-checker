"""文中の英語の見出し語＋日本語の名前（`Name: 山田太郎`・`Customer name = 佐藤花子`）の試験。

前は英語の見出し語を本文の中では読まず、`Name: 山田太郎` を見落とし、`Full Name: 山田 太郎` は「よくある姓＋空白＋名」の 低 だった。
`name:` は YAML・設定の項目名にも多いので、値がよくある姓で始まる日本語の名前のものだけを 中 で拾う。
名前はすべて試験のために作ったもの。
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pii_checker import detectors  # noqa: E402

RULE = detectors.NAME_LABEL_EN_RULE


@pytest.fixture(params=[True, False], ids=["rust", "python"])
def engine(request, monkeypatch):
    """Rust 拡張がある経路と Python 版の経路の両方で試す。"""
    monkeypatch.setattr(detectors, "_short_cache", {})  # 覚え書きに残った前の回の結果を返さない
    if not request.param:
        monkeypatch.setattr(detectors, "_RUST", None)
    elif detectors._RUST is None:
        pytest.skip("Rust 拡張が無い")
    return request.param


def _names(text: str) -> list[detectors.Hit]:
    return [h for h in detectors.detect(detectors.normalize(text), None) if h.pii_type == "name"]


@pytest.mark.parametrize(
    "text, value",
    [
        ("Name: 山田太郎", "山田太郎"),
        ("name:山田太郎", "山田太郎"),
        ("NAME = 佐藤花子", "佐藤花子"),
        ("Full Name: 山田 太郎", "山田 太郎"),
        ("full_name: 鈴木一郎", "鈴木一郎"),
        ("Customer name: 佐藤花子", "佐藤花子"),
        ("customer-name=高橋健", "高橋健"),
        ("First Name：田中幸子", "田中幸子"),
        ("UserName: 伊藤誠", "伊藤誠"),
        ('{"name": "山田太郎", "age": 40}', "山田太郎"),
        ("name: '佐藤花子'", "佐藤花子"),
        ("  name: 渡辺 健\n", "渡辺 健"),  # YAML の字下げの項目
        ("担当\nContact name: 中村一郎（営業部）", "中村一郎"),
        ('name = "山田太郎"', "山田太郎"),  # コードの代入の文字列の値（日本語の見出し語の「氏名="…"」と同じ扱い）
    ],
)
def test_found_medium(text, value, engine):
    got = [h for h in _names(text) if h.value == value]
    assert got and all(h.confidence.value == "medium" for h in got), _names(text)
    assert any(h.rule == RULE for h in got), got


@pytest.mark.parametrize(
    "text",
    [
        "name: 営業部",  # 値がよくある姓で始まらない
        "name: 東京本社",
        "name: 山田",  # 姓だけ（名が無い）
        "name: 山田工業株式会社",  # 社名（姓の後ろに漢字が4字以上続く）
        "filename: 山田太郎.txt",  # 見出し語の直前が英字
        "company_name: 山田太郎",
        "company name: 山田太郎",
        "project-name: 田中太郎",
        "name1: 山田太郎",  # 見出し語の後ろが「:」「=」でない
        "name 山田太郎",  # 空白だけの区切りは読まない
        'name: "Taro Yamada"',  # ローマ字の名前は今までどおり本文では読まない
        "nickname: 山田太郎",
    ],
)
def test_not_found_by_english_label(text, engine):
    got = [h for h in _names(text) if h.rule.startswith(RULE)]
    assert not got, got


@pytest.mark.parametrize("text", ["name = 山田太郎.strip()", "name = 山田太郎 * 2"])
def test_code_assignment_dropped(text, engine):
    got = [h for h in _names(text) if h.rule.startswith(RULE)]
    assert not got, got


def test_in_call_is_low(engine):
    got = [h for h in _names('user = User(id=1, name="山田太郎")') if h.value == "山田太郎"]
    assert got and all(h.confidence.value == "low" for h in got), got
    assert any(h.rule == RULE + detectors.NAME_IN_CALL_NOTE for h in got), got


def test_rule_is_english_label(engine):
    """拾った名前の理由は英語の見出し語のもの（「よくある姓＋空白＋名」の 低 と重なっても 中 が残る）。"""
    got = [h for h in _names("Full Name: 山田 太郎") if h.value == "山田 太郎"]
    assert [h.rule for h in got] == [RULE], got


def test_two_labels_on_one_line(engine):
    got = {h.value for h in _names("name: 山田太郎, contact name: 佐藤花子") if h.rule == RULE}
    assert got == {"山田太郎", "佐藤花子"}, got

"""JSON・設定・XML の書き方の見出し（`"氏名": "山田太郎"`・`氏名="山田太郎"`・`<氏名>山田太郎</氏名>`）の試験。

見出し語と値の間の引用符・「=」・タグで区切りが切れて、氏名と要配慮の記載を見落としていた。
名前・病名はすべて試験のために作ったもの。
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pii_checker import detectors  # noqa: E402


def _found(text: str) -> set[tuple[str, str, str]]:
    return {(h.pii_type, h.confidence.value, h.value) for h in detectors.detect(detectors.normalize(text), None)}


@pytest.mark.parametrize(
    "text, value",
    [
        ('{"氏名": "山田太郎"}', "山田太郎"),
        ('{"名前":"山田 太郎"}', "山田 太郎"),
        ("{'お名前': '佐藤花子'}", "佐藤花子"),
        ('氏名="鈴木一郎"', "鈴木一郎"),
        ("氏名=鈴木一郎", "鈴木一郎"),
        ("<氏名>高橋健</氏名>", "高橋健"),
        ('{"患者名": "田中幸子", "年齢": 40}', "田中幸子"),
        # 今までどおり
        ("氏名: 山田太郎", "山田太郎"),
        ("氏名 山田太郎", "山田太郎"),
    ],
)
def test_quoted_name_labels(text, value):
    assert ("name", "medium", value) in _found(text), _found(text)


@pytest.mark.parametrize(
    "text, want",
    [
        ('{"病名": "糖尿病"}', "糖尿病"),
        ("病名=糖尿病", "糖尿病"),
        ("<病名>糖尿病</病名>", "糖尿病"),
        ('病名: "糖尿病"', "糖尿病"),
    ],
)
def test_quoted_sensitive_labels(text, want):
    got = [h for h in detectors.detect(detectors.normalize(text), None) if h.pii_type == "sensitive"]
    assert len(got) == 1, got
    # 値は見出し語から記載まで。記載の後ろの引用符・タグは含めない
    assert got[0].value.endswith(want), got[0].value


@pytest.mark.parametrize(
    "text",
    [
        'name = "山田太郎"',  # 見出し語は日本語だけ（英語の name は表の列見出しでだけ読む）
        '宛先="https://example.com"',  # 値が名前の字でない
        '{"名前": "戦略の名前"}',  # 見出し語の後の説明の文（今までどおり落とす）
        "病名 不明",  # 要配慮は空白の区切りを今までどおり読まない
        # 「>」はタグ `<見出し語>` の形のときだけ区切りにする（パンくず・矢印の代わりの「>」は読まない）
        "ホーム>担当>営業部",
        "TOP>お名前>入力画面",
        "お名前>確認",
        "病名>糖尿病",
        "信仰>設定",
        '"氏名","山田太郎"',  # CSV は表として読むので、本文の形では拾わない（表の経路の試験は別）
    ],
)
def test_not_found(text):
    got = {k for k in _found(text) if k[0] in ("name", "sensitive")}
    assert not got, got

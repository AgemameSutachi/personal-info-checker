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


@pytest.mark.parametrize(
    "text",
    [
        # コードの日本語の変数への代入。値の後ろがコードの続き（人の名前ならそこで終わる）
        '名前 = 有効["holder_name"].fillna("")',
        '名前 = 表示.fillna("")',
        "名前 = 有効[0]",
        '名前 = "営業利益÷総資産 上位20%"',
        "名前 = '佐藤花子の÷'",
        "名前 = 営業利益 * 2",
        "名前 = 営業利益×総資産",
    ],
)
@pytest.mark.parametrize("rust", [True, False])
def test_name_label_code_assignment_dropped(text, rust, monkeypatch):
    monkeypatch.setattr(detectors, "_short_cache", {})  # 覚え書きに残った前の回の結果を返さない
    if not rust:
        monkeypatch.setattr(detectors, "_RUST", None)
    got = {k for k in _found(text) if k[0] == "name"}
    assert not got, got


@pytest.mark.parametrize(
    "text, value",
    [
        # 人の名前の後ろにも来る形は、「=」の書き方でも今までどおり 中（落とさない）
        ('氏名="山田太郎（営業部）"', "山田太郎"),
        ("氏名=山田太郎(営業部)", "山田太郎"),
        ('氏名="ジョン・スミス"', "ジョン"),
        ('氏名="山田太郎 Taro"', "山田太郎"),
        ("氏名=山田 太郎.", "山田 太郎"),
        ("氏名=山田太郎[営業]", "山田太郎"),
        ("氏名=山田太郎<br>", "山田太郎"),
        ("氏名=山田太郎/営業", "山田太郎"),
        ('氏名="山田太郎', "山田太郎"),  # 途中で切れた値
        ("氏名=山田太郎", "山田太郎"),  # 本文の末尾
    ],
)
def test_name_label_equals_real_names_kept(text, value):
    assert ("name", "medium", value) in _found(text), _found(text)


@pytest.mark.parametrize(
    "text, value",
    [
        # 関数の引数（閉じていない「(」の中）は落とさず 低 に（ログの書き方も同じ形なので見落とさない）
        ('ベンチ = _成績(日次, 名前="ベンチ")', "ベンチ"),
        ("記録 = 判定(\n    名前=表示名,\n    詳細={},\n)", "表示名"),
        ("更新(氏名=山田太郎, 年齢=40)", "山田太郎"),
        ("（氏名=山田太郎）", "山田太郎"),  # 全角の括弧も正規化で半角になる
        ("x = f(\n" + "a, " * 60 + "名前=表示名)", "表示名"),  # 括弧が改行をまたいで前 200 字の中
    ],
)
@pytest.mark.parametrize("rust", [True, False])
def test_name_label_in_call_is_low(text, value, rust, monkeypatch):
    monkeypatch.setattr(detectors, "_short_cache", {})
    if not rust:
        monkeypatch.setattr(detectors, "_RUST", None)
    got = [h for h in detectors.detect(detectors.normalize(text), None) if h.pii_type == "name" and h.value == value]
    assert got and all(h.confidence.value == "low" for h in got), got
    assert any(h.rule.endswith(detectors.NAME_IN_CALL_NOTE) for h in got), got


@pytest.mark.parametrize(
    "text, value",
    [
        # 閉じた括弧の後ろ・括弧の外の「=」の形は今までどおり 中
        ('(備考) 氏名="鈴木一郎"', "鈴木一郎"),
        ("[会員]\n氏名=鈴木一郎\n", "鈴木一郎"),
        ('<input 氏名="鈴木一郎" />', "鈴木一郎"),
        ("f(" + "a, " * 70 + "\n氏名=鈴木一郎", "鈴木一郎"),  # 括弧が前 200 字より遠い
        ("x = [f(a), 氏名=鈴木一郎]", "鈴木一郎"),  # 近いのは「[」
        # 「:」の形は値の後ろに説明が続いても見ない
        ('{"氏名": "山田 太郎（営業部）"}', "山田 太郎"),
    ],
)
def test_name_label_outside_call_stays_medium(text, value):
    assert ("name", "medium", value) in _found(text), _found(text)

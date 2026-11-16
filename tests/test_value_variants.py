"""値の書き方の揺れの試験（括弧で区切る携帯・語で書く郵便番号・1字の元号・年が後ろの日付・郡部の番地・
「（普）」の口座・ゆうちょの記号と番号・人を指す語＋名前）。

2026-11-16 に、書き方を変えた 113 通りを検出器に通して取りこぼした形を直した。直さなかった形（フリーダイヤル・
「[at]」で書くアドレス・年の無い誕生日・英字だけの名前・敬称の前の空白）は、末尾の試験で拾わないことを押さえる。
値はすべて架空（住所は実在しない番地）。Rust 拡張があれば Rust の経路、無ければ Python の経路を試す
（両者の一致は tests/test_rust_equivalence.py の SEEDS が確かめる）。
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pii_checker.detectors import detect, normalize  # noqa: E402


def found(text: str, header: str | None = None) -> dict[str, tuple[str, str]]:
    """種類 → (確度, 値)。"""
    return {h.pii_type: (h.confidence.value, h.value) for h in detect(normalize(text), header)}


@pytest.mark.parametrize(
    "text, value",
    [
        ("090(1234)5678", "090(1234)5678"),
        ("０９０（１２３４）５６７８", "090(1234)5678"),
        ("(090)1234-5678", "(090)1234-5678"),
        ("携帯 (080) 1234 5678", "(080) 1234 5678"),
    ],
)
def test_mobile_with_parentheses(text, value):
    assert found(text)["phone"] == ("medium", value)


@pytest.mark.parametrize("text", ["郵便番号 100-0005", "郵便番号：1000005", "郵便番号:１００－０００５"])
def test_postal_code_after_label(text):
    conf, value = found(text)["postal_code"]
    assert conf == "medium"
    assert value.replace("-", "") == "1000005"


def test_postal_label_needs_seven_digits():
    assert "postal_code" not in found("郵便番号 1234-5678")
    assert "postal_code" not in found("郵便番号 100-00056")


@pytest.mark.parametrize("text", ["生年月日 昭60.4.1", "生年月日：平2年12月24日", "生年月日 令3.5.6"])
def test_one_letter_era_with_birth_word(text):
    assert found(text)["birthdate"][0] == "high"


def test_one_letter_era_without_birth_word_is_not_birthdate():
    # 語の無い和暦の日付を 低 で拾うのは「昭和」「平成」「大正」と S・T・H だけ
    assert "birthdate" not in found("最大1.2.3 の版")
    assert "birthdate" not in found("昭60.4.1")
    assert found("昭和60年4月1日")["birthdate"][0] == "low"


@pytest.mark.parametrize("text", ["Date of Birth: 01/04/1985", "DOB 4/1/1985", "生年月日 01.04.1985"])
def test_year_last_date_with_birth_word(text):
    assert found(text)["birthdate"][0] == "high"


def test_year_last_date_in_birth_column():
    assert found("01/04/1985", "生年月日")["birthdate"][0] == "high"


def test_year_last_date_without_birth_word_is_not_birthdate():
    assert "birthdate" not in found("更新日 01/04/1985")


@pytest.mark.parametrize(
    "text, value",
    [
        ("長野県北佐久郡軽井沢町大字軽井沢9999", "長野県北佐久郡軽井沢町大字軽井沢9999"),
        ("沖縄県島尻郡与那原町字与那原999", "沖縄県島尻郡与那原町字与那原999"),
        ("長野県北佐久郡軽井沢町大字軽井沢9999-9", "長野県北佐久郡軽井沢町大字軽井沢9999-9"),
    ],
)
def test_rural_address_with_aza(text, value):
    assert found(text)["address"][1] == value


@pytest.mark.parametrize(
    "text",
    ["サンプル銀行 丸の内支店（普）1234567", "サンプル銀行 丸の内支店(当)1234567", "振込先 (普) 0009-123-1234567"],
)
def test_bank_account_abbreviated_type(text):
    assert found(text)["bank_account"][0] == "high"


def test_bank_abbreviation_amount_is_not_account():
    assert "bank_account" not in found("(普)残高 1234567円")


@pytest.mark.parametrize(
    "text",
    ["ゆうちょ 記号10120 番号12345671", "記号：10120 番号：1234561", "記号 19990、番号 12345671"],
)
def test_yucho_symbol_and_number(text):
    conf, value = found(text)["bank_account"]
    assert conf == "high"
    assert value.isdigit() and len(value) >= 6


def test_yucho_needs_its_symbol_shape():
    # 保険証の「記号 12 番号 345」や、1で始まり0で終わる5桁でない記号はゆうちょにしない
    assert "bank_account" not in found("保険証 記号 12 番号 345")
    assert "bank_account" not in found("記号 20120 番号 12345671")
    assert "bank_account" not in found("記号 10121 番号 12345671")


@pytest.mark.parametrize(
    "text, value",
    [
        ("申込者 山田太郎", "山田太郎"),
        ("契約者：佐藤花子", "佐藤花子"),
        ("保護者 鈴木 一郎", "鈴木 一郎"),
        ("被保険者 田中次郎", "田中次郎"),
        ("加入者　高橋三郎", "高橋三郎"),
        ("申請者:伊藤四郎", "伊藤四郎"),
    ],
)
def test_person_word_and_common_surname(text, value):
    assert found(text)["name"] == ("medium", value)


def test_person_word_needs_common_surname():
    # よくある姓で始まらない語（「申込者 変更手続き」）は名前にしない
    assert "name" not in found("申込者 変更手続き")
    assert "name" not in found("契約者 本人確認書類")


@pytest.mark.parametrize(
    "text",
    [
        "0120-123-456",  # フリーダイヤル（会社の番号）
        "taro [at] example.jp",  # 書き換えたアドレス
        "誕生日 4月1日",  # 年の無い日付
    ],
)
def test_forms_left_out_on_purpose(text):
    assert not found(text)

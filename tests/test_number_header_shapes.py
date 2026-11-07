"""番号の見出し（列見出し・横持ちの左隣のセル）の値でも、番号にありえない形は拾わない試験。

2026-11-07 の株のデータの検査で見つかった誤検出の型:
- 社名「パスポート」の右隣の市場名「JASDAQ スタンダード」を旅券番号に
- 備考「…当選口座: SBI1枚→」の右隣の URL を銀行口座番号に
- 書類番号「S100ETEL」（TEL を含む）の右隣のコード「E31640」を電話番号に
- 数値の表の小数「0.1234567890123545」の小数部を、Luhn が合うのでカード番号に

陽性対照: 本物の番号（TEL の頭の電話・英字つきの旅券番号・区切りのあるカード番号）は今までどおり拾う。
"""

from __future__ import annotations

import pytest

from pii_checker import detectors
from pii_checker.engine import Collector
from pii_checker.models import ItemResult, Status


def _table_counts(rows) -> dict[str, int]:
    item = ItemResult(path="t", kind="", status=Status.PENDING)
    col = Collector(item, 20)
    col.add_table(rows, lambda r, c: f"R{r}C{c + 1}")
    return item.finding_counts


def _types(value: str, header: str | None = None) -> set[str]:
    return {h.pii_type for h in detectors.detect(detectors.normalize(value), header)}


@pytest.mark.parametrize(
    "category,value",
    [
        ("passport", "JASDAQ スタンダード"),
        ("passport", "https://example.com/a/123456"),
        ("drivers_license", "ゴールド免許"),
        ("bank_account", "https://example.jp/bunbai/123456.html"),
        ("bank_account", "www.example.jp/123456"),
        ("phone", "E31640"),
        ("phone", "S100ETEL"),
        ("phone", "ABCD1234"),
        ("postal_code", "https://example.jp/1000005"),
        ("credit_card", "https://example.com/card/4111111111111111"),
    ],
)
def test_impossible_number_values_dropped(category, value):
    assert detectors._header_value_hit(category, value) is None


@pytest.mark.parametrize(
    "category,value",
    [
        ("passport", "TK1234567"),
        ("drivers_license", "301234567890"),
        ("health_insurance", "12-3456"),
        ("bank_account", "普通 1234567"),
        ("phone", "03-1234-5678"),
        ("phone", "fax.0312345678"),
        ("phone", "No123456"),
        ("postal_code", "100-0005"),
        # 〒を T と書いたもの・国の頭つき（英字の頭のコードの判定は電話だけ）
        ("postal_code", "T1000005"),
        ("postal_code", "JP1000005"),
        ("bank_account", "A1234567"),
        ("credit_card", "4111 1111 1111 1111"),
    ],
)
def test_real_number_values_kept(category, value):
    hit = detectors._header_value_hit(category, value)
    assert hit is not None and hit.pii_type == category


@pytest.mark.parametrize("value", ["TEL0312345678", "Tel:0312345678", "TEL 090-1234-5678"])
def test_tel_prefixed_phone_kept(value):
    # TEL の頭の電話番号は、コードの形として落とさない（電話の形の検出で拾う）
    assert "phone" in _types(value, "電話番号")


@pytest.mark.parametrize(
    "rows,kind",
    [
        # 社名がパスポート（縦持ちの表の値）。右隣の市場名は旅券番号ではない
        ([["code", "name", "market"], ["7577", "パスポート", "JASDAQ スタンダード"]], "passport"),
        # 備考に「口座」の語。右隣の URL は口座番号ではない
        (
            [["name", "note", "url"], ["例の会社", "当選口座: SBI1枚", "https://example.jp/bunbai/123456.html"]],
            "bank_account",
        ),
        # 書類番号が TEL を含む。右隣のコードは電話番号ではない
        ([["doc_id", "edinet_code"], ["S100ETEL", "E31640"]], "phone"),
    ],
)
def test_horizontal_label_does_not_turn_values_into_numbers(rows, kind):
    assert _table_counts(rows).get(kind, 0) == 0


@pytest.mark.parametrize(
    "rows,expect",
    [
        ([["パスポート", "TK1234567"]], {"passport": 1}),
        ([["口座番号", "1234567"]], {"bank_account": 1}),
        ([["TEL", "03-1234-5678"]], {"phone": 1}),
    ],
)
def test_horizontal_label_still_reads_real_numbers(rows, expect):
    got = _table_counts(rows)
    for k, n in expect.items():
        assert got.get(k, 0) == n, got


@pytest.mark.parametrize("text", ["0.4111111111111111", "x=12.5555555555554444", "4111111111111111.25"])
def test_card_digits_in_decimal_dropped(text):
    assert "credit_card" not in _types(text)


@pytest.mark.parametrize("text", ["4111111111111111", "カード番号 4111111111111111", "4111-1111-1111-1111"])
def test_card_digits_outside_decimal_kept(text):
    assert "credit_card" in _types(text)


@pytest.mark.parametrize(
    "value,header",
    [
        ("JASDAQ スタンダード", "パスポート"),
        ("https://example.jp/bunbai/123456.html", "当選口座: SBI1枚"),
        ("E31640", "S100ETEL"),
        ("0.4111111111111111", None),
        ("T1000005", "郵便番号"),
        ("TEL0312345678", "電話番号"),
    ],
)
def test_python_and_rust_agree(monkeypatch, value, header):
    # Rust 拡張がある環境では、Python 版だけで検出したときと同じ結果になること
    text = detectors.normalize(value)
    got = [(h.pii_type, h.confidence, h.rule) for h in detectors._detect_uncached(text, header)]
    monkeypatch.setattr(detectors, "_RUST", None)
    want = [(h.pii_type, h.confidence, h.rule) for h in detectors._detect_uncached(text, header)]
    assert got == want


def test_card_in_decimal_with_card_header_kept():
    # 列の見出しがカード番号なら値の形で落とさない（確度 高）
    assert "credit_card" in _types("4111111111111111", "カード番号")

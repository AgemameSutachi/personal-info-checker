"""検出規則の単体試験（見逃しと誤検出の両方）。"""

# 試験の住所は施設の公開所在地（例 東京都千代田区丸の内1-1-1）で、個人の住所ではない。人名・電話・メールはすべて架空

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pii_checker.detectors import (  # noqa: E402
    detect,
    header_category,
    luhn_is_valid,
    mask_value,
    my_number_is_valid,
    normalize,
)


def types_of(text: str, header: str | None = None) -> dict[str, str]:
    return {h.pii_type: h.confidence.value for h in detect(normalize(text), header)}


def test_my_number_check_digit():
    assert my_number_is_valid("123456789018")
    assert not my_number_is_valid("123456789012")
    assert not my_number_is_valid("111111111111")


def test_luhn():
    assert luhn_is_valid("4111111111111111")
    assert not luhn_is_valid("4111111111111112")


@pytest.mark.parametrize(
    "text, expected",
    [
        ("携帯 090-1234-5678", "phone"),
        ("ＴＥＬ：０３－１２３４－５６７８", "phone"),
        ("(03)1234-5678", "phone"),
        ("+81 90-1234-5678", "phone"),
        ("taro.yamada@example.jp", "email"),
        ("〒100-0005", "postal_code"),
        ("東京都千代田区丸の内1-2-3", "address"),
        ("生年月日 1985年4月1日", "birthdate"),
        ("生年月日：昭和60年4月1日", "birthdate"),
        ("個人番号 1234 5678 9018", "my_number"),
        ("カード番号 4111-1111-1111-1111", "credit_card"),
        ("口座番号 普通 1234567", "bank_account"),
        ("免許証番号 123456789012", "drivers_license"),
        ("旅券番号 TK1234567", "passport"),
        ("基礎年金番号 1234-567890", "pension"),
        ("氏名：山田 太郎", "name"),
        ("氏名山田太郎", "name"),
        ("佐藤様", "name"),
        ("病名：糖尿病", "sensitive"),
        ("氏名 山田太郎", "name"),
        ("担当：佐藤花子", "name"),
        ("TEL 03.1234.5678", "phone"),
        ("TEL 03 1234 5678", "phone"),
        ("東京都港区六本木六丁目十番一号", "address"),
        ("千代田区丸の内一丁目1番1号", "address"),
        # 「運転免許」だけ（証・番号なし）の書き方。以前は免許の語でマイナンバーから外したうえ、免許証としても拾わなかった
        ("運転免許 123456789012", "drivers_license"),
        ("運転免許 123456789018", "drivers_license"),
        ("運転免許証 123456789012", "drivers_license"),
        # 都道府県・市区町村の後に空白を挟んだ住所（以前は拾わなかった・不具合の修正）
        ("東京都千代田区 丸の内1-1-1", "address"),
        ("東京都 千代田区 丸の内1-1-1", "address"),
        ("東京都港区 六本木1-2-3", "address"),
        ("東京都港区 三田1-2-3", "address"),
        ("東京都千代田区 九段北1-2-3", "address"),
        ("東京都港区 六本木六丁目10番1号", "address"),
    ],
)
def test_detects(text, expected):
    assert expected in types_of(text)


@pytest.mark.parametrize(
    "text",
    [
        "JANコード 4901234567894",
        "注文番号 202410170001",
        "金額 1,234,567円",
        "日付 2024-10-17 会議",
        "フリーダイヤル 0120-123-456",
        "検査数字が合わない 123456789012",
        "Luhn が通らない 4111 1111 1111 1112",
        "商品コード ABC-1234-5678",
        "バージョン 10.0.19045.1234",
        "株式会社サンプル 本社 TEL 03-1234-5678 FAX 03-1234-5679",
        "口座残高：1234567円",
        "口座振替額 2500000",
        "注文番号 4111111111111111",
        "品番 123-4567 東京都向け",
        "SN 08012345678",
        # フリーダイヤル等はどの書き方でも外す（空白区切り・区切りなしで 0800・0990 が残っていた）
        "TEL 0800 123 4567",
        "TEL 0990123456",
        "TEL 0570-123-456",
    ],
)
def test_no_false_positive(text):
    found = types_of(text)
    assert not {k for k, v in found.items() if v in ("high", "medium")}, found


@pytest.mark.parametrize(
    "text",
    [
        "運転免許：有 個人番号：123456789018",
        "運転免許 有、マイナンバー 123456789018",
        "免許証：有 個人番号：123456789018",
    ],
)
def test_my_number_after_license_field_is_not_taken_as_license(text):
    """申込書の「運転免許：有」の欄の後ろの個人番号を、免許証番号と取り違えない（2026-10-18 不具合の修正）。"""
    found = types_of(text)
    assert found.get("my_number") == "high" and "drivers_license" not in found, found


@pytest.mark.parametrize(
    "text",
    [
        "所在地 東京都港区 03-1234-5678",
        "東京都港区 2024-10-18 開催",
        "神奈川県横浜市 10-15名",
        "東京都港区 3番会議室",
    ],
)
def test_space_after_city_needs_town_name(text):
    """市区町村の後の空白は、町名が続くときだけ住所の続きとみなす（日付・電話・人数を番地と取り違えない）。"""
    assert "address" not in types_of(text), types_of(text)


def test_card_number_is_not_also_my_number():
    assert "my_number" not in types_of("4111 1111 1111 1111")


def test_header_categories():
    assert header_category("氏名") == "name"
    assert header_category("顧客名") == "name"
    assert header_category("会社名") is None
    assert header_category("商品名") is None
    assert header_category("電話番号") == "phone"
    assert header_category("生年月日") == "birthdate"
    assert header_category("E-mail") == "email"
    assert header_category("マイナンバー") == "my_number"
    assert header_category("MAC Address") is None
    assert header_category("本社所在地") is None
    assert header_category("メールアドレス") == "email"
    assert header_category("担当者") == "name"


def test_context_has_no_raw_values():
    from pii_checker.detectors import masked_context

    text = normalize("氏名:東海林一郎 電話:090-1234-5678 住所:東京都港区六本木6-10-1")
    hit = [h for h in detect(text) if h.pii_type == "phone"][0]
    ctx = masked_context(text, hit.start, hit.end, mask_value("phone", hit.value))
    assert "東海林一郎" not in ctx and "6-10-1" not in ctx and "六本木" not in ctx, ctx


def test_header_value_hits_unknown_name():
    # 辞書に無い名前でも、列見出しが氏名なら拾う
    assert "name" in types_of("鬼瓦 権左衛門", header="氏名")
    assert types_of("株式会社サンプル", header="会社名") == {}


@pytest.mark.parametrize(
    "pii_type, value, must_not_contain",
    [
        ("phone", "090-1234-5678", "1234"),
        ("my_number", "123456789018", "12345678"),
        ("email", "taro.yamada@example.jp", "taro"),
        ("credit_card", "4111 1111 1111 1111", "4111 1111 1111"),
        ("name", "山田太郎", "太郎"),
    ],
)
def test_mask_hides_value(pii_type, value, must_not_contain):
    assert must_not_contain not in mask_value(pii_type, value)


def _found(text, header=None):
    from pii_checker.detectors import normalize

    return [(h.pii_type, h.confidence.value) for h in detect(normalize(text), header)]


@pytest.mark.parametrize("text", ["東京都港区 第3会議室1番", "東京都港区 Room3-1"])
def test_room_name_after_space_is_not_address(text):
    """市区町村の空白の後が「第」・英字で始まるもの（部屋の名前）を番地にしない。"""
    assert not [t for t in _found(text) if t[0] == "address"], _found(text)


def test_space_before_town_name_still_found():
    """空白の後が町名の文字なら、今までどおり番地として拾う。"""
    assert ("address", "medium") in _found("東京都千代田区 丸の内1-1-1")


def test_license_with_negated_my_number_word():
    """「免許証番号（個人番号ではない）123…」は免許証番号として拾う（どれにも拾わず落ちていた）。"""
    assert ("drivers_license", "high") in _found("運転免許証番号（個人番号ではない）123456789012")


def test_free_dial_shaped_12_digits_is_low_with_reason():
    """語の無い「0800 1234 5678」（検査数字が偶然合う）は拾わないことはせず 低 にし、番号の形に見えると理由を添える。"""
    hits = [h for h in detect("フリーダイヤル 0800 1234 5678") if h.pii_type == "my_number"]
    assert len(hits) == 1 and hits[0].confidence.value == "low" and "フリーダイヤル" in hits[0].rule, hits


@pytest.mark.parametrize(
    "text",
    [
        "電話 +81-3-1234-5678",
        "Tel: +81 6 1234 5678",
        "+81-45-123-4567",
        "TEL:+81(0)3-1234-5678",
        "+81 (0)3 1234 5678",
        "+81-(0)45-123-4567",
    ],
)
def test_international_landline_is_found(text):
    """「+81-3-…」の固定電話も拾う（今までは携帯の +81 だけだった）。"""
    assert ("phone", "medium") in _found(text), _found(text)


def test_international_landline_of_company_is_low():
    assert ("phone", "low") in _found("株式会社サンプル 本社 +81-3-1234-5678")


def test_fax_next_to_name_is_not_company():
    """「山田太郎 TEL … FAX …」の電話を、FAX の語だけで会社の番号（低）にしない。"""
    found = _found("山田太郎 TEL 03-1234-5678 FAX 03-1234-5679")
    assert found.count(("phone", "medium")) == 2, found


def test_workplace_address_is_personal():
    """「勤務先 〇〇高校 東京都…」は施設の所在地でも、その人の勤め先として 中。"""
    hits = [h for h in detect("勤務先 港高校 東京都港区芝5-1-1") if h.pii_type == "address"]
    assert hits and hits[0].confidence.value == "medium" and not hits[0].needs_person


def test_facility_word_inside_address_column_value():
    """「住所」列の値の中の施設名（「港区役所 東京都…」）も施設の所在地として 低。"""
    hits = [h for h in detect("港区役所 東京都港区芝公園1-5-25", "住所") if h.pii_type == "address"]
    assert hits and all(h.confidence.value == "low" for h in hits), hits
    plain = [h for h in detect("東京都港区芝公園1-5-25", "住所") if h.pii_type == "address"]
    assert plain and plain[0].confidence.value == "medium" and plain[0].needs_person


def test_international_navi_dial_is_not_found():
    """+81 で書いたナビダイヤル（0570）も、国内の書き方と同じく個人の電話にしない。"""
    assert not [t for t in _found("+81-570-01-2345") if t[0] == "phone"]


def test_english_letterhead_is_low():
    assert ("phone", "low") in _found("ABC Co., Ltd. Head Office +81-3-1234-5678")


def test_facility_named_after_prefecture_in_address_column():
    """「大阪府立病院 大阪府…」のように都道府県で始まる施設名も、住所列の値の中で施設とみなす。"""
    hits = [h for h in detect("大阪府立病院 大阪府大阪市中央区1-1-1", "住所") if h.pii_type == "address"]
    assert hits and all(h.confidence.value == "low" for h in hits), hits


@pytest.mark.parametrize("text", ["TEL +81312345678", "+81-3-12345678", "+81312345678"])
def test_international_landline_without_separators(text):
    """区切りの無い +81 の固定電話（vCard の書き出しなど）も拾う。"""
    assert ("phone", "medium") in _found(text), _found(text)


@pytest.mark.parametrize("phone", ["+81-3-1234-5678", "03-1234-5678"])
def test_personal_word_beats_company_word_for_landline(phone):
    """会社の語の近くでも「自宅」などの語があれば、+81 の形も国内の形も 中 にし、当たった語を明細に出す。"""
    hits = [h for h in detect(f"株式会社サンプル 自宅 {phone}") if h.pii_type == "phone"]
    assert hits and hits[0].confidence.value == "medium" and "「自宅」" in hits[0].rule, hits


def test_company_note_names_the_word_found():
    hits = [h for h in detect("ABC Co., Ltd. Head Office +81-3-1234-5678") if h.pii_type == "phone"]
    # 書かれていない「株式会社」ではなく、実際に当たった語を出す
    assert hits and hits[0].confidence.value == "low" and "「Co., Ltd」" in hits[0].rule, hits
    assert "株式会社" not in hits[0].rule


@pytest.mark.parametrize("text", ["TEL +81 (3) 1234-5678", "TEL +81.3.1234.5678"])
def test_international_landline_other_separators(text):
    assert ("phone", "medium") in _found(text), _found(text)


@pytest.mark.parametrize("text", ["1e+81234567890", "1234+81312345678"])
def test_plus81_inside_numbers_is_not_phone(text):
    """数式・長い数字の中の「+81…」を電話番号にしない。"""
    assert not [t for t in _found(text) if t[0] == "phone"], _found(text)


def test_company_word_needs_word_start():
    """「zinc.」の中の「inc.」を会社の語にしない。"""
    hits = [h for h in detect("zinc. tel +81-3-1234-5678") if h.pii_type == "phone"]
    assert hits and hits[0].confidence.value == "medium" and "会社" not in hits[0].rule, hits

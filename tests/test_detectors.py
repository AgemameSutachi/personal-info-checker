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


# ---------------------------------------------------------------- 番号の種類の追加（在留カード・住民票コード等）


def _conf_of(text: str, pii_type: str, header: str | None = None) -> list[str]:
    return [h.confidence.value for h in detect(normalize(text), header) if h.pii_type == pii_type]


@pytest.mark.parametrize(
    "text, pii_type, conf",
    [
        ("在留カード番号 AB12345678CD", "residence_card", "high"),
        ("在留カード：XY98765432ZW", "residence_card", "high"),
        ("在留カード番号　ＡＢ１２３４５６７８ＣＤ", "residence_card", "high"),
        ("住民票コード 12345678901", "resident_code", "high"),
        ("住民票コード：98765432109", "resident_code", "high"),
        ("雇用保険被保険者番号 1234-567890-1", "employment_insurance", "high"),
        ("雇用保険番号 12345678901", "employment_insurance", "high"),
        ("雇用保険 被保険者番号：1234-567890-1", "employment_insurance", "high"),
        ("社員番号：A12345", "member_id", "low"),
        ("職員番号 2024-0012", "member_id", "low"),
        ("従業員番号 E00123", "member_id", "low"),
        ("会員番号 M-000123", "member_id", "low"),
        ("顧客番号 C123456", "member_id", "low"),
        ("お客様番号 1234567890", "member_id", "low"),
        ("学籍番号 21X1234", "member_id", "low"),
        ("患者番号 000123", "member_id", "low"),
        ("診察券番号 00123456", "member_id", "low"),
        ("口座 0001-234-5678901", "bank_account", "high"),
        ("振込先 0005-123-1234567", "bank_account", "high"),
        ("振込口座 0005-123-1234567", "bank_account", "high"),
        ("引落口座：0009-876-7654321", "bank_account", "high"),
    ],
)
def test_new_number_types_found(text, pii_type, conf):
    assert _conf_of(text, pii_type) == [conf], types_of(text)


@pytest.mark.parametrize(
    "text, pii_type",
    [
        # 語の無いものは拾わない
        ("AB12345678CD", "residence_card"),
        ("型番 AB12345678CD", "residence_card"),
        ("在留カード番号 AB1234567CD", "residence_card"),  # 数字が7桁
        ("在留カードの申請は2024年4月1日から", "residence_card"),
        ("12345678901", "resident_code"),
        ("住民票コード 1234567890", "resident_code"),  # 10桁
        ("住民票コードの記入は不要です", "resident_code"),
        ("1234-567890-1", "employment_insurance"),
        ("雇用保険の加入日 2024年4月1日", "employment_insurance"),
        ("雇用保険料 12,345円", "employment_insurance"),
        ("A12345", "member_id"),
        ("社員番号の欄に記入してください", "member_id"),
        ("会員番号：未登録", "member_id"),
        ("会員番号 ABCDEF", "member_id"),  # 数字を含まない
        ("会員番号 2024年度から変更", "member_id"),
        ("会員番号 1200件", "member_id"),
        ("会員番号 123", "member_id"),  # 3文字
        ("0001-234-5678901", "bank_account"),  # 口座の語が無い
        ("口座残高 0001-234-5678901円", "bank_account"),
    ],
)
def test_new_number_types_need_keyword(text, pii_type):
    assert not _conf_of(text, pii_type), types_of(text)


def test_employment_insurance_is_not_health_insurance():
    """「雇用保険被保険者番号」の「被保険者番号」で、保険証の記号番号として出さない。"""
    for text in ("雇用保険被保険者番号 1234-567890-1", "雇用保険被保険者番号 123456789"):
        found = types_of(text)
        assert "health_insurance" not in found and "employment_insurance" in found, (text, found)
    # 雇用保険の語が無ければ、今までどおり保険証の記号番号
    assert types_of("被保険者番号 1234-567890-1") == {"health_insurance": "medium"}


def test_member_id_header_column_is_low():
    for header in ("社員番号", "職員番号", "会員番号", "顧客番号", "お客様番号", "学籍番号", "患者番号", "診察券番号"):
        assert header_category(header) == "member_id", header
    assert _conf_of("A0123", "member_id", header="社員番号") == ["low"]
    assert not _conf_of("未登録", "member_id", header="会員番号")
    # 「社員名」「患者名」は今までどおり氏名の列
    assert header_category("社員名") == "name" and header_category("患者名") == "name"


def test_new_types_header_columns():
    assert header_category("在留カード番号") == "residence_card"
    assert header_category("住民票コード") == "resident_code"
    assert header_category("雇用保険被保険者番号") == "employment_insurance"
    assert header_category("雇用保険番号") == "employment_insurance"
    assert header_category("雇用保険料") is None
    assert _conf_of("AB12345678CD", "residence_card", header="在留カード番号") == ["high"]
    assert _conf_of("12345678901", "resident_code", header="住民票コード") == ["high"]
    assert _conf_of("1234-567890-1", "employment_insurance", header="雇用保険被保険者番号") == ["high"]
    assert not _conf_of("1234", "resident_code", header="住民票コード")


# ---------------------------------------------------------------- 型番などの近くの電話


@pytest.mark.parametrize(
    "text",
    [
        "型番 090-1234-5678",
        "品番 080-2345-6789",
        "製品コード 070-1111-2222",
        "商品コード 050-1234-5678",
        "部品番号 03-1234-5678",
        "図面番号 06-1234-5678",
        "追跡番号 090-1111-2222",
        "お問い合わせ番号 080-1234-5678",
        "伝票番号 090-8765-4321",
        "整理番号 06-1234-5678",
        "受付番号 03-1234-5678",
        "ISBN 090-1234-5678",
        "JAN 080-1234-5678",
    ],
)
def test_model_number_word_lowers_phone(text):
    hits = [h for h in detect(normalize(text)) if h.pii_type == "phone"]
    assert hits and all(h.confidence.value == "low" for h in hits) and "型番などの番号" in hits[0].rule, hits


@pytest.mark.parametrize(
    "text",
    [
        "型番 TEL 090-1234-5678",
        "型番 X-100 連絡先 090-1234-5678",
        "品番 A-1 携帯 080-2345-6789",
        "受付番号 12 電話 03-1234-5678",
    ],
)
def test_phone_word_right_before_value_beats_model_word(text):
    """電話の語が値のすぐ左（型番の語より値に近い）にあれば、型番の語では下げない。"""
    assert _conf_of(text, "phone") == ["medium"], types_of(text)


def test_model_word_after_value_does_not_lower():
    assert _conf_of("090-1234-5678 型番", "phone") == ["medium"]


def test_model_word_does_not_lower_phone_column():
    assert _conf_of("型番 090-1234-5678", "phone", header="電話番号") == ["medium"]


def test_grouped_card_number_next_to_model_word_is_low():
    """4桁ずつ区切ったカード番号の形でも、前に品番などの語があり、カードの語が無ければ 低。"""
    assert _conf_of("品番 4111-1111-1111-1111", "credit_card") == ["low"]
    assert _conf_of("カード番号 4111-1111-1111-1111", "credit_card") == ["high"]
    assert _conf_of("4111-1111-1111-1111", "credit_card") == ["high"]


# ---------------------------------------------------------------- 語はあるのに検査数字が合わない番号


@pytest.mark.parametrize("text", ["個人番号 123456789012", "マイナンバー：1234 5678 9013", "123456789012（個人番号）"])
def test_my_number_with_keyword_but_bad_check_digit_is_low(text):
    hits = [h for h in detect(normalize(text)) if h.pii_type == "my_number"]
    assert len(hits) == 1 and hits[0].confidence.value == "low", hits
    assert "検査数字が合わない（打ち間違いの可能性）" in hits[0].rule


@pytest.mark.parametrize(
    "text",
    [
        "検査数字が合わない 123456789012",  # 語が無い
        "個人番号 111111111111",  # 全部同じ数字
        "注文番号 123456789012",
    ],
)
def test_my_number_bad_check_digit_without_keyword_is_not_found(text):
    assert "my_number" not in types_of(text), types_of(text)


@pytest.mark.parametrize(
    "text", ["カード番号 4111 1111 1111 1112", "クレジット 4111111111111112", "Card No. 3530111333300001"]
)
def test_card_with_keyword_but_bad_luhn_is_low(text):
    hits = [h for h in detect(normalize(text)) if h.pii_type == "credit_card"]
    assert len(hits) == 1 and hits[0].confidence.value == "low", hits
    assert "Luhn 検査が合わない（打ち間違いの可能性）" in hits[0].rule


@pytest.mark.parametrize(
    "text",
    [
        "4111 1111 1111 1112",
        "ポイントカード 4111111111111112",
        "カード番号 4444444444444444",
        "カード番号 123456789012",
    ],
)
def test_card_bad_luhn_without_card_number_word_is_not_found(text):
    assert "credit_card" not in types_of(text), types_of(text)


def test_license_number_with_negated_my_number_is_not_my_number():
    """免許証の語の後の12桁は、個人番号の語があっても検査数字が合わなければ免許証番号のまま（マイナンバーの 低 にしない）。"""
    found = types_of("運転免許証番号（個人番号ではない）123456789012")
    assert found == {"drivers_license": "high"}, found


# ---------------------------------------------------------------- 本人確認書類の写し（OCR の文字だけ）


@pytest.mark.parametrize(
    "text, doc",
    [
        ("運転免許証\n氏名 山田 太郎\n交付 令和5年4月1日\n東京都公安委員会", "運転免許証"),
        ("運 転 免 許 証  免許の条件等 眼鏡等", "運転免許証"),
        ("個人番号カード\n有効期限 2030年4月1日まで\n電子証明書の有効期限", "個人番号カード"),
        ("個人番号カード 裏面 個人番号 1234 5678 9018", "個人番号カード"),
        ("在留カード\n在留資格 留学\n在留期間 2年", "在留カード"),
        ("在留カード 就労制限の有無", "在留カード"),
        ("健康保険 被保険者証\n記号 12 番号 34\n保険者番号 01234567", "健康保険証"),
        ("資格確認書 保険者番号 06123456", "健康保険証"),
        ("日本国旅券 発行年月日 2020年1月1日", "旅券"),
        ("PASSPORT\nDate of issue 01 JAN 2020", "旅券"),
        ("旅券 有効期間満了日 2030年", "旅券"),
    ],
)
def test_id_document_from_ocr(text, doc):
    from pii_checker.detectors import detect_id_documents

    hits = detect_id_documents(normalize(text), from_ocr=True)
    assert [h.value for h in hits] == [doc], hits
    assert hits[0].pii_type == "id_document" and hits[0].confidence.value == "high"


@pytest.mark.parametrize(
    "text",
    [
        "運転免許証のコピーを添付してください",  # 書類の名前だけ
        "個人番号カードをお持ちの方",  # 「個人番号」は名前の語の中だけ
        "在留カードの提示",
        "被保険者証の写し",
        "旅券を持参",
        "PASSPORT photo",
        "公安委員会 交付 有効期限 在留資格 保険者番号 発行年月日",  # 書類の名前が無い
        "",
    ],
)
def test_id_document_needs_both_words(text):
    from pii_checker.detectors import detect_id_documents

    assert detect_id_documents(normalize(text), from_ocr=True) == []


def test_id_document_not_from_plain_text():
    """普通の文書（Word・Excel・テキスト）の文字では判別しない（申込書の見本・説明文で誤検出しないため）。"""
    from pii_checker.detectors import detect_id_documents

    text = normalize("運転免許証（公安委員会が交付したもの）の写しを添付してください")
    assert detect_id_documents(text, from_ocr=False) == []
    assert "id_document" not in types_of(text)


def test_collector_id_document_only_for_ocr_lines():
    from pii_checker.engine import Collector, risk_of
    from pii_checker.models import ItemResult, Status

    text = "運転免許証\n交付 令和5年4月1日\n東京都公安委員会"
    item = ItemResult(path="t", kind="", status=Status.PENDING)
    col = Collector(item, 20)
    col.add_lines(text, location_prefix="2ページ（OCR） ", method="OCR", ocr=True)
    col.finish()
    assert item.conf_counts.get("id_document:high") == 1, item.conf_counts
    f = [f for f in item.findings if f.pii_type == "id_document"]
    assert f and f[0].masked_value == "運転免許証" and f[0].location == "2ページ（OCR）", f
    assert risk_of([item]) == "高"

    plain = ItemResult(path="t", kind="", status=Status.PENDING)
    col = Collector(plain, 20)
    col.add_lines(text, location_prefix="本文 ", method="本文")
    col.finish()
    assert "id_document" not in plain.finding_counts, plain.finding_counts


# ---------------------------------------------------------------- 伏せ方・危険度


@pytest.mark.parametrize(
    "pii_type, value, shown, hidden",
    [
        ("residence_card", "AB12345678CD", "78CD", "AB123456"),
        ("resident_code", "12345678901", "8901", "1234567"),
        ("employment_insurance", "1234-567890-1", "890-1", "1234-567"),
        ("member_id", "M-000123", "0123", "M-00"),
        ("bank_account", "0001-234-5678901", "8901", "0001-234-567"),
    ],
)
def test_mask_new_types_keeps_last_four(pii_type, value, shown, hidden):
    masked = mask_value(pii_type, value)
    assert masked.endswith(shown) and hidden not in masked, masked


def test_mask_id_document_keeps_name():
    assert mask_value("id_document", "運転免許証") == "運転免許証"


def test_critical_types_include_new_number_types():
    from pii_checker.detectors import CRITICAL_TYPES, PII_TYPES

    for t in ("residence_card", "resident_code", "employment_insurance", "id_document"):
        assert t in CRITICAL_TYPES and t in PII_TYPES, t
    assert "member_id" in PII_TYPES and "member_id" not in CRITICAL_TYPES


def test_member_id_alone_is_low_risk():
    from pii_checker.engine import risk_of
    from pii_checker.models import ItemResult, Status

    item = ItemResult(path="t", kind="", status=Status.PENDING)
    item.conf_counts = {"member_id:low": 5}
    assert risk_of([item]) == "低"
    item.conf_counts = {"employment_insurance:medium": 1}
    assert risk_of([item]) == "高"


# ---------------------------------------------------------------- 紛らわしい否定例（番号の形が個人情報に似ているもの）


@pytest.mark.parametrize(
    "text",
    [
        "型番 090-1234-5678",
        "品番 080-2345-6789",
        "製品コード 070-1111-2222",
        "部品番号 03-1234-5678",
        "図面番号 DWG-2024-0012",
        "追跡番号 1234-5678-9018",
        "お問い合わせ番号 080-1234-5678",
        "伝票番号 090-8765-4321",
        "受付番号 0312345678",
        "整理番号 06-1234-5678",
        "ISBN978-4-12-345678-0",
        "ISBN 4-12-345678-9",
        "ISBN 978-4-00-000000-0 定価1,980円",
        "JAN 4901234567894",
        "JANコード 4512345678901",
        "第3会議室",
        "会議室 A-1203",
        "部屋番号 1203",
        "民法第123条第2項",
        "労働基準法 第36条 第1項第2号",
        "議案第12号",
        "第2024-15号議案",
        "Version 1.2.3",
        "v2.10.4 リリース",
        "ビルド 10.0.19045.1234",
        "2024-10-17 13:45:20",
        "令和6年10月17日 午後3時",
        "会議 10:00-11:00",
        "第2四半期 2024/07/01-2024/09/30",
        "金額 ¥1,234,567",
        "請求額 12,345,678円",
        "合計 1234567890123円",
        "簡易書留 1234-5678-9012",
        "書留番号 1234-5678-9013",
        "注文番号 2024-1017-0001",
        "注文番号 20241017000123",
        "IPアドレス 192.0.2.12",
        "MACアドレス 00:1A:2B:3C:4D:5E",
        "座標 35.681236, 139.767125",
        "シリアル 4111111111111111",
        "品番 4111-1111-1111-1111",
        "ロット番号 0901234567",
        "口座振替日 27日",
        "口座 5000000円",
        "社員番号の欄に記入してください",
        "会員番号 2024年度から変更",
        "在留カードの申請は2024年4月1日から",
        "住民票コードの記入は不要です",
        "AB12345678CD",
        "12345678901",
    ],
)
def test_confusing_numbers_are_not_high_or_medium(text):
    found = types_of(text)
    assert not {k for k, v in found.items() if v in ("high", "medium")}, found

"""個人情報らしき値の検出規則。

- 本文の文字列からは正規表現＋検査数字（マイナンバー・Luhn）＋前後の手がかり語で検出する。
- 表形式（Excel・Access・CSV・Word の表）では、列見出しから列の意味を推定し、
  その列の値も検出に数える（「氏名」列の値は、辞書に無い名前でも拾える）。
- 返す値はマスク済み。生の値は呼び出し元へ返さない。
"""

from __future__ import annotations

import functools
import logging
import re
from bisect import bisect_left, bisect_right
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .models import Confidence
from .tlds import TLDS

# 種類のキー → 表示名。レポートの列順もこの順にする。
PII_TYPES: dict[str, str] = {
    "my_number": "マイナンバー",
    "credit_card": "クレジットカード番号",
    "bank_account": "銀行口座番号",
    "drivers_license": "運転免許証番号",
    "passport": "旅券番号",
    "pension": "基礎年金番号",
    "health_insurance": "保険証の記号番号",
    "residence_card": "在留カード番号",
    "resident_code": "住民票コード",
    "employment_insurance": "雇用保険被保険者番号",
    "id_document": "本人確認書類の写し",
    "sensitive": "要配慮個人情報",
    "member_id": "会員・社員などの番号",
    "name": "氏名",
    "address": "住所",
    "postal_code": "郵便番号",
    "phone": "電話番号",
    "email": "メールアドレス",
    "birthdate": "生年月日",
    "gender": "性別",
    "age": "年齢",
    "custom": "利用者の規則",  # 利用者が足した語・正規表現（userrules）。重要な種類には入れない
}

# これらは単独で漏れると被害が大きい（リスクの重み付けに使う）
CRITICAL_TYPES = {
    "my_number",
    "credit_card",
    "bank_account",
    "drivers_license",
    "passport",
    "pension",
    "health_insurance",
    "residence_card",
    "resident_code",
    "employment_insurance",
    "id_document",
    "sensitive",
}

H = r"[\-‐‑‒–—―ー−]"  # NFKC 後に残りうるハイフンの仲間
SEP = rf"(?:\s?{H}\s?|\s|\.)?"
NOT_DIGIT_BEFORE = rf"(?<![0-9])"
NOT_DIGIT_AFTER = r"(?![0-9])"

PREFECTURES = (
    "北海道|青森県|岩手県|宮城県|秋田県|山形県|福島県|茨城県|栃木県|群馬県|埼玉県|千葉県|東京都|"
    "神奈川県|新潟県|富山県|石川県|福井県|山梨県|長野県|岐阜県|静岡県|愛知県|三重県|滋賀県|京都府|"
    "大阪府|兵庫県|奈良県|和歌山県|鳥取県|島根県|岡山県|広島県|山口県|徳島県|香川県|愛媛県|高知県|"
    "福岡県|佐賀県|長崎県|熊本県|大分県|宮崎県|鹿児島県|沖縄県"
)

# よくある姓（敬称つき・空白区切りの氏名を拾う手がかり。網羅ではない）
SURNAMES = (
    "佐藤|鈴木|高橋|田中|伊藤|渡辺|渡邊|山本|中村|小林|加藤|吉田|山田|佐々木|山口|松本|井上|木村|林|"
    "斎藤|斉藤|清水|山崎|森|池田|橋本|阿部|石川|山下|中島|石井|小川|前田|岡田|長谷川|藤田|後藤|近藤|"
    "村上|遠藤|青木|坂本|斉木|福田|太田|西村|藤井|金子|岡本|藤原|中野|三浦|原田|中川|松田|竹内|小野|"
    "田村|中山|和田|石田|森田|上田|原|柴田|酒井|工藤|横山|宮崎|宮本|内田|高木|安藤|谷口|大野|丸山|"
    "今井|河野|藤本|村田|武田|上野|杉山|増田|平野|大塚|千葉|久保|松井|小島|岩崎|桜井|野口|松尾|野村|"
    "木下|菊地|菊池|佐野|大西|杉本|新井|浜田|菅原|市川|水野|小松|島田|古川|小山|高野|西田|菊田|山内|"
    "西川|五十嵐|北村|安田|中田|川口|平田|川崎|飯田|吉川|本田|久保田|沢田|辻|関|吉村|渡部|岩田|中西|"
    "服部|樋口|福島|川上|永井|松岡|田口|山中|森本|土屋|矢野|広瀬|秋山|石原|松下|大橋|松浦|吉岡|小池|"
    "馬場|浅野|荒木|大久保|野田|小沢|田辺|川村|星野|黒田|堀|尾崎|望月|永田|熊谷|内藤|松村|西山|大谷|"
    "平井|大島|岩本|片山|本間|早川|横田|岡崎|荒井|大石|鎌田|成田|宮田|小田|石橋|篠原|須藤|河合|大川"
)

MY_NUMBER_KW = re.compile(r"(個人番号|マイナンバー|my\s?number|my\s?ナンバー|通知カード)", re.I)
CARD_KW = re.compile(r"(カード|card|クレジット|クレカ|visa|master|jcb|amex)", re.I)
PHONE_KW = re.compile(r"(電話|tel|携帯|連絡先|自宅|phone|mobile|fax)", re.I)
BIRTH_KW = re.compile(r"(生年月日|誕生日|生まれ|dob|birth)", re.I)
LICENSE_KW = re.compile(r"(免許)")

RE_MY_NUMBER = re.compile(
    rf"(?<![0-9])(?<![0-9][ \-])([0-9]{{4}}){SEP}([0-9]{{4}}){SEP}([0-9]{{4}})(?![0-9])(?![ \-][0-9])"
)
RE_CARD = re.compile(rf"{NOT_DIGIT_BEFORE}(?:[0-9][ \-]?){{12,18}}[0-9]{NOT_DIGIT_AFTER}")
RE_MOBILE = re.compile(rf"(?<![0-9{H[1:-1]}])0[5789]0{SEP}[0-9]{{4}}{SEP}[0-9]{{4}}{NOT_DIGIT_AFTER}")
RE_MOBILE_INTL = re.compile(r"\+81[\s\-]?\(?0?\)?[5789]0[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}(?![0-9])")
# 「+81-3-1234-5678」の固定電話（市外局番の頭の0を除いて9桁）。携帯（[5789]0）は RE_MOBILE_INTL で拾う
RE_LANDLINE_INTL = re.compile(
    # 区切りの無い「+81312345678」（vCard・連絡先の書き出し）も拾う。桁数（国内で9桁）は拾った後に確かめる
    # 数式・長い数字の中の「+81…」（「1e+81234567890」）は拾わない。区切りは国内の形と同じく「.」も許す
    r"(?<![0-9A-Za-z])\+81[\s\-.]?\(?0?\)?(?![5789]0)\(?[1-9][0-9]{0,3}\)?[\s\-.]?[0-9]{1,4}[\s\-.]?[0-9]{4}(?![0-9])"
)
HC = H[1:-1]  # 文字クラスの中身だけ
LAND_SEP = rf"(?:\s?{H}\s?|\.)"
RE_LANDLINE = re.compile(
    rf"(?<![0-9{HC}])(?:\(0[0-9]{{1,4}}\)\s?[0-9]{{1,4}}{LAND_SEP}"
    rf"|0[1-9][0-9]{{0,3}}(?:{LAND_SEP}|\s?\(\s?)[0-9]{{1,4}}(?:{LAND_SEP}|\s?\)\s?))"
    rf"[0-9]{{4}}(?![0-9{HC}])"
)
# 個人に結びつかない番号（フリーダイヤル・ナビダイヤル・ダイヤル Q2）。電話のどの書き方でも同じに外す
NON_PERSONAL_PHONE_PREFIXES = ("0120", "0800", "0570", "0990")
RE_LANDLINE_SPACE = re.compile(r"(?<![0-9])0[1-9][0-9]{0,3} [0-9]{1,4} [0-9]{4}(?![0-9])")
COMPANY_KW = re.compile(
    # FAX は個人の連絡先にも並ぶ（「山田太郎 TEL … FAX …」）ので会社の語にしない。施設の一覧の電話は、人の手がかりが
    # 無ければ 低 に落ちる（_classify_addresses の needs_person）
    r"(代表|本社|株式会社|有限会社|合同会社|\(株\)|\(有\)|支店|営業所|事業所|受付時間|"
    # 英文のレターヘッド・署名（「ABC Co., Ltd. Head Office +81-3-…」）
    # 語の途中（「zinc.」）に当たらないよう、英語の語は語の頭から
    r"\bco\.,?\s?ltd|\binc\.|\bcorporation|\bhead\s?office|\bheadquarters)",
    re.I,
)
# 横持ちの表の項目名（名前ではない語）。「UENO」「春日」のような実在の名前を落とさないよう、
# 完全一致か「2文字以上＋日」の形に限る
RE_LABEL_WORD = re.compile(
    r"^(?:.{0,6}(?:日付|年月日|番号|区分|コード|備考|所属|部署|部門|役職|時刻|金額|数量|単価|合計|状態|種別|分類|メモ|内容|件名|期限|会社名?|社名|項目)"
    r"|[一-龥]{2,3}日|ID|No\.?|NO|日)$"
)
RE_ANNOTATION = re.compile(r"[（(【\[〔<＜][^）)】\]〕>＞]{0,20}[）)】\]〕>＞]")
PERSONAL_PHONE_KW = re.compile(r"(自宅|携帯|個人|緊急連絡|本人|実家)")
ORDER_KW = re.compile(
    r"(注文|受注|発注|伝票|管理番号|品番|型番|製造番号|シリアル|serial|order|商品コード|jan|s/?n\b)", re.I
)
# 製品の番号の語（値の左にあれば、電話・カード番号の形をしていても製品の番号とみなして確度 低）。
# 整理番号・受付番号・伝票番号・お問い合わせ番号・追跡番号は入れない（名簿・受付票の「整理番号1 山田太郎 090-…」の
# ように、番号の列の右に人の電話が並ぶ書き方が多く、下げると個人の電話を見落とすため）
MODEL_KW = re.compile(
    r"(型番|品番|製品コード|商品コード|部品番号|図面番号|(?<![a-z])isbn(?![a-z])|(?<![a-z])jan(?![a-z]))",
    re.I,
)
# 語が無ければ拾わない番号（クレジットカードの Luhn が合わないものを、打ち間違いとして 低 で残すときの語）
CARD_NUMBER_KW = re.compile(r"(カード番号|クレジット|クレカ|card\s?no|card\s?number)", re.I)
MONEY_AFTER = re.compile(r"^\s*(円|,|万|千|百|ドル|\.[0-9])")
MONEY_BEFORE = re.compile(r"(残高|金額|額|振替|手数料|入金|出金|支払|請求)")
RE_PHONE_BARE = re.compile(rf"{NOT_DIGIT_BEFORE}0[1-9][0-9]{{8,9}}{NOT_DIGIT_AFTER}")
RE_EMAIL = re.compile(
    r"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63})*\.[A-Za-z]{2,24}(?![A-Za-z])"
)
RE_POSTAL_MARK = re.compile(rf"〒\s?[0-9]{{3}}{H}?[0-9]{{4}}{NOT_DIGIT_AFTER}")
RE_POSTAL_BEFORE_PREF = re.compile(
    rf"(?<![0-9{H[1:-1]}])[0-9]{{3}}{H}[0-9]{{4}}(?![0-9{H[1:-1]}])(?=\s{{0,3}}(?:{PREFECTURES}))"
)
NUM = r"(?:[0-9]+|[一二三四五六七八九十〇]+)"
ADDR_TAIL = rf"{NUM}(?:丁目|番地|番|号|{H}[0-9]+)"
RE_ADDRESS = re.compile(
    # 市区町村の後の空白1つも許す（「東京都千代田区 丸の内1-1-1」と書く人がいる）。ただし空白の後が町名の文字で
    # 始まるときだけ（「東京都港区 03-1234-5678」「横浜市 10-15名」の数字を番地と取り違えない）。漢数字は外さない
    # （六本木・三田・九段・五反田など、漢数字で始まる町名が多い）。英字・「第」で始まるもの（「港区 Room3-1」
    # 「港区 第3会議室1番」）は部屋の名前で町名ではないので続けない
    rf"(?:{PREFECTURES})\s?[^\s、。,，「」()（）]{{1,20}}?[市区町村郡](?:\s(?=(?!第)[一-龥々ぁ-んァ-ヶー]))?"
    rf"[^\s、。,，「」()（）]{{0,25}}?{ADDR_TAIL}(?:{H}?[0-9]+)*"
)
RE_ADDRESS_NO_PREF = re.compile(
    rf"(?<![一-龥])[一-龥]{{1,5}}[市区][一-龥ぁ-んァ-ヶー]{{1,10}}(?:[0-9]+{H}[0-9]+(?:{H}[0-9]+)?|{NUM}丁目(?:{NUM}番地?)?(?:{NUM}号)?[0-9\-]*|{NUM}番地)"
)
DATE_WEST = r"(?:19|20)[0-9]{2}\s?[年/.\-]\s?[0-9]{1,2}\s?[月/.\-]\s?[0-9]{1,2}日?"
DATE_ERA = (
    r"(?:明治|大正|昭和|平成|令和|[MTSHR])\s?(?:[0-9]{1,2}|元)\s?[年.\-/]\s?[0-9]{1,2}\s?[月.\-/]\s?[0-9]{1,2}日?"
)
RE_DATE = re.compile(rf"(?:{DATE_WEST}|{DATE_ERA})")
RE_DATE_ERA = re.compile(DATE_ERA)
RE_BANK = re.compile(
    r"(?:口座番号|口座no\.?|口座|普通預金|当座預金|普通|当座)[^0-9\n]{0,12}?([0-9]{7})(?![0-9])",
    re.I,
)
# 「運転免許 123…」（証・番号を付けない書き方）も免許証番号として拾う。免許の語があるとマイナンバーからは外すので、
# ここで拾わないとどちらにも数えられずに落ちていた（不具合の修正）
RE_LICENSE = re.compile(r"(?:免許証番号|免許番号|免許証|運転免許)[^0-9\n]{0,12}?([0-9]{12})(?![0-9])")
RE_PASSPORT = re.compile(
    r"(?:旅券番号|旅券|パスポート番号|パスポート|passport\s?no\.?)[^A-Za-z0-9\n]{0,12}?([A-Z]{2}[0-9]{7})(?![0-9])",
    re.I,
)
RE_PENSION = re.compile(rf"(?:基礎年金番号|年金番号)[^0-9\n]{{0,12}}?([0-9]{{4}}{H}?[0-9]{{6}})(?![0-9])")
RE_INSURANCE = re.compile(
    r"(?:被保険者番号|保険者番号|記号番号|保険証番号)[^0-9A-Za-z\n]{0,8}?([0-9A-Za-z][0-9A-Za-z\-]{3,19})"
)
# 在留カード番号（英字2＋数字8＋英字2）。語の無いものは型番などと区別できないので拾わない
RE_RESIDENCE_CARD = re.compile(
    r"(?:在留カード番号|在留カード)[^A-Za-z0-9\n]{0,12}?([A-Z]{2}[0-9]{8}[A-Z]{2})(?![A-Za-z0-9])"
)
# 住民票コード（11桁）。検査数字の算式を公的な資料で確かめられていないので、桁数と語だけで判定する
RE_RESIDENT_CODE = re.compile(r"住民票コード[^0-9\n]{0,12}?([0-9]{11})(?![0-9])")
# 雇用保険被保険者番号（4桁-6桁-1桁、区切りの無い11桁も）
EMPLOYMENT_KW = re.compile(r"雇用保険\s?(?:の\s?)?(?:被保険者\s?)?番号")
RE_EMPLOYMENT = re.compile(
    rf"{EMPLOYMENT_KW.pattern}[^0-9\n]{{0,12}}?([0-9]{{4}}{H}[0-9]{{6}}{H}[0-9]|[0-9]{{11}})(?![0-9])"
)
# 会員・社員などの番号。それだけでは人を特定しにくいので確度 低（要確認）どまり
MEMBER_ID_WORDS = r"社員番号|職員番号|従業員番号|会員番号|顧客番号|お客様番号|学籍番号|患者番号|診察券番号"
RE_MEMBER_ID = re.compile(
    # 後ろに「年」「件」などの単位が続く数（「会員番号 2024年度から」「会員番号 1200件」）は番号ではない
    rf"(?:{MEMBER_ID_WORDS})[\s:：]{{0,3}}((?=[0-9A-Za-z\-]*[0-9])[0-9A-Za-z][0-9A-Za-z\-]{{3,19}})"
    r"(?![0-9A-Za-z\-]|\s?[年月日円件名人個回桁台])"
)
# 口座の「金融機関コード-支店番号-口座番号」（4桁-3桁-7桁）の書き方
RE_BANK_FULL = re.compile(
    rf"(?:口座番号|口座no\.?|口座|普通預金|当座預金|普通|当座|振込先)[^0-9\n]{{0,12}}?"
    rf"([0-9]{{4}}{H}[0-9]{{3}}{H}[0-9]{{7}})(?![0-9])",
    re.I,
)
NAME_CHARS = r"[一-龥々ぁ-んァ-ヶー]"
RE_NAME_LABEL = re.compile(
    rf"(?:氏名|お名前|名前|患者名|顧客名|利用者名|契約者名|申込者名|保護者名|受取人|宛名|宛先|担当者?|ふりがな|フリガナ)"
    rf"(?:\s*[:：]\s*|[ 　]+)({NAME_CHARS}{{2,8}}(?:[ 　]{NAME_CHARS}{{1,8}})?)"
)
RE_NAME_LABEL_TIGHT = re.compile(
    rf"(?:^|(?<=[\s　:：、,|]))(?:氏名|お名前|名前|患者名|顧客名|契約者名)((?:{SURNAMES})[ 　]?[一-龥々]{{1,3}})(?![一-龥々])"
)
RE_NAME_HONORIFIC = re.compile(rf"(?<![一-龥])(?:{SURNAMES})[ 　]?[一-龥々]{{0,3}}(?:様|殿|さん|君|くん|ちゃん)")
HONORIFIC_STOP = re.compile(
    r"(お客|皆|各位|関係者|担当者|会員|利用者|取引先|貴|御|責任者|代表者|社長|部長|課長|先生|保護者|ご家族|応募者|参加者|受講者|入居者|契約者)$"
)
RE_NAME_HONORIFIC_ANY = re.compile(r"(?<![一-龥々])([一-龥々]{3,5})(?:様|殿)(?![方])")
RE_NAME_SPACED = re.compile(rf"(?<![一-龥])(?:{SURNAMES})[ 　][一-龥々]{{1,3}}(?![一-龥々])")

# 上の RE_NAME_HONORIFIC・RE_NAME_SPACED は先頭が後読みなので、正規表現エンジンが「最初の1文字の候補」で
# 先へ飛ばす最適化を使えず、全部の位置で 190 通りの姓を順に試す（検出時間の3〜5割を占めていた）。
# 後読みを外した本体（姓の選択肢が先頭）で探し、直前が漢字かどうかは Python 側で確かめる。当たる範囲は元の式と同じ。
# （元の式は仕様の基準として残してあり、tests/test_detect_speedup.py が両者の一致を確かめる）
_RE_NAME_HONORIFIC_BODY = re.compile(rf"(?:{SURNAMES})[ 　]?[一-龥々]{{0,3}}(?:様|殿|さん|君|くん|ちゃん)")
_RE_NAME_SPACED_BODY = re.compile(rf"(?:{SURNAMES})[ 　][一-龥々]{{1,3}}(?![一-龥々])")
_HONORIFIC_WORD = re.compile(r"様|殿|さん|君|くん|ちゃん")


def _finditer_not_after_kanji(body: re.Pattern[str], text: str):
    """body が当たる位置のうち、直前の1文字が漢字（一〜龥）でないものを、重ならないよう左から順に返す。

    `(?<![一-龥])` + body を finditer した結果と同じになる（後読みで外れた位置は1文字進めて探し直す）。
    """
    search = body.search
    pos = 0
    while True:
        m = search(text, pos)
        if m is None:
            return
        s = m.start()
        if s > 0 and "一" <= text[s - 1] <= "龥":
            pos = s + 1
            continue
        yield m
        pos = m.end()


def iter_name_honorific(text: str):
    """RE_NAME_HONORIFIC.finditer(text) と同じ結果を、速く返す。敬称の語が無ければ当たりようが無いので走らせない。"""
    if not _HONORIFIC_WORD.search(text):
        return iter(())
    return _finditer_not_after_kanji(_RE_NAME_HONORIFIC_BODY, text)


def iter_name_spaced(text: str):
    """RE_NAME_SPACED.finditer(text) と同じ結果を、速く返す。空白（半角・全角）が無ければ当たりようが無いので走らせない。"""
    if " " not in text and "　" not in text:
        return iter(())
    return _finditer_not_after_kanji(_RE_NAME_SPACED_BODY, text)


RE_SENSITIVE = re.compile(
    r"(?:病名|病歴|既往歴|診断名|傷病名|障害等級|障害者手帳|犯罪歴|前科|信仰|宗教|信条|本籍)\s*[:：]\s*([^\s、。,]{1,30})"
)
ROLE_EMAIL = re.compile(
    r"^(info|support|noreply|no-reply|admin|sales|contact|webmaster|postmaster|help|service)@",
    re.I,
)

# 列見出し → 種類。完全一致（短い語）と部分一致（長い語）に分ける。
HEADER_EXACT = {
    "姓": "name",
    "名": "name",
    "氏": "name",
    "氏名": "name",
    "名前": "name",
    "お名前": "name",
    "name": "name",
    "fullname": "name",
    "firstname": "name",
    "lastname": "name",
    "surname": "name",
    "カナ": "name",
    "かな": "name",
    "セイ": "name",
    "メイ": "name",
    "age": "age",
    "年齢": "age",
    "性別": "gender",
    "gender": "gender",
    "sex": "gender",
    "〒": "postal_code",
    "zip": "postal_code",
    "tel": "phone",
    "fax": "phone",
    "mail": "email",
    "email": "email",
    "e-mail": "email",
    "住所": "address",
    "担当者": "name",
    "担当": "name",
    "宛先": "name",
    "宛名": "name",
    "受取人": "name",
    "address": "address",
    "addr": "address",
}
HEADER_CONTAINS: list[tuple[re.Pattern[str], str]] = [
    # 「在留カード番号」はカード番号の語を、「雇用保険被保険者番号」は保険証の語（被保険者番号）を含むので先に見る。
    # 「雇用保険料」の列は番号ではない
    (re.compile(r"(在留カード番号|在留カードno)", re.I), "residence_card"),
    (re.compile(r"(雇用保険.{0,6}番号)"), "employment_insurance"),
    (re.compile(r"(住民票コード)"), "resident_code"),
    (re.compile(r"(マイナンバー|個人番号|mynumber|individualnumber)", re.I), "my_number"),
    (re.compile(r"(カード番号|クレジット|cardno|cardnumber|creditcard|ccnumber)", re.I), "credit_card"),
    (re.compile(r"(口座番号|口座no|口座)", re.I), "bank_account"),
    (re.compile(r"(免許証番号|免許番号|免許証|drivers?'?s?license)", re.I), "drivers_license"),
    (re.compile(r"(旅券|パスポート|passport)", re.I), "passport"),
    (re.compile(r"(年金番号)"), "pension"),
    (re.compile(r"(被保険者番号|保険者番号|保険証|記号番号)"), "health_insurance"),
    (re.compile(rf"({MEMBER_ID_WORDS})"), "member_id"),
    (
        re.compile(r"(病名|病歴|既往歴|診断|傷病|障害|犯罪|前科|宗教|信条|本籍|信仰)"),
        "sensitive",
    ),
    (re.compile(r"(生年月日|誕生日|birthday|birthdate|dateofbirth|dob)", re.I), "birthdate"),
    (re.compile(r"(郵便番号|postal|zipcode|postcode)", re.I), "postal_code"),
    (re.compile(r"(メール|mail)", re.I), "email"),
    (re.compile(r"(住所|番地|address|居所)", re.I), "address"),
    (re.compile(r"(電話|携帯|連絡先|phone|mobile|tel)", re.I), "phone"),
    (re.compile(r"(メール|mail)", re.I), "email"),
    # 英語の見出し（姓・名・ふりがな）。「name」だけの語は値の列（「file name」など）にも多いので完全一致の表で見る
    (
        re.compile(r"(氏名|名前|フリガナ|ふりがな|ﾌﾘｶﾞﾅ|カナ氏名|姓名|surname|givenname|familyname|furigana)", re.I),
        "name",
    ),
    # 顧客表・申込の控えでよく見る、人を指す見出し（2026-10-18 評価で、これらの列が氏名にならず住所・電話が 低 に落ちた）
    (
        re.compile(
            r"(お客様名|お客様氏名|契約者|申込者|送り主|依頼主|届け?先名|加入者|customername|clientname|ご?芳名)"
        ),
        "name",
    ),
    (
        re.compile(
            r"(顧客|会員|患者|社員|従業員|職員|生徒|学生|児童|園児|利用者|申込者|契約者|担当者|"
            r"保護者|入居者|受講者|参加者|応募者|受取人|被保険者|世帯主|代表者|本人|家族)(名|氏名|の名前)"
        ),
        "name",
    ),
    (re.compile(r"(性別)"), "gender"),
    (re.compile(r"(年齢)"), "age"),
]
# 「〜名」でも個人名でないもの（誤検出を防ぐ）
HEADER_NOT_PII = re.compile(
    r"((mac|ip|url|web)\s*(address|アドレス)|本社|所在地|会社名|社名|法人名|団体名|商品名|品名|製品名|店舗名|店名|部署名|部門名|課名|ファイル名|シート名|"
    r"項目名|件名|地名|駅名|施設名|学校名|銀行名|支店名|機種名|型名|品目|メールサーバ|作成者|更新者)"
)


@dataclass
class Hit:
    """検出1件（内部用。値は生のまま。外へ出す前に mask する）。"""

    pii_type: str
    confidence: Confidence
    value: str
    start: int
    end: int
    rule: str
    # 住所だけ: 人と結びつく手がかり（同じファイルの氏名など）があって初めて確度 中にするもの。
    # 集める側（engine.Collector）が、手がかりが無ければ 低 にする
    needs_person: bool = False


# 住所を「個人の住所」とみなす手がかりの語（近くにあれば、人の手がかりを待たずに確度 中）
PERSONAL_ADDRESS_KW = re.compile(
    # 「勤務先 〇〇高校 …」は施設の所在地でも、その人の勤め先として人と結びつく
    r"(自宅|現住所|本人|実家|居所|住民票|本籍|転居|引越|引っ越し|お届け先|届け先|送付先|配送先|送り先|宛先|宛名|緊急連絡|勤務先)"
)
# 公共施設・会社などの所在地を示す語（住所の前にあれば確度 低。公共施設の所在地や市区町村の番地の一覧を
# 「個人情報の可能性あり」にしないため。拾わないと言い切りに反するので、消さずに 低＝要確認にする）
FACILITY_KW = re.compile(
    r"(所在地|市役所|区役所|町役場|村役場|役場|役所|庁舎|出張所|支所|図書館|図書室|公民館|体育館|美術館|博物館|資料館|"
    # 「大学生」「高校生」「専門学校生」のように人を指す言い方は除く
    r"会館|ホール|センター|プラザ|小学校(?!生)|中学校(?!生)|高等学校(?!生)|高校(?!生)|大学(?!生|院生)|学校(?!生)|"
    r"幼稚園|保育園|保育所|こども園|病院|医院|"
    # 「駅」は「駅前」「最寄駅」を除く（個人の住所の欄の前によく出る）
    r"クリニック|診療所|薬局|郵便局|警察署|交番|消防署|(?<!最寄)(?<!最寄り)駅(?!前|から|まで|徒歩)|公園|ホテル|会場|施設|株式会社|有限会社|合同会社|\(株\)|"
    r"本社|支店|営業所|事業所|工場|店舗)"
)
# 人と結びつける手がかりになる種類（同じファイルにあれば住所を確度 中にする）。電話・メール・郵便番号は施設の一覧にも
# 普通に載るので手がかりにしない
PERSON_CUE_TYPES = frozenset({"name", "birthdate"}) | frozenset(CRITICAL_TYPES)
# 人の情報を集めた書類の題（ファイル名か本文の先頭にあれば、そのファイルの住所・固定電話を人と結びつける）。
# 見出し語の無い名前（「山田 太郎」）しか無い連絡網・履歴書で、住所・電話が 低 に落ちないようにする
PERSON_DOC_TITLE = re.compile(
    r"(履歴書|職務経歴書|名簿|連絡網|緊急連絡|申込書|申込み書|申し込み書|住所録|顧客|会員|社員|職員|従業員|生徒|児童|園児|"
    r"患者|入居者|利用者|受講者|参加者|応募者|宛名|年賀状|カルテ|身上書)"
)


RE_MOBILE_PREFIX = re.compile(r"^(?:\+81[\s\-]?\(?0?\)?)?0?[5789]0")


def _classify_addresses(hits: list[Hit], context_text: str, offset: int) -> None:
    """確度 中の住所を、近くの語で「個人の住所（中のまま）」「施設の所在地（低）」「人の手がかり待ち」に分ける。

    確度 中の固定電話も「人の手がかり待ち」にする（施設の一覧の電話の列を「可能性あり」にしない・2026-10-18 評価）。
    携帯と、近くに「自宅」「緊急連絡」などがある番号は待たない。
    """
    for h in hits:
        if h.confidence != Confidence.MEDIUM:
            continue
        if h.pii_type == "phone":
            s, e = h.start + offset, h.end + offset
            near = context_text[max(0, s - 12) : s] + " " + context_text[e : e + 6]
            if not RE_MOBILE_PREFIX.match(h.value.strip()) and not PERSONAL_PHONE_KW.search(near):
                h.needs_person = True
            continue
        if h.pii_type != "address":
            continue
        s, e = h.start + offset, h.end + offset
        # 前の30文字。ただし前の行・前のセル（改行・タブ・カンマ・| の前）は見ない（前の行の建物名で施設扱いにしない）
        before = re.split(r"[\n\t,|]", context_text[max(0, s - 30) : s])[-1]
        after = re.split(r"[\n\t,|]", context_text[e : e + 12])[0]
        if h.start == 0 and h.end == len(h.value) and h.rule.startswith("列見出し"):
            # 「住所」列の値は丸ごと1件なので、値の中で住所の形より前（「港区役所 東京都港区…」の施設名）も前の語として見る。
            # 都道府県の位置で切らないのは、「大阪府立病院 大阪府…」のように施設名が都道府県で始まることがあるため
            addr = RE_ADDRESS.search(h.value)
            if addr:
                before += " " + h.value[: addr.start()]
        personal = PERSONAL_ADDRESS_KW.search(before + " " + after)
        if personal:
            h.rule += f"（近くに「{personal.group(0)}」の語）"
            continue
        facility = None
        for m in FACILITY_KW.finditer(before):
            facility = m
        # 「住所」の語が施設の語より住所に近ければ、施設の名前の後に個人の住所の欄が続く形（「〇〇病院 患者 住所 …」）
        if facility and "住所" not in before[facility.end() :]:
            h.confidence = Confidence.LOW
            h.rule += f"（前に「{facility.group(0)}」があり、施設・会社の所在地とみなした）"
        else:
            h.needs_person = True


# 全角英数・全角記号（U+FF01〜FF5E）と全角空白 → 互換分解した先の ASCII。
# 長い本文に「：」が1つあるだけで NFKC は本文全体を分解・合成し直す（280 文字で約 20µs）ので、
# よく来るこれらの文字だけ先に写してから NFKC に回す。文字をその互換分解に置き換えても NFKC の結果は変わらない
# （NFKC は互換分解してから合成するので、分解済みの形から始めても同じところに行き着く。試験が総当たりで確かめる）
_PREMAP = {chr(c): unicodedata.normalize("NFKD", chr(c)) for c in [*range(0xFF01, 0xFF5F), 0x3000]}
_RE_PREMAP = re.compile("[！-～　]")


def _premap(m: re.Match) -> str:
    return _PREMAP[m.group()]


def normalize(text: str) -> str:
    """全角英数・全角記号を半角へ寄せる（NFKC）。"""
    if unicodedata.is_normalized("NFKC", text):
        return text
    return unicodedata.normalize("NFKC", _RE_PREMAP.sub(_premap, text))


def my_number_is_valid(digits: str) -> bool:
    """マイナンバー（個人番号）12桁の検査数字を確かめる。"""
    if len(digits) != 12 or not digits.isdigit():
        return False
    if len(set(digits)) == 1:
        return False
    body = digits[:11]
    total = 0
    for n in range(1, 12):
        p = int(body[11 - n])
        q = n + 1 if n <= 6 else n - 5
        total += p * q
    remainder = total % 11
    check = 0 if remainder <= 1 else 11 - remainder
    return check == int(digits[11])


def luhn_is_valid(digits: str) -> bool:
    """クレジットカード番号の Luhn 検査。"""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def card_prefix_is_plausible(digits: str) -> bool:
    """国際ブランドの番号体系（IIN）に合うか。"""
    n = len(digits)
    if digits[0] == "4" and n in (16, 19):
        return True  # VISA
    if n == 16 and (51 <= int(digits[:2]) <= 55 or 2221 <= int(digits[:4]) <= 2720):
        return True  # Mastercard
    if n == 15 and digits[:2] in ("34", "37"):
        return True  # AMEX
    if n in (16, 17, 18, 19) and 3528 <= int(digits[:4]) <= 3589:
        return True  # JCB
    if n == 14 and (digits[:2] in ("36", "38") or 300 <= int(digits[:3]) <= 305):
        return True  # Diners
    if n == 16 and (digits[:4] == "6011" or digits[:2] == "65"):
        return True  # Discover
    return False


def _context_find(text: str, start: int, end: int, pattern: re.Pattern[str], width: int = 20) -> str | None:
    """検出箇所の前（width 文字）と後ろ（6文字）で pattern に当たった語。無ければ None。"""
    m = pattern.search(text[max(0, start - width) : start]) or pattern.search(text[end : end + 6])
    return m.group(0) if m else None


def _context_has(text: str, start: int, end: int, pattern: re.Pattern[str], width: int = 20) -> bool:
    return _context_find(text, start, end, pattern, width) is not None


def _model_word_before(context_text: str, start: int, width: int = 20) -> str | None:
    """値の左（width 文字）にある型番・伝票番号などの語。無いか、その語と値のあいだに電話の語があれば None。

    「型番 X-100 TEL 090-…」のように、電話の語が値のすぐ左にあるなら電話の語を優先する。
    """
    left = context_text[max(0, start - width) : start]
    last = None
    for m in MODEL_KW.finditer(left):
        last = m
    if last is None or PHONE_KW.search(left[last.end() :]):
        return None
    return last.group(0)


def _phone_unless_model(m: re.Match, rule: str, model_word: Callable[[int], str | None], category: str | None) -> Hit:
    """電話の語つきの番号を 中 で返す。ただし値の左に型番などの語があれば 低 にする（列見出しが電話なら下げない）。"""
    model = model_word(m.start()) if category != "phone" else None
    if model:
        return Hit(
            "phone",
            Confidence.LOW,
            m.group(0),
            m.start(),
            m.end(),
            rule + f"（前に「{model}」の語があり、型番などの番号とみなした）",
        )
    return Hit("phone", Confidence.MEDIUM, m.group(0), m.start(), m.end(), rule)


def _landline_context(context_text: str, start: int, end: int) -> tuple[str | None, str | None]:
    """固定電話の近くの (会社の語, 個人の語)。会社の語があり個人の語が無ければ、会社の代表番号とみなす。"""
    return (
        _context_find(context_text, start, end, COMPANY_KW, width=30),
        _context_find(context_text, start, end, PERSONAL_PHONE_KW, width=12),
    )


RE_ASCII_ALPHA = re.compile(r"[A-Za-z]")


def _scoped(p: re.Pattern[str]) -> str:
    """パターンを、そのフラグを内側だけに効かせた (?i:…) / (?:…) の形にする。HEADER_CONTAINS のフラグは re.I の有無だけ
    （ほかのフラグを足すときはここも直すこと）。"""
    flag = "i" if p.flags & re.I else ""
    return f"(?{flag}:{p.pattern})"


# HEADER_CONTAINS のどれかに当たるかを1回で見る下見（当たらない文字列を25本の正規表現に通さない）
_HEADER_ANY = re.compile("|".join(_scoped(p) for p, _ in HEADER_CONTAINS))


def cannot_be_header(text: str) -> bool:
    """英字を含まない ASCII だけの文字列（数・日付・記号）か。見出し語はどれも英字・かな・漢字・〒を含むので、
    これに当たる文字列は見出しではない。表の値の大半（番号・日付）を、覚え込みの表を汚さずに素早く弾くために使う。"""
    return text.isascii() and RE_ASCII_ALPHA.search(text) is None


@functools.lru_cache(maxsize=65536)
def header_category(header: str | None) -> str | None:
    """列見出しから、その列が何の個人情報かを推定する。当てはまらなければ None。

    同じ見出しがセルごとに来るので覚えておく。表の値（番号・日付）を渡す側は、先に cannot_be_header で弾くこと
    （覚え込みの表を値で押し流さないため）。
    """
    if not header:
        return None
    h = normalize(str(header)).strip()
    if not h or len(h) > 40:
        return None
    # 「姓（漢字）」「〒（7桁）」の括弧書きは丸ごと除いてから照合する（中身が残ると「姓漢字」になり当たらない）
    core = RE_ANNOTATION.sub("", h).strip()
    if core:
        h = core
    key = re.sub(r"[\s_\-・()（）\[\]【】:：]", "", h).lower()
    if key in HEADER_EXACT:
        return HEADER_EXACT[key]
    if not _HEADER_ANY.search(key):
        return None
    if HEADER_NOT_PII.search(h.lower()):
        return None
    for pattern, category in HEADER_CONTAINS:
        if pattern.search(key):
            return category
    return None


@functools.lru_cache(maxsize=4096)
def _header_prefix(header: str | None) -> str:
    """本文の前に置く見出し（正規化して空白を1つ足す）。同じ見出しがセルごとに来るので覚えておく。"""
    return (normalize(header) + " ") if header else ""


# _header_value_hit で値ごとに使う正規表現（文字列のまま渡すと、呼ぶたびに re のキャッシュを引くので先に作る）
_RE_NON_DIGIT = re.compile(r"[^0-9]")
_RE_NON_ALNUM = re.compile(r"[^0-9A-Za-z]")
_RE_WORD_CHAR = re.compile(r"[A-Za-z一-龥ぁ-んァ-ヶ]")
_RE_YYYYMMDD = re.compile(r"(19|20)[0-9]{6}")
_RE_ISO_DATE_HEAD = re.compile(r"^\d{4}-\d{2}-\d{2}")
_RE_DATE_SERIAL = re.compile(r"[0-9]{4,5}(\.0+)?")
_RE_PLAIN_NUMBER = re.compile(r"[0-9]{1,9}(\.[0-9]+)?")
_RE_AT_WORD = re.compile(r"[\[(（]\s*at\s*[\])）]|\sat\s|アットマーク", re.I)
# プログラムの識別子・コードの断片（見出しが住所・氏名の列に入っていても、人の住所・名前ではない）。ASCII の値だけに使う。
# 人の名前・地名も空白なしにつなぐと識別子の形になる（MacDonaldSmith・Taro_Yamada・Bldg(3F)・Oak St.; Apt 4）ので、
# 形だけでは外さず、次の2つに限る:
# (1) 空白の無い語を、こぶ（小文字の後の大文字）か「_」で語に割ったとき、2つ目より後ろにプログラムでよく使う語がある
#     （AddressBookType の Type・ContactAddressIndex の Index・user_name の name）。人の名前・地名にこの語はまず続かない
# (2) 文の記号: 「=」・「{」「}」・「::」・「->」・小文字で始まる識別子のメソッドの呼び出し（cookie_pair.split( の形）・
#     引数の無い呼び出し（getName()）。「;」・括弧の注記・引用符で始まる値・a.b.c の形だけでは外さない
_RE_IDENT_TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z0-9]+)+|[A-Za-z][a-z0-9]*(?:[A-Z][a-z0-9]*)+")
_RE_IDENT_PART = re.compile(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])")
_CODE_WORDS = frozenset(
    "type types index idx id ids name names address addr properties property props flag flags info data list map set "
    # 姓にもある語（Key・Field・Book・Count など）は入れない（Anna_Field・JohnKey を落とさないため）
    "get value values kind mode status format class enum keys code str num obj ptr ref "
    "handler callback config options param params attr attrs item items node table row col column entry".split()
)
# 呼び出しは小文字で始まる識別子に限る（Apt.3B(2F)・Bldg.A(3F)・Mr.Smith(Jr)・Smith() は住所・名前の書き方）
_RE_CODE_MARK = re.compile(r"[={}]|::|->|[a-z_]\w*\.[a-z_]\w*\(|(?<![\w.])[a-z_]\w*\(\s*\)")


def _looks_like_code(v: str) -> bool:
    """ASCII の値が、プログラムの識別子（コードの語を含む）か文の断片か。"""
    if _RE_CODE_MARK.search(v):
        return True
    v = v.strip("'\"[](),")  # コードを表として読んだセルの 'DisplayName', の引用符・括弧・カンマ
    if not _RE_IDENT_TOKEN.fullmatch(v):
        return False
    parts = [p.lower() for p in _RE_IDENT_PART.findall(v)]
    return len(parts) >= 2 and any(p in _CODE_WORDS for p in parts[1:])


# 英語の見出しに使う語。英字だけの値は、語がすべてこの中にあるときだけ見出し語そのもの（項目名）とみなす。
# 見出しの判定は語の一部でも当たる（usermail・homephone を拾うため）ので、値の「Patel」「Ismail」「Dobson」が
# tel・mail・dob を含むだけで項目名になり、氏名の列から落ちていた（2026-11-07）
_EN_HEADER_WORDS = frozenset(
    "name names full first last given family middle sur surname kana furigana kanji roman "
    "address addr line street city zip code postal postcode zipcode home work office mailing current permanent "
    "phone tel telephone mobile cell fax no number num contact emergency primary secondary "
    "email mail e date of birth birthday birthdate dob gender sex age "
    "card credit cc my individual passport driver drivers s license licence customer client user person".split()
)
_RE_EN_WORD = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])")


def _is_header_word_value(v: str) -> bool:
    """表の値が「住所」「電話」「Date of Birth」などの見出し語そのもの（横持ちの表の項目名）か。"""
    if cannot_be_header(v) or header_category(v) is None:
        return False
    if not v.isascii():
        return len(v) <= 12
    words = [w.lower() for w in _RE_EN_WORD.findall(v)]
    return bool(words) and all(w in _EN_HEADER_WORDS for w in words)


def _header_value_hit(category: str, value: str) -> Hit | None:
    """見出しが個人情報の列の値を、検出として扱うかを決める。"""
    v = value.strip()
    if not v or len(v) > 300:
        return None
    if v.lower() in ("null", "none", "nan", "-", "ー", "なし", "無し", "n/a", "na", "0"):
        return None
    if _is_header_word_value(v):
        return None  # 「住所」「電話」などの見出し語そのもの（横持ちの表の項目名）は値ではない
    if category in ("address", "name") and v.isascii() and _looks_like_code(v):
        return None  # コードを表として読んだときの識別子・文の断片は、住所・名前ではない
    conf = Confidence.MEDIUM
    digits = _RE_NON_DIGIT.sub("", v)
    if category == "name":
        # 数字だけ・記号だけの値は名前ではない
        if not _RE_WORD_CHAR.search(v):
            return None
        # 横持ちの表の項目名（入社日・所属・備考など）は名前ではない
        if len(v) <= 8 and RE_LABEL_WORD.fullmatch(v):
            return None
    elif category == "my_number":
        if my_number_is_valid(digits):
            conf = Confidence.HIGH
        elif len(digits) < 8:
            return None
    elif category == "birthdate":
        if RE_DATE.search(v) or _RE_YYYYMMDD.fullmatch(digits) or _RE_ISO_DATE_HEAD.match(v):
            conf = Confidence.HIGH
        elif _RE_DATE_SERIAL.fullmatch(v) and 1000 < float(v) < 60000:
            conf = Confidence.HIGH  # Excel の日付シリアル値（xlsb・書式の無いセル）
        else:
            return None
    elif category in ("phone", "postal_code", "bank_account", "credit_card", "pension"):
        if len(digits) < 5:
            return None
        if category == "postal_code" and len(digits) not in (6, 7):
            return None  # 6桁は数値として先頭の0が落ちたもの
        if category == "credit_card" and luhn_is_valid(digits):
            conf = Confidence.HIGH
        if category == "bank_account":
            conf = Confidence.HIGH
    elif category in ("drivers_license", "passport", "health_insurance"):
        if len(_RE_NON_ALNUM.sub("", v)) < 4:
            return None
        conf = Confidence.HIGH if category != "health_insurance" else Confidence.MEDIUM
    elif category == "residence_card":
        if len(_RE_NON_ALNUM.sub("", v)) < 8 or not digits:
            return None
        conf = Confidence.HIGH
    elif category == "resident_code":
        if len(digits) != 11:
            return None
        conf = Confidence.HIGH
    elif category == "employment_insurance":
        if len(digits) != 11:
            return None
        conf = Confidence.HIGH
    elif category == "member_id":
        # 社員番号などの列。数字を含む短い値だけ（それだけでは人を特定しにくいので 低）
        if not digits or len(v) > 30:
            return None
        conf = Confidence.LOW
    elif category == "email":
        # 見出しが「メール」でも、@ の無い値（コードを表として読んだときの「'」「(」で始まる断片など）はメールではない。
        # 「taro[at]example.jp」のように @ を書き換えたものは残す（全角の ＠ は normalize で @ になっている）
        if "@" not in v and "＠" not in v and not _RE_AT_WORD.search(v):
            return None
    elif category in ("gender", "age"):
        # 数だけの値が年齢にありえない大きさなら年齢ではない（競馬の表の「age」列の 1879 など・2026-11-02 実物の検査）
        if category == "age" and _RE_PLAIN_NUMBER.fullmatch(v.strip()) and float(v) > 130:
            return None
        conf = Confidence.LOW
    elif category == "sensitive":
        conf = Confidence.MEDIUM
    elif category == "address":
        if not _RE_WORD_CHAR.search(v):
            return None
    return Hit(category, conf, v, 0, len(v), f"列見出しが「{PII_TYPES[category]}」の列の値")


def _detect_py(text: str, header: str | None = None) -> list[Hit]:
    """detect の Python 版（正規表現は標準の re）。Rust 拡張が無いとき・使えない本文のとき、こちらで検出する。"""
    hits: list[Hit] = []
    category = header_category(header)
    if category:
        hv = _header_value_hit(category, text)
        if hv:
            hits.append(hv)
    if not text or len(text) < 3:
        return hits
    context_text = _header_prefix(header) + text
    offset = len(context_text) - len(text)

    def ctx(start: int, end: int, pattern: re.Pattern[str]) -> bool:
        return _context_has(context_text, start + offset, end + offset, pattern)

    def model_word(start: int) -> str | None:
        return _model_word_before(context_text, start + offset)

    has_digit = any(c.isdigit() for c in text)

    if has_digit:
        # 運転免許証（12桁）はマイナンバーより先に判定する
        license_spans: list[tuple[int, int]] = []
        for m in RE_LICENSE.finditer(text):
            if MY_NUMBER_KW.search(text[m.start() : m.start(1)]) and my_number_is_valid(m.group(1)):
                # 「運転免許：有 個人番号：…」の数字は個人番号（マイナンバーの判定に回す）。検査数字が合わなければ
                # マイナンバーにもならないので、免許証番号として拾う（「免許証番号（個人番号ではない）…」）
                continue
            hits.append(Hit("drivers_license", Confidence.HIGH, m.group(1), m.start(1), m.end(1), "免許証の語＋12桁"))
            license_spans.append((m.start(1), m.end(1)))
        for m in RE_MY_NUMBER.finditer(text):
            digits = m.group(1) + m.group(2) + m.group(3)
            if any(s <= m.start() < e for s, e in license_spans):
                continue
            if not my_number_is_valid(digits):
                if len(set(digits)) > 1 and ctx(m.start(), m.end(), MY_NUMBER_KW):
                    # 語はあるのに検査数字が合わない: 打ち間違いの可能性があるので、消さずに 低 で残す
                    hits.append(
                        Hit(
                            "my_number",
                            Confidence.LOW,
                            m.group(0),
                            m.start(),
                            m.end(),
                            "12桁・個人番号の語あり・検査数字が合わない（打ち間違いの可能性）",
                        )
                    )
                continue
            if ctx(m.start(), m.end(), MY_NUMBER_KW) or category == "my_number":
                conf, rule = Confidence.HIGH, "12桁・検査数字一致・個人番号の語"
            elif ctx(m.start(), m.end(), LICENSE_KW):
                continue
            elif digits.startswith(NON_PERSONAL_PHONE_PREFIXES):
                # 語の無い「0800 1234 5678」はフリーダイヤルの書き方にも見える。拾わないことはせず、低 のまま理由を添える
                conf, rule = (
                    Confidence.LOW,
                    "12桁・検査数字一致（手がかり語なし。フリーダイヤル等の番号の形にも見える）",
                )
            else:
                conf, rule = Confidence.LOW, "12桁・検査数字一致（手がかり語なし）"
            hits.append(Hit("my_number", conf, m.group(0), m.start(), m.end(), rule))
        for m in RE_CARD.finditer(text):
            raw = m.group(0)
            digits = re.sub(r"[^0-9]", "", raw)
            if not (13 <= len(digits) <= 19) or len(set(digits)) == 1:
                continue
            if not luhn_is_valid(digits):
                if ctx(m.start(), m.end(), CARD_NUMBER_KW):
                    # 語はあるのに Luhn 検査が合わない: 打ち間違いの可能性があるので、消さずに 低 で残す
                    hits.append(
                        Hit(
                            "credit_card",
                            Confidence.LOW,
                            raw,
                            m.start(),
                            m.end(),
                            "13〜19桁・カード番号の語あり・Luhn 検査が合わない（打ち間違いの可能性）",
                        )
                    )
                continue
            if not card_prefix_is_plausible(digits):
                continue
            grouped = bool(re.fullmatch(r"[0-9]{4}([ \-])[0-9]{4}\1[0-9]{4}\1[0-9]{1,7}", raw))
            rule = "Luhn一致・ブランド番号体系一致"
            model = model_word(m.start())
            if ctx(m.start(), m.end(), CARD_KW) or category == "credit_card":
                conf = Confidence.HIGH
            elif ctx(m.start(), m.end(), ORDER_KW) or model:
                conf = Confidence.LOW  # 注文番号・品番などの偶然の一致（4桁ずつ区切ってあっても）
                if model:
                    rule += f"（前に「{model}」の語があり、型番などの番号とみなした）"
            elif grouped:
                conf = Confidence.HIGH  # 4桁ずつの区切りは注文番号などではまず見ない書き方
            else:
                conf = Confidence.MEDIUM
            hits.append(Hit("credit_card", conf, raw, m.start(), m.end(), rule))
        for m in RE_MOBILE.finditer(text):
            separated = not m.group(0).isdigit()
            rule = "携帯電話番号の形"
            if separated or ctx(m.start(), m.end(), PHONE_KW) or category == "phone":
                conf = Confidence.MEDIUM
                model = model_word(m.start())
                if model and category != "phone":
                    conf = Confidence.LOW
                    rule += f"（前に「{model}」の語があり、型番などの番号とみなした）"
            elif ctx(m.start(), m.end(), ORDER_KW):
                continue
            else:
                conf = Confidence.LOW  # 区切りの無い11桁は製造番号などと区別できない
            hits.append(Hit("phone", conf, m.group(0), m.start(), m.end(), rule))
        for m in RE_MOBILE_INTL.finditer(text):
            hits.append(Hit("phone", Confidence.MEDIUM, m.group(0), m.start(), m.end(), "携帯電話番号（+81）"))
        for m in RE_LANDLINE_INTL.finditer(text):
            # 国番号 81 と、国内の頭の0（「+81(0)3-…」の「(0)」）を除いた残りが9桁
            national = re.sub(r"^0", "", re.sub(r"[^0-9]", "", m.group(0))[2:])
            if len(national) != 9 or ("0" + national).startswith(NON_PERSONAL_PHONE_PREFIXES):
                continue
            rule = "固定電話番号・+81 の形"
            company, personal = _landline_context(context_text, m.start() + offset, m.end() + offset)
            if company and not personal:
                conf = Confidence.LOW  # 会社の代表番号（英文のレターヘッド等）
                rule += f"（近くに「{company}」の語があり、会社の番号とみなした）"
            else:
                conf = Confidence.MEDIUM  # +81 で書く数字の並びは電話のほかにまず無い
                if personal:
                    rule += f"（近くに「{personal}」の語）"
            hits.append(Hit("phone", conf, m.group(0), m.start(), m.end(), rule))
        for m in RE_LANDLINE.finditer(text):
            digits = re.sub(r"[^0-9]", "", m.group(0))
            if len(digits) != 10 or digits.startswith(NON_PERSONAL_PHONE_PREFIXES):
                continue
            company, personal = _landline_context(context_text, m.start() + offset, m.end() + offset)
            rule = "固定電話番号の形"
            if company and not personal:
                conf = Confidence.LOW  # 会社の代表番号（レターヘッド等）
                rule += f"（近くに「{company}」の語があり、会社の番号とみなした）"
            elif (model := model_word(m.start())) and category != "phone":
                conf = Confidence.LOW
                rule += f"（前に「{model}」の語があり、型番などの番号とみなした）"
            elif ctx(m.start(), m.end(), PHONE_KW) or category == "phone":
                conf = Confidence.MEDIUM
                if personal:
                    rule += f"（近くに「{personal}」の語）"
            else:
                conf = Confidence.LOW
            hits.append(Hit("phone", conf, m.group(0), m.start(), m.end(), rule))
        for m in RE_LANDLINE_SPACE.finditer(text):
            if re.sub(r"[^0-9]", "", m.group(0)).startswith(NON_PERSONAL_PHONE_PREFIXES):
                continue
            if (ctx(m.start(), m.end(), PHONE_KW) or category == "phone") and not _context_has(
                context_text, m.start() + offset, m.end() + offset, COMPANY_KW, width=30
            ):
                hits.append(_phone_unless_model(m, "電話の語＋空白区切りの番号", model_word, category))
        for m in RE_PHONE_BARE.finditer(text):
            if ctx(m.start(), m.end(), PHONE_KW) or category == "phone":
                if m.group(0).startswith(NON_PERSONAL_PHONE_PREFIXES):
                    continue
                hits.append(_phone_unless_model(m, "電話の語＋区切りなし番号", model_word, category))
        for m in RE_POSTAL_MARK.finditer(text):
            hits.append(Hit("postal_code", Confidence.MEDIUM, m.group(0), m.start(), m.end(), "〒＋7桁"))
        for m in RE_POSTAL_BEFORE_PREF.finditer(text):
            if ctx(m.start(), m.end(), ORDER_KW):
                continue
            hits.append(Hit("postal_code", Confidence.MEDIUM, m.group(0), m.start(), m.end(), "7桁＋都道府県"))
        for m in RE_DATE.finditer(text):
            if ctx(m.start(), m.end(), BIRTH_KW) or category == "birthdate":
                hits.append(Hit("birthdate", Confidence.HIGH, m.group(0), m.start(), m.end(), "生年月日の語＋日付"))
            elif RE_DATE_ERA.fullmatch(m.group(0)) and re.match(r"(昭和|平成|大正|[STH])", m.group(0)):
                hits.append(
                    Hit("birthdate", Confidence.LOW, m.group(0), m.start(), m.end(), "和暦の日付（生年月日の可能性）")
                )
        for m in RE_BANK.finditer(text):
            if MONEY_AFTER.match(text[m.end(1) : m.end(1) + 3]) or MONEY_BEFORE.search(text[m.start() : m.start(1)]):
                continue  # 「口座残高 1234567円」など金額
            hits.append(Hit("bank_account", Confidence.HIGH, m.group(1), m.start(1), m.end(1), "口座の語＋7桁"))
        for m in RE_BANK_FULL.finditer(text):
            if MONEY_AFTER.match(text[m.end(1) : m.end(1) + 3]) or MONEY_BEFORE.search(text[m.start() : m.start(1)]):
                continue
            hits.append(
                Hit(
                    "bank_account",
                    Confidence.HIGH,
                    m.group(1),
                    m.start(1),
                    m.end(1),
                    "口座の語＋金融機関コード-支店番号-口座番号",
                )
            )
        for m in RE_PENSION.finditer(text):
            hits.append(Hit("pension", Confidence.HIGH, m.group(1), m.start(1), m.end(1), "年金番号の語＋10桁"))
        for m in RE_PASSPORT.finditer(text):
            hits.append(Hit("passport", Confidence.HIGH, m.group(1), m.start(1), m.end(1), "旅券の語＋番号"))
        for m in RE_RESIDENCE_CARD.finditer(text):
            hits.append(
                Hit("residence_card", Confidence.HIGH, m.group(1), m.start(1), m.end(1), "在留カードの語＋番号")
            )
        for m in RE_RESIDENT_CODE.finditer(text):
            hits.append(
                Hit("resident_code", Confidence.HIGH, m.group(1), m.start(1), m.end(1), "住民票コードの語＋11桁")
            )
        employment_spans: list[tuple[int, int]] = []
        for m in RE_EMPLOYMENT.finditer(text):
            employment_spans.append((m.start(1), m.end(1)))
            hits.append(
                Hit(
                    "employment_insurance",
                    Confidence.HIGH,
                    m.group(1),
                    m.start(1),
                    m.end(1),
                    "雇用保険の番号の語＋11桁",
                )
            )
        for m in RE_INSURANCE.finditer(text):
            if not any(c.isdigit() for c in m.group(1)):
                continue
            if "雇用保険" in context_text[max(0, m.start() + offset - 20) : m.start(1) + offset]:
                # 「雇用保険被保険者番号」は保険証の番号ではない。4桁-6桁-1桁の形なら上で拾っている。形が違っても
                # 落とさず、雇用保険の番号として 中 で残す
                if not any(s < m.end(1) and m.start(1) < e for s, e in employment_spans):
                    hits.append(
                        Hit(
                            "employment_insurance",
                            Confidence.MEDIUM,
                            m.group(1),
                            m.start(1),
                            m.end(1),
                            "雇用保険の番号の語＋番号（4桁-6桁-1桁の形ではない）",
                        )
                    )
                continue
            hits.append(
                Hit("health_insurance", Confidence.MEDIUM, m.group(1), m.start(1), m.end(1), "保険証の語＋番号")
            )
        for m in RE_MEMBER_ID.finditer(text):
            hits.append(
                Hit("member_id", Confidence.LOW, m.group(1), m.start(1), m.end(1), "会員・社員などの番号の語＋番号")
            )

    # 住所は漢数字だけの番地（六丁目十番一号）もあるので、算用数字の有無に関係なく調べる
    if has_digit or any(c in text for c in "丁番号"):
        for m in RE_ADDRESS.finditer(text):
            hits.append(Hit("address", Confidence.MEDIUM, m.group(0), m.start(), m.end(), "都道府県＋市区町村＋番地"))
        for m in RE_ADDRESS_NO_PREF.finditer(text):
            hits.append(Hit("address", Confidence.LOW, m.group(0), m.start(), m.end(), "市区＋町名＋番地"))

    if "@" in text:
        for m in RE_EMAIL.finditer(text):
            conf = Confidence.LOW if ROLE_EMAIL.match(m.group(0)) else Confidence.MEDIUM
            hits.append(Hit("email", conf, m.group(0), m.start(), m.end(), "メールアドレスの形"))

    for m in RE_NAME_LABEL.finditer(text):
        hits.append(Hit("name", Confidence.MEDIUM, m.group(1), m.start(1), m.end(1), "氏名の見出し語＋名前"))
    for m in RE_NAME_LABEL_TIGHT.finditer(text):
        hits.append(
            Hit("name", Confidence.MEDIUM, m.group(1), m.start(1), m.end(1), "氏名の見出し語＋よくある姓の名前")
        )
    for m in iter_name_honorific(text):
        conf = Confidence.MEDIUM if len(m.group(0)) >= 4 else Confidence.LOW
        hits.append(Hit("name", conf, m.group(0), m.start(), m.end(), "よくある姓＋敬称"))
    # 「様」「殿」が無ければ当たりようが無い（全位置を調べる前に飛ばす）
    if "様" in text or "殿" in text:
        for m in RE_NAME_HONORIFIC_ANY.finditer(text):
            if not HONORIFIC_STOP.search(m.group(1)):
                hits.append(Hit("name", Confidence.LOW, m.group(0), m.start(), m.end(), "漢字の名前＋様・殿"))
    for m in iter_name_spaced(text):
        hits.append(Hit("name", Confidence.LOW, m.group(0), m.start(), m.end(), "よくある姓＋空白＋名"))
    for m in RE_SENSITIVE.finditer(text):
        hits.append(Hit("sensitive", Confidence.MEDIUM, m.group(0), m.start(), m.end(), "要配慮の見出し語＋記載"))

    hits = _dedupe(hits)
    _classify_addresses(hits, context_text, offset)
    return hits


# ---- Rust 拡張（pii_rs_detect）。本文の検出の中心を Rust に置き換える。無ければ上の Python 版で動く ----
# 環境変数 PII_CHECKER_NO_RUST が空でなければ、拡張があっても使わない（拡張なしの動作の確認・不具合の切り分け用）
_CONFIDENCE_NUM = {Confidence.LOW: 1, Confidence.MEDIUM: 2, Confidence.HIGH: 3}
_CONFIDENCE_BY_NUM = {1: Confidence.LOW, 2: Confidence.MEDIUM, 3: Confidence.HIGH}


def _xor_ranges(a: list[tuple[int, int]], b: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """2 つの範囲の列（それぞれ重ならない [開始, 終了]）の、片方にだけある範囲（対称差）。"""
    parity: dict[int, int] = {}
    for lo, hi in a + b:
        parity[lo] = parity.get(lo, 0) ^ 1
        parity[hi + 1] = parity.get(hi + 1, 0) ^ 1
    out: list[tuple[int, int]] = []
    start = -1
    for point in sorted(p for p, v in parity.items() if v):
        if start < 0:
            start = point
        else:
            out.append((start, point - 1))
            start = -1
    return out


def _rust_guard_ranges(ext) -> list[tuple[int, int]]:
    """Python の re と Rust の regex で「語の文字（\\w・\\b の元）」「空白（\\s）」の判定が食い違う文字の範囲。

    どちらも Unicode の表から決まるので、表の版が違う（Python の版と拡張の版のずれ）と食い違う。片方向だけでなく
    両方向（Python だけが語の文字とみなす ² ³ など・Rust だけがみなす結合文字など）を求める。この文字を含む本文は
    Rust を使わず Python の経路で検出する。
    """
    everything = "".join(map(chr, range(0x110000)))
    out: list[tuple[int, int]] = []
    for kind, py_pattern in (("word", r"\w+"), ("space", r"\s+")):
        py_ranges = [(m.start(), m.end() - 1) for m in re.finditer(py_pattern, everything)]
        out += _xor_ranges(py_ranges, [tuple(r) for r in ext.class_ranges(kind)])
    # 2 種の範囲を 1 つの列にまとめる（重なり・隣り合いはつなぐ）
    merged: list[tuple[int, int]] = []
    for lo, hi in sorted(out):
        if merged and lo <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return merged


def _guard_key(ext) -> list[str]:
    """食い違う範囲の計算結果を使い回してよいかの鍵。Python の Unicode データの版と、拡張の Unicode の表（regex-syntax）の版。"""
    import unicodedata

    return [unicodedata.unidata_version, ext.unicode_key()]


def _guard_ranges_for(ext) -> list[tuple[int, int]]:
    """食い違う範囲。ビルド時に求めて同梱した表(_rust_guard.py)の鍵が今の環境と一致すればそれを使い、
    無い・一致しないときは、その場で求める（約 0.15 秒）。"""
    try:
        from . import _rust_guard

        if list(_rust_guard.KEY) == _guard_key(ext):
            return [tuple(r) for r in _rust_guard.RANGES]
    except ImportError:
        pass
    except Exception as exc:  # noqa: BLE001 - 表が途中で切れた・項目が無いなど。その場で求め直せば正しい
        _record_engine_event(f"同梱の範囲の表（_rust_guard.py）が読めないため、その場で求め直した: {exc!r}")
    return _rust_guard_ranges(ext)


def _load_rust():
    """Rust 拡張を読み込んで、使える状態にして返す。使えなければ None（Python 版で動く）。"""
    import os

    global _RUST_NOTE
    if os.environ.get("PII_CHECKER_NO_RUST"):
        _RUST_NOTE = "環境変数 PII_CHECKER_NO_RUST により使っていない"
        return None
    try:
        import pii_rs_detect as ext
    except ModuleNotFoundError:
        _RUST_NOTE = "拡張が入っていない"
        return None
    except ImportError as exc:  # 入っているのに読めない（DLL の読み込みの失敗など）
        _RUST_NOTE = f"拡張を読み込めない（{exc!r}）"
        _record_engine_event(f"Rust 拡張を読み込めないため、Python の経路で検出する: {exc!r}")
        return None
    try:
        ext.set_mismatch_ranges(_guard_ranges_for(ext))
    except Exception as exc:  # noqa: BLE001 - 拡張が壊れていても、検出は Python 版で続ける
        _RUST_NOTE = f"拡張の読み込みに失敗した（{exc!r}）"
        _record_engine_event(f"Rust 拡張を使えないため、Python の経路で検出する: {exc!r}")
        return None
    return ext


def engine_log_path() -> Path:
    """検出エンジンの出来事（Rust 拡張を使えなくなった理由など）を追記するファイル。検査の記録と同じフォルダ。"""
    import os

    return Path(os.environ.get("LOCALAPPDATA") or str(Path.home())) / "PiiChecker" / "engine.log"


def _record_engine_event(message: str) -> None:
    """検出エンジンの出来事を logging と engine.log に残す。

    画面の版や作業用プロセス（spawn の子）には標準エラーが無く、warnings や logging の既定の出力は捨てられる。
    検査の途中で Rust から Python に切り替わると結果は同じまま遅くなるだけなので、後から理由を追えるようファイルに書く。
    書けなくても検査は止めない。
    """
    import datetime
    import os

    _log.warning("%s", message)
    try:
        path = engine_log_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        stamp = datetime.datetime.now().isoformat(timespec="seconds")
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"{stamp} pid={os.getpid()} {message}\n")
    except OSError:
        pass


# Rust 拡張を使っていないときの理由（使っていれば空）。--version などで利用者に見せる
_RUST_NOTE = ""
_log = logging.getLogger(__name__)
_RUST = _load_rust()


def rust_enabled() -> bool:
    """本文の検出に Rust 拡張を使っているか。"""
    return _RUST is not None


def rust_status() -> str:
    """検出エンジンの説明（利用者向け）。Rust を使っていないときは理由を添える。"""
    if _RUST is not None:
        return "Rust 拡張"
    return f"Python（Rust 拡張なし: {_RUST_NOTE}）" if _RUST_NOTE else "Python（Rust 拡張なし）"


def _disable_rust(error: BaseException) -> None:
    """拡張が想定外の失敗をした（panic など）ので、以後は使わず Python 版で検出する。

    結果は Python 版で同じものが出るので検査は続く。遅くなった理由を後から追えるよう、ログ（logging）にも残す。
    画面の版や作業用プロセスでは標準エラーが無いことがあるので、warnings だけには頼らない。
    """
    global _RUST, _RUST_NOTE
    _RUST = None
    _RUST_NOTE = f"検査の途中で拡張が失敗した（{error!r}）"
    _record_engine_event(f"Rust 拡張が失敗したため、以後は Python の経路で検出する: {error!r}")
    import warnings

    warnings.warn(f"Rust 拡張が失敗したため、以後は Python の経路で検出します: {error!r}", RuntimeWarning, stacklevel=3)


def _detect_rust(text: str, header: str | None = None) -> list[Hit] | None:
    """detect の Rust 版。Python 版と同じ結果を返す。この本文を Rust で扱えないとき（語の文字の判定が
    Python と食い違う文字を含む・サロゲートを含む・拡張が失敗した）は None を返し、呼び出し側が Python 版で検出する。"""
    category = header_category(header)
    hdr = None
    hv = None
    if category:
        hv = _header_value_hit(category, text)
        if hv:
            hdr = (hv.pii_type, _CONFIDENCE_NUM[hv.confidence], hv.value, hv.rule)
    if not text or len(text) < 3:
        return [hv] if hv else []
    prefix = _header_prefix(header)
    try:
        rows = _RUST.detect_body(text, prefix, category, hdr)
    except UnicodeEncodeError:
        return (
            None  # 単独のサロゲート（壊れた文字）を含む本文は Rust の文字列にできない。この本文だけ Python 版で検出する
        )
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except BaseException as exc:  # noqa: BLE001 - pyo3 の PanicException は BaseException 由来
        _disable_rust(exc)
        return None
    if rows is None:
        return None
    return [Hit(t, _CONFIDENCE_BY_NUM[c], v, s, e, rule, needs) for (t, c, v, s, e, rule, needs) in rows]


# 短い本文の検出結果の覚え書き（(本文, 見出し) → 検出のタプル）。表では同じ短い値（性別・続柄・用途・年・区分など）が
# 行ごとに繰り返し来るので、正規表現を通し直さずに返す。値ごとに異なる列でも溢れたら空にするだけなので、メモリは上限で止まる
# （約 17MB。異なる値が続く列では空にし直すたびに覚え直すので効きは薄れるが、結果は変わらない）。
# 覚えるのは Hit のフィールドを順に並べたタプル（Hit にフィールドを足したら、ここで写す並びも足すこと。試験が数を確かめる）
_SHORT_CACHE_LEN = 24
_SHORT_CACHE_LIMIT = 32768
_short_cache: dict[tuple[str, str | None], tuple[tuple, ...]] = {}


def detect(text: str, header: str | None = None) -> list[Hit]:
    """文字列から個人情報らしきものを探す。header は表の列見出し（無ければ None）。

    text は呼び出し側で normalize 済みであること（位置がずれないように）。
    Rust 拡張があればそれで検出する（結果は Python 版と同じ）。無いとき・Rust で扱えない本文のときは Python 版。
    短い本文は結果を覚えておき、同じ本文・見出しには覚えた結果を新しい Hit にして返す（呼び出し側が Hit を書き換えるため）。
    """
    if len(text) > _SHORT_CACHE_LEN:
        return _detect_uncached(text, header)
    key = (text, header)
    got = _short_cache.get(key)
    if got is None:
        hits = _detect_uncached(text, header)
        if len(_short_cache) >= _SHORT_CACHE_LIMIT:
            _short_cache.clear()
        _short_cache[key] = tuple(
            (h.pii_type, h.confidence, h.value, h.start, h.end, h.rule, h.needs_person) for h in hits
        )
        return hits
    return [Hit(*t) for t in got]


def _detect_uncached(text: str, header: str | None) -> list[Hit]:
    """detect の本体（覚え書きを通さない）。"""
    hits = _detect_rust(text, header) if _RUST is not None else None
    if hits is None:
        hits = _detect_py(text, header)
    return _drop_false_shapes(text, _drop_inside_hash(text, hits)) if hits else hits


# カード番号の区切り方として普通の並び（4桁ずつ・最後だけ1〜7桁、Amex の 4-6-5、Diners の 4-6-4）
_CARD_GROUPS = re.compile(
    r"[0-9]{4}(?:[ \-][0-9]{4}){2}[ \-][0-9]{1,7}|[0-9]{4}(?:[ \-][0-9]{4}){3}[ \-][0-9]{1,3}"  # 19桁の 4-4-4-4-3 も
    r"|[0-9]{4}[ \-][0-9]{6}[ \-][0-9]{4,5}"
)
# 「様」「殿」で終わっても敬称ではない語（名前の終わりになりにくい字に限る。「健一様」「和正様」は落とさない）
_HONORIFIC_WORDS = (
    "仕様",
    "同様",
    "模様",
    "異様",
    "態様",
    "紋様",
    "有様",
    "両様",
    "別様",
    "各様",
    "神様",
    "王様",
    "宮殿",
    "神殿",
    "本殿",
    "拝殿",
    "社殿",
    "寝殿",
    "仏殿",
    "霊殿",
)
# 様式・様子・多様性・様態・殿堂（「様相」は「○○様相談」のように人の名前の後ろにも来るので入れない）
_HONORIFIC_NOT_AFTER = "式子性態堂"
# 「様」で終わる語のうち、終わりの2文字だけでは名前と分けられないもの（「美歩様」は名前なので「歩様」では落とさない）
_HONORIFIC_LONG_WORDS = ("交差歩様",)  # 馬の歩き方（競馬の調教の寸評）
# 「よくある姓＋敬称」の値の末尾の敬称（RE_NAME_HONORIFIC の終わりと同じ並び）
_RE_HONORIFIC_TAIL = re.compile(r"(?:様|殿|さん|君|くん|ちゃん)\Z")
# 手がかり語の無い番号の形（数字ばかりの並びの中にあれば、数値のデータとみなして捨てる）
_BARE_NUMBER_RULES = frozenset(
    {
        "12桁・検査数字一致（手がかり語なし）",
        "12桁・検査数字一致（手がかり語なし。フリーダイヤル等の番号の形にも見える）",
        "Luhn一致・ブランド番号体系一致",
        "携帯電話番号の形",
        "固定電話番号の形",
    }
)
# 年月日（19xx・20xx の年＋月＋日）で始まる12桁。レースの ID・時刻つきのファイル名（202205020606・202610211234）
_RE_DATE_PREFIX_12 = re.compile(r"(?:19|20)[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])[0-9]{4}")
_RE_DATE_NUMBERS = re.compile(r"[0-9]+|元")
_NUMERIC_CHARS = frozenset("0123456789.+-:/,")
_RE_NUMBER_CHUNK_SPLIT = re.compile(r"[\s,]+")
# 番号（電話・カード・マイナンバー）にならない長さ（20桁以上）の数字の連続が、空白と、英字の欄1つ（「A」「A1」の
# ASCII の英字1〜2字＋数字1つまで）だけをはさんで後ろ・前にあるもの（_beside_long_digit_run。前のほうは窓の終わり＝検出の直前で終わる形）
_RE_LONG_RUN_AFTER = re.compile(r"[ \t　]*(?:[A-Za-z]{1,2}[0-9]?[ \t　]+)?[0-9]{20}")
_RE_LONG_RUN_BEFORE = re.compile(r"[0-9]{20}[ \t　]*(?:[A-Za-z]{1,2}[0-9]?[ \t　]*)?\Z")
# 16進のダンプの行。od・hexdump の「0000030  36 32 34 4B …」（番地7〜8桁＋2桁の組が8つ以上）・
# od -Ax の「000030 36 32 34 4b …」（番地6桁＋2桁の組が12以上）と、
# xxd の「00000030: 3632 344b …」（番地8桁＋コロン＋4桁の組が4つ以上）・xxd -g1 の「00000030: 36 32 …」
# （2桁の組が8つ以上）。番地は16の倍数なので末尾が0
# （「2024 11 07 12 30 …」のような年と2桁の数の並びに当たらないよう、番地の桁と末尾を絞る。
# 6桁の番地は「202410 …」のような年月にも見えるので、組の数を1行の16に近い12以上にする）
_RE_DUMP_LINE = re.compile(
    r"[ \t]*(?:[0-9A-Fa-f]{6,7}0(?:[ \t]+[0-9A-Fa-f]{2}){8,}|[0-9A-Fa-f]{5}0(?:[ \t]+[0-9A-Fa-f]{2}){12,}"
    r"|[0-9A-Fa-f]{7}0:(?:(?:[ \t]+[0-9A-Fa-f]{4}){4,}|(?:[ \t]+[0-9A-Fa-f]{2}){8,}))(?![0-9A-Fa-f])"
)
_DUMP_LINE_MAX = 200
# URL のパスの中の検出（_in_url_path）。手前の「scheme://」を探す幅と、パスとみなす文字
# （ASCII の英数字と「-._~/%:@+=」だけ。「?」「#」「;」「&」「,」・空白・引用符・日本語の文字などが来たら URL の外とみなす）
_URL_PATH_MAX = 300
_URL_PATH_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~/%:@+=")
# Wavefront OBJ の要素の行（頂点・面・線。「f 1074/12/3 1076/13/3 1075/14/3」）
_RE_OBJ_LINE = re.compile(r"(?:v|vt|vn|vp|f|l|p)(?:[ \t]+-?[0-9.eE/+-]+){2,}")
# IANA の一覧に無いが、社内のメールで使われる TLD（.local の Active Directory など）。
# 予約語の .test・.example・.invalid・.localhost は実在の宛先にならないので入れない
_PRIVATE_TLDS = frozenset({"local", "localdomain", "internal", "lan", "corp", "home", "intranet"})
# 直後に1文字続いたアドレスから、その1文字を外してよい TLD（_email_trim_tail）
# 画像の倍率つきの名前の「@2x」「@3x」の部分（_email_domain_plausible）
_RE_SCALE_LABEL = re.compile(r"[0-9]x")
_TRIM_TLDS = frozenset({"com", "org", "net", "edu", "gov", "mil", "info", "io"})


def _email_domain_plausible(value: str) -> bool:
    """メールアドレスの形の値のドメインが、実在しうるものか。

    プログラムの識別子・バイナリの断片がメールの形に当たったもの（実物の検査の生データ走査で 7,107 件）を捨てるため:
    - TLD が IANA の一覧（と社内向けの .local など）に無い: 「z@FlaxRobertaPreLayerNormLayerCollection.setup」「-x@TestX.test」
    - TLD の大文字・小文字が混ざる: 「6x@W.lC」（.lc は実在するが、人が書くアドレスでは「lC」とは書かない）
    - ラベルが3つ以上で、TLD だけが頭文字の大文字・ほかは小文字だけ: Java の注釈「x@org.example.annotation.Data」の形
      （.data・.app・.page のように、注釈の名前が実在の TLD に当たるもの）
      （「taro@gmail.Com」のような2つのラベルは人の書き間違いもありうるので残す。「taro@mail.example.Com」は見落とす）
    - 2つ目のラベルが1文字で、TLD が小文字だけでない: バイナリの断片「x@r.JO」「x@H.Se」（「x@q.com」は残す）
    - 2つ目のラベルが「2x」「3x」: 画像・動画の倍率つきの名前「icon@2x.mov」「logo@3x.zip」（.mov・.zip は実在の TLD。
      実在のドメイン「x@3x.com」も見落とすが、画像の名前のほうがずっと多い）
    """
    domain = value.rpartition("@")[2]
    head, _, tld = domain.rpartition(".")
    if not (tld.islower() or tld.isupper() or tld.istitle()):
        return False
    if tld.lower() not in TLDS and tld.lower() not in _PRIVATE_TLDS:
        return False
    label = head.rpartition(".")[2]
    if len(label) == 1 and not tld.islower():
        return False
    if _RE_SCALE_LABEL.fullmatch(label):
        return False
    return not (tld.istitle() and "." in head and head == head.lower())


def _email_trim_tail(h: Hit) -> Hit | None:
    """TLD の直後に英字が空白なしで続いたアドレスなら、続いた分を外した Hit を返す。そうでなければ None。

    - 小文字の TLD の直後に大文字で始まる語: 改行の消えた本文「taro@example.comTEL 03-…」「x@example.co.jpTel」・
      .pyc の中の「x@cam.ac.ukE」（式は英字を続く限り TLD として取るので、外さないと TLD が実在しない形になる）
    - 汎用の TLD の直後に1文字: .pyc の中で次の文字列の型の1バイトが続いた「x@gmail.comz」。国の2文字の TLD は
      拡張子と取り違える（「x@2x.png」の .pn・.jpg の .jp）ので、小文字が続く形は汎用のもの（_TRIM_TLDS）に限る
    """
    tld = h.value.rpartition(".")[2]
    cut = 0
    lower_run = len(tld) - len(tld.lstrip("abcdefghijklmnopqrstuvwxyz"))
    if 2 <= lower_run < len(tld) and tld[:lower_run] in TLDS:
        cut = lower_run  # 小文字の TLD ＋ 大文字で始まる続き
    elif len(tld) >= 3 and (tld[:-1].islower() or tld[:-1].isupper()) and tld[:-1].lower() in _TRIM_TLDS:
        cut = len(tld) - 1
    if not cut:
        return None
    extra = len(tld) - cut
    trimmed = h.value[:-extra]
    if not _email_domain_plausible(trimmed):
        return None
    return Hit(h.pii_type, h.confidence, trimmed, h.start, h.end - extra, h.rule, h.needs_person)


def _decimal_adjacent(text: str, start: int, end: int) -> bool:
    """検出の直前が「数字＋.」か、直後が「.＋数字」か（小数の並びの途中から始まる・小数へ続く）。"""
    before = text[max(0, start - 2) : start]
    after = text[end : end + 2]
    return (len(before) == 2 and before[1] == "." and before[0].isdigit()) or (
        len(after) == 2 and after[0] == "." and after[1].isdigit()
    )


def _in_numeric_run(text: str, start: int, end: int, width: int = 30) -> bool:
    """検出と同じ行の前後（各 width 文字）が数字と数の記号だけで、ほかの数の塊が3つ以上・数字が10個以上あるか。

    固定長のレコード（競馬のデータ「3132512031318081   231050710450   1770  2001-18.3」）・数値の列の並びの中の
    番号の形は、人の番号ではなく数値のデータ。前後の行は見ない（番号だけの行が並ぶ一覧を落とさないため）。
    番号が2つ並ぶだけの行（「09012345678 09087654321」）も、塊が足りないので当たらない。
    """
    before = text[max(0, start - width) : start].rsplit("\n", 1)[-1]
    after = text[end : end + width].split("\n", 1)[0]
    digits = 0
    for c in before + after:
        if c.isspace():
            continue
        if c not in _NUMERIC_CHARS:
            return False
        digits += c.isdigit()
    if digits < 10:
        return False
    chunks = [x for x in _RE_NUMBER_CHUNK_SPLIT.split(before + " " + after) if x]
    # 塊がどれも10桁以上の番号なら、番号を並べた一覧（「09012345678 09087654321 …」）とみなして捨てない
    # （窓の端で切れた塊は短く見えるので、両端の塊は数えない）
    inner = chunks[1:-1] if len(chunks) > 2 else chunks
    if all(sum(c.isdigit() for c in x) >= 10 for x in inner):
        return False
    return len(chunks) >= 3


def _beside_long_digit_run(text: str, start: int, end: int, width: int = 40) -> bool:
    """検出のすぐ前か後ろ（同じ行の前後 width 文字。間は空白と英字の欄1つだけ）に、20桁以上の数字の連続があるか。

    連続は20桁が丸ごと窓に入るものだけを見る（空白が20個を超えて離れたもの・窓の途中から始まるものは見ない）。
    使うのは手がかり語の無い12桁（マイナンバー）だけ。電話・カードの形は語があっても同じ規則名で出るので使わない。

    固定長のレコード（JRA-VAN のレース情報「…    180000002400    00039000000160000000980000…」・
    「120000001800A   0012000000048…」）では、0詰めの数値の欄が空白なしにつながって数十〜数百桁の数字の連続になる。
    その隣の12桁は欄の一部で、_in_numeric_run の「塊が3つ以上」に届かない（窓の中が空白と長い塊1つだけ・英字の欄が混じる）。
    電話・カード・マイナンバーの番号はどれも19桁以下なので、20桁以上の連続は番号の一覧ではない。
    間に日本語などがあるもの（「123456789018 様 0012…」）は見ない。
    """
    if _RE_LONG_RUN_AFTER.match(text, end, min(len(text), end + width)):
        return True
    return bool(_RE_LONG_RUN_BEFORE.search(text, max(0, start - width), start))


def _in_url_path(text: str, start: int, end: int) -> bool:
    """検出が URL のパス（「scheme://」の後ろ・「?」より前）の中にあるか。

    次の3つがそろうものだけを見る:
    - 検出の手前 _URL_PATH_MAX 文字の中に「://」がある（それより遠い「://」は見ない）
    - その最後の「://」の直前が ASCII の英字（scheme の終わり）
    - 「://」の後ろから検出の終わりまでが、パスの文字（_URL_PATH_CHARS）だけ
    実物の検査（2026-11-07・.db の生データ）では、手がかり語の無い12桁 55,675 個がすべて
    「https://…/public/<12桁>_<16進>」のような配信の URL のパスの一部だった。
    クエリの値（「?id=123456789018」）・「;jsessionid=」の類は番号が漏れる経路なので残す。
    URL の後ろに空白なしで続く文（「https://a.jp/、123456789018」「…/x,山田,123456789018」）も、
    句読点・カンマで URL の外とみなして残す。日本語を含むパスも同じく外とみなす（見落とすより残す側）。
    検出のすぐ前が「:」「=」のもの（「https://a.jp/x:123456789018」・「?」の無い「…/x=123456789018」）は、
    パスの一部ではなく項目の値として書いた形なので残す（配信の URL の番号は「/」「_」「-」の後ろに来る）。
    パスの中の「token=」「sig=」「ts=」「order:」の後ろ・パスに入れた AWS の ARN の本物でない番号も拾うが、
    形では分けられないので見落とさない側に倒す。
    """
    if start > 0 and text[start - 1] in ":=":
        return False
    i = text.rfind("://", max(0, start - _URL_PATH_MAX), start)
    if i <= 0 or not (text[i - 1].isascii() and text[i - 1].isalpha()):
        return False
    return all(c in _URL_PATH_CHARS for c in text[i + 3 : end])


def _across_number_lines(text: str, start: int, end: int) -> bool:
    """検出が改行をまたいでいて、検出の始まる行の1つ前の行か、終わる行の1つ後ろの行が数だけの行か
    （1行に数が1つずつ並ぶ一覧の一部）。

    Perl の unicore の表（「1132↵1133↵1134」）・Excel のシートの XML を文にしたもの（セルの値が1行ずつ）では、
    4桁の行が3つ続くと区切りの改行をはさんで12桁の番号の形になる。1行ずつ書いた番号（前後が数の行でない）は残す。
    """
    if "\n" not in text[start:end]:
        return False
    line_start = text.rfind("\n", 0, start)
    if line_start > 0:
        prev = text[text.rfind("\n", 0, line_start) + 1 : line_start].strip()
        if prev and all(c in _NUMERIC_CHARS for c in prev):
            return True
    line_end = text.find("\n", end)
    if line_end >= 0:
        nxt_end = text.find("\n", line_end + 1)
        nxt = text[line_end + 1 : nxt_end if nxt_end >= 0 else len(text)].strip()
        if nxt and all(c in _NUMERIC_CHARS for c in nxt):
            return True
    return False


def _in_dump_or_mesh_line(text: str, start: int) -> bool:
    """検出の始まる行が、16進のダンプの行か Wavefront OBJ の要素の行か。

    - ダンプ（od・hexdump・xxd の出力をログに貼ったもの）: 右の文字の欄「624K000135004120」に数字が並ぶと、
      左の16進の欄と同じ中身が12桁の番号の形に見える（見本のダンプの貼られたログ1つで 106 件）
    - OBJ の面・頂点の行「f 1074 1076 1075」: 4桁の数が3つ空白で並ぶと、区切りつきの12桁の形になる
    どちらの行も短いので、前後 _DUMP_LINE_MAX 文字の中に行の端が無い行は見ない
    （改行の無い長い本文で、検出ごとに行全体をなめて二乗の遅さにならないため）。
    """
    line_start = text.rfind("\n", max(0, start - _DUMP_LINE_MAX), start) + 1
    if line_start == 0 and start > _DUMP_LINE_MAX:
        return False
    line_end = text.find("\n", start, start + _DUMP_LINE_MAX)
    if line_end < 0:
        if len(text) > start + _DUMP_LINE_MAX:
            return False
        line_end = len(text)
    if _RE_DUMP_LINE.match(text, line_start, line_end):
        return True
    while line_start < line_end and text[line_start] in " \t":
        line_start += 1
    while line_end > line_start and text[line_end - 1] in " \t\r":
        line_end -= 1
    return bool(_RE_OBJ_LINE.fullmatch(text, line_start, line_end))


def _era_date_is_broken(text: str, h: Hit) -> bool:
    """和暦の日付の形（確度 低）が、日付としてありえないか、数値の並びの一部か。

    「532637H 10.3-13.0」（固定長のレコードの英字の後ろの数）・「H 15.3-99」（日が99）を拾わないため。
    """
    nums = _RE_DATE_NUMBERS.findall(h.value)
    if len(nums) >= 3 and nums[1] != "元" and nums[2] != "元":
        if not (1 <= int(nums[1]) <= 12 and 1 <= int(nums[2]) <= 31):
            return True
    prev = text[h.start - 1 : h.start]
    if h.value[:1].isascii() and prev.isascii() and prev.isalnum():
        return True  # 1文字の元号（H・S）の前に英数字が続く
    return text[h.end : h.end + 1] == "." and text[h.end + 1 : h.end + 2].isdigit()


def _drop_false_shapes(text: str, hits: list[Hit]) -> list[Hit]:
    """実物の検査（2026-10-21・ドライブ全体）で多かった、形だけ当たる誤検出を除く。

    - カード番号: 区切りがあるのに普通の並びでないもの（16進のダンプ「3f 32 30 …」の数字だけの組など）。
      確度 高（カードの語・列の見出し）と、カード番号の語があって Luhn が合わない 低 は残す
    - 電話（確度 低 のもの）: 小数の途中から始まる・小数へ続くもの（SVG の座標「0.07612 -0.4056」など）。
      区切りのある携帯などの確度 中 は、「項目1.090-…」のような箇条書きもあるので落とさない
    - 「様」「殿」: 仕様・同様・宮殿のような語と、様式・殿堂のように後ろへ続く語
    以下は 2026-11-02 に同じ検査の結果を見直して足したもの（競馬のデータ・小数の並び・時刻つきの名前）:
    - 手がかり語の無い番号の形（マイナンバー・カード 中・電話 低）: 数字ばかりの並びの中のもの
    - マイナンバー（手がかり語なし）: 小数の並びの途中（「104.4447.1657.9170.6」）・年月日で始まる12桁
    - 和暦の日付（低）: 月日がありえない・英数字の直後の1文字の元号・小数へ続く
    - メールアドレスの形: TLD が実在しない・大文字小文字の混ざり・Java の注釈の形（_email_domain_plausible）
    2026-11-07: 手がかり語の無い番号の形が改行をまたぎ、前後の行が数だけの行のもの（1行に数が1つずつの一覧）・
    16進のダンプの行と OBJ の要素の行の中のもの。マイナンバー（手がかり語なし）のすぐ隣が20桁以上の数字の連続のもの
    （固定長のレコードの0詰めの欄）・URL のパスの中のもの（_in_url_path。クエリの値は残す）
    """
    out = []
    for h in hits:
        if h.rule.startswith("列見出し"):
            out.append(h)  # 列の見出しで決めたものは値の形で落とさない
            continue
        if (
            h.rule in _BARE_NUMBER_RULES
            and h.confidence != Confidence.HIGH
            and (
                _in_numeric_run(text, h.start, h.end)
                or _across_number_lines(text, h.start, h.end)
                or _in_dump_or_mesh_line(text, h.start)
            )
        ):
            continue
        if h.pii_type == "my_number" and h.rule.startswith("12桁・検査数字一致（手がかり語なし"):
            if (
                _decimal_adjacent(text, h.start, h.end)
                or _RE_DATE_PREFIX_12.fullmatch(_RE_NON_DIGIT.sub("", h.value))
                or _beside_long_digit_run(text, h.start, h.end)
                or _in_url_path(text, h.start, h.end)
            ):
                continue
        elif h.rule == "和暦の日付（生年月日の可能性）":
            if _era_date_is_broken(text, h):
                continue
        elif h.pii_type == "email":
            if not _email_domain_plausible(h.value):
                h = _email_trim_tail(h)
                if h is None:
                    continue
        elif h.pii_type == "credit_card":
            if (
                h.confidence != Confidence.HIGH
                and "カード番号の語あり" not in h.rule
                and not h.value.isdigit()
                and not _CARD_GROUPS.fullmatch(h.value)
            ):
                continue
        elif h.pii_type == "phone" and h.confidence == Confidence.LOW:
            before = text[max(0, h.start - 2) : h.start]
            after = text[h.end : h.end + 2]
            decimal_before = len(before) == 2 and before[1] == "." and before[0].isdigit()
            if decimal_before and text[max(0, h.start - 4) : h.start] == "+81.":
                decimal_before = False  # 「+81.90-…」の国番号の区切り（小数ではない）
            if decimal_before or (len(after) == 2 and after[0] == "." and after[1].isdigit()):
                continue
        elif h.rule == "よくある姓＋敬称":
            # 「関係者様」は姓の「関」で始まるだけの語。敬称の前がまるごと除外の語なら名前ではない
            # （「田中部長殿」のように姓が前に付いたものは人なので残す）。空白は姓の直後に入りうる（「関 係者様」）ので詰めて比べる
            if HONORIFIC_STOP.fullmatch(_RE_HONORIFIC_TAIL.sub("", h.value).replace(" ", "").replace("　", "")):
                continue
        elif h.rule == "漢字の名前＋様・殿":
            nxt = text[h.end : h.end + 1]
            if (
                h.value[-2:] in _HONORIFIC_WORDS
                or h.value.endswith(_HONORIFIC_LONG_WORDS)
                or (nxt and nxt in _HONORIFIC_NOT_AFTER)
            ):
                continue
        out.append(h)
    return out


# ハッシュ・識別子（git のオブジェクトや pack の名前・SHA-1/SHA-256/MD5・UUID）。16進の数字だけの並びが偶然
# 12桁の検査数字に合うと、マイナンバー等として拾ってしまう（40桁のランダムな16進の約0.15%）。英字を1つ以上含む
# 32文字以上の16進の並び（頭の 0x は許す）と、UUID の形の中で見つけたものは、種類を問わず捨てる
# （数字だけの長い並びは今までどおり扱う）。利用者が足した規則（userrules）の検出は detect を通らないので対象外。
# 頭に 0x の付いた12文字以上の16進（Python の repr の番地「object at 0x000001958895D6D0」・C の16進の数）も捨てる
# （2026-11-07・デバッグのログ1つで 599 件。0x を書いた時点で16進の数で、番号ではない）
_HASH_LIKE = re.compile(
    r"(?<![0-9A-Za-z])(?:"
    r"(?:0[xX])?"
    r"(?:[0-9A-Fa-f]{32,}|[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})"
    r"|0[xX][0-9A-Fa-f]{12,}"
    r")(?![0-9A-Za-z])"
)
# _HASH_LIKE に当たる最も短い並び（「0x」＋12文字）。これより短い本文は並びを探さない
_HASH_LIKE_MIN = 14


def _drop_inside_hash(text: str, hits: list[Hit]) -> list[Hit]:
    """ハッシュ・UUID の並びの中で見つけた検出を除く（検出があるときだけ呼ばれる）。"""
    if len(text) < _HASH_LIKE_MIN:
        return hits  # 16進の並び・UUID の入らない短い本文
    spans = [m.span() for m in _HASH_LIKE.finditer(text) if not m.group().replace("-", "").isdigit()]
    if not spans:
        return hits
    starts = [s for s, _ in spans]
    out = []
    for h in hits:
        # 並びは位置の順で重ならないので、検出の始まりより前で最後に始まる並びだけを見ればよい
        i = bisect_right(starts, h.start) - 1
        if i >= 0 and h.end <= spans[i][1]:
            continue
        out.append(h)
    return out


# 本人確認書類の写しの判別（書類の名前, 書類の名前の語, 一緒に載る語, 一緒に載る語がいくつ要るか）。
# どの語も空白を除いた大文字の文字列で探す。被保険者証・個人番号カードは、案内の文書・申請書の見本にも
# 「記号」「有効期限」などが1つは並びやすいので、一緒に載る語を2つ求める
ID_DOCUMENT_RULES: tuple[tuple[str, tuple[str, ...], tuple[str, ...], int], ...] = (
    ("運転免許証", ("運転免許証",), ("公安委員会", "免許の条件", "交付"), 1),
    ("個人番号カード", ("個人番号カード",), ("有効期限", "電子証明書", "個人番号", "生年月日"), 2),
    ("在留カード", ("在留カード",), ("在留資格", "在留期間", "就労制限"), 1),
    ("健康保険証", ("被保険者証", "資格確認書"), ("保険者番号", "記号", "番号", "資格取得年月日"), 2),
    ("旅券", ("旅券", "PASSPORT"), ("発行年月日", "有効期間満了日", "DATEOFISSUE"), 1),
)


def detect_id_documents(text: str, from_ocr: bool) -> list[Hit]:
    """OCR で読んだ1項目（画像1枚・PDF の1ページ）の文字から、本人確認書類の写しを見分ける。

    書類の名前の語と、その書類に必ず載る語の組み合わせが揃えば、書類ごとに1件（値は書類の名前）を返す。
    OCR で読んだ文字でなければ（from_ocr=False）何も返さない。普通の文書の文字（申込書の見本・説明文の
    「運転免許証の交付を受けた…」）では写しと区別できないため。
    text は normalize 済みであること。位置は書類の名前の語の位置（見つからなければ 0）。
    """
    if not from_ocr or not text:
        return []
    # OCR は文字のあいだに空白を挟むことがあるので、空白を除いてから探す
    compact = re.sub(r"\s+", "", text).upper()
    hits: list[Hit] = []
    for doc, names, companions, need in ID_DOCUMENT_RULES:
        name = next((n for n in names if n in compact), None)
        if name is None:
            continue
        # 書類の名前の語そのものに含まれる語（「個人番号カード」の「個人番号」）は、名前の語を除いた残りで探す
        rest = compact.replace(name, "\0")
        found: list[str] = []
        # 長い語から探して、見つけた語は消す（「保険者番号」の中の「番号」を別の語として二重に数えない）
        for c in sorted(companions, key=len, reverse=True):
            if c in rest:
                found.append(c)
                rest = rest.replace(c, "\0")
        if len(found) < need:
            continue
        companion = "」「".join(found[:need])
        pos = text.upper().find(name)
        start, end = (pos, pos + len(name)) if pos >= 0 else (0, 0)
        hits.append(
            Hit(
                "id_document",
                Confidence.HIGH,
                doc,
                start,
                end,
                f"OCR の文字に「{name}」と「{companion}」があり、本人確認書類の写しとみなした",
            )
        )
    return hits


# Confidence.rank は呼ぶたびに辞書を作るので、検出の並べ替えでは表を引く
_CONF_RANK = {c: c.rank for c in Confidence}


def _dedupe(hits: list[Hit]) -> list[Hit]:
    """同じ種類で範囲が重なるものは、確からしさの高い1件にまとめる。"""
    hits.sort(key=lambda h: (-_CONF_RANK[h.confidence], h.start))
    if any(h.end <= h.start for h in hits):
        # 長さ 0 以下の範囲があると「開始順に並べて隣だけ見る」が成り立たない。実際には起きないが、念のため総当たりで
        kept: list[Hit] = []
        for h in hits:
            if any(k.pii_type == h.pii_type and h.start < k.end and k.start < h.end for k in kept):
                continue
            kept.append(h)
        kept.sort(key=lambda h: h.start)
        return kept
    # 残す検出は種類ごとに互いに重ならない。開始位置の順に並べた配列で二分探索すれば、重なりうるのは
    # 「開始が h.end より前で一番後ろのもの」だけ（終了も開始の順に増えるため）。総当たり（O(n²)）と結果は同じ
    kept = []
    starts: dict[str, list[int]] = {}
    ends: dict[str, list[int]] = {}
    for h in hits:
        ss = starts.setdefault(h.pii_type, [])
        es = ends.setdefault(h.pii_type, [])
        i = bisect_left(ss, h.end)  # 開始が h.end より前のものの数
        if i and es[i - 1] > h.start:
            continue
        j = bisect_left(ss, h.start)
        ss.insert(j, h.start)
        es.insert(j, h.end)
        kept.append(h)
    kept.sort(key=lambda h: h.start)
    return kept


# ---------------------------------------------------------------- マスク


def _mask_digits_keep_last(value: str, keep: int = 4) -> str:
    total = sum(c.isalnum() for c in value)
    shown = 0
    out = []
    for c in value:
        if c.isalnum():
            if total - shown <= keep:
                out.append(c)
            else:
                out.append("*")
            shown += 1
        else:
            out.append(c)
    return "".join(out)


def mask_value(pii_type: str, value: str) -> str:
    """レポートに載せる形へマスクする（元の値に戻せない程度に隠す）。"""
    v = value.strip()
    if not v:
        return v
    if pii_type == "email":
        local, _, domain = v.partition("@")
        return (local[:1] + "***@" + domain) if domain else v[:1] + "***"
    if pii_type == "postal_code":
        return re.sub(r"[0-9]", "*", v[::-1], count=4)[::-1]
    if pii_type in (
        "my_number",
        "credit_card",
        "bank_account",
        "drivers_license",
        "passport",
        "pension",
        "health_insurance",
        "residence_card",
        "resident_code",
        "employment_insurance",
        "member_id",
        "phone",
    ):
        return _mask_digits_keep_last(v, 4 if len(re.sub(r"[^0-9A-Za-z]", "", v)) > 6 else 2)
    if pii_type == "name":
        return v[:1] + "＊" * max(1, min(len(v) - 1, 6))
    if pii_type == "address":
        # 都道府県と市区町村までは残し、町名・番地は伏せる
        m = re.match(rf"((?:{PREFECTURES})?[^0-9０-９\s]{{0,10}}?[市区町村郡])", v)
        head = m.group(1) if m else v[:3]
        return head + "＊＊＊"
    if pii_type == "birthdate":
        m = re.match(r"(.*?(?:年|[/.\-]))", v)
        head = m.group(1) if m else v[:4]
        return head + re.sub(r"[0-9]", "*", v[len(head) :])
    if pii_type in ("gender", "age"):
        return "＊"
    if pii_type == "id_document":
        return v  # 書類の名前（「運転免許証」など）で、個人の値ではない
    if pii_type == "custom":
        # 利用者の規則に当たった値: 数字を含めば番号として末尾だけ残し、ほかは先頭1文字だけ残す。
        # 短い値は、残す分で値の大半（全部）が見えてしまうので、残さずに全部伏せる
        if any(c.isdigit() for c in v):
            n = sum(c.isalnum() for c in v)
            return _mask_digits_keep_last(v, 0 if n <= 4 else (2 if n <= 8 else 4))
        if len(v) <= 2:
            return "＊" * len(v)
        return v[:1] + "＊" * max(1, min(len(v) - 1, 8))
    return v[:2] + "＊" * max(1, min(len(v) - 2, 8))


RE_CONTEXT_DIGITS = re.compile(r"[0-9]")
RE_CONTEXT_WORD = re.compile(r"[一-龥々ぁ-んァ-ヶーｦ-ﾟA-Za-z]+")
# 文脈に残してよい語（見出し語・敬称・助詞など、個人を特定しない語）。これ以外の文字は伏せる
CONTEXT_KEEP = {
    "様",
    "殿",
    "御中",
    "さん",
    "の",
    "は",
    "が",
    "を",
    "に",
    "へ",
    "と",
    "で",
    "も",
    "や",
    "から",
    "まで",
    "TEL",
    "Tel",
    "tel",
    "FAX",
    "Fax",
    "fax",
    "Mail",
    "mail",
    "E",
    "No",
    "NO",
    "電話",
    "電話番号",
    "携帯",
    "携帯電話",
    "自宅",
    "勤務先",
    "連絡先",
    "住所",
    "現住所",
    "氏名",
    "名前",
    "お名前",
    "フリガナ",
    "ふりがな",
    "カナ",
    "番号",
    "メール",
    "メールアドレス",
    "生年月日",
    "誕生日",
    "年齢",
    "性別",
    "郵便番号",
    "口座",
    "口座番号",
    "普通",
    "当座",
    "預金",
    "銀行",
    "支店",
    "カード",
    "カード番号",
    "有効期限",
    "個人番号",
    "マイナンバー",
    "免許証",
    "免許証番号",
    "旅券",
    "パスポート",
    "年金",
    "基礎年金番号",
    "保険証",
    "被保険者番号",
    "記号",
    "在留カード",
    "住民票コード",
    "雇用保険",
    "社員番号",
    "職員番号",
    "会員番号",
    "顧客番号",
    "学籍番号",
    "患者番号",
    "病名",
    "本籍",
    "担当",
    "担当者",
    "宛先",
    "宛名",
    "契約者",
    "申込者",
    "保護者",
    "年",
    "月",
    "日",
    "丁目",
    "番地",
    "号",
    "都",
    "道",
    "府",
    "県",
    "市",
    "区",
    "町",
    "村",
    "郡",
}


def _mask_window(seg: str) -> str:
    """文脈の窓を伏せる。決まった語（見出し語・敬称など）だけを残し、それ以外の文字と数字はすべて伏せる。

    名前・カナ・町名は辞書で見分けきれないので、「伏せる語」ではなく「残す語」を決める方式にしている。
    """
    if not seg:
        return seg
    out = RE_EMAIL.sub("***@***", seg)

    def keep_or_mask(m: re.Match) -> str:
        # 漢字・かなの続いた並び（「東海林一郎さんの連絡先は」）から、残してよい語（2文字以上）だけを切り出し、
        # それ以外は伏せる。見出し語を含むだけの語を丸ごと残さない
        w = m.group(0)
        if w in CONTEXT_KEEP:
            return w
        parts = []
        pos = 0
        for k in RE_CONTEXT_KEEP_IN_WORD.finditer(w):
            if k.start() > pos:
                parts.append("＊" * min(k.start() - pos, 4))
            parts.append(k.group(0))
            pos = k.end()
        if pos < len(w):
            parts.append("＊" * min(len(w) - pos, 4))
        return "".join(parts)

    out = RE_CONTEXT_WORD.sub(keep_or_mask, out)
    return RE_CONTEXT_DIGITS.sub("*", out)


# 語の中から切り出してよい「残す語」（1文字の語は名前の一部と区別できないので切り出さない）
RE_CONTEXT_KEEP_IN_WORD = re.compile(
    "|".join(sorted((re.escape(w) for w in CONTEXT_KEEP if len(w) >= 2), key=len, reverse=True))
)


def masked_context(text: str, start: int, end: int, masked: str, width: int = 20) -> str:
    """検出箇所の前後の文脈。検出値はマスクに置き換え、窓の中の他の個人情報・数字・見出しの後の値も伏せる。"""
    before = _mask_window(text[max(0, start - width) : start])
    after = _mask_window(text[end : end + width])
    s = f"{before}【{masked}】{after}"
    return re.sub(r"\s+", " ", s).strip()

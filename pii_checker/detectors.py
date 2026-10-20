"""個人情報らしき値の検出規則。

- 本文の文字列からは正規表現＋検査数字（マイナンバー・Luhn）＋前後の手がかり語で検出する。
- 表形式（Excel・Access・CSV・Word の表）では、列見出しから列の意味を推定し、
  その列の値も検出に数える（「氏名」列の値は、辞書に無い名前でも拾える）。
- 返す値はマスク済み。生の値は呼び出し元へ返さない。
"""

from __future__ import annotations

import functools
import re
from bisect import bisect_left
import unicodedata
from dataclasses import dataclass
from typing import Callable

from .models import Confidence

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
}
HEADER_CONTAINS: list[tuple[re.Pattern[str], str]] = [
    # 「在留カード番号」はカード番号の語を、「雇用保険被保険者番号」は保険証の語（被保険者番号）を含むので先に見る。
    # 「雇用保険料」の列は番号ではない
    (re.compile(r"(在留カード番号|在留カードno)", re.I), "residence_card"),
    (re.compile(r"(雇用保険.{0,6}番号)"), "employment_insurance"),
    (re.compile(r"(住民票コード)"), "resident_code"),
    (re.compile(r"(マイナンバー|個人番号|mynumber)", re.I), "my_number"),
    (re.compile(r"(カード番号|クレジット|cardno|cardnumber)", re.I), "credit_card"),
    (re.compile(r"(口座番号|口座no|口座)", re.I), "bank_account"),
    (re.compile(r"(免許証番号|免許番号|免許証)"), "drivers_license"),
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
    (re.compile(r"(氏名|名前|フリガナ|ふりがな|ﾌﾘｶﾞﾅ|カナ氏名|姓名)", re.I), "name"),
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


def normalize(text: str) -> str:
    """全角英数・全角記号を半角へ寄せる（NFKC）。"""
    return unicodedata.normalize("NFKC", text)


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


@functools.lru_cache(maxsize=65536)
def header_category(header: str | None) -> str | None:
    """列見出しから、その列が何の個人情報かを推定する。当てはまらなければ None。"""
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
    if HEADER_NOT_PII.search(h.lower()):
        return None
    for pattern, category in HEADER_CONTAINS:
        if pattern.search(key):
            return category
    return None


def _header_value_hit(category: str, value: str) -> Hit | None:
    """見出しが個人情報の列の値を、検出として扱うかを決める。"""
    v = value.strip()
    if not v or len(v) > 300:
        return None
    if v.lower() in ("null", "none", "nan", "-", "ー", "なし", "無し", "n/a", "na", "0"):
        return None
    if len(v) <= 12 and header_category(v) is not None:
        return None  # 「住所」「電話」などの見出し語そのもの（横持ちの表の項目名）は値ではない
    conf = Confidence.MEDIUM
    digits = re.sub(r"[^0-9]", "", v)
    if category == "name":
        # 数字だけ・記号だけの値は名前ではない
        if not re.search(r"[A-Za-z一-龥ぁ-んァ-ヶ]", v):
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
        if RE_DATE.search(v) or re.fullmatch(r"(19|20)[0-9]{6}", digits) or re.match(r"^\d{4}-\d{2}-\d{2}", v):
            conf = Confidence.HIGH
        elif re.fullmatch(r"[0-9]{4,5}(\.0+)?", v) and 1000 < float(v) < 60000:
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
        if len(re.sub(r"[^0-9A-Za-z]", "", v)) < 4:
            return None
        conf = Confidence.HIGH if category != "health_insurance" else Confidence.MEDIUM
    elif category == "residence_card":
        if len(re.sub(r"[^0-9A-Za-z]", "", v)) < 8 or not digits:
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
    elif category in ("gender", "age"):
        conf = Confidence.LOW
    elif category == "sensitive":
        conf = Confidence.MEDIUM
    elif category == "address":
        if not re.search(r"[一-龥ぁ-んァ-ヶA-Za-z]", v):
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
    context_text = (normalize(header) + " " if header else "") + text
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


def _load_rust():
    """Rust 拡張を読み込んで、使える状態にして返す。使えなければ None（Python 版で動く）。"""
    import os

    if os.environ.get("PII_CHECKER_NO_RUST"):
        return None
    try:
        import pii_rs_detect as ext
    except ImportError:
        return None
    try:
        ext.set_mismatch_ranges(_rust_guard_ranges(ext))
    except Exception:  # noqa: BLE001 - 拡張が壊れていても、検出は Python 版で続ける
        return None
    return ext


_RUST = _load_rust()


def rust_enabled() -> bool:
    """本文の検出に Rust 拡張を使っているか。"""
    return _RUST is not None


def _detect_rust(text: str, header: str | None = None) -> list[Hit] | None:
    """detect の Rust 版。Python 版と同じ結果を返す。この本文を Rust で扱えないとき（語の文字の判定が
    Python と食い違う文字を含む）は None を返す。"""
    category = header_category(header)
    hdr = None
    hv = None
    if category:
        hv = _header_value_hit(category, text)
        if hv:
            hdr = (hv.pii_type, _CONFIDENCE_NUM[hv.confidence], hv.value, hv.rule)
    if not text or len(text) < 3:
        return [hv] if hv else []
    prefix = (normalize(header) + " ") if header else ""
    rows = _RUST.detect_body(text, prefix, category, hdr)
    if rows is None:
        return None
    return [Hit(t, _CONFIDENCE_BY_NUM[c], v, s, e, rule, needs) for (t, c, v, s, e, rule, needs) in rows]


def detect(text: str, header: str | None = None) -> list[Hit]:
    """文字列から個人情報らしきものを探す。header は表の列見出し（無ければ None）。

    text は呼び出し側で normalize 済みであること（位置がずれないように）。
    Rust 拡張があればそれで検出する（結果は Python 版と同じ）。無いとき・Rust で扱えない本文のときは Python 版。
    """
    if _RUST is not None:
        hits = _detect_rust(text, header)
        if hits is not None:
            return hits
    return _detect_py(text, header)


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

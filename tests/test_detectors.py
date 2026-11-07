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
        # git の pack・オブジェクトの名前（SHA-1）。12桁の数字の並びが偶然マイナンバーの検査数字に合う
        "pack-a123456789018bc0d1e2f3a4b5c6d7e8f9a0b1.pack",
        "a123456789018bc0d1e2f3a4b5c6d7e8f9a0b1",
        # SHA-256・MD5・UUID の中のカード番号・電話番号の形
        "sha256: 4111111111111111abcdef0123456789abcdef0123456789abcdef01234567",
        "md5 090123456780abcdef0123456789abcd",
        "id=0a1b2c3d-4e5f-4a6b-8c7d-123456789018",
        "0x4111111111111111abcdef0123456789abcdef01",
        # Python の repr の番地・頭に 0x の付いた16進の数（32文字に満たない）
        "<__main__.Foo object at 0x000001958895D6D0>",
        "0x123456789018",
        "mask=0X4111111111111111",
    ],
)
def test_nothing_inside_hash(text):
    """ハッシュ・UUID の16進の並びの中の数字は、確度を問わず何も拾わない（git の中のファイル名からの誤検出の修正）。"""
    assert types_of(text) == {}


def test_hash_in_long_text_next_to_japanese():
    """並びは検出を含む語の中だけで探す。日本語が隣り合う並び・長い本文の離れた所の並びも捨て、ほかの検出は残す。"""
    noise = "処理を確認しました。size=123 elapsed=0.5\n" * 2000
    text = (
        "電話 090-1234-5678\n"
        + noise
        + "メモ：0a1b2c3d-4e5f-4a6b-8c7d-123456789018です\n"
        + noise
        + "sha 4111111111111111abcdef0123456789abcdef0123456789abcdef01234567"
    )
    assert set(types_of(text)) == {"phone"}


@pytest.mark.parametrize(
    "text, expected",
    [
        # 16進の並びが短い・英字を含まない・前後に英数字が続くものは今までどおり拾う
        ("個人番号 123456789018 abcdef", "my_number"),
        ("a123456789018bc", "my_number"),
        # 0x の付かない16進・0x の前に英数字が続くもの・0x の後ろが12文字に満たないもの
        ("番地 000001958895D6D0", "my_number"),
        ("10x123456789018", "my_number"),
        ("0x1F 123456789018", "my_number"),
        ("カード 4111111111111111 sha 0123456789abcdef0123456789abcdef", "credit_card"),
    ],
)
def test_near_hash_still_found(text, expected):
    assert expected in types_of(text)


@pytest.mark.parametrize(
    "text, pii_type",
    [
        # 16進のダンプ（2桁ずつ）・区切りの位置がカードとして不自然な並び
        ("41 11 11 11 11 11 11 11", "credit_card"),
        ("411111111111-1111", "credit_card"),
        # SVG の座標・小数の並びの続き
        ('<path d="M0.07612 -0.4056,0.1 0.2"/>', "phone"),
        ("1.03-1234-5678", "phone"),
        ("03-1234-5678.25", "phone"),
        # 「様」「殿」で終わる普通の語・後ろへ続く語
        ("この画面の表示仕様", "name"),
        ("前回報告同様", "name"),
        ("京都の平安宮殿", "name"),
        ("帳票出力様式", "name"),
        ("生物の遺伝子多様性", "name"),
        ("野球名誉殿堂", "name"),
    ],
)
def test_shape_only_false_positive(text, pii_type):
    """実物の検査（ドライブ全体）で多かった、形だけ当たる誤検出を拾わない。"""
    assert pii_type not in types_of(text), types_of(text)


@pytest.mark.parametrize(
    "text, expected",
    [
        ("4111 1111 1111 1111", "credit_card"),
        ("4111-1111-1111-1111", "credit_card"),
        ("3782 822463 10005", "credit_card"),  # Amex の 4-6-5
        ("4111111111111111", "credit_card"),
        ("カード 41 11 11 11 11 11 11 11", "credit_card"),  # カードの語があれば区切りが変でも拾う
        ("カード番号 4111-1111-1111-1112", "credit_card"),  # 語つきの打ち間違い（低）は残す
        ("TEL.03-1234-5678", "phone"),
        ("+81.090-123-5678", "phone"),  # 国番号の後ろの「.」は小数ではない
        ("項目1.090-1234-5678", "phone"),  # 区切りのある携帯（確度 中）は、箇条書きの番号の後ろでも拾う
        ("3560 1234 5678 9012 347", "credit_card"),  # 19桁の 4-4-4-4-3
        ("大和田様相談の件", "name"),  # 「様相」は人の名前の後ろにも来る
        ("連絡先 03-1234-5678。", "phone"),
        ("山田健一様", "name"),
        ("佐藤和正様", "name"),
        ("鈴木一郎殿", "name"),
    ],
)
def test_shape_filter_keeps_real_ones(text, expected):
    assert expected in types_of(text)


@pytest.mark.parametrize(
    "text, pii_type",
    [
        # 固定長のレコード（競馬のデータ）の数字ばかりの並びの中の番号の形
        ("3132512031318081         123456789018   1770  2001-18.3 -4.2", "my_number"),
        ("13440610132708091336073  4111111111111111   2902  4501-19.4", "credit_card"),
        ("3132512031318081  09012345678   1770  2001-18.3", "phone"),
        # 小数の並びの途中の「4桁.4桁.4桁」
        ("88.9346.1563.4 104.1234.5678.9018.6295.1", "my_number"),
        # 年月日で始まる12桁（レースの ID・時刻つきのファイル名）
        ("csvs/race/202205020600.csv", "my_number"),
        # 英字の頭のついたコード（大量保有報告の保有者名の口座のコード）
        ("SCB HK PROP-JP123456789018（常任代理人）", "my_number"),
        ("JP123456789018", "my_number"),
        ("ID123456789018", "my_number"),  # 「NO」「ID」の直後に直接つなげたものも落ちる（文書に書いた見落とし）
        # 和暦の形: 英数字の直後の1文字の元号・小数へ続く・月日がありえない
        ("532637H 10.3-13.0 14.0", "birthdate"),
        ("H 10.3-13.0", "birthdate"),
        ("備考 H 15.3-99", "birthdate"),
        # 馬の歩き方の寸評
        ("両前バンテージ、交差歩様。右前蹄欠け。", "name"),
        # 1行に数が1つずつ並ぶ一覧（Perl の unicore の表・Excel のシートの XML を文にしたもの）で、
        # 4桁の行が3つ続いて改行をはさんだ12桁の形（2026-11-07 の見直し）
        # （手前の行が4桁だと先にそちらと組まれるので、手前は4桁でない数にする）
        ("V1678\n112\n1234\n5678\n9018\n1135\n", "my_number"),
        ("5926\n608\n1234\n5678\n9018\n", "my_number"),
        ("1234\n5678\n9018\n45379\n609\n", "my_number"),
        ("610\n090\n1234\n5678\n0\n", "phone"),
        # 16進のダンプの行の右の文字の欄（od・hexdump・xxd の出力をログに貼ったもの）
        ("0000030  36 32 34 4B 30 30 30 31 33 35 30 30 34 31 32 30  624K123456789018\n", "my_number"),
        ("0000020  2e 7c 31 30 33 32 32 30 32 36 38 30 30      .|123456789018\n", "my_number"),
        ("00000030: 3632 344b 3030 3031 3335 3030 3431 3230  624K123456789018\n", "my_number"),
        # od -Ax -tx1z（番地6桁）・xxd -g1（2桁の組）
        ("000030 36 32 34 4b 31 32 33 34 35 36 37 38 39 30 31 38  >624K123456789018<\n", "my_number"),
        ("00000030: 36 32 34 4b 31 32 33 34 35 36 37 38 39 30 31 38  624K123456789018\n", "my_number"),
        # 途中の番地から出したダンプ（hexdump -s 5・xxd -s 7・od の8進の番地）。前か後ろの行の番地が1行分ずれている
        (
            "0000005  61 62 3a 20 31 32 33 34 35 36 37 38 39 30 31 38  |ab: 123456789018|\n"
            "0000015  61 62 3a 20 31 32 33 34 35 36 37 38 39 30 31 38  |ab: 123456789018|\n",
            "my_number",
        ),
        (
            "0000025  34 31 31 31 31 31 31 31 31 31 31 31 31 31 31 31  |4111111111111111|\n"
            "0000035  78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78  |xxxxxxxxxxxxxxxx|\n",
            "credit_card",
        ),
        (
            "00000007: 6162 3a20 3132 3334 3536 3738 3930 3138  ab: 123456789018\n"
            "00000017: 6162 3a20 3132 3334 3536 3738 3930 3138  ab: 123456789018\n",
            "my_number",
        ),
        (
            "0000005  61 62 3a 20 31 32 33 34 35 36 37 38 39 30 31 38  >ab: 123456789018<\n"
            "0000025  61 62 3a 20 31 32 33 34 35 36 37 38 39 30 31 38  >ab: 123456789018<\n",
            "my_number",
        ),  # od の8進の番地（005 → 025 は 020 ずれ）
        # Wavefront OBJ の面・頂点の行で4桁の数が3つ空白で並ぶもの
        ("f 1074 1076 1075\nf 1234 5678 9018\n", "my_number"),
        # 固定長のレコードの0詰めの欄がつながった20桁以上の連続の隣（JRA-VAN のレース情報）
        (
            "新春0000E 120202000999000000999" + " " * 30 + "123456789018    00120000000480000003000000018000",
            "my_number",
        ),
        ("00120000000480000003000000018000   123456789018", "my_number"),
        ("ヒヤシ0000E 12A002000999000000999" + " " * 30 + "123456789018A1  0012000000048000000300000001", "my_number"),
        ("123456789018" + " " * 20 + "0" * 20, "my_number"),  # 20桁が窓（40字）にちょうど入る
        ("123456789018　　" + "0" * 20, "my_number"),  # 全角空白
        # URL のパスの中の語の無い12桁（配信の URL の「/public/<12桁>_<16進>」）
        ("https://cdn.example.com/public/123456789018_3fa9c2.jpg", "my_number"),
        ('src="http://192.0.2.10/a/b/123456789018"', "my_number"),
        ("見本 ftp://u:p@192.0.2.10:21/a-b_c~d/%E3%81%82/123456789018", "my_number"),
        # AWS の ARN のアカウント番号の欄（IAM のポリシー・CloudFormation・ログの JSON・URL のパスの中）
        ("arn:aws:iam::123456789018:role/admin", "my_number"),
        ('"RoleArn": "arn:aws:iam::123456789018:role/x"', "my_number"),
        ("arn:aws:lambda:ap-northeast-1:123456789018:function:hello", "my_number"),
        ("arn:aws-us-gov:sns:us-gov-west-1:123456789018:topic", "my_number"),
        ("https://console.aws.amazon.com/x/arn:aws:iam::123456789018:role/x", "my_number"),
    ],
)
def test_numeric_data_false_positive(text, pii_type):
    """実物の検査（2026-11-02 見直し）で多かった、数値のデータの中の番号・日付の形を拾わない。"""
    assert pii_type not in types_of(text), types_of(text)


@pytest.mark.parametrize(
    "text, expected",
    [
        ("123456789018", "my_number"),  # 番号だけの行・表のセル（前後が空）は今までどおり
        # 隣の数字の連続が19桁まで・20桁以上の連続との間に文字がある・連続が窓（40字）より遠い
        ("123456789018    1234567890123456789", "my_number"),
        ("123456789018 様 00120000000480000003000000018000", "my_number"),
        ("123456789018" + " " * 30 + "00120000000480000003000000018000", "my_number"),
        ("123456789018" + " " * 21 + "0" * 20, "my_number"),  # 1文字はみ出す
        ("123456789018 A12 " + "0" * 22, "my_number"),  # 英字の欄は数字1つまで
        ("番号JP 123456789018", "my_number"),  # 英字との間に空白があれば今までどおり
        ("あ123456789018い", "my_number"),  # 英字でない文字に挟まれたもの
        ("XJP123456789018", "my_number"),  # 大文字3字以上の続きは国の頭とみなさない
        ("Jp123456789018", "my_number"),  # 小文字の混ざる2字
        ("123456789018 order number " + "0" * 22, "my_number"),  # 語をはさむ
        ("123456789018\n" + "0" * 22, "my_number"),  # 行をまたがない
        # URL のクエリ・断片の値・URL の後ろの空白の先・「://」の手前が英字でないものは残す
        ("https://example.com/form?id=123456789018", "my_number"),
        ("https://example.com/p#123456789018", "my_number"),
        ("https://example.com/p 123456789018", "my_number"),
        ('"https://example.com/p" 123456789018', "my_number"),
        ("://example.com/123456789018", "my_number"),
        # URL の後ろに空白なしで続く文・CSV の欄・パスの引数・日本語を含むパス・URL でないパス
        ("https://example.com/、123456789018", "my_number"),
        ("詳細はhttps://example.com/です。123456789018", "my_number"),
        ("https://a.jp/x,山田太郎,123456789018", "my_number"),
        ("id,url,num\n1,https://a.jp/x,123456789018", "my_number"),
        ("https://a.jp/a;jsessionid=123456789018", "my_number"),
        ("https://a.jp/a&amp;x=123456789018", "my_number"),
        ("https://example.jp/日本語/123456789018/x", "my_number"),
        # URL のすぐ後ろに「:」「=」だけをはさんで書いた値（パスの一部でなく項目の値）
        ("https://a.jp/x:123456789018", "my_number"),
        ("https://a.jp/x=123456789018", "my_number"),
        ("https://a.jp/form/id=123456789018/next", "my_number"),
        ("mailto:a@b.jp 123456789018", "my_number"),
        ("C:\\Users\\123456789018\\a.txt", "my_number"),
        ("個人番号 https://a.jp/123456789018", "my_number"),  # 語があれば（語の届く近さなら）確度 高 で残る
        # ARN でも、アカウントの欄でないもの（S3 の空の欄の後の資源の名前）・後ろが「:」でないもの・
        # 「arn」の前に英数字が続くもの・語があるものは残す
        ("arn:aws:s3:::123456789018", "my_number"),
        ("arn:aws:iam::123456789018 role", "my_number"),
        ("xarn:aws:iam::123456789018:role/x", "my_number"),
        ("arn:gcp:iam::123456789018:role/x", "my_number"),
        ("個人番号 arn:aws:iam::123456789018:role/x", "my_number"),
        # 電話・カードの形は、隣に長い連続があっても今までどおり（語があっても同じ規則名で出るため）
        ("TEL 09012345678 ID 1234567890123456789012", "phone"),
        ("090-1234-5678 1234567890123456789012", "phone"),
        ("2001 1770 3132512031 山田 123456789018 様 2001-18.3 1770", "my_number"),  # 数字が多くても文字が混じる
        ("130505020600", "my_number"),  # 年月日の形でない12桁
        ("個人番号 202205020600", "my_number"),  # 語があれば年月日で始まっても拾う
        ("4111111111111111", "credit_card"),
        ("ID 1234 090-1234-5678 2026", "phone"),
        ("平成10年3月13日", "birthdate"),
        ("H10.3.13 入社", "birthdate"),
        ("S60.4.1", "birthdate"),
        ("山田美歩様", "name"),
        # 番号だけの行が並ぶ一覧・番号が2つ並ぶだけの行（前後の行は見ない・塊が足りない）
        ("09012345678\n09087654321\n09011112222\n", "phone"),
        ("123456789018\n123456789018\n123456789018\n", "my_number"),
        ("4111111111111111\n4111111111111111\n5500000000000004\n", "credit_card"),
        ("09012345678 09087654321", "phone"),
        ("1234567890,090-1234-5678,1234567890", "phone"),
        # 1行に番号を4つ以上並べた一覧（塊がどれも10桁以上なら数値のデータとみなさない）
        ("09012345678 09087654321 08011112222 07033334444", "phone"),
        # 空白区切りで並べた12桁は元の正規表現が拾わない（後ろに「空白＋数字」が続く形）のでコンマ区切りで確かめる
        ("123456789018,123456789018,123456789018,123456789018", "my_number"),
        ("09012345678,09087654321,08011112222,07033334444,09055556666", "phone"),
        ("田中はS60.4.1", "birthdate"),  # 1文字の元号の前が日本語の文字
        # 改行をまたぐ番号でも、前後の行が数だけの行でなければ残す（枠ごとに1行になった書類の写し）
        ("氏名 山田太郎\n1234\n5678\n9018\n以上", "my_number"),
        ("1234\n5678\n9018", "my_number"),
        ("個人番号\n1234\n5678\n9018\n608\n", "my_number"),  # 語があれば確度 高 で残る
        # ダンプ・OBJ に似ているが当たらない行（16進の組が8つ未満・英字の語で始まる行）
        ("0001  12 34 56  山田 123456789018\n", "my_number"),
        ("2024 11 07 12 30 45 10 20 担当 123456789018", "my_number"),  # 年＋2桁の数の並び（番地の形でない）
        ("202410 11 07 12 30 45 10 20 担当 123456789018", "my_number"),  # 年月の6桁＋2桁の組8つ（od -Ax は12以上）
        ("00000030: 36 32 34  担当 123456789018\n", "my_number"),  # xxd -g1 の形でも組が8つ未満
        ("no 1234 5678 9018\n", "my_number"),
        ("for 1234 5678 9018\n", "my_number"),
        ("個人番号 0000030  36 32 34 4B 30 30 30 31 33 35 30 30  123456789018", "my_number"),  # 語があれば残す
        # ダンプ・OBJ の行の次の行にある番号（判定は検出の始まる行だけを見る）
        ("0000030  36 32 34 4B 30 30 30 31 33 35 30 30 34 31 32 30  624K\n山田 123456789018\n", "my_number"),
        ("f 1074 1076 1075\n山田 1234 5678 9018\n", "my_number"),
        ("v 1.0 2.0 3.0\n担当 1234 5678 9018 です\n", "my_number"),
        # ダンプの形で始まる行でも、検出が行頭から 200 文字より後ろなら行を見ない（長い本文で遅くならないため）
        ("0000030  36 32 34 4B 30 30 30 31 33 35 30 30 34 31 32 30  " + "備考" * 100 + " 123456789018\n", "my_number"),
        # 番地の末尾が0でない行は、前後の行の番地がちょうど1行分ずれていなければ今までどおり
        ("0000005  61 62 3a 20 31 32 33 34 35 36 37 38 39 30 31 38  |ab: 123456789018|\n", "my_number"),
        (
            "0000005  61 62 3a 20 31 32 33 34 35 36 37 38 39 30 31 38  |ab: 123456789018|\n"
            "0000035  61 62 3a 20 31 32 33 34 35 36 37 38 39 30 31 38  |ab: 123456789018|\n",
            "my_number",
        ),  # 0x30 ずれ（16進でも8進でも1行分でない）
        (
            "0000005  61 62 3a 20 31 32 33 34 35 36 37 38 39 30 31 38  |ab: 123456789018|\n"
            "00000015  61 62 3a 20 31 32 33 34 35 36 37 38 39 30 31 38  |ab: 123456789018|\n",
            "my_number",
        ),  # 番地の桁の数が違う
    ],
)
def test_numeric_data_filter_keeps_real_ones(text, expected):
    assert expected in types_of(text), types_of(text)


def test_age_column_rejects_impossible_numbers():
    """見出しが「age」の列でも、年齢にありえない数（競馬の表の 1879 など）は年齢として拾わない。"""
    assert "age" not in types_of("1879", "age")
    assert "age" in types_of("35", "age")
    assert "age" in types_of("35歳", "年齢")
    assert "age" in types_of("30代", "年齢")


def test_email_column_needs_at_mark():
    """見出しが「メールアドレス」の列でも、@ の無い値はメールとして拾わない。"""
    assert "email" not in types_of("'utf-8'", "メールアドレス")
    assert "email" not in types_of("(x)", "メールアドレス")
    assert "email" in types_of("taro@example.jp", "メールアドレス")
    for v in ("taro＠example.jp", "taro[at]example.jp", "taro(at)example.jp", "taro アットマーク example.jp"):
        assert "email" in types_of(v, "メールアドレス"), v


@pytest.mark.parametrize(
    "text",
    [
        "z@FlaxRobertaPreLayerNormLayerCollection.setup.",  # 実在しない TLD（Python の識別子）
        "x-0@TestDataFramePlots.test_plot",  # 予約語の .test
        "6x@W.lC",  # 大文字小文字の混ざり（.lc は実在する）
        "2x@A13.BCA+",  # 実在しない TLD
        "@Inject x@org.example.annotation.Data",  # Java の注釈（.data は実在する）
        "\x00x@r.JO\x01",  # バイナリの断片（1文字のラベル＋大文字の TLD）
        "\x00x@builtins.BaseExceptionl\x01",  # 末尾の1文字を外しても TLD にならない
        "icon@2x.png",  # 画像の名前（.pn は国の TLD だが、拡張子の .png から1文字を外したもの）
        "logo@3x.zip",  # 倍率つきの名前（.zip は実在の TLD）
        # mypy のキャッシュ（.mypy_cache の *.db）の型・モジュールの名前の並び
        "click.utils(click.core@click.shell_completion(__future",  # 識別子の途中で .shell が切れる
        "\x04j_pytest.debugging.PytestPdbWrapper@151.do_continue\x03",  # 同じく .do
        "pandas._libs.missing:pandas._libs.tslibs@pandas.tseries.offsets2collections.abc,",  # ローカル部に「._」
        "tarfile.FilterError4tarfile.TarError8builtins.Exception@builtins.Ba\x01",  # 頭文字の大文字の TLD＋CamelCase
    ],
)
def test_email_needs_real_tld(text):
    """メールアドレスの形でも、TLD が実在しない・識別子の形のものは拾わない（実物の検査の生データ走査から）。"""
    assert "email" not in types_of(text)


@pytest.mark.parametrize(
    "text",
    [
        "taro.yamada@example.jp",
        "TARO@EXAMPLE.CO.JP",
        "taro@gmail.Com",  # 2つのラベルの頭文字の大文字は人の書き方もある
        "hanako@example.tokyo",
        "admin@corp.local",  # 社内の .local
        "Taro@Example.Org",
        "見積_taro@example.com_memo.txt",  # アドレス入りのファイル名（よく使う TLD は「_」が続いても残す）
        "taro@example.co.jp_2024.pdf",
        "hanako@example.shop_2024.pdf",  # 「_」の後が数字なら識別子の続きとみなさない
        "taro@example.de_memo.txt",  # 国の2文字の TLD は「_＋小文字」が続いても残す
        "hanako@mail.example.co.uk_a.txt",
        "taro@example.tokyo_memo.pdf",  # よく使う汎用の TLD も残す
        "taro@example.biz_list.csv",
        "user@example.org_Memo",  # 「_」の後が大文字なら識別子の続きとみなさない
        "taro_yamada@example.shop",  # ローカル部の「_」だけなら残す
        "john._smith@example.com",  # 「._」でもドメインが2段なら残す
        "Taro.Yamada@gmail.Com",  # 頭文字の大文字の並びは CamelCase ではない
    ],
)
def test_email_with_real_tld_kept(text):
    assert "email" in types_of(text)


@pytest.mark.parametrize(
    "text, value",
    [
        ("\x00taro@gmail.comz\x05", "taro@gmail.com"),
        ("(x@cpan.orgE\x01", "x@cpan.org"),
        ("<x@cam.ac.ukE\x01", "x@cam.ac.uk"),  # 国の TLD は、後ろが大文字で始まるときだけ
        ("メール taro@example.comTEL 03-1234-5678", "taro@example.com"),  # 改行の消えた本文
        ("info2@example.co.jpTel", "info2@example.co.jp"),
    ],
)
def test_email_trailing_type_byte_trimmed(text, value):
    """.pyc の中のアドレスの直後に次の文字列の型の1バイト（z・E など）が続いたものは、その1文字を外して拾う。"""
    hits = [h for h in detect(normalize(text)) if h.pii_type == "email"]
    assert [h.value for h in hits] == [value]
    assert text[hits[0].start : hits[0].end] == value


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


@pytest.mark.parametrize(
    "header, category",
    [
        ("Surname", "name"),
        ("Given Name", "name"),
        ("Family Name", "name"),
        ("FAMILY_NAME", "name"),
        ("Furigana", "name"),
        ("ADDR", "address"),
        ("Credit Card", "credit_card"),
        ("CC Number", "credit_card"),
        ("Individual Number", "my_number"),
        ("Driver's License", "drivers_license"),
        ("Drivers License No", "drivers_license"),
        ("Driver License", "drivers_license"),
    ],
)
def test_english_header_categories(header, category):
    """英語の見出しも、日本語の同じ意味の見出し（姓・名・フリガナ・住所・カード番号・個人番号・免許証）と同じ種類に読む。"""
    assert header_category(header) == category


@pytest.mark.parametrize("header", ["Kana", "Kana Input", "File Name", "Cell", "City", "Account No", "Acc Number"])
def test_english_headers_that_are_not_pii_columns(header):
    """足した語の近くの見出しで、個人情報の列としないもの（「Kana」はローマ字の名前（佳奈）にもあるので見出しにしない）。"""
    assert header_category(header) is None, header


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
    ],
)
def test_phone_word_right_before_value_beats_model_word(text):
    """電話の語が値のすぐ左（型番の語より値に近い）にあれば、型番の語では下げない。"""
    assert _conf_of(text, "phone") == ["medium"], types_of(text)


@pytest.mark.parametrize(
    "text",
    [
        "整理番号1 山田太郎 090-1234-5678",
        "受付番号5 鈴木花子 090-1234-5678",
        "伝票番号 12 携帯 090-1234-5678",
        "お問い合わせ番号 090-1234-5678",
        "追跡番号 090-1234-5678",
    ],
)
def test_roster_number_words_do_not_lower_phone(text):
    """名簿・受付票にも出る番号の語（整理番号・受付番号など）では、右の携帯を下げない。"""
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
        ("個人番号カード 裏面 個人番号 1234 5678 9018 生年月日 平成元年1月1日", "個人番号カード"),
        ("在留カード\n在留資格 留学\n在留期間 2年", "在留カード"),
        ("在留カード 就労制限の有無", "在留カード"),
        ("健康保険 被保険者証\n記号 12 番号 34\n保険者番号 01234567", "健康保険証"),
        ("被保険者証 記号 12 番号 34", "健康保険証"),
        ("資格確認書 保険者番号 06123456 資格取得年月日 令和5年4月1日", "健康保険証"),
        ("個人番号カード 氏名 山田太郎 生年月日 平成元年1月1日 有効期限 2030年", "個人番号カード"),
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
        "資格確認書 保険者番号 06123456",  # 被保険者証は一緒に載る語が2つ要る
        "被保険者証の記号を記入してください",
        "個人番号カード 裏面 個人番号 1234 5678 9018",
        "個人番号カード 有効期限の確認",  # 個人番号カードも2つ要る
        "個人番号カードの電子証明書の更新",
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
        "受付番号 0312345678",
        "整理番号 06-1234-5678",  # 固定電話は人の手がかりが無ければ 低
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


# ---------------------------------------------------------------- 網羅で通っていなかった分岐（T4・2026-11-07）


@pytest.mark.parametrize(
    "category, value, expected",
    [
        ("birthdate", "31138", "high"),  # Excel の日付シリアル値（1985/04/01）
        ("birthdate", "999", None),  # シリアル値の範囲の外
        ("birthdate", "60001", None),
        ("drivers_license", "A-1", None),  # 英数字が4つ未満
        ("drivers_license", "123456789012", "high"),
        ("passport", "TK1234567", "high"),
        ("health_insurance", "1-2", None),
        ("health_insurance", "12345678", "medium"),  # 保険証の番号は人を特定しにくいので 中
        ("residence_card", "AB12-34", None),  # 英数字が8つ未満
        ("residence_card", "ABCDEFGHIJ", None),  # 数字を含まない
        ("residence_card", "AB12345678CD", "high"),
        ("employment_insurance", "1234-567890-1", "high"),
        ("employment_insurance", "1234-567890", None),  # 11桁でない
        ("address", "---", None),  # 記号だけ
    ],
)
def test_header_value_hit_by_category(category, value, expected):
    from pii_checker.detectors import _header_value_hit

    hit = _header_value_hit(category, value)
    assert (hit.confidence.value if hit else None) == expected


def test_diners_card_prefix():
    from pii_checker.detectors import card_prefix_is_plausible

    assert card_prefix_is_plausible("30569309025904")  # 300〜305 で始まる14桁
    assert card_prefix_is_plausible("36227206271667")  # 36 で始まる14桁
    assert types_of("カード番号 30569309025904") == {"credit_card": "high"}


@pytest.mark.parametrize(
    "text",
    [
        "INFO job=1 id=36227206271667 size=5",
        '{"id": "4111111111111111"}',
        "user_id=4111111111111111",
        "request-id: 4111111111111111",
        "trace.ID=4111111111111111",
        "userId=4111111111111111",
        "sessionID:'4111111111111111'",
        "Id=4111111111111111",
        "ログ: id=4111111111111111",  # キーの前が空白で、その前の日本語との間に区切りがある
    ],
)
def test_card_shape_after_id_key_is_low(text):
    """値のすぐ前が ID の項目のキー（id=・"id":・user_id・userId）なら、識別番号とみなしてカード番号を 低 にする。"""
    assert _conf_of(text, "credit_card") == ["low"]
    assert any("ID の項目のキー" in h.rule for h in detect(normalize(text), None))


@pytest.mark.parametrize(
    "text, conf",
    [
        ("id 4111111111111111", "medium"),  # 区切りの「=」「:」が無い
        ("paid=4111111111111111", "medium"),  # 英単語の末尾の id
        ("valid: 4111111111111111", "medium"),
        ("ids=4111111111111111", "medium"),
        ("uuid=4111111111111111", "medium"),
        ("会員ID: 4111111111111111", "medium"),  # 日本語の項目名の ID はカード番号を書く欄でもある
        ("支払い ID: 4111111111111111", "medium"),
        ("id=\n4111111111111111", "medium"),  # キーと値の間に改行

        ("id=x 4111111111111111", "medium"),  # キーの値はほかにあり、カードの形はその後ろ
        ("card_id=4111111111111111", "high"),  # カードの語が先
        ("id=4111 1111 1111 1111", "high"),  # 4桁ずつの区切りは識別番号の書き方でない
        ("4111111111111111", "medium"),  # 陽性対照
    ],
)
def test_card_shape_without_id_key_is_unchanged(text, conf):
    """ID のキーでないもの・カードの語や4桁の区切りがあるものは今までどおり。"""
    assert _conf_of(text, "credit_card") == [conf]


def test_mask_value_of_blank_is_blank():
    assert mask_value("phone", "   ") == ""


@pytest.mark.parametrize("text", ["関係者様", "ご関係者様各位", "関係者殿", "関係者さんへ", "関 係者様"])
def test_role_word_starting_with_surname_is_not_name(text):
    # 「関係者」は姓の「関」で始まるだけの語（以前は「よくある姓＋敬称」で氏名 中 になっていた）
    assert "name" not in types_of(text)


@pytest.mark.parametrize("text", ["関口様", "関様へ", "田中部長殿", "関 太郎様"])
def test_surname_with_honorific_still_found(text):
    assert "name" in types_of(text)


@pytest.mark.parametrize(
    "text",
    [
        "楽天 約3,600円・松井 約12,600円",  # 証券会社の名前の後の「約」（2026-11-07・株のデータの報告）
        "楽天 当選 33（14.2%）／松井 当選 50（21.5%）",
        "Russell/野村 総合バリュー（配当込み）",
        "[松井 手数料](https://example.com/)",
        "マネックス 通常 0.1%・松井 最低 0.2%",
    ],
)
def test_surname_then_common_word_is_not_name(text):
    assert "name" not in types_of(text)


@pytest.mark.parametrize(
    "text", ["渡辺　勉 9 / 山田　直樹 4", "担当: 松井 実", "佐藤 計子", "佐藤 計", "田中 全", "田中 等"]
)
def test_surname_then_given_name_still_found(text):
    # 1字の名（勉・実・計・全・等）と、一般の語で始まるだけの名（計子）は残す
    assert "name" in types_of(text)


@pytest.mark.parametrize(
    "text",
    [
        "名前: 戦略の名前。",  # 関数の引数の説明（2026-11-07・株のデータの台本の docstring）
        "名前: 報告に出す名前。省略すると関数名。",
        "名前: 表示用の名前。",
    ],
)
def test_name_label_followed_by_description_is_not_name(text):
    assert "name" not in types_of(text)


def _label_name_confidences(text):
    """「氏名の見出し語＋名前」の検出の確度の一覧。"""
    return [
        h.confidence.name
        for h in detect(normalize(text))
        if h.pii_type == "name" and h.rule.startswith("氏名の見出し語＋名前")
    ]


@pytest.mark.parametrize(
    "text",
    [
        # 固定幅の表の見出し行で、右の列の見出しが個人情報の見出しの語
        "氏名      住所      電話",
        "氏名　　住所　　電話番号　　生年月日",
    ],
)
def test_name_label_beside_pii_header_word_is_not_name(text):
    assert _label_name_confidences(text) == []


@pytest.mark.parametrize(
    "text",
    [
        # 固定幅の表の見出し行の右の列の見出しで、次の行がデータの行（2026-11-07・株のデータの報告の文）
        "名前          年率    超過    最大DD\nベンチ      5.2%    0.0%   -12%",
        "名前      年率      超過\n\nA戦略     3.1%      1.2%",  # 空行をはさんだデータの行
        "名前　　年率　　超過\nベンチ　　5.2%　　0.0%",  # 全角空白の区切り
        "氏名      部署      内線\n山田太郎    営業部    1234",  # 数字が値の列より右にある
        # 帳票の次の行が同じ形になるもの（見出しの語でない項目名＋数字）は、本物の名前でもあるので 低 で残す
        "氏名    山田太郎    営業部\n入社日    2024/01/01    正社員",
        "氏名    山田太郎    フリガナ\nヤマダタロウ    1990    男",
    ],
)
def test_name_label_in_fixed_width_header_row_is_low(text):
    assert _label_name_confidences(text) == ["LOW"]


@pytest.mark.parametrize(
    "text",
    [
        "名前      山田太郎",  # セルが2つだけ
        "名前    山田太郎    年齢 40",  # 行に数字がある（値の入った帳票の行）
        "名前 山田太郎 営業部\n鈴木 3.1% 1.2%",  # 空白1つの区切りは表の列とみなさない
        "氏名    山田太郎    営業部\n電話    03-1234-5678    内線12",  # 次の行の最初のセルが見出しの語
        "氏名    山田太郎    営業部\n勤務地    東京    大阪",  # 次の行に数字が無い
        "氏名    山田太郎    営業部\nA    1    2    3",  # 次の行のセルの数が違う
        "氏名    山田太郎    営業部\n3年    課長    営業",  # 値の列から右のセルに数字が無い
        "お名前    山田太郎    様\n001    田中    東京",
        "氏名    山田太郎    営業部\n\n\n\n2024    1    2",  # 空行が3つ以上はさまる
        "名前      年率      超過",  # 次の行が無く、値が見出しの語でもない（見落とさない側）
    ],
)
def test_name_label_not_header_row_still_found(text):
    assert _label_name_confidences(text) == ["MEDIUM"]


def test_name_label_header_row_check_is_not_quadratic():
    # 改行の無い長い本文で、検出ごとに行の端を本文の全体から探さない（評価で 4 万回 4.9 秒だった）
    import time

    text = "名前    山田    " * 40000
    started = time.perf_counter()
    detect(text)
    assert time.perf_counter() - started < 3.0


@pytest.mark.parametrize(
    "text",
    [
        "名前: 鬼瓦権左衛門",
        # 値は空白の後の語まで取り込むので、後ろの「名前」の語で本物の名前ごと落とさない（評価で見つかった穴）
        "名前: 山田太郎 名前: 鈴木花子",
        "お名前: 山田太郎 お名前（ふりがな）",
        "氏名: 山田太郎 名前を変更した",
    ],
)
def test_name_label_with_real_name_still_found(text):
    assert "name" in types_of(text)


@pytest.mark.parametrize(
    "value",
    [
        "株式会社サンプル",
        "サンプルホールディングス",
        "(株)サンプル",
        "㈱サンプル",
        "サンプル銀行",
        "Sample Holdings Inc.",
        "Ｓａｍｐｌｅ Ｉｎｃ．",  # 全角も normalize の後で同じに読む
        "Sample Inc_",  # 「_」は語の切れ目
        "サンプルホールディングス（株） *",  # 銘柄の表の注の印（記号だけの語）は語に数えない
        "（株）Sample Technologies",  # 頭に法人格・後ろの語に漢字が無い
        "（株）サンプル カンパニー",
    ],
)
def test_company_in_name_column_is_not_name(value):
    # 株の表の英語の見出し「name」の列の銘柄名（2026-11-07）。法人格・会社の語のある値は会社名
    assert "name" not in types_of(value, header="name")


@pytest.mark.parametrize(
    "value",
    [
        "株式会社サンプル 山田様",
        "三井住友銀行 山田太郎",  # 会社名の後に人の名前が続くもの（最後の語に会社の語が無い）
        "株式会社サンプル 山田太郎",  # 頭に法人格があっても、後ろに漢字の名前が続けば残す
        "鬼瓦 権左衛門",
        "Taro Yamada",
        "Ann Incorporated",  # Inc は語の頭だけでは当たらない
        "証田 太郎",
    ],
)
def test_person_in_name_column_still_found(value):
    # 敬称つきの担当者・会社名の後の人の名前・法人格の無い名前は残す（「証田」は語の「証券」でないので当たらない）
    assert "name" in types_of(value, header="name")


@pytest.mark.parametrize(
    "text, absent",
    [
        ("口座残高 1234567円", "bank_account"),  # 口座の語の後ろが金額
        ("口座 支払 1234567", "bank_account"),  # 前に金額の語
        ("振込先 0009-123-1234567円", "bank_account"),
        ("振込先 請求 0009-123-1234567", "bank_account"),
        ("製造番号 09012345678", "phone"),  # 区切りの無い11桁が注文・製造の番号の語の後ろ
        ("電話 0120123456 TEL 0570123456", "phone"),  # 個人の電話ではない番号
        ("被保険者番号 ABCD-EFGH", "health_insurance"),  # 数字を含まない
        ("運転免許 有 個人番号 123456789018", "drivers_license"),  # 個人番号の判定に回す
    ],
)
def test_excluded_forms(text, absent):
    assert absent not in types_of(text)


def test_bare_mobile_and_model_word_are_low():
    assert types_of("番号 09012345678") == {"phone": "low"}  # 区切りも電話の語も無い11桁
    assert types_of("電話 型番 0312345678") == {"phone": "low"}  # 電話の語の後ろに型番の語
    assert types_of("運転免許 有 個人番号 123456789018") == {"my_number": "high"}

"""Rust 拡張 pii_rs_detect の検出が、Python 版（detectors._detect_py）と完全に同じ結果を返すことの試験。

拡張が無い（または環境変数 PII_CHECKER_NO_RUST が立っている）ときは全部飛ばす。
結果は (種類, 確度, 値, 開始, 終了, 規則名, 担当者の確認の要否) の列で比べる。
入力の例はすべて架空（住所は施設の公開所在地、番号は検査数字だけ合わせた作り物）。
"""

from __future__ import annotations

import random
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

from pii_checker import detectors  # noqa: E402

pytestmark = pytest.mark.skipif(not detectors.rust_enabled(), reason="Rust 拡張 pii_rs_detect を使っていない")

HEADERS = [
    None,
    None,
    "電話",
    "住所",
    "氏名",
    "生年月日",
    "カード番号",
    "マイナンバー",
    "TEL",
    "備考",
    "メール",
    "郵便番号",
]

# 規則ごとの代表的な入力（当たる形・当たらない形・手がかり語の有無）
SEEDS = [
    "携帯 090-1234-5678",
    "TEL：03-1234-5678",
    "(03)1234-5678",
    "+81 90-1234-5678",
    "+81-3-1234-5678",
    "株式会社サンプル 本社 03-1234-5678",
    "ABC Co., Ltd. Head Office +81-3-1234-5678",
    "zinc. tel +81-3-1234-5678",
    "自宅 03 1234 5678",
    "電話 0312345678",
    "型番 0312345678",
    "品番 090-1234-5678",
    "フリーダイヤル 0120-123-456 0800 1234 5678",
    "taro.yamada@example.jp",
    "info@example.co.jp 連絡先 support@example.com",
    "〒100-0005 東京都千代田区丸の内1-2-3",
    "100-0005 東京都千代田区丸の内1-2-3",
    "東京都千代田区丸の内 1-2-3 丸ビル",
    "住所 東京都千代田区丸の内六丁目十番一号",
    "勤務先 港高校 東京都港区芝5-1-1",
    "最寄駅 東京駅前 大阪市北区梅田3-1-1",
    "大阪府立病院 大阪府大阪市中央区1-1-1",
    "千代田区丸の内1-1-1",
    "東京都 千代田区 丸の内 1-1-1",
    "生年月日 1985年4月1日",
    "生年月日：昭和60年4月1日 平成7年12月31日",
    "S60.4.1 H7.12.31 令和3年5月6日",
    "個人番号 1234 5678 9018",
    "マイナンバー 123456789018 / 123456789012",
    "免許証番号 123456789012",
    "運転免許 有 個人番号 1234 5678 9018",
    "カード番号 4111-1111-1111-1111",
    "4111 1111 1111 1111 5555555555554444 378282246310005",
    "注文番号 4111111111111111 管理番号 3530111333300000",
    "口座番号 普通 1234567 残高 1,234,567円",
    "振込先 0009-123-1234567",
    "旅券番号 TK1234567 在留カード番号 AB12345678CD",
    "基礎年金番号 1234-567890 住民票コード 12345678901",
    "雇用保険被保険者番号 1234-567890-1 保険証 記号 12 番号 345",
    "会員番号：AB-12345 社員番号 E0001234 受注 2024年4月1日",
    "氏名：山田 太郎 氏名山田太郎 お名前 佐藤花子",
    "佐藤様 田中さん 山田 太郎 鈴木君 高橋殿 渡辺ちゃん",
    "田中一郎様 木村 次郎 伊藤　三郎",
    "病名：糖尿病 宗教 本籍：東京都",
    "S/N 4111111111111111 SN4111111111111111",
    "serial 03-1234-5678 JAN 4901234567894",
    "ISBN 978-4-00-000000-0 jan 0312345678",
    "ＴＥＬ：０３－１２３４－５６７８",
    "01234567890123456789012345678901234567890",
    "090-1234-56789 0120-1234-5678 090 1234 5678",
    "メール：a@b.c user+tag@sub.example.com a@@b.com @example.com",
    "令和6年4月1日 2024/04/01 2024-4-1 1999.12.31",
    "東京都千代田区丸の内1-2-3 03-1234-5678 090-1234-5678 test@example.jp 4111111111111111",
    "第一ビル 東京都港区芝公園1-5-25 東京タワー",
    "北海道札幌市中央区北1条西2丁目 青森県弘前市大字下白銀町1-1",
    "沖縄県那覇市おもろまち 123-4",
    "English text with no PII at all, 12345 and some numbers 2024.",
    "   ",
    "ab",
    "",
]


def rows(hits) -> list[tuple]:
    return [(h.pii_type, h.confidence.value, h.value, h.start, h.end, h.rule, h.needs_person) for h in hits]


def both(text: str, header: str | None):
    """(Python 版, Rust 版)。Rust 版が扱えない本文なら Rust 側は None。"""
    py = rows(detectors._detect_py(text, header))
    rust = detectors._detect_rust(text, header)
    return py, (rows(rust) if rust is not None else None)


def assert_same(text: str, header: str | None) -> bool:
    """同じ結果を確かめる。Rust で処理したなら True。"""
    py, rust = both(text, header)
    if rust is None:
        return False
    assert rust == py, f"text={text!r} header={header!r}"
    return True


def test_seeds_are_same():
    used = 0
    total = 0
    for seed in SEEDS:
        for header in HEADERS:
            text = detectors.normalize(seed)
            total += 1
            used += assert_same(text, header)
    # 作り物の入力に、Rust で扱えない文字は混ぜていない（全部 Rust で処理される）
    assert used == total


def test_seeds_find_something():
    """陽性対照: 入力の例が実際に検出されている（何も検出しない入力ばかりの比べで素通りしていない）。"""
    found = sum(len(detectors._detect_rust(detectors.normalize(s), None) or []) for s in SEEDS)
    assert found >= 60


def test_generated_valid_numbers_are_same():
    """検査数字が合うマイナンバー・カード番号を作り、手がかり語・区切りを変えて比べる。"""
    rnd = random.Random(20241021)
    my_numbers = []
    while len(my_numbers) < 8:
        n = str(rnd.randrange(10**10, 10**11 - 1))  # 先頭 11 桁。最後の 1 桁を足して検査数字を合わせる
        for last in "0123456789":
            if detectors.my_number_is_valid(n + last):
                my_numbers.append(n + last)
                break
    cards = []
    while len(cards) < 8:
        prefix = rnd.choice(["4", "51", "55", "6011", "3530"])
        n = prefix + "".join(rnd.choice("0123456789") for _ in range(15 - len(prefix)))
        for last in "0123456789":
            if detectors.luhn_is_valid(n + last):
                cards.append(n + last)
                break
    words = ["", "個人番号 ", "マイナンバー：", "免許証番号 ", "注文番号 ", "電話 ", "カード番号 ", "型番 ", "tel "]
    seps = ["", " ", "-"]
    for number in my_numbers + cards:
        for word in words:
            for sep in seps:
                s = sep.join([number[i : i + 4] for i in range(0, len(number), 4)])
                assert_same(word + s, rnd.choice(HEADERS))
                assert_same(f"{word}{s} 他 {word}{number}", None)


def test_headers_with_row_values():
    """列見出しつきの値（列見出しの検出と本文の検出が同居する）。"""
    pairs = [
        ("氏名", "山田 太郎"),
        ("住所", "東京都千代田区丸の内1-1-1"),
        ("住所", "港区役所 東京都港区芝公園1-5-25"),
        ("電話番号", "03-1234-5678"),
        ("電話番号", "090-1234-5678"),
        ("生年月日", "1985/04/01"),
        ("カード番号", "4111111111111111"),
        ("マイナンバー", "123456789018"),
        ("メールアドレス", "taro@example.jp"),
        ("郵便番号", "100-0005"),
        ("性別", "男"),
        ("年齢", "35"),
        ("備考", "病歴あり"),
    ]
    for header, value in pairs:
        assert_same(detectors.normalize(value), header)
        assert_same(detectors.normalize(value), None)


def test_fuzz_same():
    """入力を壊して（文字の挿入・削除・置換・つなぎ合わせ）比べる。乱数の種は固定。"""
    tricky = list(
        " 　\t\n\r\x0b\x0c\x1c\x1d\x1e\x1f\x85\xa0 ​　-ー－―‐−()（）,，、。|:：/.+@_%"
        "0123456789０１２３４５６７８９²①٣"
        "abcxyzABCXYZＡｂſKİıé゙́"
        "〒市区町村郡丁目番地号都道府県様殿さん君東京都大阪府港区千代田佐藤田中山田太郎"
        "電話携帯TELtelFAXfax生年月日カード番号口座免許型番品番co.,ltd.inc株式会社自宅"
        "昭和平成SHRT元年月日一二三十〇"
    )
    rnd = random.Random(20241021)
    pool = [detectors.normalize(s) for s in SEEDS if len(s) >= 3]
    used = 0
    n = 4000
    for _ in range(n):
        s = list(rnd.choice(pool))
        if rnd.random() < 0.3:
            s += list(rnd.choice([" ", "\n", "　", ""]) + rnd.choice(pool))
        for _ in range(rnd.randint(1, 4)):
            pos = rnd.randrange(len(s) + 1)
            op = rnd.random()
            if op < 0.4:
                s.insert(pos, rnd.choice(tricky))
            elif op < 0.7 and s:
                del s[min(pos, len(s) - 1)]
            elif s:
                s[min(pos, len(s) - 1)] = rnd.choice(tricky)
        text = "".join(s)
        if rnd.random() < 0.6:
            text = detectors.normalize(text)
        used += assert_same(text, rnd.choice(HEADERS) if rnd.random() < 0.3 else None)
    # 多くは Rust で処理される（食い違う文字を含む入力だけが Python へ回る）
    assert used > n * 0.6


# ---------------------------------------------------------------- 語の文字（\b・\w）の食い違い


def test_guard_ranges_cover_known_differences():
    """Python の \\w は ² ³ を語の文字とみなすが、Rust の \\w はみなさない（逆方向の例: 結合文字）。"""
    ranges = detectors._rust_guard_ranges(detectors._RUST)

    def covered(ch: str) -> bool:
        return any(lo <= ord(ch) <= hi for lo, hi in ranges)

    assert covered("²") and covered("³") and covered("́")
    assert not covered("a") and not covered("あ") and not covered("0") and not covered(" ") and not covered("\n")


def test_guard_ranges_are_exact():
    """範囲の外の文字は、\\w・\\s の判定が Python と Rust で一致する（範囲の内側は食い違うはずの文字）。"""
    ext = detectors._RUST
    ranges = detectors._rust_guard_ranges(ext)
    everything = "".join(map(chr, range(0x110000)))
    for kind, py_pattern in (("word", r"\w"), ("space", r"\s")):
        py_set = set(re.findall(py_pattern, everything))
        rust_set = {chr(c) for lo, hi in ext.class_ranges(kind) for c in range(lo, hi + 1)}
        different = py_set ^ rust_set
        in_ranges = {chr(c) for lo, hi in ranges for c in range(lo, hi + 1)}
        assert different <= in_ranges
    # 食い違う文字はごく一部（1 万 3 千字程度）。全体が範囲に入ってしまっていない
    assert sum(hi - lo + 1 for lo, hi in ranges) < 30000


def test_mismatch_chars_fall_back_to_python():
    for ch in ("²", "³", "¹", "́", "゙"):
        text = f"S/N{ch} 4111111111111111 注文番号 4111111111111111"
        assert detectors._detect_rust(text, None) is None
        assert rows(detectors.detect(text)) == rows(detectors._detect_py(text))
    # 見出し（normalize 後）の側にあっても Python へ回す
    assert detectors._detect_rust("電話 03-1234-5678", "電話́") is None


def test_word_boundary_all_unicode_sweep():
    """語の境目（\\b）の前後に、Unicode の全ての 1 文字を置いて比べる（食い違う文字は Python へ回る）。

    全部（約 110 万文字）だと数分かかるので、食い違う文字の範囲の全部と、ほかは 97 字おきに取る。
    全部の総当たりは、拡張を作り直したときに手で流すこと（docs/開発者向け.md）。
    """
    card = "4111111111111111"
    templates = [
        "S/N{c} " + card,
        "SN{c}" + card,
        "{c}inc. 03-1234-5678",
        "{c}co.,ltd 03-1234-5678",
        "{c}head office 03-1234-5678",
        "x{c}HEADQUARTERS 03-1234-5678",
        "03-1234-5678 {c}inc.",
        "ABC{c}Corporation 03-1234-5678 TEL",
    ]
    ranges = detectors._rust_guard_ranges(detectors._RUST)
    cps = {c for lo, hi in ranges for c in range(lo, hi + 1)} | set(range(0, 0x110000, 97))
    cps |= set(range(0x80)) | {0x17F, 0x212A, 0x130, 0x131, 0x2028, 0x2029, 0xFF21, 0xFF41}
    used = 0
    for cp in sorted(cps):
        if 0xD800 <= cp < 0xE000:
            continue
        for t in templates:
            used += assert_same(t.format(c=chr(cp)), None)
    assert used > 0


def test_case_folding_matches_python():
    """re.I の大文字小文字の畳み込み（ſ・K・ı・İ など）が、Python と Rust で同じ文字に当たる。"""
    import export_rust_patterns as export

    ext = detectors._RUST
    everything = "".join(chr(c) for c in range(0x110000) if not 0xD800 <= c < 0xE000)
    sources = [c for c in "abcdefghijklmnopqrstuvwxyz"] + [
        "[a-z]",
        "[A-Z]",
        "[A-Za-z]",
        "[A-Za-z0-9._%+\\-]",
        "[a-z0-9]",
    ]
    for src in sources:
        py = re.findall(src, everything, re.I)
        rust = ext.findall(export.fix_turkic_i(src), True, everything)
        assert py == rust, src


def test_no_rust_env_disables(monkeypatch):
    """PII_CHECKER_NO_RUST が立っていれば拡張を読み込まない。"""
    monkeypatch.setenv("PII_CHECKER_NO_RUST", "1")
    assert detectors._load_rust() is None

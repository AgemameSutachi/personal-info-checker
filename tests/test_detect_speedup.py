"""検出の高速化（正規表現の先読み・_dedupe の走査）が、元の実装と同じ結果を返すことの試験。

元の式・元の実装は、この試験の中に写してある（速くする前のもの）。
"""

from __future__ import annotations

import random
import re

import pytest

from pii_checker import detectors
from pii_checker.detectors import Hit, SURNAMES
from pii_checker.models import Confidence

# ---- 速くする前の式（そのまま写したもの） ----
OLD_NAME_HONORIFIC = re.compile(rf"(?<![一-龥])(?:{SURNAMES})[ 　]?[一-龥々]{{0,3}}(?:様|殿|さん|君|くん|ちゃん)")
OLD_NAME_SPACED = re.compile(rf"(?<![一-龥])(?:{SURNAMES})[ 　][一-龥々]{{1,3}}(?![一-龥々])")
OLD_NAME_HONORIFIC_ANY = re.compile(r"(?<![一-龥々])([一-龥々]{3,5})(?:様|殿)(?![方])")


def old_dedupe(hits: list[Hit]) -> list[Hit]:
    """速くする前の _dedupe（全件を総当たりで比べる）。"""
    hits.sort(key=lambda h: (-h.confidence.rank, h.start))
    kept: list[Hit] = []
    for h in hits:
        if any(k.pii_type == h.pii_type and h.start < k.end and k.start < h.end for k in kept):
            continue
        kept.append(h)
    kept.sort(key=lambda h: h.start)
    return kept


SURNAME_LIST = SURNAMES.split("|")
GIVEN_KANJI = "太郎花子一二三健司美咲々陽翔蓮龥一鈴木林原"
PIECES = (
    SURNAME_LIST
    + ["様", "殿", "さん", "君", "くん", "ちゃん", "方", " ", "　", "  ", "\n", "、", "a", "1", "氏名", "お名前"]
    + ["々", "ぁ", "ア", "龥", "龦", "一", "丁"]
)


def random_text(rnd: random.Random) -> str:
    out = []
    for _ in range(rnd.randint(0, 14)):
        r = rnd.random()
        if r < 0.55:
            out.append(rnd.choice(PIECES))
        elif r < 0.85:
            out.append("".join(rnd.choice(GIVEN_KANJI) for _ in range(rnd.randint(1, 5))))
        else:
            out.append(
                rnd.choice(["佐藤 太郎様", "山田　花子", "原田 花", "木佐藤 太郎", "大久保 一郎さん", "佐藤太郎君"])
            )
    return "".join(out)


def spans(it) -> list[tuple[int, int, str]]:
    return [(m.start(), m.end(), m.group(0)) for m in it]


FIXED_CASES = [
    "",
    "佐藤 太郎",
    "佐藤　太郎様",
    "木佐藤 太郎",  # 直前が漢字なら当たらない
    "A佐藤 太郎",
    "佐藤 太郎郎郎",  # 名が4字以上なら当たらない
    "佐藤 太郎々",
    "佐藤 佐藤 太郎",
    "山田 山田 花子さん",
    "林 太郎林 一郎",
    "原田 花、原 田中",
    "原田様原様",
    "田中さん田中くん田中ちゃん田中君田中殿",
    "佐藤花子様\n鈴木 一郎",
    "氏名佐藤 太郎",
    "漢字三字様",
    "漢字三字様方",
    "各位殿",
    "佐藤　太郎",
    "龥佐藤 太郎",  # 直前が範囲の最後の漢字
    "龦佐藤 太郎",  # 範囲の外
    "丁佐藤 太郎",
]


@pytest.mark.parametrize("text", FIXED_CASES)
def test_name_regex_fixed_cases(text):
    assert spans(detectors.iter_name_honorific(text)) == spans(OLD_NAME_HONORIFIC.finditer(text))
    assert spans(detectors.iter_name_spaced(text)) == spans(OLD_NAME_SPACED.finditer(text))


def test_name_regex_random_equivalence():
    rnd = random.Random(20261020)
    n_hit = 0
    for _ in range(30000):
        text = random_text(rnd)
        old_h = spans(OLD_NAME_HONORIFIC.finditer(text))
        old_s = spans(OLD_NAME_SPACED.finditer(text))
        assert spans(detectors.iter_name_honorific(text)) == old_h, repr(text)
        assert spans(detectors.iter_name_spaced(text)) == old_s, repr(text)
        n_hit += bool(old_h) + bool(old_s)
    # 陽性対照: 当たる入力が十分に含まれていること（当たらない入力だけでは何も確かめていない）
    assert n_hit > 2000


def test_name_regex_every_surname_and_boundary():
    """全部の姓について、敬称つき・空白つき・直前が漢字・直前が仮名の4形を突き合わせる。"""
    for s in SURNAME_LIST:
        for text in (
            f"{s}様",
            f"{s} 太郎",
            f"{s}　花子さん",
            f"木{s} 太郎",
            f"あ{s} 太郎様",
            f"{s}{s} 太郎",
            f"{s} {s}",
        ):
            assert spans(detectors.iter_name_honorific(text)) == spans(OLD_NAME_HONORIFIC.finditer(text)), text
            assert spans(detectors.iter_name_spaced(text)) == spans(OLD_NAME_SPACED.finditer(text)), text


def test_honorific_any_prefilter_is_equivalent():
    """「様」「殿」が無い文字列では RE_NAME_HONORIFIC_ANY は当たらない（飛ばしてよい）。"""
    rnd = random.Random(7)
    for _ in range(5000):
        text = random_text(rnd)
        if "様" not in text and "殿" not in text:
            assert not OLD_NAME_HONORIFIC_ANY.search(text)


# ---- ボリュームの調べ（フォルダ単位で覚える） ----


@pytest.mark.skipif(__import__("os").name != "nt", reason="Windows のボリューム情報の試験")
def test_volume_root_is_cached_per_folder(tmp_path):
    from pii_checker import engine

    engine._volume_root_of_dir.cache_clear()
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    files = [a / "1.txt", a / "2.txt", a / "3.txt", b / "1.txt"]
    for f in files:
        f.write_text("x", encoding="utf-8")
    results = {engine._volume_has_streams(str(f)) for f in files}
    info = engine._volume_root_of_dir.cache_info()
    assert info.misses == 2  # フォルダの数（ファイルの数ではない）だけ調べる
    assert info.hits == 2
    assert len(results) == 1
    # 上限つき（フォルダが何万あっても覚えるのは上限まで）
    assert engine._volume_root_of_dir.cache_info().maxsize is not None


# ---- _dedupe ----


def random_hits(rnd: random.Random) -> list[Hit]:
    types = ["name", "address", "phone", "email"]
    hits = []
    for i in range(rnd.randint(0, 40)):
        start = rnd.randint(0, 60)
        length = rnd.choice([1, 1, 2, 3, 5, 8, 15]) if rnd.random() > 0.03 else 0  # 長さ 0 も混ぜる
        hits.append(
            Hit(
                rnd.choice(types),
                rnd.choice(list(Confidence)),
                f"v{i}",
                start,
                start + length,
                f"r{i}",
            )
        )
    return hits


def snapshot(hits: list[Hit]) -> list[tuple]:
    return [(h.pii_type, h.confidence, h.value, h.start, h.end, h.rule) for h in hits]


def test_dedupe_random_equivalence():
    rnd = random.Random(20261020)
    for _ in range(20000):
        hits = random_hits(rnd)
        expected = snapshot(old_dedupe([Hit(**h.__dict__) for h in hits]))
        got = snapshot(detectors._dedupe([Hit(**h.__dict__) for h in hits]))
        assert got == expected


def test_dedupe_random_equivalence_large():
    """件数が多い入力（行をまとめて検査したときの形）でも同じ。"""
    rnd = random.Random(99)
    for _ in range(30):
        hits = []
        for i in range(rnd.randint(500, 1500)):
            start = rnd.randint(0, 20000)
            hits.append(
                Hit(
                    rnd.choice(["name", "address", "phone"]),
                    rnd.choice(list(Confidence)),
                    f"v{i}",
                    start,
                    start + rnd.randint(1, 30),
                    "r",
                )
            )
        expected = snapshot(old_dedupe([Hit(**h.__dict__) for h in hits]))
        got = snapshot(detectors._dedupe([Hit(**h.__dict__) for h in hits]))
        assert got == expected
        assert len(expected) > 50


# ---- 列見出しの判定の下見（_HEADER_ANY・cannot_be_header）と、明細の枠の数え方 ----


def old_header_category(header):
    """速くする前の header_category（下見なしで、正規表現を順に当てる）。"""
    if not header:
        return None
    h = detectors.normalize(str(header)).strip()
    if not h or len(h) > 40:
        return None
    core = detectors.RE_ANNOTATION.sub("", h).strip()
    if core:
        h = core
    key = re.sub(r"[\s_\-・()（）\[\]【】:：]", "", h).lower()
    if key in detectors.HEADER_EXACT:
        return detectors.HEADER_EXACT[key]
    if detectors.HEADER_NOT_PII.search(h.lower()):
        return None
    for pattern, category in detectors.HEADER_CONTAINS:
        if pattern.search(key):
            return category
    return None


HEADER_PIECES = (
    list(detectors.HEADER_EXACT)
    + [w for p, _ in detectors.HEADER_CONTAINS for w in re.findall(r"[^()|?.{}0-9,\\]+", p.pattern)]
    + ["ＴＥＬ", "℡", "〒", "Ｅメール", "MAIL", "Address", "e-Mail", "No.", "番号", "名", "(必須)", "（任意）"]
    + ["1", "2024", "-", "/", ":", " ", "　", "_", "・", "a", "Z", "ｱ", "あ", "漢", "会社名", "所在地", "本社"]
)


def test_header_category_prefilter_is_equivalent():
    rng = random.Random(20261021)
    samples = list(HEADER_PIECES)
    for _ in range(20000):
        samples.append("".join(rng.choice(HEADER_PIECES) for _ in range(rng.randint(1, 4))))
    detectors.header_category.cache_clear()
    for s in samples:
        assert detectors.header_category(s) == old_header_category(s), s
        if detectors.cannot_be_header(s):
            assert old_header_category(s) is None, s


@pytest.mark.parametrize(
    "text, expected",
    [
        ("12345678901", True),
        ("1990-04-01", True),
        ("03-1234-5678", True),
        ("(7桁)", False),
        ("TEL", False),
        ("tel:", False),
        ("〒", False),
        ("℡", False),  # NFKC で TEL になる
        ("１２３", False),  # 全角は ASCII ではないので本体で判定する
        ("", True),
    ],
)
def test_cannot_be_header(text, expected):
    assert detectors.cannot_be_header(text) is expected
    if expected:
        assert old_header_category(text) is None


def test_has_room_matches_recount():
    """明細の枠の数（_has_room が持つ件数）が、明細を数え直した結果といつも一致する（確度の引き上げ・待ちの解決を含む）。"""
    from pii_checker.engine import Collector
    from pii_checker.models import ItemResult, Status

    item = ItemResult(path="t", kind="", status=Status.PENDING)
    col = Collector(item, 3)

    def check():
        for t in ("address", "name", "phone", "birthdate"):
            for c in Confidence:
                n = sum(1 for f in item.findings if f.pii_type == t and f.confidence == c)
                assert col._has_room(t, c) is (n < 3), (t, c, n)

    for i in range(6):
        col.add_text(f"東京都千代田区丸の内9-9-{i + 1}", f"A{i}", header="住所")  # 人の手がかり待ち（低）
        check()
    col.add_text("03-1234-5678", "P1")
    check()
    col.add_text("鬼瓦 権左衛門", "N1", header="氏名")  # 人の手がかり → 待ちの住所を 中 へ
    check()
    for i in range(6):
        col.add_text(f"東京都千代田区丸の内9-9-{i + 1}", f"B{i}", header="住所")
        check()
    col.finish()
    check()
    assert any(f.confidence == Confidence.MEDIUM and f.pii_type == "address" for f in item.findings)


def test_header_category_prefilter_every_char():
    """1文字ずつの総当たり（文字だけ・英字の前後に付けた形）でも、下見つきの判定が元と同じ。"""
    detectors.header_category.cache_clear()
    for cp in range(0x20, 0x10000):
        if 0xD800 <= cp <= 0xDFFF:
            continue
        ch = chr(cp)
        for s in (ch, "x" + ch, ch + "tel"):
            assert detectors.header_category(s) == old_header_category(s), hex(cp)
            if detectors.cannot_be_header(s):
                assert old_header_category(s) is None, hex(cp)
    detectors.header_category.cache_clear()


def _rows(hits):
    return [(h.pii_type, h.confidence, h.value, h.start, h.end, h.rule, h.needs_person) for h in hits]


SHORT_SAMPLES = [
    "男",
    "世帯主",
    "佐藤太郎",
    "090-1234-5678",
    "1950-03-04",
    "123456789018",
    "〒100-0005",
    "東京都千代田区丸の内9-9-9",
    "",
    "ab",
    "null",
]
SHORT_HEADERS = [None, "氏名", "電話番号", "生年月日", "住所", "性別", "個人番号", "備考"]


def test_short_cache_matches_uncached(monkeypatch):
    """短い本文の覚え書きを通しても、1回目・2回目とも覚え書きなしと同じ検出になる。"""
    monkeypatch.setattr(detectors, "_short_cache", {})
    for _ in range(2):
        for text in SHORT_SAMPLES:
            for header in SHORT_HEADERS:
                norm = detectors.normalize(text)
                assert _rows(detectors.detect(norm, header)) == _rows(detectors._detect_uncached(norm, header)), (
                    text,
                    header,
                )
    assert detectors._short_cache, "短い本文が覚えられていない"


def test_short_cache_returns_fresh_hits(monkeypatch):
    """呼び出し側が Hit を書き換えても（add_text は規則名に追記し確度を変える）、次に返す結果は変わらない。"""
    monkeypatch.setattr(detectors, "_short_cache", {})
    first = detectors.detect("090-1234-5678", "電話番号")
    assert first
    expected = _rows(first)
    for h in first:
        h.rule += "（書き換え）"
        h.confidence = Confidence.LOW
        h.needs_person = True
    second = detectors.detect("090-1234-5678", "電話番号")
    assert _rows(second) == expected
    assert all(a is not b for a, b in zip(first, second))


def test_short_cache_skips_long_text_and_is_bounded(monkeypatch):
    """長い本文は覚えない。覚え書きは上限に達したら空にするので、上限を超えて増えない。"""
    monkeypatch.setattr(detectors, "_short_cache", {})
    monkeypatch.setattr(detectors, "_SHORT_CACHE_LIMIT", 5)
    long_text = "連絡先は 090-1234-5678 です。" + "あ" * detectors._SHORT_CACHE_LEN
    detectors.detect(long_text)
    assert not detectors._short_cache
    for i in range(23):
        detectors.detect(f"値{i}")
        assert len(detectors._short_cache) <= 5


def test_short_cache_skips_second_detection(monkeypatch):
    """同じ短い本文・見出しの2回目は検出をやり直さない（覚え書きを読んでいる）。覚えるタプルは Hit の全フィールド。"""
    import dataclasses

    assert len(dataclasses.fields(Hit)) == 7, "Hit のフィールドが変わった: detect の覚え書きで写す並びも直すこと"
    monkeypatch.setattr(detectors, "_short_cache", {})
    calls = []
    real = detectors._detect_uncached
    monkeypatch.setattr(detectors, "_detect_uncached", lambda t, h: calls.append(t) or real(t, h))
    detectors.detect("090-1234-5678", "電話番号")
    detectors.detect("090-1234-5678", "電話番号")
    assert len(calls) == 1
    detectors.detect("090-1234-5678", None)  # 見出しが違えば別に検出する
    assert len(calls) == 2


def test_normalize_premap_matches_nfkc():
    """全角英数・記号を先に写す normalize が、NFKC そのものと同じ結果を返す。
    基本多言語面の全部の文字を、写す文字（全角の英字・記号・空白）の前後に置いて確かめる（合成・並べ替えの相手になる文字も含む）。"""
    import unicodedata

    nfkc = lambda s: unicodedata.normalize("NFKC", s)  # noqa: E731
    for cp in range(0x10000):
        if 0xD800 <= cp <= 0xDFFF:
            continue
        c = chr(cp)
        for s in (c + "Ａ", "Ａ" + c, "：" + c + "\u0301", c + "　\u3099", "ｶ" + c + "Ｚ"):
            assert detectors.normalize(s) == nfkc(s), (hex(cp), s)


def test_normalize_premap_random_mixes():
    """写す文字・半角カナ・濁点・結合文字・互換文字・ハングルの字母を混ぜた乱択の本文で、NFKC と同じ結果を返す。"""
    import unicodedata

    pool = (
        [chr(c) for c in range(0xFF01, 0xFF5F)]
        + ["\u3000", "ｶ", "ﾞ", "ﾟ", "ﾊ", "\u3099", "\u309a", "\u0301", "\u0323", "\u0308", "①", "㍻", "ﬁ", "Å"]
        + ["\u1100", "\u1161", "\u11a8", "か", "は", "A", "a", " ", "佐", "藤", "ー", "－", "～", "〜", "、", "。"]
    )
    rng = random.Random(20261021)
    for _ in range(30000):
        s = "".join(rng.choice(pool) for _ in range(rng.randint(1, 30)))
        assert detectors.normalize(s) == unicodedata.normalize("NFKC", s), s

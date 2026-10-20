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

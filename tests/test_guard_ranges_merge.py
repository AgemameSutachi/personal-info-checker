"""Python と Rust で文字の判定が食い違う範囲を、語の文字と空白の2種からまとめるところの試験。

実物の拡張では2種の範囲が重ならず、つなぐ処理を通らないので、範囲を返す偽の拡張で確かめる（拡張が無くても走る）。
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pii_checker import detectors  # noqa: E402

_EVERYTHING = "".join(map(chr, range(0x110000)))


def _py_ranges(pattern: str) -> list[tuple[int, int]]:
    return [(m.start(), m.end() - 1) for m in re.finditer(pattern, _EVERYTHING)]


class _FakeExt:
    """語の文字から A〜Z を抜き、空白に [ と P を足した表を返す（Python と食い違うのは A〜Z・[・P）。"""

    def class_ranges(self, kind):
        if kind == "word":
            out = []
            for lo, hi in _py_ranges(r"\w+"):
                if lo <= 0x41 and 0x5A <= hi:  # A〜Z を含む範囲を、その前後に割る
                    out += [r for r in ((lo, 0x40), (0x5B, hi)) if r[0] <= r[1]]
                else:
                    out.append((lo, hi))
            return out
        return sorted(_py_ranges(r"\s+") + [(0x50, 0x50), (0x5B, 0x5B)])  # P は A〜Z の中・[ は Z の隣


def test_overlapping_and_adjacent_ranges_are_joined():
    """語の文字の食い違い A〜Z と、空白の食い違い P（重なる）・[（隣り合う）を1つの範囲にまとめる。"""
    assert detectors._rust_guard_ranges(_FakeExt()) == [(0x41, 0x5B)]

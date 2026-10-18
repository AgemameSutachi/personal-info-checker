"""文字コードの判定と、バイナリからの文字列の拾い出し（生データ走査）。"""

from __future__ import annotations

import codecs
import math
import re
from collections import Counter
from typing import Iterator

# 生データ走査で「文字として意味のある並び」とみなす文字
_GOOD = r"0-9A-Za-z　-ヿ一-鿿！-ﾟ@._%+\-:/()（）〒・、。 "
RE_GOOD_RUN = re.compile(rf"[{_GOOD}]{{4,}}")
RE_HAS_SIGNAL = re.compile(r"[0-9@぀-ヿ一-鿿]")


def decode_text(data: bytes) -> tuple[str, str]:
    """テキストファイルのバイト列を文字列にする。戻り値は（文字列, 使った文字コード）。

    BOM → UTF-8 → ISO-2022-JP（エスケープがあるとき）→ cp932 → EUC-JP → chardet の順に試し、
    どれも厳密に通らなければ cp932 で置換しながら読む（読めた部分は検査する）。
    """
    if data.startswith(codecs.BOM_UTF8):
        return data[3:].decode("utf-8", errors="replace"), "utf-8-sig"
    if data.startswith(codecs.BOM_UTF16_LE) or data.startswith(codecs.BOM_UTF16_BE):
        return data.decode("utf-16", errors="replace"), "utf-16"
    sample = data[:200_000]
    # BOM なし UTF-16 の見分け（ASCII の間に 0x00 が多い）
    if len(sample) >= 4:
        zeros_odd = sample[1::2].count(0)
        zeros_even = sample[0::2].count(0)
        half = len(sample) / 2
        if zeros_odd > half * 0.3 and zeros_even < half * 0.05:
            return data.decode("utf-16-le", errors="replace"), "utf-16-le"
        if zeros_even > half * 0.3 and zeros_odd < half * 0.05:
            return data.decode("utf-16-be", errors="replace"), "utf-16-be"
    if b"\x1b$B" in sample or b"\x1b$@" in sample or b"\x1b(J" in sample:
        try:
            return data.decode("iso2022_jp"), "iso-2022-jp"
        except UnicodeDecodeError:
            pass
    for enc in ("utf-8", "cp932", "euc_jp"):
        try:
            return data.decode(enc), enc
        except UnicodeDecodeError:
            continue
    try:
        import chardet

        guess = chardet.detect(sample)
        enc = guess.get("encoding")
        if enc:
            return data.decode(enc, errors="replace"), enc
    except Exception:
        pass
    return data.decode("cp932", errors="replace"), "cp932(置換あり)"


def entropy(sample: bytes) -> float:
    """1バイトあたりのシャノンエントロピー（8に近いほど圧縮・暗号化された中身）。"""
    if not sample:
        return 0.0
    counts = Counter(sample)
    n = len(sample)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def iter_strings(data: bytes, min_len: int = 4) -> Iterator[str]:
    """バイナリから人が読める文字列を拾い出す（UTF-16LE 両位相・cp932・UTF-8）。

    Access・Excel97・Word97・一太郎などは本文を UTF-16LE か cp932 で持つため、
    構造が読めない形式や削除済み領域の残留もこれで拾える。
    """
    if not data:
        return
    seen: set[str] = set()
    decoded = [
        data.decode("utf-16-le", errors="replace"),
        data[1:].decode("utf-16-le", errors="replace"),
        data.decode("cp932", errors="replace"),
        data.decode("utf-8", errors="replace"),
        data.decode("euc_jp", errors="replace"),
    ]
    for text in decoded:
        for m in RE_GOOD_RUN.finditer(text):
            s = m.group(0).strip()
            if len(s) < min_len or not RE_HAS_SIGNAL.search(s):
                continue
            if s in seen:
                continue
            seen.add(s)
            yield s


def iter_strings_chunked(read, chunk_size: int = 8 * 1024 * 1024, overlap: int = 4096) -> Iterator[str]:
    """大きなファイルを少しずつ読みながら iter_strings する。read(n) はファイルの read。"""
    tail = b""
    seen: set[str] = set()
    while True:
        chunk = read(chunk_size)
        if not chunk:
            break
        buf = tail + chunk
        for s in iter_strings(buf):
            if s not in seen:
                seen.add(s)
                yield s
        # 境界をまたぐ文字列のため、末尾を少し次へ持ち越す（偶数にして UTF-16 の位相を保つ）
        tail = buf[-overlap:] if len(buf) > overlap else buf
        if len(seen) > 2_000_000:
            seen.clear()

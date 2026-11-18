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
# BOM も ASCII の間の 0x00 も無い UTF-16 の見分け（utf16_without_bom）で見る長さ・文字の数・割合
UTF16_STRICT_SAMPLE = 8192
UTF16_STRICT_MIN_CHARS = 32
UTF16_STRICT_RATIO = 0.98
UTF16_STRICT_SWAPPED_RATIO = 0.9
UTF16_STRICT_KANA_RATIO = 0.2
UTF16_STRICT_JA_RATIO = 0.05


# BOM の無い UTF-16 の厳しい見分けで、ふつうの文字とみなさない文字。ふつうの文字は、印字できる ASCII・改行とタブ・
# ラテン1の記号・一般の記号から罫線と記号まで（U+2000〜U+2BFF）・日本語の記号とかなと漢字（U+3000〜U+9FFF）・
# 全角（U+FF00〜U+FFEF）・絵文字などの補助面の文字（正しいサロゲートの対）。16bit の数の表（上位が 0 の制御文字になる）や
# 圧縮した中身（どの文字にもなる）は、ほとんど入らない。数えるのはファイルごとに数千字なので、正規表現でまとめて数える
_RE_UTF16_ODD_CHAR = re.compile(r"[^\t\n\r\x20-\x7e\xa0-\xff -⯿　-鿿＀-￯\U00010000-\U0010ffff]")
_RE_KANA = re.compile(r"[ぁ-ヺ]")
# かな・漢字・日本語の句読点（U+3030 の「〰」は数字の「00」を2バイトずつ読んだ形なので除く）
_RE_JA_CHAR = re.compile(r"[　-〯〱-ヿ一-鿿]")


def _is_utf8(sample: bytes) -> bool:
    """UTF-8 として厳密に読めるか（見本の末尾で切れた1文字は許す）。"""
    try:
        sample.decode("utf-8")
    except UnicodeDecodeError as e:
        return e.start >= len(sample) - 3 and e.reason == "unexpected end of data"
    return True


def utf16_without_bom(sample: bytes) -> str | None:
    """BOM も ASCII の間の 0x00 も無い UTF-16 なら、その文字コード（"utf-16-le" か "utf-16-be"）を返す。違えば None。

    ASCII をほとんど含まない日本語だけの文や、上位と下位の両方に 0x00 が出る罫線（U+2500 など）の多い表は、
    0x00 の偏りでは見分けられない（2026-11-08 まで「簡易検査」の生データ走査になり、ビッグエンディアンでは
    何も拾えなかった）。先頭 UTF16_STRICT_SAMPLE バイトを2バイトずつの文字として読み、次のすべてを満たすときだけ
    UTF-16 とみなす。
    - UTF16_STRICT_RATIO 以上がふつうの文字（_RE_UTF16_ODD_CHAR に当たらない文字）
    - 逆の向き（バイトの順を入れ替えた読み方）では UTF16_STRICT_SWAPPED_RATIO 未満しかふつうの文字にならない。
      ASCII の2バイトはどちらの向きに読んでも漢字などの文字（"AB" → U+4142）になるので、ASCII の多いバイナリ
      （Python の .pyc）を UTF-16 と誤らないための見分け
    - 改行の文字（U+000A）がある
    - かな・漢字・日本語の句読点（_RE_JA_CHAR）が UTF16_STRICT_JA_RATIO 以上
    UTF-8 として読めるもの（ASCII だけの文を含む）と、両方の向きで通るもの（向きを決められない）は UTF-16 にしない。
    """
    sample = sample[:UTF16_STRICT_SAMPLE]
    n = len(sample) - len(sample) % 2
    if n < UTF16_STRICT_MIN_CHARS * 2 or _is_utf8(sample):
        return None
    texts = {enc: sample[:n].decode(enc, errors="replace") for enc in ("utf-16-le", "utf-16-be")}
    ratios = {enc: 1 - len(_RE_UTF16_ODD_CHAR.findall(t)) / len(t) for enc, t in texts.items()}
    if max(ratios.values()) < UTF16_STRICT_RATIO:
        return None  # バイナリの大半はここで終わる
    kana = {enc: len(_RE_KANA.findall(t)) / len(t) for enc, t in texts.items()}
    found = []
    for enc, other in (("utf-16-le", "utf-16-be"), ("utf-16-be", "utf-16-le")):
        text = texts[enc]
        if ratios[enc] < UTF16_STRICT_RATIO or "\n" not in text:
            continue
        # ひらがなは逆の向きに読んでも漢字（U+3042 → U+4230）になるので、かなの多い文は、この向きにだけかなが多いことで見る
        # （ASCII の多いバイナリは、どちらの向きに読んでもかなは同じくらいしか出ない）
        hiragana_text = kana[enc] >= UTF16_STRICT_KANA_RATIO and kana[other] < kana[enc] * 0.1
        if ratios[other] >= UTF16_STRICT_SWAPPED_RATIO and not hiragana_text:
            continue
        if len(_RE_JA_CHAR.findall(text)) >= len(text) * UTF16_STRICT_JA_RATIO:
            found.append(enc)
    # 両方の向きで通るもの（40〜60字ほどの短い文で起きる）は向きを決められないので、取り違えて化けたまま
    # 「検査済み」にせず、今までどおり簡易検査に回す
    return found[0] if len(found) == 1 else None


def decode_text(data: bytes) -> tuple[str, str]:
    """テキストファイルのバイト列を文字列にする。戻り値は（文字列, 使った文字コード）。

    BOM → BOM の無い UTF-16（0x00 の偏り）→ ISO-2022-JP（エスケープがあるとき）→ UTF-8 →
    BOM も 0x00 の偏りも無い UTF-16（utf16_without_bom）→ cp932 → EUC-JP → chardet の順に試し、
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
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        pass
    # 日本語だけの文・罫線の多い表の、BOM も 0x00 の偏りも無い UTF-16（cp932 として偶然読めることがあるので先に見る）
    enc16 = utf16_without_bom(sample)
    if enc16:
        return data.decode(enc16, errors="replace"), enc16
    for enc in ("cp932", "euc_jp"):
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


_RE_BE_JA = re.compile(r"[ぁ-ヺ一-鿿]")
# ビッグエンディアンの読みで拾う並びの条件（_be_plausible）
BE_MIN_REAL_CHARS = 2
BE_MIN_REAL_RATIO = 0.2
BE_MIN_DISTINCT = 2


def _from_ascii_pair(c: str) -> bool:
    """印字できる ASCII の2バイトをビッグエンディアンで読んだ形で作れる文字か（"AB" → U+4142 の類）。"""
    v = ord(c)
    return 0x20 <= v >> 8 <= 0x7E and 0x20 <= v & 0xFF <= 0x7E


def _is_level1(c: str) -> bool:
    """かなか、JIS 第1水準の漢字（cp932 の 0x889F〜0x9872）か。"""
    if "ぁ" <= c <= "ヺ":
        return True
    try:
        b = c.encode("cp932")
    except UnicodeEncodeError:
        return False
    return len(b) == 2 and 0x889F <= int.from_bytes(b, "big") <= 0x9872


def _be_plausible(s: str) -> bool:
    """ビッグエンディアンの読みで拾った並びが、日本語の文として本物らしいか。

    バイナリを2バイトずつ読むと、乱れた漢字の並びがいくらでも出る（実ファイル 4,000 件で、条件が緩いと
    「名前」の誤検出が 146 件）。次のすべてを満たす並びだけ拾う（同じ 4,000 件で誤検出 0 件）。
    - かな漢字のうち、ASCII の2バイトから作れない字が BE_MIN_REAL_CHARS 字以上・BE_MIN_REAL_RATIO 以上
    - かな漢字が全部、かなか JIS 第1水準の漢字（第2水準の字を含む並びは拾えない）
    - かな漢字の異なる字が BE_MIN_DISTINCT 字以上（同じ字の繰り返しを除く）
    ASCII だけの並びはここで拾わない（ビッグエンディアンの ASCII は、UTF-16LE を1バイトずらした読みで拾える）。
    """
    ja = _RE_BE_JA.findall(s)
    real = sum(1 for c in ja if not _from_ascii_pair(c))
    if real < BE_MIN_REAL_CHARS or real < len(ja) * BE_MIN_REAL_RATIO:
        return False
    return len(set(ja)) >= BE_MIN_DISTINCT and all(_is_level1(c) for c in ja)


def iter_strings(data: bytes, min_len: int = 4, big_endian: bool = False) -> Iterator[str]:
    """バイナリから人が読める文字列を拾い出す（UTF-16LE 両位相・cp932・UTF-8）。

    Access・Excel97・Word97・一太郎などは本文を UTF-16LE か cp932 で持つため、
    構造が読めない形式や削除済み領域の残留もこれで拾える。
    big_endian=True なら UTF-16BE の両位相も読み、日本語の文として本物らしい並び（_be_plausible）だけ足す
    （約 14MB/秒と重いので、形式不明のファイルの読み方だけで使う）。
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
    if not big_endian:
        return
    for text in (data.decode("utf-16-be", errors="replace"), data[1:].decode("utf-16-be", errors="replace")):
        for m in RE_GOOD_RUN.finditer(text):
            s = m.group(0).strip()
            if len(s) < min_len or s in seen or not _be_plausible(s):
                continue
            seen.add(s)
            yield s


def iter_strings_chunked(
    read, chunk_size: int = 8 * 1024 * 1024, overlap: int = 4096, big_endian: bool = False
) -> Iterator[str]:
    """大きなファイルを少しずつ読みながら iter_strings する。read(n) はファイルの read。"""
    tail = b""
    seen: set[str] = set()
    while True:
        chunk = read(chunk_size)
        if not chunk:
            break
        buf = tail + chunk
        for s in iter_strings(buf, big_endian=big_endian):
            if s not in seen:
                seen.add(s)
                yield s
        # 境界をまたぐ文字列のため、末尾を少し次へ持ち越す（偶数にして UTF-16 の位相を保つ）
        tail = buf[-overlap:] if len(buf) > overlap else buf
        if len(seen) > 2_000_000:
            seen.clear()

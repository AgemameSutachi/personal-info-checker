"""対処（remediate）で、Oracle のダンプ（旧 exp・expdp）の中身を書き換える部分（T2-d）。

位置は検査（formats/oracle_dump.py）のときに集めたもの。シート=表の名前（同じ名前の区画は 2 つ目から「名前 (2)」）、行=表の中の
行の通し番号（1 始まり）、列=列の番号（0 始まり）。生の値は位置に入れていないので、ダミー化は書き換えるときにその場で値を読み直す。

旧 exp（layout=oracle_exp）
    ファイルを先頭から少しずつ読み、触らない区画（文・行）はバイト単位でそのまま写す。表の区画は
    `TABLE "X"` 行 → `CREATE TABLE` 行 → `INSERT INTO` 行（`:1, :2…` のバインド）→ 列の定義 → 行 → `00 00 FF FF` → 後続の文（統計・索引・制約など）。
    - 行の削除 / ダミー化: 行のバイト列を写さない / 値を置き換えて長さの前置きを直す
    - 列の削除: CREATE TABLE の列・INSERT の列名と :n・列の定義・各行のその列を取り除く。その列を使う索引・制約・コメントの文も外す
    - 表の削除: 表の区画（TABLE から次の TABLE・ENDTABLE の手前まで）と、2 周目の `TABLE "X"` 区画を写さない
    - 書き換えた表の統計（ANALSTATS。列の最小・最大値の 16 進が入っていて、元の値が残るため）は取り除く（読み込み後に統計は取り直される）

expdp（layout=oracle_expdp。直接パス形式・圧縮なし）
    ファイルは 4096 バイトのブロック。表のデータの単位は「制御ブロック（先頭 ff ff 24 24）＋ 本体」で、本体は XML（列の定義）・行・索引・ゼロ詰め。
    制御ブロックの 6 つの値 F1..F6（8 バイト BE・+6 から）は、見出しの長さ・ブロックの大きさ・行の合計・行の始まり・索引の大きさ・索引の始まり
    （docs/開発者向け.md の「Oracle ダンプの形式」）。メタデータ（DDL・統計）は KGC で圧縮されていて書き換えられないので、
    行の削除とダミー化だけに対応し、ファイルの大きさは変えない（マスターテーブルが持つ各単位の位置を保つため）:
    行を詰め直して、行の合計（F3）・索引の大きさ（F5）・索引の始まり（F6）・索引（行の境界）を直し、残りをゼロで埋める。
    列の削除・表の削除・圧縮や暗号化・想定と違う作りの区画は、壊さずに断る。

どちらも、新しいファイルを別の名前で書き、元には触らない。呼び出し側が検査し直して確定する。
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import struct
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation, localcontext

from .formats import oracle_dump as od
from .remedy_write import DummyMaker, RemedyError, Selection, break_digit_runs, replace_spans

GRANULE = 10_240_000  # expdp の索引の間隔（前の項目から数えて、この大きさ以上で最初の行の境界）
BLOCK = 4096
CTRL_MAGIC = b"\xff\xff$$"
CTRL_FIELDS_AT = 6  # 制御ブロックの中で、6 つの 8 バイト BE の値が始まる位置
_KEEP = object()  # 行の書き換えの結果: 元のバイト列のまま写す
CHUNK = 4 * 1024 * 1024
MAX_PART = 64 * 1024 * 1024  # exp の表のあとに続く文をメモリに持つ上限
MAX_ROW_TOTAL = 0xFFFF  # expdp の行の全長（2 バイト）の上限

EXPDP_UNSUPPORTED_REASON = (
    "expdp のダンプは、列の定義（DDL）が圧縮された管理情報の区画に入っていて書き換えられないため、列の削除・表の削除には対応していません"
    "（行の削除・ダミー化は対応しています）。ファイルの削除はできます"
)

TABLE_MARK = b'\nTABLE "'
ENDTABLE_MARK = b"\nENDTABLE"
RE_TABLE_LINE = re.compile(rb'TABLE "((?:[^"\n]|"")*)"\n')
RE_CREATE_HEAD = re.compile(rb'CREATE TABLE "((?:[^"\n]|"")*)" \(')
RE_QUOTED_TOKEN = re.compile(rb'"(?:[^"]|"")*"')
RE_ELEMENT_NAME = re.compile(rb'\s*"((?:[^"]|"")*)"(?:\s|$)')
RE_UNIT_START = re.compile(
    rb"(?m)^(?=(?:ANALSTATS |ANALCOMPUTE |CREATE |ALTER |GRANT |REVOKE |COMMENT |AUDIT |DROP |TRIGGER ))"
)
RE_ANALSTATS_TABLE = re.compile(rb'ANALSTATS TS "((?:[^"\n]|"")*)"')
RE_ANALSTATS_INDEX = re.compile(rb'ANALSTATS IS "((?:[^"\n]|"")*)"')
RE_CREATE_INDEX = re.compile(rb'CREATE (?:UNIQUE |BITMAP )?INDEX "((?:[^"\n]|"")*)" ON ')
# 索引の統計の文（ANALSTATS IS "表" の後ろの SET_INDEX_STATS）と、2 周目の ANALCOMPUTE の ANALYZE INDEX が指す索引の名前
RE_SET_INDEX_STATS = re.compile(rb"""SET_INDEX_STATS\(NULL,'"((?:[^"\n]|"")*)"'""")
RE_ANALYZE_INDEX = re.compile(rb'ANALCOMPUTE IS "(?:[^"\n]|"")*" ANALYZE\s+INDEX "((?:[^"\n]|"")*)"')
RE_ALTER_ADD = re.compile(rb"ALTER TABLE .*? ADD\s+(?:\(\s*)?(?:CONSTRAINT|PRIMARY|UNIQUE|FOREIGN|CHECK)\b", re.S)
RE_COMMENT_COLUMN = re.compile(rb"COMMENT ON COLUMN ")


# ---------------------------------------------------------------- Oracle の内部形式を作る（解き方 od.decode_number・decode_date の逆）


def encode_number(text: str) -> bytes:
    """十進の文字列を Oracle NUMBER の内部形式（基数 100 の仮数）にする。0 は 80。有効数字は 40 桁まで。"""
    try:
        d = Decimal(text.strip())
    except InvalidOperation:
        raise ValueError("数値として読めません") from None
    if not d.is_finite():
        raise ValueError("有限の数値ではありません")
    if d == 0:
        return b"\x80"
    neg = d < 0
    with localcontext() as ctx:
        ctx.prec = 100  # 既定の 28 桁で丸めない（Oracle の NUMBER は 38 桁）
        d = abs(d).normalize()
    _sign, digit_tuple, exp10 = d.as_tuple()
    digits = "".join(str(x) for x in digit_tuple).rstrip("0") or "0"
    # 値 = 0.<digits> × 10^point（point は小数点より左の桁数。負もある）
    point = exp10 + len(digit_tuple)
    if point % 2:
        digits = "0" + digits
        point += 1
    if len(digits) % 2:
        digits += "0"
    groups = [int(digits[i : i + 2]) for i in range(0, len(digits), 2)]
    while groups and groups[-1] == 0:
        groups.pop()
    if not groups or len(groups) > 20:
        raise ValueError("桁数が多すぎます")
    exp100 = point // 2 - 1
    if neg:
        body = [101 - g for g in groups]
        return bytes([0x3E - exp100, *body] + ([0x66] if len(body) < 20 else []))
    return bytes([0xC1 + exp100, *[g + 1 for g in groups]])


def numeric_dummy(maker: DummyMaker, pii_type: str, text: str) -> str:
    """NUMBER の値のダミー（十進の文字列）。形を保つ・固定は 0。同じ値は同じダミー（検出した桁数と同じ桁数）。"""
    if maker.mode != "same":
        return "0"
    neg = text.startswith("-")
    body = text.lstrip("+-")
    ip, _dot, fp = body.partition(".")
    n = len(ip) + len(fp)
    if n == 0:
        return "0"
    digest = hmac.new(maker.key, f"{pii_type}\0num\0{text}".encode("utf-8"), hashlib.sha256).hexdigest()
    digits = str(int(digest, 16)).rjust(n, "0")[-n:]
    if ip and digits[0] == "0":
        digits = "1" + digits[1:]
    if digits == (ip + fp):
        digits = digits[:-1] + str((int(digits[-1]) + 1) % 10)
    out = digits[: len(ip)] + ("." + digits[len(ip) :] if fp else "")
    return ("-" if neg else "") + out


def date_dummy(maker: DummyMaker, pii_type: str, raw: bytes) -> bytes:
    """DATE（7 バイト）・TIMESTAMP の日付の部分（先頭の 7 バイト）のダミー。時刻の部分は変えない。

    同じ値は同じダミーの日付（1900〜1999 年・月・日は 1〜28）。形を保つ・固定は 1900-01-01。
    """
    if maker.mode == "same":
        text = od.decode_date(raw) or raw[:4].hex()
        d = hmac.new(maker.key, f"{pii_type}\0date\0{text}".encode("utf-8"), hashlib.sha256).digest()
        year, month, day = 1900 + d[0] % 100, 1 + d[1] % 12, 1 + d[2] % 28
    else:
        year, month, day = 1900, 1, 1
    out = bytes([year // 100 + 100, year % 100 + 100, month, day])
    if out == raw[:4]:
        # 元と同じ日付になった（約 1/33600。固定なら元が 1900-01-01 のとき）。同じままだと書き換えが飛ばされ、元の値が残るので日をずらす
        out = out[:3] + bytes([day % 28 + 1])
    return out + raw[4:7]


class _StarMaker:
    """ダミーが列の長さに収まらないときの最後の代わり: 値と同じ文字数の「*」（半角なので 1 バイト）。"""

    produced: set[str] = set()

    def make(self, _pii_type: str, value: str) -> str:
        return "*" * max(1, len(value))


class _CompactMaker:
    """「同じ値は同じダミー」で、ダミーが列の長さ（expdp は元の値の長さ）に収まらないときの代わり。

    値と同じバイト数の、鍵つき（実行ごとの鍵）の英数字の文字列（16 進の数字が 5 桁を超えて続くところは g〜p にする）。
    同じ値は同じ文字列になる。3 文字に満たない値は「*」にする。
    """

    def __init__(self, base: DummyMaker, codec: str):
        self.base = base
        self.codec = codec
        self.unit = len(" ".encode(codec))  # 半角 1 文字のバイト数（UTF-16 は 2）

    def make(self, pii_type: str, value: str) -> str:
        chars = len(value.encode(self.codec, "replace")) // self.unit
        if chars < 3:
            return "*" * max(1, len(value))
        digest = hmac.new(self.base.key, f"{pii_type}\0compact\0{value}".encode("utf-8"), hashlib.sha256).hexdigest()
        # 数字が長く続くと、その部分がマイナンバー・電話番号などとして検出し直されるので切る（remedy_write.break_digit_runs）
        token = break_digit_runs((digest * (chars // len(digest) + 1))[:chars])
        self.base.produced.add(token)
        return token


# ---------------------------------------------------------------- 値の書き換え（型ごと）


class CellEditor:
    """列の型に合わせて、検出した値の部分だけをダミーにした新しいバイト列を作る。

    strict が True（expdp）のときは、新しい値を元の値より長くしない（ファイルの大きさを変えないため）。
    False（exp）は、列の宣言の長さに収まればよい。収まらないダミーは、同じ文字数の「*」に代える。
    """

    def __init__(
        self, maker: DummyMaker, columns: list[str], types: list[int], codecs: list, maxlens: list, strict: bool
    ):
        self.maker = maker
        self.columns = columns
        self.types = types
        self.codecs = codecs
        self.maxlens = maxlens
        self.strict = strict

    def edit(self, i: int, raw: bytes, spans: list) -> bytes | None:
        """列 i の値 raw を、位置 spans（開始, 終了, 種類）の部分だけダミーにした値を返す。変わらなければ None。"""
        t = self.types[i]
        if t in (od.TYPE_VARCHAR2, od.TYPE_CHAR):
            return self._text(i, raw, spans, t == od.TYPE_CHAR)
        if t == od.TYPE_NUMBER:
            return self._number(raw, spans)
        if t in (od.TYPE_DATE, od.TYPE_TIMESTAMP, od.TYPE_TIMESTAMP_TZ, od.TYPE_TIMESTAMP_LTZ):
            return self._date(raw, spans)
        raise RemedyError(f"列「{self.columns[i]}」の型は、置き換えに対応していません")

    def _limit(self, i: int, raw: bytes) -> int:
        return len(raw) if self.strict else max(self.maxlens[i], len(raw))

    def _text(self, i: int, raw: bytes, spans: list, is_char: bool) -> bytes | None:
        codec = self.codecs[i]
        if not codec:
            raise RemedyError(f"列「{self.columns[i]}」の文字セットに対応していません")
        try:
            text = raw.decode(codec)
        except UnicodeDecodeError:
            raise RemedyError(f"列「{self.columns[i]}」に、文字として読めない値があるため、書き換えません") from None
        try:
            if text.encode(codec) != raw:
                raise UnicodeEncodeError(codec, text, 0, 1, "")
        except UnicodeEncodeError:
            raise RemedyError(
                f"列「{self.columns[i]}」に、元のバイト列へ正確に戻せない値があるため、書き換えません"
            ) from None
        body = text.rstrip(" ") if is_char else text  # CHAR は右側が空白で埋められる（検査も同じ）
        new = replace_spans(body, spans, self.maker)
        if new == body:
            return None
        limit = self._limit(i, raw)
        out = self._fit(codec, new, raw, is_char, limit)
        if out is None and self.maker.mode == "same":
            # 収まらない: 「同じ値は同じダミー」を保ったまま、値と同じバイト数の鍵つきの英数字の文字列にする（_CompactMaker）
            new = replace_spans(body, spans, _CompactMaker(self.maker, codec))
            out = self._fit(codec, new, raw, is_char, limit)
        if out is None:
            new = replace_spans(body, spans, _StarMaker())
            out = self._fit(codec, new, raw, is_char, limit)
        if out is None:
            raise RemedyError(f"列「{self.columns[i]}」の値が、置き換えても列の長さに収まらないため、書き換えません")
        return None if out == raw else out

    @staticmethod
    def _fit(codec: str, new: str, raw: bytes, is_char: bool, limit: int) -> bytes | None:
        try:
            nb = new.encode(codec)
        except UnicodeEncodeError:
            return None
        if is_char and len(nb) < len(raw):
            unit = " ".encode(codec)
            gap = len(raw) - len(nb)
            if gap % len(unit):
                return None
            nb += unit * (gap // len(unit))
        return nb if len(nb) <= limit else None

    def _number(self, raw: bytes, spans: list) -> bytes | None:
        text = od.decode_number(raw)
        if text is None:
            raise RemedyError("読み解けない数値があるため、書き換えません")
        limit = len(raw) if self.strict else 22
        new = numeric_dummy(self.maker, spans[0][2], text)
        nb = encode_number(new)
        if len(nb) > limit:
            nb = b"\x80"
        if nb == raw:
            return None
        self.maker.produced.add(od.decode_number(nb) or "0")
        return nb

    def _date(self, raw: bytes, spans: list) -> bytes | None:
        if len(raw) < 7:
            raise RemedyError("読み解けない日付があるため、書き換えません")
        new = date_dummy(self.maker, spans[0][2], raw) + raw[7:]
        if new == raw:
            return None
        shown = od.decode_date(new)
        if shown:
            self.maker.produced.add(shown)
            self.maker.produced.add(shown.split(" ")[0])
        return new


# ---------------------------------------------------------------- 共通の下ごしらえ


@dataclass
class _Plan:
    """書き換える表1つ分の指示（検査のときに集めた位置から作る）。"""

    rows: set
    cols: set
    by_row: dict  # 行の番号 → {列 → [(開始, 終了, 種類)]}
    seen_rows: set
    touched: bool = False


def _build_plans(method: str, sel: Selection) -> dict[str, _Plan]:
    rows, cols, spans = sel.rows(), sel.cols(), sel.spans()
    plans: dict[str, _Plan] = {}
    for table in sel.sheets():
        by_row: dict = {}
        if method == "dummy":
            for (r, c), lst in spans.get(table, {}).items():
                by_row.setdefault(r, {})[c] = lst
        plans[table] = _Plan(set(rows.get(table, set())), set(cols.get(table, set())), by_row, set())
    return plans


def _check_found(method: str, plans: dict[str, _Plan], found: set[str]) -> None:
    """選んだ位置がすべて見つかったかを確かめる（検査と読み方が食い違っていれば、書き換えを断る）。"""
    for name, plan in plans.items():
        if name not in found:
            raise RemedyError(
                f"表「{name}」の区画が見つかりませんでした。ファイルの読み方が検査と食い違ったため、書き換えません（元のファイルは変えていません）"
            )
        missing = 0
        if method == "delete_rows":
            missing = len(plan.rows - plan.seen_rows)
        elif method == "dummy":
            missing = len(set(plan.by_row) - plan.seen_rows)
        if missing:
            raise RemedyError(
                f"表「{name}」で、検査のときの位置の行が見つかりません（{missing} 行）。"
                "ファイルの読み方が検査と食い違ったため、書き換えません（元のファイルは変えていません）"
            )


def _column_codecs(types: list[int], csids: list[int], default: str) -> list:
    return [
        (od.CHARSET_CODECS.get(c) or default) if t in (od.TYPE_VARCHAR2, od.TYPE_CHAR) else None
        for t, c in zip(types, csids)
    ]


# ---------------------------------------------------------------- 旧 exp


def _exp_cell(v: bytes | None) -> bytes:
    return b"\xff\xff" if v is None else struct.pack("<H", len(v)) + v


def _exp_row_bytes(raws: list) -> bytes:
    return b"\x00\x00" + b"".join(_exp_cell(v) for v in raws)


def _unescape_name(token: bytes, codec: str) -> str:
    return token.decode(codec, "replace").replace('""', '"')


def _split_create_columns(line: bytes):
    """CREATE TABLE の行から、列の定義の並びを取り出す。戻り値は（開き括弧までの文字列, 定義の並び, 閉じ括弧からの文字列）。
    引用符（"…"・'…'）の中と、入れ子の括弧の中のコンマでは区切らない。"""
    m = RE_CREATE_HEAD.match(line)
    if m is None:
        raise RemedyError("CREATE TABLE の行を読み解けないため、列を削除できません")
    start = m.end()  # 開き括弧の次
    depth, i, n = 1, start, len(line)
    cuts = [start]
    while i < n:
        c = line[i : i + 1]
        if c in (b'"', b"'"):
            j = i + 1
            while j < n:
                if line[j : j + 1] == c:
                    if line[j + 1 : j + 2] == c:
                        j += 2
                        continue
                    break
                j += 1
            i = j + 1
            continue
        if c == b"(":
            depth += 1
        elif c == b")":
            depth -= 1
            if depth == 0:
                cuts.append(i)
                break
        elif c == b"," and depth == 1:
            cuts.append(i)
        i += 1
    else:
        raise RemedyError("CREATE TABLE の括弧が閉じていないため、列を削除できません")
    close = cuts[-1]
    elements = [line[cuts[k] + (1 if k else 0) : cuts[k + 1]].strip() for k in range(len(cuts) - 1)]
    return line[:start], elements, line[close:]


class _ExpRewriter:
    """旧 exp のダンプを、先頭から少しずつ読みながら書き出す。"""

    def __init__(self, f_in, out, head_codec: str, method: str, sel: Selection, maker: DummyMaker | None):
        self.st = od._Stream(f_in)
        self.out = out
        self.codec = head_codec
        self.method = method
        self.maker = maker
        self.plans = _build_plans(method, sel)
        self.counts: dict[str, int] = {}
        self.found: set[str] = set()
        self.stats = {"rows": 0, "cols": 0, "tables": 0, "cells": 0, "detections": 0, "statements": 0}
        self.dropped_columns: set[tuple[str, str]] = set()
        # 直前の _move_to_marker が「TABLE "…" の行の先頭」で止まったか（そこから次の区画の処理を始める）
        self.at_table_line = False

    # ------------------------------------------------------------ 読み書きの道具

    def _write(self, data) -> None:
        if len(data):
            self.out.write(data)

    def _first_marker(self, markers) -> int:
        buf, pos = self.st.buf, self.st.pos
        best = -1
        for m in markers:
            i = buf.find(m, pos)
            if i >= 0 and (best < 0 or i < best):
                best = i
        return best

    def _move_to_marker(self, markers, sink) -> bool:
        """次の区切り（行の先頭の目印）の手前までを sink に渡して進む。区切りの行頭（直前の改行の次）で止まり True。
        見つからないままファイルの終わりなら、残りを渡して False。"""
        st = self.st
        keep = max(len(m) for m in markers)
        self.at_table_line = False
        while True:
            idx = self._first_marker(markers)
            if idx >= 0:
                sink(st.buf[st.pos : idx + 1])
                st.pos = idx + 1
                self.at_table_line = st.buf.startswith(b'TABLE "', st.pos)
                return True
            safe = len(st.buf) - keep
            if safe > st.pos:
                sink(st.buf[st.pos : safe])
                st.pos = safe
            if not st.more():
                sink(st.buf[st.pos :])
                st.pos = len(st.buf)
                return False

    def _gather_to_marker(self, markers) -> bytes:
        parts: list[bytes] = []
        size = [0]

        def sink(b) -> None:
            size[0] += len(b)
            if size[0] > MAX_PART:
                raise RemedyError("表のあとに続く文が大きすぎて読み解けないため、書き換えません")
            parts.append(bytes(b))

        self._move_to_marker(markers, sink)
        return b"".join(parts)

    def _peek_line(self, rel: int):
        """st.pos から rel バイト先で始まる1行（改行を含む）と、その次の rel を返す。見つからなければ None。"""
        st = self.st
        while True:
            i = st.buf.find(b"\n", st.pos + rel)
            if i >= 0:
                return st.buf[st.pos + rel : i + 1], i + 1 - st.pos
            if len(st.buf) - st.pos > od.MAX_HEADER or not st.more():
                return None

    # ------------------------------------------------------------ 全体

    def run(self) -> dict:
        while True:
            if not self.at_table_line and not self._move_to_marker((TABLE_MARK,), self._write):
                break
            self.at_table_line = False
            self._section()
        self.out.flush()
        _check_found(self.method, self.plans, self.found)
        for name, plan in self.plans.items():
            if self.method == "delete_table" and not plan.touched:
                raise RemedyError(
                    f"表「{name}」の区画が見つかりませんでした。書き換えません（元のファイルは変えていません）"
                )
        if self.method == "dummy" and self.stats["cells"] == 0:
            raise RemedyError("書き換える値が見つかりませんでした。元のファイルは変えていません")
        self.stats["cols"] = len(self.dropped_columns)
        return self.stats

    # ------------------------------------------------------------ 表の区画

    def _section(self) -> None:
        """st.pos は「TABLE "…"」の行の先頭。データの区画（CREATE TABLE・INSERT つき）か、それ以外（2 周目の統計など）かを見分ける。"""
        st = self.st
        first = self._peek_line(0)
        if first is None:
            self._write(b'TABLE "')  # 改行の無い行（ここから先は通常の本文として写される）
            st.pos += len(b'TABLE "')
            return
        line1, rel = first
        second = self._peek_line(rel)
        if second is not None and second[0].startswith(b'CREATE TABLE "'):
            rel = second[1]
        st.ensure(rel + len(b'INSERT INTO "'))
        if not st.buf.startswith(b'INSERT INTO "', st.pos + rel):
            self._other_section(line1)
            return
        head = st.buf[st.pos : st.pos + rel]  # TABLE 行と CREATE TABLE 行
        st.pos += rel
        try:
            parsed = od._parse_exp_header(st, self.codec)
        except od._Bad:
            parsed = None
        if parsed is None:
            self._write(head)  # 検査も表として読まない形。そのまま写す
            return
        tbl, header_len = parsed
        base = tbl.name
        name = od.unique_table_name(self.counts, base)
        header = bytes(st.buf[st.pos : st.pos + header_len])
        st.pos += header_len
        self._data_section(bytes(head), header, tbl, base, name)

    def _other_section(self, line1: bytes) -> None:
        """データを持たない TABLE 区画（2 周目の ANALCOMPUTE など）。表の削除なら、次の区切りまで取り除く。"""
        st = self.st
        m = RE_TABLE_LINE.match(line1)
        name = _unescape_name(m.group(1), self.codec) if m else None
        plan = self.plans.get(name) if name is not None else None
        if plan is not None and self.method == "delete_table":
            plan.touched = True
            self._move_to_marker((TABLE_MARK, ENDTABLE_MARK), lambda b: None)
            self.stats["statements"] += 1
            return
        if plan is not None and self.method == "delete_columns":
            part = self._gather_to_marker((TABLE_MARK, ENDTABLE_MARK))
            dropped = [c for (t, c) in sorted(self.dropped_columns) if t == name]
            self._write(self._filter_units(part, name, name, dropped))
            return
        self._write(line1)
        st.pos += len(line1)

    def _data_section(self, head: bytes, header: bytes, tbl, base: str, name: str) -> None:
        """データの区画1つ（TABLE・CREATE TABLE の行 head と、INSERT の行・列の定義 header は読み終えている）。"""
        plan = self.plans.get(name)
        if plan is not None:
            self.found.add(name)
            plan.touched = True
        if plan is not None and self.method == "delete_table":
            self._rows(tbl, lambda n, raws: None, lambda b: None, name)  # 行を読み飛ばし、後ろの文も取り除く
            self._move_to_marker((TABLE_MARK, ENDTABLE_MARK), lambda b: None)
            self.stats["tables"] += 1
            return
        drop_idx: set[int] = set()
        if plan is not None and self.method == "delete_columns":
            drop_idx = {c for c in plan.cols if c < len(tbl.columns)}
            if len(drop_idx) >= len(tbl.columns):
                raise RemedyError(
                    f"表「{name}」のすべての列は削除できません（列が1つも残りません）。表ごと消すなら「表を削除」を選んでください"
                )
            head, header = self._edit_headers(head, header, tbl, drop_idx, name)
            for i in drop_idx:
                self.dropped_columns.add((name, tbl.columns[i]))
        self._write(head)
        self._write(header)
        self._rows(tbl, self._row_callback(plan, tbl, drop_idx), self._write, name)
        if plan is not None:
            part = self._gather_to_marker((TABLE_MARK, ENDTABLE_MARK))
            dropped = [tbl.columns[i] for i in sorted(drop_idx)]
            self._write(self._filter_units(part, base, name, dropped))

    def _row_callback(self, plan: _Plan | None, tbl, drop_idx: set[int]):
        """方法に合わせた行の書き換え（_rows の row_cb）。選ばれていない表は、すべての行をそのまま写す。"""
        if plan is None or self.method == "delete_table":
            return lambda n, raws: _KEEP
        if self.method == "delete_rows":

            def delete_row(n, raws):
                if n in plan.rows:
                    plan.seen_rows.add(n)
                    self.stats["rows"] += 1
                    return None
                return _KEEP

            return delete_row
        if self.method == "dummy":
            types = [d[0] for d in tbl.descs]
            codecs = _column_codecs(types, [d[2] for d in tbl.descs], self.codec)
            editor = CellEditor(self.maker, tbl.columns, types, codecs, [d[1] for d in tbl.descs], strict=False)

            def dummy_row(n, raws):
                cols = plan.by_row.get(n)
                if cols is None:
                    return _KEEP
                plan.seen_rows.add(n)
                new = list(raws)
                for c, spans in cols.items():
                    if c >= len(new) or new[c] is None:
                        continue
                    nb = editor.edit(c, new[c], spans)
                    if nb is not None:
                        new[c] = nb
                        self.stats["cells"] += 1
                        self.stats["detections"] += len(spans)
                return _KEEP if new == list(raws) else _exp_row_bytes(new)

            return dummy_row
        return lambda n, raws: _exp_row_bytes([v for i, v in enumerate(raws) if i not in drop_idx])  # 列の削除

    # ------------------------------------------------------------ 行

    def _rows(self, tbl, row_cb, write, name: str) -> None:
        """表の行を順に読む。row_cb(行の番号, 値の並び) が _KEEP なら元のバイト列のまま、None なら取り除き、bytes ならその行に置き換える。
        触らない行は、続く範囲をまとめて1回で写す。終わりの印（00 00 FF FF）まで写して止まる。"""
        st = self.st
        buf, pos = st.buf, st.pos
        copy_from = pos
        n = 0
        at_eof = False
        while True:
            try:
                r = od._exp_row(buf, pos, len(buf), tbl, st.eof)
            except od._NeedMore:
                write(buf[copy_from:pos])
                st.pos = pos
                if len(buf) - pos > od.MAX_ROW:
                    raise RemedyError("1行が大きすぎるため、書き換えません") from None
                if not st.more():
                    if not at_eof:
                        at_eof = True
                        buf, pos = st.buf, st.pos
                        copy_from = pos
                        continue
                    raise RemedyError(f"表「{name}」の行の途中でダンプが切れているため、書き換えません")
                buf, pos = st.buf, st.pos
                copy_from = pos
                continue
            except od._Bad as exc:
                raise RemedyError(f"表「{name}」の行を読み解けないため、書き換えません（{exc}）") from None
            at_eof = False
            if r[0] == "end":
                write(buf[copy_from:pos])
                write(buf[pos : r[1]])
                st.pos = r[1]
                return
            n += 1
            res = row_cb(n, r[1])
            if res is not _KEEP:
                write(buf[copy_from:pos])
                if res is not None:
                    write(res)
                copy_from = r[2]
            pos = r[2]

    # ------------------------------------------------------------ 列の削除（見出しの書き換え）

    def _edit_headers(self, head: bytes, header: bytes, tbl, drop_idx: set[int], name: str) -> tuple[bytes, bytes]:
        keep = [i for i in range(len(tbl.columns)) if i not in drop_idx]
        # TABLE 行と CREATE TABLE 行
        if head.endswith(b"\n") and b'CREATE TABLE "' in head:
            first_end = head.find(b"\n") + 1
            create = head[first_end:]
            prefix, elements, suffix = _split_create_columns(create)
            names = []
            for el in elements:
                m = RE_ELEMENT_NAME.match(el)
                if m is None:
                    raise RemedyError(
                        f"表「{name}」の CREATE TABLE に、列の定義でない項目があるため、列を削除できません（制約などは別の文のはずですが、読み取れませんでした）"
                    )
                names.append(_unescape_name(m.group(1), self.codec))
            if names != list(tbl.columns):
                raise RemedyError(
                    f"表「{name}」の CREATE TABLE の列が INSERT の列と合わないため、列を削除できません（元のファイルは変えていません）"
                )
            dropped = {tbl.columns[i] for i in drop_idx}
            for k, el in enumerate(elements):
                if k in drop_idx:
                    continue
                for dn in dropped:
                    if b'"' + dn.replace('"', '""').encode(self.codec) + b'"' in el:
                        raise RemedyError(
                            f"表「{name}」の列の定義が、削除する列「{dn}」を使っているため、列を削除できません（元のファイルは変えていません）"
                        )
            head = (
                head[:first_end]
                + prefix
                + b", ".join(el for k, el in enumerate(elements) if k not in drop_idx)
                + suffix
            )
        # INSERT 行と列の定義
        eol = header.find(b"\n") + 1
        line, rest = header[:eol], header[eol:]
        m = od.RE_EXP_INSERT.match(line)
        if m is None:
            raise RemedyError(f"表「{name}」の INSERT 文を読み解けないため、列を削除できません")
        tokens = RE_QUOTED_TOKEN.findall(m.group(2))
        if len(tokens) != len(tbl.columns):
            raise RemedyError(f"表「{name}」の INSERT 文の列を読み解けないため、列を削除できません")
        new_names = b", ".join(tokens[i] for i in keep)
        new_binds = b", ".join(b":%d" % (k + 1) for k in range(len(keep)))
        line = line[: m.start(2)] + new_names + line[m.end(2) : m.start(3)] + new_binds + line[m.end(3) :]
        # 列の定義: 列数(2) + 列ごとに 型(2)・長さ(2)（文字型はさらに 文字セット ID(2)・形(2)）+ 終わりの 00 00
        defs: list[bytes] = []
        p = 2
        for d in tbl.descs:
            size = 8 if d[0] in od.EXP_CHAR_TYPES else 4
            defs.append(rest[p : p + size])
            p += size
        if rest[p : p + 2] != b"\x00\x00" or len(rest) != p + 2:
            raise RemedyError(f"表「{name}」の列の定義を読み解けないため、列を削除できません")
        new_rest = struct.pack("<H", len(keep)) + b"".join(defs[i] for i in keep) + b"\x00\x00"
        return head, line + new_rest

    # ------------------------------------------------------------ 表のあとに続く文（統計・索引・制約など）

    def _filter_units(self, part: bytes, base: str, name: str, dropped_cols: list[str]) -> bytes:
        """表のあとに続く文の並びから、取り除くものを外す。

        - 書き換えた表の統計（ANALSTATS TS "表"）: 列の最小・最大値の 16 進に元の値が入っているため、すべて取り除く
        - 列の削除: その列を使う索引・制約・コメントの文を取り除く（取り除いた索引の統計も）。ほかの文がその列を使っていれば断る
        """
        starts = [m.start() for m in RE_UNIT_START.finditer(part)]
        if not starts:
            return part
        units = [part[starts[k] : starts[k + 1] if k + 1 < len(starts) else len(part)] for k in range(len(starts))]
        out = [part[: starts[0]]]
        tokens = [b'"' + c.replace('"', '""').encode(self.codec) + b'"' for c in dropped_cols]
        # 取り除いた索引の名前（2 周目の区画の ANALCOMPUTE でも使うので、書き換えの間ずっと覚えておく）
        gone_indexes: set[bytes] = self.__dict__.setdefault("_gone_indexes", set())
        keep_flags = []
        for unit in units:
            drop = False
            m = RE_ANALSTATS_TABLE.match(unit)
            if m is not None:
                drop = _unescape_name(m.group(1), self.codec) == base
            elif tokens and any(t in unit for t in tokens):
                mi = RE_CREATE_INDEX.match(unit)
                if mi is not None:
                    gone_indexes.add(mi.group(1))
                    drop = True
                elif RE_ALTER_ADD.match(unit) or RE_COMMENT_COLUMN.match(unit):
                    drop = True
                else:
                    first = unit[: unit.find(b"\n") + 1 or 80][:80].decode(self.codec, "replace").strip()
                    raise RemedyError(
                        f"表「{name}」に付いた文（{first}…）が削除する列を使っていて、取り除き方が分からないため、列を削除できません"
                        "（元のファイルは変えていません）"
                    )
            keep_flags.append(not drop)
            if drop:
                self.stats["statements"] += 1
        for unit, keep in zip(units, keep_flags):
            if keep:
                mi = RE_ANALSTATS_INDEX.match(unit)
                if mi is not None:
                    # ANALSTATS IS の後ろの名前は表の名前のことがあるので、統計の文の中の索引の名前でも見る
                    ms = RE_SET_INDEX_STATS.search(unit)
                    if mi.group(1) in gone_indexes or (ms is not None and ms.group(1) in gone_indexes):
                        self.stats["statements"] += 1
                        continue
                ma = RE_ANALYZE_INDEX.match(unit)
                if ma is not None and ma.group(1) in gone_indexes:
                    self.stats["statements"] += 1
                    continue
                out.append(unit)
        return b"".join(out)


def rewrite_exp_dump(src: str, dst: str, method: str, sel: Selection, maker: DummyMaker | None) -> dict:
    from .engine import long_path

    with open(long_path(src), "rb") as f:
        head = f.read(64)
    if b"EXPORT:V" not in head:
        raise RemedyError("旧 exp のダンプとして読めないため、書き換えません（元のファイルは変えていません）")
    head_codec = od.CHARSET_CODECS.get(int.from_bytes(head[1:3], "big"), "utf-8")
    with open(long_path(src), "rb") as f_in, open(long_path(dst), "wb", buffering=1 << 20) as out:
        rw = _ExpRewriter(f_in, out, head_codec, method, sel, maker)
        stats = rw.run()
        out.flush()
        os.fsync(out.fileno())
    if stats["statements"]:
        stats["notes"] = [
            f"書き換えた表の統計などの文を {stats['statements']} 個取り除きました（統計には列の最小・最大値が入っているため。読み込んだあとに取り直せます）"
        ]
    return stats


# ---------------------------------------------------------------- expdp


def _align8(n: int) -> int:
    return (n + 7) & ~7


def _read_at(f, off: int, n: int) -> bytes:
    f.seek(off)
    return f.read(n)


def _find_marker(f, marker: bytes, start: int, size: int) -> int:
    """ファイルの start 以降で最初の marker の位置（無ければ -1）。少しずつ読む。"""
    pos = start
    keep = len(marker) - 1
    while pos < size:
        f.seek(pos)
        chunk = f.read(CHUNK)
        if not chunk:
            break
        i = chunk.find(marker)
        if i >= 0:
            return pos + i
        if len(chunk) <= keep:
            break
        pos += len(chunk) - keep
    return -1


@dataclass
class _DpSeg:
    name: str  # 同じ名前の区画を見分けた名前（「名前 (2)」）
    xml_at: int  # XML の先頭（<?xml）のファイル上の位置
    xml_len: int
    tbl: object
    rows_end: int  # 検査（読み取り）が行を読み終えた位置


class _Limited:
    """ファイルの start から nbytes バイトだけを読ませる（od._Stream に渡す）。"""

    def __init__(self, f, start: int, nbytes: int):
        self.f, self.left = f, nbytes
        f.seek(start)

    def read(self, n: int) -> bytes:
        if self.left <= 0:
            return b""
        b = self.f.read(min(n, self.left))
        self.left -= len(b)
        return b


def _hop_rows_end(f, start: int, tbl) -> int:
    """作りが分からない区画の行の終わり（検査の読み方と同じ）。ゼロを飛ばし、行（3C…）を順にたどる。"""
    f.seek(start)
    st = od._Stream(f)
    while True:
        while st.pos < len(st.buf) and st.buf[st.pos] == 0:
            st.pos += 1
        if st.pos < len(st.buf) or not st.more():
            break
    buf, pos = st.buf, st.pos
    while True:
        try:
            r = od._dp_row(buf, pos, len(buf), tbl)
        except od._NeedMore:
            st.pos = pos
            if not st.more():
                break
            buf, pos = st.buf, st.pos
            continue
        except (od._Bad, IndexError, ValueError):
            break
        if r[0] == "end":
            break
        pos = r[2]
    return st.total - len(st.buf) + pos


def _ctrl_fields(c: bytes) -> list[int] | None:
    if c[:4] != CTRL_MAGIC or len(c) < CTRL_FIELDS_AT + 48:
        return None
    return [struct.unpack(">Q", c[CTRL_FIELDS_AT + 8 * k : CTRL_FIELDS_AT + 8 * k + 8])[0] for k in range(6)]


def _structure_ok(f, size: int, seg_start: int, xml_len: int) -> list[int] | None:
    """区画が想定どおりの作り（制御ブロック＋本体）なら F1..F6 を返す。違えば None。"""
    if seg_start % BLOCK or seg_start < BLOCK or seg_start + BLOCK > size:
        return None
    fs = _ctrl_fields(_read_at(f, seg_start - BLOCK, BLOCK))
    if fs is None:
        return None
    f1, f2, f3, f4, f5, f6 = fs
    if f1 != 2 + xml_len or f2 != BLOCK or f4 != _align8(f1) + BLOCK or f6 != _align8(f1) + _align8(f3) + BLOCK:
        return None
    if f5 % 8 or seg_start + f6 - BLOCK + f5 > size:
        return None
    return fs


def _read_xml(f, at: int) -> bytes | None:
    """at から始まる列定義の XML（</ROWSET> まで）。検査と同じく、見つからないまま MAX_HEADER を超えたら None。少しずつ読む。"""
    f.seek(at)
    buf = b""
    while len(buf) <= od.MAX_HEADER:
        chunk = f.read(65536)
        if not chunk:
            return None
        buf += chunk
        e = buf.find(b"</ROWSET>")
        if e >= 0:
            return buf[: e + 9]
    return None


def find_dp_segments(f, size: int) -> list[_DpSeg]:
    """expdp のダンプから、検査（scan_oracle_tables）と同じ順で表の区画を見つける。"""
    segs: list[_DpSeg] = []
    counts: dict[str, int] = {}
    pos = 0
    marker = od.EXPDP_MARKER
    while True:
        j = _find_marker(f, marker, pos, size)
        if j < 0:
            break
        xml = _read_xml(f, j)
        if xml is None:
            pos = j + len(marker)
            continue
        tbl = od._parse_dp_xml(xml, od.dp_xml_codec(xml))
        if tbl is None:
            pos = j + len(marker)
            continue
        name = od.unique_table_name(counts, tbl.name)
        fs = _structure_ok(f, size, j - 2, len(xml))
        if fs is not None:
            rows_end = j - 2 + _align8(fs[0]) + fs[2]
        else:
            rows_end = _hop_rows_end(f, j + len(xml), tbl)
        segs.append(_DpSeg(name, j, len(xml), tbl, rows_end))
        pos = max(rows_end, j + len(marker))
    return segs


def _dp_cells(row: bytes) -> tuple[int, list]:
    """行（3C…）の列を (値 or None, 長さを 0xFE の形で書いてあったか) の並びにする。戻り値は（行の列数の印, 並び）。"""
    nc = row[3]
    q = 4
    cells = []
    for _ in range(nc):
        ln = row[q]
        q += 1
        if ln == 0xFF:
            cells.append((None, False))
            continue
        fe = ln == 0xFE
        if fe:
            ln = (row[q] << 8) | row[q + 1]
            q += 2
        cells.append((row[q : q + ln], fe))
        q += ln
    return nc, cells


def _dp_row_bytes(nc: int, cells: list) -> bytes:
    body = bytearray([nc])
    for v, fe in cells:
        if v is None:
            body.append(0xFF)
        elif fe or len(v) >= 0xFA:
            body += b"\xfe" + struct.pack(">H", len(v)) + v
        else:
            body.append(len(v))
            body += v
    total = len(body) + 3
    if total > MAX_ROW_TOTAL:
        raise RemedyError("置き換えた行が長すぎるため、書き換えません（元のファイルは変えていません）")
    return b"\x3c" + struct.pack(">H", total) + bytes(body)


class _IndexBuilder:
    """行の境界から、expdp の索引（[0, 前の項目から GRANULE 以上で最初の行の境界, …]）を作る。"""

    def __init__(self):
        self.entries = [0]
        self.next = GRANULE

    def row_start(self, off: int) -> None:
        if off >= self.next:
            self.entries.append(off)
            self.next = off + GRANULE

    def finish(self, n_rows: int, had_entries: bool) -> list[int]:
        return self.entries if (n_rows or had_entries) else []


def expdp_structure_problem(path: str, tables: set[str]) -> str:
    """書き換える表（tables）の区画が、書き換えられる作りか。だめなら理由（利用者に見せる文）、よければ空。

    分析の段で一度だけ確かめ、下見で断る（実行してから断ると、下見が通ったのに実行で断られて分かりにくい）。
    """
    with open(path, "rb") as f:
        size = os.fstat(f.fileno()).st_size
        for seg in find_dp_segments(f, size):
            if seg.name in tables and _structure_ok(f, size, seg.xml_at - 2, seg.xml_len) is None:
                return (
                    f"表「{seg.name}」の区画が想定した作り（制御ブロック・見出し・行・索引）と違うため、"
                    "中身を書き換えられません（切り出した・壊れたダンプなど）。ファイルの削除はできます"
                )
    return ""


def rewrite_dp_unit(f, out, seg: _DpSeg, size: int, row_fn) -> tuple[int, int]:
    """expdp の表の単位（制御ブロック＋本体）を、同じ大きさで書き直す。

    row_fn(行の番号, 行のバイト列 bytes) → _KEEP（そのまま）／None（取り除く）／bytes（置き換える）。
    戻り値は（取り除いた行数, 書いた行数）。想定と違う作りは RemedyError。
    """
    seg_start = seg.xml_at - 2
    fs = _structure_ok(f, size, seg_start, seg.xml_len)
    if fs is None:
        raise RemedyError(
            f"表「{seg.name}」の区画が想定した作り（制御ブロック・見出し・行・索引）と違うため、書き換えに対応していません"
            "（元のファイルは変えていません）"
        )
    f1, _f2, f3, _f4, f5, _f6 = fs
    rows_at = seg_start + _align8(f1)
    idx_at = seg_start + _align8(f1) + _align8(f3)
    seg_len = _unit_length(fs)
    if seg_start + seg_len != size and _read_at(f, seg_start + seg_len, 4) != CTRL_MAGIC:
        raise RemedyError(
            f"表「{seg.name}」の区画のあとが、次の単位の制御ブロックでないため、書き換えに対応していません"
        )
    if _read_at(f, seg_start + f1, rows_at - seg_start - f1).strip(b"\x00"):
        raise RemedyError(
            f"表「{seg.name}」の見出しと行のあいだに、想定していない値があるため、書き換えに対応していません"
        )
    if _read_at(f, idx_at + f5, seg_start + seg_len - idx_at - f5).strip(b"\x00"):
        raise RemedyError(f"表「{seg.name}」の索引のあとに、想定していない値があるため、書き換えに対応していません")
    # 元の制御ブロック（あとで F3・F5・F6 を直して書き直す）と、見出し（XML とゼロ詰め。変えずに写す）
    ctrl = bytearray(_read_at(f, seg_start - BLOCK, BLOCK))
    ctrl_pos = out.tell()
    out.write(bytes(ctrl))
    out.write(_read_at(f, seg_start, rows_at - seg_start))
    # 行
    st = od._Stream(_Limited(f, rows_at, f3))
    old_idx, new_idx = _IndexBuilder(), _IndexBuilder()
    old_off = new_off = 0
    n = kept = removed = 0
    buf, pos = st.buf, st.pos
    copy_from = pos

    def more() -> bool:
        """未処理の手前までを書き出して、続きを読み足す。"""
        nonlocal buf, pos, copy_from
        out.write(buf[copy_from:pos])
        st.pos = pos
        ok = st.more()
        buf, pos = st.buf, st.pos
        copy_from = pos
        return ok

    cut = f"表「{seg.name}」の行が、行の合計（制御ブロックの値）の境目で切れているため、書き換えません"
    while True:
        if len(buf) - pos < 3:
            if not more():
                if len(buf) - pos:
                    raise RemedyError(cut)
                break
            continue
        if buf[pos] != 0x3C:
            raise RemedyError(f"表「{seg.name}」の行の並びに、行でないバイトがあるため、書き換えに対応していません")
        total = (buf[pos + 1] << 8) | buf[pos + 2]
        if total < 4:
            raise RemedyError(f"表「{seg.name}」の行の長さが小さすぎるため、書き換えません")
        if len(buf) - pos < total:
            if not more():
                raise RemedyError(cut)
            continue
        n += 1
        row_end = pos + total
        old_idx.row_start(old_off)
        res = row_fn(n, buf[pos:row_end])
        if res is _KEEP:
            new_idx.row_start(new_off)
            new_off += total
            kept += 1
        else:
            out.write(buf[copy_from:pos])
            copy_from = row_end
            if res is None:
                removed += 1
            else:
                new_idx.row_start(new_off)
                out.write(res)
                new_off += len(res)
                kept += 1
        old_off += total
        pos = row_end
    out.write(buf[copy_from:pos])
    if old_off != f3:
        raise RemedyError(f"表「{seg.name}」の行の合計が制御ブロックの値と合わないため、書き換えません")
    # 元の索引が、この読み方で作り直した索引と同じか（違えば、作りを取り違えている）
    had = f5 > 0
    expect = b"".join(struct.pack(">Q", v) for v in old_idx.finish(n, had))
    if _read_at(f, idx_at, f5) != expect:
        raise RemedyError(
            f"表「{seg.name}」の索引が、想定した作り（{GRANULE:,} バイトごとの行の境界）と違うため、書き換えに対応していません"
        )
    # 新しい行の後ろ: 索引とゼロ詰め（単位の大きさは同じ）
    entries = new_idx.finish(kept, had)
    new_f5 = 8 * len(entries)
    new_idx_rel = _align8(f1) + _align8(new_off)
    if new_idx_rel + new_f5 > seg_len:
        raise RemedyError(
            f"表「{seg.name}」は、置き換えると元の場所に収まらないため、書き換えません（元のファイルは変えていません）"
        )
    out.write(b"\x00" * (new_idx_rel - (_align8(f1) + new_off)))
    out.write(b"".join(struct.pack(">Q", v) for v in entries))
    out.write(b"\x00" * (seg_len - new_idx_rel - new_f5))
    end_pos = out.tell()
    # 制御ブロックの行の合計（F3）・索引の大きさ（F5）・索引の始まり（F6）を直す
    struct.pack_into(">Q", ctrl, CTRL_FIELDS_AT + 16, new_off)
    struct.pack_into(">Q", ctrl, CTRL_FIELDS_AT + 32, new_f5)
    struct.pack_into(">Q", ctrl, CTRL_FIELDS_AT + 40, new_idx_rel + BLOCK)
    out.seek(ctrl_pos)
    out.write(bytes(ctrl))
    out.seek(end_pos)
    return removed, kept


def _unit_length(fs: list[int]) -> int:
    """単位の本体の大きさ（ブロックの倍数）。見出し・行・索引を 8 バイト境界で並べた長さを、ブロック境界まで切り上げる。"""
    f1, _f2, f3, _f4, f5, _f6 = fs
    return (_align8(f1) + _align8(f3) + f5 + BLOCK - 1) // BLOCK * BLOCK


def rewrite_expdp_dump(src: str, dst: str, method: str, sel: Selection, maker: DummyMaker | None) -> dict:
    from .engine import long_path

    if method not in ("delete_rows", "dummy"):
        raise RemedyError(EXPDP_UNSUPPORTED_REASON)
    plans = _build_plans(method, sel)
    stats = {"rows": 0, "cols": 0, "tables": 0, "cells": 0, "detections": 0, "statements": 0}
    size = os.path.getsize(long_path(src))
    with open(long_path(src), "rb") as f:
        segs = find_dp_segments(f, size)
        found = {s.name for s in segs}
        for name in plans:
            if name.upper().startswith(od.DP_MASTER_PREFIXES):
                raise RemedyError("Data Pump の管理用の表（マスターテーブル）は書き換えられません")
        for name in plans:
            if name not in found:
                raise RemedyError(
                    f"表「{name}」の区画が見つかりませんでした。ファイルの読み方が検査と食い違ったため、書き換えません（元のファイルは変えていません）"
                )
        targets = sorted((s for s in segs if s.name in plans), key=lambda s: s.xml_at)
        with open(long_path(dst), "wb", buffering=1 << 20) as out:
            cursor = 0
            for seg in targets:
                plan = plans[seg.name]
                plan.touched = True
                ctrl_start = seg.xml_at - 2 - BLOCK
                _copy_range(f, out, cursor, ctrl_start)
                row_fn = _dp_row_fn(method, plan, seg, maker, stats)
                removed, _kept = rewrite_dp_unit(f, out, seg, size, row_fn)
                stats["rows"] += removed
                cursor = _unit_end(f, seg, size)
            _copy_range(f, out, cursor, size)
            out.flush()
            os.fsync(out.fileno())
    _check_found(method, plans, found)
    if method == "dummy" and stats["cells"] == 0:
        raise RemedyError("書き換える値が見つかりませんでした。元のファイルは変えていません")
    stats["notes"] = [
        "ファイルの大きさは変えずに、行と索引を詰めて残りをゼロで埋めました（マスターテーブルが持つ各表の位置を保つため）。"
        "圧縮された管理情報の区画（列の統計など）は変えていません"
    ]
    return stats


def _unit_end(f, seg: _DpSeg, size: int) -> int:
    """単位の終わり（次の単位の制御ブロックの位置）。"""
    fs = _structure_ok(f, size, seg.xml_at - 2, seg.xml_len)
    if fs is None:
        raise RemedyError(f"表「{seg.name}」の区画の作りが想定と違うため、書き換えに対応していません")
    return seg.xml_at - 2 + _unit_length(fs)


def _copy_range(f, out, start: int, end: int) -> None:
    f.seek(start)
    left = end - start
    while left > 0:
        b = f.read(min(CHUNK, left))
        if not b:
            raise RemedyError("ダンプが途中で切れているため、書き換えません")
        out.write(b)
        left -= len(b)


def _dp_row_fn(method: str, plan: _Plan, seg: _DpSeg, maker: DummyMaker | None, stats: dict):
    tbl = seg.tbl
    if method == "delete_rows":
        rows = plan.rows

        def fn(n: int, row: bytes):
            if n in rows:
                plan.seen_rows.add(n)
                return None
            return _KEEP

        return fn
    codecs = _column_codecs(tbl.types, tbl.csids, tbl.default_codec)
    editor = CellEditor(maker, tbl.columns, tbl.types, codecs, [0] * len(tbl.columns), strict=True)

    def fn(n: int, row: bytes):
        cols = plan.by_row.get(n)
        if cols is None:
            return _KEEP
        plan.seen_rows.add(n)
        nc, cells = _dp_cells(row)
        changed = False
        for c, spans in cols.items():
            if c >= nc or cells[c][0] is None:
                continue
            nb = editor.edit(c, cells[c][0], spans)
            if nb is not None:
                cells[c] = (nb, cells[c][1])
                stats["cells"] += 1
                stats["detections"] += len(spans)
                changed = True
        return _dp_row_bytes(nc, cells) if changed else _KEEP

    return fn


# ---------------------------------------------------------------- 入口


def rewrite_oracle_dump_file(
    src: str, dst: str, layout: str, method: str, sel: Selection, maker: DummyMaker | None
) -> dict:
    """Oracle のダンプ src を書き換えた結果を dst へ書く（巨大でもメモリに載せない）。元の src には書かない。失敗したら dst は消す。"""
    from .engine import long_path

    if method not in ("delete_rows", "delete_columns", "dummy", "delete_table"):
        raise RemedyError("この方法は Oracle のダンプに使えません")
    try:
        if layout == "oracle_exp":
            return rewrite_exp_dump(src, dst, method, sel, maker)
        if layout == "oracle_expdp":
            return rewrite_expdp_dump(src, dst, method, sel, maker)
        raise RemedyError("この形式の Oracle のダンプは、書き換えに対応していません")
    except BaseException:
        try:
            os.remove(long_path(dst))
        except OSError:
            pass
        raise

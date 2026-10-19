"""Oracle の旧 exp ダンプと expdp（Data Pump）ダンプを、表の列名つきで読む。

どちらも内部形式は公開されていないが、実物（21c・AL32UTF8）の解析で次の形だと分かった。

旧 exp
    `INSERT INTO "表" ("列", ...) VALUES (:1, ...)` の行の直後に、列数（2バイト LE）・列ごとの型と長さ
    （型が VARCHAR2=1・CHAR=96 のときは文字セット ID と形も）・`00 00` の後、行ごとに `00 00` と
    「列ごとの長さ（2バイト LE・0xFFFF は NULL）＋値」が続き、表の終わりは `00 00 FF FF`。

expdp（直接パス形式・圧縮なし）
    表ごとに 4KB 境界から `<?xml ...><ROWSET><ROW><STRMTABLE_T>...`（列の定義）があり、その直後から行が続く。
    行は `3C` ＋ 長さ（2バイト BE・見出しを含む総長）＋ 列数（1バイト）＋「列ごとの長さ（1バイト・0xFE は続く
    2バイト BE・0xFF は NULL）＋値」。

値は NUMBER（内部形式）・DATE（7バイト）・文字（列の文字セット）を解く。読み解けない部分（未対応の型・壊れた
区画・圧縮や暗号化・知らない形の表）は、表の外側と同じく文字列の走査に回し、取りこぼさない。
全体をメモリに載せず、少しずつ読む。
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field

from ..engine import Collector
from ..textdecode import entropy, iter_strings

CHUNK = 4 * 1024 * 1024  # 1回に読む大きさ
GAP_FLUSH = 8 * 1024 * 1024  # 表の外側の走査をまとめる大きさ
GAP_TAIL = 4096  # 走査の切れ目をまたぐ文字列のために持ち越す大きさ
MAX_HEADER = 8 * 1024 * 1024  # INSERT 文・列定義の XML の長さの上限（閉じない文で際限なく溜めない）
MAX_ROW = 256 * 1024 * 1024  # 1行の長さの上限
GAP_NONZERO_LIMIT = 4 * 1024 * 1024  # 表の外側の（ゼロでない）バイトがこれを超えたら、読めない表があるとみなす

# 文字セット ID（Oracle の NLS_CHARACTERSET の番号）→ Python の文字コード
CHARSET_CODECS = {
    1: "ascii",
    31: "latin-1",
    178: "cp1252",
    830: "euc_jp",
    832: "cp932",
    871: "utf-8",
    873: "utf-8",
    2000: "utf-16-be",
    2002: "utf-16-le",
}
# XML の <CHARSET> の名前 → Python の文字コード
CHARSET_NAMES = {
    "AL32UTF8": "utf-8",
    "UTF8": "utf-8",
    "JA16SJIS": "cp932",
    "JA16SJISTILDE": "cp932",
    "JA16EUC": "euc_jp",
    "JA16EUCTILDE": "euc_jp",
    "WE8MSWIN1252": "cp1252",
    "WE8ISO8859P1": "latin-1",
    "US7ASCII": "ascii",
}

TYPE_VARCHAR2, TYPE_NUMBER, TYPE_LONG, TYPE_DATE, TYPE_RAW, TYPE_CHAR = 1, 2, 8, 12, 23, 96
TYPE_TIMESTAMP, TYPE_TIMESTAMP_TZ, TYPE_TIMESTAMP_LTZ = 180, 181, 231
# 旧 exp の列の定義（型と長さの後ろに文字セット ID と形が付く型）と、付かない型
EXP_CHAR_TYPES = (TYPE_VARCHAR2, TYPE_CHAR)
EXP_PLAIN_TYPES = (TYPE_NUMBER, TYPE_DATE, TYPE_RAW, 100, 101, TYPE_TIMESTAMP, TYPE_TIMESTAMP_TZ, TYPE_TIMESTAMP_LTZ)

EXP_MARKER = b'INSERT INTO "'
EXPDP_MARKER = b'<?xml version="1.0"?><ROWSET><ROW>'
RE_EXP_INSERT = re.compile(rb'INSERT INTO "((?:[^"\n]|"")+)" \((.*)\) VALUES \((:\d+(?:, :\d+)*)\)\n')
RE_QUOTED = re.compile(rb'"((?:[^"]|"")*)"')
RE_XML_COL = re.compile(r"<COL_LIST_ITEM>(.*?)</COL_LIST_ITEM>", re.S)
RE_XML_OWNER_NAME = re.compile(r"<OWNER_NAME>[^<]*</OWNER_NAME><NAME>([^<]*)</NAME>")
RE_XML_CHARSET = re.compile(r"<CHARSET>([^<]*)</CHARSET>")


class _NeedMore(Exception):
    """行の途中でバッファの終わりに着いた（もう少し読めば続きが取れる）。"""


class _Bad(Exception):
    """形式が想定と合わない（理由を持つ）。この表の読み取りをやめ、残りは文字列の走査に回す。"""


@dataclass
class OracleScanResult:
    """表ごとの読み取りの結果。"""

    kind: str = ""  # "exp" または "expdp"
    tables: int = 0  # 読み解けた表の数
    rows: int = 0  # 読み解けた行の数
    row_bytes: int = 0  # 行として読み解いたバイト数
    total_bytes: int = 0  # 読んだバイト数
    gap_nonzero: int = 0  # 表の外側のゼロでないバイト数
    failed: list[str] = field(default_factory=list)  # 読み解けなかった表と理由
    unsupported_cols: dict[str, str] = field(default_factory=dict)  # 「表「X」列「Y」」 → 型の説明
    truncated: list[str] = field(default_factory=list)  # 途中で切れていた表
    chunks_high: int = 0  # 圧縮・暗号化されていそうな区画の数（表の外側のみ）
    chunks_total: int = 0


# ------------------------------------------------------------------ 値の解き方


def decode_number(b: bytes) -> str | None:
    """Oracle NUMBER の内部形式を十進の文字列にする。読めない形（無限大など）は None。"""
    if not b:
        return None
    first = b[0]
    if len(b) == 1:
        return "0" if first == 0x80 else None
    if first & 0x80:
        exp = first - 0xC1
        digs = [x - 1 for x in b[1:]]
        neg = False
    else:
        exp = 0x3E - first
        body = b[1:-1] if b[-1] == 0x66 else b[1:]  # 負数は末尾に 0x66 の終わりの印が付く（21バイト未満のとき）
        digs = [101 - x for x in body]
        neg = True
    if not digs or any(not 0 <= d <= 99 for d in digs) or len(digs) > 21:
        return None
    if exp >= 0:
        int_part = digs[: exp + 1] + [0] * max(0, exp + 1 - len(digs))
        frac_part = digs[exp + 1 :]
        int_s = "".join(f"{d:02d}" for d in int_part).lstrip("0") or "0"
        frac_s = "".join(f"{d:02d}" for d in frac_part).rstrip("0")
    else:
        int_s = "0"
        frac_s = ("00" * (-exp - 1) + "".join(f"{d:02d}" for d in digs)).rstrip("0")
    s = int_s + ("." + frac_s if frac_s else "")
    return "-" + s if neg and s != "0" else s


def decode_date(b: bytes) -> str | None:
    """Oracle DATE（7バイト）・TIMESTAMP（11バイト以上は先頭の7バイトだけ）を 日付／日時の文字列にする。"""
    if len(b) < 7:
        return None
    year = (b[0] - 100) * 100 + (b[1] - 100)
    month, day, hour, minute, sec = b[2], b[3], b[4] - 1, b[5] - 1, b[6] - 1
    if not (
        1 <= year <= 9999
        and 1 <= month <= 12
        and 1 <= day <= 31
        and 0 <= hour < 24
        and 0 <= minute < 60
        and 0 <= sec < 61
    ):
        return None
    s = f"{year:04d}-{month:02d}-{day:02d}"
    return s if (hour, minute, sec) == (0, 0, 0) else f"{s} {hour:02d}:{minute:02d}:{sec:02d}"


def _text_decoder(codec: str):
    def dec(b: bytes) -> str:
        return b.decode(codec, "replace")

    return dec


def _char_decoder(codec: str):
    def dec(b: bytes) -> str:
        return b.decode(codec, "replace").rstrip(" ")  # CHAR は右側が空白で埋められる

    return dec


def _make_decoder(type_num: int, csid: int, codec_override: str | None = None):
    """列の型から「バイト列 → 文字列」の関数を作る。扱えない型は None（その列は文字列の走査に回す）。"""
    if type_num in (TYPE_VARCHAR2, TYPE_CHAR):
        codec = CHARSET_CODECS.get(csid) or codec_override
        if not codec:
            return None
        return _char_decoder(codec) if type_num == TYPE_CHAR else _text_decoder(codec)
    if type_num == TYPE_NUMBER:
        return decode_number
    if type_num in (TYPE_DATE, TYPE_TIMESTAMP, TYPE_TIMESTAMP_TZ, TYPE_TIMESTAMP_LTZ):
        return decode_date
    return None


def _type_label(type_num: int) -> str:
    names = {
        8: "LONG",
        23: "RAW",
        24: "LONG RAW",
        100: "BINARY_FLOAT",
        101: "BINARY_DOUBLE",
        112: "CLOB",
        113: "BLOB",
        114: "BFILE",
        180: "TIMESTAMP",
        181: "TIMESTAMP WITH TIME ZONE",
        231: "TIMESTAMP WITH LOCAL TIME ZONE",
    }
    if type_num in names:
        return f"{names[type_num]}(型番号 {type_num})"
    return f"型番号 {type_num}"


# ------------------------------------------------------------------ 読み込みの道具


class _Stream:
    """ファイルを少しずつ読むバッファ。buf[pos:] が未処理の部分。"""

    def __init__(self, f) -> None:
        self.f = f
        self.buf = b""
        self.pos = 0
        self.eof = False
        self.total = 0

    def more(self) -> bool:
        """もう一塊読み足す（処理済みの前半は捨てる）。読み足せなければ False。pos は 0 に戻る。"""
        if self.eof:
            return False
        chunk = self.f.read(CHUNK)
        if not chunk:
            self.eof = True
            return False
        self.total += len(chunk)
        self.buf = self.buf[self.pos :] + chunk
        self.pos = 0
        return True

    def ensure(self, need: int) -> bool:
        """buf[pos:] を need バイト以上にする。足りなければ False。"""
        while len(self.buf) - self.pos < need:
            if not self.more():
                return False
        return True


class _GapSweeper:
    """表として読めなかった部分（表の外側・壊れた表の残り・扱えない型の値）の文字列を、これまでと同じく走査する。"""

    def __init__(self, col: Collector, res: OracleScanResult) -> None:
        self.col = col
        self.res = res
        self.parts: list[bytes] = []
        self.size = 0
        self.tail = b""
        self.seen: set[str] = set()

    def feed(self, data) -> None:
        """表の外側のバイト列を渡す。"""
        if not data:
            return
        data = bytes(data)
        self.res.gap_nonzero += len(data) - data.count(0)
        self._add(data)

    def feed_cell(self, data: bytes) -> None:
        """読み解けなかった値のバイト列を渡す（表の外側の量には数えない）。"""
        if data:
            self._add(data + b"\x00")

    def _add(self, data: bytes) -> None:
        self.parts.append(data)
        self.size += len(data)
        if self.size >= GAP_FLUSH:
            self.flush()

    def flush(self, boundary: bool = False) -> None:
        """たまった分を走査する。boundary=True は離れた場所との境目（持ち越しを捨てる）。"""
        if self.parts:
            body = b"".join(self.parts)
            self.parts, self.size = [], 0
            if len(body) >= 65536:
                self.res.chunks_total += 1
                if entropy(body[:1_000_000]) > 7.5:
                    self.res.chunks_high += 1
            data = self.tail + body
            for s in iter_strings(data):
                if s not in self.seen:
                    self.seen.add(s)
                    self.col.add_text(s, "生データ", method="生データ走査")
            if len(self.seen) > 2_000_000:
                self.seen.clear()
            self.tail = data[-GAP_TAIL:]
        if boundary:
            self.tail = b""


# ------------------------------------------------------------------ 旧 exp


@dataclass
class _ExpTable:
    name: str
    columns: list[str]
    descs: list[tuple]  # (型, 最大の長さ, 文字セット ID)
    decoders: list


def _parse_exp_header(st: _Stream, head_codec: str):
    """st.pos にある INSERT 文から表の定義を読む。
    戻り値は (_ExpTable, st.pos から行の始まりまでの長さ)。INSERT 文として読めなければ None、列の定義が想定と合わなければ _Bad。"""
    eol = st.buf.find(b"\n", st.pos)
    while eol < 0:
        if len(st.buf) - st.pos > MAX_HEADER or not st.more():
            return None
        eol = st.buf.find(b"\n", st.pos)
    m = RE_EXP_INSERT.match(st.buf, st.pos, eol + 1)
    if not m:
        return None
    name = m.group(1).decode(head_codec, "replace").replace('""', '"')
    columns = [c.decode(head_codec, "replace").replace('""', '"') for c in RE_QUOTED.findall(m.group(2))]
    ncols = len(m.group(3).split(b","))
    if len(columns) != ncols:
        return None
    # 列の定義: 列数(2) + 列ごとに 型(2)・長さ(2)（文字型はさらに 文字セット ID(2)・形(2)）+ 終わりの 00 00
    rel = m.end() - st.pos
    if not st.ensure(rel + 2 + 8 * ncols + 2):
        raise _Bad("列の定義が途中で切れている")
    buf = st.buf
    p = st.pos + rel
    if int.from_bytes(buf[p : p + 2], "little") != ncols:
        raise _Bad("列数が INSERT 文と合わない")
    p += 2
    descs: list[tuple] = []
    decoders = []
    for _ in range(ncols):
        t = int.from_bytes(buf[p : p + 2], "little")
        ln = int.from_bytes(buf[p + 2 : p + 4], "little")
        p += 4
        csid = 0
        if t in EXP_CHAR_TYPES:
            csid = int.from_bytes(buf[p : p + 2], "little")
            p += 4
        elif t not in EXP_PLAIN_TYPES:
            raise _Bad(f"列の型が未対応（{_type_label(t)}）で、行の並びを読めない")
        descs.append((t, ln, csid))
        decoders.append(_make_decoder(t, csid, head_codec if t in EXP_CHAR_TYPES else None))
    if buf[p : p + 2] != b"\x00\x00":
        raise _Bad("列の定義の終わりの印が見つからない")
    return _ExpTable(name, columns, descs, decoders), p + 2 - st.pos


def _exp_row(buf: bytes, pos: int, n: int, tbl: _ExpTable, eof: bool):
    """exp の1行（先頭の 00 00 から）を切り出す。戻り値は ("row", 生の値の並び, 次の位置) か ("end", 次の位置)。"""
    descs = tbl.descs
    ncols = len(descs)
    if pos + 4 > n:
        raise _NeedMore
    if buf[pos] != 0 or buf[pos + 1] != 0:
        raise _Bad("行の先頭の印（00 00）が見つからない")
    q = pos + 2
    if buf[q] == 0xFF and buf[q + 1] == 0xFF:
        # 表の終わりか、先頭の列が NULL か。終わりの後には次の文の改行が続く
        if q + 4 > n and not eof:
            raise _NeedMore
        nxt = buf[q + 2 : q + 4]
        if ncols == 1:
            is_end = nxt[:1] == b"\n" or (eof and not nxt)
        else:
            col2 = int.from_bytes(buf[q + 2 : q + 4], "little") if len(nxt) == 2 else 0
            is_end = (
                (eof and not nxt)
                or (nxt[:1] == b"\n" and (len(nxt) < 2 or nxt[1] >= 0x20))
                or (len(nxt) == 2 and col2 != 0xFFFF and col2 > max(descs[1][1], 22))
            )
        if is_end:
            return "end", q + 2
    raws: list[bytes | None] = []
    for i in range(ncols):
        if q + 2 > n:
            raise _NeedMore
        ln = buf[q] | (buf[q + 1] << 8)
        q += 2
        if ln == 0xFFFF:
            raws.append(None)
            continue
        if q + ln > n:
            raise _NeedMore
        t, maxlen, _ = descs[i]
        if (t == TYPE_DATE and ln != 7) or (t != TYPE_DATE and ln > max(maxlen, 22 if t == TYPE_NUMBER else 0)):
            raise _Bad(f"列「{tbl.columns[i]}」の長さ {ln} が定義（{maxlen}）と合わない")
        raws.append(buf[q : q + ln])
        q += ln
    return "row", raws, q


# ------------------------------------------------------------------ expdp


@dataclass
class _DpTable:
    name: str
    columns: list[str]
    types: list[int]
    decoders: list


def _parse_dp_xml(xml: bytes, default_codec: str):
    """列定義の XML から表の定義を取り出す。読めなければ None。"""
    text = xml.decode(default_codec, "replace")
    m = RE_XML_OWNER_NAME.search(text)
    if not m:
        return None
    name = html.unescape(m.group(1))
    cols, types, decoders = [], [], []
    for item in RE_XML_COL.findall(text):
        fields = dict(re.findall(r"<([A-Z_]+)>([^<]*)</\1>", item))
        if "NAME" not in fields or "TYPE_NUM" not in fields:
            return None
        try:
            t = int(fields["TYPE_NUM"])
            csid = int(fields.get("CHARSETID", "0") or 0)
        except ValueError:
            return None
        cols.append(html.unescape(fields["NAME"]))
        types.append(t)
        decoders.append(_make_decoder(t, csid, default_codec if t in (TYPE_VARCHAR2, TYPE_CHAR) else None))
    if not cols:
        return None
    return _DpTable(name, cols, types, decoders)


def _dp_row(buf: bytes, pos: int, n: int, tbl: _DpTable):
    """expdp の1行を切り出す。戻り値は ("row", 生の値の並び, 次の位置) か ("end", pos)。"""
    if pos >= n:
        raise _NeedMore
    if buf[pos] != 0x3C:
        return "end", pos
    if pos + 4 > n:
        raise _NeedMore
    total = (buf[pos + 1] << 8) | buf[pos + 2]
    nc = buf[pos + 3]
    if total < 4:
        raise _Bad("行の長さが小さすぎる")
    if nc > len(tbl.columns):
        raise _Bad(f"行の列数 {nc} が表の定義（{len(tbl.columns)}）より多い")
    if pos + total > n:
        raise _NeedMore
    end = pos + total
    q = pos + 4
    raws: list[bytes | None] = []
    for _ in range(nc):
        if q >= end:
            raise _Bad("行の長さの中に列が収まらない")
        ln = buf[q]
        q += 1
        if ln == 0xFF:
            raws.append(None)
            continue
        if ln == 0xFE:
            if q + 2 > end:
                raise _Bad("行の長さの中に列が収まらない")
            ln = (buf[q] << 8) | buf[q + 1]
            q += 2
        if q + ln > end:
            raise _Bad("列の長さが行の長さを超えた")
        raws.append(buf[q : q + ln])
        q += ln
    if q != end:
        raise _Bad("行の長さと列の並びが合わない")
    raws += [None] * (len(tbl.columns) - nc)  # 末尾の NULL の列は省かれる
    return "row", raws, end


# ------------------------------------------------------------------ 表を流す共通部分


def _decode_row(raws, decoders, sweeper: _GapSweeper, bad_cols: set[int]) -> list:
    """生の値を文字列にする。解けない値は、文字列の走査に回して取りこぼさない。"""
    out = []
    for i, raw in enumerate(raws):
        if raw is None:
            out.append(None)
            continue
        dec = decoders[i]
        v = dec(raw) if dec is not None else None
        if v is None:
            if dec is None:
                bad_cols.add(i)
            sweeper.feed_cell(raw)
        out.append(v)
    return out


def scan_oracle_tables(f, col: Collector, kind: str, head: bytes) -> OracleScanResult:
    """ファイルを先頭から少しずつ読み、表の行を列名つきで検査する。表の外側は文字列の走査に回す。"""
    res = OracleScanResult(kind=kind)
    st = _Stream(f)
    sweeper = _GapSweeper(col, res)
    marker = EXP_MARKER if kind == "exp" else EXPDP_MARKER
    head_codec = "utf-8"
    if kind == "exp" and len(head) >= 3:
        head_codec = CHARSET_CODECS.get(int.from_bytes(head[1:3], "big"), "utf-8")
    while True:
        idx = st.buf.find(marker, st.pos)
        if idx < 0:
            # 見つからない間は、印が境目をまたぐ分だけ残して走査へ回す
            keep = min(len(marker) + 8, len(st.buf) - st.pos)
            safe = len(st.buf) - keep
            if safe > st.pos:
                sweeper.feed(st.buf[st.pos : safe])
                st.pos = safe
            if not st.more():
                sweeper.feed(st.buf[st.pos :])
                st.pos = len(st.buf)
                break
            continue
        sweeper.feed(st.buf[st.pos : idx])
        st.pos = idx
        handled = _read_table(st, col, sweeper, res, kind, head_codec)
        if not handled:
            sweeper.feed(st.buf[st.pos : st.pos + len(marker)])
            st.pos += len(marker)
    sweeper.flush(boundary=True)
    res.total_bytes = st.total
    return res


def _read_table(
    st: _Stream, col: Collector, sweeper: _GapSweeper, res: OracleScanResult, kind: str, head_codec: str
) -> bool:
    """st.pos にある表の先頭から行を流す。表として読めなければ False（st.pos は進めない）。"""
    if kind == "exp":
        try:
            parsed = _parse_exp_header(st, head_codec)
        except _Bad as exc:
            m = RE_EXP_INSERT.match(st.buf, st.pos, min(len(st.buf), st.pos + MAX_HEADER))
            label = m.group(1).decode(head_codec, "replace") if m else "（不明）"
            res.failed.append(f"表「{label}」: {exc}")
            return False
        if parsed is None:
            return False
        tbl, header_len = parsed
        st.pos += header_len
        decoders = tbl.decoders
        col_types = [d[0] for d in tbl.descs]
    else:
        end = st.buf.find(b"</ROWSET>", st.pos)
        while end < 0:
            if len(st.buf) - st.pos > MAX_HEADER or not st.more():
                return False
            end = st.buf.find(b"</ROWSET>", st.pos)
        xml = st.buf[st.pos : end + 9]
        # 文字セット名は XML の先頭近くにある
        mcs = RE_XML_CHARSET.search(xml[:4096].decode("ascii", "replace"))
        codec = CHARSET_NAMES.get(mcs.group(1), "utf-8") if mcs else "utf-8"
        tbl = _parse_dp_xml(xml, codec)
        if tbl is None:
            return False
        st.pos = end + 9
        # XML の後ろは数バイトのゼロを挟んで行が始まる
        while True:
            while st.pos < len(st.buf) and st.buf[st.pos] == 0:
                st.pos += 1
            if st.pos < len(st.buf) or not st.more():
                break
        decoders = tbl.decoders
        col_types = tbl.types

    # status: None=最後まで流れていない / "end"=表の終わりまで読めた / "truncated"=途中で切れていた / "bad"=形式が合わず中断
    state = {"status": None, "reason": "", "rows": 0, "bytes": 0}
    bad_cols: set[int] = set()

    def rows():
        buf, pos = st.buf, st.pos
        at_eof = False  # ファイルの終わりまで読んだ後の読み直しの最中
        try:
            while True:
                try:
                    if kind == "exp":
                        r = _exp_row(buf, pos, len(buf), tbl, st.eof)
                    else:
                        r = _dp_row(buf, pos, len(buf), tbl)
                except _NeedMore:
                    st.pos = pos
                    if len(buf) - pos > MAX_ROW:
                        raise _Bad("1行が大きすぎる") from None
                    if not st.more():
                        if not at_eof:
                            at_eof = True  # 終わりの印の判定は eof を知ってからやり直す
                            continue
                        # ファイルの終わり。exp は終わりの印が無い・expdp は行の途中で終わっていれば、切れたダンプ
                        clean = kind == "expdp" and pos >= len(buf)
                        state["status"] = "end" if clean else "truncated"
                        return
                    buf, pos = st.buf, st.pos
                    continue
                at_eof = False
                if r[0] == "end":
                    pos = r[1]
                    state["status"] = "end"
                    return
                state["rows"] += 1
                state["bytes"] += r[2] - pos
                pos = r[2]
                yield _decode_row(r[1], decoders, sweeper, bad_cols)
        except _Bad as exc:
            state["status"], state["reason"] = "bad", str(exc)
        except (IndexError, ValueError) as exc:
            state["status"], state["reason"] = "bad", f"行を読み解けない（{type(exc).__name__}）"
        finally:
            st.pos = pos  # 読めたところまで進める（残りは表の外側と同じく文字列の走査へ）

    name, columns = tbl.name, tbl.columns
    col.add_records(
        columns,
        rows(),
        lambda r, c, name=name, columns=columns: f"表「{name}」{r}行目 列「{columns[c] if c < len(columns) else c + 1}」",
        method="Oracle ダンプの行データ",
    )
    res.rows += state["rows"]
    res.row_bytes += state["bytes"]
    for i in sorted(bad_cols):
        res.unsupported_cols[f"表「{name}」列「{columns[i]}」"] = _type_label(col_types[i])
    if state["status"] in ("bad", None):
        reason = state["reason"] or "読み取りが途中で止まった"
        res.failed.append(f"表「{name}」: {reason}（{state['rows']}行目まで読めた）")
    else:
        res.tables += 1
        if state["status"] == "truncated":
            res.truncated.append(f"表「{name}」（{state['rows']}行まで）")
    sweeper.flush(boundary=True)
    return True

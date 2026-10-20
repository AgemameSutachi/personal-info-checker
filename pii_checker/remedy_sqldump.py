"""対処（remediate）で、SQL のダンプ（pg_dump の平文・mysqldump・一般の INSERT 文の .sql）を書き換える部分（T2-b）。

決まり:
- 検査（formats/dbdump.py の scan_sql_lines）と同じ読み方で1行ずつ読み、一時の新ファイルへ1行ずつ書く（巨大でも全文をメモリに載せない。
  複数行にまたがる INSERT 文だけは、検査と同じく「;」で終わる行まで1文としてメモリに持つ）。
- 触らない行は、バイト列をそのまま写す（文字コード・BOM・改行を保つ）。書き換えた行・文の改行も、元の改行を使う。
- 位置は検査のときに集めたもの。行の鍵は COPY のデータ行が（行番号 << 24）、INSERT の組が（文の先頭の行番号 << 24 | 文の中の何組目か）。
  生の値は位置に入れていないので、ダミー化は書き換えるときにその場で値を読み直す。
- 書き換えのあと、選んだ位置がすべて見つかったかを確かめる（検査と読み方が食い違っていれば、書き換えを断る）。
"""

from __future__ import annotations

import codecs
import os
import re
from bisect import bisect_right
from dataclasses import dataclass, field

from .formats.dbdump import (
    CONSTRAINT_WORDS,
    RE_COPY,
    RE_CREATE,
    RE_CREATE_START,
    RE_INSERT,
    ROW_KEY_SHIFT,
    SQL_STMT_LIMIT,
    _clean_ident,
    _Pushback,
    _unescape_copy,
    parse_create_tables,
    parse_values_spans,
    split_top_level,
)
from .remedy_write import TEXT_REWRITE_LIMIT, DummyMaker, RemedyError, Selection, decode_for_rewrite, replace_spans

RE_LINE = re.compile(r"([^\r\n]*)(\r\n|\r|\n)|([^\r\n]+)")
CREATE_LINES_LIMIT = 5000  # 検査（scan_sql_lines）が CREATE 文として集める行数の上限
ROW_MASK = (1 << ROW_KEY_SHIFT) - 1
HEAD_BYTES = 4 * 1024 * 1024  # 巨大なテキストの文字コードを決める先頭の大きさ（検査の _handle_huge_text と同じ）
ENCODINGS = ("utf-8", "cp932", "euc_jp", "utf-16-le", "utf-16-be")

IDENT = r"(?:[`\"\[]?[\w$]+[`\"\]]?\.)*[`\"\[]?[\w$]+[`\"\]]?"
RE_STMT_START = re.compile(r"^\s*(?:/\*!\d+\s+)?(?:ALTER|CREATE|DROP|LOCK|COMMENT|GRANT|REVOKE)\b", re.I)
RE_STMT_KINDS = [
    ("drop", re.compile(rf"^\s*DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?P<t>{IDENT})", re.I)),
    ("lock", re.compile(rf"^\s*LOCK\s+TABLES\s+(?P<t>{IDENT})", re.I)),
    ("keys", re.compile(rf"^\s*/\*!\d+\s+ALTER\s+TABLE\s+(?P<t>{IDENT})\s+(?:DISABLE|ENABLE)\s+KEYS", re.I)),
    ("owned", re.compile(rf"^\s*ALTER\s+SEQUENCE\s+.*?\bOWNED\s+BY\s+(?P<t>{IDENT})", re.I | re.S)),
    ("alter", re.compile(rf"^\s*ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?(?P<t>{IDENT})", re.I)),
    (
        "index",
        re.compile(
            rf"^\s*CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?{IDENT}\s+ON\s+(?:ONLY\s+)?(?P<t>{IDENT})",
            re.I,
        ),
    ),
    ("comment_table", re.compile(rf"^\s*COMMENT\s+ON\s+TABLE\s+(?P<t>{IDENT})", re.I)),
    ("comment_column", re.compile(rf"^\s*COMMENT\s+ON\s+COLUMN\s+(?P<t>{IDENT})", re.I)),
    (
        "grant",
        re.compile(rf"^\s*(?:GRANT|REVOKE)\s+.*?\s+ON\s+(?:TABLE\s+)?(?P<t>{IDENT})\s+(?:TO|FROM)\b", re.I | re.S),
    ),
    (
        "trigger",
        re.compile(
            rf"^\s*CREATE\s+(?:OR\s+REPLACE\s+)?(?:CONSTRAINT\s+)?TRIGGER\s+{IDENT}\b.*?\bON\s+(?P<t>{IDENT})",
            re.I | re.S,
        ),
    ),
]
RE_ALTER_CONSTRAINT = re.compile(r"\bADD\s+(?:CONSTRAINT|PRIMARY|UNIQUE|FOREIGN|CHECK)\b", re.I)
RE_COLUMN_LINE = re.compile(r'([`"\[]?)([^`"\]\s]+)\1?\]?\s+\w')
RE_CREATE_NAME = re.compile(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([`\"\[\]\w.]+)", re.I)
RE_INTRODUCER = re.compile(r"(?:[NnEeBbXx]|_[A-Za-z0-9]+)")  # 文字列の前に付く接頭辞（N'…'・_utf8mb4'…'）
RE_QUOTED_CELL = re.compile(r"(\s*)([^']*)'((?:[^'\\]|\\.|'')*)'(\s*)", re.S)


# ---------------------------------------------------------------- 入出力（文字コード・改行を保つ）


def detect_encoding(path: str) -> tuple[str, bytes]:
    """検査（handle_text・_handle_huge_text）と同じ決め方で、書き換えに使う文字コードと BOM を決める。"""
    from .engine import long_path
    from .formats import misc
    from .textdecode import decode_text

    size = os.path.getsize(long_path(path))
    with open(long_path(path), "rb") as f:
        data = f.read() if size <= misc.TEXT_READ_ALL_LIMIT else f.read(HEAD_BYTES)
    if data.startswith(codecs.BOM_UTF8):
        return "utf-8", codecs.BOM_UTF8
    if data.startswith(codecs.BOM_UTF16_LE):
        return "utf-16-le", codecs.BOM_UTF16_LE
    if data.startswith(codecs.BOM_UTF16_BE):
        return "utf-16-be", codecs.BOM_UTF16_BE
    label = decode_text(data)[1].split("(")[0]
    if label not in ENCODINGS:
        raise RemedyError(
            f"文字コード（{label}）の SQL は、書き換えに対応していません（ファイルの削除はできます）。元のファイルは変えていません"
        )
    return label, b""


def _split_lines(text: str):
    """文字列を（本文, 改行）に分ける。改行は \\r\\n・\\r・\\n（検査が行を数える数え方と同じ）。"""
    for m in RE_LINE.finditer(text):
        if m.group(2) is not None:
            yield m.group(1), m.group(2)
        else:
            yield m.group(3), ""


def _stream_lines(path: str, enc: str, bom: bytes):
    """ASCII と同じ改行の文字コード（utf-8・cp932・euc_jp）のファイルを、1行ずつ（本文, 改行）で返す。元のバイト列に戻せない行は断る。"""
    from .engine import long_path

    with open(long_path(path), "rb") as f:
        first = True
        for raw in f:
            if first:
                first = False
                if bom and raw.startswith(bom):
                    raw = raw[len(bom) :]
            try:
                text = raw.decode(enc)
            except UnicodeDecodeError:
                raise RemedyError(
                    "文字コードを読み取れない行があるため、書き換えません（元のファイルは変えていません）"
                ) from None
            if text.encode(enc) != raw:
                raise RemedyError(
                    "文字コードを変換して戻しても元と同じ中身にならない行があるため、書き換えません（元のファイルは変えていません）"
                )
            yield from _split_lines(text)


def open_dump(path: str):
    """（行の並び（本文, 改行）, 文字コード, BOM）。"""
    from .engine import long_path

    enc, bom = detect_encoding(path)
    if enc.startswith("utf-16"):
        if os.path.getsize(long_path(path)) > TEXT_REWRITE_LIMIT:
            raise RemedyError(
                f"大きすぎるため書き換えできません（UTF-16 は {TEXT_REWRITE_LIMIT // 1024**2}MB まで。ファイルの削除はできます）"
            )
        with open(long_path(path), "rb") as f:
            text, name, bom2 = decode_for_rewrite(f.read())
        return _split_lines(text), name, bom2
    return _stream_lines(path, enc, bom), enc, bom


# ---------------------------------------------------------------- 名前・位置の選び方


def norm_ident(name: str) -> str:
    """表名を引用符・括弧を外して、ドットで区切った形にそろえる。"""
    return ".".join(p.strip().strip('`"[]').strip() for p in name.split("."))


def _last_part(name: str) -> str:
    return name.rsplit(".", 1)[-1]


def norm_col(name: str) -> str:
    return name.strip().strip('`"[]').strip()


@dataclass
class Target:
    """書き換える表1つ分の位置（検査のときに集めたもの）。"""

    name: str
    rows: set
    cols: set
    by_row: dict  # 行の鍵 → {列 → [(開始, 終了, 種類)]}
    seen_rows: set = field(default_factory=set)
    touched: bool = False  # この表の文を1つでも書き換えた・消した


class Targets:
    def __init__(self, sel: Selection):
        rows, cols, spans = sel.rows(), sel.cols(), sel.spans()
        self.items: dict[str, Target] = {}
        for table in sel.sheets():
            by_row: dict = {}
            for (r, c), lst in spans.get(table, {}).items():
                by_row.setdefault(r, {})[c] = lst
            self.items[norm_ident(table)] = Target(table, rows.get(table, set()), cols.get(table, set()), by_row)

    def find(self, name: str) -> Target | None:
        """文の中の表名に当たる対象（スキーマ名の有無が違っても、最後の部分が1つに決まれば当てる）。"""
        n = norm_ident(name)
        hit = self.items.get(n)
        if hit is not None:
            return hit
        last = _last_part(n)
        cands = [v for k, v in self.items.items() if _last_part(k) == last and ("." not in k or "." not in n)]
        return cands[0] if len(cands) == 1 else None


# ---------------------------------------------------------------- 値の読み書き（SQL の引用・エスケープ）


def _unescape_sql(body: str) -> str:
    """検査（parse_values_spans）と同じ、引用符の中身のエスケープの外し方。"""
    out = []
    i, n = 0, len(body)
    while i < n:
        c = body[i]
        if c == "\\" and i + 1 < n:
            out.append({"n": "\n", "t": "\t", "r": "\r", "0": ""}.get(body[i + 1], body[i + 1]))
            i += 2
            continue
        if c == "'" and i + 1 < n and body[i + 1] == "'":
            out.append("'")
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _sql_escape(text: str, backslash: bool) -> str:
    """文字列を、引用符の中へ入れる形にする。元が \\ のエスケープを使っていれば、同じ流儀で書く（改行も \\n にする）。"""
    if backslash:
        text = text.replace("\\", "\\\\")
    text = text.replace("'", "''")
    if backslash:
        text = text.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    return text


def _whole_cell(spans: list, parsed: str, maker: DummyMaker) -> str:
    return maker.make(spans[0][2], parsed)


def dummy_insert_cell(raw: str, parsed: str, spans: list, maker: DummyMaker) -> str:
    """INSERT の値1つ（元の書き方 raw・検査と同じ読み方の文字列 parsed）の、検出した部分をダミーにした書き方を返す。

    値の書き方は、前後の空白・接頭辞（N・_utf8mb4 など）・引用符の流儀を保つ。数値など引用符の無い値は、文字列として引用符で囲む。
    変わらないときは raw をそのまま返す。
    """
    m = RE_QUOTED_CELL.fullmatch(raw)
    if m is None:
        new = replace_spans(parsed, spans, maker)
        if new == parsed:
            return raw
        lead = raw[: len(raw) - len(raw.lstrip())]
        trail = raw[len(raw.rstrip()) :]
        return f"{lead}'{_sql_escape(new, False)}'{trail}"
    lead, prefix, body, trail = m.groups()
    backslash = "\\" in body
    pre = prefix.lstrip()
    ub = _unescape_sql(body)
    full = pre + ub
    if full.strip() != parsed:
        # 検査の読み方と合わない（連結した文字列など）。セル全体をダミーにする
        if replace_spans(parsed, spans, DummyMaker("fixed")) == parsed:
            return raw
        whole = _whole_cell(spans, parsed, maker)
        return f"{lead}{prefix}'{_sql_escape(whole, backslash)}'{trail}"
    if pre and RE_INTRODUCER.fullmatch(pre.strip()):
        # N・_utf8mb4 などの接頭辞は書き方の一部。検査の読み方では値の頭に付いているので、位置をその分ずらして、中身だけを置き換える
        value = ub.rstrip()
        tw = ub[len(value) :]
        shift = len(pre)
        shifted = [(max(0, s0 - shift), e0 - shift, t) for s0, e0, t in spans if e0 > shift]
        if not shifted:
            return raw
        new = replace_spans(value, shifted, maker)
        if new == value:
            return raw
        return f"{lead}{prefix}'{_sql_escape(new + tw, backslash)}'{trail}"
    new = replace_spans(parsed, spans, maker)
    if new == parsed:
        return raw
    lw = full[: len(full) - len(full.lstrip())]
    tw = full[len(full.rstrip()) :]
    new_full = lw + new + tw
    new_body = new_full[len(pre) :] if new_full.startswith(pre) else new
    return f"{lead}{prefix}'{_sql_escape(new_body, backslash)}'{trail}"


def dummy_copy_cell(raw: str, spans: list, maker: DummyMaker) -> str:
    """COPY のデータ行の欄1つ（\\N・\\t・\\n・\\\\ のエスケープつき）の、検出した部分をダミーにした書き方を返す。"""
    value = _unescape_copy(raw)
    if value is None:
        return raw
    unusual = re.search(r"\\[^\\tnr]", raw) is not None  # 検査が外さないエスケープ（\b・\0 など）がある
    if unusual:
        if replace_spans(value, spans, DummyMaker("fixed")) == value:
            return raw
        new = _whole_cell(spans, value, maker)
    else:
        new = replace_spans(value, spans, maker)
        if new == value:
            return raw
    return new.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n").replace("\r", "\\r")


def drop_items(text: str, drop_idx: set[int]) -> str:
    """「a, b, c」のようなコンマ区切りの並び（列名の並び）から、番号の項目を取り除く。先頭を消したときは、先頭の空白を保つ。"""
    items = text.split(",")
    kept = [x for i, x in enumerate(items) if i not in drop_idx]
    if not kept:
        raise RemedyError(
            "表のすべての列は削除できません（列が1つも残りません）。表ごと消すなら「表を削除」を選んでください"
        )
    if 0 in drop_idx:
        head = items[0][: len(items[0]) - len(items[0].lstrip())]
        kept[0] = head + kept[0].lstrip()
    return ",".join(kept)


# ---------------------------------------------------------------- 表の列の下調べ（列を削除するとき）


def collect_columns(path: str) -> tuple[dict[str, list[str]], set[str]]:
    """表ごとの列名の並び（COPY・INSERT の列名を優先し、無ければ CREATE TABLE）と、列の並びが文によって違う表の集まり。"""
    lines, _enc, _bom = open_dump(path)
    it = _Pushback((i, b) for i, (b, _t) in enumerate(lines, start=1))
    explicit: dict[str, list[tuple]] = {}
    created: dict[str, list[str]] = {}
    for _no, line in it:
        m = RE_COPY.match(line)
        if m:
            explicit.setdefault(norm_ident(_clean_ident(m.group(1))), []).append(
                tuple(norm_col(c) for c in m.group(2).split(","))
            )
            for _n2, ln in it:
                if ln == "\\.":
                    break
            continue
        mi = RE_INSERT.search(line)
        if mi:
            size, last = len(line), line
            while not last.rstrip().endswith(";") and size < SQL_STMT_LIMIT:
                nxt = next(it, None)
                if nxt is None:
                    break
                last = nxt[1]
                size += len(last) + 1
            if mi.group(2):
                explicit.setdefault(norm_ident(_clean_ident(mi.group(1))), []).append(
                    tuple(norm_col(c) for c in mi.group(2).split(","))
                )
            continue
        if RE_CREATE_START.match(line):
            parts = [line]
            pending = None
            while ";" not in parts[-1] and len(parts) < CREATE_LINES_LIMIT:
                nxt = next(it, None)
                if nxt is None:
                    break
                if RE_COPY.match(nxt[1]) or RE_INSERT.search(nxt[1]):
                    pending = nxt
                    break
                parts.append(nxt[1])
            for name, cols in parse_create_tables("\n".join(parts)).items():
                created.setdefault(norm_ident(name), list(cols))
            if pending is not None:
                it.push(pending)
    canonical: dict[str, list[str]] = {}
    conflicts: set[str] = set()
    for table, tuples in explicit.items():
        canonical[table] = list(tuples[0])
        if len(set(tuples)) > 1:
            conflicts.add(table)
    for table, cols in created.items():
        canonical.setdefault(table, [norm_col(c) for c in cols])
    return canonical, conflicts


# ---------------------------------------------------------------- 書き換え本体


class StatementEditor:
    """複数行の文を、元の文字列の一部（元の改行のまま）と新しい文字列を並べて組み立てる。"""

    def __init__(self, parts: list[str], terms: list[str]):
        self.stmt = "\n".join(parts)
        self.terms = terms
        self.starts = [0]
        for p in parts[:-1]:
            self.starts.append(self.starts[-1] + len(p) + 1)
        self.default_term = next((t for t in terms if t), "\n")
        self.out: list[str] = []

    def copy(self, a: int, b: int) -> None:
        """元の文の [a, b) を、元の改行（行ごとの改行）のまま写す。"""
        idx = a
        while True:
            p = self.stmt.find("\n", idx, b)
            if p < 0:
                self.out.append(self.stmt[idx:b])
                return
            self.out.append(self.stmt[idx:p])
            self.out.append(self.terms[bisect_right(self.starts, p) - 1])
            idx = p + 1

    def text(self, t: str) -> None:
        self.out.append(t.replace("\n", self.default_term))

    def result(self) -> str:
        return "".join(self.out) + self.terms[-1]


class DumpRewriter:
    def __init__(self, method: str, sel: Selection, maker: DummyMaker | None, canonical, conflicts):
        self.method = method
        self.maker = maker
        self.targets = Targets(sel)
        self.canonical = canonical
        self.conflicts = conflicts
        self.stats = {"rows": 0, "cols": 0, "tables": 0, "cells": 0, "detections": 0, "statements": 0}
        self.dropped_columns: set[tuple[str, str]] = set()
        self.write = None  # run() が入れる

    # ------------------------------------------------------------ 全体の流れ（検査 scan_sql_lines と同じ分け方）

    def run(self, lines, write) -> None:
        self.write = write
        it = _Pushback((i, b, t) for i, (b, t) in enumerate(lines, start=1))
        has_targets = bool(self.targets.items)
        for ln_no, body, term in it:
            m = RE_COPY.match(body)
            if m:
                self._copy(ln_no, body, term, m, it)
                continue
            if RE_INSERT.search(body):
                self._insert(ln_no, body, term, it)
                continue
            if RE_CREATE_START.match(body):
                self._create(body, term, it)
                continue
            if has_targets and self.method in ("delete_table", "delete_columns") and RE_STMT_START.match(body):
                self._other(body, term, it)
                continue
            write(body + term)

    def finish(self) -> dict:
        for t in self.targets.items.values():
            if self.method == "delete_rows" and t.rows - t.seen_rows:
                raise RemedyError(
                    f"表「{t.name}」で、検査のときの位置の行が見つかりません（{len(t.rows - t.seen_rows)} 行）。"
                    "ファイルの読み方が検査と食い違ったため、書き換えません（元のファイルは変えていません）"
                )
            if self.method == "dummy" and set(t.by_row) - t.seen_rows:
                raise RemedyError(
                    f"表「{t.name}」で、検査のときの位置の行が見つかりません（{len(set(t.by_row) - t.seen_rows)} 行）。"
                    "ファイルの読み方が検査と食い違ったため、書き換えません（元のファイルは変えていません）"
                )
            if self.method in ("delete_columns", "delete_table") and not t.touched:
                raise RemedyError(
                    f"表「{t.name}」の文が見つかりませんでした。書き換えません（元のファイルは変えていません）"
                )
        if self.method == "dummy" and self.stats["cells"] == 0:
            raise RemedyError("書き換える値が見つかりませんでした。元のファイルは変えていません")
        self.stats["cols"] = len(self.dropped_columns)
        if self.method == "delete_table":
            self.stats["tables"] = sum(1 for t in self.targets.items.values() if t.touched)
        return self.stats

    # ------------------------------------------------------------ 列の番号

    def drop_names(self, tgt: Target) -> set[str]:
        """削除する列の名前（検査の列番号を、その表の列名の並びで名前にする）。"""
        key = norm_ident(tgt.name)
        if key in self.conflicts:
            raise RemedyError(
                f"表「{tgt.name}」は、文によって列の並びが違うため、列の削除はできません（行の削除・ダミー化はできます）"
            )
        canon = self.canonical.get(key)
        if canon is None:
            raise RemedyError(f"表「{tgt.name}」の列の名前を読み取れないため、列の削除はできません")
        if any(i >= len(canon) for i in tgt.cols):
            # 列の名前の並びが、検査で見つけた列の位置より短い（CREATE TABLE を読み切れていない）。名前で落とせない列が
            # あると、CREATE を直さずに INSERT などの値だけ減らす（読み込めないダンプになる）ので、断る
            raise RemedyError(f"表「{tgt.name}」の列の名前を全部は読み取れないため、列の削除はできません")
        names = {canon[i] for i in tgt.cols}
        for n in names:
            self.dropped_columns.add((key, n))
        return names

    # ------------------------------------------------------------ COPY ブロック

    def _copy(self, ln_no: int, body: str, term: str, m, it) -> None:
        write = self.write
        table = _clean_ident(m.group(1))
        columns = [norm_col(c) for c in m.group(2).split(",")]
        tgt = self.targets.find(table)
        drop_all = tgt is not None and self.method == "delete_table"
        drop_idx: set[int] = set()
        if tgt is not None and self.method == "delete_columns":
            names = self.drop_names(tgt)
            drop_idx = {i for i, c in enumerate(columns) if c in names}
            if len(drop_idx) >= len(columns):
                raise RemedyError(
                    f"表「{tgt.name}」のすべての列は削除できません。表ごと消すなら「表を削除」を選んでください"
                )
        if tgt is not None:
            tgt.touched = tgt.touched or drop_all or bool(drop_idx) or self.method in ("delete_rows", "dummy")
        if drop_all:
            pass  # COPY の見出しと行をすべて書かない
        elif drop_idx:
            write(body[: m.start(2)] + drop_items(m.group(2), drop_idx) + body[m.end(2) :] + term)
        else:
            write(body + term)
        for rn, rbody, rterm in it:
            if rbody == "\\.":
                if not drop_all:
                    write(rbody + rterm)
                return
            if drop_all:
                continue
            key = rn << ROW_KEY_SHIFT
            if tgt is not None and self.method == "delete_rows" and key in tgt.rows:
                tgt.seen_rows.add(key)
                self.stats["rows"] += 1
                continue
            if drop_idx:
                cells = rbody.split("\t")
                if len(cells) != len(columns):
                    raise RemedyError(
                        f"{rn} 行目の欄の数が COPY の列の数と合いません。書き換えません（元のファイルは変えていません）"
                    )
                write("\t".join(c for i, c in enumerate(cells) if i not in drop_idx) + rterm)
                continue
            if tgt is not None and self.method == "dummy" and key in tgt.by_row:
                tgt.seen_rows.add(key)
                cells = rbody.split("\t")
                changed = False
                for c, spans in tgt.by_row[key].items():
                    if c >= len(cells):
                        continue
                    new = dummy_copy_cell(cells[c], spans, self.maker)
                    if new != cells[c]:
                        cells[c] = new
                        changed = True
                        self.stats["cells"] += 1
                        self.stats["detections"] += len(spans)
                write(("\t".join(cells) if changed else rbody) + rterm)
                continue
            write(rbody + rterm)

    # ------------------------------------------------------------ INSERT 文

    def _insert(self, ln_no: int, body: str, term: str, it) -> None:
        write = self.write
        parts, terms = [body], [term]
        size = len(body)
        while not parts[-1].rstrip().endswith(";") and size < SQL_STMT_LIMIT:
            nxt = next(it, None)
            if nxt is None:
                break
            parts.append(nxt[1])
            terms.append(nxt[2])
            size += len(nxt[1]) + 1
        stmt = "\n".join(parts) if len(parts) > 1 else body
        mi = RE_INSERT.search(stmt)
        table = _clean_ident(mi.group(1))
        tgt = self.targets.find(table)

        def passthrough() -> None:
            for p, t in zip(parts, terms):
                write(p + t)

        if tgt is None:
            passthrough()
            return
        if self.method == "delete_table":
            self._require_clean_prefix(stmt, mi)
            tgt.touched = True
            self.stats["statements"] += 1
            return
        explicit = [norm_col(c) for c in mi.group(2).split(",")] if mi.group(2) else []
        tuples, _end = parse_values_spans(stmt, mi.end())
        drop_idx: set[int] = set()
        if self.method == "delete_columns":
            names = self.drop_names(tgt) if explicit else None
            drop_idx = {i for i, c in enumerate(explicit) if c in names} if explicit else set(tgt.cols)
            if explicit and len(drop_idx) >= len(explicit):
                raise RemedyError(
                    f"表「{tgt.name}」のすべての列は削除できません。表ごと消すなら「表を削除」を選んでください"
                )
            if not explicit:
                for i in tgt.cols:
                    canon = self.canonical.get(norm_ident(tgt.name))
                    if canon and i < len(canon):
                        self.dropped_columns.add((norm_ident(tgt.name), canon[i]))
        # 組ごとの処理を決める
        keep: list[int] = []
        edits: dict[int, dict[int, str]] = {}
        for j, (_s, _e, _closed, cells) in enumerate(tuples):
            key = (ln_no << ROW_KEY_SHIFT) | (j + 1)
            if self.method == "delete_rows":
                if key in tgt.rows:
                    tgt.seen_rows.add(key)
                    self.stats["rows"] += 1
                    continue
            elif self.method == "dummy" and key in tgt.by_row:
                tgt.seen_rows.add(key)
                for c, spans in tgt.by_row[key].items():
                    if c >= len(cells) or cells[c][2] is None:
                        continue
                    raw = stmt[cells[c][0] : cells[c][1]]
                    new = dummy_insert_cell(raw, cells[c][2], spans, self.maker)
                    if new != raw:
                        edits.setdefault(j, {})[c] = new
                        self.stats["cells"] += 1
                        self.stats["detections"] += len(spans)
            keep.append(j)
        changed = bool(edits) or len(keep) != len(tuples) or bool(drop_idx)
        if not changed:
            passthrough()
            return
        if not tuples:
            passthrough()
            return
        self._require_clean_tail(stmt, tuples)
        if drop_idx and explicit and any(len(t[3]) != len(explicit) for t in tuples):
            raise RemedyError(
                f"表「{tgt.name}」の INSERT の値の数が列名の数と合わない組があります。書き換えません（元のファイルは変えていません）"
            )
        tgt.touched = True
        if not keep:
            self._require_clean_prefix(stmt, mi)
            self.stats["statements"] += 1
            return
        ed = StatementEditor(parts, terms)
        prefix_end = tuples[0][0]
        if drop_idx and explicit:
            ed.copy(0, mi.start(2))
            ed.text(drop_items(mi.group(2), drop_idx))
            ed.copy(mi.end(2), prefix_end)
        else:
            ed.copy(0, prefix_end)
        prev = None
        for j in keep:
            if prev is not None:
                ed.copy(tuples[prev][1], tuples[prev + 1][0])
            ed.text(self._tuple_text(stmt, tuples[j], drop_idx, edits.get(j, {})))
            prev = j
        ed.copy(tuples[-1][1], len(stmt))
        write(ed.result())

    @staticmethod
    def _tuple_text(stmt: str, tup, drop_idx: set[int], edits: dict[int, str]) -> str:
        _s, _e, closed, cells = tup
        if not closed:
            raise RemedyError("閉じていない INSERT の組があるため、書き換えません（元のファイルは変えていません）")
        raws = [stmt[cs:ce] for cs, ce, _v, _q in cells]
        for c, new in edits.items():
            raws[c] = new
        if drop_idx:
            kept = [r for i, r in enumerate(raws) if i not in drop_idx]
            if not kept:
                raise RemedyError("表のすべての列は削除できません（列が1つも残りません）")
            if 0 in drop_idx and raws:
                head = raws[0][: len(raws[0]) - len(raws[0].lstrip())]
                kept[0] = head + kept[0].lstrip()
            raws = kept
        return "(" + ",".join(raws) + ")"

    @staticmethod
    def _require_clean_prefix(stmt: str, mi) -> None:
        if stmt[: mi.start()].strip():
            raise RemedyError(
                "INSERT 文の前に別の文があるため、その文ごとは消せません。書き換えません（元のファイルは変えていません）"
            )

    @staticmethod
    def _require_clean_tail(stmt: str, tuples) -> None:
        tail = stmt[tuples[-1][1] :].strip(" \t\r\n;")
        if tail and not re.match(r"(?:ON\s+(?:DUPLICATE|CONFLICT)|RETURNING)\b", tail, re.I):
            raise RemedyError(
                "INSERT 文の値を最後まで読み解けない（関数呼び出しの括弧など）ため、書き換えません（元のファイルは変えていません）"
            )

    # ------------------------------------------------------------ CREATE TABLE

    def _create(self, body: str, term: str, it) -> None:
        write = self.write
        parts, terms = [body], [term]
        pending = None
        while ";" not in parts[-1] and len(parts) < CREATE_LINES_LIMIT:
            nxt = next(it, None)
            if nxt is None:
                break
            if RE_COPY.match(nxt[1]) or RE_INSERT.search(nxt[1]):
                pending = nxt
                break
            parts.append(nxt[1])
            terms.append(nxt[2])
        if pending is not None:
            it.push(pending)
        text = "\n".join(parts)
        m = RE_CREATE.search(text)
        tgt = self.targets.find(_clean_ident(m.group(1))) if m else None
        if m is None and self.method == "delete_columns":
            mn = RE_CREATE_NAME.search(text)
            if mn is not None and self.targets.find(_clean_ident(mn.group(1))) is not None:
                # CREATE TABLE の形を読み解けない。そのまま写して INSERT だけ列を減らすと、読み込めないダンプになる
                raise RemedyError(
                    f"表「{_clean_ident(mn.group(1))}」の CREATE TABLE を読み解けないため、列を削除できません"
                    "（元のファイルは変えていません）"
                )
        if tgt is None or self.method not in ("delete_table", "delete_columns"):
            for p, t in zip(parts, terms):
                write(p + t)
            return
        tgt.touched = True
        if self.method == "delete_table":
            return
        names = self.drop_names(tgt)
        edited, dropped = self._edit_create(parts, text, m, names)
        missing = names - dropped
        if missing:
            # CREATE から落とせない列があるのに INSERT などの列だけ減らすと、CREATE と中身がずれて読み込めなくなる
            raise RemedyError(
                f"表「{tgt.name}」の CREATE TABLE から、削除する列「{'、'.join(sorted(missing))}」を見つけられないため、"
                "列を削除できません（元のファイルは変えていません）"
            )
        if isinstance(edited, str):
            # 1 行に複数の列がある形（sqlite3 の .dump など）は、文を組み直した。元の行末記号で書く
            lines = edited.split("\n")
            inner = next((t for t in terms if t), "\n")
            for i, line in enumerate(lines):
                write(line + (terms[-1] if i == len(lines) - 1 else inner))
            return
        for p, t in zip(edited, terms):
            if p is not None:
                write(p + t)

    @staticmethod
    def _edit_create_inline(text: str, m, names: set[str]) -> tuple[str, set[str]]:
        """1 行に複数の列がある CREATE TABLE（sqlite3 の .dump の形）の本体を、コンマで項目に分けて、削除する列（と、その列を
        使う制約）の項目を取り除いた文を返す（文字列）。落とした列の名前の集まりも返す。"""
        body_start, body_end = m.span(2)
        pieces = split_top_level(text[body_start:body_end])
        kept: list[str] = []
        dropped: set[str] = set()
        for piece in pieces:
            st = piece.strip()
            if not st:
                kept.append(piece)
                continue
            if st.upper().startswith(CONSTRAINT_WORDS):
                if any(re.search(r"(?<![\w$])" + re.escape(n) + r"(?![\w$])", st) for n in names):
                    continue
                kept.append(piece)
                continue
            mm = RE_COLUMN_LINE.match(st)
            col = norm_col(mm.group(2)) if mm else None
            if col is not None and col in names:
                dropped.add(col)
                continue
            kept.append(piece)
        if not [k for k in kept if k.strip()]:
            raise RemedyError(
                "表のすべての列は削除できません（列が1つも残りません）。表ごと消すなら「表を削除」を選んでください"
            )
        # 先頭の項目の前の空白と、最後の項目の後ろの空白（閉じ括弧の前の改行など）は、元のまま保つ
        head = pieces[0][: len(pieces[0]) - len(pieces[0].lstrip())]
        tail = pieces[-1][len(pieces[-1].rstrip()) :]
        kept[0] = head + kept[0].lstrip()
        kept[-1] = kept[-1].rstrip() + tail
        return text[:body_start] + ",".join(kept) + text[body_end:], dropped

    @staticmethod
    def _edit_create(parts: list[str], text: str, m, names: set[str]) -> tuple[list[str | None] | str, set[str]]:
        """CREATE TABLE の列の定義の行から、削除する列の行（と、その列を使う制約・索引の行）を外す。外した行は None。
        1 行に複数の列・制約がある形のときは、文を組み直した文字列を返す。落とした列の名前の集まりも返す。"""
        body_start, body_end = m.span(2)
        starts = [0]
        for p in parts[:-1]:
            starts.append(starts[-1] + len(p) + 1)
        elements = []  # (行番号, 種類, 列名)
        for li, line in enumerate(parts):
            ls, le = starts[li], starts[li] + len(line)
            a, b = max(ls, body_start), min(le, body_end)
            if a >= b:
                continue
            frag = text[a:b]
            st = frag.strip().rstrip(",")
            if not st:
                continue
            if len([x for x in split_top_level(frag) if x.strip()]) > 1:
                # 1 行に複数の列・制約がある（sqlite3 の .dump は表を 1 行で出す）。行ごとには扱えないので、項目ごとに組み直す
                return DumpRewriter._edit_create_inline(text, m, names)
            alone = not text[ls:a].strip() and not text[b:le].strip()
            if st.upper().startswith(CONSTRAINT_WORDS):
                elements.append((li, "constraint", st, alone))
                continue
            mm = RE_COLUMN_LINE.match(st)
            elements.append((li, "column", norm_col(mm.group(2)) if mm else None, alone))
        out: list[str | None] = list(parts)
        dropped_lines: list[int] = []
        dropped_cols: set[str] = set()
        for li, kind, info, alone in elements:
            if kind == "column":
                hit = info in names
            else:
                hit = any(re.search(r"(?<![\w$])" + re.escape(n) + r"(?![\w$])", info) for n in names)
            if not hit:
                continue
            if not alone:
                # 1 行に複数の列がある形（CREATE と同じ行・閉じ括弧と同じ行を含む）は、行ごとでなく項目ごとに組み直す
                return DumpRewriter._edit_create_inline(text, m, names)
            dropped_lines.append(li)
            out[li] = None
            if kind == "column":
                dropped_cols.add(info)
        if not dropped_lines:
            return out, dropped_cols
        remaining = [e[0] for e in elements if out[e[0]] is not None]
        if not remaining:
            raise RemedyError(
                "表のすべての列は削除できません（列が1つも残りません）。表ごと消すなら「表を削除」を選んでください"
            )
        if elements[-1][0] in dropped_lines:
            # 最後の定義を消したので、残る最後の定義の行末のコンマを外す
            last = remaining[-1]
            line = out[last]
            stripped = line.rstrip()
            if stripped.endswith(","):
                out[last] = stripped[:-1] + line[len(stripped) :]
        return out, dropped_cols

    # ------------------------------------------------------------ そのほかの文（索引・制約・権限など）

    def _other(self, body: str, term: str, it) -> None:
        write = self.write
        parts, terms = [body], [term]
        pending = None
        while ";" not in parts[-1] and len(parts) < CREATE_LINES_LIMIT:
            nxt = next(it, None)
            if nxt is None:
                break
            if RE_COPY.match(nxt[1]) or RE_INSERT.search(nxt[1]) or RE_CREATE_START.match(nxt[1]):
                pending = nxt
                break
            parts.append(nxt[1])
            terms.append(nxt[2])
        if pending is not None:
            it.push(pending)
        text = "\n".join(parts)
        if self._drops(text):
            self.stats["statements"] += 1
            return
        for p, t in zip(parts, terms):
            write(p + t)

    def _drops(self, text: str) -> bool:
        """この文（索引・制約・権限など）を、書き換えで取り除くか。"""
        for kind, rx in RE_STMT_KINDS:
            m = rx.match(text)
            if m is None:
                continue
            name = m.group("t")
            if kind in ("owned", "comment_column"):
                name = name.rsplit(".", 1)[0] if "." in name else ""
                if not name:
                    return False
            tgt = self.targets.find(name)
            if tgt is None:
                return False
            if self.method == "delete_table":
                tgt.touched = True
                return True
            # 列の削除: その列を使う索引・制約・列のコメントだけ取り除く
            drop = {c for (t, c) in self.dropped_columns if t == norm_ident(tgt.name)} or self.drop_names(tgt)
            rest = text[m.end("t") :]
            if kind == "comment_column":
                col = norm_col(m.group("t").rsplit(".", 1)[-1])
                return col in drop
            if kind == "index" or (kind == "alter" and RE_ALTER_CONSTRAINT.search(rest)):
                return any(re.search(r"(?<![\w$])" + re.escape(n) + r"(?![\w$])", rest) for n in drop)
            return False
        return False


def rewrite_sql_dump_file(src: str, dst: str, method: str, sel: Selection, maker: DummyMaker | None) -> dict:
    """SQL のダンプ src を書き換えた結果を dst へ1行ずつ書く（巨大でもメモリに載せない）。元の src には書かない。"""
    from .engine import long_path

    if method not in ("delete_rows", "delete_columns", "dummy", "delete_table"):
        raise RemedyError("この方法は SQL のダンプに使えません")
    canonical, conflicts = collect_columns(src) if method == "delete_columns" else ({}, set())
    lines, enc, bom = open_dump(src)
    rw = DumpRewriter(method, sel, maker, canonical, conflicts)
    try:
        with open(long_path(dst), "wb", buffering=1 << 20) as out:
            if bom:
                out.write(bom)

            def write(text: str) -> None:
                try:
                    out.write(text.encode(enc))
                except UnicodeEncodeError:
                    raise RemedyError(
                        "置き換えた文字を元の文字コードに直せませんでした（元のファイルは変えていません）"
                    ) from None

            rw.run(lines, write)
            out.flush()
            os.fsync(out.fileno())
    except BaseException:
        try:
            os.remove(long_path(dst))
        except OSError:
            pass
        raise
    return rw.finish()

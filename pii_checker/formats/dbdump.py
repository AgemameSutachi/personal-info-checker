"""データベースのダンプ・データファイルの処理。

- SQL 文（pg_dump のプレーン形式・mysqldump・各種 INSERT 文）: COPY と INSERT を列名つきの表として読む
- PostgreSQL の custom 形式（PGDMP）: pg_restore があれば SQL へ戻して読む。無ければ形式を解いて
  データ部（zlib 圧縮）を自前で展開する
- Oracle の exp / expdp（Data Pump）ダンプ: 内部形式は公開されていないため、文字列型の値だけを走査する
  （簡易検査）。完全に確かめるには Oracle へ取り込んで表の中身を確かめる（このツールは DB へ接続しない）
- SQL Server・MySQL・Oracle・PostgreSQL のデータファイル本体: 同じく文字列のみ（簡易検査）
"""

from __future__ import annotations

import glob
import os
import re
import shutil
import subprocess
import zlib

from ..engine import READ_ALL_LIMIT, Blob, Collector, ItemResult, PartialScan, ScanContext, Uncheckable
from ..textdecode import decode_text, entropy, iter_strings_chunked

CREATE_NO_WINDOW = 0x08000000


# ------------------------------------------------------------------ SQL 文


RE_COPY = re.compile(r"^COPY\s+([^\s(]+)\s*\(([^)]*)\)\s+FROM\s+stdin;?\s*$", re.I)
RE_INSERT = re.compile(r"INSERT\s+(?:IGNORE\s+)?INTO\s+([`\"\[\]\w.]+)\s*(?:\(([^)]*)\))?\s*VALUES\s*", re.I)


RE_CREATE = re.compile(
    r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([`\"\[\]\w.]+)\s*\((.*?)\)\s*(?:ENGINE|WITH|TABLESPACE|PARTITION|;)",
    re.I | re.S,
)
CONSTRAINT_WORDS = (
    "PRIMARY",
    "KEY",
    "UNIQUE",
    "CONSTRAINT",
    "INDEX",
    "FOREIGN",
    "CHECK",
    "FULLTEXT",
    "SPATIAL",
    "EXCLUDE",
)


def parse_create_tables(text: str) -> dict[str, list[str]]:
    """CREATE TABLE 文から表ごとの列名を取り出す（列名の無い INSERT の見出しに使う）。"""
    tables: dict[str, list[str]] = {}
    for m in RE_CREATE.finditer(text):
        name = _clean_ident(m.group(1))
        cols = []
        for line in m.group(2).split("\n"):
            line = line.strip().rstrip(",")
            if not line or line.upper().startswith(CONSTRAINT_WORDS):
                continue
            mm = re.match(r'([`"\[]?)([^`"\]\s]+)\1?\]?\s+\w', line)
            if mm:
                cols.append(mm.group(2))
        if cols:
            tables[name] = cols
            tables[name.split(".")[-1]] = cols
    return tables


def pg_toc_mapping(toc: bytes) -> dict[str, tuple[str, list[str]]]:
    """pg_dump の directory/tar 形式の toc.dat から「データファイル名 → (表, 列名)」を作る。"""
    out: dict[str, tuple[str, list[str]]] = {}
    for m in re.finditer(rb"COPY ([^\s(]+) \(([^)]*)\) FROM stdin;", toc):
        table = m.group(1).decode("utf-8", "replace")
        cols = [_clean_ident(c) for c in m.group(2).decode("utf-8", "replace").split(",")]
        fm = re.search(rb"(\d+)\.dat", toc[m.end() : m.end() + 4096])
        if fm:
            out[fm.group(0).decode("ascii")] = (_clean_ident(table), cols)
    return out


def scan_copy_rows(text: str, table: str, columns: list[str], col: Collector, item: ItemResult) -> None:
    """COPY 形式（タブ区切り・\\N は NULL）のデータを列名つきで読む。"""
    rows = ([_unescape_copy(v) for v in ln.split("\t")] for ln in text.splitlines() if ln != "\\.")
    col.add_records(
        columns,
        rows,
        lambda r, c: f"表「{table}」{r}行目 列「{columns[c] if c < len(columns) else c + 1}」",
        method="COPY データ",
    )
    item.method += f"・PostgreSQL ダンプのデータ（表「{table}」の列名を toc.dat から当てた）"


def looks_like_sql(text: str) -> bool:
    head = text[:200000]
    return bool(re.search(r"^COPY\s+\S+.*FROM\s+stdin;", head, re.M | re.I) or re.search(r"INSERT\s+INTO", head, re.I))


def _clean_ident(s: str) -> str:
    return s.strip().strip('`"[]').strip()


def _unescape_copy(v: str) -> str | None:
    if v == r"\N":
        return None
    return (
        v.replace("\\\\", "\x00").replace("\\t", "\t").replace("\\n", "\n").replace("\\r", "\r").replace("\x00", "\\")
    )


def _parse_values(s: str, pos: int):
    """VALUES (...),(...); の並びを読む。戻り値は（行のリスト, 読み終えた位置）。"""
    rows = []
    n = len(s)
    while pos < n:
        while pos < n and s[pos] in " \t\r\n,":
            pos += 1
        if pos >= n or s[pos] != "(":
            break
        pos += 1
        row: list[str | None] = []
        cur: list[str] = []
        quoted = False
        while pos < n:
            ch = s[pos]
            if ch == "'":
                pos += 1
                buf = []
                while pos < n:
                    c = s[pos]
                    if c == "\\" and pos + 1 < n:
                        buf.append({"n": "\n", "t": "\t", "r": "\r", "0": ""}.get(s[pos + 1], s[pos + 1]))
                        pos += 2
                        continue
                    if c == "'":
                        if pos + 1 < n and s[pos + 1] == "'":
                            buf.append("'")
                            pos += 2
                            continue
                        pos += 1
                        break
                    buf.append(c)
                    pos += 1
                cur.append("".join(buf))
                quoted = True
                continue
            if ch == ",":
                token = "".join(cur).strip()
                row.append(None if (not quoted and token.upper() == "NULL") else token)
                cur, quoted = [], False
                pos += 1
                continue
            if ch == ")":
                token = "".join(cur).strip()
                row.append(None if (not quoted and token.upper() == "NULL") else token)
                pos += 1
                break
            cur.append(ch)
            pos += 1
        rows.append(row)
    return rows, pos


def scan_sql_text(text: str, col: Collector, item: ItemResult) -> None:
    """SQL 文を読む。COPY ブロックと INSERT 文は列名を見出しにした表として検査する。"""
    lines = text.splitlines()
    create_cols = parse_create_tables(text)
    i = 0
    n_copy = n_insert = 0
    other: list[tuple[int, str]] = []
    while i < len(lines):
        line = lines[i]
        m = RE_COPY.match(line)
        if m:
            table = _clean_ident(m.group(1))
            columns = [_clean_ident(c) for c in m.group(2).split(",")]
            start = i + 1
            j = start
            while j < len(lines) and lines[j] != "\\.":
                j += 1
            block = lines[start:j]

            def rows(block=block):
                for ln in block:
                    yield [_unescape_copy(v) for v in ln.split("\t")]

            col.add_records(
                columns,
                rows(),
                lambda r, c, table=table, columns=columns, start=start: f"表「{table}」データ{r}行目（{start + r}行目） 列「{columns[c] if c < len(columns) else c + 1}」",
                method="COPY データ",
            )
            n_copy += 1
            i = j + 1
            continue
        mi = RE_INSERT.search(line)
        if mi:
            # 複数行にまたがる INSERT は ; まで連結する
            stmt = line
            j = i
            while not stmt.rstrip().endswith(";") and j + 1 < len(lines) and len(stmt) < 50_000_000:
                j += 1
                stmt += "\n" + lines[j]
            mi = RE_INSERT.search(stmt)
            table = _clean_ident(mi.group(1))
            columns = [_clean_ident(c) for c in mi.group(2).split(",")] if mi.group(2) else []
            if not columns:
                columns = create_cols.get(table) or create_cols.get(table.split(".")[-1]) or []
            values, _ = _parse_values(stmt, mi.end())
            if columns:
                col.add_records(
                    columns,
                    values,
                    lambda r, c, table=table, columns=columns, i=i: f"表「{table}」INSERT（{i + 1}行目〜）{r}件目 列「{columns[c] if c < len(columns) else c + 1}」",
                    method="INSERT 文",
                )
            else:
                for r, row in enumerate(values, start=1):
                    for c, v in enumerate(row):
                        if v:
                            col.add_text(
                                v, f"表「{table}」INSERT（{i + 1}行目〜）{r}件目 {c + 1}番目の値", method="INSERT 文"
                            )
            n_insert += 1
            i = j + 1
            continue
        other.append((i + 1, line))
        i += 1
    # COPY・INSERT 以外の行（DDL・コメント等）も本文として検査する
    block: list[str] = []
    base = None
    for ln_no, ln in other:
        if base is None:
            base = ln_no
        block.append(ln)
        if len(block) >= 200:
            col.add_lines("\n".join(block), location_prefix=f"{base}行目付近 ", method="SQL 本文")
            block, base = [], None
    if block:
        col.add_lines("\n".join(block), location_prefix=f"{base}行目付近 ", method="SQL 本文")
    item.method += f"・SQL として読み取り（COPY {n_copy} 件・INSERT {n_insert} 文を列名つきで検査）"


# ------------------------------------------------------------------ PostgreSQL custom 形式


def find_pg_restore() -> str | None:
    w = shutil.which("pg_restore")
    if w:
        return w
    cands = sorted(glob.glob(r"C:\Program Files\PostgreSQL\*\bin\pg_restore.exe"), reverse=True)
    return cands[0] if cands else None


def handle_pg_custom(ctx: ScanContext, blob: Blob, item: ItemResult, col: Collector, depth: int) -> None:
    item.kind = "PostgreSQL ダンプ（custom 形式）"
    exe = find_pg_restore()
    path = ctx.blob_as_path(blob, ".dump")
    if exe:
        out = os.path.join(ctx.new_tmp_subdir(), "restored.sql")
        r = subprocess.run(
            [exe, "-f", out, path],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=24 * 3600,
            creationflags=CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        if r.returncode == 0 and os.path.isfile(out):
            if os.path.getsize(out) > READ_ALL_LIMIT:
                # 戻した SQL が大きいときはメモリへ丸ごと読まず、巨大なテキストとして少しずつ検査する
                item.method = "pg_restore で SQL に戻して読み取り（大きいため少しずつ）"
                ctx.scan_nested(
                    f"{blob.display}!（pg_restore で戻した SQL）", path=out, depth=depth + 1, name_hint="restored.sql"
                )
                return
            with open(out, "rb") as f:
                text, _ = decode_text(f.read())
            item.method = "pg_restore で SQL に戻して読み取り"
            scan_sql_text(text, col, item)
            return
        item.notes.append(
            f"pg_restore で戻せなかったため形式を自前で解いた: {r.stderr.decode('utf-8', 'replace')[-200:]}"
        )
    data = blob.read_all()
    _scan_pg_custom_bytes(data, col, item)


def _pg_int(data: bytes, pos: int, int_size: int) -> tuple[int, int]:
    sign = data[pos]
    v = int.from_bytes(data[pos + 1 : pos + 1 + int_size], "little")
    return (-v if sign else v), pos + 1 + int_size


def _scan_pg_custom_bytes(data: bytes, col: Collector, item: ItemResult) -> None:
    """custom 形式のデータ部（BLK_DATA）を探して展開し、COPY の列名と対応づけて読む。"""
    if not data.startswith(b"PGDMP"):
        raise Uncheckable("PostgreSQL の custom 形式の見出しが読めない")
    int_size = data[8] if len(data) > 8 else 4
    copies = [
        (
            m.group(1).decode("utf-8", "replace"),
            [_clean_ident(c) for c in m.group(2).decode("utf-8", "replace").split(",")],
        )
        for m in re.finditer(rb"COPY ([^\s(]+) \(([^)]*)\) FROM stdin;", data)
    ]
    # BLK_DATA(1) + dumpId(int) + 最初の塊の長さ(int) の並びを探す
    pat = re.compile(rb"\x01\x00(.{%d})\x00(.{%d})" % (int_size, int_size), re.S)
    blocks: list[str] = []
    failed = 0
    pos = 0
    expanded = 0  # 展開した合計（圧縮爆弾でメモリを食い潰さないよう上限を掛ける）
    cut_short = False
    while True:
        m = pat.search(data, pos)
        if not m:
            break
        p = m.start() + 1
        _, p = _pg_int(data, p, int_size)
        first_len = int.from_bytes(m.group(2), "little")
        if not (0 < first_len < 1 << 26) or p + 1 + int_size + first_len > len(data):
            pos = m.start() + 1
            continue
        chunks = []
        q = p
        ok = True
        while q < len(data):
            length, q = _pg_int(data, q, int_size)
            if length == 0:
                break
            if length < 0 or q + length > len(data):
                ok = False
                break
            chunks.append(data[q : q + length])
            q += length
        if not ok or not chunks:
            pos = m.start() + 1
            continue
        raw = b"".join(chunks)
        if raw[:1] == b"\x78":
            try:
                d = zlib.decompressobj()
                text_bytes = d.decompress(raw, max(1, READ_ALL_LIMIT - expanded))
                if d.unconsumed_tail:
                    cut_short = True
            except zlib.error:
                failed += 1
                pos = q
                continue
        elif b"\t" in raw[:4096] or b"\n" in raw[:4096]:
            text_bytes = raw  # 圧縮なし（-Z0）
        else:
            failed += 1  # lz4・zstd など未対応の圧縮
            pos = q
            continue
        blocks.append(text_bytes.decode("utf-8", errors="replace"))
        expanded += len(text_bytes)
        pos = q
        if expanded >= READ_ALL_LIMIT:
            cut_short = True
            break
    n_with_cols = 0
    for idx, text in enumerate(blocks):
        table, columns = copies[idx] if len(copies) == len(blocks) else (f"データ{idx + 1}", [])
        rows = ([_unescape_copy(v) for v in ln.split("\t")] for ln in text.splitlines() if ln != "\\.")
        if columns:
            n_with_cols += 1
            col.add_records(
                columns,
                rows,
                lambda r, c, table=table, columns=columns: f"表「{table}」{r}行目 列「{columns[c] if c < len(columns) else c + 1}」",
                method="COPY データ",
            )
        else:
            col.add_lines(text, location_prefix=f"{table} ", method="COPY データ")
    item.method = f"custom 形式を解いてデータ部 {len(blocks)} 個を展開（列名つき {n_with_cols} 個）"
    if not blocks:
        # データ部を1つも見つけられなかったものを「検査済み・検出なし」にしない（不具合の修正）。文字だけは拾っておく
        from ..textdecode import iter_strings

        for s in iter_strings(data):
            col.add_text(s, "文字列走査", method="custom 形式の文字列走査")
        if copies or failed:
            raise Uncheckable(
                f"PostgreSQL の custom 形式のデータ部を見つけられず、表 {len(copies)} 個の中身を検査していない。"
                "pg_restore を入れて再検査する"
            )
        raise PartialScan(
            "データ部が見つからなかった（表の定義だけのダンプの可能性）。文字として読める部分だけを検査した"
        )
    if cut_short:
        raise PartialScan(
            f"展開した中身が大きすぎる（{READ_ALL_LIMIT // 1024**2}MB を超えた）ため、そこまでを検査した。"
            "pg_restore を入れると全部を少しずつ読める"
        )
    if failed:
        raise PartialScan(
            f"データ部 {failed} 個は未対応の圧縮（lz4/zstd 等）で展開できなかった。pg_restore を入れると全部読める"
        )


# ------------------------------------------------------------------ 内部形式の分からないダンプ・データファイル


def _sweep_with_entropy(blob: Blob, col: Collector) -> tuple[int, int]:
    """文字列を走査しつつ、圧縮・暗号化されていそうな区画の数を数える。"""
    high = total = 0
    with blob.open() as f:

        def reader(n, f=f):
            nonlocal high, total
            chunk = f.read(n)
            if chunk:
                total += 1
                if entropy(chunk[:1_000_000]) > 7.5:
                    high += 1
            return chunk

        for s in iter_strings_chunked(reader):
            col.add_text(s, "生データ", method="生データ走査")
    return high, total


def handle_oracle_dump(ctx: ScanContext, blob: Blob, item: ItemResult, col: Collector, depth: int) -> None:
    high, total = _sweep_with_entropy(blob, col)
    item.method = "Oracle ダンプの文字列走査（UTF-8 / Shift_JIS / UTF-16）"
    if total and high / total > 0.1:
        raise Uncheckable(
            f"Oracle ダンプの {high}/{total} 区画が圧縮または暗号化されている（COMPRESSION/ENCRYPTION 指定の expdp 等）ため、"
            "文字を取り出せない。不要なダンプなら削除・移動し、要るなら Oracle へ取り込んで表の中身を確かめること"
        )
    raise PartialScan(
        "Oracle ダンプ（exp/expdp）は内部形式が非公開のため、文字列型の値だけを検査した（数値型・日付型の列は読めない）。"
        "言い切るには、不要なダンプなら削除・移動し、要るなら Oracle へ取り込んで表の中身を確かめること"
    )


DB_FILE_ADVICE = {
    "sqlserver_bak": "SQL Server のバックアップ（.bak）",
    "db_datafile": "データベースのデータファイル本体",
}


def handle_db_binary(ctx: ScanContext, blob: Blob, item: ItemResult, col: Collector, depth: int) -> None:
    high, total = _sweep_with_entropy(blob, col)
    item.method = "データファイルの文字列走査"
    what = item.kind or "データベースのファイル"
    if total and high / total > 0.3:
        raise Uncheckable(
            f"{what}の多くの区画が圧縮・暗号化されていて文字を取り出せない。"
            "不要なファイルなら削除・移動し、要るなら DB に戻して（復元・起動して）表の中身を確かめること"
        )
    raise PartialScan(
        f"{what}は内部形式を解釈できないため文字列の値だけを検査した（数値型の列・圧縮された値は読めない）。"
        "言い切るには、不要なファイルなら削除・移動し、要るなら DB に戻して（復元・起動して）表の中身を確かめること"
    )

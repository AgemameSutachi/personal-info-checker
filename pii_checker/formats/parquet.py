"""Apache Parquet（列指向の表のファイル）を、列の型を見て表として読む。

parquet の中身はふつう列ごとに圧縮（SNAPPY・ZSTD 等）されているので、生データ走査では中の文字をほとんど読めない
（実物の 1GB の parquet で 1つ 500〜580 秒かかり、それでも見落とした）。pyarrow で行を取り出し、
文字の列・見出しが個人情報の見出し語に当たる列・番号になりうる桁の整数の列だけを表のレコードとして検査する。

pyarrow が入っていない環境（依存を足していない配布物）では、今までどおり形式不明の生データ走査に任せる。
"""

from __future__ import annotations

import json

from .. import detectors
from ..engine import Blob, Collector, ItemResult, PartialScan, ScanContext, Uncheckable
from ..textdecode import iter_strings

MAGIC = b"PAR1"
BATCH_ROWS = 8192  # 1回に取り出す行の数（列ごとの Python のリストに直すので、大きすぎるとメモリを食う）
WIDE_INT = 10**8  # この大きさ以上の整数がある列は、電話番号（先頭の 0 が落ちた 9 桁〜）・マイナンバーになりうるので読む
HASH_WIDTHS = (16, 20, 32, 64)  # UUID・MD5・SHA-1・SHA-256・SHA-512 の長さの固定長バイト列は読まない


def available() -> bool:
    """pyarrow が使えるか。"""
    try:
        import pyarrow.parquet  # noqa: F401
    except Exception:  # 入っていない・壊れている（DLL が読めない等）
        return False
    return True


def looks_like_parquet(blob: Blob, head: bytes) -> bool:
    """頭と尾の両方に PAR1 があり、尾の前の定義の長さがファイルに収まるか（PAR1 で始まり終わるテキストを誤らない）。"""
    if not head.startswith(MAGIC):
        return False
    try:
        size = blob.size
        if size < 12:
            return False
        with blob.open() as f:
            f.seek(-8, 2)
            tail = f.read(8)
    except OSError:
        return False
    footer = int.from_bytes(tail[:4], "little")
    return tail[4:] == MAGIC and 0 < footer <= size - 12


def _base_type(t):
    """拡張型（JSON 等）は中身の型に降ろす。"""
    while hasattr(t, "storage_type"):
        t = t.storage_type
    return t


def _leaf_has_text(t) -> bool:
    """型（入れ子なら中の型）に文字の列が含まれるか。"""
    import pyarrow as pa

    t = _base_type(t)
    if pa.types.is_dictionary(t):
        return _leaf_has_text(t.value_type)
    if pa.types.is_string(t) or pa.types.is_large_string(t) or pa.types.is_binary(t) or pa.types.is_large_binary(t):
        return True
    for name in ("is_string_view", "is_binary_view"):  # pyarrow の版によっては無い
        check = getattr(pa.types, name, None)
        if check and check(t):
            return True
    if pa.types.is_fixed_size_binary(t):
        return t.byte_width not in HASH_WIDTHS  # 固定長の番号（12 桁の文字など）は読む
    if pa.types.is_list(t) or pa.types.is_large_list(t) or pa.types.is_fixed_size_list(t):
        return _leaf_has_text(t.value_type)
    if pa.types.is_map(t):
        return _leaf_has_text(t.key_type) or _leaf_has_text(t.item_type)
    if pa.types.is_struct(t):
        return any(_leaf_has_text(t.field(i).type) for i in range(t.num_fields))
    return False


def _has_header_word(name: str, t) -> bool:
    """列の名前か、入れ子（struct）の中の項目の名前が、個人情報の見出し語に当たるか。"""
    import pyarrow as pa

    if detectors.header_category(name):
        return True
    t = _base_type(t)
    if pa.types.is_list(t) or pa.types.is_large_list(t) or pa.types.is_fixed_size_list(t):
        return _has_header_word("", t.value_type)
    if pa.types.is_struct(t):
        return any(_has_header_word(t.field(i).name, t.field(i).type) for i in range(t.num_fields))
    return False


def _wide_int_columns(pf) -> set[str]:
    """番号になりうる大きさの整数が入っている（または統計が無くて分からない）最上位の整数の列の名前。"""
    import pyarrow as pa

    schema = pf.schema_arrow
    candidates = {f.name for f in schema if pa.types.is_integer(_base_type(f.type))}
    if not candidates:
        return set()
    leaf_of = {}  # 最上位の列の名前 → parquet の葉の列の番号
    pschema = pf.schema
    for j in range(len(pschema)):
        path = pschema.column(j).path
        if path in candidates:
            leaf_of[path] = j
    wide = {name for name in candidates if name not in leaf_of}  # 葉の対応が取れないものは読む（安全側）
    md = pf.metadata
    for name, j in leaf_of.items():
        for g in range(md.num_row_groups):
            stats = md.row_group(g).column(j).statistics
            if (
                stats is not None
                and not stats.has_min_max
                and stats.has_null_count
                and stats.null_count >= stats.num_values
            ):
                continue  # この行のまとまりは空（null だけ）
            if stats is None or not stats.has_min_max:
                wide.add(name)
                break
            try:
                big = max(abs(int(stats.min)), abs(int(stats.max))) >= WIDE_INT
            except (TypeError, ValueError):
                big = True
            if big:
                wide.add(name)
                break
    return wide


class _Cells:
    """取り出した値を、表の検査に渡せる値にする。文字として読めなかったバイト列の数を数える。"""

    def __init__(self):
        self.unreadable = 0

    def __call__(self, v):
        if isinstance(v, bytes):
            return self._bytes(v)
        if isinstance(v, (list, dict, tuple)):
            return json.dumps(v, ensure_ascii=False, default=self._default)
        return v

    def _default(self, v):
        if isinstance(v, bytes):
            return self._bytes(v) or ""
        return str(v)

    def _bytes(self, v: bytes):
        try:
            return v.decode("utf-8")
        except UnicodeDecodeError:
            pass
        # cp932・EUC-JP はでたらめなバイト列もほとんど通してしまうので、厳密に読めるかでは決めない。
        # 文字の拾い出し（UTF-16・cp932・UTF-8 の、人が読める文字が続く所だけ）に任せる
        parts = list(iter_strings(v))
        if parts:
            return " ".join(dict.fromkeys(parts))  # 同じ文字を別の符号で二重に拾った分は1つに
        self.unreadable += 1
        return None


def handle_parquet(ctx: ScanContext, blob: Blob, item: ItemResult, col: Collector, depth: int) -> None:
    import pyarrow as pa
    import pyarrow.parquet as pq

    cell = _Cells()
    with blob.open() as f:
        try:
            pf = pq.ParquetFile(f)
            schema = pf.schema_arrow
        except (pa.ArrowException, OSError, ValueError) as e:
            raise Uncheckable(
                f"parquet の表の定義を読めなかった（壊れている・暗号化されている・未対応の形の可能性）: {e}"
            )
        # 表の定義に付いた説明（pandas の列の情報など）にも文字が入りうる
        meta = pf.metadata.metadata or {}
        meta_cell = _Cells()  # 付記の読めなかった数は、列の値の数に混ぜない
        for k, v in meta.items():
            text = meta_cell(v)
            if text:
                col.add_text(text, f"表の付記「{meta_cell(k) or ''}」", method="parquet の付記")
        fields = [x for x in schema if _leaf_has_text(x.type) or _has_header_word(x.name, x.type)]
        names = [x.name for x in fields]
        read = set(names)
        # 見出しの無い桁の大きい整数の列は読まない（ID・時刻の列が多く、読むとマイナンバーの誤検出が大量に出る。
        # 数で持つと電話番号は先頭の 0 も落ちている）。読まなかったことは列の数で注記する
        wide = [n for n in _wide_int_columns(pf) if n not in read]
        total_rows = pf.metadata.num_rows
        skipped = len(schema) - len(fields) - len(wide)
        item.method = (
            f"parquet の表（{total_rows} 行・読んだ列 {len(fields)} 列（文字の列と見出し語の列）／全 {len(schema)} 列）"
        )
        notes = []
        if wide:
            notes.append(
                f"9 桁以上の整数が入った（または統計が無く桁を確かめられない）整数の列 {len(wide)} 列は、"
                "見出しが個人情報の見出し語に当たらないので読んでいない"
                "（ID・時刻などの列とみなした。番号を数で持つ列なら、見出しを「マイナンバー」などにすると読む）"
            )
        if skipped:
            notes.append(
                f"そのほかの文字以外の列 {skipped} 列（小さな整数・小数・日付・真偽・ハッシュの長さの値など）は、"
                "見出しが個人情報の見出し語に当たらないので読んでいない"
            )
        if not fields:
            item.notes.extend(notes)
            return
        limit = ctx.options.max_rows_per_table or 0
        seen = [0]
        broken = []  # (行グループの番号, その行数, 理由)
        skips = []  # (それまでに渡した行の数, 飛ばした行の数): 明細の行番号を元のファイルの行番号に直す
        truncated = [False]
        md = pf.metadata

        def rows():
            # 行グループごとに読み、壊れた行グループだけを飛ばして先を読む
            for g in range(md.num_row_groups):
                n_group = md.row_group(g).num_rows
                given = 0
                try:
                    for batch in pf.iter_batches(columns=names, batch_size=BATCH_ROWS, row_groups=[g]):
                        cols = [c.to_pylist() for c in batch.columns]
                        for r in zip(*cols):
                            if limit and seen[0] >= limit:
                                truncated[0] = True
                                return
                            seen[0] += 1
                            given += 1
                            yield [cell(v) for v in r]
                except (pa.ArrowException, OSError, ValueError) as e:
                    broken.append((g, n_group - given, str(e)))
                    skips.append((seen[0], n_group - given))

        def file_row(r: int) -> int:
            return r + sum(n for at, n in skips if at < r)

        col.add_records(
            names,
            rows(),
            lambda r, c: f"{file_row(r)}行目 列「{names[c] if c < len(names) else c + 1}」",
            method="parquet の表",
        )
    item.notes.extend(notes)
    if cell.unreadable:
        item.notes.append(f"文字として読めなかったバイト列の値が {cell.unreadable} 件あった（中身は検査していない）")
    if broken:
        lost = sum(n for _, n, _ in broken)
        why = f"（壊れている・暗号化されている・未対応の圧縮の可能性）: {broken[0][2]}"
        if lost >= total_rows:
            raise Uncheckable(f"parquet の表の行を1行も読めなかった{why}")
        raise PartialScan(
            f"parquet の {total_rows} 行のうち {lost} 行（行のまとまり {len(broken)} 個）を読めず、残りの行だけを検査した{why}"
        )
    if truncated[0]:
        raise PartialScan(f"表の行数の上限（{limit} 行）までを検査した（全 {total_rows} 行）")

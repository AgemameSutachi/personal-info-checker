"""対処（remediate）で、SQLite のデータベースを書き換える部分（T2-b）。

決まり:
- 元のファイルは開いて書き換えない。元の写しを一時の名前（呼び出し側が決める）に作り、その写しへ SQL を当てる。
- 行の特定: 位置の行は rowid（rowid を持つ表）。WITHOUT ROWID の表など rowid が使えない表は、検査と同じ
  「SELECT * の通し番号」で数え直し、その行の主キーを書き換えるときにその場で読む（生の値は位置に入れない）。
- 外部キーの連鎖削除は動かさない（foreign_keys=OFF）。その表のトリガーは、書き換えの間だけ外して終わりに元の定義で作り直す
  （削除・更新のトリガーが、消した値をほかの表へ写してしまわないように）。
- 書き換えのあとは VACUUM（空き領域も詰める）。secure_delete も使い、消した値がファイルの空きに残らないようにする。
- WAL・ジャーナルの付属ファイル（-wal・-shm・-journal）が元にあれば、他のプログラムが開いている可能性があるので断る。
"""

from __future__ import annotations

import os
import re
import shutil
import sqlite3
from pathlib import Path
from urllib.parse import quote

from .remedy_write import DummyMaker, RemedyError, Selection, replace_spans

SIDECARS = ("-wal", "-shm", "-journal")
MIN_DROP_COLUMN_VERSION = (3, 35, 0)  # ALTER TABLE DROP COLUMN が使える SQLite の版
KEY_ALIASES = ("rowid", "_rowid_", "oid")
BATCH = 500  # 1回の SQL にまとめる行の数
SQLITE_MAGIC = b"SQLite format 3\x00"


def quote_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def sidecar_problem(path: str) -> str:
    """元のファイルに WAL・ジャーナルの付属ファイルがあれば、断る理由（無ければ空）。絶対パスだけを調べる。"""
    if not os.path.isabs(path):
        return ""
    from .engine import long_path

    for suffix in SIDECARS:
        if os.path.exists(long_path(path + suffix)):
            return (
                f"付属ファイル「{os.path.basename(path)}{suffix}」があります（他のプログラムが開いている、"
                "または正しく閉じられなかった可能性）。そのプログラムを終えてから、もう一度お試しください。ファイルの削除はできます"
            )
    return ""


def version_problem(method: str) -> str:
    if method == "delete_columns" and sqlite3.sqlite_version_info < MIN_DROP_COLUMN_VERSION:
        return (
            f"この環境の SQLite（{sqlite3.sqlite_version}）は列の削除（ALTER TABLE DROP COLUMN）に対応していません"
            "（3.35 以上が要ります）。ファイルの削除はできます"
        )
    return ""


# ---------------------------------------------------------------- 検査と書き換えで共有する決まり


def row_key_alias(conn: sqlite3.Connection, table: str) -> str | None:
    """表の行を特定する名前（rowid・_rowid_・oid のうち、列の名前に使われていないもの）。使えない表は None。

    WITHOUT ROWID の表や、3つとも列の名前に使われている表は None（検査の通し番号で行を数える）。
    """
    q = quote_ident(table)
    try:
        names = {r[1].lower() for r in conn.execute(f"PRAGMA table_xinfo({q})")}
    except sqlite3.Error:
        return None
    for alias in KEY_ALIASES:
        if alias in names:
            continue
        try:
            conn.execute(f"SELECT {alias} FROM {q} LIMIT 0")
        except sqlite3.Error:
            return None  # WITHOUT ROWID の表
        return alias
    return None


def unsafe_tables(conn: sqlite3.Connection) -> set[str]:
    """書き換えの対象にできない表（仮想表・その内部の表・sqlite_ で始まる管理用の表）。位置を集めない。"""
    rows = conn.execute("SELECT name, sql FROM sqlite_master WHERE type='table'").fetchall()
    virtual = {n for n, s in rows if s and re.match(r"\s*CREATE\s+VIRTUAL\s+TABLE", s, re.I)}
    out: set[str] = set()
    for name, _sql in rows:
        if name.lower().startswith("sqlite_") or name in virtual or any(name.startswith(v + "_") for v in virtual):
            out.add(name)
    return out


def _pk_columns(conn: sqlite3.Connection, table: str) -> list[str]:
    rows = conn.execute(f"PRAGMA table_xinfo({quote_ident(table)})").fetchall()
    return [r[1] for r in sorted((r for r in rows if r[5] > 0), key=lambda r: r[5])]


def _table_names(conn: sqlite3.Connection, table: str) -> tuple[list[str], set[str]]:
    """（SELECT * の列名の並び, 生成列の名前の集まり）。"""
    cur = conn.execute(f"SELECT * FROM {quote_ident(table)} LIMIT 0")
    names = [d[0] for d in cur.description]
    generated = {r[1] for r in conn.execute(f"PRAGMA table_xinfo({quote_ident(table)})") if r[6] in (2, 3)}
    return names, generated


# ---------------------------------------------------------------- 下見のための構造の情報（値は含まない）


def schema_notes(path: str, tables) -> dict:
    """位置のある表の構造（列名・主キー・索引・外部キー・ビュー・トリガー）を集める。下見の注意に使う。生の値は読まない。"""
    uri = "file:" + quote(Path(path).as_posix(), safe="/:") + "?mode=ro&immutable=1"
    out: dict = {"tables": {}}
    try:
        conn = sqlite3.connect(uri, uri=True)
    except sqlite3.Error:
        return out
    try:
        objs = conn.execute("SELECT type, name, tbl_name, sql FROM sqlite_master").fetchall()
        all_tables = [o[1] for o in objs if o[0] == "table"]
        dependents = [
            (o[1], o[2], set(re.findall(r"[\w$]+", (o[3] or "").lower()))) for o in objs if o[0] in ("view", "trigger")
        ]
        fks = {}
        for other in all_tables:
            try:
                fks[other] = conn.execute(f"PRAGMA foreign_key_list({quote_ident(other)})").fetchall()
            except sqlite3.Error:
                fks[other] = []
        for t in tables:
            try:
                q = quote_ident(t)
                xinfo = conn.execute(f"PRAGMA table_xinfo({q})").fetchall()
                cols = [r[1] for r in xinfo if r[6] in (0, 2, 3)]
                pk = _pk_columns(conn, t)
                indexed: set[str] = set()
                unique: set[str] = set()
                n_indexes = 0
                for idx in conn.execute(f"PRAGMA index_list({q})").fetchall():
                    n_indexes += 1
                    for r in conn.execute(f"PRAGMA index_info({quote_ident(idx[1])})").fetchall():
                        if r[2]:
                            indexed.add(r[2])
                            if idx[2]:
                                unique.add(r[2])
                referenced: set[str] = set()
                referenced_by: set[str] = set()
                for other, rows in fks.items():
                    for r in rows:
                        if r[2].lower() == t.lower() and other.lower() != t.lower():
                            referenced_by.add(other)
                            referenced.update([r[4]] if r[4] else pk)
                words = t.lower()
                col_deps: dict[str, list[str]] = {}
                views: list[str] = []
                for name, tbl, tokens in dependents:
                    if words not in tokens and tbl.lower() != words:
                        continue
                    views.append(name)
                    for c in cols:
                        if c.lower() in tokens:
                            col_deps.setdefault(c, []).append(name)
                out["tables"][t] = {
                    "columns": cols,
                    "pk": pk,
                    "indexed": sorted(indexed),
                    "unique": sorted(unique),
                    "fk_from": sorted({r[3] for r in fks.get(t, [])}),
                    "referenced": sorted(x for x in referenced if x),
                    "referenced_by": sorted(referenced_by),
                    "indexes": n_indexes,
                    "triggers": sum(1 for o in objs if o[0] == "trigger" and o[2].lower() == t.lower()),
                    "dependents": sorted(set(views)),
                    "col_deps": col_deps,
                    "generated": [r[1] for r in xinfo if r[6] in (2, 3)],
                    "has_rowid": row_key_alias(conn, t) is not None,
                }
            except sqlite3.Error:
                continue
    finally:
        conn.close()
    return out


# ---------------------------------------------------------------- 書き換え


def _remove_file(path: str) -> None:
    from .engine import long_path

    try:
        os.remove(long_path(path))
    except OSError:
        pass


def _discard_all(dst: str) -> None:
    """途中で失敗したとき、一時の新ファイルと SQLite が作った付属ファイルを消す。"""
    _remove_file(dst)
    for suffix in SIDECARS:
        _remove_file(dst + suffix)


def _fetch_by_keys(conn: sqlite3.Connection, table: str, alias: str, keys: list[int]) -> dict[int, tuple]:
    out: dict[int, tuple] = {}
    q = quote_ident(table)
    for i in range(0, len(keys), BATCH):
        chunk = keys[i : i + BATCH]
        marks = ",".join("?" * len(chunk))
        for row in conn.execute(f"SELECT {alias}, * FROM {q} WHERE {alias} IN ({marks})", chunk):
            out[row[0]] = row[1:]
    return out


def _ordinal_rows(conn: sqlite3.Connection, table: str, wanted: set[int]) -> dict[int, tuple[tuple, tuple]]:
    """rowid の使えない表で、検査と同じ通し番号（SELECT * の順）の行を、{番号: (主キーの値, 行の値)} で返す。"""
    pk = _pk_columns(conn, table)
    if not pk:
        raise RemedyError(f"表「{table}」は rowid も主キーも無いため、行を特定できません。ファイルの削除はできます")
    cur = conn.execute(f"SELECT * FROM {quote_ident(table)}")
    names = [d[0] for d in cur.description]
    pk_idx = [names.index(c) for c in pk]
    last = max(wanted) if wanted else 0
    out: dict[int, tuple[tuple, tuple]] = {}
    try:
        for r_idx, row in enumerate(cur, start=1):
            if r_idx in wanted:
                out[r_idx] = (tuple(row[i] for i in pk_idx), tuple(row))
            if r_idx >= last:
                break
    finally:
        cur.close()
    return out


def _where_pk(pk: list[str]) -> str:
    return " AND ".join(f"{quote_ident(c)}=?" for c in pk)


def _apply_delete_rows(conn: sqlite3.Connection, sel: Selection, stats: dict) -> None:
    for table, keys in sel.rows().items():
        q = quote_ident(table)
        alias = row_key_alias(conn, table)
        deleted = 0
        if alias:
            ordered = sorted(keys)
            for i in range(0, len(ordered), BATCH):
                chunk = ordered[i : i + BATCH]
                cur = conn.execute(f"DELETE FROM {q} WHERE {alias} IN ({','.join('?' * len(chunk))})", chunk)
                deleted += cur.rowcount
        else:
            rows = _ordinal_rows(conn, table, set(keys))
            pk = _pk_columns(conn, table)
            for r_idx in sorted(rows):
                deleted += conn.execute(f"DELETE FROM {q} WHERE {_where_pk(pk)}", rows[r_idx][0]).rowcount
        if deleted != len(keys):
            raise RemedyError(
                f"表「{table}」で、検査のときの位置と行の数が食い違いました（{len(keys)} 行のはずが {deleted} 行）。何も変えていません"
            )
        stats["rows"] += deleted


def _apply_delete_columns(conn: sqlite3.Connection, sel: Selection, stats: dict) -> None:
    for table, idxs in sel.cols().items():
        names, _gen = _table_names(conn, table)
        drop = [names[i] for i in sorted(idxs) if i < len(names)]
        if len(drop) >= len(names):
            raise RemedyError(
                f"表「{table}」のすべての列は削除できません（列が1つも残りません）。表ごと消すなら「表を削除」を選んでください"
            )
        for name in drop:
            try:
                conn.execute(f"ALTER TABLE {quote_ident(table)} DROP COLUMN {quote_ident(name)}")
            except sqlite3.Error as e:
                raise RemedyError(
                    f"表「{table}」の列「{name}」を削除できません（SQLite: {e}）。主キー・一意の索引・索引・外部キー・"
                    "CHECK 制約・ビュー・トリガーなどに使われている列は、削除できません。元のファイルは変えていません"
                ) from None
            stats["cols"] += 1


def _apply_delete_tables(conn: sqlite3.Connection, sel: Selection, stats: dict) -> None:
    for table in sel.sheets():
        try:
            conn.execute(f"DROP TABLE {quote_ident(table)}")
        except sqlite3.Error as e:
            raise RemedyError(f"表「{table}」を削除できません（SQLite: {e}）。元のファイルは変えていません") from None
        stats["tables"] += 1


def _apply_dummy(conn: sqlite3.Connection, sel: Selection, maker: DummyMaker, stats: dict) -> None:
    from .engine import _cell_to_str

    spans = sel.spans()
    for table, cells in spans.items():
        q = quote_ident(table)
        names, generated = _table_names(conn, table)
        by_row: dict[int, dict[int, list]] = {}
        for (row, col), lst in cells.items():
            by_row.setdefault(row, {})[col] = lst
        alias = row_key_alias(conn, table)
        if alias:
            fetched = _fetch_by_keys(conn, table, alias, sorted(by_row))
            where = f"{alias}=?"
            keyed = {row: ((row,), fetched[row]) for row in by_row if row in fetched}
        else:
            pk = _pk_columns(conn, table)
            keyed = _ordinal_rows(conn, table, set(by_row))
            where = _where_pk(pk)
        if len(keyed) != len(by_row):
            raise RemedyError(
                f"表「{table}」で、検査のときの位置の行が見つかりません（{len(by_row) - len(keyed)} 行）。何も変えていません"
            )
        for row in sorted(by_row):
            key_values, values = keyed[row]
            sets: dict[str, str] = {}
            for c, lst in by_row[row].items():
                if c >= len(names) or c >= len(values):
                    continue
                if names[c] in generated:
                    stats["skipped_generated"] += 1
                    continue
                v = values[c]
                text = "" if v is None else _cell_to_str(v)
                if not text:
                    continue
                new = replace_spans(text, lst, maker)
                if new != text:
                    sets[names[c]] = new
                    stats["detections"] += len(lst)
            if not sets:
                continue
            assign = ",".join(f"{quote_ident(n)}=?" for n in sets)
            try:
                cur = conn.execute(f"UPDATE {q} SET {assign} WHERE {where}", [*sets.values(), *key_values])
            except sqlite3.Error as e:
                raise RemedyError(
                    f"表「{table}」の値を置き換えられません（SQLite: {e}）。一意の制約・CHECK 制約・STRICT 表の型などに"
                    "引っかかった可能性があります（ダミーの作り方を「同じ値は同じダミー」にすると、一意の制約を保ちやすくなります）。"
                    "元のファイルは変えていません"
                ) from None
            if cur.rowcount != 1:
                raise RemedyError(f"表「{table}」で、置き換える行を1つに特定できませんでした。何も変えていません")
            stats["cells"] += len(sets)


def _apply(conn: sqlite3.Connection, method: str, sel: Selection, maker: DummyMaker | None) -> dict:
    stats = {"rows": 0, "cols": 0, "tables": 0, "cells": 0, "detections": 0, "skipped_generated": 0, "vacuum": True}
    was_wal = str(conn.execute("PRAGMA journal_mode").fetchone()[0]).lower() == "wal"
    if was_wal:
        conn.execute(
            "PRAGMA journal_mode=DELETE"
        )  # 写しの上では、WAL の付属ファイルを作らずに書き換える（終わりに戻す）
    conn.execute("PRAGMA secure_delete=ON")
    conn.execute("PRAGMA foreign_keys=OFF")
    touched = sorted({k[0] for k in sel.groups})
    conn.execute("BEGIN IMMEDIATE")
    try:
        saved: list[str] = []
        if method != "delete_table" and touched:
            marks = ",".join("?" * len(touched))
            for name, sql in conn.execute(
                f"SELECT name, sql FROM sqlite_master WHERE type='trigger' AND tbl_name IN ({marks})", touched
            ).fetchall():
                saved.append(sql)
                conn.execute(f"DROP TRIGGER {quote_ident(name)}")
        if method == "delete_rows":
            _apply_delete_rows(conn, sel, stats)
        elif method == "delete_columns":
            _apply_delete_columns(conn, sel, stats)
        elif method == "delete_table":
            _apply_delete_tables(conn, sel, stats)
        elif method == "dummy":
            _apply_dummy(conn, sel, maker, stats)
        else:
            raise RemedyError("この方法は SQLite に使えません")
        for sql in saved:
            try:
                conn.execute(sql)
            except sqlite3.Error as e:
                raise RemedyError(
                    f"トリガーを元の定義で作り直せませんでした（SQLite: {e}）。元のファイルは変えていません"
                ) from None
        conn.execute("COMMIT")
    except BaseException:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise
    if method == "dummy" and stats["cells"] == 0:
        raise RemedyError("書き換える値が見つかりませんでした（生成列は書き換えません）。元のファイルは変えていません")
    # 空き領域も詰める（消した値が、ページの空きに残らないように）
    conn.execute("VACUUM")
    check = conn.execute("PRAGMA integrity_check").fetchall()
    if [tuple(r) for r in check] != [("ok",)]:
        raise RemedyError(
            "書き換えた SQLite の整合性の確認（integrity_check）に失敗したため、置き換えません。元のファイルは変えていません"
        )
    if was_wal:
        conn.execute("PRAGMA journal_mode=WAL")
    return stats


def rewrite_sqlite_file(src: str, dst: str, method: str, sel: Selection, maker: DummyMaker | None) -> dict:
    """SQLite のファイル src の写しを dst に作り、選んだ方法で書き換える（VACUUM つき）。元の src には書かない。"""
    from .engine import long_path

    problem = sidecar_problem(src) or version_problem(method)
    if problem:
        raise RemedyError(problem)
    with open(long_path(src), "rb") as f:
        if f.read(16) != SQLITE_MAGIC:
            raise RemedyError("SQLite のファイルとして読めません。元のファイルは変えていません")
    try:
        shutil.copyfile(long_path(src), long_path(dst))
        conn = sqlite3.connect(long_path(dst), isolation_level=None)
        try:
            stats = _apply(conn, method, sel, maker)
        finally:
            conn.close()
        for suffix in SIDECARS:  # 閉じれば消えるはず。残っていれば（空の）付属ファイルを片付ける
            _remove_file(dst + suffix)
        with open(long_path(dst), "r+b") as f:
            f.flush()
            os.fsync(f.fileno())
    except BaseException as e:
        _discard_all(dst)
        if isinstance(e, sqlite3.Error):
            raise RemedyError(f"SQLite の書き換えに失敗しました（{e}）。元のファイルは変えていません") from None
        raise
    return stats

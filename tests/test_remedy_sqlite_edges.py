"""対処の SQLite の書き換え（remedy_sqlite）の細かい枝の試験（実際の検査は使わない）。

test_remediate_db.py は実際の検査の位置で書き換えと元の保ち方を確かめる。ここでは、位置を手で作って
断りの文（行の数の食い違い・列が残らない・表が無い・制約に引っかかる・壊れたファイル）と、
下見の構造の情報（外部キー・読めない表）、行の特定の仕方（rowid の別名）を軽い材料で確かめる。
"""

from __future__ import annotations

import sqlite3
import sys
from array import array
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pii_checker import remedy_sqlite  # noqa: E402
from pii_checker.remedy_write import DummyMaker, RemedyError, Selection, sha256_file  # noqa: E402

MAIL = "taro@example.com"


def make_db(path: Path, *sqls: str) -> Path:
    conn = sqlite3.connect(path)
    try:
        for sql in sqls:
            conn.execute(sql)
        conn.commit()
    finally:
        conn.close()
    return path


def sel(table: str, *pos: tuple[int, int, int, int], pii_type: str = "email") -> Selection:
    """位置（行, 列, 開始, 終了）の並びから Selection を作る。"""
    flat = [v for p in pos for v in p]
    return Selection({(table, pii_type, 0): array("q", flat)})


def refused(tmp_path: Path, src: Path, method: str, selection: Selection, maker=None) -> str:
    """書き換えが断られ、元が変わらず一時の新ファイルも残らないことを確かめて、断りの文を返す。"""
    before = sha256_file(str(src))
    dst = tmp_path / "out.sqlite"
    with pytest.raises(RemedyError) as e:
        remedy_sqlite.rewrite_sqlite_file(str(src), str(dst), method, selection, maker)
    assert sha256_file(str(src)) == before
    assert not dst.exists()
    return str(e.value)


# ---------------------------------------------------------------- 版・行の特定・管理用の表


def test_old_sqlite_cannot_drop_columns(monkeypatch):
    monkeypatch.setattr(remedy_sqlite.sqlite3, "sqlite_version_info", (3, 30, 0))
    assert "3.35 以上" in remedy_sqlite.version_problem("delete_columns")
    assert remedy_sqlite.version_problem("delete_rows") == ""


def test_row_key_alias_skips_names_used_by_columns():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE a(rowid, name)")
    conn.execute('CREATE TABLE "b c"(rowid, _rowid_, oid, name)')
    assert remedy_sqlite.row_key_alias(conn, "a") == "_rowid_"
    assert remedy_sqlite.row_key_alias(conn, "b c") is None


def test_row_key_alias_is_none_when_the_table_cannot_be_read():
    class Broken:
        def execute(self, *_a):
            raise sqlite3.OperationalError("読めない")

    assert remedy_sqlite.row_key_alias(Broken(), "t") is None


def test_virtual_tables_and_their_shadow_tables_are_unsafe():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE people(name)")
    try:
        conn.execute("CREATE VIRTUAL TABLE notes USING fts5(body)")
    except sqlite3.OperationalError:
        pytest.skip("この SQLite には fts5 がありません")
    unsafe = remedy_sqlite.unsafe_tables(conn)
    assert "notes" in unsafe and "notes_data" in unsafe and "notes_content" in unsafe
    assert "people" not in unsafe


# ---------------------------------------------------------------- 下見の構造の情報


def test_schema_notes_of_a_missing_file_is_empty(tmp_path):
    assert remedy_sqlite.schema_notes(str(tmp_path / "無い.sqlite"), ["t"]) == {"tables": {}}


def test_schema_notes_lists_tables_that_refer_to_the_table(tmp_path):
    db = make_db(
        tmp_path / "fk.sqlite",
        "CREATE TABLE people(id INTEGER PRIMARY KEY, mail TEXT UNIQUE)",
        "CREATE TABLE orders(id INTEGER PRIMARY KEY, who INTEGER REFERENCES people(id), contact TEXT REFERENCES people)",
    )
    notes = remedy_sqlite.schema_notes(str(db), ["people", "orders"])["tables"]
    assert notes["people"]["referenced_by"] == ["orders"]
    # 列を書かない参照（REFERENCES people）は、主キーを参照しているとみなす
    assert notes["people"]["referenced"] == ["id"]
    assert notes["people"]["unique"] == ["mail"]
    assert notes["orders"]["fk_from"] == ["contact", "who"]
    assert notes["orders"]["referenced_by"] == []


def test_schema_notes_skips_tables_whose_structure_cannot_be_read(tmp_path, monkeypatch):
    """外部キーの一覧・索引の一覧が読めない表があっても、ほかの表の情報は返す。"""
    db = make_db(tmp_path / "s.sqlite", "CREATE TABLE good(a)", "CREATE TABLE bad(b)")
    real_connect = sqlite3.connect

    class Conn:
        def __init__(self, inner):
            self.inner = inner

        def execute(self, sql, *args):
            if "foreign_key_list" in sql and '"good"' in sql:
                raise sqlite3.OperationalError("外部キーを読めない")
            if "index_list" in sql and '"bad"' in sql:
                raise sqlite3.OperationalError("索引を読めない")
            return self.inner.execute(sql, *args)

        def close(self):
            self.inner.close()

    monkeypatch.setattr(remedy_sqlite.sqlite3, "connect", lambda *a, **k: Conn(real_connect(*a, **k)))
    notes = remedy_sqlite.schema_notes(str(db), ["good", "bad"])["tables"]
    assert set(notes) == {"good"}
    assert notes["good"]["fk_from"] == []


# ---------------------------------------------------------------- 書き換えの断り


def test_table_without_rowid_or_primary_key_is_refused(tmp_path):
    db = make_db(
        tmp_path / "nokey.sqlite",
        "CREATE TABLE t(rowid, _rowid_, oid, mail)",
        f"INSERT INTO t VALUES (1, 2, 3, '{MAIL}')",
    )
    msg = refused(tmp_path, db, "delete_rows", sel("t", (1, 3, 0, len(MAIL))))
    assert "rowid も主キーも無い" in msg


def test_delete_rows_refuses_when_rows_are_missing(tmp_path):
    db = make_db(tmp_path / "rows.sqlite", "CREATE TABLE t(mail)", f"INSERT INTO t VALUES ('{MAIL}')")
    msg = refused(tmp_path, db, "delete_rows", sel("t", (1, 0, 0, 4), (99, 0, 0, 4)))
    assert "2 行のはずが 1 行" in msg


def test_delete_columns_refuses_to_drop_every_column(tmp_path):
    db = make_db(tmp_path / "cols.sqlite", "CREATE TABLE t(mail, tel)", f"INSERT INTO t VALUES ('{MAIL}', '0')")
    msg = refused(tmp_path, db, "delete_columns", sel("t", (1, 0, 0, 4), (1, 1, 0, 1)))
    assert "すべての列は削除できません" in msg


def test_delete_table_refuses_a_table_that_is_not_there(tmp_path):
    db = make_db(tmp_path / "tbl.sqlite", "CREATE TABLE t(mail)")
    msg = refused(tmp_path, db, "delete_table", sel("無い表", (1, 0, 0, 4)))
    assert "表「無い表」を削除できません" in msg


def test_dummy_refuses_when_rows_are_missing(tmp_path):
    db = make_db(tmp_path / "dm.sqlite", "CREATE TABLE t(mail)", f"INSERT INTO t VALUES ('{MAIL}')")
    msg = refused(tmp_path, db, "dummy", sel("t", (1, 0, 0, 4), (50, 0, 0, 4)), DummyMaker("fixed"))
    assert "位置の行が見つかりません（1 行）" in msg


def test_dummy_skips_generated_empty_and_out_of_range_cells(tmp_path):
    """生成列・空の値・列の数を超える位置は書き換えない。書き換える値が1つも無ければ断る。"""
    db = make_db(
        tmp_path / "gen.sqlite",
        "CREATE TABLE t(mail TEXT, upper_mail TEXT GENERATED ALWAYS AS (upper(mail)) VIRTUAL, memo TEXT)",
        f"INSERT INTO t(mail, memo) VALUES ('{MAIL}', NULL)",
        "INSERT INTO t(mail, memo) VALUES ('', '')",
    )
    msg = refused(
        tmp_path,
        db,
        "dummy",
        sel("t", (1, 1, 0, 4), (1, 2, 0, 4), (1, 9, 0, 4), (2, 0, 0, 4)),
        DummyMaker("fixed"),
    )
    assert "書き換える値が見つかりませんでした（生成列は書き換えません）" in msg


def test_dummy_counts_skipped_generated_columns(tmp_path):
    db = make_db(
        tmp_path / "gen2.sqlite",
        "CREATE TABLE t(mail TEXT, upper_mail TEXT GENERATED ALWAYS AS (upper(mail)) VIRTUAL)",
        f"INSERT INTO t(mail) VALUES ('{MAIL}')",
    )
    dst = tmp_path / "out.sqlite"
    stats = remedy_sqlite.rewrite_sqlite_file(
        str(db), str(dst), "dummy", sel("t", (1, 0, 0, len(MAIL)), (1, 1, 0, len(MAIL))), DummyMaker("fixed")
    )
    assert stats["cells"] == 1 and stats["skipped_generated"] == 1
    conn = sqlite3.connect(dst)
    try:
        assert conn.execute("SELECT mail FROM t").fetchone()[0] != MAIL
    finally:
        conn.close()


def test_dummy_that_breaks_a_check_constraint_is_refused(tmp_path):
    db = make_db(
        tmp_path / "chk.sqlite",
        f"CREATE TABLE t(mail TEXT CHECK (mail = '{MAIL}'))",
        f"INSERT INTO t VALUES ('{MAIL}')",
    )
    msg = refused(tmp_path, db, "dummy", sel("t", (1, 0, 0, len(MAIL))), DummyMaker("fixed"))
    assert "値を置き換えられません" in msg and "CHECK" in msg


def test_unknown_method_is_refused(tmp_path):
    db = make_db(tmp_path / "m.sqlite", "CREATE TABLE t(mail)", f"INSERT INTO t VALUES ('{MAIL}')")
    assert "この方法は SQLite に使えません" in refused(tmp_path, db, "shred", sel("t", (1, 0, 0, 4)))


def test_file_that_is_not_sqlite_is_refused(tmp_path):
    src = tmp_path / "fake.sqlite"
    src.write_bytes(b"not a database at all, just text\n")
    assert "SQLite のファイルとして読めません" in refused(tmp_path, src, "delete_rows", sel("t", (1, 0, 0, 4)))


def test_broken_sqlite_after_the_header_is_refused(tmp_path):
    """先頭の印だけ正しく、中身が壊れたファイル。SQLite の失敗を言い換えて断り、写しを片付ける。"""
    src = tmp_path / "broken.sqlite"
    src.write_bytes(remedy_sqlite.SQLITE_MAGIC + b"\xff" * 4096)
    assert "SQLite の書き換えに失敗しました" in refused(tmp_path, src, "delete_rows", sel("t", (1, 0, 0, 4)))

"""対処の SQL のダンプの書き換え（remedy_sqldump）の細かい枝の試験（実際の検査は使わない）。

test_remediate_db.py は実際の検査の位置で、文字コード・改行・巨大なファイルを通した書き換えを確かめる。ここでは、
位置を手で作って、断りの文（行が見つからない・列の並びが食い違う・列が残らない・読み解けない文）と、
値1つの書き換えの細かい形（接頭辞・連結・NULL・閉じない組）、列の下調べ、索引・コメントなどの文の扱いを確かめる。
"""

from __future__ import annotations

import codecs
import sys
from array import array
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pii_checker import remedy_sqldump as rs  # noqa: E402
from pii_checker.formats.dbdump import ROW_KEY_SHIFT, parse_values_spans  # noqa: E402
from pii_checker.remedy_write import FIXED_DUMMY, DummyMaker, RemedyError, Selection, sha256_file  # noqa: E402

MAIL = "taro@example.com"
FIXED = DummyMaker("fixed")


def key(line: int, j: int = 0) -> int:
    """位置の行の鍵（COPY のデータ行は j=0、INSERT は文の先頭の行と何組目か）。"""
    return (line << ROW_KEY_SHIFT) | j


def sel(table: str, *pos: tuple[int, int, int, int], pii_type: str = "email") -> Selection:
    flat = [v for p in pos for v in p]
    return Selection({(table, pii_type, 0): array("q", flat)})


def write_dump(tmp_path: Path, text: str, enc: str = "utf-8", bom: bytes = b"") -> Path:
    src = tmp_path / "dump.sql"
    src.write_bytes(bom + text.encode(enc))
    return src


def rewrite(tmp_path: Path, text: str, method: str, selection: Selection, maker=None, enc="utf-8", bom=b""):
    src = write_dump(tmp_path, text, enc, bom)
    dst = tmp_path / "out.sql"
    stats = rs.rewrite_sql_dump_file(str(src), str(dst), method, selection, maker)
    return dst.read_bytes(), stats


def refused(tmp_path: Path, text: str, method: str, selection: Selection, maker=None) -> str:
    """書き換えが断られ、元が変わらないことを確かめて、断りの文を返す。"""
    src = write_dump(tmp_path, text)
    before = sha256_file(str(src))
    with pytest.raises(RemedyError) as e:
        rs.rewrite_sql_dump_file(str(src), str(tmp_path / "out.sql"), method, selection, maker)
    assert sha256_file(str(src)) == before
    return str(e.value)


# ---------------------------------------------------------------- 文字コードと行の読み方


def test_utf16_be_with_bom_is_written_back_in_utf16_be(tmp_path):
    text = f"INSERT INTO t VALUES ('{MAIL}');\nINSERT INTO t VALUES ('x');\n"
    src = write_dump(tmp_path, text, "utf-16-be", codecs.BOM_UTF16_BE)
    assert rs.detect_encoding(str(src)) == ("utf-16-be", codecs.BOM_UTF16_BE)
    out, stats = rewrite(
        tmp_path, text, "delete_rows", sel("t", (key(1, 1), 0, 0, 4)), enc="utf-16-be", bom=codecs.BOM_UTF16_BE
    )
    assert out.startswith(codecs.BOM_UTF16_BE)
    assert out[2:].decode("utf-16-be") == "INSERT INTO t VALUES ('x');\n"
    assert stats["rows"] == 1


def test_huge_utf16_dump_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(rs, "TEXT_REWRITE_LIMIT", 10)
    src = write_dump(tmp_path, "INSERT INTO t VALUES ('a');\n", "utf-16-le", codecs.BOM_UTF16_LE)
    with pytest.raises(RemedyError, match="大きすぎる"):
        rs.open_dump(str(src))


def test_line_that_cannot_be_decoded_is_refused(tmp_path):
    src = tmp_path / "bad.sql"
    src.write_bytes(b"SELECT 1;\n\xff\xfe\xfd\n")
    with pytest.raises(RemedyError, match="文字コードを読み取れない行"):
        list(rs._stream_lines(str(src), "utf-8", b""))


def test_line_that_does_not_round_trip_is_refused(tmp_path):
    """cp932 の NEC 選定の重複文字（0x8790 の ≒）は、読んで書き戻すと別のバイト列（0x81E0）になる。"""
    src = tmp_path / "nec.sql"
    src.write_bytes(b"SELECT 1;\n\x87\x90\n")
    assert "\x87\x90".encode("latin-1").decode("cp932").encode("cp932") != b"\x87\x90"
    with pytest.raises(RemedyError, match="元と同じ中身にならない行"):
        list(rs._stream_lines(str(src), "cp932", b""))


# ---------------------------------------------------------------- 値1つの書き換え


def test_unquoted_value_without_a_usable_span_is_kept():
    assert rs.dummy_insert_cell(" 123 ", "123", [(10, 12, "phone")], FIXED) == " 123 "


def test_value_that_reads_differently_from_the_scan_is_replaced_whole():
    """検査の読み方と合わない書き方（連結など）は、セル全体を1つのダミーにする。位置が当たらなければ変えない。"""
    raw = f"foo'{MAIL}'"
    assert rs.dummy_insert_cell(raw, MAIL, [(0, len(MAIL), "email")], FIXED) == f"foo'{FIXED_DUMMY}'"
    assert rs.dummy_insert_cell(raw, MAIL, [(99, 100, "email")], FIXED) == raw


def test_introducer_prefix_spans_outside_the_value_are_kept():
    """N'…' の N は書き方の一部。位置が接頭辞の中だけ・空になるときは変えない。"""
    assert rs.dummy_insert_cell("N'abc'", "Nabc", [(0, 1, "name")], FIXED) == "N'abc'"
    assert rs.dummy_insert_cell("N'abc'", "Nabc", [(2, 2, "name")], FIXED) == "N'abc'"


def test_quoted_value_without_a_usable_span_is_kept():
    assert rs.dummy_insert_cell("'abc'", "abc", [(5, 9, "name")], FIXED) == "'abc'"


def test_copy_cell_without_a_usable_span_is_kept():
    assert rs.dummy_copy_cell("a\\bc", [(9, 10, "name")], FIXED) == "a\\bc"  # 検査が外さないエスケープつき
    assert rs.dummy_copy_cell("abc", [(9, 10, "name")], FIXED) == "abc"


def test_drop_items_keeps_leading_space_and_refuses_dropping_everything():
    assert rs.drop_items(" a, b, c", {0}) == " b, c"
    with pytest.raises(RemedyError, match="すべての列は削除できません"):
        rs.drop_items("a, b", {0, 1})


def test_tuple_text_refuses_unclosed_and_empty_tuples_and_keeps_leading_space():
    stmt = "( 'a', 'b')"
    tuples, _ = parse_values_spans(stmt, 0)
    assert rs.DumpRewriter._tuple_text(stmt, tuples[0], {0}, {}) == "( 'b')"
    with pytest.raises(RemedyError, match="すべての列は削除できません"):
        rs.DumpRewriter._tuple_text(stmt, tuples[0], {0, 1}, {})
    s, e, _closed, cells = tuples[0]
    with pytest.raises(RemedyError, match="閉じていない INSERT の組"):
        rs.DumpRewriter._tuple_text(stmt, (s, e, False, cells), set(), {})


# ---------------------------------------------------------------- 列の下調べ


def test_collect_columns_reads_unterminated_statements_to_the_end(tmp_path):
    """閉じない INSERT・閉じない CREATE（次の INSERT の手前・ファイルの終わりまで）も、検査と同じ区切りで読む。"""
    src = write_dump(
        tmp_path,
        "CREATE TABLE a (\n  x text,\n  y text\n) WITH (fillfactor=70)\nINSERT INTO a (x, y) VALUES ('1', '2'),\n",
    )
    canonical, conflicts = rs.collect_columns(str(src))
    assert canonical == {"a": ["x", "y"]} and conflicts == set()
    src.write_bytes(b"CREATE TABLE b (\n  p text,\n  q text\n) WITH (fillfactor=70)\n")
    assert rs.collect_columns(str(src)) == ({"b": ["p", "q"]}, set())


def test_collect_columns_notices_tables_with_different_column_orders(tmp_path):
    src = write_dump(
        tmp_path, "INSERT INTO t (a, mail) VALUES ('1', '2');\nINSERT INTO t (mail, a) VALUES ('2', '1');\n"
    )
    canonical, conflicts = rs.collect_columns(str(src))
    assert canonical["t"] == ["a", "mail"] and conflicts == {"t"}


# ---------------------------------------------------------------- 書き換えの終わりの確かめ


def test_delete_rows_refuses_when_a_row_is_missing(tmp_path):
    text = f"INSERT INTO t VALUES ('{MAIL}');\n"
    msg = refused(tmp_path, text, "delete_rows", sel("t", (key(1, 1), 0, 0, 4), (key(7, 1), 0, 0, 4)))
    assert "位置の行が見つかりません（1 行）" in msg


def test_dummy_refuses_when_a_row_is_missing(tmp_path):
    text = f"INSERT INTO t VALUES ('{MAIL}');\n"
    msg = refused(tmp_path, text, "dummy", sel("t", (key(1, 1), 0, 0, 4), (key(5, 1), 0, 0, 4)), FIXED)
    assert "位置の行が見つかりません（1 行）" in msg


def test_delete_table_refuses_a_table_without_statements(tmp_path):
    msg = refused(tmp_path, "INSERT INTO other VALUES ('a');\n", "delete_table", sel("t", (key(1, 1), 0, 0, 1)))
    assert "表「t」の文が見つかりませんでした" in msg


def test_dummy_refuses_when_nothing_changes(tmp_path):
    """NULL の値・組の値の数を超える位置・当たらない位置だけなら、書き換える値が無いとして断る。"""
    text = f"INSERT INTO t VALUES (NULL, '{MAIL}');\n"
    selection = sel("t", (key(1, 1), 0, 0, 4), (key(1, 1), 5, 0, 4), (key(1, 1), 1, 50, 60))
    assert "書き換える値が見つかりませんでした" in refused(tmp_path, text, "dummy", selection, FIXED)


def test_unknown_method_is_refused(tmp_path):
    assert "SQL のダンプに使えません" in refused(tmp_path, "SELECT 1;\n", "shred", sel("t", (key(1), 0, 0, 1)))


def test_dummy_that_cannot_be_written_in_the_file_encoding_is_refused(tmp_path):
    class EmojiMaker:
        def make(self, _t, _v):
            return "\U0001f600"

    text = f"INSERT INTO t VALUES ('{MAIL}');\n"
    src = tmp_path / "cp.sql"
    src.write_bytes(("-- 顧客の一覧（日本語の注記）\n" * 20 + text).encode("cp932"))
    dst = tmp_path / "out.sql"
    with pytest.raises(RemedyError, match="元の文字コードに直せません"):
        rs.rewrite_sql_dump_file(str(src), str(dst), "dummy", sel("t", (key(21, 1), 0, 0, len(MAIL))), EmojiMaker())
    assert not dst.exists()


# ---------------------------------------------------------------- 列の削除の断り


def test_delete_columns_refuses_tables_whose_column_order_differs(tmp_path):
    text = "INSERT INTO t (a, mail) VALUES ('1', '2');\nINSERT INTO t (mail, a) VALUES ('2', '1');\n"
    assert "列の並びが違う" in refused(tmp_path, text, "delete_columns", sel("t", (key(1, 1), 1, 0, 1)))


def test_delete_columns_refuses_when_column_names_are_unknown(tmp_path):
    text = "CREATE INDEX i ON t (mail);\nINSERT INTO t VALUES ('1', '2');\n"
    assert "列の名前を読み取れない" in refused(tmp_path, text, "delete_columns", sel("t", (key(2, 1), 1, 0, 1)))


def test_delete_columns_refuses_positions_beyond_the_known_columns(tmp_path):
    text = f"COPY t (mail) FROM stdin;\n{MAIL}\n\\.\n"
    assert "全部は読み取れない" in refused(tmp_path, text, "delete_columns", sel("t", (key(2), 3, 0, 1)))


def test_delete_columns_refuses_dropping_every_copy_column(tmp_path):
    text = f"COPY t (mail) FROM stdin;\n{MAIL}\n\\.\n"
    assert "すべての列は削除できません" in refused(tmp_path, text, "delete_columns", sel("t", (key(2), 0, 0, 4)))


def test_delete_columns_refuses_copy_rows_with_wrong_cell_counts(tmp_path):
    text = f"COPY t (a, mail) FROM stdin;\n1\t{MAIL}\nonly-one\n\\.\n"
    msg = refused(tmp_path, text, "delete_columns", sel("t", (key(2), 1, 0, 4)))
    assert "3 行目の欄の数" in msg


def test_delete_columns_refuses_insert_tuples_with_wrong_value_counts(tmp_path):
    text = f"INSERT INTO t (a, mail) VALUES ('1', '{MAIL}'), ('2');\n"
    assert "値の数が列名の数と合わない" in refused(tmp_path, text, "delete_columns", sel("t", (key(1, 1), 1, 0, 4)))


def test_delete_columns_refuses_insert_without_names_that_does_not_match_create(tmp_path):
    text = "CREATE TABLE t (\n  a text,\n  mail text\n);\nINSERT INTO t VALUES ('1');\n"
    msg = refused(tmp_path, text, "delete_columns", sel("t", (key(5, 1), 1, 0, 1)))
    assert "CREATE TABLE から読んだ列の数（2）" in msg


def test_delete_columns_refuses_create_table_that_cannot_be_parsed(tmp_path):
    text = f"CREATE TABLE t AS SELECT 1;\nINSERT INTO t (a, mail) VALUES ('1', '{MAIL}');\n"
    msg = refused(tmp_path, text, "delete_columns", sel("t", (key(2, 1), 1, 0, 4)))
    assert "CREATE TABLE を読み解けない" in msg


def test_delete_columns_refuses_when_create_lacks_the_column(tmp_path):
    text = f"CREATE TABLE t (\n  a text,\n  email text\n);\nINSERT INTO t (a, mail) VALUES ('1', '{MAIL}');\n"
    msg = refused(tmp_path, text, "delete_columns", sel("t", (key(5, 1), 1, 0, 4)))
    assert "削除する列「mail」を見つけられない" in msg


def test_delete_columns_refuses_when_create_would_be_left_empty(tmp_path):
    text = f"CREATE TABLE t (\n  mail text\n);\nINSERT INTO t (a, mail) VALUES ('1', '{MAIL}');\n"
    assert "すべての列は削除できません" in refused(tmp_path, text, "delete_columns", sel("t", (key(4, 1), 1, 0, 4)))


def test_delete_columns_refuses_inline_create_that_would_be_left_empty(tmp_path):
    text = f"CREATE TABLE t(mail text, UNIQUE(mail));\nINSERT INTO t (a, mail) VALUES ('1', '{MAIL}');\n"
    assert "すべての列は削除できません" in refused(tmp_path, text, "delete_columns", sel("t", (key(2, 1), 1, 0, 4)))


def test_delete_table_refuses_insert_with_another_statement_before_it(tmp_path):
    text = f"SET x = 1; INSERT INTO t VALUES ('{MAIL}');\n"
    assert "INSERT 文の前に別の文がある" in refused(tmp_path, text, "delete_table", sel("t", (key(1, 1), 0, 0, 4)))


def test_dummy_refuses_unclosed_tuple(tmp_path):
    text = f"INSERT INTO t VALUES ('{MAIL}'),('b'"
    msg = refused(tmp_path, text, "dummy", sel("t", (key(1, 1), 0, 0, len(MAIL))), FIXED)
    assert "閉じていない INSERT の組" in msg


# ---------------------------------------------------------------- 書き換えの細かい形


def test_dummy_skips_copy_cells_beyond_the_row(tmp_path):
    text = f"COPY t (mail) FROM stdin;\n{MAIL}\n\\.\n"
    out, stats = rewrite(tmp_path, text, "dummy", sel("t", (key(2), 0, 0, len(MAIL)), (key(2), 4, 0, 1)), FIXED)
    assert out.decode() == f"COPY t (mail) FROM stdin;\n{FIXED_DUMMY}\n\\.\n"
    assert stats["cells"] == 1


def test_insert_that_runs_to_the_end_of_the_file_is_rewritten(tmp_path):
    text = f"INSERT INTO t VALUES\n('{MAIL}')"
    out, _ = rewrite(tmp_path, text, "dummy", sel("t", (key(1, 1), 0, 0, len(MAIL))), FIXED)
    assert out.decode() == f"INSERT INTO t VALUES\n('{FIXED_DUMMY}')"


def test_delete_rows_passes_untouched_statements_through(tmp_path):
    text = "INSERT INTO t VALUES ('keep');\n" f"INSERT INTO t VALUES ('{MAIL}'),('keep2');\n"
    out, stats = rewrite(tmp_path, text, "delete_rows", sel("t", (key(2, 1), 0, 0, 4)))
    assert out.decode() == "INSERT INTO t VALUES ('keep');\nINSERT INTO t VALUES ('keep2');\n"
    assert stats["rows"] == 1


def test_delete_columns_passes_insert_without_tuples_through(tmp_path):
    text = (
        "CREATE TABLE t (\n  a text,\n  mail text\n);\n"
        "INSERT INTO t (a, mail) VALUES ;\n"
        f"INSERT INTO t (a, mail) VALUES ('1', '{MAIL}');\n"
    )
    out, stats = rewrite(tmp_path, text, "delete_columns", sel("t", (key(6, 1), 1, 0, 4)))
    assert out.decode() == (
        "CREATE TABLE t (\n  a text\n);\nINSERT INTO t (a, mail) VALUES ;\nINSERT INTO t (a) VALUES ('1');\n"
    )
    assert stats["cols"] == 1


def test_delete_columns_rebuilds_inline_create_and_its_constraints(tmp_path):
    """sqlite3 の .dump の形（1 行の CREATE TABLE）。消す列を使う制約も外し、ほかの制約は残す。"""
    text = (
        "CREATE TABLE t(a text, mail text, UNIQUE(mail), CHECK (a <> ''));\r\n"
        f"INSERT INTO t VALUES('1','{MAIL}');\r\n"
    )
    out, _ = rewrite(tmp_path, text, "delete_columns", sel("t", (key(2, 1), 1, 0, 4)))
    assert out.decode() == "CREATE TABLE t(a text, CHECK (a <> ''));\r\nINSERT INTO t VALUES('1');\r\n"


def test_delete_columns_rebuilds_create_when_a_column_shares_the_create_line(tmp_path):
    text = (
        "CREATE TABLE t (mail text,\n"
        "   \n"
        "  a text,\n"
        "  b text\n"
        ");\n"
        f"INSERT INTO t (mail, a, b) VALUES ('{MAIL}', '1', '2');\n"
    )
    out, _ = rewrite(tmp_path, text, "delete_columns", sel("t", (key(6, 1), 0, 0, 4)))
    assert out.decode() == "CREATE TABLE t (a text,\n  b text\n);\nINSERT INTO t (a, b) VALUES ('1', '2');\n"


def test_delete_columns_rebuilds_create_when_one_line_holds_two_columns(tmp_path):
    text = (
        "CREATE TABLE t (\n"
        "  a text, mail text,\n"
        "  b text\n"
        ");\n"
        f"INSERT INTO t (a, mail, b) VALUES ('1', '{MAIL}', '2');\n"
    )
    out, _ = rewrite(tmp_path, text, "delete_columns", sel("t", (key(5, 1), 1, 0, 4)))
    body = out.decode()
    assert "mail" not in body.split("INSERT")[0]
    assert body.endswith("INSERT INTO t (a, b) VALUES ('1', '2');\n")


def test_delete_table_drops_create_without_semicolon_and_keeps_following_insert_of_other_table(tmp_path):
    """「;」の無い CREATE は、次の INSERT の手前（またはファイルの終わり）までを1文とみなす。"""
    text = "CREATE TABLE t (\n  mail text\n) WITH (fillfactor=70)\nINSERT INTO other VALUES ('x');\nCREATE TABLE t2 (\n  a text\n"
    out, stats = rewrite(tmp_path, text, "delete_table", sel("t", (key(1, 1), 0, 0, 4)))
    assert out.decode() == "INSERT INTO other VALUES ('x');\nCREATE TABLE t2 (\n  a text\n"
    assert stats["tables"] == 1


def test_delete_table_handles_other_statements(tmp_path):
    """索引・権限などの文は、その表のものだけ取り除く。読み解けない文・ほかの表の文は残す。"""
    text = (
        "ALTER TABLE ONLY t\n"
        "INSERT INTO t VALUES ('a');\n"
        "ALTER SEQUENCE s OWNED BY t;\n"
        "COMMENT ON COLUMN mail IS 'x';\n"
        "GRANT ALL PRIVILEGES TO someone;\n"
        "CREATE INDEX i ON other (x);\n"
        "ALTER TABLE t OWNER TO x"
    )
    out, stats = rewrite(tmp_path, text, "delete_table", sel("t", (key(2, 1), 0, 0, 1)))
    assert out.decode() == (
        "ALTER SEQUENCE s OWNED BY t;\n"
        "COMMENT ON COLUMN mail IS 'x';\n"
        "GRANT ALL PRIVILEGES TO someone;\n"
        "CREATE INDEX i ON other (x);\n"
    )
    assert stats["tables"] == 1 and stats["statements"] == 3


def test_delete_columns_drops_comments_of_the_dropped_column_only(tmp_path):
    text = (
        "CREATE TABLE public.t (\n  a text,\n  mail text\n);\n"
        "COMMENT ON COLUMN public.t.mail IS 'メール';\n"
        "COMMENT ON COLUMN public.t.a IS '番号';\n"
        f"COPY public.t (a, mail) FROM stdin;\n1\t{MAIL}\n\\.\n"
    )
    out, stats = rewrite(tmp_path, text, "delete_columns", sel("public.t", (key(8), 1, 0, 4)))
    assert out.decode() == (
        "CREATE TABLE public.t (\n  a text\n);\n"
        "COMMENT ON COLUMN public.t.a IS '番号';\n"
        "COPY public.t (a) FROM stdin;\n1\n\\.\n"
    )
    assert stats["cols"] == 1

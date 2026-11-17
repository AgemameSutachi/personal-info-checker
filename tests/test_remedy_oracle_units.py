"""Oracle のダンプの書き換え（remedy_oracle）の、部品ごとの試験。

ダンプを組み立てずに、内部形式の作り方・ダミーの作り方・型ごとの値の書き換え・位置の照合・旧 exp の見出しと
後続の文の書き換え・expdp の読み方の部品の動き（断る枝を含む）を確かめる。ファイルは作らない（すべてメモリの上）。
"""

from __future__ import annotations

import io
import struct
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pii_checker import remedy_oracle as ro  # noqa: E402
from pii_checker.formats import oracle_dump as od  # noqa: E402
from pii_checker.remedy_write import DummyMaker, RemedyError  # noqa: E402

KEYS = [bytes([i]) * 32 for i in range(1, 201)]


# ---------------------------------------------------------------- encode_number


@pytest.mark.parametrize("text", ["abc", "", "1e"])
def test_encode_number_rejects_non_number(text):
    with pytest.raises(ValueError, match="数値として読めません"):
        ro.encode_number(text)


@pytest.mark.parametrize("text", ["NaN", "Infinity", "-Infinity"])
def test_encode_number_rejects_non_finite(text):
    with pytest.raises(ValueError, match="有限の数値ではありません"):
        ro.encode_number(text)


def test_encode_number_rejects_too_many_digits():
    # 有効数字 41 桁は基数 100 で 21 組になり、Oracle の 20 組を超える
    with pytest.raises(ValueError, match="桁数が多すぎます"):
        ro.encode_number("1" * 41)


@pytest.mark.parametrize(
    "text",
    ["0", "1", "-1", "100", "-100", "12.5", "-0.001", "0.05", "123456789", "9" * 40, "-" + "9" * 40, "-1" + "2" * 39],
)
def test_encode_number_round_trips(text):
    raw = ro.encode_number(text)
    assert od.decode_number(raw) == text


@pytest.mark.parametrize(
    "text, hexed",
    [
        ("0", "80"),
        ("1", "c102"),
        ("100", "c202"),
        ("12.5", "c10d33"),
        ("0.05", "c006"),
        ("-1", "3e6466"),
        ("-100", "3d6466"),
    ],
)
def test_encode_number_known_vectors(text, hexed):
    # Oracle の DUMP() で知られている内部形式（往復だけだと、解き方と対称の誤りを見逃すため）
    assert ro.encode_number(text).hex() == hexed


def test_encode_number_negative_terminator_only_below_20_groups():
    # 負の数は、仮数が 20 組に満たないときだけ終わりの 0x66 を付ける
    assert ro.encode_number("-1")[-1] == 0x66
    assert ro.encode_number("-" + "9" * 40)[-1] != 0x66
    assert len(ro.encode_number("-" + "9" * 40)) == 21


# ---------------------------------------------------------------- numeric_dummy・date_dummy


@pytest.mark.parametrize("mode", ["shape", "fixed"])
def test_numeric_dummy_non_same_is_zero(mode):
    assert ro.numeric_dummy(DummyMaker(mode), "電話番号", "09012345678") == "0"


@pytest.mark.parametrize("text", [".", "-", "+", "-."])
def test_numeric_dummy_without_digits_is_zero(text):
    assert ro.numeric_dummy(DummyMaker("same", KEYS[0]), "電話番号", text) == "0"


@pytest.mark.parametrize("text", ["5", "12", "-37", "4.25", "0.5", "-0.07"])
def test_numeric_dummy_keeps_shape_and_differs(text):
    # どの鍵でも: 桁数と符号と小数点の位置が同じ・先頭の整数部が 0 にならない・元の値と違う
    for key in KEYS:
        out = ro.numeric_dummy(DummyMaker("same", key), "口座番号", text)
        ip, _, fp = text.lstrip("+-").partition(".")
        oip, _, ofp = out.lstrip("-").partition(".")
        assert out.startswith("-") == text.startswith("-")
        assert (len(oip), len(ofp)) == (len(ip), len(fp))
        if len(ip) > 1 or ip not in ("", "0"):
            assert oip[0] != "0"
        assert out != text


def test_numeric_dummy_same_value_same_dummy():
    a, b = DummyMaker("same", KEYS[3]), DummyMaker("same", KEYS[3])
    assert ro.numeric_dummy(a, "t", "1234") == ro.numeric_dummy(b, "t", "1234")


def test_date_dummy_fixed_shifts_day_when_equal_to_original():
    # 固定のダミー 1900-01-01 が元と同じ日付なら、日をずらす（同じままだと書き換えが飛ばされる）
    raw = bytes([119, 100, 1, 1, 13, 31, 1])
    out = ro.date_dummy(DummyMaker("fixed"), "生年月日", raw)
    assert out == bytes([119, 100, 1, 2, 13, 31, 1])


def test_date_dummy_keeps_time_part():
    raw = bytes([120, 124, 5, 17, 10, 20, 30])
    out = ro.date_dummy(DummyMaker("same", KEYS[0]), "生年月日", raw)
    assert out[4:] == raw[4:] and out[:4] != raw[:4]
    assert 1900 <= (out[0] - 100) * 100 + (out[1] - 100) <= 1999


# ---------------------------------------------------------------- 代わりのダミー


def test_star_maker_at_least_one_star():
    assert ro._StarMaker().make("t", "") == "*"
    assert ro._StarMaker().make("t", "abcd") == "****"


def test_compact_maker_short_value_is_stars():
    base = DummyMaker("same", KEYS[0])
    m = ro._CompactMaker(base, "ascii")
    assert m.make("t", "ab") == "**"
    assert not base.produced


def test_compact_maker_same_bytes_and_recorded():
    base = DummyMaker("same", KEYS[0])
    m = ro._CompactMaker(base, "utf-16-le")
    out = m.make("t", "山田太郎")
    assert len(out) == 4 and out.isascii()
    assert out in base.produced
    assert m.make("t", "山田太郎") == out


# ---------------------------------------------------------------- CellEditor


def _editor(types, codecs, maxlens, mode="same", strict=False):
    cols = [f"C{i}" for i in range(len(types))]
    return ro.CellEditor(DummyMaker(mode, KEYS[0]), cols, types, codecs, maxlens, strict)


def test_cell_editor_rejects_unsupported_type():
    ed = _editor([od.TYPE_RAW], [None], [10])
    with pytest.raises(RemedyError, match="型は、置き換えに対応していません"):
        ed.edit(0, b"\x01\x02", [(0, 1, "t")])


def test_cell_editor_text_without_codec():
    ed = _editor([od.TYPE_VARCHAR2], [None], [10])
    with pytest.raises(RemedyError, match="文字セットに対応していません"):
        ed.edit(0, b"abc", [(0, 3, "t")])


def test_cell_editor_text_undecodable():
    ed = _editor([od.TYPE_VARCHAR2], ["ascii"], [10])
    with pytest.raises(RemedyError, match="文字として読めない値"):
        ed.edit(0, b"\xff\xfe", [(0, 1, "t")])


def test_cell_editor_text_not_round_trippable():
    # cp932 の NEC 特殊文字の「≒」（87 90）は、読んで書き直すと JIS の「≒」（81 E0）になる（元へ正確に戻せない）
    raw = b"\x87\x90"
    assert raw.decode("cp932").encode("cp932") != raw
    ed = _editor([od.TYPE_VARCHAR2], ["cp932"], [10])
    with pytest.raises(RemedyError, match="正確に戻せない値"):
        ed.edit(0, raw, [(0, 1, "t")])


def test_cell_editor_text_no_spans_unchanged():
    ed = _editor([od.TYPE_VARCHAR2], ["ascii"], [10])
    assert ed.edit(0, b"abc", []) is None


def test_cell_editor_fixed_unencodable_falls_back_to_stars():
    # 固定のダミー「＊＊＊」は ascii に書けないので、同じ文字数の「*」になる
    ed = _editor([od.TYPE_VARCHAR2], ["ascii"], [10], mode="fixed")
    assert ed.edit(0, b"x 0312345678 y", [(2, 12, "電話番号")]) == b"x ********** y"


def test_cell_editor_strict_too_long_falls_back_to_stars():
    # 長くできない（expdp）: 固定のダミー（9 バイト）は 2 バイトの値に収まらない
    ed = _editor([od.TYPE_VARCHAR2], ["utf-8"], [2], mode="fixed", strict=True)
    assert ed.edit(0, b"ab", [(0, 2, "t")]) == b"**"


def test_cell_editor_char_pads_with_spaces():
    ed = _editor([od.TYPE_CHAR], ["ascii"], [8], mode="fixed")
    assert ed.edit(0, b"abcd    ", [(0, 4, "t")]) == b"****    "


def test_cell_editor_number_unreadable():
    ed = _editor([od.TYPE_NUMBER], [None], [22])
    with pytest.raises(RemedyError, match="読み解けない数値"):
        ed.edit(0, b"", [(0, 1, "t")])


def test_cell_editor_number_unchanged_returns_none():
    # 固定のダミーは 0。元が 0 なら書き換えない
    ed = _editor([od.TYPE_NUMBER], [None], [22], mode="fixed")
    assert ed.edit(0, b"\x80", [(0, 1, "t")]) is None


def test_cell_editor_number_strict_too_long_becomes_zero():
    # 100 は 2 バイト（c2 02）。3 桁のダミーは、末尾が 00 でなければ 3 バイトになって収まらないので 0 にする
    raw = ro.encode_number("100")
    assert len(raw) == 2
    for key in KEYS:
        maker = DummyMaker("same", key)
        if ro.numeric_dummy(maker, "t", "100").endswith("00"):
            continue
        ed = ro.CellEditor(maker, ["N"], [od.TYPE_NUMBER], [None], [22], strict=True)
        assert ed.edit(0, raw, [(0, 3, "t")]) == b"\x80"
        assert "0" in maker.produced
        break
    else:
        pytest.fail("末尾が 00 でないダミーを作る鍵が見つかりません")


def test_cell_editor_date_too_short():
    ed = _editor([od.TYPE_DATE], [None], [7])
    with pytest.raises(RemedyError, match="読み解けない日付"):
        ed.edit(0, b"\x78\x64\x01", [(0, 1, "t")])


def test_cell_editor_timestamp_keeps_fraction():
    raw = bytes([120, 124, 5, 17, 10, 20, 30]) + b"\x00\x01\x02\x03"
    ed = _editor([od.TYPE_TIMESTAMP], [None], [11])
    out = ed.edit(0, raw, [(0, 10, "生年月日")])
    assert out[4:] == raw[4:] and len(out) == len(raw)
    assert od.decode_date(out) in ed.maker.produced


# ---------------------------------------------------------------- 位置の照合


def _plan(rows=(), by_row=None, seen=()):
    return ro._Plan(rows=set(rows), cols=set(), by_row=by_row or {}, seen_rows=set(seen))


def test_check_found_missing_table():
    with pytest.raises(RemedyError, match="表「T」の区画が見つかりませんでした"):
        ro._check_found("delete_rows", {"T": _plan()}, set())


def test_check_found_missing_rows_delete():
    with pytest.raises(RemedyError, match="位置の行が見つかりません（2 行）"):
        ro._check_found("delete_rows", {"T": _plan(rows={1, 2, 3}, seen={1})}, {"T"})


def test_check_found_missing_rows_dummy():
    with pytest.raises(RemedyError, match="（1 行）"):
        ro._check_found("dummy", {"T": _plan(by_row={4: {}, 5: {}}, seen={4})}, {"T"})


def test_check_found_other_methods_need_only_table():
    ro._check_found("delete_columns", {"T": _plan(rows={1})}, {"T"})


# ---------------------------------------------------------------- CREATE TABLE の列の分け方


def test_split_create_columns_not_create():
    with pytest.raises(RemedyError, match="CREATE TABLE の行を読み解けない"):
        ro._split_create_columns(b'CREATE VIEW "V" AS SELECT 1\n')


def test_split_create_columns_unclosed():
    with pytest.raises(RemedyError, match="括弧が閉じていない"):
        ro._split_create_columns(b'CREATE TABLE "T" ("A" NUMBER, "B" VARCHAR2(10)\n')


def test_split_create_columns_quotes_and_nesting():
    line = b'CREATE TABLE "T" ("A,""x" NUMBER(10, 2), "B" VARCHAR2(10) DEFAULT \'a,\'\'b\')  PCTFREE 10\n'
    prefix, elements, suffix = ro._split_create_columns(line)
    assert prefix == b'CREATE TABLE "T" ('
    assert elements == [b'"A,""x" NUMBER(10, 2)', b"\"B\" VARCHAR2(10) DEFAULT 'a,''b'"]
    assert suffix == b")  PCTFREE 10\n"


# ---------------------------------------------------------------- 旧 exp: 列の削除の見出し


def _rewriter(data: bytes = b"", method: str = "delete_columns"):
    # 位置を何も選んでいない Selection（_build_plans が使う 4 つが空を返す）
    sel = SimpleNamespace(rows=dict, cols=dict, spans=dict, sheets=list)
    return ro._ExpRewriter(io.BytesIO(data), io.BytesIO(), "ascii", method, sel, None)


TBL = SimpleNamespace(columns=["A", "B"], descs=[(od.TYPE_NUMBER, 22, 0), (od.TYPE_VARCHAR2, 10, 1)])
HEAD = b'TABLE "T"\nCREATE TABLE "T" ("A" NUMBER, "B" VARCHAR2(10))\n'
DEFS = struct.pack("<HH", od.TYPE_NUMBER, 22) + struct.pack("<HHHH", od.TYPE_VARCHAR2, 10, 1, 1)
HEADER = b'INSERT INTO "T" ("A", "B") VALUES (:1, :2)\n' + struct.pack("<H", 2) + DEFS + b"\x00\x00"


def test_edit_headers_drops_column():
    head, header = _rewriter()._edit_headers(HEAD, HEADER, TBL, {1}, "T")
    assert head == b'TABLE "T"\nCREATE TABLE "T" ("A" NUMBER)\n'
    assert header == b'INSERT INTO "T" ("A") VALUES (:1)\n' + struct.pack("<H", 1) + DEFS[:4] + b"\x00\x00"


def test_edit_headers_drops_first_column():
    # 先頭の数値の列（定義 4 バイト）を落とすと、文字の列の定義（8 バイト）だけが残る
    head, header = _rewriter()._edit_headers(HEAD, HEADER, TBL, {0}, "T")
    assert head == b'TABLE "T"\nCREATE TABLE "T" ("B" VARCHAR2(10))\n'
    assert header == b'INSERT INTO "T" ("B") VALUES (:1)\n' + struct.pack("<H", 1) + DEFS[4:] + b"\x00\x00"


def test_edit_headers_element_not_column():
    head = b'TABLE "T"\nCREATE TABLE "T" ("A" NUMBER, CONSTRAINT PK PRIMARY KEY ("A"))\n'
    with pytest.raises(RemedyError, match="列の定義でない項目"):
        _rewriter()._edit_headers(head, HEADER, TBL, {1}, "T")


def test_edit_headers_create_columns_mismatch():
    head = b'TABLE "T"\nCREATE TABLE "T" ("A" NUMBER, "Z" VARCHAR2(10))\n'
    with pytest.raises(RemedyError, match="INSERT の列と合わない"):
        _rewriter()._edit_headers(head, HEADER, TBL, {1}, "T")


def test_edit_headers_column_used_by_other_definition():
    head = b'TABLE "T"\nCREATE TABLE "T" ("A" NUMBER GENERATED ALWAYS AS (LENGTH("B")), "B" VARCHAR2(10))\n'
    with pytest.raises(RemedyError, match="削除する列「B」を使っている"):
        _rewriter()._edit_headers(head, HEADER, TBL, {1}, "T")


def test_edit_headers_insert_unreadable():
    header = b'INSERT "T" VALUES\n' + HEADER.split(b"\n", 1)[1]
    with pytest.raises(RemedyError, match="INSERT 文を読み解けない"):
        _rewriter()._edit_headers(HEAD, header, TBL, {1}, "T")


def test_edit_headers_insert_column_count_mismatch():
    header = b'INSERT INTO "T" ("A") VALUES (:1, :2)\n' + HEADER.split(b"\n", 1)[1]
    with pytest.raises(RemedyError, match="INSERT 文の列を読み解けない"):
        _rewriter()._edit_headers(HEAD, header, TBL, {1}, "T")


@pytest.mark.parametrize("tail", [b"\x00", b"\x00\x00\x00\x00", b"\x01\x00"])
def test_edit_headers_defs_unreadable(tail):
    header = HEADER[:-2] + tail
    with pytest.raises(RemedyError, match="列の定義を読み解けない"):
        _rewriter()._edit_headers(HEAD, header, TBL, {1}, "T")


# ---------------------------------------------------------------- 旧 exp: 表のあとに続く文


def test_filter_units_without_statements_unchanged():
    assert _rewriter()._filter_units(b"ENDTABLE\n", "T", "T", ["B"]) == b"ENDTABLE\n"


def test_filter_units_unknown_statement_using_column():
    part = b'CREATE VIEW "V" AS SELECT "B" FROM "T"\n'
    with pytest.raises(RemedyError, match="取り除き方が分からない"):
        _rewriter()._filter_units(part, "T", "T", ["B"])


def test_filter_units_drops_index_and_its_second_pass_analyze():
    w = _rewriter()
    part = (
        b'CREATE INDEX "IX_B" ON "T" ("B" )\n'
        b'ANALSTATS TS "T"\nBEGIN NULL; END;\n'
        b'COMMENT ON COLUMN "T"."B" IS \'x\'\n'
        b'GRANT SELECT ON "T" TO "U"\n'
    )
    assert w._filter_units(part, "T", "T", ["B"]) == b'GRANT SELECT ON "T" TO "U"\n'
    assert w.stats["statements"] == 3
    # 2 周目の区画の ANALCOMPUTE は、取り除いた索引を指すものだけ外す
    second = b'ANALCOMPUTE IS "T" ANALYZE  INDEX "IX_B"  ESTIMATE STATISTICS\nANALCOMPUTE IS "T" ANALYZE  INDEX "IX_A"  ESTIMATE STATISTICS\n'
    assert w._filter_units(second, "T", "T", []) == b'ANALCOMPUTE IS "T" ANALYZE  INDEX "IX_A"  ESTIMATE STATISTICS\n'
    assert w.stats["statements"] == 4


# ---------------------------------------------------------------- 旧 exp: 読み進め方


def test_gather_to_marker_too_large(monkeypatch):
    monkeypatch.setattr(ro, "MAX_PART", 16)
    w = _rewriter(b"x" * 64 + b'\nTABLE "U"\n')
    with pytest.raises(RemedyError, match="表のあとに続く文が大きすぎて"):
        w._gather_to_marker((ro.TABLE_MARK, ro.ENDTABLE_MARK))


def test_section_table_line_without_newline_copied():
    # 改行の無い「TABLE "」の行は区画として読まず、そのまま写して先へ進む
    w = _rewriter(b'TABLE "T')
    w.st.ensure(1)
    w._section()
    assert w.out.getvalue() == b'TABLE "'
    assert w.st.pos == len(b'TABLE "')


# 列 A（数値）と B（文字）の行。00 00 のあとに列ごとの長さ（2 バイト）と値が続く
ROW1 = b"\x00\x00" + b"\x02\x00\xc1\x02" + b"\x01\x00x"
ROW2 = b"\x00\x00" + b"\x02\x00\xc1\x03" + b"\x01\x00y"
ROWS_END = b"\x00\x00\xff\xff"  # 表の終わりの印（次の文の改行が続く）


def _run_rows(data: bytes, row_cb=lambda n, raws: ro._KEEP):
    w = _rewriter(data)
    out = io.BytesIO()
    w._rows(TBL, row_cb, out.write, "T")
    return w, out.getvalue()


def test_rows_keeps_and_drops_rows_and_stops_at_end():
    # 取り除いた行の前後は元のバイト列のまま写し、終わりの印のあとは読まない
    w, out = _run_rows(ROW1 + ROW2 + ROWS_END + b"\nENDTABLE\n", lambda n, raws: None if n == 1 else ro._KEEP)
    assert out == ROW2 + ROWS_END
    assert w.st.pos == len(ROW1 + ROW2 + ROWS_END)


def test_rows_end_mark_at_end_of_file():
    # 終わりの印でファイルが終わるときは、読み足せないと分かってから終わりと見なす
    _, out = _run_rows(ROW1 + ROWS_END)
    assert out == ROW1 + ROWS_END


def test_rows_refuses_a_row_cut_by_the_end_of_the_dump():
    # 値の長さ 5 に対して 1 バイトしか無い。切れた行の手前までは写してから断る
    out = io.BytesIO()
    w = _rewriter(ROW1 + b"\x00\x00\x05\x00a")
    with pytest.raises(RemedyError, match="表「T」の行の途中でダンプが切れている"):
        w._rows(TBL, lambda n, raws: ro._KEEP, out.write, "T")
    assert out.getvalue() == ROW1


def test_rows_refuses_a_row_without_the_start_mark():
    with pytest.raises(RemedyError, match=r"表「T」の行を読み解けない.*00 00"):
        _run_rows(ROW1 + b"\x01\x00\x02\x00\xc1\x02")


def test_rows_refuses_a_value_longer_than_its_column():
    # B は VARCHAR2(10) なので、長さ 11 の値は定義と合わない
    with pytest.raises(RemedyError, match="列「B」の長さ 11"):
        _run_rows(b"\x00\x00\x02\x00\xc1\x02\x0b\x00" + b"z" * 11 + ROWS_END + b"\n")


def test_rows_refuses_a_too_large_row(monkeypatch):
    # 読み足しても1行が終わらず、手元の未処理の部分が上限を超えたら断る
    monkeypatch.setattr(od, "MAX_ROW", 8)
    with pytest.raises(RemedyError, match="1行が大きすぎる"):
        _run_rows(b"\x00\x00\x02\x00\xc1\x02\x0a\x00" + b"z" * 5)


def test_dummy_row_skips_null_and_missing_columns():
    # 位置が NULL の値や、行に無い列を指していても、その列は飛ばす（行は元のまま・照合のために見た行として数える）
    sel = SimpleNamespace(rows=dict, cols=dict, spans=dict, sheets=list)
    w = ro._ExpRewriter(io.BytesIO(), io.BytesIO(), "ascii", "dummy", sel, DummyMaker("fixed", KEYS[0]))
    plan = SimpleNamespace(by_row={1: {1: [(0, 1, "t")], 5: [(0, 1, "t")]}}, seen_rows=set())
    cb = w._row_callback(plan, TBL, set())
    assert cb(1, [b"\xc1\x02", None]) is ro._KEEP
    assert cb(2, [b"\xc1\x03", b"y"]) is ro._KEEP  # 位置の無い行はそのまま（見た行にも数えない）
    assert plan.seen_rows == {1}
    assert w.stats["cells"] == 0 and w.stats["detections"] == 0


def test_rewrite_exp_dump_refuses_a_file_without_export_head(tmp_path):
    src = tmp_path / "x.dmp"
    src.write_bytes(b"\x00" * 64)
    with pytest.raises(RemedyError, match="旧 exp のダンプとして読めない"):
        ro.rewrite_exp_dump(str(src), str(tmp_path / "out.dmp"), "dummy", None, None)
    assert not (tmp_path / "out.dmp").exists()


def test_run_dummy_without_cells_rejected():
    # 選んだ表が無い（plans が空）ので位置の照合は素通りし、書き換えた値が 0 件の断りに届く
    w = _rewriter(b"EXPORT:V21.00.00\nENDEXPORT\n", method="dummy")
    with pytest.raises(RemedyError, match="書き換える値が見つかりませんでした"):
        w.run()
    assert w.out.getvalue() == b"EXPORT:V21.00.00\nENDEXPORT\n"


# ---------------------------------------------------------------- expdp: 読み方の部品


def test_find_marker_across_chunks(monkeypatch):
    # 読む塊の境目をまたぐ印も見つける（塊の終わりの印の長さ -1 バイトを次の塊に持ち越す）
    monkeypatch.setattr(ro, "CHUNK", 8)
    data = b"0123456" + b"MARK" + b"xyz"
    f = io.BytesIO(data)
    assert ro._find_marker(f, b"MARK", 0, len(data)) == 7
    assert ro._find_marker(f, b"MARK", 8, len(data)) == -1


def test_find_marker_size_beyond_file():
    # 大きさが実際より大きくても、読めなくなったところで止まる
    assert ro._find_marker(io.BytesIO(b"abc"), b"MARK", 0, 100) == -1
    assert ro._find_marker(io.BytesIO(b"abc"), b"MARK", 3, 100) == -1


def _ctrl(fs) -> bytes:
    return (ro.CTRL_MAGIC + b"\x00\x00" + b"".join(struct.pack(">Q", v) for v in fs)).ljust(ro.BLOCK, b"\x00")


def _good_fields(xml_len: int, rows_len: int, index_len: int = 8):
    f1 = 2 + xml_len
    return [
        f1,
        ro.BLOCK,
        rows_len,
        ro._align8(f1) + ro.BLOCK,
        index_len,
        ro._align8(f1) + ro._align8(rows_len) + ro.BLOCK,
    ]


def test_ctrl_fields_rejects_bad_magic_and_short():
    assert ro._ctrl_fields(b"\x00" * 64) is None
    assert ro._ctrl_fields(ro.CTRL_MAGIC + b"\x00" * 10) is None
    assert ro._ctrl_fields(_ctrl([1, 2, 3, 4, 5, 6])) == [1, 2, 3, 4, 5, 6]


def test_structure_ok_accepts_expected_layout():
    # XML 100 バイト・行 41 バイト: F1=2+100=102、F4=8 に揃えた 104+4096、F6=104+行を揃えた 48+4096
    fs = [102, 4096, 41, 4200, 8, 4248]
    assert _good_fields(100, 41) == fs
    data = _ctrl(fs) + b"\x00" * (ro.BLOCK * 2)
    assert ro._structure_ok(io.BytesIO(data), len(data), ro.BLOCK, 100) == fs


@pytest.mark.parametrize(
    "seg_start, fix",
    [
        (ro.BLOCK + 8, None),  # 区画の始まりがブロックの境目でない
        (0, None),  # 前に制御ブロックが無い
        (ro.BLOCK * 3, None),  # 区画がファイルの外
        (ro.BLOCK, lambda fs: fs.__setitem__(0, fs[0] + 1)),  # 見出しの長さが XML と合わない
        (ro.BLOCK, lambda fs: fs.__setitem__(1, 8192)),  # ブロックの大きさが違う
        (ro.BLOCK, lambda fs: fs.__setitem__(3, fs[3] + 8)),  # 行の始まりが違う
        (ro.BLOCK, lambda fs: fs.__setitem__(5, fs[5] + 8)),  # 索引の始まりが違う
        (ro.BLOCK, lambda fs: fs.__setitem__(4, 12)),  # 索引の大きさが 8 の倍数でない
        (ro.BLOCK, lambda fs: fs.__setitem__(4, ro.BLOCK * 8)),  # 索引がファイルの外へはみ出す
    ],
)
def test_structure_ok_rejects(seg_start, fix):
    fs = _good_fields(100, 41)
    if fix is not None:
        fix(fs)
    data = _ctrl(fs) + b"\x00" * (ro.BLOCK * 2)
    assert ro._structure_ok(io.BytesIO(data), len(data), seg_start, 100) is None


def test_structure_ok_rejects_missing_ctrl_magic():
    data = b"\x00" * (ro.BLOCK * 3)
    assert ro._structure_ok(io.BytesIO(data), len(data), ro.BLOCK, 100) is None


def test_read_xml_found_and_eof():
    f = io.BytesIO(b"junk<?xml?><ROWSET><ROW/></ROWSET>tail")
    assert ro._read_xml(f, 4) == b"<?xml?><ROWSET><ROW/></ROWSET>"
    assert ro._read_xml(io.BytesIO(b"<?xml?><ROWSET><ROW>"), 0) is None


def test_read_xml_too_large(monkeypatch):
    monkeypatch.setattr(od, "MAX_HEADER", 10)
    f = io.BytesIO(b"<?xml?><ROWSET>" + b"x" * 70000 + b"</ROWSET>")
    assert ro._read_xml(f, 0) is None


def test_find_dp_segments_skips_unreadable_xml():
    # 印のあとに </ROWSET> が無い・列の定義として読めない XML は、区画として数えない
    data = od.EXPDP_MARKER + b"<NOTHING/></ROW></ROWSET>" + b"\x00" * 16 + od.EXPDP_MARKER + b"no end"
    assert ro.find_dp_segments(io.BytesIO(data), len(data)) == []


def test_hop_rows_end_stops_at_bad_row():
    tbl = SimpleNamespace(columns=["A"])
    rows = b"\x3c\x00\x06\x01\x01A" + b"\x3c\x00\x06\x01\x01B"
    data = b"\x00" * 5 + rows + b"\x3c\x00\x02\x01"  # 長さ 2 の行は読めない（検査も同じ所で止まる）
    assert ro._hop_rows_end(io.BytesIO(data), 0, tbl) == 5 + len(rows)


def test_hop_rows_end_stops_at_truncated_row_and_end_mark():
    tbl = SimpleNamespace(columns=["A"])
    row = b"\x3c\x00\x06\x01\x01A"
    assert ro._hop_rows_end(io.BytesIO(row + b"\x3c\x00\x09\x01\x04AB"), 0, tbl) == len(row)
    assert ro._hop_rows_end(io.BytesIO(row + b"\x01rest"), 0, tbl) == len(row)
    assert ro._hop_rows_end(io.BytesIO(b"\x00" * 32), 0, tbl) == 32


def test_dp_cells_and_row_bytes_round_trip():
    long_value = b"v" * 300
    row = ro._dp_row_bytes(4, [(b"ab", False), (None, False), (long_value, False), (b"c", True)])
    assert row[0] == 0x3C and struct.unpack(">H", row[1:3])[0] == len(row)
    nc, cells = ro._dp_cells(row)
    assert nc == 4
    assert cells == [(b"ab", False), (None, False), (long_value, True), (b"c", True)]
    assert ro._dp_row_bytes(nc, cells) == row


def test_dp_row_bytes_too_long():
    with pytest.raises(RemedyError, match="置き換えた行が長すぎる"):
        ro._dp_row_bytes(2, [(b"x" * 40000, True), (b"y" * 40000, True)])


def test_index_builder():
    b = ro._IndexBuilder()
    for off in (0, 100, ro.GRANULE - 1, ro.GRANULE, ro.GRANULE + 5, 2 * ro.GRANULE + 1):
        b.row_start(off)
    assert b.finish(6, False) == [0, ro.GRANULE, 2 * ro.GRANULE + 1]
    assert ro._IndexBuilder().finish(0, False) == []
    assert ro._IndexBuilder().finish(0, True) == [0]

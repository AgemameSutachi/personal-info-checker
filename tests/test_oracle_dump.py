"""Oracle の exp / expdp ダンプを、表の列名つきで読む作りの試験。

形式は実物（Oracle 21c・AL32UTF8）の解析で分かったもの。ここでは同じ形のバイト列を組み立てて確かめる
（架空のデータ。実物の先頭を切り出した試験は tests/data/ の oracle_*.bin）。
"""

from __future__ import annotations

import io
import pathlib
import struct

import pytest

from pii_checker import engine
from pii_checker.formats import dbdump, oracle_dump
from pii_checker.models import ScanOptions, Status

DATA = pathlib.Path(__file__).parent / "data"

PEOPLE = [
    ("山田太郎", "12373284535", (1980, 1, 2), "090-1234-5678"),
    ("佐藤花子", "12431251615", (1975, 3, 4), "090-2222-3333"),
    ("鈴木一郎", "12489218695", (1990, 5, 6), "080-4444-5555"),
]


# ------------------------------------------------------------------ 値の作り方（解き方の逆）


def enc_number(v: int) -> bytes:
    """整数を Oracle NUMBER の内部形式にする（正の整数と 0・負の整数）。"""
    if v == 0:
        return b"\x80"
    neg = v < 0
    s = str(abs(v))
    if len(s) % 2:
        s = "0" + s
    digs = [int(s[i : i + 2]) for i in range(0, len(s), 2)]
    while digs and digs[-1] == 0:
        digs.pop()
    exp = (len(s) // 2) - 1
    if not neg:
        return bytes([0xC1 + exp] + [d + 1 for d in digs])
    body = [101 - d for d in digs]
    return bytes([0x3E - exp] + body + ([0x66] if len(body) < 20 else []))


def enc_date(y: int, m: int, d: int, hh: int = 0, mm: int = 0, ss: int = 0) -> bytes:
    return bytes([y // 100 + 100, y % 100 + 100, m, d, hh + 1, mm + 1, ss + 1])


# ------------------------------------------------------------------ 旧 exp の組み立て

EXP_HEAD = b"\x03\x03iEXPORT:V21.00.00\nUPIICHK\nRUSERS\n8192\n0\n72\n0\n" + b"\x00" * 64


def exp_table(name: str, cols: list[tuple[str, int, int]], rows: list[list], end: bool = True) -> bytes:
    """cols は (列名, 型, 長さ)。rows の値は bytes（そのまま）か None（NULL）。"""
    names = ", ".join(f'"{c[0]}"' for c in cols)
    binds = ", ".join(f":{i + 1}" for i in range(len(cols)))
    out = f'\nTABLE "{name}"\nCREATE TABLE "{name}" (...)  PCTFREE 10\n'.encode()
    out += f'INSERT INTO "{name}" ({names}) VALUES ({binds})\n'.encode()
    out += struct.pack("<H", len(cols))
    for _, t, ln in cols:
        out += struct.pack("<HH", t, ln)
        if t in (1, 96):
            out += struct.pack("<HH", 873, 1)
    out += b"\x00\x00"
    for row in rows:
        out += b"\x00\x00"
        for v in row:
            out += b"\xff\xff" if v is None else struct.pack("<H", len(v)) + v
    if end:
        out += b"\x00\x00\xff\xff"
    return out + b'\nANALSTATS TS "' + name.encode() + b'"\n'


def customer_cols():
    return [("ID", 2, 22), ("氏名", 1, 40), ("住民票コード", 1, 44), ("生年月日", 12, 7), ("電話番号", 1, 25)]


def customer_rows(n_extra: int = 0):
    rows = []
    for i, (name, code, (y, m, d), phone) in enumerate(PEOPLE + [PEOPLE[0]] * n_extra, start=1):
        rows.append(
            [enc_number(i), name.encode(), code.encode(), enc_date(y, m, d), phone.encode()],
        )
    return rows


def build_exp(**kw) -> bytes:
    return EXP_HEAD + exp_table("顧客", customer_cols(), customer_rows(**kw))


# ------------------------------------------------------------------ expdp の組み立て


def dp_xml(name: str, cols: list[tuple[str, int, int, int]]) -> bytes:
    items = "".join(
        f"<COL_LIST_ITEM><OBJ_NUM>1</OBJ_NUM><NAME>{c}</NAME><TYPE_NUM>{t}</TYPE_NUM><LENGTH>{ln}</LENGTH>"
        f"<CHARSETID>{cs}</CHARSETID><CHARSETFORM>{1 if cs else 0}</CHARSETFORM></COL_LIST_ITEM>"
        for c, t, ln, cs in cols
    )
    xml = (
        '<?xml version="1.0"?><ROWSET><ROW>\n  <STRMTABLE_T><VERS_MAJOR>1</VERS_MAJOR><CHARSET>AL32UTF8</CHARSET>'
        f"<OBJ_NUM>1</OBJ_NUM><OWNER_NAME>PIICHK</OWNER_NAME><NAME>{name}</NAME><COL_LIST>{items}</COL_LIST>"
        "</STRMTABLE_T></ROW></ROWSET>"
    )
    return b"\x03i" + xml.encode()


def dp_row(vals: list) -> bytes:
    body = bytes([len(vals)])
    for v in vals:
        if v is None:
            body += b"\xff"
        elif len(v) >= 0xFA:
            body += b"\xfe" + struct.pack(">H", len(v)) + v
        else:
            body += bytes([len(v)]) + v
    return b"\x3c" + struct.pack(">H", len(body) + 3) + body


DP_HEAD = b"\x05\x01M\x11" + b"\x00" * 60 + b"AL32UTF8" + b"\x00" * 64


def dp_table(name: str, cols, rows, pad_before_rows: int = 2) -> bytes:
    data = dp_xml(name, cols) + b"\x00" * pad_before_rows + b"".join(dp_row(r) for r in rows)
    data += b"\x00" * 100 + b"\x00\x00\x00\x00\x9c\x40\x0f\x00" * 8 + b"\xff\xff$$\n"
    return data + b"\x00" * (-len(data) % 4096)


def dp_customer_cols():
    return [
        ("ID", 2, 22, 0),
        ("氏名", 1, 160, 873),
        ("住民票コード", 1, 44, 873),
        ("生年月日", 12, 7, 0),
        ("電話番号", 1, 25, 873),
    ]


def build_dp(**kw) -> bytes:
    return DP_HEAD + b"\x00" * (4096 - len(DP_HEAD)) + dp_table("顧客", dp_customer_cols(), customer_rows(**kw))


# ------------------------------------------------------------------ 道具


def _scan(tmp_path, name: str, data: bytes):
    p = tmp_path / name
    p.write_bytes(data)
    return engine.scan_file(str(p), ScanOptions(temp_dir=str(tmp_path)))


def _types(res) -> dict:
    return dict(res.items[0].finding_counts)


def _locs(res) -> list[str]:
    return [f.location for f in res.items[0].findings]


class _Col:
    """Collector の代わり（読んだ列名・行・文字列の走査に回った文字列を覚える）。"""

    def __init__(self):
        self.tables = []
        self.texts = []

    def add_records(self, columns, rows, location_fn, method=""):
        self.tables.append((list(columns), [list(r) for r in rows]))
        return len(self.tables[-1][1])

    def add_text(self, text, location, **kw):
        self.texts.append(text)


def _run(data: bytes, kind: str):
    col = _Col()
    res = oracle_dump.scan_oracle_tables(io.BytesIO(data), col, kind, data[:64])
    return res, col


# ------------------------------------------------------------------ 値の解き方


@pytest.mark.parametrize(
    "v",
    [0, 1, 9, 10, 40, 99, 100, 120, 1464497, 123456789012345, 99999999999, -1, -120, -1464497],
)
def test_number_roundtrip(v):
    assert oracle_dump.decode_number(enc_number(v)) == str(v)


def test_number_known_vectors_from_real_dump():
    """実物の住基の連番・世帯番号（c2 23 57 → 3486・c3 0b 0c 3f → 101162）と小数・負の小数。"""
    assert oracle_dump.decode_number(bytes.fromhex("c22357")) == "3486"
    assert oracle_dump.decode_number(bytes.fromhex("c30b0c3f")) == "101162"
    assert oracle_dump.decode_number(bytes.fromhex("c10233")) == "1.5"  # 1.5
    assert oracle_dump.decode_number(bytes.fromhex("c006")) == "0.05"
    assert oracle_dump.decode_number(bytes.fromhex("c1240d2d")) == "35.1244"  # 35.1244
    assert oracle_dump.decode_number(bytes.fromhex("3e6466")) == "-1"
    assert oracle_dump.decode_number(bytes.fromhex("3e643366")) == "-1.5"
    assert oracle_dump.decode_number(b"\x80") == "0"
    assert oracle_dump.decode_number(b"\xff\x65") is None  # 無限大は読まない
    assert oracle_dump.decode_number(b"") is None


def test_date_decode():
    assert oracle_dump.decode_date(bytes.fromhex("77840909010101")) == "1932-09-09"  # 実物の住基の生年月日
    assert oracle_dump.decode_date(enc_date(2026, 10, 19, 12, 34, 56)) == "2026-10-19 12:34:56"
    assert (
        oracle_dump.decode_date(enc_date(2026, 10, 19) + b"\x00\x00\x00\x00") == "2026-10-19"
    )  # TIMESTAMP の小数部は捨てる
    assert oracle_dump.decode_date(bytes.fromhex("77840d09010101")) is None  # 13月
    assert oracle_dump.decode_date(b"\x77\x84") is None


# ------------------------------------------------------------------ 旧 exp


def test_exp_columns_named_and_values_decoded():
    res, col = _run(build_exp(), "exp")
    assert res.tables == 1 and res.rows == 3 and not res.failed and not res.truncated
    columns, rows = col.tables[0]
    assert columns == ["ID", "氏名", "住民票コード", "生年月日", "電話番号"]
    assert rows[0] == ["1", "山田太郎", "12373284535", "1980-01-02", "090-1234-5678"]
    assert rows[2][0] == "3" and rows[2][3] == "1990-05-06"


def test_exp_end_to_end_finds_name_code_birth_phone(tmp_path):
    res = _scan(tmp_path, "exp.dmp", build_exp(n_extra=2))
    it = res.items[0]
    assert it.status == Status.SCANNED, (it.status, it.method)
    assert "表ごとに読み取り" in it.method
    counts = _types(res)
    for t in ("name", "resident_code", "birthdate", "phone"):
        assert counts.get(t, 0) >= 5, (t, counts)
    locs = _locs(res)
    assert "表「顧客」1行目 列「氏名」" in locs
    assert any("列「住民票コード」" in s for s in locs) and any("列「生年月日」" in s for s in locs)


def test_exp_null_first_column_is_not_end():
    cols = customer_cols()
    rows = [[None, "山田太郎".encode(), b"12373284535", enc_date(1980, 1, 2), b"090-1234-5678"], customer_rows()[1]]
    res, col = _run(EXP_HEAD + exp_table("顧客", cols, rows), "exp")
    assert res.rows == 2 and not res.failed
    assert col.tables[0][1][0][0] is None and col.tables[0][1][1][1] == "佐藤花子"


def test_exp_two_tables_and_empty_table():
    data = EXP_HEAD + exp_table("顧客", customer_cols(), customer_rows()) + exp_table("空", [("A", 1, 10)], [])
    data += exp_table("会員", [("氏名", 1, 40)], [["田中三郎".encode()]])
    res, col = _run(data, "exp")
    assert res.tables == 3 and res.rows == 4
    assert [t[0] for t in col.tables] == [customer_cols_names() for _ in range(1)] + [["A"], ["氏名"]]


def customer_cols_names():
    return [c[0] for c in customer_cols()]


def test_exp_truncated_dump_does_not_crash(tmp_path):
    data = build_exp(n_extra=50)
    for cut in (len(data) - 3, len(data) // 2 + 7, len(EXP_HEAD) + 400, 100, 5):
        res, col = _run(data[:cut], "exp")  # 落ちない
        assert res.total_bytes == cut
    res, col = _run(data[: len(data) // 2 + 7], "exp")
    assert res.truncated and res.rows > 0
    out = _scan(tmp_path, "cut.dmp", data[: len(data) // 2 + 7])
    it = out.items[0]
    assert it.status == Status.PARTIAL and "途中で切れている" in (it.reason or it.method + " ".join(it.notes))
    assert _types(out).get("name", 0) >= 3  # 読めた行は列名つきで拾えている


def test_exp_unsupported_type_falls_back_to_string_sweep():
    """列の並びを読めない型（LONG=8）の表は、表の外側と同じく文字列の走査に回す（拾えなくならない）。"""
    cols = [("氏名", 1, 40), ("メモ", 8, 100)]
    head = f'\nINSERT INTO "手紙" ("氏名", "メモ") VALUES (:1, :2)\n'.encode()
    data = (
        EXP_HEAD
        + head
        + struct.pack("<HHHHHHHH", 2, 1, 40, 873, 1, 8, 100, 0)
        + b"\x00\x00\x00\x00"
        + "連絡先 090-1234-5678 まで".encode()
        + b"\x00\x00\xff\xff\n"
    )
    res, col = _run(data, "exp")
    assert res.tables == 0 and res.failed
    assert any("090-1234-5678" in s for s in col.texts)


def test_exp_bad_row_marker_keeps_earlier_rows_and_sweeps_rest():
    data = bytearray(build_exp(n_extra=3))
    idx = data.find("鈴木一郎".encode())
    data[idx - 7] = 0x55  # 3行目の先頭の 00 00 を壊す
    res, col = _run(bytes(data), "exp")
    assert res.failed and res.rows == 2
    assert any("鈴木一郎" in s or "080-4444-5555" in s for s in col.texts)


# ------------------------------------------------------------------ expdp


def test_dp_columns_named_and_values_decoded():
    res, col = _run(build_dp(), "expdp")
    assert res.tables == 1 and res.rows == 3 and not res.failed
    columns, rows = col.tables[0]
    assert columns == customer_cols_names()
    assert rows[1] == ["2", "佐藤花子", "12431251615", "1975-03-04", "090-2222-3333"]


def test_dp_end_to_end(tmp_path):
    res = _scan(tmp_path, "dp.dmp", build_dp(n_extra=2))
    it = res.items[0]
    assert it.status == Status.SCANNED, (it.status, it.method)
    counts = _types(res)
    for t in ("name", "resident_code", "birthdate", "phone"):
        assert counts.get(t, 0) >= 5, (t, counts)
    assert "表「顧客」1行目 列「氏名」" in _locs(res)


def test_dp_long_value_and_null_columns():
    long_text = ("備考" * 300).encode()  # 600 バイト（0xFE の長さ）
    cols = dp_customer_cols() + [("備考", 1, 1120, 873)]
    rows = [r + [long_text] for r in customer_rows()]
    rows[1][4] = None  # NULL
    rows[2] = rows[2][:4]  # 末尾の列が省かれた行
    data = DP_HEAD + b"\x00" * 4000 + dp_table("顧客", cols, rows)
    res, col = _run(data, "expdp")
    assert res.tables == 1 and not res.failed
    r = col.tables[0][1]
    assert r[0][5] == "備考" * 300 and r[1][4] is None and r[2][4] is None and r[2][5] is None


def test_dp_two_tables_back_to_back():
    data = DP_HEAD + b"\x00" * 4000 + dp_table("顧客", dp_customer_cols(), customer_rows())
    data += dp_table("会員", [("氏名", 1, 160, 873)], [["田中三郎".encode()], ["伊藤四郎".encode()]])
    res, col = _run(data, "expdp")
    assert res.tables == 2 and res.rows == 5
    assert col.tables[1][1] == [["田中三郎"], ["伊藤四郎"]]


def test_dp_truncated_dump_does_not_crash():
    data = build_dp(n_extra=40)
    start = data.find(b"</ROWSET>") + 11
    for cut in (len(data) - 3000, start + 300, start + 3, len(DP_HEAD) + 30, 7):
        res, col = _run(data[:cut], "expdp")
        assert res.total_bytes == cut
    res, col = _run(data[: start + 300], "expdp")
    assert res.truncated or res.failed


def test_dp_unknown_lob_column_is_swept_as_strings():
    cols = [("氏名", 1, 160, 873), ("手紙", 112, 4000, 873)]
    rows = [["山田太郎".encode(), b"\x00\x01" + "電話は 090-1234-5678 です".encode()]]
    data = DP_HEAD + b"\x00" * 4000 + dp_table("手紙表", cols, rows)
    res, col = _run(data, "expdp")
    assert res.tables == 1 and res.unsupported_cols
    sweeper_texts = col.texts
    # 走査は最後にまとめて行われるが、終了時に必ず流し切る
    assert any("090-1234-5678" in s for s in sweeper_texts)


def test_dp_bad_row_length_aborts_table_but_keeps_earlier_rows():
    data = bytearray(build_dp(n_extra=3))
    idx = data.find("鈴木一郎".encode())
    # 3行目の行の長さ（3c の直後2バイト）を壊す
    row_start = data.rfind(b"\x3c", 0, idx)
    data[row_start + 1] = 0x00
    data[row_start + 2] = 0x05
    res, col = _run(bytes(data), "expdp")
    assert res.failed and res.rows == 2
    assert any("鈴木一郎" in s for s in col.texts)


# ------------------------------------------------------------------ 状態の決め方・従来との互換


def test_unparsed_dump_keeps_old_partial_behavior(tmp_path):
    """表の並びを見つけられないダンプは、これまでと同じ簡易検査（文字列の走査）のまま。"""
    data = (
        b"\x03\x03iEXPORT:V21.00.00\n" + "連絡先 090-1234-5678 住所 東京都千代田区千代田1番1号".encode() + b"\x00" * 100
    )
    res = _scan(tmp_path, "plain.dmp", data)
    it = res.items[0]
    assert it.status == Status.PARTIAL
    assert _types(res).get("phone", 0) >= 1


def test_random_binary_dmp_is_not_broken(tmp_path):
    import random

    rnd = random.Random(1)
    data = b"AL32UTF8" + bytes(rnd.randrange(256) for _ in range(300000))
    res = _scan(tmp_path, "rand.dmp", data)
    assert res.items[0].status in (Status.PARTIAL, Status.UNCHECKABLE)


def test_gap_threshold_makes_partial(monkeypatch, tmp_path):
    """表の外側に読み解けていないデータが多いときは、全部読めたとは言わない。"""
    monkeypatch.setattr(oracle_dump, "GAP_NONZERO_LIMIT", 100)
    data = build_exp() + b"A" * 50 + "連絡先 090-9999-8888 です".encode() * 20
    res = _scan(tmp_path, "gap.dmp", data)
    assert res.items[0].status == Status.PARTIAL


def test_small_chunk_boundaries(monkeypatch):
    """読み込みの塊を極端に小さくしても、塊の境目で行・印を取りこぼさない。"""
    monkeypatch.setattr(oracle_dump, "CHUNK", 37)
    for kind, data in (("exp", build_exp(n_extra=20)), ("expdp", build_dp(n_extra=20))):
        res, col = _run(data, kind)
        assert res.tables == 1 and res.rows == 23 and not res.failed, kind
        assert col.tables[0][1][22][1] == "山田太郎"


def test_memory_stays_small_for_many_rows(tmp_path):
    """行を溜めずに流す（行数に比例してメモリが増えない）。"""
    import tracemalloc

    data = build_exp(n_extra=6000)

    class Sink(_Col):
        def add_records(self, columns, rows, location_fn, method=""):
            n = 0
            for _ in rows:
                n += 1
            return n

    tracemalloc.start()
    res = oracle_dump.scan_oracle_tables(io.BytesIO(data), Sink(), "exp", data[:64])
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert res.rows == 6003
    assert peak < len(data) * 2 + 20_000_000  # 全体のコピー数個分より小さい（ここでは BytesIO 自体を除いても数 MB）


# ------------------------------------------------------------------ 実物の先頭の切り出し（架空のデータ・住基の先頭 150 行）


REAL_FIRST_ROW = [
    "3486",
    "12373284535",
    "高橋結衣",
    "タカハシ ユイ",
    "1932-09-09",
    "女",
    "架空県架空市緑区本町4丁目28番7号",
    "101162",
    "世帯主",
    "1996-09-02",
]


@pytest.mark.parametrize("fname,kind", [("oracle_exp_sample.bin", "exp"), ("oracle_expdp_sample.bin", "expdp")])
def test_real_excerpt_decodes_like_the_database(fname, kind):
    data = (DATA / fname).read_bytes()
    res, col = _run(data, kind)
    assert res.tables == 1 and res.rows == 150 and not res.failed and not res.truncated and not res.unsupported_cols
    columns, rows = col.tables[0]
    assert columns[:10] == [
        "連番",
        "住民票コード",
        "氏名",
        "フリガナ",
        "生年月日",
        "性別",
        "住所",
        "世帯番号",
        "続柄",
        "転入日",
    ]
    assert rows[0][:10] == REAL_FIRST_ROW
    # 住民票コードは build.py の式（LPAD(MOD(連番*7919+12345678901,99999999999),11,0)）で答え合わせ
    for r in rows:
        assert r[1] == f"{(int(r[0]) * 7919 + 12345678901) % 99999999999:011d}"


@pytest.mark.parametrize("fname", ["oracle_exp_sample.bin", "oracle_expdp_sample.bin"])
def test_real_excerpt_end_to_end(tmp_path, fname):
    res = _scan(tmp_path, "real.dmp", (DATA / fname).read_bytes())
    it = res.items[0]
    assert it.status == Status.SCANNED, (it.status, it.method)
    counts = _types(res)
    for t in ("name", "resident_code", "birthdate"):
        assert counts.get(t, 0) >= 150, (t, counts)
    assert "表「住基」1行目 列「氏名」" in _locs(res)

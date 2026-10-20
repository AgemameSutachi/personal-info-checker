"""Oracle のダンプ（旧 exp・expdp）への対処（T2-d）の試験。

守ること: T2-a〜c と同じ（検査は何も書き込まない・書き換えは一時の名前の新ファイルから確定・失敗で元を壊さない・記録とジョブの DB に生の値を入れない）に加えて、
- 旧 exp: 行の削除・列の削除・ダミー化・表の削除。書き換えたダンプを検査（oracle_dump）で読み直して、消した行・列・表が無く、ダミーの値になり、
  ほかの行・列・表の値が元のまま（全行を比べる）・触らない区画のバイト列が元のまま・検査し直して検出が消える
- expdp: 行の削除・ダミー化だけ（列・表の削除は、圧縮された DDL を書き換えられないので断る）。ファイルの大きさを変えず、制御ブロックの
  行の合計・索引の大きさ・索引の始まりと索引（行の境界）が、独立に作った期待と一致する。管理用の表・作りの違う区画は書き換えない
- 検体は、旧 exp・expdp とも実物（Oracle 21c）の作りどおりに、この試験の中で組み立てる（実物の先頭を切り出した tests/data の検体も使う）
検体はすべて pytest の tmp_path に作る。本物のごみ箱へは送らない（送る関数を差し替える）。tests/data の検体は読むだけ。
"""

from __future__ import annotations

import glob
import io
import random
import re
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from pii_checker import remediate, remedy_oracle  # noqa: E402
from pii_checker.formats import oracle_dump as od  # noqa: E402
from pii_checker.models import ScanOptions  # noqa: E402
from pii_checker.remedy_write import DummyMaker, RemedyError, break_digit_runs, select_positions  # noqa: E402
from test_oracle_dump import EXP_HEAD, enc_date, enc_number  # noqa: E402
from test_remediate import (  # noqa: E402
    ALL_RANKS,
    FakeTrash,
    _leak,
    analyze,
    make_service,
    new_tmp_files,
    run,
    scan_counts,
)

DATA = Path(__file__).parent / "data"
RANKS = [3, 2, 1]


@pytest.fixture(autouse=True)
def trash(tmp_path, monkeypatch):
    """どの試験でも、ごみ箱へ送る関数を差し替える（本物のごみ箱へ送らない）。ごみ箱のある場所として扱う。"""
    t = FakeTrash(tmp_path / "_trash")
    monkeypatch.setattr(remediate, "send_to_recycle_bin", t)
    monkeypatch.setattr(remediate, "has_recycle_bin", lambda path: True)
    return t


# ---------------------------------------------------------------- 検体の部品（読み取り側の関数は使わず、形式の記述どおりに組み立てる）

SQL_TYPES = {1: "VARCHAR2", 2: "NUMBER", 12: "DATE", 96: "CHAR"}
STATS_PHONE_HEX = "".join(f"{b:02X}" for b in "090-1000-5000".encode())


def q(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def sql_type(t: int, ln: int) -> str:
    if t == 2:
        return "NUMBER"
    if t == 12:
        return "DATE"
    return f"{SQL_TYPES[t]}({ln})"


def exp_units(name: str, col_values: dict[str, bytes]) -> bytes:
    """表のあとに続く統計（ANALSTATS）。列の最小・最大値の 16 進に、元の値が入る（実物と同じ）。"""
    out = f"ANALSTATS TS {q(name)}\n".encode()
    stmt = f"BEGIN  DBMS_STATS.SET_TABLE_STATS(NULL,'{q(name)}',NULL,NULL,NULL,60,12358,284,6); END;\n".encode()
    out += struct.pack("<H", len(stmt)) + stmt
    for col, v in col_values.items():
        out += f"ANALSTATS TS {q(name)}\n".encode()
        text = (
            f"DECLARE  SREC DBMS_STATS.STATREC; BEGIN SREC.MINVAL := '{v.hex().upper()}'; SREC.MAXVAL := '{v.hex().upper()}'; "
            f"SREC.EAVS := 0; SREC.CHVALS := NULL; DBMS_STATS.SET_COLUMN_STATS(NULL,'{q(name)}','{q(col)}', NULL ,NULL,NULL,60,.01,0,srec,5,6); END;"
        ).encode()
        out += struct.pack("<H", len(text)) + text + b"\x00\x00\n"
    return out


def exp_section(
    name: str,
    cols: list[tuple[str, int, int]],
    rows: list[list],
    units: bytes = b"",
    create_extra: str = "",
    codec: str = "utf-8",
    csid: int = 873,
) -> bytes:
    """旧 exp の表の区画（TABLE 行から、終わりの印のあとの文まで。先頭の改行は含まない・終わりは改行）。"""
    names = ", ".join(q(c[0]) for c in cols)
    binds = ", ".join(f":{i + 1}" for i in range(len(cols)))
    coldefs = ", ".join(f"{q(c)} {sql_type(t, ln)}" for c, t, ln in cols)
    create = (
        f"CREATE TABLE {q(name)} ({coldefs}{create_extra})  PCTFREE 10 PCTUSED 40 INITRANS 1 MAXTRANS 255 "
        'STORAGE(INITIAL 65536 NEXT 1048576 MINEXTENTS 1 FREELISTS 1 FREELIST GROUPS 1 BUFFER_POOL DEFAULT) TABLESPACE "USERS" NOLOGGING NOCOMPRESS'
    )
    out = f"TABLE {q(name)}\n{create}\nINSERT INTO {q(name)} ({names}) VALUES ({binds})\n".encode(codec)
    out += struct.pack("<H", len(cols))
    for _, t, ln in cols:
        out += struct.pack("<HH", t, ln)
        if t in (1, 96):
            out += struct.pack("<HH", csid, 1)
    out += b"\x00\x00"
    for row in rows:
        out += b"\x00\x00"
        for v in row:
            out += b"\xff\xff" if v is None else struct.pack("<H", len(v)) + v
    out += b"\x00\x00\xff\xff\n" + units
    return out


def exp_dump(sections: list[bytes], second_pass: list[str], head: bytes = EXP_HEAD, codec: str = "utf-8") -> bytes:
    """旧 exp のダンプ全体: 見出し・表の区画・ENDTABLE・2 周目の統計・EXIT（実物の並びと同じ）。"""
    out = head + b"METRICEU 8\n" + b"".join(sections) + b"ENDTABLE\nMETRICSU\n"
    for t in second_pass:
        out += f"TABLE {q(t)}\nANALCOMPUTE TS {q(t)} ANALYZE  TABLE {q(t)}  ESTIMATE STATISTICS \n".encode(codec)
    return out + b"ENDTABLE\nEXIT\nEXIT\n"


N = 60  # 明細の上限（20 件）を大きく超える行数
CUSTOMER_COLS = [
    ("ID", 2, 22),
    ("備考", 1, 100),
    ("氏名", 1, 160),
    ("住民票コード", 2, 22),
    ("生年月日", 12, 7),
    ("電話番号", 1, 13),
    ("メール", 1, 100),
]


def customer_data(n: int = N) -> list[dict]:
    """5 行に 1 行は個人情報の無い行（値が NULL）。住民票コードは NUMBER・生年月日は DATE・電話番号は 13 バイトの列に 13 バイトの値。"""
    out = []
    for i in range(1, n + 1):
        blank = i % 5 == 0
        out.append(
            {
                "ID": i,
                "氏名": None if blank else f"山田太郎{i}",
                "住民票コード": None if blank else 12345678900 + i,
                "生年月日": None if blank else (1950 + i % 40, 1 + i % 12, 1 + i % 28),
                "電話番号": None if blank else f"090-{1000 + i:04d}-{5000 + i:04d}",
                "メール": None if blank else f"user{i}@example.com",
                "備考": f"メモ{i}",
            }
        )
    return out


def encode_customer(r: dict) -> list:
    return [
        enc_number(r["ID"]),
        r["備考"].encode(),
        None if r["氏名"] is None else r["氏名"].encode(),
        None if r["住民票コード"] is None else enc_number(r["住民票コード"]),
        None if r["生年月日"] is None else enc_date(*r["生年月日"]),
        None if r["電話番号"] is None else r["電話番号"].encode(),
        None if r["メール"] is None else r["メール"].encode(),
    ]


ITEM_COLS = [("SKU", 1, 20), ("名称", 1, 100)]


def item_rows() -> list[list]:
    return [[f"A-{i:03d}".encode(), f"商品{i}".encode()] for i in range(25)]


def customer_units(extra: bytes = b"") -> bytes:
    return exp_units("顧客", {"氏名": "山田太郎1".encode(), "電話番号": b"090-1000-5000", "ID": b"\xc1\x02"}) + extra


def build_exp(
    tmp_path: Path, name: str = "customer.dmp", n: int = N, extra_units: bytes = b"", create_extra: str = ""
) -> Path:
    cust = exp_section(
        "顧客", CUSTOMER_COLS, [encode_customer(r) for r in customer_data(n)], customer_units(extra_units), create_extra
    )
    items = exp_section("商品", ITEM_COLS, item_rows(), exp_units("商品", {"SKU": b"A-000"}))
    p = tmp_path / "src" / name
    p.parent.mkdir(exist_ok=True)
    p.write_bytes(exp_dump([cust, items], ["顧客", "商品"]))
    return p


# ---------------------------------------------------------------- 読み直し（検査の読み方で、表ごとの列と行を取り出す）


class _Col:
    def __init__(self):
        self.tables: dict[str, tuple[list[str], list[list]]] = {}
        self.texts: list[str] = []
        self._order: list[str] = []

    def add_records(self, columns, rows, location_fn, method=""):
        data = [list(r) for r in rows]
        self.tables[f"#{len(self._order)}"] = (list(columns), data)
        self._order.append(f"#{len(self._order)}")
        return len(data)

    def add_text(self, text, location, **kw):
        self.texts.append(text)


def read_dump(path: Path):
    """（読み取りの結果, 表の並び [(列名の並び, 行の並び)]）。"""
    data = path.read_bytes()
    kind = "exp" if b"EXPORT:V" in data[:64] else "expdp"
    col = _Col()
    res = od.scan_oracle_tables(io.BytesIO(data), col, kind, data[:64])
    return res, [col.tables[k] for k in col._order]


def customer_expected(n: int = N) -> list[list]:
    """顧客表の期待（読み取りの結果と同じ形: 文字列・None）。"""
    out = []
    for r in customer_data(n):
        y = r["生年月日"]
        out.append(
            [
                str(r["ID"]),
                r["備考"],
                r["氏名"],
                None if r["住民票コード"] is None else str(r["住民票コード"]),
                None if y is None else f"{y[0]:04d}-{y[1]:02d}-{y[2]:02d}",
                r["電話番号"],
                r["メール"],
            ]
        )
    return out


CUSTOMER_NEEDLES = [f"山田太郎{i}" for i in range(1, N + 1) if i % 5] + [
    f"user{i}@example.com" for i in range(1, N + 1) if i % 5
]


def positions_of(path: Path, tmp_path: Path) -> dict:
    return remediate.collect_task({"path": str(path), "options": ScanOptions(temp_dir=str(tmp_path))})


def rewrite(path: Path, tmp_path: Path, method: str, mode: str = "same", **select) -> tuple[Path, dict]:
    """位置を集めて、書き換えた新しいファイルを tmp_path の下に作る（元には書かない）。"""
    got = positions_of(path, tmp_path)
    sel = select_positions(got["positions"], **select)
    maker = DummyMaker(mode) if method == "dummy" else None
    dst = tmp_path / "out" / ("new_" + path.name)
    dst.parent.mkdir(exist_ok=True)
    stats = remediate.rewrite_file(str(path), str(dst), got["layout"], method, sel, maker, str(path))
    return dst, stats


# ================================================================ 内部形式を作る道具


@pytest.mark.parametrize(
    "text",
    [
        "0",
        "1",
        "9",
        "10",
        "40",
        "99",
        "100",
        "120",
        "3486",
        "101162",
        "1464497",
        "123456789012345",
        "-1",
        "-120",
        "-1464497",
    ]
    + [
        "1.5",
        "0.05",
        "35.1244",
        "-1.5",
        "-0.05",
        "12345678901234567890123456789012345678",
        "0.000123",
        "1000000000000",
    ],
)
def test_encode_number_roundtrips_with_decoder(text):
    assert od.decode_number(remedy_oracle.encode_number(text)) == text.lstrip("+")


def test_encode_number_known_vectors_from_real_dump():
    """実物の住基の連番・世帯番号・小数（解き方の試験と同じ組）。"""
    assert remedy_oracle.encode_number("3486") == bytes.fromhex("c22357")
    assert remedy_oracle.encode_number("101162") == bytes.fromhex("c30b0c3f")
    assert remedy_oracle.encode_number("1.5") == bytes.fromhex("c10233")
    assert remedy_oracle.encode_number("0.05") == bytes.fromhex("c006")
    assert remedy_oracle.encode_number("-1") == bytes.fromhex("3e6466")
    assert remedy_oracle.encode_number("-1.5") == bytes.fromhex("3e643366")
    assert remedy_oracle.encode_number("0") == b"\x80" and remedy_oracle.encode_number("0.000") == b"\x80"


def test_encode_number_random_roundtrip():
    rnd = random.Random(7)
    for _ in range(3000):
        digits = rnd.randint(1, 30)
        s = "".join(rnd.choice("0123456789") for _ in range(digits)).lstrip("0") or "0"
        if rnd.random() < 0.4:
            s += "." + "".join(rnd.choice("0123456789") for _ in range(rnd.randint(1, 8)))
        if rnd.random() < 0.3:
            s = "-" + s
        expect = od.decode_number(remedy_oracle.encode_number(s))
        from decimal import Decimal

        assert Decimal(expect) == Decimal(s), s


def test_numeric_dummy_keeps_digit_count_and_is_keyed():
    m1, m2 = DummyMaker("same"), DummyMaker("same")
    a = remedy_oracle.numeric_dummy(m1, "resident_code", "12345678901")
    assert a == remedy_oracle.numeric_dummy(m1, "resident_code", "12345678901")  # 同じ値は同じダミー
    assert a != remedy_oracle.numeric_dummy(m1, "resident_code", "12345678902")
    assert a != remedy_oracle.numeric_dummy(m2, "resident_code", "12345678901")  # 鍵は実行ごと
    assert len(a) == 11 and a[0] != "0" and a != "12345678901"
    assert remedy_oracle.numeric_dummy(DummyMaker("shape"), "x", "12345678901") == "0"
    assert remedy_oracle.numeric_dummy(DummyMaker("fixed"), "x", "12345678901") == "0"
    neg = remedy_oracle.numeric_dummy(m1, "x", "-12.5")
    assert neg.startswith("-") and "." in neg and len(neg.replace("-", "").replace(".", "")) == 3


def test_date_dummy_is_valid_and_keeps_time():
    raw = enc_date(1980, 1, 2, 12, 34, 56)
    for mode in ("same", "shape", "fixed"):
        new = remedy_oracle.date_dummy(DummyMaker(mode), "birthdate", raw)
        assert len(new) == 7 and new[4:] == raw[4:]
        shown = od.decode_date(new)
        assert shown and shown.startswith("19") and shown.endswith("12:34:56")
    assert od.decode_date(remedy_oracle.date_dummy(DummyMaker("fixed"), "b", raw)) == "1900-01-01 12:34:56"
    m = DummyMaker("same")
    assert remedy_oracle.date_dummy(m, "b", raw) == remedy_oracle.date_dummy(m, "b", raw)


# ================================================================ 旧 exp


def test_exp_fixture_is_read_by_the_scanner_and_has_detections(tmp_path):
    p = build_exp(tmp_path)
    res, tables = read_dump(p)
    assert res.tables == 2 and not res.failed and not res.truncated
    assert tables[0][0] == [c[0] for c in CUSTOMER_COLS] and tables[0][1] == customer_expected()
    total, values = scan_counts(p, tmp_path)
    kinds = {t for t, _v in values}
    assert {"name", "phone", "email", "birthdate", "resident_code"} <= kinds and total > 200
    assert _leak([str(p)], CUSTOMER_NEEDLES)  # 陽性対照: 元のダンプには値がある


def test_exp_collect_positions_cover_all_rows_without_raw_values(tmp_path):
    p = build_exp(tmp_path)
    got = positions_of(p, tmp_path)
    assert got["layout"] == "oracle_exp" and got["status"] == "scanned" and not got["overflow"]
    names = [k for k in got["positions"] if k[:2] == ("顧客", "name")]
    rows_found = sorted(r for k in names for r in got["positions"][k][0::4])
    rows_with_pii = [i for i in range(1, N + 1) if i % 5]
    assert rows_found == rows_with_pii and len(rows_with_pii) > 20  # 明細の上限を超えた分も、行の通し番号で全部
    assert {k[0] for k in got["positions"]} == {"顧客"}  # 個人情報の無い表には位置が無い
    assert all(isinstance(v, int) for arr in got["positions"].values() for v in arr)
    assert got["db_schema"]["tables"]["顧客"]["columns"] == [c[0] for c in CUSTOMER_COLS]
    assert not any(n in repr(got["db_schema"]) + repr(got["positions"]) for n in CUSTOMER_NEEDLES)


def section_bytes(data: bytes, name: str) -> bytes:
    """表の最初の区画（TABLE 行から次の TABLE・ENDTABLE の手前まで）。"""
    start = data.index(f"TABLE {q(name)}\nCREATE".encode())
    ends = [data.find(m, start + 5) for m in (b'\nTABLE "', b"\nENDTABLE")]
    return data[start : min(e for e in ends if e >= 0) + 1]


def assert_untouched_parts(old: bytes, new: bytes, names: list[str]) -> None:
    """触っていない表の区画・見出し・終わりの部分は、バイト列が元のまま。"""
    assert new.startswith(EXP_HEAD + b"METRICEU 8\n") and new.endswith(b"ENDTABLE\nEXIT\nEXIT\n")
    for name in names:
        assert section_bytes(new, name) == section_bytes(old, name)


def test_exp_delete_rows(tmp_path, trash):
    p = build_exp(tmp_path)
    original = p.read_bytes()
    svc, store, job = make_service(tmp_path, [p])
    r = run(svc, job, p, method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    rows_with_pii = [i for i in range(1, N + 1) if i % 5]
    assert r["changed"]["rows"] == len(rows_with_pii) and r["remaining"]["total"] == 0
    res, tables = read_dump(p)
    assert res.tables == 2 and not res.failed and not res.truncated
    expected = [row for row in customer_expected() if int(row[0]) % 5 == 0]  # 個人情報の無い行だけが残る
    assert tables[0][1] == expected and tables[0][0] == [c[0] for c in CUSTOMER_COLS]
    assert tables[1][1] == [[a.decode(), b.decode()] for a, b in item_rows()]  # ほかの表は全行そのまま
    data = p.read_bytes()
    assert_untouched_parts(original, data, ["商品"])
    assert _leak([str(p)], CUSTOMER_NEEDLES) == []
    assert (
        STATS_PHONE_HEX.encode() not in data and b'ANALSTATS TS "' + "顧客".encode() not in data
    )  # 統計の最小・最大値も残さない
    assert b'ANALSTATS TS "' + "商品".encode() + b'"' in data  # 触らない表の統計は残る
    assert b'ANALCOMPUTE TS "' + "顧客".encode() in data  # 2 周目の ANALYZE の文は残る
    assert [f.read_bytes() for f in trash.files()] == [original] and not new_tmp_files(p.parent)
    total, values = scan_counts(p, tmp_path)
    assert total == 0 and not values


def exp_rows_bytes(data: bytes, name: str, cols) -> list[bytes]:
    """旧 exp のダンプから、表の行のバイト列（先頭の 00 00 から次の行の手前まで）を独立に切り出す。"""
    i = data.index(b"\n", data.index(f"INSERT INTO {q(name)}".encode())) + 1
    i += 2 + sum(8 if t in (1, 96) else 4 for _, t, _ in cols) + 2
    rows = []
    while data[i : i + 4] != b"\x00\x00\xff\xff":  # 終わりの印（この試験の検体は、先頭の列が NULL にならない）
        j = i + 2
        for _ in cols:
            ln = struct.unpack("<H", data[j : j + 2])[0]
            j += 2 + (0 if ln == 0xFFFF else ln)
        rows.append(data[i:j])
        i = j
    return rows


def test_exp_untouched_rows_are_byte_identical(tmp_path):
    """行の削除のあと、残った行のバイト列は元のまま（行ごとに切り出して比べる）。"""
    p = build_exp(tmp_path)
    old = p.read_bytes()
    dst, stats = rewrite(p, tmp_path, "delete_rows")
    new = dst.read_bytes()
    old_rows, new_rows = exp_rows_bytes(old, "顧客", CUSTOMER_COLS), exp_rows_bytes(new, "顧客", CUSTOMER_COLS)
    assert len(old_rows) == N and new_rows == [r for k, r in enumerate(old_rows, start=1) if k % 5 == 0]
    assert stats["rows"] == N - len(new_rows)


def test_exp_dummy_all_types(tmp_path, trash):
    p = build_exp(tmp_path)
    original = p.read_bytes()
    svc, store, job = make_service(tmp_path, [p])
    r = run(svc, job, p, method="dummy", dummy_mode="same", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    assert r["remaining"]["total"] == 0, r["remaining"]
    res, tables = read_dump(p)
    assert res.tables == 2 and not res.failed
    before = customer_expected()
    after = tables[0][1]
    assert len(after) == N
    for old, new in zip(before, after):
        assert new[0] == old[0] and new[1] == old[1]  # ID・備考は元のまま
        if old[2] is None:  # 個人情報の無い行は丸ごと元のまま
            assert new == old
            continue
        assert new[2] != old[2] and new[2].startswith("氏名_")  # 文字: 種類の名前つきのダミー
        assert new[3] != old[3] and len(new[3]) == len(old[3])  # NUMBER: 同じ桁数の数
        assert new[4] != old[4] and new[4].startswith("19")  # DATE: 1900 年代の日付
        assert new[5] != old[5] and re.fullmatch(
            r"[0-9a-p]{13}", new[5]
        )  # 列の長さに収まらない → 同じ値は同じ（鍵つきの）英数字の 13 文字
        assert new[6] != old[6] and new[6].startswith("メール")
    # 同じ値は同じダミー・違う値は違うダミー
    assert len({row[2] for row in after if row[2]}) == len([1 for row in before if row[2]])
    data = p.read_bytes()
    assert_untouched_parts(original, data, ["商品"])
    assert _leak([str(p)], CUSTOMER_NEEDLES) == []
    assert STATS_PHONE_HEX.encode() not in data
    assert [f.read_bytes() for f in trash.files()] == [original]


@pytest.mark.parametrize("mode", ["shape", "fixed"])
def test_exp_dummy_shape_and_fixed(tmp_path, mode):
    p = build_exp(tmp_path)
    svc, store, job = make_service(tmp_path, [p])
    r = run(svc, job, p, method="dummy", dummy_mode=mode, confidences=ALL_RANKS)
    assert r["state"] == "done", r
    assert r["remaining"]["total"] == 0, r["remaining"]
    _res, tables = read_dump(p)
    for old, new in zip(customer_expected(), tables[0][1]):
        if old[2] is None:
            assert new == old
            continue
        assert new[3] == "0" and new[4] == "1900-01-01" and new[0] == old[0]
        assert new[2] == ("〇〇〇〇" + re.sub(r"\d", "0", old[2][4:]) if mode == "shape" else "＊＊＊")


def test_exp_dummy_char_column_keeps_padding_and_length(tmp_path):
    """CHAR は右側が空白で埋められる。置き換えても元の長さのまま（空白で埋める）。"""
    cols = [("ID", 2, 22), ("氏名", 96, 40), ("備考", 1, 50)]
    rows = [[enc_number(i), ("山田太郎%d" % i).encode().ljust(40, b" "), "メモ".encode()] for i in range(1, 31)]
    p = tmp_path / "src" / "char.dmp"
    p.parent.mkdir()
    p.write_bytes(exp_dump([exp_section("会員", cols, rows)], ["会員"]))
    svc, store, job = make_service(tmp_path, [p])
    r = run(svc, job, p, method="dummy", dummy_mode="same", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    assert r["remaining"]["total"] == 0
    data = p.read_bytes()
    _res, tables = read_dump(p)
    assert len(tables[0][1]) == 30 and all(row[1].startswith("氏名_") for row in tables[0][1])
    for row in exp_rows_bytes(data, "会員", cols):  # バイト列では、氏名の列は元と同じ 40 バイト（右側は空白）
        j = 2 + 2 + struct.unpack("<H", row[2:4])[0]
        assert struct.unpack("<H", row[j : j + 2])[0] == 40 and row[j + 2 : j + 42].endswith(b" ")


def exp_extra_units() -> bytes:
    return (
        'CREATE INDEX "IDX_NAME" ON "顧客" ("氏名" )  PCTFREE 10 INITRANS 2 MAXTRANS 255 TABLESPACE "USERS" LOGGING\n'.encode()
        + 'ANALSTATS IS "IDX_NAME"\n'.encode()
        + struct.pack("<H", 10)
        + b"BEGIN END;\n"
        # 実物の旧 exp の形: ANALSTATS IS の後ろは表の名前で、索引の名前は SET_INDEX_STATS の中にある
        + 'ANALSTATS IS "顧客"\n'.encode()
        + struct.pack("<H", 83)
        + b"BEGIN  DBMS_STATS.SET_INDEX_STATS(NULL,'\"IDX_NAME\"',NULL,NULL,NULL,30,1,30,1,1,1,0,6); END;\n"
        + 'ALTER TABLE "顧客" ADD CONSTRAINT "PK_C" PRIMARY KEY ("ID") USING INDEX TABLESPACE "USERS" ENABLE\n'.encode()
        + 'COMMENT ON COLUMN "顧客"."電話番号" IS \'電話の列\'\n'.encode()
        + 'COMMENT ON COLUMN "顧客"."備考" IS \'備考の列\'\n'.encode()
    )


def test_exp_delete_columns(tmp_path, trash):
    p = build_exp(tmp_path, extra_units=exp_extra_units())
    original = p.read_bytes()
    svc, store, job = make_service(tmp_path, [p])
    r = run(svc, job, p, method="delete_columns", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    dropped = {"氏名", "住民票コード", "生年月日", "電話番号", "メール"}  # 検出のある列
    keep = [i for i, c in enumerate(CUSTOMER_COLS) if c[0] not in dropped]
    assert r["changed"]["cols"] == len(dropped) and r["remaining"]["total"] == 0
    res, tables = read_dump(p)
    assert res.tables == 2 and not res.failed and not res.truncated
    assert tables[0][0] == [CUSTOMER_COLS[i][0] for i in keep] == ["ID", "備考"]
    assert tables[0][1] == [[row[i] for i in keep] for row in customer_expected()]  # 全行・残る列の値は元のまま
    assert tables[1][1] == [[a.decode(), b.decode()] for a, b in item_rows()]
    data = p.read_bytes()
    assert_untouched_parts(original, data, ["商品"])
    sec = section_bytes(data, "顧客")
    assert (
        b'CREATE TABLE "' + "顧客".encode() + b'" ("ID" NUMBER, "' + "備考".encode() + b'" VARCHAR2(100))  PCTFREE 10'
        in sec
    )
    assert (
        b'INSERT INTO "' + "顧客".encode() + b'" ("ID", "' + "備考".encode() + b'") VALUES (:1, :2)\n' + b"\x02\x00"
        in sec
    )
    assert (
        b"IDX_NAME" not in data and b'"' + "電話番号".encode() + b'"' not in sec
    )  # その列の索引・統計・コメントは外れる
    assert (
        b'ADD CONSTRAINT "PK_C"' in data and b'COMMENT ON COLUMN "' + "顧客".encode() + b'"."' + "備考".encode() in data
    )
    assert _leak([str(p)], CUSTOMER_NEEDLES) == [] and STATS_PHONE_HEX.encode() not in data
    assert [f.read_bytes() for f in trash.files()] == [original]


def test_exp_delete_columns_refuses_statement_it_cannot_handle(tmp_path, trash):
    extra = 'GRANT UPDATE ("氏名") ON "顧客" TO "PUBLIC"\n'.encode()
    p = build_exp(tmp_path, extra_units=extra)
    original = p.read_bytes()
    svc, store, job = make_service(tmp_path, [p])
    r = run(svc, job, p, method="delete_columns", confidences=ALL_RANKS)
    assert r["state"] == "error" and "削除する列を使っていて" in r["message"]
    assert p.read_bytes() == original and not trash.files() and not new_tmp_files(p.parent)
    assert store.remediations(job) == []


def test_exp_delete_columns_refuses_all_columns_and_inline_constraints(tmp_path):
    cols = [("氏名", 1, 160), ("メール", 1, 100)]
    rows = [[f"山田太郎{i}".encode(), f"user{i}@example.com".encode()] for i in range(1, 31)]
    p = tmp_path / "src" / "all.dmp"
    p.parent.mkdir()
    p.write_bytes(exp_dump([exp_section("会員", cols, rows)], ["会員"]))
    with pytest.raises(RemedyError, match="すべての列は削除できません"):
        rewrite(p, tmp_path, "delete_columns")
    p2 = build_exp(tmp_path, name="inline.dmp", create_extra=', CONSTRAINT "CK" CHECK ("ID" > 0)')
    with pytest.raises(RemedyError, match="列の定義でない項目"):
        rewrite(p2, tmp_path, "delete_columns")
    assert not (tmp_path / "out" / "new_all.dmp").exists() and not (tmp_path / "out" / "new_inline.dmp").exists()


def test_exp_delete_table(tmp_path, trash):
    p = build_exp(tmp_path)
    original = p.read_bytes()
    svc, store, job = make_service(tmp_path, [p])
    r = run(svc, job, p, method="delete_table", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    assert r["changed"]["tables"] == 1
    res, tables = read_dump(p)
    assert res.tables == 1 and tables[0][1] == [[a.decode(), b.decode()] for a, b in item_rows()]
    data = p.read_bytes()
    assert (
        "顧客".encode() not in data and STATS_PHONE_HEX.encode() not in data
    )  # 表の定義・データ・統計・2 周目の文もすべて
    assert section_bytes(data, "商品") == section_bytes(original, "商品")
    assert data.startswith(EXP_HEAD + b"METRICEU 8\n") and data.endswith(b"ENDTABLE\nEXIT\nEXIT\n")
    assert b'TABLE "' + "商品".encode() + b'"\nANALCOMPUTE' in data
    assert _leak([str(p)], CUSTOMER_NEEDLES) == [] and [f.read_bytes() for f in trash.files()] == [original]


def test_exp_same_name_sections_are_told_apart(tmp_path):
    """同じ名前の区画（パーティション・別のスキーマ）は、2 つ目から「名前 (2)」。選んだほうだけが変わる。"""
    rows1 = [encode_customer(r) for r in customer_data(30)]
    rows2 = [encode_customer(r) for r in customer_data(25)]
    s1 = exp_section("顧客", CUSTOMER_COLS, rows1)
    s2 = exp_section("顧客", CUSTOMER_COLS, rows2)
    p = tmp_path / "src" / "dup.dmp"
    p.parent.mkdir()
    p.write_bytes(exp_dump([s1, s2], ["顧客", "顧客"]))
    got = positions_of(p, tmp_path)
    assert {k[0] for k in got["positions"]} == {"顧客", "顧客 (2)"}
    dst = tmp_path / "out" / "dup.dmp"
    dst.parent.mkdir()
    sel = select_positions(got["positions"], sheets={"顧客 (2)"})
    remediate.rewrite_file(str(p), str(dst), got["layout"], "delete_rows", sel, None, str(p))
    _res, tables = read_dump(dst)
    assert tables[0][1] == customer_expected(30)  # 1 つ目は元のまま
    assert tables[1][1] == [row for row in customer_expected(25) if int(row[0]) % 5 == 0]
    # 表の削除（2 つ目）: 1 つ目の区画は残る
    dst2 = tmp_path / "out" / "dup2.dmp"
    remediate.rewrite_file(str(p), str(dst2), got["layout"], "delete_table", sel, None, str(p))
    _res, tables = read_dump(dst2)
    assert len(tables) == 1 and tables[0][1] == customer_expected(30)


def test_exp_real_excerpt_every_method(tmp_path):
    """実物（Oracle 21c）の旧 exp の先頭の切り出し（架空の住基 150 行）に、各方法を当てる。"""
    src = tmp_path / "src" / "real_exp.dmp"
    src.parent.mkdir()
    src.write_bytes((DATA / "oracle_exp_sample.bin").read_bytes())
    old = src.read_bytes()
    _res, base = read_dump(src)
    cols0, rows0 = base[0]
    assert len(rows0) == 150
    got = positions_of(src, tmp_path)
    assert got["layout"] == "oracle_exp" and got["status"] == "scanned"
    sel = select_positions(got["positions"])
    hit_cols = sorted(sel.cols()["住基"])
    assert len(sel.rows()["住基"]) == 150 and {1, 2, 4} <= set(hit_cols)  # 住民票コード・氏名・生年月日
    name_idx = cols0.index("氏名")
    dst = tmp_path / "out" / "d1.dmp"
    dst.parent.mkdir()

    st = remediate.rewrite_file(str(src), str(dst), "oracle_exp", "delete_rows", sel, None, str(src))  # 行の削除
    assert st["rows"] == 150
    _r, t = read_dump(dst)
    assert t[0][1] == []  # すべての行に検出がある → 表は空
    new = dst.read_bytes()
    assert new[: new.index(b"INSERT INTO")] == old[: old.index(b"INSERT INTO")]  # 見出し・CREATE TABLE は元のまま

    dst = tmp_path / "out" / "d2.dmp"  # ダミー化
    remediate.rewrite_file(str(src), str(dst), "oracle_exp", "dummy", sel, DummyMaker("same"), str(src))
    _r, t = read_dump(dst)
    assert len(t[0][1]) == 150 and not _r.failed
    for o, n in zip(rows0, t[0][1]):
        assert n[0] == o[0] and n[name_idx] != o[name_idx] and n[7] == o[7]  # 連番・世帯番号は元のまま
    assert _leak([str(dst)], [r[name_idx] for r in rows0]) == []

    dst = tmp_path / "out" / "d3.dmp"  # 列の削除
    only = select_positions(got["positions"], types={"name", "resident_code"})
    remediate.rewrite_file(str(src), str(dst), "oracle_exp", "delete_columns", only, None, str(src))
    _r, t = read_dump(dst)
    gone = {cols0[i] for i in only.cols()["住基"]}  # 検出のある列（名前・住民票コードの検出を含む列）
    assert {"住民票コード", "氏名"} <= gone and "連番" not in gone
    keep = [i for i, c in enumerate(cols0) if c not in gone]
    assert t[0][0] == [cols0[i] for i in keep] and not _r.failed
    assert t[0][1] == [[row[i] for i in keep] for row in rows0]

    dst = tmp_path / "out" / "d4.dmp"  # 表の削除
    remediate.rewrite_file(str(src), str(dst), "oracle_exp", "delete_table", sel, None, str(src))
    new = dst.read_bytes()
    assert b"INSERT INTO" not in new and "住基".encode() not in new
    assert new == old[: old.index(b"TABLE ")]


# ================================================================ expdp
# 検体は、実物（Oracle 21c の expdp）の作りどおり: ブロック 0（見出し）→ 単位（制御ブロック＋本体）の並び。
# 制御ブロック = ff ff 24 24 + 種別 2 バイト + F1..F6（8 バイト BE）、本体 = 03 69 + XML・行・索引・ゼロ詰め（ブロックの倍数）。

CTRL = bytes([0xFF, 0xFF, 0x24, 0x24])  # 制御ブロックの先頭
TEST_GRANULE = 400  # 実物は 10,240,000。試験では小さくして、索引に複数の項目が出るようにする（remedy_oracle.GRANULE も同じ値にする）


@pytest.fixture
def small_granule(monkeypatch):
    monkeypatch.setattr(remedy_oracle, "GRANULE", TEST_GRANULE)
    return TEST_GRANULE


def align8(n: int) -> int:
    return (n + 7) & ~7


def pad_to(data: bytes, unit: int) -> bytes:
    return data + b"\x00" * (-len(data) % unit)


def dp_xml_of(name: str, cols: list[tuple[str, int, int, int]]) -> bytes:
    """列定義の XML（先頭の 03 69 つき）。test_oracle_dump と同じ形。"""
    from test_oracle_dump import dp_xml

    return dp_xml(name, cols)


def dp_index(rows: list[bytes], granule: int) -> list[int]:
    """索引: [0, 前の項目から granule 以上で最初の行の境界, …]（実物 5 つの区画で確かめた規則）。"""
    entries, nxt, off = [0], granule, 0
    for r in rows:
        if off >= nxt:
            entries.append(off)
            nxt = off + granule
        off += len(r)
    return entries


def dp_unit_bytes(
    name, cols, rows: list[bytes], granule: int, kind: bytes = b"\x0a\x00", xml: bytes | None = None
) -> bytes:
    """表のデータの単位（制御ブロック＋本体）。rows は行のバイト列（3C…）の並び。"""
    xml = xml if xml is not None else dp_xml_of(name, cols)
    f1, rows_blob = len(xml), b"".join(rows)
    f3 = len(rows_blob)
    index = b"".join(struct.pack(">Q", v) for v in dp_index(rows, granule))
    f5 = len(index)
    fields = [f1, 4096, f3, align8(f1) + 4096, f5, align8(f1) + align8(f3) + 4096]
    ctrl = pad_to(b"\xff\xff$$" + kind + b"".join(struct.pack(">Q", v) for v in fields), 4096)
    body = xml.ljust(align8(f1), b"\x00") + rows_blob.ljust(align8(f3), b"\x00") + index
    return ctrl + pad_to(body, 4096)


def kgc_unit() -> bytes:
    """圧縮されたメタデータ（KGC）の単位の代わり（読めないバイト列）。"""
    rnd = random.Random(3)
    junk = b"KGC\x80\x01HDR>T" + bytes(rnd.randrange(256) for _ in range(1500))
    return pad_to(b"\xff\xff$$\x14\x04" + b"\x00" * 48, 4096) + pad_to(junk, 4096)


def dp_dump_bytes(units: list[bytes], master_block: int | None = None) -> bytes:
    head = bytearray(4096)
    head[0:4] = b"\x05\x01M\x11"
    head[0x40 : 0x40 + 8] = b"AL32UTF8"
    n_before = sum(len(u) for u in units[:-1]) // 4096 + 1
    struct.pack_into(
        ">I", head, 0x36, n_before if master_block is None else master_block
    )  # マスターテーブルの開始ブロック
    return bytes(head) + b"".join(units)


DP_COLS = [
    ("ID", 2, 22, 0),
    ("備考", 1, 400, 873),
    ("氏名", 1, 160, 873),
    ("住民票コード", 2, 22, 0),
    ("生年月日", 12, 7, 0),
    ("電話番号", 1, 52, 873),
    ("メール", 1, 400, 873),
]
DP_ITEM_COLS = [("SKU", 1, 80, 873), ("名称", 1, 400, 873)]


def dp_row_of(cells: list) -> bytes:
    from test_oracle_dump import dp_row

    return dp_row(cells)


def dp_customer_rows(n: int = N) -> list[bytes]:
    return [dp_row_of(encode_customer(r)) for r in customer_data(n)]


def dp_item_rows() -> list[bytes]:
    return [dp_row_of(r) for r in item_rows()]


def master_unit(granule: int) -> bytes:
    """マスターテーブルの代わり（3C の行を持つ表。個人情報らしい値も入れておく）。"""
    cols = [("PROCESS_ORDER", 2, 22, 0), ("OBJECT_NAME", 1, 400, 873)]
    rows = [dp_row_of([enc_number(i), f"090-0000-{i:04d}".encode()]) for i in range(1, 12)]
    return dp_unit_bytes("SYS_EXPORT_SCHEMA_01", cols, rows, granule)


def build_dp(
    tmp_path: Path, name: str = "customer_dp.dmp", granule: int = TEST_GRANULE, n: int = N, master: bool = True
) -> Path:
    units = [
        kgc_unit(),
        dp_unit_bytes("顧客", DP_COLS, dp_customer_rows(n), granule),
        dp_unit_bytes("商品", DP_ITEM_COLS, dp_item_rows(), granule),
    ]
    if master:
        units.append(master_unit(granule))
    p = tmp_path / "src" / name
    p.parent.mkdir(exist_ok=True)
    p.write_bytes(dp_dump_bytes(units))
    return p


def parse_units(data: bytes) -> list[dict]:
    """ダンプを、制御ブロックの値から独立に単位へ分ける（読み取り側・書き換え側の関数は使わない）。"""
    out, pos = [], 4096
    while pos < len(data):
        assert data[pos : pos + 4] == b"\xff\xff$$", hex(pos)
        f = [struct.unpack(">Q", data[pos + 6 + 8 * k : pos + 14 + 8 * k])[0] for k in range(6)]
        body = pos + 4096
        if data[pos + 4 : pos + 6] == b"\x14\x04":  # メタデータの単位（制御ブロック＋1 ブロック）
            out.append({"kind": "meta", "at": pos, "end": body + 4096, "f": f})
            pos = body + 4096
            continue
        f1, _f2, f3, f4, f5, f6 = f
        length = pad_len(align8(f1) + align8(f3) + f5)
        xml = data[body + 2 : body + f1]
        name = re.search(rb"<OWNER_NAME>[^<]*</OWNER_NAME><NAME>([^<]*)</NAME>", xml).group(1).decode()
        rows, p, off = [], body + align8(f1), 0
        while off < f3:
            assert data[p] == 0x3C
            total = (data[p + 1] << 8) | data[p + 2]
            rows.append(data[p : p + total])
            p += total
            off += total
        assert off == f3
        idx_at = body + f6 - 4096
        index = [struct.unpack(">Q", data[idx_at + 8 * k : idx_at + 8 * k + 8])[0] for k in range(f5 // 8)]
        nxt = body + length
        while nxt < len(data) and data[nxt : nxt + 4] != CTRL and not any(data[nxt : nxt + 4096]):
            nxt += 4096  # 書き換えで行が減ったときの、同じ大きさを保つためのゼロのブロック
        out.append(
            {
                "kind": "table",
                "name": name,
                "at": pos,
                "end": nxt,
                "f": f,
                "rows": rows,
                "index": index,
                "xml": data[body : body + align8(f1)],
                "tail": data[idx_at + f5 : body + length],
            }
        )
        pos = nxt
    return out


def pad_len(n: int) -> int:
    return (n + 4095) // 4096 * 4096


def check_unit_invariants(u: dict, granule: int) -> None:
    """単位の制御ブロックの値・索引・ゼロ詰めが、行から独立に求めた期待と一致する。"""
    f1, f2, f3, f4, f5, f6 = u["f"]
    assert f2 == 4096 and f3 == sum(len(r) for r in u["rows"]) and f4 == align8(f1) + 4096
    assert f6 == align8(f1) + align8(f3) + 4096 and f5 == 8 * len(u["index"])
    assert u["index"] == (dp_index(u["rows"], granule) if (u["rows"] or f5) else [])
    assert u["tail"].count(0) == len(u["tail"])


def test_dp_fixture_is_valid_and_read_by_the_scanner(tmp_path, small_granule):
    p = build_dp(tmp_path)
    data = p.read_bytes()
    units = parse_units(data)
    assert [u.get("name") for u in units] == [None, "顧客", "商品", "SYS_EXPORT_SCHEMA_01"]
    for u in units:
        if u["kind"] == "table":
            check_unit_invariants(u, small_granule)
    assert len(units[1]["index"]) > 3  # 索引に複数の項目が出る大きさ
    res, tables = read_dump(p)
    assert res.tables == 3 and not res.failed and tables[0][1] == customer_expected()
    total, values = scan_counts(p, tmp_path)
    assert {"name", "phone", "email", "birthdate", "resident_code"} <= {t for t, _v in values}
    assert _leak([str(p)], CUSTOMER_NEEDLES)  # 陽性対照


def test_dp_collect_positions_skip_master_table(tmp_path, small_granule):
    p = build_dp(tmp_path)
    got = positions_of(p, tmp_path)
    assert got["layout"] == "oracle_expdp" and got["status"] == "scanned" and not got["overflow"]
    assert {k[0] for k in got["positions"]} == {"顧客"}  # マスターテーブルの行（電話番号らしい値）には位置を集めない
    assert "SYS_EXPORT_SCHEMA_01" in got["db_schema"]["tables"]
    assert not any(n in repr(got["positions"]) for n in CUSTOMER_NEEDLES)


def test_dp_delete_rows(tmp_path, trash, small_granule):
    p = build_dp(tmp_path)
    original = p.read_bytes()
    svc, store, job = make_service(tmp_path, [p])
    r = run(svc, job, p, method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    new = p.read_bytes()
    assert len(new) == len(original)  # ファイルの大きさは変えない
    old_u, new_u = parse_units(original), parse_units(new)
    assert [u.get("name") for u in new_u] == [u.get("name") for u in old_u]
    keep = [row for k, row in enumerate(old_u[1]["rows"], start=1) if k % 5 == 0]
    assert new_u[1]["rows"] == keep  # 個人情報の無い行だけが元のバイト列のまま残る
    check_unit_invariants(new_u[1], small_granule)
    assert new_u[1]["xml"] == old_u[1]["xml"]  # 列の定義（XML）は変えない
    assert (
        r["changed"]["rows"] == N - len(keep) and r["remaining"]["total"] == 11
    )  # 残りは、位置を持たないマスターテーブルの行（電話番号らしい値 11 件）だけ
    for i in (
        0,
        2,
        3,
    ):  # 触らない単位（メタデータ・商品・マスターテーブル）は、制御ブロックも本体もバイト単位で元のまま
        assert new[old_u[i]["at"] : old_u[i]["end"]] == original[old_u[i]["at"] : old_u[i]["end"]]
    assert new[:4096] == original[:4096]  # 見出しのブロックも
    assert _leak([str(p)], CUSTOMER_NEEDLES) == []
    res, tables = read_dump(p)
    assert (
        res.tables == 3
        and not res.failed
        and tables[0][1] == [row for row in customer_expected() if int(row[0]) % 5 == 0]
    )
    assert [f.read_bytes() for f in trash.files()] == [original] and not new_tmp_files(p.parent)


def test_dp_delete_all_rows_gives_an_empty_table_with_an_index_entry(tmp_path, small_granule):
    p = build_dp(tmp_path)
    got = positions_of(p, tmp_path)
    sel = select_positions(got["positions"], types={"name", "email", "phone", "birthdate", "resident_code"})
    # 5 行に 1 行は元から個人情報が無いので、全部は消えない。ID が個人情報として拾われることは無い
    dst = tmp_path / "out" / "x.dmp"
    dst.parent.mkdir()
    remediate.rewrite_file(str(p), str(dst), "oracle_expdp", "delete_rows", sel, None, str(p))
    u = parse_units(dst.read_bytes())[1]
    assert len(u["rows"]) == N // 5 and u["index"] == [0]


def test_dp_dummy(tmp_path, trash, small_granule):
    p = build_dp(tmp_path)
    original = p.read_bytes()
    svc, store, job = make_service(tmp_path, [p])
    r = run(svc, job, p, method="dummy", dummy_mode="same", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    new = p.read_bytes()
    assert len(new) == len(original)
    old_u, new_u = parse_units(original), parse_units(new)
    check_unit_invariants(new_u[1], small_granule)
    assert len(new_u[1]["rows"]) == N
    for o, n in zip(old_u[1]["rows"], new_u[1]["rows"]):
        assert len(n) <= len(o)  # 元より長くしない（ファイルの大きさを変えないため）
    assert new_u[1]["xml"] == old_u[1]["xml"]
    for i in (0, 2, 3):
        assert new[old_u[i]["at"] : old_u[i]["end"]] == original[old_u[i]["at"] : old_u[i]["end"]]
    res, tables = read_dump(p)
    assert res.tables == 3 and not res.failed
    for old, nw in zip(customer_expected(), tables[0][1]):
        assert nw[0] == old[0] and nw[1] == old[1]  # ID・備考は元のまま
        if old[2] is None:
            assert nw == old
            continue
        assert (
            nw[2] != old[2]
            and re.fullmatch(r"[0-9a-p]{%d}" % len(old[2].encode()), nw[2])
            and nw[3] != old[3]
            and len(nw[3]) == len(old[3])
            and nw[4].startswith("19")
        )
        assert re.fullmatch(r"[0-9a-p]{13}", nw[5]) and re.fullmatch(r"[0-9a-p]{%d}" % len(old[6].encode()), nw[6])
    assert r["remaining"]["total"] == 11 and _leak([str(p)], CUSTOMER_NEEDLES) == []
    assert [f.read_bytes() for f in trash.files()] == [original]


def test_dp_dummy_rows_never_grow_when_dummy_is_longer(tmp_path, small_granule):
    """短い値（元より長いダミーになる値）は、元と同じ文字数の * になり、行は元より長くならない。"""
    cols = [("ID", 2, 22, 0), ("氏名", 1, 160, 873)]
    rows = [dp_row_of([enc_number(i), f"山田{i % 10}".encode()]) for i in range(1, 40)]
    p = tmp_path / "src" / "short.dmp"
    p.parent.mkdir()
    p.write_bytes(dp_dump_bytes([kgc_unit(), dp_unit_bytes("会員", cols, rows, small_granule)]))
    got = positions_of(p, tmp_path)
    dst = tmp_path / "out" / "short.dmp"
    dst.parent.mkdir()
    remediate.rewrite_file(
        str(p), str(dst), "oracle_expdp", "dummy", select_positions(got["positions"]), DummyMaker("same"), str(p)
    )
    old_u, new_u = parse_units(p.read_bytes()), parse_units(dst.read_bytes())
    for o, n in zip(old_u[1]["rows"], new_u[1]["rows"]):
        assert len(n) <= len(o) and n != o
    check_unit_invariants(new_u[1], small_granule)


def test_dp_identity_rewrite_reproduces_every_unit_byte_for_byte(tmp_path, small_granule):
    """行をそのまま返す書き直しは、単位を 1 バイトも変えない（制御ブロック・索引・ゼロ詰めの作りが元と同じ）。"""
    p = build_dp(tmp_path)
    data = p.read_bytes()
    with open(p, "rb") as f:
        segs = remedy_oracle.find_dp_segments(f, len(data))
        assert [s.name for s in segs] == ["顧客", "商品", "SYS_EXPORT_SCHEMA_01"]
        for s in segs:
            out = io.BytesIO()
            remedy_oracle.rewrite_dp_unit(f, out, s, len(data), lambda n, row: remedy_oracle._KEEP)
            start = s.xml_at - 2 - 4096
            assert out.getvalue() == data[start : start + len(out.getvalue())] and len(out.getvalue()) >= 8192


def test_dp_column_and_table_delete_are_unavailable_and_refused(tmp_path, small_granule):
    p = build_dp(tmp_path)
    svc, store, job = make_service(tmp_path, [p])
    a = analyze(svc, job, p)
    m = a.info["methods"]
    assert m["delete_rows"]["available"] and m["dummy"]["available"] and m["delete_file"]["available"]
    for k in ("delete_columns", "delete_table"):
        assert not m[k]["available"] and "圧縮" in m[k]["reason"] and "行の削除・ダミー化は対応" in m[k]["reason"]
    got = positions_of(p, tmp_path)
    for method in ("delete_columns", "delete_table"):
        with pytest.raises(RemedyError, match="圧縮"):
            remediate.rewrite_file(
                str(p),
                str(tmp_path / "o.dmp"),
                "oracle_expdp",
                method,
                select_positions(got["positions"]),
                None,
                str(p),
            )
    assert not (tmp_path / "o.dmp").exists()


def test_dp_refuses_master_table_and_unexpected_layouts(tmp_path, small_granule):
    p = build_dp(tmp_path)
    data = bytearray(p.read_bytes())
    got = positions_of(p, tmp_path)
    sel = select_positions(got["positions"])

    def attempt(mutated: bytes, match: str, name: str):
        q2 = tmp_path / "src" / name
        q2.write_bytes(mutated)
        dst = tmp_path / "out" / ("o_" + name)
        dst.parent.mkdir(exist_ok=True)
        with pytest.raises(RemedyError, match=match):
            remediate.rewrite_file(str(q2), str(dst), "oracle_expdp", "delete_rows", sel, None, str(q2))
        assert not dst.exists()  # 失敗した書き出しは残さない

    units = parse_units(bytes(data))
    cust = units[1]
    # 索引の値が違う（作りの取り違え）
    bad = bytearray(data)
    idx_at = cust["at"] + 4096 + cust["f"][5] - 4096
    bad[idx_at + 15] ^= 0x01
    attempt(bytes(bad), "索引が、想定した作り", "bad_index.dmp")
    # 制御ブロックの行の合計が違う
    bad = bytearray(data)
    struct.pack_into(">Q", bad, cust["at"] + 6 + 16, cust["f"][2] + 8)
    attempt(bytes(bad), "想定した作り", "bad_f3.dmp")
    # 次の単位の制御ブロックが無い
    bad = bytearray(data)
    bad[units[2]["at"] : units[2]["at"] + 4] = b"\x00\x00\x00\x00"
    attempt(bytes(bad), "次の単位の制御ブロックでない", "bad_next.dmp")
    # 行の並びに行でないバイトがある
    bad = bytearray(data)
    first = cust["at"] + 4096 + align8(cust["f"][0])
    bad[first] = 0x00
    attempt(bytes(bad), "行でないバイト|行の並び|読み解け", "bad_row.dmp")
    # 制御ブロックの無い（実物の先頭の切り出し・作りが違う）区画
    q3 = tmp_path / "src" / "cut.dmp"
    q3.write_bytes((DATA / "oracle_expdp_sample.bin").read_bytes())
    got3 = positions_of(q3, tmp_path)
    assert got3["status"] == "scanned"
    # 分析の段で見つけて、下見の前に断る（下見が通って実行で断られると分かりにくい・VM で試して見つけた）
    assert "想定した作り" in got3["structure_problem"]
    for method in ("delete_rows", "dummy"):
        assert "想定した作り" in remediate.unsupported_reason(method, str(q3), got3)
    assert remediate.unsupported_reason("delete_file", str(q3), got3) == ""
    with pytest.raises(RemedyError, match="想定した作り"):
        remediate.rewrite_file(
            str(q3),
            str(tmp_path / "out" / "cut.dmp"),
            "oracle_expdp",
            "delete_rows",
            select_positions(got3["positions"]),
            None,
            str(q3),
        )
    assert not (tmp_path / "out" / "cut.dmp").exists()
    # マスターテーブルは位置が無く、名前で指定されても書き換えない
    from pii_checker.remedy_write import Selection
    from array import array

    forced = Selection({("SYS_EXPORT_SCHEMA_01", "phone", 3): array("q", [1, 1, 0, 13])})
    with pytest.raises(RemedyError, match="マスターテーブル"):
        remediate.rewrite_file(
            str(p), str(tmp_path / "out" / "m.dmp"), "oracle_expdp", "delete_rows", forced, None, str(p)
        )


def test_dp_same_name_units_are_told_apart(tmp_path, small_granule):
    units = [
        kgc_unit(),
        dp_unit_bytes("顧客", DP_COLS, dp_customer_rows(30), small_granule),
        dp_unit_bytes("顧客", DP_COLS, dp_customer_rows(25), small_granule),
        master_unit(small_granule),
    ]
    p = tmp_path / "src" / "dup_dp.dmp"
    p.parent.mkdir()
    p.write_bytes(dp_dump_bytes(units))
    got = positions_of(p, tmp_path)
    assert {k[0] for k in got["positions"]} == {"顧客", "顧客 (2)"}
    dst = tmp_path / "out" / "dup.dmp"
    dst.parent.mkdir()
    remediate.rewrite_file(
        str(p),
        str(dst),
        "oracle_expdp",
        "delete_rows",
        select_positions(got["positions"], sheets={"顧客 (2)"}),
        None,
        str(p),
    )
    old_u, new_u = parse_units(p.read_bytes()), parse_units(dst.read_bytes())
    assert new_u[1]["rows"] == old_u[1]["rows"]  # 1 つ目は元のまま
    assert new_u[2]["rows"] == [r for k, r in enumerate(old_u[2]["rows"], start=1) if k % 5 == 0]


def test_dp_real_excerpt_completed_into_a_full_unit(tmp_path, small_granule):
    """実物（Oracle 21c の expdp）の先頭の切り出し（列定義の XML と架空の住基 150 行）を、制御ブロック・索引つきの単位に仕立てて各方法を当てる。"""
    sample = (DATA / "oracle_expdp_sample.bin").read_bytes()
    xml_at = sample.index(b"<?xml")
    xml = sample[xml_at - 2 : sample.index(b"</ROWSET>") + 9]
    pos = len(xml) + xml_at - 2
    pos = sample.index(b"</ROWSET>") + 9
    while sample[pos] == 0:
        pos += 1
    rows = []
    while sample[pos] == 0x3C:
        total = (sample[pos + 1] << 8) | sample[pos + 2]
        rows.append(sample[pos : pos + total])
        pos += total
    assert len(rows) == 150
    p = tmp_path / "src" / "real_dp.dmp"
    p.parent.mkdir()
    p.write_bytes(
        dp_dump_bytes([kgc_unit(), dp_unit_bytes("住基", [], rows, small_granule, xml=xml), master_unit(small_granule)])
    )
    _res, base = read_dump(p)
    cols0, rows0 = base[0]
    assert len(rows0) == 150 and cols0[:3] == ["連番", "住民票コード", "氏名"]
    got = positions_of(p, tmp_path)
    assert got["layout"] == "oracle_expdp" and got["status"] == "scanned"
    sel = select_positions(got["positions"])
    original = p.read_bytes()
    dst = tmp_path / "out" / "r1.dmp"
    dst.parent.mkdir()
    st = remediate.rewrite_file(str(p), str(dst), "oracle_expdp", "delete_rows", sel, None, str(p))
    assert st["rows"] == 150 and dst.stat().st_size == len(original)
    u = parse_units(dst.read_bytes())[1]
    assert u["rows"] == [] and u["index"] == [0]
    check_unit_invariants(u, small_granule)
    dst = tmp_path / "out" / "r2.dmp"
    remediate.rewrite_file(str(p), str(dst), "oracle_expdp", "dummy", sel, DummyMaker("same"), str(p))
    assert dst.stat().st_size == len(original)
    _r, t = read_dump(dst)
    assert len(t[0][1]) == 150 and not _r.failed
    name_idx = cols0.index("氏名")
    for o, n in zip(rows0, t[0][1]):
        assert n[0] == o[0] and n[7] == o[7] and n[name_idx] != o[name_idx]
    check_unit_invariants(parse_units(dst.read_bytes())[1], small_granule)
    assert _leak([str(dst)], [r[name_idx] for r in rows0]) == []


def test_dp_index_follows_the_rows_when_rows_shrink(tmp_path, small_granule):
    """行を消すと索引の項目の数と値が変わる。独立に求めた索引（行の境界）と一致し、制御ブロックの F5・F6 もそれに合う。"""
    p = build_dp(tmp_path, n=120)
    old_u = parse_units(p.read_bytes())[1]
    got = positions_of(p, tmp_path)
    dst = tmp_path / "out" / "i.dmp"
    dst.parent.mkdir()
    remediate.rewrite_file(
        str(p), str(dst), "oracle_expdp", "delete_rows", select_positions(got["positions"]), None, str(p)
    )
    new_u = parse_units(dst.read_bytes())[1]
    assert len(new_u["index"]) < len(old_u["index"]) and new_u["index"][0] == 0
    check_unit_invariants(new_u, small_granule)
    starts = [0]
    for r in new_u["rows"]:
        starts.append(starts[-1] + len(r))
    assert all(v in starts for v in new_u["index"])  # 項目はどれも行の境界


def test_dp_records_and_job_db_have_no_raw_values(tmp_path, trash, small_granule):
    p = build_dp(tmp_path)
    svc, store, job = make_service(tmp_path, [p])
    r = run(svc, job, p, method="dummy", dummy_mode="same", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    db_files = glob.glob(str(tmp_path / "jobs.sqlite3*"))
    assert db_files and _leak(db_files, CUSTOMER_NEEDLES) == []
    for table in ("jobs", "files", "items", "findings", "remediations"):
        for row in store.query(f"SELECT * FROM {table}"):
            for v in tuple(row):
                if isinstance(v, str):
                    assert not any(n in v for n in CUSTOMER_NEEDLES), (table, v[:80])
    rec = store.remediations(job)[0]
    assert rec["method"] == "dummy" and rec["state"] == "applied" and rec["backup_path"] is None
    # 陽性対照: 生の値を入れたファイルなら、この探し方で見つかる（ごみ箱へ送った元のダンプ）
    assert _leak([str(f) for f in trash.files()], CUSTOMER_NEEDLES)


# ================================================================ 旧 exp: 文字セット・切れたダンプ・DDL の読み方・記録


def build_exp_sjis(tmp_path: Path) -> Path:
    """JA16SJIS（文字セット ID 832）の旧 exp。表名・列名・値は cp932。"""
    head = EXP_HEAD.replace(b"\x03\x03iEXPORT", b"\x03\x03@EXPORT")
    cols = [("ID", 2, 22), ("備考", 1, 100), ("氏名", 1, 100), ("メール", 1, 100)]
    rows = [
        [
            enc_number(i),
            f"メモ{i}".encode("cp932"),
            None if i % 5 == 0 else f"山田太郎{i}".encode("cp932"),
            None if i % 5 == 0 else f"user{i}@example.com".encode(),
        ]
        for i in range(1, 41)
    ]
    sec = exp_section("顧客", cols, rows, codec="cp932", csid=832)
    p = tmp_path / "src" / "sjis.dmp"
    p.parent.mkdir(exist_ok=True)
    p.write_bytes(exp_dump([sec], ["顧客"], head=head, codec="cp932"))
    return p


def sjis_expected() -> list[list]:
    return [
        [str(i), f"メモ{i}", None if i % 5 == 0 else f"山田太郎{i}", None if i % 5 == 0 else f"user{i}@example.com"]
        for i in range(1, 41)
    ]


def test_exp_cp932_all_methods(tmp_path):
    p = build_exp_sjis(tmp_path)
    _res, tables = read_dump(p)
    assert tables[0][1] == sjis_expected()
    needles = [f"山田太郎{i}" for i in range(1, 41) if i % 5] + [f"user{i}@example.com" for i in range(1, 41) if i % 5]

    dst, st = rewrite(p, tmp_path, "delete_rows")
    _r, t = read_dump(dst)
    assert t[0][1] == [r for r in sjis_expected() if int(r[0]) % 5 == 0] and st["rows"] == 32
    assert _leak([str(dst)], needles) == []

    dst, st = rewrite(p, tmp_path, "dummy", mode="fixed")
    _r, t = read_dump(dst)
    for old, new in zip(sjis_expected(), t[0][1]):
        assert new[:2] == old[:2] and (new[2:] == old[2:] if old[2] is None else new[2:] == ["＊＊＊", "＊＊＊"])
    assert _leak([str(dst)], needles) == []

    dst, st = rewrite(p, tmp_path, "delete_columns")
    _r, t = read_dump(dst)
    assert t[0][0] == ["ID", "備考"] and t[0][1] == [[r[0], r[1]] for r in sjis_expected()]
    data = dst.read_bytes()
    assert 'CREATE TABLE "顧客" ("ID" NUMBER, "備考" VARCHAR2(100))'.encode("cp932") in data

    dst, st = rewrite(p, tmp_path, "delete_table")
    assert "顧客".encode("cp932") not in dst.read_bytes()


def test_exp_truncated_dump_cannot_be_rewritten(tmp_path):
    """途中で切れたダンプは、位置を最後まで集められないので、中身を書き換えない（ファイルの削除だけ）。"""
    p = build_exp(tmp_path)
    cut = tmp_path / "src" / "cut.dmp"
    cut.write_bytes(p.read_bytes()[: len(p.read_bytes()) // 3])
    svc, store, job = make_service(tmp_path, [cut])
    a = analyze(svc, job, cut)
    for m in ("delete_rows", "delete_columns", "dummy", "delete_table"):
        assert not a.info["methods"][m]["available"] and "Oracle のダンプ" in a.info["methods"][m]["reason"]
        assert "ファイルの削除" in a.info["methods"][m]["reason"]
    assert a.info["methods"]["delete_file"]["available"]


def test_exp_analysis_lists_methods_and_preview_warns_to_check_with_imp(tmp_path):
    p = build_exp(tmp_path)
    svc, store, job = make_service(tmp_path, [p])
    a = analyze(svc, job, p)
    assert all(
        a.info["methods"][m]["available"]
        for m in ("delete_rows", "delete_columns", "dummy", "delete_table", "delete_file")
    )
    assert a.info["layout"] == "oracle_exp"
    assert "顧客" in a.view()["sheets"] and "商品" not in a.view()["sheets"]  # 対象にする表（検出のある表だけ）
    pv = svc.preview(job, str(p), {"method": "delete_rows", "confidences": ALL_RANKS})
    text = "\n".join(pv["warnings"] + pv["notes"])
    assert "imp" in text and "確かめ" in text and "元の場所へ戻して" in text and pv["sample_rows"][0] == "顧客: 1 行目"
    assert "統計" in text  # 書き換えた表の統計を取り除く旨
    pv = svc.preview(job, str(p), {"method": "delete_columns", "confidences": ALL_RANKS})
    assert pv["sample_cols"][0].startswith("顧客.") and "外部キー" in "\n".join(pv["warnings"] + pv["notes"])
    pv = svc.preview(job, str(p), {"method": "dummy", "dummy_mode": "same", "confidences": ALL_RANKS})
    assert "1900 年代" in "\n".join(pv["warnings"] + pv["notes"]) and "欄" in pv["summary"]
    pv = svc.preview(job, str(p), {"method": "delete_table", "confidences": ALL_RANKS})
    assert "すべて消えます" in "\n".join(pv["warnings"] + pv["notes"]) and pv["changes"]["table_names"] == ["顧客"]


def test_dp_preview_warns_about_size_statistics_and_imp(tmp_path, small_granule):
    p = build_dp(tmp_path)
    svc, store, job = make_service(tmp_path, [p])
    analyze(svc, job, p)
    pv = svc.preview(job, str(p), {"method": "dummy", "dummy_mode": "same", "confidences": ALL_RANKS})
    text = "\n".join(pv["warnings"] + pv["notes"])
    assert "impdp" in text and "ファイルの大きさは変わりません" in text and "EXCLUDE=STATISTICS" in text
    assert "SYS_EXPORT_SCHEMA_01" not in repr(pv)  # マスターテーブルは対象に出ない


def test_exp_records_and_job_db_have_no_raw_values(tmp_path, trash):
    p = build_exp(tmp_path)
    svc, store, job = make_service(tmp_path, [p])
    r = run(svc, job, p, method="dummy", dummy_mode="same", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    db_files = glob.glob(str(tmp_path / "jobs.sqlite3*"))
    assert db_files and _leak(db_files, CUSTOMER_NEEDLES) == []
    for table in ("jobs", "files", "items", "findings", "remediations"):
        for row in store.query(f"SELECT * FROM {table}"):
            for v in tuple(row):
                if isinstance(v, str):
                    assert not any(n in v for n in CUSTOMER_NEEDLES), (table, v[:80])
    rec = store.remediations(job)[0]
    assert rec["method"] == "dummy" and rec["state"] == "applied" and rec["backup_path"] is None
    assert not any(n in json_text(rec) for n in CUSTOMER_NEEDLES)
    assert _leak([str(f) for f in trash.files()], CUSTOMER_NEEDLES)  # 陽性対照: ごみ箱へ送った元のダンプには値がある


def json_text(obj) -> str:
    import json

    return json.dumps(obj, ensure_ascii=False, default=str)


@pytest.mark.parametrize("kind,nth", [("rename", 1), ("rename", 2), ("state", 3)])
def test_exp_crash_during_commit_is_recovered(tmp_path, monkeypatch, trash, kind, nth):
    """確定の手順は T2-a と同じ。どの段で落ちても、元か新が元の名前（か「対処前」の名前）で残る。"""
    from test_remediate import SimulatedCrash, crash_after, run_until_crash

    p = build_exp(tmp_path)
    original = p.read_bytes()
    svc, store, job = make_service(tmp_path, [p])
    if kind == "rename":
        crash_after(monkeypatch, remediate, "_fs_rename", nth)
    else:
        crash_after(monkeypatch, store, "update_remediation", nth)
    with pytest.raises(SimulatedCrash):
        run_until_crash(svc, job, p, {"method": "delete_rows", "confidences": ALL_RANKS})
    monkeypatch.undo()
    monkeypatch.setattr(remediate, "send_to_recycle_bin", trash)
    monkeypatch.setattr(remediate, "has_recycle_bin", lambda path: True)
    remediate.RemedyService(store, runner_fn=remediate.inline_runner).recover()
    assert store.unfinished_remediations() == []
    final = p.read_bytes()
    if final != original:  # 新しい中身が入っていた: 読めて、該当の行が無い
        _res, tables = read_dump(p)
        assert tables[0][1] == [r for r in customer_expected() if int(r[0]) % 5 == 0]
    assert original in [final] + [f.read_bytes() for f in trash.files()]
    assert not new_tmp_files(p.parent) and not list(p.parent.glob("*対処前*"))


def test_unavailable_reasons_for_oracle_without_layout():
    """位置を集められなかった Oracle のダンプ（読み解けなかった・圧縮・暗号化）は、理由つきでファイルの削除だけ。"""
    info = {"status": "partial", "kind": "Oracle ダンプ（exp/expdp）", "layout": ""}
    for method in ("delete_rows", "delete_columns", "dummy", "delete_table"):
        reason = remediate.unsupported_reason(method, "x.dmp", info)
        assert "Oracle のダンプ" in reason and "ファイルの削除はできます" in reason
    assert remediate.unsupported_reason("delete_file", "x.dmp", info) == ""
    assert (
        remediate.file_only_reason("Oracle ダンプ（exp/expdp）") == ""
    )  # 中身の対処に対応したので、形式だけでは断らない


def test_split_create_columns_handles_defaults_with_commas_and_quotes():
    line = (
        'CREATE TABLE "T" ("A" NUMBER(10, 2), "B" VARCHAR2(10) DEFAULT \'x, (y)\', "C" DATE DEFAULT SYSDATE, "D""E" CHAR(2))'
        '  PCTFREE 10 TABLESPACE "USERS"\n'
    ).encode()
    prefix, elements, suffix = remedy_oracle._split_create_columns(line)
    assert prefix == b'CREATE TABLE "T" ('
    assert elements == [
        b'"A" NUMBER(10, 2)',
        b"\"B\" VARCHAR2(10) DEFAULT 'x, (y)'",
        b'"C" DATE DEFAULT SYSDATE',
        b'"D""E" CHAR(2)',
    ]
    assert suffix.startswith(b")  PCTFREE 10")


def test_cell_editor_fallbacks_keep_same_value_same_dummy_and_never_grow():
    maker = DummyMaker("same")
    cols = ["氏名"]
    ed = remedy_oracle.CellEditor(maker, cols, [1], ["utf-8"], [0], strict=True)
    raw = "山田太郎".encode()  # 12 バイト。「氏名_xxxxxxxx」(15 バイト) は収まらない → 同じバイト数の英数字
    a = ed.edit(0, raw, [(0, 4, "name")])
    assert a is not None and len(a) == len(raw) and re.fullmatch(rb"[0-9a-p]{12}", a)
    assert a == ed.edit(0, raw, [(0, 4, "name")])  # 同じ値は同じダミー
    assert a != ed.edit(0, "山田次郎".encode(), [(0, 4, "name")])
    assert ed.edit(0, b"ab", [(0, 2, "name")]) == b"**"  # 3 文字に満たない値は *
    assert maker.produced and a.decode() in maker.produced
    # 検出の無い部分は元のまま
    mixed = "連絡先: 090-1234-5678 です".encode()
    out = ed.edit(0, mixed, [(5, 18, "phone")])
    assert (
        out is not None
        and out.startswith("連絡先: ".encode())
        and out.endswith(" です".encode())
        and len(out) <= len(mixed)
    )
    # 数・日付は、元より長くならず、元の値と違う
    ned = remedy_oracle.CellEditor(maker, ["n"], [2], [None], [0], strict=True)
    nb = ned.edit(0, enc_number(12345678901), [(0, 11, "resident_code")])
    assert nb is not None and len(nb) <= len(enc_number(12345678901)) and nb != enc_number(12345678901)
    zero = ned.edit(
        0, enc_number(5), [(0, 1, "x")]
    )  # 1 桁の数も、元と違う（0 でない同じ桁数の数）か、元より長くならない
    assert zero is None or len(zero) <= len(enc_number(5))


def build_exp_two_pii_tables(tmp_path: Path) -> Path:
    """個人情報のある表が続けて 2 つ（顧客・会員）と、ない表（商品）。2 つ目の表の区画は、1 つ目の後ろの文のすぐ後ろに続く。"""
    cust = exp_section("顧客", CUSTOMER_COLS, [encode_customer(r) for r in customer_data(40)], customer_units())
    member = exp_section(
        "会員", CUSTOMER_COLS, [encode_customer(r) for r in customer_data(35)], exp_units("会員", {"氏名": b"x"})
    )
    items = exp_section("商品", ITEM_COLS, item_rows(), exp_units("商品", {"SKU": b"A-000"}))
    p = tmp_path / "src" / "two.dmp"
    p.parent.mkdir(exist_ok=True)
    p.write_bytes(exp_dump([cust, member, items], ["顧客", "会員", "商品"]))
    return p


@pytest.mark.parametrize("method", ["delete_rows", "dummy", "delete_columns", "delete_table"])
def test_exp_consecutive_pii_tables_are_all_rewritten(tmp_path, method):
    """表の後ろの文を作り直す表（書き換える表）のすぐ後ろに、次の表の区画が続いても、次の表も書き換える。"""
    p = build_exp_two_pii_tables(tmp_path)
    old = p.read_bytes()
    dst, st = rewrite(p, tmp_path, method, mode="same")
    new = dst.read_bytes()
    _res, tables = read_dump(dst)
    needles = [f"山田太郎{i}" for i in range(1, 41) if i % 5]
    assert _leak([str(dst)], needles) == []
    assert section_bytes(new, "商品") == section_bytes(old, "商品")
    if method == "delete_table":
        assert len(tables) == 1 and tables[0][0] == ["SKU", "名称"] and st["tables"] == 2
        return
    assert len(tables) == 3
    if method == "delete_rows":
        assert tables[0][1] == [r for r in customer_expected(40) if int(r[0]) % 5 == 0]
        assert tables[1][1] == [r for r in customer_expected(35) if int(r[0]) % 5 == 0] and st["rows"] == 32 + 28
    elif method == "dummy":
        for t, n in ((tables[0], 40), (tables[1], 35)):
            assert len(t[1]) == n and all(
                row[2] != old_row[2] for row, old_row in zip(t[1], customer_expected(n)) if old_row[2]
            )
    else:
        assert tables[0][0] == tables[1][0] == ["ID", "備考"] and tables[1][1] == [
            [r[0], r[1]] for r in customer_expected(35)
        ]
    assert b'ANALSTATS TS "' + "会員".encode() not in new and b'ANALSTATS TS "' + "顧客".encode() not in new


# ================================================================ 断る形・確定の手順・型の追加


def test_timestamp_columns_are_replaced_in_the_date_part_only():
    """TIMESTAMP（先頭の 7 バイトが日付・続きは小数部）は、日付の部分だけを置き換える。"""
    maker = DummyMaker("same")
    ed = remedy_oracle.CellEditor(maker, ["t"], [180], [None], [0], strict=True)
    raw = enc_date(1980, 1, 2, 3, 4, 5) + b"\x01\x02\x03\x04"
    new = ed.edit(0, raw, [(0, 10, "birthdate")])
    assert new is not None and len(new) == 11 and new[7:] == raw[7:] and new[4:7] == raw[4:7] and new[:4] != raw[:4]
    assert od.decode_date(new).startswith("19")


@pytest.mark.parametrize("kind", ["exp", "expdp"])
def test_compressed_or_encrypted_looking_dump_is_refused_with_reason(tmp_path, kind):
    """圧縮・暗号化された（表として読めず、ほとんどが乱数に見える）ダンプは、中身を書き換えない（ファイルの削除だけ）。"""
    rnd = random.Random(11)
    head = EXP_HEAD if kind == "exp" else b"\x05\x01M\x11" + b"\x00" * 60 + b"AL32UTF8" + b"\x00" * 64
    p = tmp_path / "src" / f"enc_{kind}.dmp"
    p.parent.mkdir()
    p.write_bytes(head + bytes(rnd.randrange(256) for _ in range(300000)))
    svc, store, job = make_service(tmp_path, [p])
    a = analyze(svc, job, p)
    shown = [m for m in ("delete_rows", "delete_columns", "dummy", "delete_table") if m in a.info["methods"]]
    assert {"delete_rows", "delete_columns", "dummy"} <= set(shown)  # 位置の無い形式でも、方法は理由つきで並ぶ
    for m in shown:
        assert not a.info["methods"][m]["available"]
        assert "ファイルの削除はできます" in a.info["methods"][m]["reason"]
    assert a.info["methods"]["delete_file"]["available"]


def test_dp_broken_header_is_not_touched_by_a_rewrite_that_finds_no_table(tmp_path):
    """読み取りが表を見つけられなかった（位置が無い）ダンプに、書き換えは何も当てない。"""
    p = tmp_path / "src" / "plain.dmp"
    p.parent.mkdir()
    p.write_bytes(b"\x05\x01M\x11" + b"\x00" * 4092 + "連絡先 090-1234-5678".encode() * 3)
    svc, store, job = make_service(tmp_path, [p])
    a = analyze(svc, job, p)
    assert not a.info["methods"]["delete_rows"]["available"] and not a.positions


def test_oracle_rewrite_goes_through_temp_file_and_commit_rewrite(tmp_path, monkeypatch, trash):
    """確定の手順は T2-a と同じ（一時の新ファイルを書く → fsync → 検査し直す → 記録に「始めた」→ 元を「対処前」の名前でごみ箱へ）。"""
    p = build_exp(tmp_path)
    svc, store, job = make_service(tmp_path, [p])
    from pii_checker.remedy_write import sha256_file

    orig_sha = sha256_file(str(p))
    seen = {}
    real_rewrite, real_commit, real_fsync = remediate.rewrite_file, remediate.commit_rewrite, remediate.fsync_path

    def spy_rewrite(src, dst, *a, **k):
        seen["dst"] = dst
        out = real_rewrite(src, dst, *a, **k)
        assert sha256_file(src) == orig_sha  # 書いている間、元は変わらない
        assert Path(dst).exists() and Path(dst).name.startswith(remediate.NEW_PREFIX)
        return out

    def spy_commit(store_, rid, path, plan, orig):
        seen["plan"] = plan
        assert sha256_file(path) == orig_sha and Path(plan["tmp_new"]).exists()  # 確定の前も、元は変わらない
        return real_commit(store_, rid, path, plan, orig)

    def spy_fsync(path):
        seen["fsync"] = path
        return real_fsync(path)

    monkeypatch.setattr(remediate, "rewrite_file", spy_rewrite)
    monkeypatch.setattr(remediate, "commit_rewrite", spy_commit)
    monkeypatch.setattr(remediate, "fsync_path", spy_fsync)
    r = run(svc, job, p, method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    plan = seen["plan"]
    assert plan["mode"] == "recycle" and plan["tmp_new"] == seen["dst"] == seen["fsync"]
    assert r["disposal"] == "recycle_bin" and "（対処前 " in r["pre_name"]
    assert [f.name for f in trash.files()] == [f"1-{r['pre_name']}"] and not new_tmp_files(p.parent)
    assert store.remediations(job)[0]["state"] == "applied"


def test_failed_rewrite_keeps_original_and_leaves_no_temp_file(tmp_path, monkeypatch, trash):
    p = build_dp(tmp_path)
    original = p.read_bytes()
    svc, store, job = make_service(tmp_path, [p])
    monkeypatch.setattr(remedy_oracle, "GRANULE", 12345)  # 索引の規則が元のダンプと合わない（作りの取り違え）→ 断る
    r = run(svc, job, p, method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "error" and "索引" in r["message"]
    assert p.read_bytes() == original and not trash.files() and not new_tmp_files(p.parent)
    assert store.remediations(job) == []


def test_compact_dummy_never_has_long_digit_runs():
    """列に収まらないときのダミーに数字が長く続かない（たまたまマイナンバー・電話番号として検出し直されないように）。"""
    from pii_checker import detectors

    assert break_digit_runs("ae86dc960221608970") == "ae86dc96022h60897g"
    assert break_digit_runs("12345") == "12345"
    assert break_digit_runs("123456789012") == "12345m78901i"
    # 実際に落ちた鍵（ダミーの中の 12 桁が検査数字まで合ってマイナンバーに当たった）でも、再検出しない
    maker = remedy_oracle._CompactMaker(DummyMaker("same", (8).to_bytes(4, "big") * 8), "utf-8")
    rng = random.Random(0)
    for _ in range(3000):
        value = "".join(rng.choice("0123456789abcdef山田") for _ in range(rng.randint(3, 40)))
        token = maker.make("name", value)
        assert not re.search(r"\d{6}", token), token
        assert not [h for h in detectors.detect(token) if h.pii_type in ("my_number", "phone", "credit_card")], token


def test_date_dummy_never_returns_the_original_date():
    """日付のダミーが元と同じ日付にならない（同じだと書き換えが飛ばされ、元の生年月日が残る）。1900 年代の全部の日付で確かめる。"""
    for mode in ("same", "fixed"):
        maker = DummyMaker(mode, b"k" * 32)
        for year in range(1900, 2000):
            for month in range(1, 13):
                for day in range(1, 29):
                    raw = bytes([year // 100 + 100, year % 100 + 100, month, day, 1, 1, 1])
                    out = remedy_oracle.date_dummy(maker, "birthdate", raw)
                    assert out[:4] != raw[:4], (mode, year, month, day)
                    assert out[4:] == raw[4:7]  # 時刻の部分は変えない

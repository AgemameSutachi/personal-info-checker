"""Parquet（列指向の表）を表として読む試験。

圧縮された parquet は生データ走査では中の文字を読めない。pyarrow で文字の列と見出し語の列を取り出して検査する。
pyarrow の無い環境では、今までどおり形式不明の生データ走査に任せる（落ちない・検査済みと言い切らない）。
"""

import zipfile

import pytest

from pii_checker import sniff
from pii_checker.engine import Blob, scan_file
from pii_checker.formats import misc
from pii_checker.models import ScanOptions, Status

pa = pytest.importorskip("pyarrow")
pq = pytest.importorskip("pyarrow.parquet")

LABEL = sniff.KIND_LABELS["parquet"]
N = 3000  # 1回に取り出す行の数（8192）を超えないが、行ごとの検出の数え方を確かめるのに十分な数


def _table():
    return pa.table(
        {
            "id": pa.array(range(N), pa.int64()),
            "メモ": pa.array([f"連絡先 taro{i}@example.com" if i % 100 == 7 else "なし" for i in range(N)]),
            "電話": pa.array(["090-1234-5678" if i == 5 else None for i in range(N)]),
            # 数で持つ番号の列（見出し語で読む）
            "マイナンバー": pa.array([123456789018 if i == 9 else 0 for i in range(N)], pa.int64()),
            # 見出し語に当たらない小さな整数・小数の列は読まない
            "賞金": pa.array([5000 + i for i in range(N)], pa.int64()),
            "体重": pa.array([480.5] * N, pa.float64()),
            "タグ": pa.array([["a", "山田太郎様"] if i == 3 else [] for i in range(N)], pa.list_(pa.string())),
        }
    )


def _write(p, compression="snappy", **kw):
    pq.write_table(_table(), str(p), compression=compression, **kw)


def _found(res):
    return {k: v for it in res.items for k, v in it.finding_counts.items()}


@pytest.mark.parametrize("compression", ["snappy", "zstd", "none"])
def test_parquet_is_read_as_table(tmp_path, compression):
    p = tmp_path / "people.parquet"
    _write(p, compression)
    res = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path)))
    top = res.items[0]
    assert top.kind == LABEL and top.status == Status.SCANNED, (top.kind, top.status, top.notes)
    found = _found(res)
    assert found.get("email") == N // 100 + (1 if N % 100 > 7 else 0), found
    assert found.get("phone") == 1 and found.get("my_number") == 1, found
    assert "parquet の表" in top.method and f"{N} 行" in top.method
    # 見出し語に当たらない数の列は読まなかったと書く
    assert any("読んでいない" in n for n in top.notes), top.notes


def test_parquet_location_names_row_and_column(tmp_path):
    p = tmp_path / "people.parquet"
    _write(p)
    res = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path)))
    locs = [f.location for it in res.items for f in it.findings if f.pii_type == "phone"]
    assert locs == ["6行目 列「電話」"], locs


def test_parquet_inside_zip_is_read(tmp_path):
    src = tmp_path / "people.parquet"
    _write(src)
    z = tmp_path / "a.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.write(src, "data/people.parquet")
    res = scan_file(str(z), ScanOptions(temp_dir=str(tmp_path)))
    inner = [it for it in res.items if it.kind == LABEL]
    assert inner and inner[0].status == Status.SCANNED
    assert _found(res).get("phone") == 1


def test_broken_parquet_is_uncheckable_not_scanned(tmp_path):
    """頭と尾は PAR1 だが中の定義が壊れている: 落ちず、検査不能と理由を出す。"""
    p = tmp_path / "broken.parquet"
    p.write_bytes(b"PAR1" + b"\x00" * 200 + b"\x10\x00\x00\x00" + b"PAR1")
    res = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path)))
    top = res.items[0]
    assert top.kind == LABEL and top.status == Status.UNCHECKABLE, (top.status, top.reason)
    assert "parquet" in top.reason


def test_truncated_parquet_is_not_parquet_kind(tmp_path):
    """途中で切れて尾の PAR1 が無いものは parquet と決めつけない（形式不明の生データ走査に回す）。"""
    src = tmp_path / "people.parquet"
    _write(src, "none")
    p = tmp_path / "cut.parquet"
    p.write_bytes(src.read_bytes()[:-100])
    res = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path)))
    top = res.items[0]
    assert top.kind != LABEL and top.status != Status.SCANNED


def test_text_starting_with_par1_is_still_text(tmp_path):
    """陽性対照: PAR1 で始まるだけのテキストは parquet にしない。"""
    p = tmp_path / "memo.txt"
    p.write_text("PAR1 の部品表\n山田太郎,090-1234-5678\n", encoding="utf-8")
    res = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path)))
    assert res.items[0].kind == sniff.KIND_LABELS["text"] and _found(res).get("phone") == 1


def test_without_pyarrow_falls_back_to_raw_sweep(monkeypatch):
    from pii_checker.formats import parquet

    monkeypatch.setattr(parquet, "available", lambda: False)
    assert sniff.handler_for("parquet") is misc.handle_unknown
    monkeypatch.setattr(parquet, "available", lambda: True)
    assert sniff.handler_for("parquet") is parquet.handle_parquet


def test_sniff_needs_both_magics():
    assert (
        sniff.sniff(Blob(display="x", data=b"PAR1" + b"\x00" * 64 + (40).to_bytes(4, "little") + b"PAR1")) == "parquet"
    )
    assert sniff.sniff(Blob(display="x", data=b"PAR1" + b"\x01" * 64)) != "parquet"
    # 定義の長さが 0・ファイルより大きいものは parquet にしない
    assert sniff.sniff(Blob(display="x", data=b"PAR1" + b"\x00" * 64 + b"\x00\x00\x00\x00PAR1")) != "parquet"
    assert (
        sniff.sniff(Blob(display="x", data=b"PAR1" + b"\x00" * 64 + (999).to_bytes(4, "little") + b"PAR1")) != "parquet"
    )


def test_text_wrapped_in_par1_is_still_text(tmp_path):
    """PAR1 で始まり PAR1 で終わるテキスト（末尾に改行なし）も、テキストとして読む。"""
    p = tmp_path / "memo.txt"
    p.write_text("PAR1 部品表\n山田太郎,090-1234-5678\nPAR1", encoding="utf-8")
    res = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path)))
    assert res.items[0].kind == sniff.KIND_LABELS["text"] and _found(res).get("phone") == 1


def _scan_table(tmp_path, table, **kw):
    p = tmp_path / "t.parquet"
    pq.write_table(table, str(p), **kw)
    return scan_file(str(p), ScanOptions(temp_dir=str(tmp_path)))


def test_wide_int_column_without_header_word_is_read(tmp_path):
    """見出し語に当たらない名前でも、番号になりうる桁の整数の列は読む（小さな整数の列は読まない）。"""
    n = 100
    table = pa.table(
        {
            "c1": pa.array([123456789018 if i == 4 else 1000 + i for i in range(n)], pa.int64()),
            "c2": pa.array(range(n), pa.int32()),
        }
    )
    res = _scan_table(tmp_path, table)
    top = res.items[0]
    assert top.status == Status.SCANNED and _found(res).get("my_number") == 1, (top.method, _found(res))
    assert "1 列）" in top.method and any("1 列" in n for n in top.notes), (top.method, top.notes)


def test_cp932_bytes_are_read(tmp_path):
    table = pa.table({"b": pa.array(["山田太郎 090-1234-5678".encode("cp932"), b"\xff\xfe\x00"], pa.binary())})
    res = _scan_table(tmp_path, table)
    assert _found(res).get("phone") == 1
    # 文字として読めなかった値は、黙って捨てずに注記に数を出す
    table = pa.table({"b": pa.array([bytes([0x80, 0x81, 0xFF, 0x00])], pa.binary())})
    res = _scan_table(tmp_path, table)
    assert any("読めなかったバイト列の値が 1 件" in n for n in res.items[0].notes), res.items[0].notes


def test_dictionary_map_struct_and_date_columns(tmp_path):
    import datetime

    table = pa.table(
        {
            "区分": pa.array(["090-1234-5678", "a", "a"]).dictionary_encode(),
            "属性": pa.array([[("tel", "03-1234-5678")], [], []], pa.map_(pa.string(), pa.string())),
            "s": pa.array([{"マイナンバー": 123456789018}, {"マイナンバー": 0}, {"マイナンバー": 0}]),
            "生年月日": pa.array([datetime.date(1980, 1, 2)] * 3),
        }
    )
    res = _scan_table(tmp_path, table)
    found = _found(res)
    assert found.get("phone") == 2 and found.get("my_number") == 1, found
    assert found.get("birthdate"), found


def test_fixed_size_binary_number_is_read_but_hash_is_not(tmp_path):
    table = pa.table(
        {
            "k": pa.array([b"090123456789"], pa.binary(12)),
            "h": pa.array([b"0" * 32], pa.binary(32)),
        }
    )
    res = _scan_table(tmp_path, table)
    assert "1 列）" in res.items[0].method, res.items[0].method


def test_broken_row_group_is_partial(tmp_path):
    """途中の行グループが壊れているものは、読めたところまでを検査して一部だけ検査と出す（落ちない）。"""
    p = tmp_path / "t.parquet"
    pq.write_table(_table(), str(p), compression="none", row_group_size=1000)
    data = bytearray(p.read_bytes())
    md = pq.ParquetFile(str(p)).metadata
    start = md.row_group(2).column(1).data_page_offset
    data[start : start + 64] = b"\xff" * 64
    p.write_bytes(bytes(data))
    res = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path)))
    top = res.items[0]
    assert top.status == Status.PARTIAL and "残りの行だけを検査" in top.reason, (top.status, top.reason)
    assert _found(res).get("phone") == 1  # 1つ目の行グループの分は検査した
    assert _found(res).get("email", 0) >= 20  # 壊れた行グループの先も検査した


def test_row_limit_is_partial(tmp_path):
    p = tmp_path / "people.parquet"
    _write(p)
    res = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path), max_rows_per_table=6))
    top = res.items[0]
    assert top.status == Status.PARTIAL and "上限（6 行）" in top.reason
    assert _found(res).get("phone") == 1 and not _found(res).get("email")
    # 上限ちょうどの行数なら一部だけにしない
    res = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path), max_rows_per_table=N))
    assert res.items[0].status == Status.SCANNED

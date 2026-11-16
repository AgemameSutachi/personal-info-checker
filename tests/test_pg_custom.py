"""PostgreSQL の custom 形式（pg_dump -Fc）・データファイル本体・Oracle ダンプの理由の文の試験（formats/dbdump.py）。

custom 形式は本物の pg_dump が書く二進の代わりに、読む側が見る並び（頭の PGDMP と版・整数の幅・
「COPY 表 (列…) FROM stdin;」・データ部 BLK_DATA＋dumpId＋長さつきの塊の並び＋長さ 0）だけを持つ作り物。
pg_restore はこの PC に無い前提で、使う道は差し替えて試す。番号・名前はすべて架空。
"""

from __future__ import annotations

import io
import random
import subprocess
import zlib
from types import SimpleNamespace

import pytest

from pii_checker import engine
from pii_checker.engine import PartialScan, Uncheckable
from pii_checker.formats import dbdump
from pii_checker.models import ScanOptions, Status

ROWS = "1\t山田 太郎\t090-1234-5678\n2\t佐藤 花子\t\\N\n\\.\n"
COPY_MEMBERS = b"COPY public.members (id, name, phone) FROM stdin;"


def _int(v: int, size: int = 4) -> bytes:
    """custom 形式の整数（符号の1バイト＋絶対値の little endian）。"""
    return (b"\x01" if v < 0 else b"\x00") + abs(v).to_bytes(size, "little")


def _block(dump_id: int, chunks: list[bytes], size: int = 4) -> bytes:
    """データ部 1 個（BLK_DATA・dumpId・長さつきの塊の並び・終わりの長さ 0）。"""
    return b"\x01" + _int(dump_id, size) + b"".join(_int(len(c), size) + c for c in chunks) + _int(0, size)


def _dump(copies: list[bytes], blocks: list[bytes], size: int = 4) -> bytes:
    head = b"PGDMP" + bytes([1, 14, 0, size, 8, 1])
    toc = b"".join(b"\x00\x00" + c + b"\x00\x00" for c in copies)
    return head + b"\xff" * 32 + toc + b"\xff" * 8 + b"".join(blocks)


def _no_pg_restore(monkeypatch):
    monkeypatch.setattr(dbdump, "find_pg_restore", lambda: None)


def _scan(tmp_path, name: str, data: bytes):
    tmp = tmp_path / "tmp"
    tmp.mkdir(parents=True, exist_ok=True)
    p = tmp_path / name
    p.write_bytes(data)
    return engine.scan_file(str(p), ScanOptions(temp_dir=str(tmp)))


def _item(tmp_path, data: bytes, name: str = "db.dump"):
    return _scan(tmp_path, name, data).items[0]


def test_zlib_block_is_read_with_column_names(tmp_path, monkeypatch):
    """zlib で圧縮したデータ部を展開し、toc の COPY の列名で場所を示す。"""
    _no_pg_restore(monkeypatch)
    item = _item(tmp_path, _dump([COPY_MEMBERS], [_block(7, [zlib.compress(ROWS.encode())])]))
    assert item.status == Status.SCANNED, item.reason
    assert item.kind == "PostgreSQL ダンプ（custom 形式）"
    assert "データ部 1 個を展開（列名つき 1 個）" in item.method, item.method
    locations = {f.location for f in item.findings}
    assert "表「public.members」1行目 列「phone」" in locations, locations


def test_zlib_stream_split_over_chunks(tmp_path, monkeypatch):
    """1 つの zlib の流れが複数の塊に分かれていても、つないで展開する。"""
    _no_pg_restore(monkeypatch)
    z = zlib.compress(ROWS.encode())
    item = _item(tmp_path, _dump([COPY_MEMBERS], [_block(7, [z[:5], z[5:11], z[11:]])]))
    assert item.status == Status.SCANNED, item.reason
    assert "phone" in item.finding_counts


def test_uncompressed_blocks_of_two_tables(tmp_path, monkeypatch):
    """圧縮なし（-Z0）のデータ部が 2 個あれば、COPY と順に対応づける。8 バイトの整数の版も読む。"""
    _no_pg_restore(monkeypatch)
    copies = [COPY_MEMBERS, b"COPY public.staff (no, mail) FROM stdin;"]
    blocks = [
        _block(7, [ROWS.encode()], size=8),
        _block(8, ["1\tyamada@example.com\n\\.\n".encode()], size=8),
    ]
    item = _item(tmp_path, _dump(copies, blocks, size=8))
    assert item.status == Status.SCANNED, item.reason
    assert "列名つき 2 個" in item.method, item.method
    locations = {f.location for f in item.findings}
    assert "表「public.members」1行目 列「phone」" in locations, locations
    assert "表「public.staff」1行目 列「mail」" in locations, locations


def test_block_count_mismatch_falls_back_to_plain_lines(tmp_path, monkeypatch):
    """COPY の数とデータ部の数が合わないときは列名を当てず、「データN」の本文として検査する。"""
    _no_pg_restore(monkeypatch)
    blocks = [_block(7, [zlib.compress(ROWS.encode())]), _block(8, [zlib.compress(b"x\t1\n")])]
    item = _item(tmp_path, _dump([COPY_MEMBERS], blocks))
    assert item.status == Status.SCANNED, item.reason
    assert "データ部 2 個を展開（列名つき 0 個）" in item.method, item.method
    assert "phone" in item.finding_counts
    assert all(f.location.startswith("データ1") for f in item.findings if f.pii_type == "phone"), [
        f.location for f in item.findings
    ]


def test_unsupported_compression_is_partial(tmp_path, monkeypatch):
    """lz4・zstd のような未対応の圧縮のデータ部があれば、読めた分を検査して一部だけの検査にする。"""
    _no_pg_restore(monkeypatch)
    lz4_like = b"\x04\x22\x4d\x18" + bytes(range(60, 120))
    blocks = [_block(7, [zlib.compress(ROWS.encode())]), _block(8, [lz4_like])]
    item = _item(tmp_path, _dump([COPY_MEMBERS], blocks))
    assert item.status == Status.PARTIAL, (item.status, item.reason)
    assert "データ部 1 個は未対応の圧縮" in item.reason, item.reason
    assert "pg_restore を入れると全部読める" in item.reason, item.reason
    assert "phone" in item.finding_counts


def test_broken_zlib_only_is_uncheckable(tmp_path, monkeypatch):
    """zlib の頭なのに展開できないデータ部しか無ければ、表の中身を検査していないので検査不能にする。"""
    _no_pg_restore(monkeypatch)
    item = _item(tmp_path, _dump([COPY_MEMBERS], [_block(7, [b"\x78\x9c" + b"\xff" * 30])]))
    assert item.status == Status.UNCHECKABLE, (item.status, item.reason)
    assert "表 1 個の中身を検査していない" in item.reason, item.reason
    assert "PostgreSQL を入れて再検査してください" in item.reason, item.reason


def test_no_data_block_with_copy_is_uncheckable_but_strings_scanned(tmp_path, monkeypatch):
    """データ部が見つからないのに表がある（COPY がある）なら検査不能。読める文字だけは拾う。"""
    _no_pg_restore(monkeypatch)
    data = _dump([COPY_MEMBERS], []) + "連絡先 090-1234-5678".encode()
    item = _item(tmp_path, data)
    assert item.status == Status.UNCHECKABLE, (item.status, item.reason)
    assert "データ部を見つけられず、表 1 個" in item.reason, item.reason
    assert "phone" in item.finding_counts


def test_definition_only_dump_is_partial(tmp_path, monkeypatch):
    """COPY もデータ部も無い（表の定義だけの）ダンプは、文字だけを検査した一部の検査にする。"""
    _no_pg_restore(monkeypatch)
    item = _item(tmp_path, _dump([], []) + b"CREATE TABLE t (a int);")
    assert item.status == Status.PARTIAL, (item.status, item.reason)
    assert "表の定義だけのダンプの可能性" in item.reason, item.reason


def test_bad_lengths_are_skipped(tmp_path, monkeypatch):
    """長さが大きすぎる・負・ファイルの外へはみ出す塊の並びは読み飛ばし、後ろの正しいデータ部を読む。"""
    _no_pg_restore(monkeypatch)
    huge = b"\x01" + _int(5) + _int(1 << 27) + b"zz"  # 最初の長さが上限を超える
    negative = b"\x01" + _int(6) + _int(3) + b"abc" + _int(-2)  # 2 つ目の長さが負
    overrun = b"\x01" + _int(4) + _int(3) + b"abc" + _int(1 << 20)  # 2 つ目の長さがファイルの外まで届く
    good = _block(7, [zlib.compress(ROWS.encode())])
    item = _item(tmp_path, _dump([COPY_MEMBERS], [huge, negative, overrun, good]))
    assert item.status == Status.SCANNED, item.reason
    assert "データ部 1 個を展開" in item.method, item.method
    assert "表「public.members」1行目 列「phone」" in {f.location for f in item.findings}


def _fake_collector():
    """add_records・add_lines に渡された行・本文を溜めるだけの受け皿。"""
    col = SimpleNamespace(records=[], lines=[])
    col.add_records = lambda columns, rows, loc, method: col.records.append(list(rows))
    col.add_lines = lambda text, location_prefix, method: col.lines.append(text)
    return col


def test_expanded_size_limit_is_partial(monkeypatch):
    """展開した中身が上限を超えたら、そこまでを検査した一部の検査にする（圧縮爆弾でメモリを食い潰さない）。"""
    col = _fake_collector()
    big = ("1\t" + "あ" * 50 + "\n") * 2000
    data = _dump([COPY_MEMBERS], [_block(7, [zlib.compress(big.encode())])])
    monkeypatch.setattr(dbdump, "READ_ALL_LIMIT", 4096)
    with pytest.raises(PartialScan) as e:
        dbdump._scan_pg_custom_bytes(data, col, SimpleNamespace(method=""))
    assert "大きすぎる" in str(e.value)
    assert "pg_restore を入れると全部を少しずつ読める" in str(e.value)
    assert col.records and len(col.records[0]) < 2000  # 上限までは読んでいる


def test_zlib_cut_inside_block_is_partial():
    """塊の長さは合っているのに zlib の流れが終わりの印の前で切れていたら、読めた分を検査して一部だけの検査にする。"""
    col = _fake_collector()
    z = zlib.compress(ROWS.encode())
    data = _dump([COPY_MEMBERS], [_block(7, [z[: len(z) // 2]])])
    with pytest.raises(PartialScan) as e:
        dbdump._scan_pg_custom_bytes(data, col, SimpleNamespace(method=""))
    assert "データ部 1 個は圧縮の途中で切れていて、読めた分だけを検査した" in str(e.value), str(e.value)
    assert col.records, "読めた分を検査していない"


# ------------------------------------------------------------------ pg_restore の道


def _fake_pg_restore(monkeypatch, tmp_path, *, returncode=0, sql="", stderr=b""):
    exe = tmp_path / "bin" / "pg_restore.exe"
    calls = []

    def run(args, **kw):
        calls.append(args)
        assert args[0] == str(exe) and args[1] == "-f"
        if returncode == 0:
            with open(args[2], "w", encoding="utf-8") as f:
                f.write(sql)
        return subprocess.CompletedProcess(args, returncode, b"", stderr)

    monkeypatch.setattr(dbdump, "find_pg_restore", lambda: str(exe))
    # 標準の subprocess そのものは差し替えず、dbdump から見える subprocess だけを替える（ほかの呼び出しを巻き込まない）
    fake = SimpleNamespace(run=run, DEVNULL=subprocess.DEVNULL, CompletedProcess=subprocess.CompletedProcess)
    monkeypatch.setattr(dbdump, "subprocess", fake)
    return calls


SQL = "COPY public.members (id, name, phone) FROM stdin;\n" + ROWS


def test_pg_restore_success_reads_sql(tmp_path, monkeypatch):
    """pg_restore があれば SQL へ戻して、COPY の列名つきで読む。"""
    calls = _fake_pg_restore(monkeypatch, tmp_path, sql=SQL)
    item = _item(tmp_path, _dump([COPY_MEMBERS], []))
    assert calls, "pg_restore を呼んでいない"
    assert item.status == Status.SCANNED, item.reason
    assert item.method.startswith("pg_restore で SQL に戻して読み取り"), item.method
    assert "COPY 1 件" in item.method, item.method
    assert any(f.location.startswith("表「public.members」") for f in item.findings), [
        f.location for f in item.findings
    ]


def test_pg_restore_large_output_scanned_in_pieces(tmp_path, monkeypatch):
    """戻した SQL が大きいときはメモリへ丸ごと読まず、入れ子の検査として少しずつ読む。"""
    _fake_pg_restore(monkeypatch, tmp_path, sql=SQL)
    monkeypatch.setattr(dbdump, "READ_ALL_LIMIT", 16)
    res = _scan(tmp_path, "db.dump", _dump([COPY_MEMBERS], []))
    assert "大きいため少しずつ" in res.items[0].method, res.items[0].method
    nested = [it for it in res.items if "pg_restore で戻した SQL" in it.path]
    assert nested, [it.path for it in res.items]
    assert "phone" in nested[0].finding_counts


def test_pg_restore_failure_falls_back_to_own_parser(tmp_path, monkeypatch):
    """pg_restore が失敗したら、その出力の末尾を補足に残して、自前の読み方へ切り替える。"""
    _fake_pg_restore(monkeypatch, tmp_path, returncode=1, stderr="pg_restore: エラー: 版が新しすぎる".encode())
    item = _item(tmp_path, _dump([COPY_MEMBERS], [_block(7, [zlib.compress(ROWS.encode())])]))
    assert item.status == Status.SCANNED, item.reason
    assert any("pg_restore で戻せなかった" in n and "版が新しすぎる" in n for n in item.notes), item.notes
    assert "custom 形式を解いて" in item.method, item.method


def test_find_pg_restore_prefers_path_then_newest_install(monkeypatch):
    """PATH にあればそれを、無ければ C:\\Program Files\\PostgreSQL の下の一番新しい版を使う。"""
    monkeypatch.setattr(dbdump.shutil, "which", lambda name: "X:/pg/pg_restore.exe")
    assert dbdump.find_pg_restore() == "X:/pg/pg_restore.exe"
    monkeypatch.setattr(dbdump.shutil, "which", lambda name: None)
    # 文字の順では 9.6 が 17 より後ろになるが、数で比べて 17 を選ぶ
    found = [
        r"C:\Program Files\PostgreSQL\15\bin\pg_restore.exe",
        r"C:\Program Files\PostgreSQL\17\bin\pg_restore.exe",
        r"C:\Program Files\PostgreSQL\9.6\bin\pg_restore.exe",
    ]
    monkeypatch.setattr(dbdump.glob, "glob", lambda pattern: list(found))
    assert dbdump.find_pg_restore() == found[1]
    monkeypatch.setattr(dbdump.glob, "glob", lambda pattern: [])
    assert dbdump.find_pg_restore() is None


# ------------------------------------------------------------------ データファイル本体


def test_db_datafile_strings_are_partial(tmp_path):
    """内部形式の分からないデータファイルは、文字列の値だけを検査した一部の検査にする。"""
    data = b"\x00" * 512 + "氏名 山田 太郎 電話 090-1234-5678".encode() + b"\x00" * 512
    item = _item(tmp_path, data, name="sales.mdf")
    assert item.status == Status.PARTIAL, (item.status, item.reason)
    assert item.method == "データファイルの文字列走査"
    assert "内部形式を解釈できないため文字列の値だけを検査した" in item.reason, item.reason
    assert "phone" in item.finding_counts


def test_db_datafile_mostly_encrypted_is_uncheckable(tmp_path):
    """区画の多くが圧縮・暗号化されていそうなデータファイルは、文字を取り出せないので検査不能にする。"""
    item = _item(tmp_path, random.Random(0).randbytes(256 * 1024), name="sales.ibd")  # 毎回同じ乱数の並び
    assert item.status == Status.UNCHECKABLE, (item.status, item.reason)
    assert "圧縮・暗号化されていて文字を取り出せない" in item.reason, item.reason
    assert "DB に戻して（復元・起動して）" in item.reason, item.reason


# ------------------------------------------------------------------ Oracle ダンプの理由の文


def _oracle(monkeypatch, **res):
    from pii_checker.formats import oracle_dump

    base = dict(
        chunks_total=0,
        chunks_high=0,
        row_bytes=0,
        total_bytes=0,
        tables=1,
        rows=3,
        failed=[],
        unsupported_cols={},
        truncated=[],
        gap_nonzero=0,
    )
    base.update(res)
    monkeypatch.setattr(oracle_dump, "scan_oracle_tables", lambda f, col, kind, head: SimpleNamespace(**base))
    blob = SimpleNamespace(open=lambda: io.BytesIO(b"\x03\x00EXPORT:V19.00.00" + bytes(64)))
    item = SimpleNamespace(method="")
    return blob, item


def test_oracle_reasons_list_failed_tables_and_unsupported_types(monkeypatch):
    """表として読み解けなかった表・未対応の型の列を、上限の数まで並べて理由に書く。"""
    failed = [f"T{i}" for i in range(7)]
    blob, item = _oracle(monkeypatch, failed=failed, unsupported_cols={"T0.PHOTO": "BLOB", "T0.GEO": "SDO_GEOMETRY"})
    with pytest.raises(PartialScan) as e:
        dbdump.handle_oracle_dump(None, blob, item, None, 0)
    msg = str(e.value)
    assert "旧 exp" in msg, msg
    assert "読み解けず文字列の走査に切り替えた表がある（T0、T1、T2、T3、T4 ほか 2 件）" in msg, msg
    assert "未対応の型の列は文字列の走査だけで検査した（T0.PHOTO（BLOB）、T0.GEO（SDO_GEOMETRY））" in msg, msg
    assert "表 1 個・3 行" in item.method, item.method


def test_oracle_all_read_has_no_reason(monkeypatch):
    """全部の表を読めたら理由を付けない（検査済み）。"""
    blob, item = _oracle(monkeypatch)
    dbdump.handle_oracle_dump(None, blob, item, None, 0)
    assert "Oracle ダンプ（旧 exp）を表ごとに読み取り" in item.method, item.method


# ------------------------------------------------------------------ SQL 文の細かい枝


def test_split_top_level_keeps_escaped_quote_and_brackets():
    """引用符の中の \\' と、角括弧で囲んだ名前の中のコンマでは分けない。"""
    items = dbdump.split_top_level(r"a varchar(5) DEFAULT 'x\',y', [b,c] int, d int")
    assert [s.strip() for s in items] == [r"a varchar(5) DEFAULT 'x\',y'", "[b,c] int", "d int"]


def test_sql_many_other_lines_and_unterminated_statements(tmp_path):
    """本文の行が多いときは区切って検査し、; の無い CREATE TABLE・INSERT がファイルの終わりで切れても読む。"""
    body = "\n".join(f"-- コメント {i}" for i in range(450))
    sql = (
        body
        + "\n-- 担当 090-1111-2222\n"
        + "CREATE TABLE members (id int, name text, phone text)\n"
        + "\n".join(f"-- 続き {i}" for i in range(3))
    )
    item = _item(tmp_path, sql.encode(), name="a.sql")
    assert "phone" in item.finding_counts, item.method
    sql2 = "CREATE TABLE members (id int, name text, phone text);\nINSERT INTO members VALUES (1, '山田', '090-1234-5678'),\n(2, '佐藤', NULL)"
    item2 = _item(tmp_path / "b", sql2.encode(), name="b.sql")
    assert "INSERT 1 文" in item2.method, item2.method
    assert "表「members」INSERT（2行目〜）1件目 列「phone」" in {f.location for f in item2.findings}

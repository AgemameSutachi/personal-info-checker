"""評価で見つかった境目（巨大な pg_dump のデータファイル・「;」の無い CREATE・特殊なパスの DB・古い途中経過）の試験。"""

from __future__ import annotations

import os

from pii_checker import engine
from pii_checker.formats import dbdump, misc
from pii_checker.models import ItemResult, ScanOptions, Status
from pii_checker.store import Store

DAT = "1\t山田 太郎\t090-1234-5678\n2\t佐藤 花子\t\\N\n\\.\n"


def _scan_dat(tmp_path, monkeypatch, limit=None):
    if limit is not None:
        monkeypatch.setattr(misc, "TEXT_READ_ALL_LIMIT", limit)
    p = tmp_path / "3001.dat"
    p.write_bytes(DAT.encode("utf-8"))
    ctx = engine.ScanContext(str(p), ScanOptions(temp_dir=str(tmp_path)), [])
    ctx.pg_columns["3001.dat"] = ("public.members", ["id", "name", "phone"])
    item = ItemResult(path=str(p), kind="テキスト", status=Status.PENDING)
    col = engine.Collector(item, 20)
    misc.handle_text(ctx, engine.Blob(display=str(p), path=str(p)), item, col, 0)
    return item


def test_huge_pg_dat_keeps_column_names(tmp_path, monkeypatch):
    """丸ごと読む上限を超えた pg_dump のデータファイルも、toc.dat の列名つきで読む（丸ごと読んだときと同じ場所で拾う）。"""
    whole = _scan_dat(tmp_path, monkeypatch)
    huge = _scan_dat(tmp_path, monkeypatch, limit=10)
    assert "少しずつ" in huge.method and "toc.dat" in huge.method
    assert sorted(f.location for f in huge.findings) == sorted(f.location for f in whole.findings)
    assert dict(huge.finding_counts) == dict(whole.finding_counts)
    assert "表「public.members」1行目 列「phone」" in {f.location for f in huge.findings}


def test_create_without_semicolon_does_not_swallow_copy():
    """「;」で終わらない CREATE の後ろの COPY を本文として飲み込まず、列名つきで読む。"""
    lines = [
        "CREATE TABLE members (id int, name text, phone text)",
        "COPY public.members (id, name, phone) FROM stdin;",
        "1\t山田 太郎\t090-1234-5678",
        "\\.",
    ]
    item = ItemResult(path="x.sql", kind="", status=Status.PENDING)
    col = engine.Collector(item, 20)
    dbdump.scan_sql_lines(iter(lines), col, item)
    assert "COPY 1 件" in item.method
    assert "表「public.members」データ1行目（3行目） 列「phone」" in {f.location for f in item.findings}


def test_iter_query_with_percent_in_path(tmp_path):
    """DB のパスに % があっても、レポート用の読み取り専用の接続で開ける。"""
    d = tmp_path / "a%41b#c"
    d.mkdir()
    store = Store(str(d / "jobs.sqlite3"))
    job = store.create_job([str(tmp_path)], ScanOptions(temp_dir=str(tmp_path)))
    rows = list(store.iter_query("SELECT id FROM jobs WHERE id=?", (job,)))
    assert len(rows) == 1


def test_stale_checkpoint_is_not_reused(tmp_path):
    """前の検査が残した途中経過は、次の検査の始めに片付ける（今回の分として読ませない）。"""
    p = tmp_path / "a.txt"
    p.write_text("会議の議事録\n", encoding="utf-8")
    opts = ScanOptions(temp_dir=str(tmp_path))
    ck = engine.checkpoint_path(opts, str(p))
    with open(ck, "wb") as f:
        f.write(b"stale")
    engine.scan_file(str(p), opts)
    assert not os.path.exists(ck)
    assert engine.read_checkpoint(ck) is None

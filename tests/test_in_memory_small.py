"""小さなファイルを一時フォルダへ写さずにメモリで検査する（safeio.read_small・engine.DIRECT_READ_LIMIT）の試験。

写す読み方（DIRECT_READ_LIMIT=0）と結果がまったく同じであること、写しも一時フォルダも作らないこと、
読み方の約束（最終アクセス日時・読む間の書き換え・クラウドの代替ファイル）を snapshot と同じに守ることを確かめる。
個人情報はすべて架空。
"""

import gzip
import hashlib
import io
import os
import sqlite3
import tempfile
import time
import zipfile

import pytest

from pii_checker import engine, safeio
from pii_checker.engine import scan_file
from pii_checker.models import ScanOptions

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows の共有モード・最終アクセス日時の試験")

TEXT = "氏名 山田 太郎 メール taro.yamada@example.com 電話 090-1234-5678 マイナンバー 123456789018\n"


def _samples(folder) -> list[str]:
    """形式の違う小さなファイル（中で外部の道具や実ファイルを要るものを含む）。"""
    folder.mkdir()
    paths = []

    p = folder / "memo.txt"
    p.write_text(TEXT * 3, encoding="utf-8")
    paths.append(p)

    p = folder / "list.csv"
    p.write_text("氏名,メール\n山田 太郎,taro.yamada@example.com\n佐藤 花子,hanako@example.com\n", encoding="utf-8")
    paths.append(p)

    p = folder / "pack.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("inner/memo.txt", TEXT)
        z.writestr("inner/list.csv", "メール\ntaro.yamada@example.com\n")
    paths.append(p)

    p = folder / "log.txt.gz"
    p.write_bytes(gzip.compress(TEXT.encode("utf-8")))
    paths.append(p)

    p = folder / "people.db"
    con = sqlite3.connect(p)
    con.execute("CREATE TABLE people(name TEXT, email TEXT)")
    con.execute("INSERT INTO people VALUES ('山田 太郎', 'taro.yamada@example.com')")
    con.commit()
    con.close()
    paths.append(p)

    p = folder / "with_stream.txt"
    p.write_text("ふつうの文\n", encoding="utf-8")
    with open(str(p) + ":secret", "w", encoding="utf-8") as f:
        f.write(TEXT)
    paths.append(p)
    return [str(x) for x in paths]


def _norm(res) -> list:
    """比べる中身（項目のパス・種類・状態・理由・件数・注記）と元の SHA-256。"""
    items = [
        (
            i.path,
            i.kind,
            i.status.value,
            i.reason,
            sorted(i.finding_counts.items()),
            sorted(i.conf_counts.items()),
            list(i.notes),
        )
        for i in res.items
    ]
    return [items, (res.source or {}).get("sha256"), sorted((res.distinct_counts or {}).items())]


def test_same_results_as_copying(tmp_path, monkeypatch):
    """メモリで読んでも、写して読んだときと結果が同じ（外部の道具に渡す形式は、その時だけ書き出す）。"""
    paths = _samples(tmp_path / "src")
    opt = ScanOptions(temp_dir=str(tmp_path / "tmp"))
    os.makedirs(opt.temp_dir)
    in_memory = [_norm(scan_file(p, opt)) for p in paths]
    monkeypatch.setattr(engine, "DIRECT_READ_LIMIT", 0)  # 全部写す（直す前と同じ読み方）
    copied = [_norm(scan_file(p, opt)) for p in paths]
    assert in_memory == copied
    # 陽性対照: 仕込んだ値をちゃんと見つけている（両方とも空で一致、を防ぐ）
    for p, r in zip(paths, in_memory):
        assert any(counts for _, _, _, _, counts, _, _ in r[0]), p
    assert os.listdir(opt.temp_dir) == []  # どちらの読み方でも片付けている


def test_small_text_makes_no_temp_folder(tmp_path, monkeypatch):
    """ふつうの小さな文のファイルでは、写しも一時フォルダも作らない。"""
    src = tmp_path / "a.txt"
    src.write_text(TEXT, encoding="utf-8")
    made = []
    real = tempfile.mkdtemp
    monkeypatch.setattr(tempfile, "mkdtemp", lambda *a, **k: made.append(1) or real(*a, **k))
    res = scan_file(str(src), ScanOptions(temp_dir=str(tmp_path)))
    assert res.items[0].status.value == "scanned"
    assert res.source["sha256"] == hashlib.sha256(src.read_bytes()).hexdigest()
    assert made == []
    # 陽性対照: 上限を超える大きさなら今までどおり写す（一時フォルダを作る）
    monkeypatch.setattr(engine, "DIRECT_READ_LIMIT", 10)
    scan_file(str(src), ScanOptions(temp_dir=str(tmp_path)))
    assert made


def test_read_small_returns_data_and_identity(tmp_path):
    data = os.urandom(safeio.CHUNK + 7)  # 読む単位を1回またぐ
    src = tmp_path / "a.bin"
    src.write_bytes(data)
    info, got = safeio.read_small(str(src), safeio.CHUNK * 2)
    assert got == data
    assert info.sha256 == hashlib.sha256(data).hexdigest()
    assert info.size == len(data) and info.file_id
    assert safeio.stat_identity(str(src)).same_as(info)
    assert safeio.read_small(str(src), len(data) - 1) is None  # 上限を超えれば何も読まない
    info, got = safeio.read_small(str(src), len(data))  # ちょうど上限は読む
    assert got == data
    empty = tmp_path / "e.bin"
    empty.write_bytes(b"")
    info, got = safeio.read_small(str(empty), 10)
    assert got == b"" and info.size == 0


def test_read_small_keeps_access_time(tmp_path):
    src = tmp_path / "a.bin"
    src.write_bytes(os.urandom(4096))
    old = time.time() - 3 * 86400
    os.utime(src, (old, os.stat(src).st_mtime))
    info, _ = safeio.read_small(str(src), 1 << 20)
    assert info.atime_kept is True
    assert abs(os.stat(src).st_atime - old) < 2
    # 陽性対照: 普通に読むと最終アクセス日時が進む（OS が更新を止めている環境では確かめられない）
    with open(src, "rb") as f:
        f.read()
    if abs(os.stat(src).st_atime - old) < 2:
        pytest.skip("この環境は最終アクセス日時を更新しない設定（陽性対照が取れない）")


def test_read_small_detects_change_while_reading(tmp_path, monkeypatch):
    src = tmp_path / "a.bin"
    src.write_bytes(b"abc" * 100)
    real = safeio._handle_info
    calls = {"n": 0}

    def flaky(h):
        info = real(h)
        calls["n"] += 1
        if calls["n"] % 2 == 0:  # 読み終えた後の情報だけ毎回ずらす
            info.change_ns += 1
        return info

    monkeypatch.setattr(safeio, "_handle_info", flaky)
    with pytest.raises(safeio.ChangedWhileReading):
        safeio.read_small(str(src), 1 << 20)
    assert calls["n"] == 6  # 3回読んで3回とも変わっていた
    res = scan_file(str(src), ScanOptions(temp_dir=str(tmp_path)))
    assert res.items[0].status.value == "uncheckable" and "書き換えられた" in res.items[0].reason


def test_cloud_placeholder_is_not_read_in_memory(tmp_path, monkeypatch):
    """クラウドの代替ファイルは、メモリで読む道でも中身を読まず、写す道と同じ理由で断る。"""
    src = tmp_path / "a.txt"
    src.write_text(TEXT, encoding="utf-8")
    real = safeio._handle_info
    reads = []
    real_read = safeio._read_chunk

    def offline(h):
        info = real(h)
        info.attributes |= safeio.FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
        return info

    monkeypatch.setattr(safeio, "_handle_info", offline)
    monkeypatch.setattr(safeio, "_read_chunk", lambda h, buf: reads.append(1) or real_read(h, buf))
    assert safeio.read_small(str(src), 1 << 20) is None
    res = scan_file(str(src), ScanOptions(temp_dir=str(tmp_path)))
    assert reads == []
    assert res.items[0].status.value == "uncheckable" and "代替ファイル" in res.items[0].reason


def test_neighbors_still_copied(tmp_path, monkeypatch):
    """隣のファイルを一緒に読むもの（分割アーカイブの続き）は、メモリで読まずに今までどおり写す。"""
    src = tmp_path / "a.7z.002"
    src.write_bytes(b"\x00" * 64)
    called = []
    monkeypatch.setattr(safeio, "read_small", lambda *a, **k: called.append(a) or None)
    res = scan_file(str(src), ScanOptions(temp_dir=str(tmp_path)))
    assert called == []
    assert res.items[0].status.value in ("uncheckable", "out_of_scope")
    # 陽性対照: ふつうの名前ならメモリで読みに行く
    plain = tmp_path / "a.txt"
    plain.write_bytes(b"x")
    scan_file(str(plain), ScanOptions(temp_dir=str(tmp_path)))
    assert called


def test_top_file_keeps_its_name_for_external_tools(tmp_path):
    """メモリで読んだ元のファイルを外部の道具へ渡すときは、写したときと同じ元の名前で書き出す。

    7-Zip は書庫の名前から中身の名前を決める（rep.csv.Z の中身は rep.csv）ので、仮の名前だと項目のパスと
    拡張子が変わる（評価の指摘・2026-11-15）。
    """
    top = str(tmp_path / "rep.csv.Z")
    ctx = engine.ScanContext(top, ScanOptions(temp_dir=str(tmp_path)), [])
    try:
        p = ctx.blob_as_path(engine.Blob(display=top, data=b"abc", name_hint="rep.csv.Z"))
        assert os.path.basename(p) == "rep.csv.Z" and open(p, "rb").read() == b"abc"
        # 内側の項目は今までどおり仮の名前（拡張子は保つ）
        q = ctx.blob_as_path(engine.Blob(display=top + "!in.csv", data=b"x", name_hint="in.csv"))
        assert q.endswith(".csv") and os.path.basename(q) != "in.csv"
    finally:
        ctx.cleanup()


def test_memory_blob_reads_like_file(tmp_path):
    """メモリの中身でも、形式の判定に使う先頭・大きさ・拡張子が実ファイルと同じに見える。"""
    data = TEXT.encode("utf-8")
    p = tmp_path / "x.csv"
    p.write_bytes(data)
    a = engine.Blob(display=str(p), path=str(p), name_hint="x.csv")
    b = engine.Blob(display=str(p), data=data, name_hint="x.csv")
    assert (a.size, a.head(16), a.ext, a.read_all()) == (b.size, b.head(16), b.ext, b.read_all())
    assert io.BytesIO(data).read() == b.open().read()

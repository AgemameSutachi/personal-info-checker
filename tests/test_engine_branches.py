"""engine の網羅で通っていなかった分岐の試験（T4・2026-11-07）。

読み取りの失敗を「検査不能」に振り分ける分岐・大きすぎて簡易検査に回したあとの失敗・NTFS の隠しストリーム（代替データストリーム）の検査。
"""

import errno
import os

import pytest

from pii_checker import engine, safeio, sniff
from pii_checker.models import ScanOptions, Status

PHONE = "090-1234-5678"


def _scan(tmp_path, name="a.txt", text="会議の議題\n", **opts):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return engine.scan_file(str(p), ScanOptions(temp_dir=str(tmp_path), **opts))


def _types(res):
    return {k for it in res.items for k in it.finding_counts}


def _raising_handler(monkeypatch, error):
    def handler(ctx, blob, item, collector, depth):
        raise error

    monkeypatch.setattr(sniff, "handler_for", lambda kind: handler)


@pytest.mark.parametrize(
    "error, words",
    [
        (PermissionError(13, "拒否"), "アクセスが拒否された"),
        (FileNotFoundError(2, "無い"), "ファイルが見つからない"),
        (OSError(errno.ENOSPC, "No space left on device"), "ドライブが満杯"),
        (ValueError("想定外の中身"), "読み取り中にエラー（ValueError: 想定外の中身）"),
    ],
)
def test_read_failures_are_uncheckable_with_reason(tmp_path, monkeypatch, error, words):
    """読み取りの途中の失敗は、種類に応じた理由つきの「検査不能」として必ず残る（検査済みと言い切らない）。"""
    _raising_handler(monkeypatch, error)
    top = _scan(tmp_path).items[0]
    assert top.status == Status.UNCHECKABLE
    assert words in top.reason


def test_unexpected_error_reason_names_the_place(tmp_path, monkeypatch):
    """想定外の失敗の理由には、どこで起きたか（ファイル名:行）を添える（利用者の報告から直せるように）。"""
    _raising_handler(monkeypatch, KeyError("x"))
    top = _scan(tmp_path).items[0]
    assert "test_engine_branches.py:" in top.reason


def test_too_deep_nesting_is_uncheckable(tmp_path):
    """入れ子の段の上限を超えたら、中身を開かずに「検査不能」（zip 爆弾の類で止まらない）。"""
    res = _scan(tmp_path, max_depth=-1)
    assert res.items[0].status == Status.UNCHECKABLE
    assert "入れ子が深すぎる" in res.items[0].reason


def test_sweep_failure_after_too_large_is_uncheckable(tmp_path, monkeypatch):
    """大きすぎて簡易検査（文字列の走査）に回したのに、その走査も失敗したら「簡易検査」ではなく「検査不能」。"""
    from pii_checker import textdecode

    monkeypatch.setattr(engine, "READ_ALL_LIMIT", 10)
    for error, words in ((MemoryError(), "メモリ不足で失敗した"), (OSError("壊れた"), "走査も失敗した（OSError")):

        def broken(read, error=error):
            raise error
            yield  # 生成器にする

        monkeypatch.setattr(textdecode, "iter_strings_chunked", broken)
        top = _scan(tmp_path, "big.html", "<html><body>" + "<p>あいうえお</p>" * 20 + "</body></html>").items[0]
        assert top.status == Status.UNCHECKABLE, top.reason
        assert words in top.reason


def _streams_supported(path) -> bool:
    try:
        with open(str(path) + ":probe", "w", encoding="utf-8") as f:
            f.write("x")
    except OSError:
        return False
    return True


windows_only = pytest.mark.skipif(os.name != "nt", reason="代替データストリームは Windows の NTFS だけ")


@windows_only
def test_alternate_stream_is_scanned_as_own_item(tmp_path):
    """本体に何も無くても、隠しストリーム（a.txt:secret）に書いた電話番号を別の項目として拾う。"""
    src = tmp_path / "a.txt"
    src.write_text("会議の議題\n", encoding="utf-8")
    if not _streams_supported(src):
        pytest.skip("一時フォルダのボリュームが代替データストリームを持てない")
    with open(str(src) + ":secret", "w", encoding="utf-8") as f:
        f.write(f"電話 {PHONE}\n")
    with open(str(src) + ":Zone.Identifier", "w", encoding="utf-8") as f:
        f.write(f"[ZoneTransfer]\nZoneId=3\n電話 {PHONE}\n")  # ダウンロードの印は検査しない
    res = engine.scan_file(str(src), ScanOptions(temp_dir=str(tmp_path)))
    by_path = {i.path: i for i in res.items}
    # _streams_supported が確かめに作った :probe も隠しストリームの1つなので、別の項目として検査される
    assert set(by_path) == {str(src), str(src) + ":probe", str(src) + ":secret"}
    secret = by_path[str(src) + ":secret"]
    assert secret.depth == 1 and secret.status == Status.SCANNED
    assert "phone" in secret.finding_counts
    assert "phone" not in by_path[str(src)].finding_counts  # 本体には無い


@windows_only
def test_alternate_stream_copy_failure_is_kept(tmp_path, monkeypatch):
    """隠しストリームだけ写せなかったときは、その項目を「検査不能」で残し、本体の検査は続ける。"""
    src = tmp_path / "a.txt"
    src.write_text(f"電話 {PHONE}\n", encoding="utf-8")
    if not _streams_supported(src):
        pytest.skip("一時フォルダのボリュームが代替データストリームを持てない")
    real = safeio.snapshot

    def snapshot(path, *args, **kwargs):
        if path.endswith(":probe"):
            raise OSError(None, "共有違反", path, 32)
        return real(path, *args, **kwargs)

    monkeypatch.setattr(safeio, "snapshot", snapshot)
    res = engine.scan_file(str(src), ScanOptions(temp_dir=str(tmp_path)))
    by_path = {i.path: i for i in res.items}
    assert by_path[str(src)].status == Status.SCANNED and "phone" in by_path[str(src)].finding_counts
    failed = by_path[str(src) + ":probe"]
    assert failed.depth == 1 and failed.status == Status.UNCHECKABLE
    assert not res.network_lost


def _context(tmp_path):
    top = tmp_path / "outer.zip"
    top.write_bytes(b"")
    return engine.ScanContext(str(top), ScanOptions(temp_dir=str(tmp_path)), [])


def test_large_nested_item_is_spilled_to_temp_file(tmp_path, monkeypatch):
    """メモリに置くには大きい内側のファイルは、一時フォルダへ書き出してから検査する（中身は同じに読める）。"""
    monkeypatch.setattr(engine, "IN_MEMORY_LIMIT", 10)
    data = f"電話 {PHONE}\n".encode("utf-8")
    ctx = _context(tmp_path)
    try:
        item = ctx.scan_nested("outer.zip!inner.txt", data=data)
        assert item.status == Status.SCANNED, item.reason
        assert "phone" in item.finding_counts
        spilled = [os.path.join(ctx.tmpdir, n) for n in os.listdir(ctx.tmpdir) if n != engine.OWNER_MARK]
        assert [open(p, "rb").read() for p in spilled] == [data]
    finally:
        ctx.cleanup()


def test_large_nested_item_without_temp_space_is_uncheckable(tmp_path, monkeypatch):
    """書き出す空きが無ければ、その1件だけを理由つきの「検査不能」で残し、例外で残りの中身を止めない。"""
    monkeypatch.setattr(engine, "IN_MEMORY_LIMIT", 10)

    def short(folder, need, what="一時フォルダ"):
        raise safeio.TempSpaceShort("一時フォルダの空きが足りない")

    monkeypatch.setattr(safeio, "ensure_free", short)
    ctx = _context(tmp_path)
    try:
        item = ctx.scan_nested("outer.zip!inner.txt", data=b"x" * 20, depth=2)
        assert item.status == Status.UNCHECKABLE
        assert "空きが足りない" in item.reason
        assert (item.size, item.depth) == (20, 2)
        assert ctx.items == [item]
    finally:
        ctx.cleanup()


def test_blob_as_path_writes_memory_blob_with_extension(tmp_path):
    """外部の道具に渡すため、メモリ上の中身は拡張子つきの一時ファイルに書き出す（suffix の指定が優先）。"""
    ctx = _context(tmp_path)
    try:
        blob = engine.Blob(display="outer.zip!db/顧客.MDB", data=b"\x00\x01Standard Jet DB")
        p = ctx.blob_as_path(blob)
        assert p.endswith(".mdb") and os.path.dirname(p) == ctx.tmpdir
        assert open(p, "rb").read() == blob.data
        assert ctx.blob_as_path(blob, suffix=".accdb").endswith(".accdb")
    finally:
        ctx.cleanup()


def test_blob_as_path_returns_real_file_path(tmp_path):
    """実ファイルならそのパスを返す（書き出さない）。240文字以上なら Windows の長いパスの形にする。"""
    ctx = _context(tmp_path)
    short_path = str(tmp_path / "a.mdb")
    assert ctx.blob_as_path(engine.Blob(display=short_path, path=short_path)) == short_path
    long = str(tmp_path / ("d" * 120) / ("e" * 120) / "a.mdb")
    got = ctx.blob_as_path(engine.Blob(display=long, path=long))
    assert got == engine.long_path(long)
    if os.name == "nt":
        assert got.startswith("\\\\?\\")
    assert ctx._tmp is None  # 一時フォルダも作らない

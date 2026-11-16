"""検査先に影響を与えずに読む部品（safeio）の試験。"""

import hashlib
import os
import time

import pytest

from pii_checker import safeio

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows の共有モード・最終アクセス日時の試験")


def _make(tmp_path, data=b"abc" * 1000, name="a.bin"):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def test_snapshot_copies_and_hashes(tmp_path):
    data = os.urandom(3 * safeio.CHUNK + 123)
    src = _make(tmp_path, data)
    dest = str(tmp_path / "copy.bin")
    info = safeio.snapshot(src, dest, str(tmp_path))
    with open(dest, "rb") as f:
        assert f.read() == data
    assert info.sha256 == hashlib.sha256(data).hexdigest()
    assert info.size == len(data)
    assert info.mtime_ns == os.stat(src).st_mtime_ns
    assert info.file_id
    same = safeio.stat_identity(src)
    assert same.same_as(info)


def test_open_does_not_block_others(tmp_path):
    """こちらが開いている間も、他の人の書き込み・改名（上書き保存）・削除ができる。"""
    src = _make(tmp_path)
    h, _ = safeio._open_shared(src)
    f = safeio._fd_from_handle(h)
    try:
        with open(src, "ab") as g:
            g.write(b"more")
        os.replace(src, src + ".renamed")
        os.replace(src + ".renamed", src)
        os.remove(src)
    finally:
        f.close()
    assert not os.path.exists(src)


def test_python_open_blocks_rename(tmp_path):
    """陽性対照: 普通の open() で開いていると改名できない（この試験が守っていることの前提）。"""
    src = _make(tmp_path)
    with open(src, "rb"):
        with pytest.raises(PermissionError):
            os.replace(src, src + ".renamed")


def test_access_time_kept(tmp_path):
    src = _make(tmp_path, os.urandom(4096))
    old = time.time() - 3 * 86400
    os.utime(src, (old, os.stat(src).st_mtime))
    safeio.snapshot(src, str(tmp_path / "c1"), str(tmp_path))
    assert abs(os.stat(src).st_atime - old) < 2

    # 陽性対照: 普通に読むと最終アクセス日時が進む（OS が更新を止めている環境では確かめられない）
    with open(src, "rb") as f:
        f.read()
    if abs(os.stat(src).st_atime - old) < 2:
        pytest.skip("この環境は最終アクセス日時を更新しない設定（陽性対照が取れない）")


def test_changed_while_reading(tmp_path, monkeypatch):
    src = _make(tmp_path)
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
        safeio.snapshot(src, str(tmp_path / "c"), str(tmp_path))
    assert calls["n"] == 6  # 3回読んで3回とも変わっていた


def test_cloud_placeholder_not_read(tmp_path, monkeypatch):
    src = _make(tmp_path)
    real = safeio._handle_info

    def offline(h):
        info = real(h)
        info.attributes |= safeio.FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
        return info

    monkeypatch.setattr(safeio, "_handle_info", offline)
    with pytest.raises(safeio.CloudPlaceholder):
        safeio.snapshot(src, str(tmp_path / "c"), str(tmp_path))
    assert not os.path.exists(tmp_path / "c")


def test_temp_space_short(tmp_path, monkeypatch):
    src = _make(tmp_path)
    monkeypatch.setattr(safeio, "free_bytes", lambda folder: 10)
    with pytest.raises(safeio.TempSpaceShort) as e:
        safeio.snapshot(src, str(tmp_path / "c"), str(tmp_path))
    assert "空きが足りない" in str(e.value)


def test_is_disk_full():
    assert safeio.is_disk_full(OSError(28, "No space left on device"))
    e = OSError()
    e.winerror = 112
    assert safeio.is_disk_full(e)
    assert not safeio.is_disk_full(OSError(2, "not found"))


def _hold_exclusive(path):
    """他のプログラムが共有なしで開いている状態を作る（Access・PST 等の排他）。"""
    h = safeio._k32.CreateFileW(path, safeio.GENERIC_READ, 0, None, safeio.OPEN_EXISTING, 0, None)
    assert h not in (None, safeio.INVALID_HANDLE)
    return h


def test_exclusive_open_is_in_use_not_permission(tmp_path):
    """排他で開かれているファイルは「使用中」と分かる理由で断る（「権限がない」と出すと権限を直しに行かせてしまう）。"""
    from pii_checker.engine import scan_file
    from pii_checker.models import ScanOptions

    src = _make(tmp_path, "マイナンバー: 123456789018\n".encode("utf-8"), "used.txt")
    h = _hold_exclusive(src)
    try:
        with pytest.raises(safeio.SourceInUse):
            safeio.snapshot(src, str(tmp_path / "copy.bin"), str(tmp_path))
        res = scan_file(src, ScanOptions(temp_dir=str(tmp_path)))
    finally:
        safeio._k32.CloseHandle(h)
    item = res.items[0]
    assert item.status.value == "uncheckable"
    assert "使用中" in item.reason and "権限がない" not in item.reason
    # 使い回しの判定（OSError だけを受ける）でも落ちない
    assert isinstance(safeio.SourceInUse("x"), OSError)


def test_range_lock_is_in_use_not_permission(tmp_path):
    """一部を範囲ロックされたファイル（開けるが読む途中で拒否される）も「使用中」と分かる理由で断る。"""
    import msvcrt

    from pii_checker.engine import scan_file
    from pii_checker.models import ScanOptions

    src = _make(tmp_path, "マイナンバー: 123456789018\n".encode("utf-8") * 10, "locked.txt")
    holder = open(src, "r+b")
    try:
        msvcrt.locking(holder.fileno(), msvcrt.LK_NBLCK, os.path.getsize(src))
        try:
            with pytest.raises(safeio.SourceInUse):
                safeio.snapshot(src, str(tmp_path / "copy.bin"), str(tmp_path))
            res = scan_file(src, ScanOptions(temp_dir=str(tmp_path)))
        finally:
            holder.seek(0)
            msvcrt.locking(holder.fileno(), msvcrt.LK_UNLCK, os.path.getsize(src))
    finally:
        holder.close()
    item = res.items[0]
    assert item.status.value == "uncheckable"
    assert "使用中" in item.reason and "権限がない" not in item.reason
    # 陽性対照: ロックを外せば読める
    res2 = scan_file(src, ScanOptions(temp_dir=str(tmp_path)))
    assert res2.items[0].status.value == "scanned"


@pytest.mark.parametrize(
    "code, expect_in_use, expect_network",
    [(33, True, False), (23, False, False), (30, False, False), (64, False, True), (5, False, False)],
)
def test_read_errors_keep_their_cause(tmp_path, monkeypatch, code, expect_in_use, expect_network):
    """読む途中の失敗は元の番号で見分ける（ディスクの故障を「使用中」、回線断を別のものと取り違えない）。"""
    from pii_checker.engine import _source_failure

    src = _make(tmp_path, b"x" * 100, "a.txt")

    def failing(h, buf):
        raise safeio.read_error(code)  # 番号の振り分けは本物を通す

    real = safeio._read_chunk
    monkeypatch.setattr(safeio, "_read_chunk", failing)
    with pytest.raises(Exception) as ei:
        safeio.snapshot(src, str(tmp_path / "copy.bin"), str(tmp_path))
    e = ei.value
    assert isinstance(e, safeio.SourceInUse) is expect_in_use
    assert safeio.is_network_lost(e) is expect_network
    reason = _source_failure(src, e).reason
    assert ("使用中" in reason) is expect_in_use
    monkeypatch.setattr(safeio, "_read_chunk", real)
    # 陽性対照: 本物の ReadFile で読める
    info = safeio.snapshot(src, str(tmp_path / "copy2.bin"), str(tmp_path))
    assert info.size == 100 and (tmp_path / "copy2.bin").read_bytes() == b"x" * 100


def test_server_that_updates_access_time_is_reported(tmp_path, monkeypatch):
    """保つ指示を出してもサーバーが読み取りで最終アクセス日時を更新したら（Samba）、保てなかったと記録する。"""
    from pii_checker.engine import scan_file
    from pii_checker.models import ScanOptions

    src = _make(tmp_path, "マイナンバー: 123456789018\n".encode("utf-8"), "a.txt")
    real = safeio._handle_info
    calls = {"n": 0}

    def moving(h):
        info = real(h)
        calls["n"] += 1
        info.atime_ns += calls["n"]  # 読むたびに日時が進むサーバー
        return info

    monkeypatch.setattr(safeio, "_handle_info", moving)
    info = safeio.snapshot(src, str(tmp_path / "c.bin"), str(tmp_path))
    assert info.atime_kept is False and info.atime_lost_reason == "server_updated"
    res = scan_file(src, ScanOptions(temp_dir=str(tmp_path)))
    assert any("サーバーが最終アクセス日時" in n for n in res.items[0].notes)
    monkeypatch.undo()
    # 陽性対照: 手元の NTFS では保てる
    info = safeio.snapshot(src, str(tmp_path / "d.bin"), str(tmp_path))
    assert info.atime_kept is True and info.atime_lost_reason == ""


def test_unknown_disk_space_does_not_block(tmp_path, monkeypatch):
    """空き容量を問い合わせられないドライブ（一部の共有など）では、空きは分からないものとして写しを止めない。"""

    def no_usage(folder):
        raise OSError(1, "not supported")

    monkeypatch.setattr(safeio.shutil, "disk_usage", no_usage)
    assert safeio.free_bytes(str(tmp_path)) == 1 << 62
    assert safeio.reserve_bytes(str(tmp_path)) == safeio.MIN_FREE_BYTES
    safeio.ensure_free(str(tmp_path), 10 * 1024**3)  # 断らない
    src = _make(tmp_path)
    info = safeio.snapshot(src, str(tmp_path / "c"), str(tmp_path))
    assert info.size == os.path.getsize(src)


def _deny_write_attributes(monkeypatch):
    """属性を書く権限が無い開き方（読み取り専用の共有など）を作る。読み取りだけなら開ける。"""
    real = safeio._open_handle

    def opener(path, access, flags):
        if access & safeio.FILE_WRITE_ATTRIBUTES:
            raise PermissionError(5, "アクセスが拒否されました")
        return real(path, access, flags)

    monkeypatch.setattr(safeio, "_open_handle", opener)


def test_no_write_attribute_permission_is_reported(tmp_path, monkeypatch):
    """属性を書けない場所では読み取りだけで開いて検査し、最終アクセス日時は「権限が無く保てなかった」と記録する。"""
    data = os.urandom(5000)
    src = _make(tmp_path, data)
    _deny_write_attributes(monkeypatch)
    info = safeio.snapshot(src, str(tmp_path / "c"), str(tmp_path))
    assert info.atime_kept is False and info.atime_lost_reason == "no_permission"
    assert (tmp_path / "c").read_bytes() == data
    small = safeio.read_small(src, 1 << 20)
    assert small is not None and small[1] == data
    assert small[0].atime_kept is False and small[0].atime_lost_reason == "no_permission"
    hashed = safeio.hash_file(src)
    assert hashed.sha256 == hashlib.sha256(data).hexdigest() and hashed.atime_lost_reason == "no_permission"
    monkeypatch.undo()
    # 陽性対照: 属性を書けるときは保てる
    info = safeio.snapshot(src, str(tmp_path / "d"), str(tmp_path))
    assert info.atime_kept is True and info.atime_lost_reason == ""


def test_read_head_shared_reads_only_the_head_and_closes(tmp_path):
    """隣のファイルの先頭だけを読む。読み終えたら閉じている（共有なしで開き直せる）。"""
    data = os.urandom(10_000)
    src = _make(tmp_path, data)
    assert safeio.read_head_shared(src, 100) == data[:100]
    assert safeio.read_head_shared(src, 1 << 20) == data
    safeio._k32.CloseHandle(_hold_exclusive(src))  # 開いたままなら共有なしでは開けない


def test_read_small_gives_up_when_file_grows_while_reading(tmp_path, monkeypatch):
    """読む前は小さかったのに読む間に limit を超えたら、読み直さずにすぐ None（写すほうで扱う）。"""
    src = _make(tmp_path, b"x" * 5000)
    real = safeio._handle_info
    calls = {"n": 0}

    def small_before(h):
        info = real(h)
        calls["n"] += 1
        if calls["n"] == 1:
            info.size = 10  # 読む前は 10 バイトだった
        return info

    monkeypatch.setattr(safeio, "_handle_info", small_before)
    assert safeio.read_small(src, 100) is None
    assert calls["n"] == 2  # 1回読んだだけで諦めた（読み直して同じファイルを何度も読まない）
    monkeypatch.undo()
    # 陽性対照: 大きくならなければ読める
    got = safeio.read_small(src, 10_000)
    assert got is not None and got[1] == b"x" * 5000


def test_hash_file_does_not_read_cloud_placeholder(tmp_path, monkeypatch):
    """クラウドの代替ファイルは中身を読まず None（読むとダウンロードが起きる）。呼び戻してよいときだけ読む。"""
    src = _make(tmp_path)
    real_info = safeio._handle_info
    real_read = safeio._read_chunk
    reads = []

    def offline(h):
        info = real_info(h)
        info.attributes |= safeio.FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
        return info

    def counting(h, buf):
        reads.append(1)
        return real_read(h, buf)

    monkeypatch.setattr(safeio, "_handle_info", offline)
    monkeypatch.setattr(safeio, "_read_chunk", counting)
    assert safeio.hash_file(src) is None
    assert reads == []
    # 陽性対照: 呼び戻してよいと言われたときは読む
    assert safeio.hash_file(src, allow_recall=True).sha256 == hashlib.sha256(b"abc" * 1000).hexdigest()
    assert reads


def test_hash_file_changed_while_reading(tmp_path, monkeypatch):
    """読む間に書き換えられ続けたら、読み直しを重ねたうえで ChangedWhileReading。"""
    src = _make(tmp_path)
    real = safeio._handle_info
    calls = {"n": 0}

    def flaky(h):
        info = real(h)
        calls["n"] += 1
        if calls["n"] % 2 == 0:  # 読み終えた後の情報だけ毎回ずらす
            info.mtime_ns += 1
        return info

    monkeypatch.setattr(safeio, "_handle_info", flaky)
    with pytest.raises(safeio.ChangedWhileReading):
        safeio.hash_file(src)
    assert calls["n"] == 6  # 3回読んで3回とも変わっていた


def test_is_network_lost_sees_wrapped_cause():
    """接続方式の回線断（NetworkLost）は、ほかの例外に包まれていても回線断と分かる。"""
    assert safeio.is_network_lost(safeio.NetworkLost("切れた"))
    try:
        try:
            raise safeio.NetworkLost("切れた")
        except safeio.NetworkLost as inner:
            raise safeio.SourceError("読めなかった") from inner
    except safeio.SourceError as outer:
        assert safeio.is_network_lost(outer)
    gone = OSError()
    gone.winerror = 2  # ファイルが無い（回線断ではない）
    assert not safeio.is_network_lost(gone)
    assert not safeio.is_network_lost(safeio.SourceError("ほかの理由"))


def test_file_id_128_of_missing_file_is_empty(tmp_path):
    """開けないファイルの 128bit の ID は空（呼び出し側は 64bit の識別子に戻す）。"""
    assert safeio.file_id_128(str(tmp_path / "missing.bin")) == ""
    fid = safeio.file_id_128(_make(tmp_path))
    assert fid == "" or [len(p) for p in fid.split("-")] == [16, 32]

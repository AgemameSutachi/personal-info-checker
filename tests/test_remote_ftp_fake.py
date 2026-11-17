"""FTP の辿り方（ftp_walk）と使い回しの接続（_pooled_call）の分かれ道を、偽の FTP で試す。

本物のサーバー（pyftpdlib）では起こしにくい失敗（フォルダの数の上限・深さの上限・ファイルの大きさが取れない・
回線断・つなぎ直しの失敗）を、一覧を返す部品を差し替えて起こす。
"""

import ftplib
import socket

import pytest

from pii_checker import remote, safeio


def _conn(**kw):
    d = {"kind": "ftp", "host": "192.0.2.10", "user": "taro", "start_dir": "/r"}
    d.update(kw)
    return remote.Connection.from_dict(d)


def _listing(entries, hidden_ok=True, mtimes=None):
    sig = "\n".join(sorted(f"{n}|{k}|{s}" for n, k, s, _ in entries))
    return remote.Listing(list(entries), hidden_ok, sig, dict(mtimes or {}))


class FakeFTP:
    """一覧・大きさ・更新日時を辞書から返す偽の FTP。"""

    def __init__(self, tree, sizes=None, mdtm=None, pwd="/"):
        self.tree = tree  # フォルダ → Listing か例外
        self.sizes = sizes or {}  # パス → 大きさか例外
        self.mdtm = mdtm or {}  # パス → MDTM の応答
        self._pwd = pwd
        self.listed = []
        self.quits = 0

    def list(self, path):
        self.listed.append(path)
        v = self.tree[path]
        if isinstance(v, BaseException):
            raise v
        return v

    def pwd(self):
        if isinstance(self._pwd, BaseException):
            raise self._pwd
        return self._pwd

    def size(self, path):
        v = self.sizes[path]
        if isinstance(v, BaseException):
            raise v
        return v

    def sendcmd(self, cmd):
        assert cmd.startswith("MDTM ")
        return self.mdtm.get(cmd[5:], "213 20260101000000")

    def quit(self):
        self.quits += 1

    def close(self):
        pass


@pytest.fixture
def fake(monkeypatch):
    """ftp_open が返す偽の FTP を順に差し出す（足りなければ ConnectError）。"""
    opened = []

    def setup(*ftps):
        queue = list(ftps)

        def fake_open(conn, password):
            if not queue:
                raise remote.ConnectError("もう開けない", network=True)
            v = queue.pop(0)
            if isinstance(v, BaseException):
                raise v
            opened.append(v)
            return v

        monkeypatch.setattr(remote, "ftp_open", fake_open)
        monkeypatch.setattr(remote, "_ftp_list", lambda ftp, path: ftp.list(path))
        monkeypatch.setattr(remote, "_list_shows_dots", lambda ftp, path: False)
        return opened

    return setup


def _walk(conn=None):
    return list(remote.ftp_walk(conn or _conn(), "pw"))


@pytest.mark.parametrize("network,lost", [(True, True), (False, False)])
def test_walk_open_failure_is_one_error_entry(fake, network, lost):
    fake(remote.ConnectError("つながらない", network=network))
    (e,) = _walk()
    assert e.kind == "error" and e.reason == "つながらない" and e.network_lost is lost


def test_walk_open_network_lost_is_lost(fake):
    fake(safeio.NetworkLost("切れた"))
    (e,) = _walk()
    assert e.network_lost is True


def test_walk_pwd_failure_is_error_and_closes(fake):
    ftp = FakeFTP({}, pwd=EOFError("切れた"))
    fake(ftp)
    (e,) = _walk(_conn(start_dir=""))
    assert e.kind == "error" and e.network_lost is True and "接続が切れた" in e.reason
    assert ftp.quits == 1


def test_walk_stops_past_max_dirs(fake, monkeypatch):
    monkeypatch.setattr(remote, "FTP_MAX_DIRS", 2)
    d = [("x", "dir", None, "")]
    fake(FakeFTP({"/r": _listing(d + [("y", "dir", None, "")]), "/r/x": _listing([]), "/r/y": _listing([])}))
    entries = _walk()
    assert entries[-1].kind == "error" and "2 個を超えた" in entries[-1].reason
    assert len(entries) == 1


def test_walk_unreadable_folder_is_recorded_and_others_continue(fake):
    ftp = FakeFTP(
        {
            "/r": _listing([("a", "dir", None, ""), ("b", "dir", None, "")]),
            "/r/a": ftplib.error_perm("550 Permission denied."),
            "/r/b": _listing([("f.txt", "file", 3, "")], mtimes={"f.txt": 100.0}),
        }
    )
    fake(ftp)
    entries = _walk()
    err = [e for e in entries if e.kind == "error"]
    assert len(err) == 1 and err[0].path.endswith("/r/a") and "権限が無い" in err[0].reason
    assert "550 Permission denied" in err[0].reason and "denied.。" not in err[0].reason
    files = [e for e in entries if e.kind == "file"]
    assert [(f.path.rsplit("/", 1)[1], f.size, f.mtime) for f in files] == [("f.txt", 3, 100.0)]


# フォルダは積んで辿るので、名前順で後の b が先に辿られる（失敗を b に置き、その後の a が辿られないことを見る）
_AB = [("a", "dir", None, ""), ("b", "dir", None, "")]


def test_walk_network_lost_in_listing_stops(fake):
    ftp = FakeFTP({"/r": _listing(_AB), "/r/b": EOFError(), "/r/a": _listing([("f", "file", 1, "")])})
    fake(ftp)
    entries = _walk()
    assert len(entries) == 1 and entries[0].kind == "error" and entries[0].network_lost is True
    assert entries[0].path.endswith("/r/b") and "/r/a" not in ftp.listed


def test_walk_non_network_failure_reopens_and_continues(fake):
    first = FakeFTP({"/r": _listing(_AB), "/r/b": UnicodeError("x")})
    second = FakeFTP({"/r/a": _listing([("g.txt", "file", 5, "")], mtimes={"g.txt": 1.0})})
    opened = fake(first, second)
    entries = _walk()
    assert len(opened) == 2 and first.quits == 1  # 応答のずれを避けて開き直した
    err = [e for e in entries if e.kind == "error"]
    assert len(err) == 1 and "文字コード" in err[0].reason and err[0].network_lost is False
    assert [e.path.rsplit("/", 1)[1] for e in entries if e.kind == "file"] == ["g.txt"]
    assert second.quits == 1  # 最後に閉じるのは開き直した方


@pytest.mark.parametrize("network", [True, False])
def test_walk_reopen_failure_stops(fake, network):
    first = FakeFTP({"/r": _listing(_AB), "/r/b": UnicodeError("x")})
    fake(first, remote.ConnectError("開き直せない", network=network))
    entries = _walk()
    assert [e.kind for e in entries] == ["error", "error"]
    assert entries[-1].reason == "開き直せない" and entries[-1].network_lost is network
    assert "/r/a" not in first.listed


def test_walk_hidden_files_unknown_is_error(fake):
    fake(FakeFTP({"/r": _listing([], hidden_ok=False)}))
    (e,) = _walk()
    assert e.kind == "error" and "隠しファイル" in e.reason


def test_walk_too_deep_folder_is_link(fake, monkeypatch):
    monkeypatch.setattr(remote, "FTP_MAX_DEPTH", 1)
    fake(FakeFTP({"/r": _listing([("deep", "dir", None, "")])}))
    (e,) = _walk()
    assert e.kind == "link" and e.path.endswith("/r/deep") and "1 段より深い" in e.reason


def test_walk_file_without_size_or_mtime_asks_server(fake):
    ftp = FakeFTP(
        {"/r": _listing([("f.bin", "file", None, "")])},
        sizes={"/r/f.bin": 42},
        mdtm={"/r/f.bin": "213 20260102030405"},
    )
    fake(ftp)
    (e,) = _walk()
    assert e.kind == "file" and e.size == 42 and e.mtime == remote._parse_mdtm("20260102030405") > 0


def test_walk_size_network_lost_stops(fake):
    fake(
        FakeFTP(
            {"/r": _listing([("a.bin", "file", None, ""), ("b.bin", "file", 1, "")])},
            sizes={"/r/a.bin": socket.timeout()},
        )
    )
    entries = _walk()
    assert len(entries) == 1 and entries[0].kind == "error" and entries[0].network_lost is True
    assert "応答が無い" in entries[0].reason


def test_walk_size_refused_still_lists_file(fake):
    fake(FakeFTP({"/r": _listing([("a.bin", "file", None, "")])}, sizes={"/r/a.bin": ftplib.error_perm("550 SIZE no")}))
    (e,) = _walk()
    assert e.kind == "file" and e.size is None  # 回線断でなければ一覧には残す（写すときに読む）


def test_walk_link_and_unknown_rows(fake):
    fake(FakeFTP({"/r": _listing([("l", "link", 0, "/etc"), ("m", "link", 0, ""), ("?? bad", "unknown", None, "")])}))
    entries = _walk()
    by = {e.path.rsplit("/", 1)[1]: e for e in entries}
    assert by["l"].kind == "link" and "/etc を指す" in by["l"].reason
    assert "? を指す" in by["m"].reason
    assert by["?? bad"].kind == "error" and "読み取れなかった" in by["?? bad"].reason


def test_walk_same_listing_repeated_is_loop_without_confirming(fake, monkeypatch):
    monkeypatch.setattr(remote, "_deeper_equal", lambda *a: False)  # 確かめが効かないときの予備の道
    same = _listing([("a", "dir", None, "")])
    fake(FakeFTP({"/r": same, "/r/a": same, "/r/a/a": same, "/r/a/a/a": same}))
    entries = _walk()
    (e,) = entries
    assert e.kind == "link" and e.path.endswith("/r/a/a/a") and "同じ中身が続いている" in e.reason
    assert f"（{_conn().ftp_base()}/r）" in e.reason  # 確かめなしの道では、いちばん上の同じ祖先を示す


# --- 使い回しの接続 ---


@pytest.fixture
def pool(monkeypatch):
    """_pooled を差し替え、呼ばれた fresh の並びを記録する。"""
    calls = []

    def setup(*results):
        queue = list(results)

        def fake_pooled(conn, password, fresh=False):
            calls.append(fresh)
            v = queue.pop(0) if queue else object()
            if isinstance(v, BaseException):
                raise v
            return v

        monkeypatch.setattr(remote, "_pooled", fake_pooled)
        return calls

    return setup


def _raiser(*excs):
    queue = list(excs)

    def fn(ftp):
        if queue:
            raise queue.pop(0)
        return "ok"

    return fn


def test_pooled_call_retries_once_with_fresh_connection(pool):
    calls = pool()
    assert remote._pooled_call(_conn(), "pw", _raiser(EOFError())) == "ok"
    assert calls == [False, True]


@pytest.mark.parametrize(
    "exc,cls,text",
    [
        (EOFError(), safeio.NetworkLost, "接続が切れた"),
        (socket.gaierror(), safeio.NetworkLost, "名前が見つからない"),
        (ValueError("壊れた"), safeio.SourceError, "FTP で読めなかった"),
    ],
)
def test_pooled_call_second_failure(pool, exc, cls, text):
    pool()
    with pytest.raises(cls, match=text) as ei:
        remote._pooled_call(_conn(), "pw", _raiser(exc, exc))
    if cls is safeio.SourceError:
        assert not isinstance(ei.value, safeio.NetworkLost)


def test_pooled_call_refused_read_is_source_error_without_retry(pool):
    calls = pool()
    with pytest.raises(safeio.SourceError, match="読み取りを断った") as ei:
        remote._pooled_call(_conn(), "pw", _raiser(ftplib.error_perm("550 gone")))
    assert not isinstance(ei.value, safeio.NetworkLost) and calls == [False]


def test_pooled_call_source_error_passes_through(pool):
    pool()
    err = safeio.ChangedWhileReading("変わった")
    with pytest.raises(safeio.ChangedWhileReading) as ei:
        remote._pooled_call(_conn(), "pw", _raiser(err))
    assert ei.value is err


@pytest.mark.parametrize(
    "exc,cls,text",
    [
        (remote.ConnectError("落ちた", network=True), safeio.NetworkLost, "落ちた"),
        (remote.ConnectError("x: ログインできない（違う）", auth=True), remote.LoginLost, remote.LOGIN_LOST_MARK),
        (remote.ConnectError("証明書"), safeio.SourceError, "証明書"),
    ],
)
def test_pooled_call_connect_errors(pool, exc, cls, text):
    calls = pool(exc)
    with pytest.raises(cls, match=text) as ei:
        remote._pooled_call(_conn(), "pw", _raiser())
    assert calls == [False]
    if cls is safeio.SourceError:
        assert not isinstance(ei.value, safeio.NetworkLost)


def test_pooled_remembers_login_failure_until_reset(monkeypatch):
    tries = []

    def fail_open(conn, password):
        tries.append(1)
        raise remote.ConnectError("x: ログインできない（違う）", auth=True)

    monkeypatch.setattr(remote, "ftp_open", fail_open)
    conn = _conn(host="192.0.2.77")
    try:
        for _ in range(2):
            with pytest.raises(remote.ConnectError, match="ログインできない"):
                remote._pooled(conn, "bad")
        assert len(tries) == 1  # 2回目はサーバーへ試さない（ロックアウトよけ）
        with pytest.raises(remote.ConnectError, match="前にも失敗"):
            remote._pooled(conn, "bad")
        remote.reset_login_failures()
        with pytest.raises(remote.ConnectError):
            remote._pooled(conn, "bad")
        assert len(tries) == 2
    finally:
        remote.reset_login_failures()


def test_pooled_fresh_replaces_cached_connection(monkeypatch):
    made = []

    def open_new(conn, password):
        f = FakeFTP({})
        made.append(f)
        return f

    monkeypatch.setattr(remote, "ftp_open", open_new)
    conn = _conn(host="192.0.2.78")
    try:
        a = remote._pooled(conn, "pw")
        assert remote._pooled(conn, "pw") is a
        b = remote._pooled(conn, "pw", fresh=True)
        assert b is not a and a.quits == 1 and len(made) == 2
    finally:
        remote.close_pool(conn)

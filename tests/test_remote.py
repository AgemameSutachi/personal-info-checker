"""接続方式（FTP）の試験。手元に FTP サーバー（pyftpdlib）を立てて、本物の通信で確かめる。

本物の vsftpd・Samba（Hyper-V の Linux の VM）での確かめは tests/linux_check.py。
"""

import os
import threading
import time

import pytest

pyftpdlib = pytest.importorskip("pyftpdlib")
from pyftpdlib.authorizers import DummyAuthorizer  # noqa: E402
from pyftpdlib.handlers import FTPHandler  # noqa: E402
from pyftpdlib.servers import ThreadedFTPServer  # noqa: E402

from pii_checker import remote, safeio  # noqa: E402
from pii_checker.engine import scan_file  # noqa: E402
from pii_checker.models import PasswordBook, ScanOptions  # noqa: E402
from pii_checker.runner import JobRunner  # noqa: E402
from pii_checker.store import Store  # noqa: E402

PII = "氏名: 山田 太郎\nマイナンバー: 123456789018\n携帯: 090-1234-5678\n"
CLEAN = "会議の議題: 来期の予算について\n"


class NoMlsdHandler(FTPHandler):
    """MLSD を持たないサーバー（vsftpd と同じ）。LIST に . と .. を出さないので、隠しファイルが出ているか分からない。"""

    proto_cmds = {k: v for k, v in FTPHandler.proto_cmds.items() if k not in ("MLSD", "MLST")}


def _serve(root, handler_cls=FTPHandler):
    auth = DummyAuthorizer()
    auth.add_user("taro", "secret-pw", str(root), perm="elr")  # 読むだけ
    handler = type("H", (handler_cls,), {})
    handler.authorizer = auth
    handler.encoding = "utf-8"
    server = ThreadedFTPServer(("127.0.0.1", 0), handler)
    th = threading.Thread(target=server.serve_forever, kwargs={"timeout": 0.2}, daemon=True)
    th.start()
    return server, server.socket.getsockname()[1]


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "srv"
    (root / "sub").mkdir(parents=True)
    (root / "a.txt").write_text(PII, encoding="utf-8")
    (root / ".hidden").write_text(PII, encoding="utf-8")
    (root / "sub" / "日本語の名簿.txt").write_text(PII, encoding="utf-8")
    (root / "clean.txt").write_text(CLEAN, encoding="utf-8")
    return root


def _conn(port, **kw):
    d = {"kind": "ftp", "host": "127.0.0.1", "port": port, "user": "taro", "encoding": "utf-8"}
    d.update(kw)
    return remote.Connection.from_dict(d)


def _run_job(tmp_path, conn, password="secret-pw", db="j.sqlite3"):
    store = Store(str(tmp_path / db))
    job = store.create_job([conn.root()], ScanOptions(temp_dir=str(tmp_path), connection=conn.public()))
    r = JobRunner(store, job, workers=1, passwords=PasswordBook(connection_password=password))
    r.start()
    r.wait(120)
    assert not r.running
    return store, job


def _snapshot_of(root):
    return sorted((p.relative_to(root).as_posix(), p.stat().st_size, p.stat().st_mtime_ns) for p in root.rglob("*"))


def test_scan_over_ftp_finds_everything_and_changes_nothing(tree, tmp_path):
    server, port = _serve(tree)
    try:
        before = _snapshot_of(tree)
        store, job = _run_job(tmp_path, _conn(port))
        files = {r[0]: r for r in store.query("SELECT top_path, state, n_findings FROM files WHERE job_id=?", (job,))}
        base = f"ftp://127.0.0.1:{port}/"
        assert set(files) == {base + "a.txt", base + ".hidden", base + "clean.txt", base + "sub/日本語の名簿.txt"}
        assert files[base + ".hidden"][2] > 0  # 隠しファイルも見つける（MLSD）
        assert files[base + "sub/日本語の名簿.txt"][2] > 0
        assert files[base + "clean.txt"][2] == 0
        assert store.summary(job)["folder_errors"] == 0
        assert _snapshot_of(tree) == before  # サーバー側は何も変わらない
        # 2回目は前回の結果を使い回す（大きさと更新日時が同じ）
        store2, job2 = _run_job(tmp_path, _conn(port))
        assert store2.summary(job2)["reused"] == 4
    finally:
        server.close_all()


def test_list_without_dots_is_not_declared_clean(tree, tmp_path):
    """LIST に . と .. が出ないサーバーでは、隠しファイルが出ているか分からないので言い切らない。"""
    server, port = _serve(tree, NoMlsdHandler)
    try:
        store, job = _run_job(tmp_path, _conn(port))
        errs = store.query("SELECT reason FROM folder_errors WHERE job_id=? AND kind='error'", (job,))
        assert errs and all("隠しファイル" in e[0] for e in errs)
        from pii_checker.verdict import decide

        # 個人情報の無いフォルダでも「検出なし（言い切り）」にしない
        assert "検出なし" not in decide(store.summary(job), store.job(job)["state"]).title
    finally:
        server.close_all()


def test_list_without_dots_clean_folder_is_undetermined(tmp_path):
    root = tmp_path / "clean"
    root.mkdir()
    (root / "memo.txt").write_text(CLEAN, encoding="utf-8")
    server, port = _serve(root, NoMlsdHandler)
    try:
        store, job = _run_job(tmp_path, _conn(port), db="c.sqlite3")
        from pii_checker.verdict import decide

        assert "言い切れない" in decide(store.summary(job), store.job(job)["state"]).title
    finally:
        server.close_all()


def test_parse_list_formats():
    unix = [
        "drwxr-xr-x    2 0 0 4096 Oct 17 18:34 .",
        "drwxr-xr-x    4 0 0 4096 Oct 17 18:34 ..",
        "-rw-rw-r--    1 1001 1001 7 Oct 17 18:34 .hidden",
        "-rw-rw-r--    1 1001 1001 12 Jan  3  2024 名前 に 空白.txt",
        "lrwxrwxrwx    1 0 0 4 Oct 17 18:34 loop -> ../..",
        "drwxr-xr-x    2 0 0 4096 Oct 17 18:34 sub",
    ]
    entries, dots, dos = remote._parse_list(unix)
    assert dots and not dos
    assert ("名前 に 空白.txt", "file", 12, "") in entries
    assert ("loop", "link", 4, "../..") in entries and (".hidden", "file", 7, "") in entries
    dosl = ["10-17-26  06:34PM       <DIR>          sub", "10-17-26  06:34PM                   12 a.txt"]
    entries, dots, dos = remote._parse_list(dosl)
    assert dos and ("sub", "dir", None, "") in entries and ("a.txt", "file", 12, "") in entries
    entries, _, _ = remote._parse_list(["?? 読めない行"])
    assert entries == [("?? 読めない行", "unknown", None, "")]  # 読めない行は黙って捨てない


def test_wrong_password_and_refused_messages(tree):
    server, port = _serve(tree)
    try:
        with pytest.raises(remote.ConnectError, match="パスワードが違う") as ei:
            remote.ftp_check(_conn(port), "wrong")
        assert not ei.value.network
        assert "件が見えます" in remote.ftp_check(_conn(port), "secret-pw")
    finally:
        server.close_all()
    with pytest.raises(remote.ConnectError, match="接続を断られた") as ei:
        remote.ftp_check(_conn(port), "secret-pw")
    assert ei.value.network


def test_server_down_during_scan_is_network_lost(tree, tmp_path):
    """検査の途中でサーバーが落ちたら、回線断として未検査で残す（検査不能で確定させない）。"""
    server, port = _serve(tree)
    conn = _conn(port)
    opts = ScanOptions(temp_dir=str(tmp_path), connection=conn.public())
    book = PasswordBook(connection_password="secret-pw")
    url = f"ftp://127.0.0.1:{port}/a.txt"
    ok = scan_file(url, opts, book)
    assert not ok.network_lost and ok.items[0].status.value == "scanned"
    server.close_all()
    time.sleep(0.3)
    lost = scan_file(url, opts, book)
    assert lost.network_lost and lost.items[0].status.value == "uncheckable"
    assert lost.items[0].reason.startswith(safeio.NETWORK_LOST_MSG)


def test_changed_while_downloading(tree, tmp_path, monkeypatch):
    server, port = _serve(tree)
    try:
        conn = _conn(port)
        calls = iter(range(1000))
        real = remote._stat
        monkeypatch.setattr(remote, "_stat", lambda ftp, p: (real(ftp, p)[0], float(next(calls))))  # 毎回日時が進む
        with pytest.raises(safeio.ChangedWhileReading):
            remote.ftp_snapshot(f"ftp://127.0.0.1:{port}/a.txt", str(tmp_path / "x"), str(tmp_path), conn, "secret-pw")
    finally:
        server.close_all()


def test_connection_validation_and_root():
    with pytest.raises(remote.ConnectError, match="共有名"):
        remote.Connection.from_dict({"kind": "smb", "host": "nas01"}).validate()
    with pytest.raises(remote.ConnectError, match="ポート"):
        remote.Connection.from_dict({"kind": "smb", "host": "nas01", "share": "a", "port": 139}).validate()
    with pytest.raises(remote.ConnectError, match="空白"):
        remote.Connection.from_dict({"kind": "ftp", "host": "nas 01"}).validate()
    c = remote.Connection.from_dict({"kind": "smb", "host": "\\\\nas01", "share": "総務", "path": "2024/名簿"})
    assert c.root() == r"\\nas01\総務\2024\名簿"
    f = remote.Connection.from_dict({"kind": "ftps_implicit", "host": "h", "path": "/a/b/"})
    assert f.root() == "ftps://h/a/b" and remote.ftp_server_path(f.root() + "/c.txt") == "/a/b/c.txt"
    assert "password" not in f.public()


def test_password_is_not_saved(tree, tmp_path):
    server, port = _serve(tree)
    try:
        store, job = _run_job(tmp_path, _conn(port))
        raw = b""
        for name in os.listdir(tmp_path):
            if name.startswith("j.sqlite3"):  # DB の本体と -wal・-shm（read_bytes は読み終えたら閉じる）
                raw += (tmp_path / name).read_bytes()
        assert b"secret-pw" not in raw
    finally:
        server.close_all()


def test_vsftpd_failed_to_open_directory_is_permission_error():
    """vsftpd は読めないフォルダの一覧に 226 と「failed to open directory」を返す。空のフォルダとみなさない。"""
    import ftplib

    with pytest.raises(ftplib.error_perm, match="開けなかった"):
        remote._check_list_resp("226 Transfer done (but failed to open directory).", "/secret")
    remote._check_list_resp("226 Directory send OK.", "/ok")  # 陽性対照: 普通の応答は通す


def test_broken_connection_attribute_error_is_network_lost():
    conn = _conn(21)
    err = remote._ftp_error(AttributeError("'NoneType' object has no attribute 'sendall'"), conn)
    assert isinstance(err, safeio.NetworkLost)
    other = remote._ftp_error(AttributeError("x has no attribute y"), conn)
    assert not isinstance(other, safeio.NetworkLost)


def _job(tmp_path, conn, db, password="secret-pw"):
    store = Store(str(tmp_path / db))
    job = store.create_job([conn.root()], ScanOptions(temp_dir=str(tmp_path), connection=conn.public()))
    return store, job, JobRunner(store, job, workers=1, passwords=PasswordBook(connection_password=password))


def _serve_with(root, handler_base, **attrs):
    auth = DummyAuthorizer()
    auth.add_user("taro", "secret-pw", str(root), perm="elr")
    handler = type("H", (handler_base,), {"authorizer": auth, "encoding": "utf-8", **attrs})
    server = ThreadedFTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, kwargs={"timeout": 0.2}, daemon=True).start()
    return server, server.socket.getsockname()[1], auth


def test_reuse_uses_current_server_values_not_stale_listing(tmp_path):
    """再開では列挙し直さないので、古い一覧で使い回すと書き換わったファイルを「検出なし」と言い切った（実測）。"""
    root = tmp_path / "srv"
    root.mkdir()
    (root / "a.txt").write_text(CLEAN, encoding="utf-8")
    server, port = _serve(root)
    try:
        conn = _conn(port)
        _run_job(tmp_path, conn, db="r.sqlite3")  # 1回目（検出なし）
        store, job, r = _job(tmp_path, conn, "r.sqlite3")
        r._enumerate()  # 2回目の列挙だけ済ませる（ここで中断したとみなす）
        time.sleep(1.1)  # 更新日時（秒）が変わるように
        (root / "a.txt").write_text(PII, encoding="utf-8")  # 中断の間にサーバーのファイルが書き換わる
        r.start()
        r.wait(120)
        row = store.query("SELECT reused_from, n_findings FROM files WHERE job_id=?", (job,))[0]
        assert row[0] is None and row[1] > 0
    finally:
        server.close_all()


def test_encoding_error_then_next_folder_is_not_network_lost(tmp_path):
    """文字コードの違いで一覧を読めなかったフォルダの後も、次のフォルダを正しく辿る（応答がずれて回線断と誤らない）。"""
    root = tmp_path / "srv"
    (root / "a").mkdir(parents=True)
    (root / "z").mkdir()
    (root / "a" / "ok.txt").write_text(PII, encoding="utf-8")
    for i in range(50):
        (root / "z" / f"名簿{i}.txt").write_text(CLEAN, encoding="utf-8")
    server, port, _ = _serve_with(root, NoMlsdHandler, encoding="cp932")
    try:
        entries = list(remote.ftp_walk(_conn(port), "secret-pw"))
        z = [e for e in entries if e.kind == "error" and e.path.endswith("/z")]
        assert z and "文字コード" in z[0].reason and not z[0].network_lost
        assert not any(e.network_lost for e in entries)
        assert any(e.kind == "file" and e.path.endswith("/a/ok.txt") for e in entries)
    finally:
        server.close_all()


def test_ftp_server_that_follows_junction_loops_is_stopped(tmp_path):
    """親を指すリンクを普通のフォルダとして見せるサーバーで、列挙が指数的に増えずに止まる（実測: 40 秒で 232 件）。"""
    import subprocess

    root = tmp_path / "srv"
    root.mkdir()
    (root / "f.txt").write_text(CLEAN, encoding="utf-8")
    for j in ("j1", "j2"):
        r = subprocess.run(["cmd", "/c", "mklink", "/J", str(root / j), str(root)], capture_output=True)
        if r.returncode != 0:
            pytest.skip("ジャンクションを作れない")
    server, port = _serve(root)
    try:
        t0 = time.time()
        entries = list(remote.ftp_walk(_conn(port), "secret-pw"))
        files = [e for e in entries if e.kind == "file"]
        links = [e for e in entries if e.kind == "link"]
        assert time.time() - t0 < 30
        assert len(files) == 1 and len(links) == 2
    finally:
        server.close_all()
        for j in ("j1", "j2"):
            # ジャンクションだけを外す（rmdir はジャンクションの先を辿らない。pytest の後片付けに残さない）
            subprocess.run(["cmd", "/c", "rmdir", str(root / j)], capture_output=True)


def test_login_lost_mid_scan_halts_and_resumes(tmp_path):
    """途中でパスワードが変わったら、1件ずつ検査不能で確定させず中断し、正しいパスワードで再開すると全部読む。"""
    root = tmp_path / "srv"
    root.mkdir()
    for i in range(6):
        (root / f"f{i}.txt").write_text(CLEAN, encoding="utf-8")
    server, port, auth = _serve_with(root, FTPHandler)
    try:
        conn = _conn(port)
        store, job, r = _job(tmp_path, conn, "l.sqlite3")
        r._enumerate()
        auth.remove_user("taro")
        auth.add_user("taro", "new-pw", str(root), perm="elr")  # 検査の途中でパスワードが変わる
        remote.close_pool()  # 前のパスワードで使い回していた接続を閉じる
        r.start()
        r.wait(120)
        assert store.job(job)["state"] == "interrupted"
        assert store.files_with_status(job, ["uncheckable"]) == []
        assert len(store.pending_files(job)) >= 3
        r2 = JobRunner(store, job, workers=1, passwords=PasswordBook(connection_password="new-pw"))
        r2.start()
        r2.wait(120)
        assert store.job(job)["state"] == "done" and store.pending_files(job) == []
        assert store.files_with_status(job, ["uncheckable"]) == []
    finally:
        server.close_all()


def test_encoding_error_message_does_not_leak_password(tree):
    server, port = _serve(tree)
    try:
        with pytest.raises(remote.ConnectError) as ei:
            remote.ftp_check(_conn(port, encoding="cp932"), "pässwörd-é")
        assert "é" not in str(ei.value) and "position" not in str(ei.value) and "文字コード" in str(ei.value)
    finally:
        server.close_all()


def test_real_nested_folders_with_same_listing_are_not_loops(tmp_path):
    """本物の入れ子（/x/x/x を同じ秒に作った）は、一覧が祖先と同じでもループとして飛ばさない（実測した誤り）。"""
    root = tmp_path / "srv"
    deep = root / "x" / "x" / "x"
    deep.mkdir(parents=True)
    (deep / "名簿.txt").write_text(PII, encoding="utf-8")
    t = time.time() - 3600
    for d in (root / "x", root / "x" / "x", deep):
        os.utime(d, (t, t))
    for handler in (FTPHandler, NoMlsdHandler):
        server, port = _serve(root, handler)
        try:
            entries = list(remote.ftp_walk(_conn(port), "secret-pw"))
            assert [e.path.rsplit("/", 1)[1] for e in entries if e.kind == "file"] == ["名簿.txt"]
            assert not [e for e in entries if e.kind == "link"]
        finally:
            server.close_all()


def test_loop_with_unreadable_folder_first_is_still_stopped(tmp_path):
    """ループの中に、名前順で最初に来る読めないフォルダがあっても止まる（実測: 40 秒で深さ 67・112 件）。"""
    import getpass
    import subprocess

    root = tmp_path / "srv"
    (root / "aaa_noperm").mkdir(parents=True)
    (root / "f.txt").write_text(CLEAN, encoding="utf-8")
    for j in ("j1", "j2"):
        r = subprocess.run(["cmd", "/c", "mklink", "/J", str(root / j), str(root)], capture_output=True)
        if r.returncode != 0:
            pytest.skip("ジャンクションを作れない")
    deny = subprocess.run(
        ["icacls", str(root / "aaa_noperm"), "/deny", f"{getpass.getuser()}:(RX)"], capture_output=True
    )
    server, port = _serve(root)
    try:
        t0 = time.time()
        entries = list(remote.ftp_walk(_conn(port), "secret-pw"))
        assert time.time() - t0 < 60
        assert len([e for e in entries if e.kind == "file"]) == 1
        assert len([e for e in entries if e.kind == "link"]) == 2
        if deny.returncode == 0:
            assert any(e.kind == "error" and e.path.endswith("/aaa_noperm") for e in entries)
    finally:
        server.close_all()
        subprocess.run(["icacls", str(root / "aaa_noperm"), "/remove:d", getpass.getuser()], capture_output=True)
        for j in ("j1", "j2"):
            subprocess.run(["cmd", "/c", "rmdir", str(root / j)], capture_output=True)  # ジャンクションだけを外す


def test_login_lost_halts_on_first_failure(tmp_path):
    """ログインできなくなったら1回目で止める（失敗を重ねてロックアウトの規則に掛からないように）。"""
    root = tmp_path / "srv"
    root.mkdir()
    for i in range(20):
        (root / f"f{i}.txt").write_text(CLEAN, encoding="utf-8")
    fails = {"n": 0}

    class Counting(FTPHandler):
        def on_login_failed(self, username, password):
            fails["n"] += 1

    server, port, auth = _serve_with(root, Counting)
    try:
        store, job, r = _job(tmp_path, _conn(port), "lf.sqlite3")
        r._enumerate()
        auth.remove_user("taro")
        auth.add_user("taro", "new-pw", str(root), perm="elr")
        remote.close_pool()  # 前のパスワードで使い回していた接続を閉じる
        r.start()
        r.wait(120)
        assert store.job(job)["state"] == "interrupted"
        assert fails["n"] <= 3, fails["n"]  # 本体の問い合わせ1回＋ワーカー1つの1回（つなぎ直しを含めても数回まで）
    finally:
        server.close_all()


class _NoOptsMlst(FTPHandler):
    def ftp_OPTS(self, line):
        if line.upper().startswith("MLST"):
            self.respond("501 Invalid argument.")
            return
        return super().ftp_OPTS(line)


def test_server_that_rejects_opts_mlst(tree):
    """OPTS MLST を断るサーバーでも、facts を付けずに MLSD で一覧を取る。"""
    server, port = _serve(tree, _NoOptsMlst)
    try:
        entries = list(remote.ftp_walk(_conn(port), "secret-pw"))
        assert len([e for e in entries if e.kind == "file"]) == 4
        assert not [e for e in entries if e.kind == "error"]
    finally:
        server.close_all()


def test_login_failure_is_auth_but_network_failure_is_not(tree):
    """パスワードを断られた失敗だけを auth にする（覚えたパスワードを捨てるのはこのときだけ）。"""
    server, port = _serve(tree)
    try:
        with pytest.raises(remote.ConnectError) as ei:
            remote.ftp_check(_conn(port), "wrong")
        assert ei.value.auth and not ei.value.network
    finally:
        server.close_all()
    with pytest.raises(remote.ConnectError) as ei:  # サーバーが落ちている: 回線の失敗で、パスワードの誤りではない
        remote.ftp_check(_conn(port), "secret-pw")
    assert ei.value.network and not ei.value.auth


def _pooled_for(port):
    return [ftp for key, ftp in remote._pool.items() if key[2] == port]


def test_close_pool_closes_only_that_server(tree):
    server, port = _serve(tree)
    server2, port2 = _serve(tree)
    try:
        assert remote.ftp_stat(f"ftp://127.0.0.1:{port}/a.txt", _conn(port), "secret-pw")[0] > 0
        assert remote.ftp_stat(f"ftp://127.0.0.1:{port2}/a.txt", _conn(port2), "secret-pw")[0] > 0
        (ftp,) = _pooled_for(port)
        assert ftp.sock is not None  # 陽性対照: 使い回しの接続が開いている
        assert remote.close_pool(_conn(port)) == 1
        assert ftp.sock is None and not _pooled_for(port)
        assert len(_pooled_for(port2)) == 1  # 別のサーバーの接続は残す
        # 閉じた後も、次の問い合わせはつなぎ直して答える
        assert remote.ftp_stat(f"ftp://127.0.0.1:{port}/a.txt", _conn(port), "secret-pw")[0] > 0
    finally:
        remote.close_pool()
        server.close_all()
        server2.close_all()
    assert not remote._pool


def test_pool_is_closed_when_job_ends(tree, tmp_path, monkeypatch):
    """前回の結果の使い回しの判定で開いた接続を、検査が終わったら閉じる（以前は試験の終わりまで残り ResourceWarning）。"""
    server, port = _serve(tree)
    try:
        _run_job(tmp_path, _conn(port))
        opened = []
        real = remote._pooled

        def spy(conn, password, fresh=False):
            ftp = real(conn, password, fresh)
            opened.append(ftp)
            return ftp

        monkeypatch.setattr(remote, "_pooled", spy)
        store, job = _run_job(tmp_path, _conn(port))  # 2回目は大きさ・更新日時を問い合わせて使い回す
        assert store.summary(job)["reused"] == 4 and opened  # 陽性対照: 使い回しの接続を実際に使った
        assert not _pooled_for(port)
        assert all(ftp.sock is None for ftp in opened)
    finally:
        server.close_all()

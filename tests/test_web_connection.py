"""Web 版の接続方式の API（接続を確かめる・接続方式で始める・再開でパスワードを受け取り直す）の試験。"""

import subprocess
import time
from contextlib import contextmanager
from pathlib import Path

import pytest
from fastapi import HTTPException

pytest.importorskip("pyftpdlib")

from pii_checker.web.server import NEEDS_PASSWORD_HEADER, NETWORK_HEADER, create_app, host_name  # noqa: E402
from test_remote import _serve  # noqa: E402  （tests は同じフォルダから読み込まれる）


def _route(app, path, method="POST"):
    return next(r.endpoint for r in app.routes if getattr(r, "path", "") == path and method in r.methods)


@pytest.fixture
def ftp(tmp_path):
    root = tmp_path / "srv"
    root.mkdir()
    (root / "a.txt").write_text("マイナンバー: 123456789018\n", encoding="utf-8")
    server, port = _serve(root)
    yield port
    server.close_all()


def _conn(port):
    return {
        "kind": "ftp",
        "host": "127.0.0.1",
        "port": port,
        "share": "",
        "path": "",
        "user": "taro",
        "encoding": "utf-8",
        "verify_cert": False,
    }


def test_info_lists_kinds(tmp_path):
    app = create_app(db=str(tmp_path / "j.sqlite3"), token="t")
    info = _route(app, "/api/info", "GET")()
    assert {k["id"] for k in info["connection_kinds"]} == {"smb", "ftp", "ftps", "ftps_implicit"}
    assert info["encodings"][0][0] == "auto"


def test_connection_test_and_job(tmp_path, ftp):
    app = create_app(db=str(tmp_path / "j.sqlite3"), token="t")
    test = _route(app, "/api/connection/test")
    with pytest.raises(HTTPException) as ei:
        test(payload={"connection": _conn(ftp), "connection_password": "wrong"})
    assert ei.value.status_code == 400 and "パスワードが違う" in ei.value.detail
    with pytest.raises(HTTPException) as ei:
        test(payload={"connection": {**_conn(ftp), "host": ""}, "connection_password": "x"})
    assert "サーバー" in ei.value.detail
    ok = test(payload={"connection": _conn(ftp), "connection_password": "secret-pw"})
    assert ok["ok"] and ok["root"] == f"ftp://127.0.0.1:{ftp}/"

    create = _route(app, "/api/jobs")
    with pytest.raises(HTTPException) as ei:  # フォルダの指定と接続方式を両方送ったら断る（どちらで検査するか曖昧）
        create(payload={"connection": _conn(ftp), "connection_password": "secret-pw", "roots": ["C:/x"]})
    assert "一緒に使えません" in ei.value.detail
    job_id = create(
        payload={
            "connection": _conn(ftp),
            "connection_password": "secret-pw",
            "roots": [],
            "options": {"temp_dir": str(tmp_path)},
        }
    )["id"]
    detail = _route(app, "/api/jobs/{job_id}", "GET")
    for _ in range(240):
        j = detail(job_id=job_id)
        if not j["running"] and j["state"] == "done":
            break
        time.sleep(0.5)
    assert j["state"] == "done" and j["summary"]["files_with_findings"] == 1
    assert j["connection"]["user"] == "taro" and "password" not in j["connection"]
    assert j["connection_label"].startswith("FTP") and j["roots"] == [f"ftp://127.0.0.1:{ftp}/"]

    # アプリを開き直した（別のアプリ）あとの再開は、接続のパスワードを受け取り直す
    app2 = create_app(db=str(tmp_path / "j.sqlite3"), token="t")
    store = app2.state.store
    store.mark_pending(job_id, [f"ftp://127.0.0.1:{ftp}/a.txt"])
    store.set_job(job_id, state="interrupted")
    resume = _route(app2, "/api/jobs/{job_id}/resume")
    with pytest.raises(HTTPException) as ei:
        resume(job_id=job_id, payload={})
    assert "パスワードを入れてから再開" in ei.value.detail
    with pytest.raises(HTTPException) as ei:
        resume(job_id=job_id, payload={"connection_password": "wrong"})
    assert "パスワードが違う" in ei.value.detail
    add_pw = _route(app2, "/api/jobs/{job_id}/passwords")
    with pytest.raises(HTTPException) as ei:
        add_pw(job_id=job_id, payload={"password": "zip-pw"})
    assert "パスワードを入れてからファイルのパスワードを試してください" in ei.value.detail
    assert resume(job_id=job_id, payload={"connection_password": "secret-pw"})["ok"]
    detail2 = _route(app2, "/api/jobs/{job_id}", "GET")
    for _ in range(240):
        j = detail2(job_id=job_id)
        if not j["running"] and j["state"] == "done":
            break
        time.sleep(0.5)
    assert j["state"] == "done" and j["summary"]["files_done"] == 1


def _wait_done(detail, job_id):
    for _ in range(240):
        j = detail(job_id=job_id)
        if not j["running"] and j["state"] == "done":
            return j
        time.sleep(0.5)
    raise AssertionError(f"検査が終わらない: {j['state']}")


SEVENZIP = Path(__file__).resolve().parent.parent / "vendor" / "7zip" / "7z.exe"


@pytest.mark.skipif(not SEVENZIP.exists(), reason="7-Zip が無い")
def test_file_password_after_reopen_reconnects(tmp_path):
    """終わった接続方式の検査をアプリを開き直してから開き、要パスワードの zip にパスワードを入れられる。

    以前は「先に再開で接続のパスワードを」と断られたが、終わった検査には「再開」が出ないので先へ進めなかった。
    """
    root = tmp_path / "srv"
    root.mkdir()
    src = tmp_path / "meibo.txt"
    src.write_text("マイナンバー: 123456789018\n", encoding="utf-8")
    subprocess.run(
        [str(SEVENZIP), "a", "-tzip", "-pzip-pw", "-mem=ZipCrypto", str(root / "locked.zip"), str(src)],
        check=True,
        capture_output=True,
    )
    server, port = _serve(root)
    try:
        app = create_app(db=str(tmp_path / "j.sqlite3"), token="t")
        job_id = _route(app, "/api/jobs")(
            payload={
                "connection": _conn(port),
                "connection_password": "secret-pw",
                "roots": [],
                "options": {"temp_dir": str(tmp_path)},
                "passwords": [],
            }
        )["id"]
        j = _wait_done(_route(app, "/api/jobs/{job_id}", "GET"), job_id)
        assert j["summary"]["password_files"] == 1 and j["summary"]["files_with_findings"] == 0
        assert j["needs_connection_password"] is False  # 同じアプリの中では接続のパスワードを覚えている

        # アプリを開き直した: 終わった検査なので「再開」は使えない。ファイルのパスワード欄で接続のパスワードも受け取る
        app2 = create_app(db=str(tmp_path / "j.sqlite3"), token="t")
        detail2 = _route(app2, "/api/jobs/{job_id}", "GET")
        j = detail2(job_id=job_id)
        assert j["state"] == "done" and j["needs_connection_password"] is True
        add_pw = _route(app2, "/api/jobs/{job_id}/passwords")
        with pytest.raises(HTTPException) as ei:
            add_pw(job_id=job_id, payload={"password": "zip-pw"})
        assert ei.value.status_code == 400 and "パスワードを入れてから" in ei.value.detail
        assert "ファイルのパスワードはまだ試していません" in ei.value.detail
        with pytest.raises(HTTPException) as ei:  # 空の欄は入れ忘れ（空でログインを試して「違う」と返さない）
            add_pw(job_id=job_id, payload={"password": "zip-pw", "connection_password": ""})
        assert "パスワードを入れてから" in ei.value.detail and "違う" not in ei.value.detail
        with pytest.raises(HTTPException) as ei:
            add_pw(job_id=job_id, payload={"password": "zip-pw", "connection_password": "wrong"})
        assert "パスワードが違う" in ei.value.detail
        assert app2.state.registry.get(job_id).passwords_tried == 0  # つなげないうちはファイルのパスワードを数えない
        r = add_pw(job_id=job_id, payload={"password": "zip-pw", "connection_password": "secret-pw"})
        assert r["requeued"] == 1
        time.sleep(0.5)
        j = _wait_done(detail2, job_id)
        assert j["summary"]["password_files"] == 0 and j["summary"]["files_with_findings"] == 1
        assert j["needs_connection_password"] is False

        # 覚えていたパスワードが誤り（SMB の既存の接続を使って確かめないまま覚えた等）で再開に失敗したら、捨てて聞き直す側に戻す
        app2.state.registry.get(job_id).passwords.connection_password = "wrong"
        app2.state.store.mark_pending(job_id, [f"ftp://127.0.0.1:{port}/locked.zip"])
        app2.state.store.set_job(job_id, state="interrupted")
        assert detail2(job_id=job_id)["needs_connection_password"] is False
        with pytest.raises(HTTPException) as ei:
            _route(app2, "/api/jobs/{job_id}/resume")(job_id=job_id, payload={})
        assert "パスワードが違う" in ei.value.detail
        assert detail2(job_id=job_id)["needs_connection_password"] is True
    finally:
        server.close_all()


@contextmanager
def _host_status(app):
    """app を立て、「Host ヘッダーを指定して / を開いたときの応答の番号」を返す関数を渡す。"""
    import http.client
    import socket
    import threading

    import uvicorn

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    th = threading.Thread(target=srv.run, daemon=True)
    th.start()
    try:
        for _ in range(100):
            if srv.started:
                break
            time.sleep(0.05)

        def status(host: str) -> int:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            c.putrequest("GET", "/", skip_host=True)
            c.putheader("Host", host)
            c.endheaders()
            code = c.getresponse().status
            c.close()
            return code

        yield status
    finally:
        srv.should_exit = True
        th.join(timeout=10)


def test_host_check_ignores_case(tmp_path):
    """ほかの PC から PC の名前で開いたとき、ブラウザが小文字で送る Host を断らない。"""
    app = create_app(db=str(tmp_path / "j.sqlite3"), token="t", allowed_hosts={"127.0.0.1", "Office-PC"})
    with _host_status(app) as status:
        assert status("office-pc:8765") == 200
        assert status("OFFICE-PC") == 200
        assert status("other-pc:8765") == 403


def test_host_name_parsing():
    assert host_name("[::1]") == "::1"  # 以前は「:」になって断っていた
    assert host_name("[::1]:8791") == "::1"
    assert host_name("[FE80::1]:80") == "fe80::1"
    assert host_name("Office-PC:8765") == "office-pc"
    assert host_name("127.0.0.1") == "127.0.0.1"
    for bad in ("[::1", "[::1]x", "[::1]:80x", "", None):
        assert host_name(bad) == ""


def test_host_check_accepts_ipv6(tmp_path):
    """IPv6 の Host（[::1]・[::1]:8791）を通す。ポートの扱い・大文字小文字・断る名前は変えない。"""
    app = create_app(db=str(tmp_path / "j.sqlite3"), token="t")  # 既定（この PC だけ）
    with _host_status(app) as status:
        assert status("[::1]") == 200
        assert status("[::1]:8791") == 200
        assert status("LOCALHOST:8765") == 200
        assert status("127.0.0.1:8765") == 200
        assert status("[::2]:8791") == 403
        assert status("[::1]evil") == 403
        assert status("evil.example.com") == 403
    app2 = create_app(db=str(tmp_path / "k.sqlite3"), token="t", allowed_hosts={"Office-PC", "[FE80::1]"})
    with _host_status(app2) as status:
        assert status("[fe80::1]:8765") == 200
        assert status("[::1]") == 403  # 許可していない名前は断る
        assert status("office-pc") == 200


def _finished_ftp_job(tmp_path, port):
    """接続方式（FTP）で検査を終え、続きが残っている（中断した）形にしたジョブ。"""
    app = create_app(db=str(tmp_path / "j.sqlite3"), token="t")
    job_id = _route(app, "/api/jobs")(
        payload={
            "connection": _conn(port),
            "connection_password": "secret-pw",
            "roots": [],
            "options": {"temp_dir": str(tmp_path)},
        }
    )["id"]
    _wait_done(_route(app, "/api/jobs/{job_id}", "GET"), job_id)
    app.state.store.mark_pending(job_id, [f"ftp://127.0.0.1:{port}/a.txt"])
    app.state.store.set_job(job_id, state="interrupted")
    return app, job_id


def test_remembered_password_is_kept_when_server_is_down(tmp_path):
    """回線断・サーバーが落ちている間の再開の失敗では、覚えた接続のパスワードを捨てない（入れ直しにしない）。"""
    root = tmp_path / "srv"
    root.mkdir()
    (root / "a.txt").write_text("マイナンバー: 123456789018\n", encoding="utf-8")
    server, port = _serve(root)
    app, job_id = _finished_ftp_job(tmp_path, port)
    server.close_all()
    time.sleep(0.3)
    r = app.state.registry.get(job_id)
    resume = _route(app, "/api/jobs/{job_id}/resume")
    with pytest.raises(HTTPException) as ei:
        resume(job_id=job_id, payload={})
    assert "接続を断られた" in ei.value.detail
    assert not (ei.value.headers or {}).get(NEEDS_PASSWORD_HEADER)  # 画面はパスワードの欄を開かない
    assert ei.value.headers[NETWORK_HEADER] == "1"  # 画面は「つながるのを確かめてからもう一度」を添える
    assert r.passwords.connection_password == "secret-pw"
    assert _route(app, "/api/jobs/{job_id}", "GET")(job_id=job_id)["needs_connection_password"] is False
    with pytest.raises(HTTPException) as ei:  # 新しく入れたパスワードでも、回線断なら印を付けない
        resume(job_id=job_id, payload={"connection_password": "secret-pw"})
    assert not (ei.value.headers or {}).get(NEEDS_PASSWORD_HEADER)


def test_password_failures_carry_the_needs_password_mark(tmp_path, ftp):
    """パスワードが要る失敗（断られた・まだ受け取っていない）にだけ印を付け、そのときだけ覚えたものを捨てる。"""
    app, job_id = _finished_ftp_job(tmp_path, ftp)
    r = app.state.registry.get(job_id)
    resume = _route(app, "/api/jobs/{job_id}/resume")
    r.passwords.connection_password = "wrong"  # 覚えていたものが誤り
    with pytest.raises(HTTPException) as ei:
        resume(job_id=job_id, payload={})
    assert ei.value.headers[NEEDS_PASSWORD_HEADER] == "1" and "パスワードが違う" in ei.value.detail
    assert not ei.value.headers.get(NETWORK_HEADER)  # つながった上で断られたので、回線の印は付けない
    assert r.passwords.connection_password == ""
    with pytest.raises(HTTPException) as ei:  # まだ受け取っていない
        resume(job_id=job_id, payload={})
    assert ei.value.headers[NEEDS_PASSWORD_HEADER] == "1" and "パスワードを入れてから再開" in ei.value.detail
    with pytest.raises(HTTPException) as ei:  # ファイルのパスワード欄から: 包み直しても印を残す
        _route(app, "/api/jobs/{job_id}/passwords")(job_id=job_id, payload={"password": "zip-pw"})
    assert ei.value.headers[NEEDS_PASSWORD_HEADER] == "1"
    with pytest.raises(HTTPException) as ei:  # パスワードと無関係な失敗（ジョブが無い）には付けない
        resume(job_id="no-such-job", payload={})
    assert ei.value.status_code == 404 and not (ei.value.headers or {}).get(NEEDS_PASSWORD_HEADER)
    assert resume(job_id=job_id, payload={"connection_password": "secret-pw"})["ok"]
    _wait_done(_route(app, "/api/jobs/{job_id}", "GET"), job_id)

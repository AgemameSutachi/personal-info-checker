"""コマンドの接続方式（--connect）と、許可リスト・規則のファイルの読み取りの試験（通信はしない）。"""

import argparse

import pytest

from pii_checker import cli
from pii_checker.safeio import NetworkLost


@pytest.fixture
def scan_spy(monkeypatch):
    """検査の本体を呼ばずに、渡された接続先と検査先を記録する。"""
    seen = {}

    def fake(args, conn, conn_password, store=None):
        seen.update(roots=list(args.roots), conn=conn, password=conn_password)
        return 0

    monkeypatch.setattr(cli, "_cmd_scan", fake)
    return seen


def _scan(tmp_path, *argv):
    return cli.main(["--db", str(tmp_path / "j.sqlite3"), "scan", *argv, "--no-ask"])


@pytest.mark.parametrize(
    "argv,text",
    [
        (["--connect", "ftp", "--host", "192.0.2.1", "--resume", "1"], "--resume と --connect は一緒に使えません"),
        (["C:/x", "--host", "192.0.2.1", "--user", "taro"], "--host・--user は --connect と一緒に"),
        (["C:/x", "--port", "21"], "--port は --connect と一緒に"),
        (["C:/x", "--connect", "ftp", "--host", "192.0.2.1"], "フォルダの指定と --connect は一緒に使えません"),
        (["--connect", "ftp"], "--host でサーバーの名前"),
        (["--connect", "smb", "--host", "nas01"], "--share で共有名"),
        (["--connect", "ftp", "--host", "192.0.2.1", "--port", "70000"], "ポート"),
    ],
)
def test_connect_option_mistakes_are_refused(tmp_path, capsys, scan_spy, argv, text):
    assert _scan(tmp_path, *argv) == 2
    assert text in capsys.readouterr().err
    assert not scan_spy  # 検査は始めない


@pytest.mark.parametrize(
    "argv,text", [(["--share", "総務"], "--host などの接続方式の指定は"), ([], "検査するフォルダを指定してください")]
)
def test_scan_without_folder_or_connect_is_usage_error(tmp_path, capsys, scan_spy, argv, text):
    with pytest.raises(SystemExit) as e:
        _scan(tmp_path, *argv)
    assert e.value.code == 2 and text in capsys.readouterr().err and not scan_spy


def test_ftp_scan_uses_connection_root_and_password_file(tmp_path, monkeypatch, scan_spy):
    pw = tmp_path / "pw.txt"
    pw.write_bytes(b"s3cret\r\nsecond line\r\n")
    checked = []
    monkeypatch.setattr(cli, "ftp_check", lambda conn, password: checked.append(password) or "接続できました")
    code = _scan(
        tmp_path,
        *("--connect", "ftps-implicit", "--host", "192.0.2.1", "--user", "taro", "--path", "a/b"),
        *("--conn-password-file", str(pw)),
    )
    assert code == 0 and checked == ["s3cret"]  # 1行目だけ・改行は除く
    conn = scan_spy["conn"]
    assert conn.kind == "ftps_implicit" and conn.ftp_port == 990
    assert scan_spy["roots"] == [conn.root()] and scan_spy["password"] == "s3cret"


def test_smb_scan_disconnects_only_what_it_connected(tmp_path, monkeypatch, scan_spy):
    calls = []
    monkeypatch.setattr(cli, "smb_connect", lambda conn, password: calls.append(("connect", password)) or True)
    monkeypatch.setattr(cli, "smb_disconnect", lambda conn: calls.append(("disconnect", conn.share)))
    assert _scan(tmp_path, "--connect", "smb", "--host", "nas01", "--share", "総務") == 0
    assert calls == [("connect", ""), ("disconnect", "総務")]  # 利用者なし＝今の Windows のアカウント
    assert scan_spy["roots"] == [r"\\nas01\総務"]

    calls.clear()
    monkeypatch.setattr(cli, "smb_connect", lambda conn, password: calls.append(("connect", password)) or False)
    assert _scan(tmp_path, "--connect", "smb", "--host", "nas01", "--share", "総務") == 0
    assert calls == [("connect", "")]  # もともとつながっていたものは切らない


def test_unattended_without_password_file_is_refused(tmp_path, monkeypatch, capsys, scan_spy):
    monkeypatch.setattr(cli, "_interactive", lambda: False)
    assert _scan(tmp_path, "--connect", "ftp", "--host", "192.0.2.1", "--user", "taro") == 2
    assert "無人実行" in capsys.readouterr().err and not scan_spy


def test_connection_lost_while_checking_is_one_line(tmp_path, monkeypatch, capsys, scan_spy):
    def lost(conn, password):
        raise NetworkLost("ftp://192.0.2.1: サーバーの応答が無い")

    monkeypatch.setattr(cli, "ftp_check", lost)
    assert _scan(tmp_path, "--connect", "ftp", "--host", "192.0.2.1") == 2
    err = capsys.readouterr().err
    assert "応答が無い" in err and "Traceback" not in err and not scan_spy


def _pw_args(**kw):
    d = {"conn_password_file": None}
    d.update(kw)
    return argparse.Namespace(**d)


def test_connection_password_sources(monkeypatch):
    conn = cli.Connection.from_dict({"kind": "ftp", "host": "192.0.2.1", "user": "taro"})
    anon = cli.Connection.from_dict({"kind": "ftp", "host": "192.0.2.1"})
    assert cli._connection_password(anon, _pw_args()) == ""  # 匿名は聞かない
    monkeypatch.setattr(cli, "_interactive", lambda: True)
    asked = []
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: asked.append(prompt) or "typed")
    assert cli._connection_password(conn, _pw_args()) == "typed"
    assert "taro のパスワード" in asked[0]
    monkeypatch.setattr(cli, "_interactive", lambda: False)
    with pytest.raises(cli.ConnectError, match="--conn-password-file"):
        cli._connection_password(conn, _pw_args())


def test_connection_password_file_wins_even_for_anonymous(tmp_path):
    pw = tmp_path / "pw.txt"
    pw.write_text("anon-mail\n", encoding="utf-8")
    anon = cli.Connection.from_dict({"kind": "ftp", "host": "192.0.2.1"})
    assert cli._connection_password(anon, _pw_args(conn_password_file=str(pw))) == "anon-mail"


def test_read_user_text_accepts_bom(tmp_path):
    p = tmp_path / "allow.txt"
    p.write_bytes("\ufeff03-0000-0000\n".encode("utf-8"))
    assert cli._read_user_text(str(p), "拾わない値") == "03-0000-0000\n"


def test_read_user_text_failures(tmp_path):
    with pytest.raises(cli.UserTextError, match="拾わない値のファイルが見つかりません"):
        cli._read_user_text(str(tmp_path / "none.txt"), "拾わない値")
    sjis = tmp_path / "sjis.txt"
    sjis.write_bytes("山田太郎".encode("cp932"))
    with pytest.raises(cli.UserTextError, match="UTF-8 として読めません"):
        cli._read_user_text(str(sjis), "規則")
    with pytest.raises(cli.UserTextError, match="を読めません: "):
        cli._read_user_text(str(tmp_path), "規則")  # フォルダは開けない（OSError）


def test_unreadable_allow_file_stops_scan(tmp_path, capsys, scan_spy):
    root = tmp_path / "share"
    root.mkdir()
    assert _scan(tmp_path, str(root), "--allow-file", str(tmp_path / "none.txt")) == 2
    assert "見つかりません" in capsys.readouterr().err and not scan_spy


def test_resume_with_allow_file_is_refused(tmp_path, capsys, scan_spy):
    assert _scan(tmp_path, "--resume", "1", "--allow-file", "x.txt") == 2
    assert "--resume と --allow-file・--rules-file は一緒に使えません" in capsys.readouterr().err

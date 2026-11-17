"""接続方式の部品（remote）の、通信を伴わない試験。接続先の読み取り・確かめ・パスの組み立て・例外の言い換え。"""

import ftplib
import socket
import ssl

import pytest

from pii_checker import remote, safeio


def _ftp(**kw):
    d = {"kind": "ftp", "host": "192.0.2.10", "user": "taro"}
    d.update(kw)
    return remote.Connection.from_dict(d)


@pytest.mark.parametrize(
    "value,expected",
    [("false", False), ("0", False), ("off", False), ("", False), ("true", True), (" Yes ", True), ("on", True)],
)
def test_verify_cert_text_is_not_read_as_true(value, expected):
    assert _ftp(verify_cert=value).verify_cert is expected


def test_verify_cert_non_text_is_bool():
    assert _ftp(verify_cert=1).verify_cert is True
    assert _ftp(verify_cert=None).verify_cert is False


@pytest.mark.parametrize("value,expected", [(1, 3), (500, 120), ("30", 30), ("abc", 15), (None, 15)])
def test_timeout_is_clamped_or_defaulted(value, expected):
    assert _ftp(timeout=value).timeout == expected


def test_port_text_and_empty():
    assert _ftp(port="2121").port == 2121
    assert _ftp(port="").port is None
    with pytest.raises(remote.ConnectError, match=r"ポート（abc）は数字で"):
        _ftp(port="abc")


def test_from_dict_ignores_unknown_keys_and_none():
    c = remote.Connection.from_dict({"kind": " ftp ", "host": " //h/ ", "password": "pw", "extra": 1})
    assert (c.kind, c.host) == ("ftp", "h")
    assert "password" not in c.public()
    empty = remote.Connection.from_dict(None)
    with pytest.raises(remote.ConnectError, match="接続方式"):
        empty.validate()


@pytest.mark.parametrize(
    "kw,words",
    [
        ({"kind": "sftp"}, "接続方式（sftp）が分かりません"),
        ({"host": ""}, "サーバーの名前か IP アドレスを入れて"),
        ({"host": "h:2121"}, "ポートを付けないで"),
        ({"port": 0}, "1〜65535"),
        ({"port": 70000}, "1〜65535"),
        ({"encoding": "euc-jp"}, "文字コード（euc-jp）が分かりません"),
    ],
)
def test_validate_messages(kw, words):
    with pytest.raises(remote.ConnectError) as ei:
        _ftp(**kw).validate()
    assert words in str(ei.value)


def test_ipv6_like_host_is_not_taken_as_port():
    _ftp(host="fe80::1").validate()  # コロンが2つ以上ならポートの付け忘れとみなさない


def test_ftp_base_and_root():
    assert _ftp().ftp_base() == "ftp://192.0.2.10"
    assert _ftp(port=21).ftp_base() == "ftp://192.0.2.10"  # 既定のポートは書かない
    assert _ftp(port=2121).ftp_base() == "ftp://192.0.2.10:2121"
    assert _ftp(kind="ftps_implicit").ftp_base() == "ftps://192.0.2.10"
    assert _ftp(kind="ftps_implicit", port=21).ftp_base() == "ftps://192.0.2.10:21"
    assert _ftp(kind="ftps").ftp_port == 21
    assert _ftp(kind="ftps_implicit").ftp_port == 990
    assert _ftp(path="a/b").root() == "ftp://192.0.2.10/a/b"
    assert _ftp(start_dir="/home/taro/a/").root() == "ftp://192.0.2.10/home/taro/a"
    assert _ftp(start_dir="/").root() == "ftp://192.0.2.10/"
    assert _ftp().is_ftp


def test_short_name():
    assert _ftp(path="総務/2024年度").short_name() == "FTP 192.0.2.10・総務/2024年度"
    assert _ftp().short_name() == "FTP 192.0.2.10・（全体）"
    assert _ftp(kind="ftps_implicit").short_name().startswith("FTPS ")
    assert "FTPS（明示的 TLS" in _ftp(kind="ftps").label()


def test_is_ftp_path_and_server_path():
    assert remote.is_ftp_path("FTP://h/a") and remote.is_ftp_path("ftps://h/a")
    assert not remote.is_ftp_path("\\\\h\\a") and not remote.is_ftp_path(None)
    assert remote.ftp_server_path("ftp://h:2121") == "/"
    assert remote.ftp_server_path("ftp://h/") == "/"
    assert remote.ftp_server_path("ftp://h/a/b.txt") == "/a/b.txt"


def test_parse_mdtm():
    assert remote._parse_mdtm("213 20240102030405") == 1704164645.0
    assert remote._parse_mdtm("20240102030405.25") == pytest.approx(1704164645.25)
    assert remote._parse_mdtm("") == 0.0
    assert remote._parse_mdtm(None) == 0.0
    assert remote._parse_mdtm("550 no such file") == 0.0


class _Mdtm:
    def __init__(self, resp=None, exc=None):
        self.resp, self.exc = resp, exc

    def sendcmd(self, cmd):
        if self.exc:
            raise self.exc
        return self.resp


def test_mdtm_without_permission_is_zero():
    assert remote._mdtm(_Mdtm(exc=ftplib.error_perm("550 not allowed")), "/a") == 0.0
    assert remote._mdtm(_Mdtm(resp="213 20240102030405"), "/a") == 1704164645.0


def _cert_error():
    e = ssl.SSLCertVerificationError("bad cert")
    e.verify_message = "self-signed certificate"
    return e


@pytest.mark.parametrize(
    "exc,cls,words,network,auth",
    [
        (socket.gaierror("no host"), remote.ConnectError, "サーバーの名前が見つからない", True, False),
        (ConnectionRefusedError(), remote.ConnectError, "接続を断られた", True, False),
        (_cert_error(), remote.ConnectError, "self-signed certificate", False, False),
        (ssl.SSLEOFError(), safeio.NetworkLost, "途中で切れた（SSLEOFError）", None, None),
        (ssl.SSLZeroReturnError(), safeio.NetworkLost, "途中で切れた（SSLZeroReturnError）", None, None),
        (ssl.SSLError("wrong version"), remote.ConnectError, "FTPS の方式（明示的・暗黙的）", False, False),
        (ftplib.error_perm("530 Login incorrect."), remote.ConnectError, "ログインできない", False, True),
        (ftplib.error_perm("550 denied"), remote.ConnectError, "サーバーが断った: 550 denied", False, False),
        (TimeoutError(), safeio.NetworkLost, "15 秒待った", None, None),
        (socket.timeout(), safeio.NetworkLost, "応答が無い", None, None),
        (ftplib.error_temp("421 too many"), safeio.NetworkLost, "error_temp: 421 too many", None, None),
        (EOFError(), safeio.NetworkLost, "接続が切れた（EOFError", None, None),
        (ConnectionResetError("reset"), safeio.NetworkLost, "ConnectionResetError", None, None),
        (ValueError("odd"), remote.ConnectError, "ValueError: odd", False, False),
    ],
)
def test_ftp_error_translation(exc, cls, words, network, auth):
    err = remote._ftp_error(exc, _ftp())
    assert type(err) is cls
    assert words in str(err)
    assert str(err).startswith("ftp://192.0.2.10")
    if network is not None:
        assert err.network is network and err.auth is auth


@pytest.mark.parametrize("code", ["500", "502", "504", "534"])
def test_ftps_auth_tls_refused_is_explained_only_for_explicit_ftps(code):
    e = ftplib.error_perm(f"{code} AUTH not understood")
    assert "FTPS（AUTH TLS）に対応していない" in str(remote._ftp_error(e, _ftp(kind="ftps")))
    assert "サーバーが断った" in str(remote._ftp_error(e, _ftp(kind="ftp")))


def test_unicode_error_does_not_show_the_text():
    with pytest.raises(UnicodeEncodeError) as ei:
        "秘密のパスワード".encode("ascii")
    e = ei.value
    err = remote._ftp_error(e, _ftp(encoding="cp932"))
    assert "Shift_JIS" in str(err) and "秘密" not in str(err)
    assert "自動" in str(remote._ftp_error(e, _ftp()))

"""SMB の接続（remote.smb_connect）の試験。Windows の mpr.dll を偽物に差し替えて、分かれ道を1つずつ確かめる。

本物の Samba での確かめは tests/linux_check.py。ここでは本物の接続を張らない。
"""

import ctypes
import os
import time

import pytest

from pii_checker import remote

pytestmark = pytest.mark.skipif(os.name != "nt", reason="SMB の接続は Windows でだけ使う")

SHARE = "\\\\nas01\\総務"


class FakeMpr:
    """WNetGetUserW・WNetAddConnection2W・WNetCancelConnection2W の偽物（呼ばれた引数を記録する）。"""

    def __init__(self, existing=None, add_err=0):
        self.existing = existing
        self.add_err = add_err
        self.added = []
        self.cancelled = []

    def WNetGetUserW(self, share, buf, n):  # noqa: N802  Windows の関数名に合わせる
        if self.existing is None:
            return 2250  # ERROR_NOT_CONNECTED
        buf.value = self.existing
        return 0

    def WNetAddConnection2W(self, nr, password, user, flags):  # noqa: N802
        res = nr._obj
        self.added.append((res.lpRemoteName, password, user, flags))
        return self.add_err

    def WNetCancelConnection2W(self, name, flags, force):  # noqa: N802
        self.cancelled.append(name)
        return 0


@pytest.fixture
def mpr(monkeypatch):
    fake = FakeMpr()
    monkeypatch.setattr(ctypes, "WinDLL", lambda name, use_last_error=False: fake)
    monkeypatch.setattr(time, "sleep", lambda s: None)  # つなぎ直しを待つ間を飛ばす
    return fake


def _isdir(monkeypatch, answers):
    """os.path.isdir の答えを順に返す（尽きたら最後の答えを返し続ける）。聞かれたパスを記録する。"""
    asked = []
    seq = list(answers)

    def fake(path):
        asked.append(path)
        return seq.pop(0) if len(seq) > 1 else seq[0]

    monkeypatch.setattr(remote.os.path, "isdir", fake)
    return asked


def _conn(**kw):
    d = {"kind": "smb", "host": "nas01", "share": "総務", "path": "2024年度", "user": "taro"}
    d.update(kw)
    return remote.Connection.from_dict(d)


def test_new_connection_is_created_with_password(mpr, monkeypatch):
    _isdir(monkeypatch, [True])
    assert remote.smb_connect(_conn(), "pw") is True
    assert mpr.added == [(SHARE, "pw", "taro", 4)]
    assert mpr.cancelled == []


def test_without_user_uses_current_account_and_no_password(mpr, monkeypatch):
    _isdir(monkeypatch, [True])
    assert remote.smb_connect(_conn(user=""), "pw") is True
    assert mpr.added == [(SHARE, None, None, 4)]  # パスワードを渡さない


def test_missing_folder_after_new_connection_disconnects(mpr, monkeypatch):
    _isdir(monkeypatch, [False])
    with pytest.raises(remote.ConnectError, match="フォルダ.*2024年度.*見つからない"):
        remote.smb_connect(_conn(), "pw")
    assert mpr.cancelled == [SHARE]  # 張った接続を残さない


def test_existing_same_user_connection_is_reused(mpr, monkeypatch):
    mpr.existing = "NAS01\\Taro"  # ドメイン付き・大文字でも同じユーザー
    _isdir(monkeypatch, [True])
    assert remote.smb_connect(_conn(), "pw") is False  # 既存の接続は終わっても切らない
    assert mpr.added == []


def test_existing_connection_of_other_user_is_refused(mpr, monkeypatch):
    mpr.existing = "hanako"
    _isdir(monkeypatch, [True])
    with pytest.raises(remote.ConnectError, match="別のユーザー（hanako）") as ei:
        remote.smb_connect(_conn(), "pw")
    assert not ei.value.auth  # パスワードを捨てて聞き直す失敗ではない
    assert mpr.added == []


def test_existing_connection_without_user_is_reused(mpr, monkeypatch):
    mpr.existing = "hanako"  # ユーザーを入れなければ、今の接続のユーザーで検査してよい
    _isdir(monkeypatch, [True])
    assert remote.smb_connect(_conn(user=""), "pw") is False


def test_existing_connection_not_visible_is_reconnected_but_not_owned(mpr, monkeypatch):
    mpr.existing = "taro"
    # つなぎ直しを待つ4回は見えず、張り直した後に見える
    asked = _isdir(monkeypatch, [False, False, False, False, True])
    assert remote.smb_connect(_conn(), "pw") is False  # 張り直しただけなので終わっても切らない
    assert len(mpr.added) == 1
    assert len(asked) == 5


@pytest.mark.parametrize("err", [85, 1219])
def test_existing_connection_reconnects_after_already_connected_error(mpr, monkeypatch, err):
    mpr.existing = "taro"
    mpr.add_err = err
    # 最初の4回は見えず、張り直しが「既につながっている」で断られた後のつなぎ直しの待ちで見える
    _isdir(monkeypatch, [False, False, False, False, False, True])
    assert remote.smb_connect(_conn(), "pw") is False
    assert mpr.cancelled == []


@pytest.mark.parametrize("err", [85, 1219])
def test_existing_connection_with_missing_folder_says_check_folder(mpr, monkeypatch, err):
    mpr.existing = "taro"
    mpr.add_err = err
    _isdir(monkeypatch, [False])
    with pytest.raises(remote.ConnectError, match="共有にはつながっているが.*フォルダの欄を確かめる"):
        remote.smb_connect(_conn(), "pw")
    assert mpr.cancelled == []  # 既存の接続は切らない


def test_1219_without_user_uses_current_account_connection(mpr, monkeypatch):
    mpr.add_err = 1219
    asked = _isdir(monkeypatch, [True])
    assert remote.smb_connect(_conn(user=""), "pw") is False
    assert asked[0] == SHARE  # 共有そのものが開けるかを見る


def test_1219_with_user_and_no_existing_connection_is_explained(mpr, monkeypatch):
    mpr.add_err = 1219
    _isdir(monkeypatch, [True])
    with pytest.raises(remote.ConnectError, match="別のユーザー名で既に接続している") as ei:
        remote.smb_connect(_conn(), "pw")
    assert not ei.value.auth


@pytest.mark.parametrize(
    "err,auth,words",
    [
        (1326, True, "ユーザー名かパスワードが違う"),
        (86, True, "パスワードが違う"),
        (1330, True, "期限が切れている"),
        (1909, False, "ロックされている"),  # 入れ直しても直らないのでパスワードを捨てない
        (53, False, "サーバーが見つからない"),
        (9999, False, "Windows のエラー 9999"),
    ],
)
def test_add_connection_errors_are_explained(mpr, monkeypatch, err, auth, words):
    mpr.add_err = err
    _isdir(monkeypatch, [True])
    with pytest.raises(remote.ConnectError) as ei:
        remote.smb_connect(_conn(), "pw")
    assert words in str(ei.value)
    assert SHARE in str(ei.value)
    assert ei.value.auth is auth
    assert "pw" not in str(ei.value)


def test_invalid_connection_is_refused_before_touching_windows(mpr, monkeypatch):
    _isdir(monkeypatch, [True])
    with pytest.raises(remote.ConnectError, match="共有名を入れて"):
        remote.smb_connect(_conn(share=""), "pw")
    with pytest.raises(remote.ConnectError, match="ポートを変えられません"):
        remote.smb_connect(_conn(port=139), "pw")
    assert mpr.added == []


def test_port_445_is_allowed(mpr, monkeypatch):
    _isdir(monkeypatch, [True])
    assert remote.smb_connect(_conn(port=445), "pw") is True


def test_disconnect_cancels_the_share(mpr):
    remote.smb_disconnect(_conn())
    assert mpr.cancelled == [SHARE]


def test_existing_user_lookup(mpr):
    assert remote._smb_existing_user(SHARE) is None
    mpr.existing = "DOM\\taro"
    assert remote._smb_existing_user(SHARE) == "DOM\\taro"


@pytest.mark.parametrize(
    "user,bare",
    [("DOMAIN\\Taro", "taro"), ("taro@example.local", "taro"), (" Taro ", "taro"), ("taro", "taro")],
)
def test_bare_user(user, bare):
    assert remote._bare_user(user) == bare


def test_isdir_after_reconnect_waits_between_tries(monkeypatch):
    waits = []
    monkeypatch.setattr(time, "sleep", waits.append)
    _isdir(monkeypatch, [False])
    assert remote._isdir_after_reconnect("x", tries=3, wait=0.5) is False
    assert waits == [0.5, 0.5]  # 最後の確かめの後は待たない
    _isdir(monkeypatch, [False, True])
    assert remote._isdir_after_reconnect("x", tries=3, wait=0.5) is True


def test_smb_root_label_and_short_name():
    c = _conn()
    assert c.root() == "\\\\nas01\\総務\\2024年度"
    assert c.short_name() == "SMB nas01・総務/2024年度"
    assert _conn(path="").root() == SHARE
    assert _conn(path="").short_name() == "SMB nas01・総務"
    assert "Windows 共有" in c.label()
    assert not c.is_ftp

"""対処の新しいファイルへの属性の引き継ぎ（remedy_meta）の細かい枝の試験。

test_remediate_safety.py は本物のファイルで隠し属性・作成日時・ACL・代替データストリームが写ることを確かめる。
ここでは、Windows の API を偽物に置き換えて、読めない・設定できないときの知らせの文と、
1つの段の失敗が他の段や対処そのものを止めないことを確かめる。
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pii_checker import remedy_meta  # noqa: E402

BAD = 0xFFFFFFFF  # GetFileAttributesW の失敗の値


class FakeK32:
    """kernel32 の偽物。属性・ハンドル・日時の読み書きの成否を試験ごとに決める。"""

    def __init__(self, attrs=None, handles=None, get_time=1, set_time=1, set_attr=1):
        self.attrs = attrs or {}
        self.handles = handles or {}
        self.get_time, self.set_time, self.set_attr = get_time, set_time, set_attr
        self.closed: list[int] = []
        self.freed: list[object] = []
        self.set_calls: list[tuple[str, int]] = []

    def GetFileAttributesW(self, path):
        return self.attrs.get(self._key(path), BAD)

    def SetFileAttributesW(self, path, value):
        self.set_calls.append((self._key(path), value))
        return self.set_attr

    def CreateFileW(self, path, *_args):
        return self.handles.get(self._key(path), remedy_meta.INVALID_HANDLE)

    def GetFileTime(self, *_args):
        return self.get_time

    def SetFileTime(self, *_args):
        return self.set_time

    def CloseHandle(self, h):
        self.closed.append(h)
        return 1

    def LocalFree(self, p):
        self.freed.append(p)
        return None

    @staticmethod
    def _key(path: str) -> str:
        return "src" if path.endswith("src") else "dst"


@pytest.fixture(autouse=True)
def plain_long(monkeypatch):
    """長いパスの前置きを外し、偽物の側で src・dst を見分けやすくする。"""
    monkeypatch.setattr(remedy_meta, "_long", lambda p: p)


# ---------------------------------------------------------------- 属性


def test_attributes_unreadable_source():
    assert "属性（隠しファイルなど）を読めず" in remedy_meta._copy_attributes(FakeK32(), "src", "dst")


def test_attributes_encrypted_source_is_noted_even_when_copied():
    k32 = FakeK32(attrs={"src": remedy_meta.ATTR_ENCRYPTED | 0x2, "dst": 0x20})
    note = remedy_meta._copy_attributes(k32, "src", "dst")
    assert "暗号化（EFS）" in note
    # 隠し属性は写り、元に無いアーカイブ属性は落とす（暗号化の印そのものは写さない）
    assert k32.set_calls == [("dst", 0x2)]


def test_attributes_compressed_source_is_not_noted():
    k32 = FakeK32(attrs={"src": remedy_meta.ATTR_COMPRESSED, "dst": 0})
    assert remedy_meta._copy_attributes(k32, "src", "dst") == ""
    assert k32.set_calls == []  # 写す属性が同じなら設定しない


def test_attributes_unreadable_destination():
    k32 = FakeK32(attrs={"src": 0x2})
    assert "新しいファイルの属性を読めず" in remedy_meta._copy_attributes(k32, "src", "dst")
    # 暗号化の知らせがあるときは、そちらを優先して返す
    k32 = FakeK32(attrs={"src": remedy_meta.ATTR_ENCRYPTED})
    assert "暗号化（EFS）" in remedy_meta._copy_attributes(k32, "src", "dst")


def test_attributes_set_failure():
    k32 = FakeK32(attrs={"src": 0x2, "dst": 0}, set_attr=0)
    assert remedy_meta._copy_attributes(k32, "src", "dst") == "属性（隠しファイルなど）を引き継げませんでした"


# ---------------------------------------------------------------- 作成日時


def test_creation_time_source_cannot_open():
    k32 = FakeK32(handles={"dst": 2})
    assert remedy_meta._copy_creation_time(k32, "src", "dst") == "作成日時を読めず、引き継げませんでした"
    assert k32.closed == []


def test_creation_time_source_cannot_read_closes_handle():
    k32 = FakeK32(handles={"src": 1, "dst": 2}, get_time=0)
    assert remedy_meta._copy_creation_time(k32, "src", "dst") == "作成日時を読めず、引き継げませんでした"
    assert k32.closed == [1]


def test_creation_time_destination_cannot_open():
    k32 = FakeK32(handles={"src": 1})
    assert remedy_meta._copy_creation_time(k32, "src", "dst") == "新しいファイルの作成日時を設定できませんでした"
    assert k32.closed == [1]


def test_creation_time_set_failure_closes_both():
    k32 = FakeK32(handles={"src": 1, "dst": 2}, set_time=0)
    assert remedy_meta._copy_creation_time(k32, "src", "dst") == "作成日時を引き継げませんでした"
    assert k32.closed == [1, 2]


# ---------------------------------------------------------------- アクセス権（ACL）


def fake_advapi(get_rc=0, set_rc=0):
    """advapi32 の偽物。restype・argtypes を付けられるよう関数で持つ。"""

    def get_info(*_args):
        return get_rc

    def set_info(*_args):
        return set_rc

    def control(*_args):
        return 0  # 読めなければ保護されていない扱い

    return SimpleNamespace(
        GetNamedSecurityInfoW=get_info, SetNamedSecurityInfoW=set_info, GetSecurityDescriptorControl=control
    )


def test_acl_unreadable(monkeypatch):
    monkeypatch.setattr(remedy_meta.ctypes, "WinDLL", lambda *_a, **_k: fake_advapi(get_rc=5))
    k32 = FakeK32()
    assert remedy_meta._copy_acl(k32, "src", "dst") == "アクセス権（ACL）を読めず、引き継げませんでした"
    assert k32.freed == []  # 読めなかったときは解放するものが無い


def test_acl_set_failure_still_frees(monkeypatch):
    monkeypatch.setattr(remedy_meta.ctypes, "WinDLL", lambda *_a, **_k: fake_advapi(set_rc=5))
    k32 = FakeK32()
    assert remedy_meta._copy_acl(k32, "src", "dst") == "アクセス権（ACL）を引き継げませんでした"
    assert len(k32.freed) == 1


# ---------------------------------------------------------------- 代替データストリーム


def test_streams_listing_failure(monkeypatch):
    def broken(_src):
        raise OSError("一覧を取れない")

    monkeypatch.setattr(remedy_meta, "_stream_names", broken)
    assert remedy_meta._copy_streams("src", "dst") == ["代替データストリームの一覧を取れず、引き継げませんでした"]


@pytest.mark.skipif(os.name != "nt", reason="代替データストリームは NTFS だけ")
def test_streams_too_big_and_write_failure(tmp_path, monkeypatch):
    src = tmp_path / "a.txt"
    src.write_bytes(b"body")
    with open(str(src) + ":big", "wb") as f:
        f.write(b"0123456789")
    with open(str(src) + ":small", "wb") as f:
        f.write(b"ok")
    monkeypatch.setattr(remedy_meta, "MAX_STREAM_BYTES", 4)
    # 書き先のフォルダが無いので、小さいストリームの書き込みは失敗する
    notes = remedy_meta._copy_streams(str(src), str(tmp_path / "missing" / "b.txt"))
    assert notes == [
        "大きな代替データストリーム 1 件（0MB 超）は引き継げませんでした",
        "代替データストリーム 1 件を引き継げませんでした",
    ]


# ---------------------------------------------------------------- まとめの入口


def test_non_windows_copies_mode(tmp_path, monkeypatch):
    monkeypatch.setattr(remedy_meta, "os", SimpleNamespace(name="posix"))
    src, dst = tmp_path / "a.txt", tmp_path / "b.txt"
    src.write_text("x")
    dst.write_text("y")
    assert remedy_meta.inherit_file_metadata(str(src), str(dst)) == []
    assert remedy_meta.inherit_file_metadata(str(tmp_path / "none"), str(dst)) == [
        "ファイルの権限を引き継げませんでした"
    ]


@pytest.mark.skipif(os.name != "nt", reason="Windows の経路")
def test_one_step_failure_does_not_stop_others(monkeypatch):
    def boom(*_args):
        raise ValueError("壊れた")

    monkeypatch.setattr(remedy_meta, "_kernel32", lambda: FakeK32())
    monkeypatch.setattr(remedy_meta, "_copy_attributes", boom)
    monkeypatch.setattr(remedy_meta, "_copy_creation_time", lambda *_a: "")
    monkeypatch.setattr(remedy_meta, "_copy_acl", lambda *_a: "アクセス権（ACL）を引き継げませんでした")
    monkeypatch.setattr(remedy_meta, "_copy_streams", lambda *_a: ["代替データストリーム 1 件を引き継げませんでした"])
    assert remedy_meta.inherit_file_metadata("src", "dst") == [
        "引き継ぎの途中で失敗しました（ValueError）",
        "アクセス権（ACL）を引き継げませんでした",
        "代替データストリーム 1 件を引き継げませんでした",
    ]


@pytest.mark.skipif(os.name != "nt", reason="Windows の経路")
def test_kernel32_unavailable_is_reported_not_raised(monkeypatch):
    def no_dll():
        raise OSError("読み込めない")

    monkeypatch.setattr(remedy_meta, "_kernel32", no_dll)
    assert remedy_meta.inherit_file_metadata("src", "dst") == [
        "属性・作成日時・アクセス権の引き継ぎに失敗しました（OSError）"
    ]

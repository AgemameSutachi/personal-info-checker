"""対処で作る新しいファイルへ、元のファイルの属性・作成日時・アクセス権（ACL）・代替データストリームを引き継ぐ。

書き換えは「一時の名前で新しいファイルを書く → 元の名前へ置く」ので、何もしないと、隠し属性・作成日時・アクセス権（元のファイルだけに
付けた許可・拒否）・代替データストリーム（ダウンロード元の印 Zone.Identifier など）が新しいファイルから抜け落ちる。
引き継げるものは引き継ぎ、引き継げなかったものは知らせ（notes）として返す（対処そのものは止めない）。Windows 以外では何もしない。
"""

from __future__ import annotations

import ctypes
import os
import shutil
from ctypes import wintypes

# 引き継ぐ属性: 隠し・システム・アーカイブ・インデックスしない（読み取り専用は対処の前提で断っているので引き継がない）
ATTR_COPY_MASK = 0x2 | 0x4 | 0x20 | 0x2000
ATTR_COMPRESSED, ATTR_ENCRYPTED = 0x800, 0x4000
# 検査が数えない既知のストリーム（engine.IGNORED_STREAMS と同じ）。印や属性なので、あれば写す
KNOWN_STREAMS = ("Zone.Identifier", "SmartScreen", "com.dropbox.attrs", "encryptable", "AFP_AfpInfo", "AFP_Resource")
MAX_STREAM_BYTES = 64 * 1024 * 1024  # 1つのストリームを写す大きさの上限（これを超えるものは写さず、知らせる）
SE_FILE_OBJECT = 1
DACL_SECURITY_INFORMATION = 0x4
PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000
SE_DACL_PROTECTED = 0x1000
INVALID_HANDLE = wintypes.HANDLE(-1).value


class _FILETIME(ctypes.Structure):
    _fields_ = [("lo", wintypes.DWORD), ("hi", wintypes.DWORD)]


def _long(path: str) -> str:
    from .engine import long_path

    return long_path(path)


def _kernel32():
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    k32.GetFileTime.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    k32.SetFileTime.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.GetFileAttributesW.restype = wintypes.DWORD
    k32.GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
    k32.SetFileAttributesW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
    k32.LocalFree.argtypes = [ctypes.c_void_p]
    return k32


def _copy_attributes(k32, src: str, dst: str) -> str:
    """属性（隠し・システムなど）を写す。引き継げなかったものの知らせ（無ければ空）。"""
    attrs = k32.GetFileAttributesW(_long(src))
    if attrs == 0xFFFFFFFF:
        return "属性（隠しファイルなど）を読めず、引き継げませんでした"
    note = ""
    if attrs & ATTR_ENCRYPTED:
        note = "元のファイルは Windows の暗号化（EFS）されていましたが、新しいファイルには引き継がれません"
    elif attrs & ATTR_COMPRESSED:
        note = ""  # NTFS の圧縮は中身に影響しないので知らせない
    cur = k32.GetFileAttributesW(_long(dst))
    if cur == 0xFFFFFFFF:
        return note or "新しいファイルの属性を読めず、引き継げませんでした"
    want = (cur & ~ATTR_COPY_MASK) | (attrs & ATTR_COPY_MASK)
    if want != cur and not k32.SetFileAttributesW(_long(dst), want):
        return "属性（隠しファイルなど）を引き継げませんでした"
    return note


def _copy_creation_time(k32, src: str, dst: str) -> str:
    """作成日時を写す（更新日時は、書き換えた時刻のまま）。"""
    GENERIC_WRITE_ATTR, READ_ATTR = 0x100, 0x80  # FILE_WRITE_ATTRIBUTES / FILE_READ_ATTRIBUTES
    SHARE_ALL = 0x7
    OPEN_EXISTING, BACKUP = 3, 0x02000000
    h_src = k32.CreateFileW(_long(src), READ_ATTR, SHARE_ALL, None, OPEN_EXISTING, BACKUP, None)
    if h_src in (None, INVALID_HANDLE):
        return "作成日時を読めず、引き継げませんでした"
    try:
        created = _FILETIME()
        if not k32.GetFileTime(h_src, ctypes.byref(created), None, None):
            return "作成日時を読めず、引き継げませんでした"
    finally:
        k32.CloseHandle(h_src)
    h_dst = k32.CreateFileW(_long(dst), GENERIC_WRITE_ATTR, SHARE_ALL, None, OPEN_EXISTING, BACKUP, None)
    if h_dst in (None, INVALID_HANDLE):
        return "新しいファイルの作成日時を設定できませんでした"
    try:
        if not k32.SetFileTime(h_dst, ctypes.byref(created), None, None):
            return "作成日時を引き継げませんでした"
    finally:
        k32.CloseHandle(h_dst)
    return ""


def _copy_acl(k32, src: str, dst: str) -> str:
    """アクセス権（DACL）を写す。元のファイルだけに付けた許可・拒否が、新しいファイルで消えないように。"""
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    adv.GetNamedSecurityInfoW.restype = wintypes.DWORD
    adv.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.UINT,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    adv.SetNamedSecurityInfoW.restype = wintypes.DWORD
    adv.SetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        wintypes.UINT,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    adv.GetSecurityDescriptorControl.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    pdacl, psd = ctypes.c_void_p(), ctypes.c_void_p()
    rc = adv.GetNamedSecurityInfoW(
        _long(src), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, None, None, ctypes.byref(pdacl), None, ctypes.byref(psd)
    )
    if rc != 0:
        return "アクセス権（ACL）を読めず、引き継げませんでした"
    try:
        control, revision = wintypes.WORD(), wintypes.DWORD()
        protected = bool(
            adv.GetSecurityDescriptorControl(psd, ctypes.byref(control), ctypes.byref(revision))
            and control.value & SE_DACL_PROTECTED
        )
        flag = PROTECTED_DACL_SECURITY_INFORMATION if protected else UNPROTECTED_DACL_SECURITY_INFORMATION
        rc = adv.SetNamedSecurityInfoW(
            _long(dst), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | flag, None, None, pdacl, None
        )
        if rc != 0:
            return "アクセス権（ACL）を引き継げませんでした"
    finally:
        k32.LocalFree(psd)
    return ""


def _stream_names(src: str) -> list[str]:
    from .engine import alternate_streams

    names = [name for name, _size in alternate_streams(src)]
    for known in KNOWN_STREAMS:
        if known not in names:
            names.append(known)  # 読めなければ（無ければ）あとで飛ばす
    return names


def _copy_streams(src: str, dst: str) -> list[str]:
    """代替データストリームを写す（隠しストリーム・ダウンロード元の印など）。引き継げなかったものの知らせ。"""
    notes: list[str] = []
    try:
        names = _stream_names(src)
    except OSError:
        return ["代替データストリームの一覧を取れず、引き継げませんでした"]
    skipped_big = failed = 0
    for name in names:
        s_path = _long(src) + ":" + name
        try:
            if os.path.getsize(s_path) > MAX_STREAM_BYTES:
                skipped_big += 1
                continue
            with open(s_path, "rb") as f:
                data = f.read()
        except OSError:
            continue  # 既知の名前で、元に無かったもの
        try:
            with open(_long(dst) + ":" + name, "wb") as f:
                f.write(data)
        except OSError:
            failed += 1
    if skipped_big:
        notes.append(
            f"大きな代替データストリーム {skipped_big} 件（{MAX_STREAM_BYTES // 1024 // 1024}MB 超）は引き継げませんでした"
        )
    if failed:
        notes.append(f"代替データストリーム {failed} 件を引き継げませんでした")
    return notes


def inherit_file_metadata(src: str, dst: str) -> list[str]:
    """新しいファイル dst へ、元のファイル src の属性・作成日時・アクセス権・代替データストリームを引き継ぐ。
    引き継げなかったものの知らせ（結果に添える。値は含めない）を返す。失敗しても例外は出さない。"""
    if os.name != "nt":
        try:
            shutil.copymode(src, dst)
        except OSError:
            return ["ファイルの権限を引き継げませんでした"]
        return []
    notes: list[str] = []
    try:
        k32 = _kernel32()
        steps = (
            lambda: _copy_attributes(k32, src, dst),
            lambda: _copy_creation_time(k32, src, dst),
            lambda: _copy_acl(k32, src, dst),
        )
        for step in steps:
            try:
                note = step()
            except Exception as e:  # noqa: BLE001  引き継ぎの失敗で、対処そのものを止めない
                note = f"引き継ぎの途中で失敗しました（{type(e).__name__}）"
            if note:
                notes.append(note)
        notes.extend(_copy_streams(src, dst))
    except Exception as e:  # noqa: BLE001
        notes.append(f"属性・作成日時・アクセス権の引き継ぎに失敗しました（{type(e).__name__}）")
    return notes

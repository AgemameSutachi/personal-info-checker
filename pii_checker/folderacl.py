"""フォルダのアクセス権（誰が読めるか）を読む。

検出のあったファイルの親フォルダのアクセス権（DACL）を読み、Everyone などの「広く誰でも」に当たる SID が
読み取りを許されているかを見る。結果は次の3つ（と FTP）:

- broad … 広く読める（Everyone・Authenticated Users・BUILTIN\\Users・Domain Users・Anonymous などに読み取りの許可）
- limited … 限られた人だけ（上の SID に読み取りの許可が無い）
- unknown … 読めなかった（アクセス権を読む権限が無い・回線断・Windows 以外 など）
- ftp … FTP にはアクセス権を問い合わせる手段が無いので取らない

読むだけで、何も書き換えない。フォルダは READ_CONTROL（アクセス権を読む権利）だけで開き、中身の一覧も
ファイルの中身も読まない（一覧や中身を読まないので、フォルダ・ファイルの最終アクセス日時は変わらない）。
FILE_FLAG_OPEN_NO_RECALL を付けて、階層化ストレージから呼び戻させない。pywin32 は依存に無いので ctypes で呼ぶ。

判定は目安: 拒否の項目は、同じ「広く誰でも」の SID への読み取りの拒否があれば許可を打ち消すとみなすだけで、
グループの入れ子・ファイル側の個別の設定・共有のアクセス許可（SMB の共有の設定）までは見ない。
"""

from __future__ import annotations

import os
import re
import threading
from dataclasses import dataclass

BROAD = "broad"
LIMITED = "limited"
UNKNOWN = "unknown"
FTP = "ftp"

LABELS = {
    BROAD: "広く読める（Everyone など）",
    LIMITED: "限られた人だけ",
    UNKNOWN: "読めなかった",
    FTP: "取れない（FTP）",
}

# 「広く誰でも」に当たるよく知られた SID
WELL_KNOWN_BROAD = {
    "S-1-1-0": "Everyone",
    "S-1-5-7": "Anonymous",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-32-546": "BUILTIN\\Guests",
    "S-1-5-2": "NETWORK",
    "S-1-5-4": "INTERACTIVE",
}
# ドメインの全員（Domain Users = 513・Domain Guests = 514）
RE_DOMAIN_BROAD = re.compile(r"^S-1-5-21-\d+-\d+-\d+-(513|514)$")

# 読み取りに当たる権利（FILE_READ_DATA / FILE_LIST_DIRECTORY・GENERIC_READ・GENERIC_ALL）
READ_MASK = 0x0001 | 0x80000000 | 0x10000000
ACCESS_ALLOWED_ACE_TYPE = 0
ACCESS_DENIED_ACE_TYPE = 1
OBJECT_INHERIT_ACE = 0x01
INHERIT_ONLY_ACE = 0x08


@dataclass
class FolderAccess:
    """フォルダ1つのアクセス権の読み取り結果。"""

    state: str  # BROAD / LIMITED / UNKNOWN / FTP
    who: str = ""  # 広く読めるとき: 許された SID の名前（「Everyone・BUILTIN\Users」）。読めなかったとき: 理由
    owner: str = ""  # フォルダの所有者の名前（取れたときだけ）

    @property
    def label(self) -> str:
        return LABELS.get(self.state, self.state)


def broad_name(sid: str) -> str | None:
    """「広く誰でも」に当たる SID なら名前を、当たらなければ None を返す。"""
    if sid in WELL_KNOWN_BROAD:
        return WELL_KNOWN_BROAD[sid]
    m = RE_DOMAIN_BROAD.match(sid)
    if m:
        return "Domain Users" if m.group(1) == "513" else "Domain Guests"
    return None


def judge(aces: list[tuple[int, int, int, str]] | None) -> tuple[str, list[str]]:
    """DACL の項目 (種類, フラグ, 権利, SID) の一覧から、広く読めるかを決める。aces が None は DACL が無い（全員に許可）。

    フォルダ自身に効く項目（継承専用でない）か、中のファイルへ継承される項目（OBJECT_INHERIT）だけを見る。
    """
    if aces is None:
        return BROAD, ["Everyone（アクセス権の設定が無く、全員に許可）"]
    denied: set[str] = set()
    allowed: list[str] = []
    for ace_type, flags, mask, sid in aces:
        name = broad_name(sid)
        if not name or not (mask & READ_MASK):
            continue
        if flags & INHERIT_ONLY_ACE and not flags & OBJECT_INHERIT_ACE:
            continue  # 下のフォルダにだけ継承され、このフォルダのファイルには効かない
        if ace_type == ACCESS_DENIED_ACE_TYPE:
            denied.add(name)
        elif ace_type == ACCESS_ALLOWED_ACE_TYPE and name not in allowed:
            allowed.append(name)
    allowed = [n for n in allowed if n not in denied]
    return (BROAD, allowed) if allowed else (LIMITED, [])


def read_folder(path: str) -> FolderAccess:
    """フォルダのアクセス権を読む（失敗しても例外にせず UNKNOWN で返す）。"""
    if os.name != "nt":
        return FolderAccess(UNKNOWN, "Windows 以外ではアクセス権を読めない")
    try:
        aces, owner = _read_dacl(path)
    except PermissionError:
        return FolderAccess(UNKNOWN, "アクセス権を読む権限が無い")
    except OSError as e:
        from .safeio import is_network_lost

        if is_network_lost(e):
            return FolderAccess(UNKNOWN, "接続が切れていて読めなかった")
        return FolderAccess(UNKNOWN, f"アクセス権を読めなかった（{e.strerror or e}）")
    state, names = judge(aces)
    return FolderAccess(state, "・".join(names), owner)


class AccessCache:
    """同じフォルダのアクセス権を1回だけ読むための覚え（1つのジョブの実行の間だけ）。"""

    def __init__(self) -> None:
        self._cache: dict[str, FolderAccess] = {}
        self._lock = threading.Lock()

    def for_file(self, top_path: str) -> FolderAccess:
        """実ファイルの親フォルダのアクセス権。FTP のパスは問い合わせずに FTP を返す。"""
        from .remote import is_ftp_path

        if is_ftp_path(top_path):
            return FolderAccess(FTP, "FTP ではアクセス権を問い合わせられない")
        folder = os.path.dirname(top_path)
        key = os.path.normcase(folder)
        with self._lock:
            hit = self._cache.get(key)
        if hit is not None:
            return hit
        got = read_folder(folder)
        with self._lock:
            self._cache[key] = got
        return got


# ---------------------------------------------------------------- Windows の呼び出し（ctypes）

if os.name == "nt":
    import ctypes
    from ctypes import wintypes

    _adv = ctypes.WinDLL("advapi32", use_last_error=True)
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    READ_CONTROL = 0x00020000
    FILE_SHARE_ALL = 0x1 | 0x2 | 0x4
    OPEN_EXISTING = 3
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000  # フォルダを開くのに要る
    FILE_FLAG_OPEN_NO_RECALL = 0x00100000
    SE_FILE_OBJECT = 1
    OWNER_SECURITY_INFORMATION = 0x1
    DACL_SECURITY_INFORMATION = 0x4
    ACL_SIZE_INFORMATION = 2
    INVALID_HANDLE = wintypes.HANDLE(-1).value

    class ACL_SIZE_INFO(ctypes.Structure):
        _fields_ = [("AceCount", wintypes.DWORD), ("AclBytesInUse", wintypes.DWORD), ("AclBytesFree", wintypes.DWORD)]

    class ACE_HEADER(ctypes.Structure):
        _fields_ = [("AceType", ctypes.c_ubyte), ("AceFlags", ctypes.c_ubyte), ("AceSize", ctypes.c_ushort)]

    class ACCESS_ACE(ctypes.Structure):
        # ACCESS_ALLOWED_ACE と ACCESS_DENIED_ACE は同じ形（SidStart から SID が続く）
        _fields_ = [("Header", ACE_HEADER), ("Mask", wintypes.DWORD), ("SidStart", wintypes.DWORD)]

    _k32.CreateFileW.restype = wintypes.HANDLE
    _k32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _k32.LocalFree.argtypes = [ctypes.c_void_p]
    _k32.LocalFree.restype = ctypes.c_void_p
    _adv.GetSecurityInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    _adv.GetSecurityInfo.restype = wintypes.DWORD
    _adv.GetAclInformation.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.c_int]
    _adv.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    _adv.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    _adv.LookupAccountSidW.argtypes = [
        wintypes.LPCWSTR,
        ctypes.c_void_p,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(ctypes.c_int),
    ]

    def _sid_string(psid) -> str:
        out = wintypes.LPWSTR()
        if not _adv.ConvertSidToStringSidW(psid, ctypes.byref(out)):
            return ""
        try:
            return out.value or ""
        finally:
            _k32.LocalFree(out)

    def _account_name(psid) -> str:
        """SID の名前（「DOMAIN\\user」）。引けなければ SID の文字列。

        名前はこの PC の引き方に任せる（検査先の NAS へは問い合わせない。ドメインに入った PC では、ドメインの SID を
        ドメインコントローラーへ問い合わせることがある）。NAS だけが知るアカウントは SID の文字列のまま出る。
        """
        name_len = wintypes.DWORD(256)
        dom_len = wintypes.DWORD(256)
        name = ctypes.create_unicode_buffer(256)
        dom = ctypes.create_unicode_buffer(256)
        use = ctypes.c_int()
        if _adv.LookupAccountSidW(
            None, psid, name, ctypes.byref(name_len), dom, ctypes.byref(dom_len), ctypes.byref(use)
        ):
            return f"{dom.value}\\{name.value}" if dom.value else name.value
        return _sid_string(psid)

    def _read_dacl(path: str) -> tuple[list[tuple[int, int, int, str]] | None, str]:
        """フォルダの DACL の項目と所有者の名前を返す。DACL が無い（全員に許可）ときは項目を None で返す。"""
        from .engine import long_path

        h = _k32.CreateFileW(
            long_path(path),
            READ_CONTROL,
            FILE_SHARE_ALL,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_NO_RECALL,
            None,
        )
        if h in (None, INVALID_HANDLE):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            owner = ctypes.c_void_p()
            dacl = ctypes.c_void_p()
            sd = ctypes.c_void_p()
            err = _adv.GetSecurityInfo(
                h,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                ctypes.byref(owner),
                None,
                ctypes.byref(dacl),
                None,
                ctypes.byref(sd),
            )
            if err:
                raise ctypes.WinError(err)
            try:
                owner_name = _account_name(owner) if owner.value else ""
                if not dacl.value:
                    return None, owner_name
                info = ACL_SIZE_INFO()
                if not _adv.GetAclInformation(dacl, ctypes.byref(info), ctypes.sizeof(info), ACL_SIZE_INFORMATION):
                    raise ctypes.WinError(ctypes.get_last_error())
                aces = []
                for i in range(info.AceCount):
                    pace = ctypes.c_void_p()
                    if not _adv.GetAce(dacl, i, ctypes.byref(pace)):
                        continue
                    head = ACE_HEADER.from_address(pace.value)
                    if head.AceType not in (ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE):
                        continue  # オブジェクトの項目・監査などは見ない
                    ace = ACCESS_ACE.from_address(pace.value)
                    sid = _sid_string(ctypes.c_void_p(pace.value + ACCESS_ACE.SidStart.offset))
                    aces.append((head.AceType, head.AceFlags, int(ace.Mask), sid))
                return aces, owner_name
            finally:
                _k32.LocalFree(sd)
        finally:
            _k32.CloseHandle(h)

else:  # Windows 以外（開発用）

    def _read_dacl(path: str):  # pragma: no cover
        raise OSError("Windows 以外ではアクセス権を読めない")

"""検査先のファイルに影響を与えずに読むための部品（Windows）。

守ること（検査で、指定したフォルダに影響を及ぼさない。一時ファイルも、読み取りのロックも残さない）:
- 元のファイルは「読み・書き・削除の共有をすべて許す」開き方で開く。こちらが開いている間も、他の人の上書き保存・
  改名・削除を妨げない（Python の open() は改名・削除を、7-Zip は書き込みまで妨げることを実測した）。
- 元のファイルは1回だけ先頭から読み、一時フォルダへ写す。外部の道具（7-Zip・ODBC・MuPDF 等）は写しだけを触る。
- 最終アクセス日時を保つ（SetFileTime に -1 を渡すと、その開き方での読み取りが日時を更新しない）。権限が無ければ保てなかったと記録する。
- クラウド・階層化ストレージの代替ファイル（OneDrive のオンラインのみ・NAS の HSM 等）は読まない。読むとダウンロード（呼び戻し）が起き、
  元のファイルの状態が変わるため。
- 読んでいる間に元のファイルが書き換えられたら（大きさ・更新日時・変更日時が変わったら）読み直す。

写しを作りながら SHA-256 を取り、ファイルの識別情報（大きさ・更新日時・変更日時・ファイル ID）と一緒に返す。
再検査で同じファイルを飛ばす判定（runner）に使う。
"""

from __future__ import annotations

import hashlib
import os
import shutil
from dataclasses import dataclass

CHUNK = 1024 * 1024

# 読むと呼び戻し（ダウンロード）が起きる属性
FILE_ATTRIBUTE_OFFLINE = 0x1000
FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x40000
FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x400000
RECALL_ATTRS = FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS

# 一時フォルダに必ず残しておく空き（これを割り込むなら写さずに検査不能にする）。1GB か容量の2%（5GB まで）の大きい方。
# 容量の5%にすると、1TB・空き 40GB のふつうの PC で 1 バイトのファイルも写せなくなった（不具合の修正）
MIN_FREE_BYTES = 1 * 1024**3
MIN_FREE_RATIO = 0.02
MAX_RESERVE_BYTES = 5 * 1024**3


class SourceError(Exception):
    """元のファイルを読めなかった（理由は日本語）。"""


class CloudPlaceholder(SourceError):
    """クラウドの代替ファイルなど、読むとダウンロードが起きるファイル。"""


class TempSpaceShort(SourceError):
    """一時フォルダの空きが足りない。"""


class ChangedWhileReading(SourceError):
    """読んでいる間に元のファイルが書き換えられ続けた。"""


class SourceInUse(SourceError, PermissionError):
    """他のプログラムが使用中で読めない（排他で開いている・範囲ロック）。

    Windows ではどちらも PermissionError になるので、そのままだと「権限がない」と表示され、
    権限を直しに行かせてしまう（SMB 越しの実測で判明・2026-10-17）。
    OSError だけを受けている呼び出し元（使い回しの判定・隣の toc.dat の読み取り）でも落ちないよう、
    PermissionError の仲間にもしておく。
    """


# 他のプログラムが使用中のときの Windows のエラー（ERROR_SHARING_VIOLATION / ERROR_LOCK_VIOLATION）
WINERR_SHARING_VIOLATION = 32
WINERR_LOCK_VIOLATION = 33

IN_USE_OPEN_MSG = (
    "他のプログラムがこのファイルを使用中で、読むことを許していない（排他で開いている。Access・Outlook の PST・"
    "データベースのファイル等）。権限の問題ではない。使われていない時間に再検査する"
    "（NAS 上なら、使っている人はファイルサーバーの「開いているファイル」で確かめられる）"
)
IN_USE_READ_MSG = (
    "他のプログラムがこのファイルの一部をロックしていて読めない（範囲ロック。Access・データベース等が使用中）。"
    "権限の問題ではない。使われていない時間に再検査する"
    "（NAS 上なら、使っている人はファイルサーバーの「開いているファイル」で確かめられる）"
)


@dataclass
class SourceInfo:
    """元のファイルの識別情報。同じファイルかどうかの判定に使う。"""

    size: int
    mtime_ns: int  # 更新日時（UNIX 時刻の ns）
    # 変更日時（ChangeTime。中身・属性・代替データストリームが変わると進む。robocopy 等の普通の道具では戻らないが、
    # 専用の API を使えば戻せる＝わざと改ざんされると見抜けない。取れなければ 0）
    change_ns: int
    file_id: str  # ボリュームのシリアル番号＋ファイル番号（取れなければ空）
    attributes: int = 0
    sha256: str = ""
    atime_kept: bool = True  # 最終アクセス日時を保てたか
    # 保てなかった理由（"no_permission": 日時を書く権限が無い / "server_updated": 保つ指示を出したがサーバーが読み取りで更新した）
    atime_lost_reason: str = ""
    atime_ns: int = 0  # 読んだ時点の最終アクセス日時（同じファイルかの判定には使わない）

    def same_as(self, other: "SourceInfo") -> bool:
        return (
            self.size == other.size
            and self.mtime_ns == other.mtime_ns
            and self.change_ns == other.change_ns
            and self.file_id == other.file_id
        )


def free_bytes(folder: str) -> int:
    """フォルダのあるドライブの空き容量。分からなければ大きな値。"""
    try:
        return shutil.disk_usage(folder).free
    except OSError:
        return 1 << 62


def reserve_bytes(folder: str) -> int:
    """そのドライブで割り込んではいけない空き（1GB か容量の2%の大きい方。ただし 5GB まで）。"""
    try:
        total = shutil.disk_usage(folder).total
    except OSError:
        total = 0
    return max(MIN_FREE_BYTES, min(int(total * MIN_FREE_RATIO), MAX_RESERVE_BYTES))


def ensure_free(folder: str, need: int, what: str = "一時フォルダ") -> None:
    """need バイトを書いても最低限の空きが残るかを確かめ、残らなければ TempSpaceShort。"""
    free = free_bytes(folder)
    reserve = reserve_bytes(folder)
    if need + reserve > free:
        raise TempSpaceShort(
            f"{what}（{folder}）の空きが足りない（必要 {_fmt(need)}・空き {_fmt(free)}・"
            f"残しておく空き {_fmt(reserve)}）。空きの多いドライブを「展開に使う一時フォルダ」に指定して再検査する"
        )


def _fmt(n: int) -> str:
    for unit, size in (("TB", 1024**4), ("GB", 1024**3), ("MB", 1024**2)):
        if n >= size:
            return f"{n / size:.1f}{unit}"
    return f"{n}B"


def inside_any(path: str, roots: list[str]) -> str | None:
    """path が roots のどれかの中（同じ場所を含む）なら、その root を返す。"""
    p = os.path.normcase(os.path.abspath(path)).rstrip("\\/")
    for r in roots:
        rr = os.path.normcase(os.path.abspath(r)).rstrip("\\/")
        if p == rr or p.startswith(rr + os.sep) or p.startswith(rr + "/"):
            return r
    return None


def output_inside_roots(path: str | None, roots: list[str], what: str) -> str | None:
    """書き出し先が検査するフォルダの中なら、断る理由（日本語）を返す。中でなければ None。

    検査先に何かを書くと検査先を変えてしまい、次の検査ではそれ自体（ファイル名・検出の控え）も検査の対象になる。
    """
    if not path:
        return None
    root = inside_any(path, roots)
    if root is None:
        return None
    return (
        f"{what}（{path}）が検査するフォルダ（{root}）の中にあります。検査するフォルダには何も書かない決まりなので、"
        "別の場所を指定してください"
    )


# NAS・共有フォルダへの接続が切れたときの Windows のエラー。ファイルの問題ではないので、つながってから読み直せば済む。
# 53 は FileNotFoundError になり「削除された」と取り違えやすい（VM の SMB 共有の回線を切って実測・2026-10-17）
NETWORK_WINERRORS = {
    51,  # ERROR_REM_NOT_LIST（リモートのコンピューターが使えない）
    53,  # ERROR_BAD_NETPATH（ネットワーク パスが見つからない）
    54,  # ERROR_NETWORK_BUSY
    59,  # ERROR_UNEXP_NET_ERR（予期しないネットワーク エラー）
    64,  # ERROR_NETNAME_DELETED（指定されたネットワーク名は利用できない）
    67,  # ERROR_BAD_NET_NAME（ネットワーク名が見つからない）
    121,  # ERROR_SEM_TIMEOUT（セマフォがタイムアウト。SMB の応答待ちの打ち切り）
    1222,  # ERROR_NO_NETWORK
    1231,  # ERROR_NETWORK_UNREACHABLE
    1232,  # ERROR_HOST_UNREACHABLE
    1236,  # ERROR_CONNECTION_ABORTED
    2250,  # ERROR_NOT_CONNECTED（このネットワーク接続は存在しない）
}

NETWORK_LOST_MSG = (
    "NAS・共有フォルダへの接続が切れて読めなかった（ネットワーク）。ファイルの問題ではない。"
    "つながってから同じジョブを再開すると読み直す"
)


class NetworkLost(SourceError):
    """接続方式（FTP 等）でサーバーとの接続が切れた。ファイルの問題ではないので、つながってから読み直す。"""


def is_network_lost(e: BaseException) -> bool:
    """NAS・共有フォルダへの接続が切れたことによる例外か。"""
    seen = 0
    while e is not None and seen < 5:  # SourceError に包まれた元の例外も見る
        if isinstance(e, NetworkLost):
            return True
        if isinstance(e, OSError) and getattr(e, "winerror", None) in NETWORK_WINERRORS:
            return True
        e = e.__cause__ or e.__context__
        seen += 1
    return False


def is_disk_full(e: BaseException) -> bool:
    """空き容量不足の例外か（WinError 112 / ENOSPC / SQLite の満杯）。"""
    if isinstance(e, OSError) and (getattr(e, "winerror", None) in (39, 112) or e.errno == 28):
        return True
    return "disk is full" in str(e) or "database or disk is full" in str(e)


# ------------------------------------------------------------------ Windows の API

if os.name == "nt":
    import ctypes
    import msvcrt
    from ctypes import wintypes

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    GENERIC_READ = 0x80000000
    FILE_READ_ATTRIBUTES = 0x80
    FILE_WRITE_ATTRIBUTES = 0x100
    FILE_SHARE_ALL = 0x1 | 0x2 | 0x4  # 読み・書き・削除
    OPEN_EXISTING = 3
    FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    FILE_FLAG_OPEN_NO_RECALL = 0x00100000  # 階層化ストレージから呼び戻さない
    INVALID_HANDLE = wintypes.HANDLE(-1).value

    class FILETIME(ctypes.Structure):
        _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]

    class FILE_BASIC_INFO(ctypes.Structure):
        _fields_ = [
            ("CreationTime", ctypes.c_longlong),
            ("LastAccessTime", ctypes.c_longlong),
            ("LastWriteTime", ctypes.c_longlong),
            ("ChangeTime", ctypes.c_longlong),
            ("FileAttributes", wintypes.DWORD),
        ]

    class FILE_STANDARD_INFO(ctypes.Structure):
        _fields_ = [
            ("AllocationSize", ctypes.c_longlong),
            ("EndOfFile", ctypes.c_longlong),
            ("NumberOfLinks", wintypes.DWORD),
            ("DeletePending", wintypes.BOOLEAN),
            ("Directory", wintypes.BOOLEAN),
        ]

    class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", FILETIME),
            ("ftLastAccessTime", FILETIME),
            ("ftLastWriteTime", FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

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
    _k32.SetFileTime.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    _k32.GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    _k32.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_void_p]

    def _open_handle(path: str, access: int, flags: int) -> int:
        h = _k32.CreateFileW(path, access, FILE_SHARE_ALL, None, OPEN_EXISTING, flags, None)
        if h in (None, INVALID_HANDLE):
            err = ctypes.get_last_error()
            if err in (WINERR_SHARING_VIOLATION, WINERR_LOCK_VIOLATION):
                raise SourceInUse(IN_USE_OPEN_MSG)
            raise ctypes.WinError(err)
        return h

    def _handle_info(h: int) -> SourceInfo:
        basic = FILE_BASIC_INFO()
        std = FILE_STANDARD_INFO()
        if not _k32.GetFileInformationByHandleEx(h, 0, ctypes.byref(basic), ctypes.sizeof(basic)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not _k32.GetFileInformationByHandleEx(h, 1, ctypes.byref(std), ctypes.sizeof(std)):
            raise ctypes.WinError(ctypes.get_last_error())
        fid = ""
        bh = BY_HANDLE_FILE_INFORMATION()
        if _k32.GetFileInformationByHandle(h, ctypes.byref(bh)):
            fid = f"{bh.dwVolumeSerialNumber:08x}-{bh.nFileIndexHigh:08x}{bh.nFileIndexLow:08x}"
        return SourceInfo(
            size=int(std.EndOfFile),
            mtime_ns=_filetime_to_unix_ns(basic.LastWriteTime),
            change_ns=_filetime_to_unix_ns(basic.ChangeTime),
            file_id=fid,
            attributes=int(basic.FileAttributes),
            atime_ns=_filetime_to_unix_ns(basic.LastAccessTime),
        )

    def _keep_atime(h: int) -> bool:
        """この開き方での読み取りが最終アクセス日時を更新しないようにする。"""
        keep = FILETIME(0xFFFFFFFF, 0xFFFFFFFF)
        return bool(_k32.SetFileTime(h, None, ctypes.byref(keep), None))

    def _open_shared(path: str, want_atime: bool = True):
        """共有をすべて許して読み取り用に開く。(handle, 最終アクセス日時を保てたか) を返す。"""
        flags = FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OPEN_NO_RECALL
        if want_atime:
            try:
                h = _open_handle(path, GENERIC_READ | FILE_WRITE_ATTRIBUTES, flags)
                return h, _keep_atime(h)
            except PermissionError:
                pass  # 属性を書く権限が無い（読み取り専用の共有など）→ 読み取りだけで開く
        return _open_handle(path, GENERIC_READ, flags), False

    def stat_identity(path: str) -> SourceInfo:
        """中身を読まずに識別情報だけ取る（属性だけの開き方は最終アクセス日時を変えない）。"""
        from .engine import long_path

        h = _open_handle(long_path(path), FILE_READ_ATTRIBUTES, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_NO_RECALL)
        try:
            return _handle_info(h)
        finally:
            _k32.CloseHandle(h)

    _k32.ReadFile.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
    ]

    def _read_chunk(h: int, buf) -> int:
        """ReadFile で読み、読めたバイト数を返す（0 は終わり）。

        msvcrt 経由（os.fdopen）で読むと、失敗の元の番号（WinError）が消えて errno だけになる。範囲ロック（33）も
        ディスクの故障（23・30 等）も errno 13 になって見分けられず、読む途中の回線断（64 等）も回線断と分からなかった
        （実測・2026-10-17）。ReadFile なら元の番号で見分けられる。
        """
        got = wintypes.DWORD(0)
        if not _k32.ReadFile(h, buf, len(buf), ctypes.byref(got), None):
            err = ctypes.get_last_error()
            if err == 38:  # ERROR_HANDLE_EOF
                return 0
            raise read_error(err)
        return got.value

    def read_error(err: int) -> Exception:
        """ReadFile の失敗の番号を例外にする（使用中だけ SourceInUse、ほかは元の番号のまま）。"""
        if err in (WINERR_SHARING_VIOLATION, WINERR_LOCK_VIOLATION):
            return SourceInUse(IN_USE_READ_MSG)
        return ctypes.WinError(err)

    def file_id_128(path: str) -> str:
        """ボリューム＋128bit のファイル ID（FileIdInfo）。ReFS では 64bit のファイル番号が一意とは限らないため。

        取れなければ空（呼び出し側は 64bit の識別子に戻す）。属性だけの開き方なので最終アクセス日時は変えない。
        """
        from .engine import long_path

        try:
            h = _open_handle(
                long_path(path), FILE_READ_ATTRIBUTES, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_NO_RECALL
            )
        except (OSError, SourceError):
            return ""
        try:
            buf = ctypes.create_string_buffer(24)  # FILE_ID_INFO: VolumeSerialNumber(8) + FileId(16)
            if not _k32.GetFileInformationByHandleEx(h, 18, buf, 24):
                return ""
            raw = buf.raw
            if not any(raw[8:24]):
                return ""
            return f"{raw[:8].hex()}-{raw[8:24].hex()}"
        finally:
            _k32.CloseHandle(h)

    def _fd_from_handle(h: int):
        fd = msvcrt.open_osfhandle(h, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        return os.fdopen(fd, "rb", buffering=0)

else:  # Windows 以外（開発用）。共有モードと最終アクセス日時は扱えない

    def stat_identity(path: str) -> SourceInfo:
        st = os.stat(path)
        return SourceInfo(
            size=st.st_size,
            mtime_ns=st.st_mtime_ns,
            change_ns=st.st_ctime_ns,
            file_id=f"{st.st_dev:x}-{st.st_ino:x}",
        )


def _filetime_to_unix_ns(ft: int) -> int:
    if not ft:
        return 0
    return (int(ft) - 116444736000000000) * 100


def read_head_shared(path: str, n: int) -> bytes:
    """元のファイルの先頭 n バイトだけを、共有を許して読む（隣のファイルの小さな参照用）。"""
    from .engine import long_path

    if os.name != "nt":
        with open(path, "rb") as f:
            return f.read(n)
    h, _ = _open_shared(long_path(path))
    with _fd_from_handle(h) as f:
        return f.read(n)


def snapshot(path: str, dest: str, temp_folder: str, allow_recall: bool = False, retries: int = 2) -> SourceInfo:
    """元のファイル path を dest へ写す（共有をすべて許す・最終アクセス日時を保つ・読む間の書き換えを検知）。

    写しながら SHA-256 を取り、識別情報と一緒に返す。失敗は SourceError（理由は日本語）か OSError。
    """
    from .engine import long_path

    lp = long_path(path)
    if os.name != "nt":
        info = stat_identity(path)
        ensure_free(temp_folder, info.size)
        h = hashlib.sha256()
        with open(path, "rb") as src, open(dest, "wb") as out:
            for chunk in iter(lambda: src.read(CHUNK), b""):
                h.update(chunk)
                out.write(chunk)
        info.sha256 = h.hexdigest()
        info.atime_kept = False
        return info

    for attempt in range(retries + 1):
        handle, atime_kept = _open_shared(lp)
        try:
            before = _handle_info(handle)
            if before.attributes & RECALL_ATTRS and not allow_recall:
                raise CloudPlaceholder(
                    "クラウド・階層化ストレージの代替ファイル（中身が手元に無い）。読むとダウンロードが起き、"
                    "元のファイルの状態が変わるため読んでいない。中身を検査するには、そのファイルを手元に置いてから再検査する"
                )
            ensure_free(temp_folder, before.size)
            digest = hashlib.sha256()
            copied = 0
            buf = ctypes.create_string_buffer(CHUNK)
            with open(dest, "wb") as out:
                while True:
                    n = _read_chunk(handle, buf)
                    if not n:
                        break
                    chunk = buf.raw[:n]
                    digest.update(chunk)
                    out.write(chunk)
                    copied += n
            after = _handle_info(handle)
        finally:
            if handle is not None:
                _k32.CloseHandle(handle)
        if before.same_as(after) and copied == after.size:
            after.sha256 = digest.hexdigest()
            after.atime_kept = atime_kept
            if not atime_kept:
                after.atime_lost_reason = "no_permission"
            elif before.atime_ns and after.atime_ns != before.atime_ns:
                # 保つ指示（SetFileTime -1）は受け付けたが、サーバーが読み取りで日時を更新した（Samba は守らない・
                # VM の Samba で実測 2026-10-18）。「保てた」と記録すると事実と違うので、保てなかったと記録する
                after.atime_kept = False
                after.atime_lost_reason = "server_updated"
            return after
        if attempt == retries:
            break
    raise ChangedWhileReading(
        "読んでいる間に元のファイルが書き換えられた（何度読み直しても変わり続けた）。使われていない時間に再検査する"
    )

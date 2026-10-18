"""接続方式（Windows 共有・Samba の SMB、FTP・FTPS）で検査先へつなぐ部品。

フォルダの指定とは別に、接続方式（SMB・FTP・FTPS）とサーバー・ユーザー名を選んで検査先へつなぐ。

- SMB: Windows の接続（WNetAddConnection2。ドライブ文字は使わない）で資格情報つきにつなぎ、あとは `\\\\サーバー\\共有` の
  パスとして今までどおり検査する（共有をすべて許す開き方・最終アクセス日時を保つ・使用中や回線断の見分けがそのまま効く）。
- FTP / FTPS: 一覧を取り、1件ずつ手元の一時フォルダへ写してから検査する（サーバーへは何も書かない）。
  vsftpd は MLSD に対応せず、普通の LIST では「.」で始まる隠しファイルが黙って抜けた（実測・2026-10-18）。
  MLSD → LIST -a → LIST の順に試し、隠しファイルが見えているか確かめられないときは言い切らない。
- パスワードは保存しない（Connection は持たない。呼び出し側がメモリ上だけで渡す）。
"""

from __future__ import annotations

import ftplib
import hashlib
import os
import posixpath
import re
import socket
import ssl
import threading
from dataclasses import asdict, dataclass, fields
from datetime import datetime, timezone

from .safeio import ChangedWhileReading, NetworkLost, SourceError, SourceInfo, ensure_free

KINDS = [
    {
        "id": "smb",
        "label": "Windows 共有・Samba（SMB）",
        "default_port": None,
        "needs_share": True,
        "is_ftp": False,
        "tls": False,
    },
    {"id": "ftp", "label": "FTP（暗号化なし）", "default_port": 21, "needs_share": False, "is_ftp": True, "tls": False},
    {
        "id": "ftps",
        "label": "FTPS（明示的 TLS・AUTH TLS）",
        "default_port": 21,
        "needs_share": False,
        "is_ftp": True,
        "tls": True,
    },
    {
        "id": "ftps_implicit",
        "label": "FTPS（暗黙的 TLS）",
        "default_port": 990,
        "needs_share": False,
        "is_ftp": True,
        "tls": True,
    },
]
KIND_BY_ID = {k["id"]: k for k in KINDS}
ENCODINGS = [
    ["auto", "自動（UTF-8 に対応していれば UTF-8、無ければ Shift_JIS）"],
    ["utf-8", "UTF-8"],
    ["cp932", "Shift_JIS（日本語の古いサーバー）"],
]
FTP_SCHEMES = ("ftp://", "ftps://")
CHUNK = 1024 * 1024
FTP_MAX_DEPTH = 64  # FTP で辿るフォルダの深さの上限（ループよけ）


class ConnectError(Exception):
    """接続できなかった（理由と次にすることは日本語）。

    network が真なら、ネットワークが原因（名前が引けない・接続を断られた）。検査の途中なら回線断として扱い、
    つながってから読み直す（ログインの失敗などは偽）。
    auth が真なら、パスワード（資格情報）を断られた。覚えていたパスワードを捨てて聞き直すのはこのときだけ
    （回線断・一時的な失敗で捨てると、つながり直したあとにユーザーが入れ直すことになる）。
    """

    def __init__(self, message: str, network: bool = False, auth: bool = False):
        super().__init__(message)
        self.network = network
        self.auth = auth


@dataclass
class Connection:
    """接続先（パスワードは持たない）。"""

    kind: str
    host: str
    share: str = ""  # SMB の共有名
    path: str = ""  # 共有・FTP の中のフォルダ（/ でも \\ でも可）
    user: str = ""  # 空なら SMB は今の Windows のアカウント、FTP は匿名
    port: int | None = None
    encoding: str = "auto"  # FTP の文字コード
    verify_cert: bool = False  # FTPS でサーバーの証明書を確かめる
    timeout: int = 15  # 応答を待つ秒数（つながらないときに待たせすぎない）
    # FTP の起点のサーバー上の場所（接続を確かめたときに「ログインした場所＋path」から決める。ジョブと一緒に保存する）
    start_dir: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "Connection":
        names = {f.name for f in fields(cls)}
        c = cls(**{k: v for k, v in (d or {}).items() if k in names})
        c.kind = (c.kind or "").strip()
        c.host = (c.host or "").strip().strip("\\/")
        c.share = (c.share or "").strip().strip("\\/")
        c.path = (c.path or "").strip().replace("\\", "/").strip("/")
        c.user = (c.user or "").strip()
        c.encoding = c.encoding or "auto"
        if isinstance(c.verify_cert, str):  # "false" を真と読まない
            c.verify_cert = c.verify_cert.strip().lower() in ("1", "true", "yes", "on")
        c.verify_cert = bool(c.verify_cert)
        try:
            c.timeout = min(max(int(c.timeout), 3), 120)  # 応答を待つ秒数（大きすぎると要求が長く止まる）
        except (TypeError, ValueError):
            c.timeout = 15
        if c.port in ("", None):
            c.port = None
        else:
            try:
                c.port = int(c.port)
            except (TypeError, ValueError):
                raise ConnectError(f"ポート（{c.port}）は数字で入れてください") from None
        return c

    def validate(self) -> None:
        if self.kind not in KIND_BY_ID:
            raise ConnectError(f"接続方式（{self.kind}）が分かりません")
        if not self.host:
            raise ConnectError("サーバーの名前か IP アドレスを入れてください")
        if self.host.count(":") == 1:
            raise ConnectError(
                f"サーバー（{self.host}）にポートを付けないでください。ポートはポートの欄（CLI では --port）へ入れる"
            )
        if re.search(r"[\s/\\]", self.host):
            raise ConnectError(
                f"サーバー（{self.host}）に空白や区切り文字は入れられません。名前か IP アドレスだけを入れてください"
            )
        if self.kind == "smb":
            if not self.share:
                raise ConnectError("共有名を入れてください（例: \\\\nas01\\総務 なら「総務」）")
            if self.port not in (None, 445):
                raise ConnectError(
                    "Windows の SMB はポートを変えられません。ポートの欄（CLI では --port）は空にしてください"
                )
        if self.port is not None and not 1 <= self.port <= 65535:
            raise ConnectError(f"ポート（{self.port}）は 1〜65535 で入れてください")
        if self.encoding not in {e[0] for e in ENCODINGS}:
            raise ConnectError(f"文字コード（{self.encoding}）が分かりません")

    @property
    def is_ftp(self) -> bool:
        return self.kind != "smb"

    @property
    def ftp_port(self) -> int:
        return self.port or KIND_BY_ID[self.kind]["default_port"]

    def ftp_base(self) -> str:
        """FTP のファイルを表すパスの先頭（例 ftp://192.168.0.5:2121）。"""
        scheme = "ftps" if self.kind.startswith("ftps") else "ftp"
        default = KIND_BY_ID[self.kind]["default_port"]
        port = f":{self.ftp_port}" if self.ftp_port != default else ""
        return f"{scheme}://{self.host}{port}"

    def root(self) -> str:
        """検査の起点（SMB は UNC パス、FTP は ftp://サーバー/フォルダ）。"""
        if self.kind == "smb":
            p = f"\\\\{self.host}\\{self.share}"
            return p + ("\\" + self.path.replace("/", "\\") if self.path else "")
        if self.start_dir:
            return self.ftp_base() + self.start_dir.rstrip("/") + ("" if self.start_dir != "/" else "/")
        return self.ftp_base() + "/" + self.path

    def label(self) -> str:
        return f"{KIND_BY_ID[self.kind]['label']}（{self.root()}）"

    def short_name(self) -> str:
        """一覧・見出しに出す短い名前（例「FTP 192.168.0.5・総務/2024年度」「SMB nas01・総務」）。"""
        kind = {"smb": "SMB", "ftp": "FTP", "ftps": "FTPS", "ftps_implicit": "FTPS"}[self.kind]
        where = self.share + ("/" + self.path if self.path else "") if self.kind == "smb" else self.path
        return f"{kind} {self.host}・{where or '（全体）'}"

    def public(self) -> dict:
        """保存・画面に出してよい形（パスワードを持たない）。"""
        return asdict(self)


def is_ftp_path(path: str) -> bool:
    return isinstance(path, str) and path.lower().startswith(FTP_SCHEMES)


def ftp_server_path(url: str) -> str:
    """ftp://サーバー:ポート/a/b.txt → /a/b.txt（サーバーの中のパス）。"""
    rest = url.split("://", 1)[1]
    i = rest.find("/")
    return "/" if i < 0 else (rest[i:] or "/")


# ------------------------------------------------------------------ SMB（Windows の接続）

SMB_ERRORS = {
    5: "アクセスが拒否された（そのユーザーには共有を開く権限がない）",
    53: "サーバーが見つからない（名前・IP アドレス・ネットワークの接続を確かめる）",
    67: "サーバー名か共有名が見つからない（綴りと、サーバーにつながるかを確かめる）",
    86: "パスワードが違う",
    1219: (
        "同じサーバーに、別のユーザー名で既に接続している（エクスプローラー等）。Windows は1つのサーバーへ別々のユーザーで"
        "同時につなげない。同じユーザー名で入れるか、既存の接続を切ってからもう一度試す（net use で確かめられる）"
    ),
    1222: "ネットワークにつながっていない",
    1231: "サーバーへの経路が無い（ネットワークの接続を確かめる）",
    1326: "ユーザー名かパスワードが違う",
    1327: "このアカウントは今の時間・この PC からは使えない（アカウントの制限）",
    1330: "パスワードの期限が切れている",
    1331: "アカウントが無効になっている",
    1909: "アカウントがロックされている",
    2202: "ユーザー名の形が正しくない",
}
# パスワードを断られた（入れ直してもらう）エラー。アカウントのロック・無効は、パスワードを入れ直しても直らないので含めない
SMB_AUTH_ERRORS = {86, 1326, 1330}


def smb_connect(conn: Connection, password: str) -> bool:
    """SMB の共有へ資格情報つきでつなぐ。新しくつないだら True（終わったら smb_disconnect で切る）。"""
    conn.validate()
    if os.name != "nt":
        raise ConnectError("SMB の接続方式は Windows でだけ使えます")
    import ctypes
    from ctypes import wintypes

    class NETRESOURCEW(ctypes.Structure):
        _fields_ = [
            ("dwScope", wintypes.DWORD),
            ("dwType", wintypes.DWORD),
            ("dwDisplayType", wintypes.DWORD),
            ("dwUsage", wintypes.DWORD),
            ("lpLocalName", wintypes.LPWSTR),
            ("lpRemoteName", wintypes.LPWSTR),
            ("lpComment", wintypes.LPWSTR),
            ("lpProvider", wintypes.LPWSTR),
        ]

    mpr = ctypes.WinDLL("mpr", use_last_error=True)
    share = f"\\\\{conn.host}\\{conn.share}"
    existing = _smb_existing_user(share)
    if existing is not None:
        # 既に接続がある（エクスプローラー等）。つなぎ直すと終わったときに元の接続まで切ってしまうので、その接続を使う。
        # ただし別のユーザーの接続なら、入れたユーザーの権限で検査したことにならないので断る（不具合の修正。アクセスに
        # 基づく列挙の共有では、見えるフォルダがユーザーで違う）
        if conn.user and _bare_user(existing) != _bare_user(conn.user):
            raise ConnectError(
                f"{share} には既に別のユーザー（{existing}）で接続しているため、{conn.user} では接続できない"
                "（Windows は1つのサーバーへ別々のユーザーで同時につなげない）。既存の接続を切る（net use で確かめられる）か、"
                f"ユーザー名を {existing} にして試す"
            )
        if _isdir_after_reconnect(conn.root()):
            return False
        # 回線が戻った直後は、Windows がサーバーとのセッションをつなぎ直すまで見えないことがある（VM の Samba で、
        # 回線断の後の再開が「フォルダが見つからない」で止まった）。数回待っても見えなければ、張り直しを試す
    nr = NETRESOURCEW(dwType=1, lpRemoteName=share)  # RESOURCETYPE_DISK
    created = False
    # 資格情報を入れないときは、今の Windows のアカウントで（既につながっていればそのまま使う）
    err = mpr.WNetAddConnection2W(ctypes.byref(nr), password if conn.user else None, conn.user or None, 4)
    if err == 0:
        created = existing is None  # 既存の接続を張り直しただけなら、終わったときに切らない
    elif err in (85, 1219) and existing is not None and _isdir_after_reconnect(conn.root()):
        created = False  # 既存の接続（同じユーザー）がつながり直した
    elif err == 1219 and not conn.user and os.path.isdir(share):
        created = False  # ユーザーを指定せず、今のアカウントの接続で共有が開ける
    elif err in (85, 1219) and existing is not None:
        raise ConnectError(
            f"共有にはつながっているが、フォルダ（{conn.root()}）が見つからない。フォルダの欄を確かめる"
            "（回線が戻った直後なら、少し待ってからもう一度試す）"
        )
    else:
        raise ConnectError(
            f"{share} へ接続できない: {SMB_ERRORS.get(err, f'Windows のエラー {err}')}", auth=err in SMB_AUTH_ERRORS
        )
    root = conn.root()
    if not os.path.isdir(root):
        if created:
            smb_disconnect(conn)
        raise ConnectError(f"共有にはつながったが、フォルダ（{root}）が見つからない。フォルダの欄を確かめる")
    return created


def _isdir_after_reconnect(path: str, tries: int = 4, wait: float = 2.0) -> bool:
    """フォルダが見えるか。見えなければ少し待って確かめ直す（回線が戻った直後のセッションのつなぎ直しを待つ）。"""
    import time

    for i in range(tries):
        if os.path.isdir(path):
            return True
        if i < tries - 1:
            time.sleep(wait)
    return False


def _bare_user(user: str) -> str:
    """「DOMAIN\\taro」「taro@domain」「taro」を比べられる形にする。"""
    u = user.strip().lower()
    return u.rsplit("\\", 1)[-1].split("@", 1)[0]


def _smb_existing_user(share: str) -> str | None:
    """その共有への既存の接続のユーザー名（接続が無ければ None）。"""
    if os.name != "nt":
        return None
    import ctypes
    from ctypes import wintypes

    mpr = ctypes.WinDLL("mpr", use_last_error=True)
    buf = ctypes.create_unicode_buffer(512)
    n = wintypes.DWORD(len(buf))
    err = mpr.WNetGetUserW(share, buf, ctypes.byref(n))
    return buf.value if err == 0 else None


def smb_disconnect(conn: Connection) -> None:
    """smb_connect で作った接続を切る（失敗しても止めない）。"""
    if os.name != "nt":
        return
    import ctypes

    mpr = ctypes.WinDLL("mpr", use_last_error=True)
    mpr.WNetCancelConnection2W(f"\\\\{conn.host}\\{conn.share}", 0, False)


# ------------------------------------------------------------------ FTP / FTPS


LOGIN_LOST_MARK = "ログインできなくなった"  # 理由の文に入れる目印（実行器が1回目で検査を止めるのに使う）


class LoginLost(NetworkLost):
    """検査の途中でログインできなくなった（パスワードの変更・アカウントのロック等）。

    1件ずつ検査不能で確定させると、正しいパスワードで再開しても読み直されず、ログインの失敗を連発してロックアウトの規則にも
    掛かる（実測）。回線断と同じく、検査を止めて未検査のまま残す。
    """


class _ImplicitFTP_TLS(ftplib.FTP_TLS):
    """暗黙的 TLS（つないだ瞬間から暗号化。普通は 990 番）。"""

    def connect(self, host="", port=0, timeout=-999, source_address=None):
        if host:
            self.host = host
        if port > 0:
            self.port = port
        if timeout != -999:
            self.timeout = timeout
        self.sock = socket.create_connection((self.host, self.port), self.timeout)
        self.af = self.sock.family
        self.sock = self.context.wrap_socket(self.sock, server_hostname=self.host)
        self.file = self.sock.makefile("r", encoding=self.encoding)
        self.welcome = self.getresp()
        return self.welcome

    def ntransfercmd(self, cmd, rest=None):
        conn, size = ftplib.FTP.ntransfercmd(self, cmd, rest)
        if self._prot_p:
            conn = self.context.wrap_socket(conn, server_hostname=self.host, session=self.sock.session)
        return conn, size


class _ReusingFTP_TLS(ftplib.FTP_TLS):
    """データ接続で TLS のセッションを使い回す（vsftpd・FileZilla Server 等は使い回しを求める）。"""

    def ntransfercmd(self, cmd, rest=None):
        conn, size = ftplib.FTP.ntransfercmd(self, cmd, rest)
        if self._prot_p:
            conn = self.context.wrap_socket(conn, server_hostname=self.host, session=self.sock.session)
        return conn, size


def _enc_name(conn: Connection) -> str:
    return {"auto": "自動", "utf-8": "UTF-8", "cp932": "Shift_JIS"}.get(conn.encoding, conn.encoding)


def _ftp_error(e: BaseException, conn: Connection) -> Exception:
    """FTP の例外を、日本語の理由の例外にする（回線断は NetworkLost）。"""
    where = f"{conn.ftp_base()}"
    if isinstance(e, UnicodeError):
        # 元の文には、送れなかった文字と位置が載る（パスワードの一部が画面に出た・実測）ので載せない
        return ConnectError(
            f"{where}: ファイル名・ユーザー名・パスワードのどれかに、選んだ文字コード（{_enc_name(conn)}）で扱えない文字が"
            "ある。文字コードの設定（UTF-8 / Shift_JIS）を変えて試す"
        )
    if isinstance(e, socket.gaierror):
        return ConnectError(f"{where}: サーバーの名前が見つからない（名前・IP アドレスを確かめる）", network=True)
    if isinstance(e, ConnectionRefusedError):
        return ConnectError(
            f"{where}: 接続を断られた（ポート番号と、サーバーで FTP が動いているかを確かめる）", network=True
        )
    if isinstance(e, ssl.SSLCertVerificationError):
        return ConnectError(
            f"{where}: サーバーの証明書を確かめられなかった（{e.verify_message}）。自己署名の証明書なら「サーバーの証明書を"
            "確かめる」を外す"
        )
    if isinstance(e, (ssl.SSLEOFError, ssl.SSLZeroReturnError)):
        return NetworkLost(f"{where}: 暗号化（TLS）の接続が途中で切れた（{type(e).__name__}）")
    if isinstance(e, ssl.SSLError):
        return ConnectError(
            f"{where}: 暗号化（TLS）の接続に失敗した（{e}）。FTPS の方式（明示的・暗黙的）とポートを確かめる"
        )
    if isinstance(e, ftplib.error_perm):
        msg = str(e)
        if msg.startswith("530"):
            return ConnectError(f"{where}: ログインできない（ユーザー名かパスワードが違う）: {msg}", auth=True)
        if msg[:3] in ("500", "502", "504", "534") and conn.kind == "ftps":
            return ConnectError(f"{where}: サーバーが FTPS（AUTH TLS）に対応していない: {msg}")
        return ConnectError(f"{where}: サーバーが断った: {msg}")
    if isinstance(e, AttributeError) and "NoneType" in str(e):
        # 切れた接続に ftplib が触れた（ソケットが None）。回線断として、つながってから読み直す
        return NetworkLost(f"{where}: サーバーとの接続が切れた（{e}）")
    if isinstance(e, (TimeoutError, socket.timeout)):
        return NetworkLost(
            f"{where}: サーバーの応答が無い（{conn.timeout} 秒待った）。サーバー名・IP アドレス・ポート番号・ファイアウォールを"
            "確かめる（FTPS の方式（明示的・暗黙的）が違ってもこうなることがある）"
        )
    if isinstance(e, (ftplib.error_temp, EOFError, OSError)):
        return NetworkLost(f"{where}: サーバーとの接続が切れた（{type(e).__name__}: {e}）")
    return ConnectError(f"{where}: {type(e).__name__}: {e}")


def ftp_open(conn: Connection, password: str) -> ftplib.FTP:
    """FTP / FTPS でログインした接続を返す。失敗は ConnectError か NetworkLost（理由は日本語）。"""
    conn.validate()
    ctx = None
    if conn.kind.startswith("ftps"):
        ctx = ssl.create_default_context()
        if not conn.verify_cert:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
    ftp = None
    try:
        if conn.kind == "ftp":
            ftp = ftplib.FTP(timeout=conn.timeout)
        elif conn.kind == "ftps":
            ftp = _ReusingFTP_TLS(context=ctx, timeout=conn.timeout)
        else:
            ftp = _ImplicitFTP_TLS(context=ctx, timeout=conn.timeout)
        ftp.encoding = "utf-8" if conn.encoding in ("auto", "utf-8") else conn.encoding
        ftp.connect(conn.host, conn.ftp_port)
        if conn.kind == "ftps":
            ftp.auth()
        ftp.login(conn.user or "anonymous", password if conn.user else (password or "anonymous@"))
        if conn.kind.startswith("ftps"):
            ftp.prot_p()  # データも暗号化する
        try:
            feat = ftp.sendcmd("FEAT").upper()
        except ftplib.all_errors:
            feat = ""
        ftp._pii_mlsd = "MLST" in feat  # type: ignore[attr-defined]
        ftp._pii_mlsd_facts = True  # type: ignore[attr-defined]  OPTS MLST を断られたら facts を付けない
        if conn.encoding == "auto":
            if "UTF8" in feat:
                try:
                    ftp.sendcmd("OPTS UTF8 ON")
                except ftplib.all_errors:
                    pass
            else:
                ftp.encoding = "cp932"
        ftp.set_pasv(True)
        ftp.voidcmd("TYPE I")
        return ftp
    except Exception as e:  # noqa: BLE001  接続の失敗はすべて日本語の理由にする
        # ログインに失敗した接続も閉じる（パスワード違いのたびにソケットを1本ずつ残さない）
        if ftp is not None:
            try:
                ftp.close()
            except Exception:  # noqa: BLE001
                pass
        if isinstance(e, ConnectError):
            raise
        raise _ftp_error(e, conn) from e


def _start_dir(ftp: ftplib.FTP, conn: Connection) -> str:
    """起点のサーバー上の場所。フォルダの欄はログインした場所から見た場所（空ならログインした場所）。"""
    if conn.start_dir:
        return conn.start_dir
    home = ftp.pwd() or "/"
    return posixpath.normpath(posixpath.join(home, conn.path)) if conn.path else home


def ftp_check(conn: Connection, password: str) -> str:
    """接続を確かめる（ログイン・フォルダへ移れる・一覧が取れる）。結果の説明を返す。

    起点のサーバー上の場所を conn.start_dir に決める（以後の検査・再開はこの場所を使う）。
    """
    ftp = ftp_open(conn, password)
    try:
        conn.start_dir = ""
        path = _start_dir(ftp, conn)
        try:
            listing = _ftp_list(ftp, path)
        except ftplib.error_perm as e:
            raise ConnectError(f"{conn.ftp_base()}{path}: フォルダへ移れない（無い・権限が無い）: {e}") from e
        conn.start_dir = path
        n_files = sum(1 for x in listing.entries if x[1] == "file")
        n_dirs = sum(1 for x in listing.entries if x[1] == "dir")
        note = (
            "。ただしこのサーバーは隠しファイル（. で始まる名前）を一覧に出さない可能性がある"
            if not listing.hidden_ok
            else ""
        )
        enc = {"utf-8": "UTF-8", "cp932": "Shift_JIS"}.get(ftp.encoding, ftp.encoding)
        return f"接続できました。{conn.root()} にファイル {n_files} 件・フォルダ {n_dirs} 件が見えます（文字コード {enc}）{note}"
    except ConnectError:
        raise
    except Exception as e:  # noqa: BLE001
        raise _ftp_error(e, conn) from e
    finally:
        _quiet_quit(ftp)


def _quiet_quit(ftp: ftplib.FTP) -> None:
    try:
        ftp.quit()
    except Exception:  # noqa: BLE001
        try:
            ftp.close()
        except Exception:  # noqa: BLE001
            pass


RE_UNIX = re.compile(
    r"^(?P<type>[-dlbcps])[-rwxsStT+.@]{9,}\s+\d+\s+\S+\s+\S+\s+(?P<size>\d+)\s+"
    r"(?P<date>\w{3}\s+\d{1,2}\s+(?:\d{1,2}:\d{2}|\d{4}))\s(?P<name>.+)$"
)
RE_DOS = re.compile(r"^(?P<date>\d{2}-\d{2}-\d{2,4}\s+\d{1,2}:\d{2}[AP]M)\s+(?P<size><DIR>|\d+)\s+(?P<name>.+)$", re.I)


def _parse_list(lines: list[str]) -> tuple[list[tuple[str, str, int | None, str]], bool, bool]:
    """LIST の行を (名前, 種類 file/dir/link/other, 大きさ, リンク先) にする。

    戻り値の2つ目は「. と .. が含まれていた（-a が効いた）」、3つ目は「DOS 形式だった」。
    """
    out = []
    dots = False
    dos = False
    for ln in lines:
        m = RE_UNIX.match(ln)
        if m:
            name = m.group("name")
            t = m.group("type")
            target = ""
            if t == "l" and " -> " in name:
                name, target = name.split(" -> ", 1)
            if name in (".", ".."):
                dots = True
                continue
            kind = {"-": "file", "d": "dir", "l": "link"}.get(t, "other")
            out.append((name, kind, int(m.group("size")), target))
            continue
        m = RE_DOS.match(ln)
        if m:
            dos = True
            name = m.group("name")
            if name in (".", ".."):
                continue
            is_dir = m.group("size").upper() == "<DIR>"
            out.append((name, "dir" if is_dir else "file", None if is_dir else int(m.group("size")), ""))
            continue
        if ln.strip() and not ln.lower().startswith("total "):
            out.append((ln, "unknown", None, ""))
    return out, dots, dos


@dataclass
class Listing:
    """フォルダの一覧（_ftp_list の結果）。"""

    entries: list  # (名前, 種類, 大きさ, リンク先)
    hidden_ok: bool  # 隠しファイルも見えていると言えるか
    signature: str  # 一覧の中身の指紋（祖先と同じならループ）
    mtimes: dict  # 名前 → 更新日時（MLSD の modify。無ければ空）


def _ftp_list(ftp: ftplib.FTP, path: str) -> Listing:
    """フォルダの一覧。フォルダへ移ってから取る（読めないフォルダはここで 550 になる）。

    パスを付けた LIST は、vsftpd では読めないフォルダにそのフォルダ自身の1行を返し（中に同じ名前のフォルダがあるように
    見えた）、サーバーによってはパターンとして解釈する。移ってから取れば、読めないフォルダは「移れない」とはっきり失敗する。
    """
    ftp.cwd(path)
    if getattr(ftp, "_pii_mlsd", False):
        rows = None
        if getattr(ftp, "_pii_mlsd_facts", True):
            try:
                rows = list(ftp.mlsd("", facts=["type", "size", "modify", "unix.mode"]))
            except ftplib.error_perm as e:
                if not str(e).startswith(("500", "501", "502", "504")):
                    raise
                ftp._pii_mlsd_facts = False  # type: ignore[attr-defined]  OPTS MLST を断るサーバー
        if rows is None:
            rows = list(ftp.mlsd(""))
        out, mtimes = [], {}
        for name, facts in rows:
            t = (facts.get("type") or "").lower()
            if t in ("cdir", "pdir") or name in (".", ".."):
                continue
            kind = "dir" if t == "dir" else "file" if t == "file" else "link" if "symlink" in t else "other"
            out.append((name, kind, int(facts["size"]) if facts.get("size", "").isdigit() else None, ""))
            if facts.get("modify"):
                mtimes[name] = _parse_mdtm(facts["modify"])
        sig = "\n".join(sorted(f"{n}|{k}|{s}|{mtimes.get(n, '')}" for n, k, s, _ in out))
        return Listing(out, True, sig, mtimes)
    lines: list[str] = []
    try:
        _check_list_resp(ftp.retrlines("LIST -a", lines.append), path)
        entries, dots, dos = _parse_list(lines)
        if dots or dos:
            return Listing(entries, True, "\n".join(sorted(lines)), {})
        if entries or lines:
            # -a を受け付けたが . と .. を返さないサーバー（隠しファイルが出ているか分からない）
            return Listing(entries, False, "\n".join(sorted(lines)), {})
    except ftplib.error_perm:
        pass  # -a を名前として扱って断るサーバー
    lines = []
    _check_list_resp(ftp.retrlines("LIST", lines.append), path)
    entries, dots, dos = _parse_list(lines)
    return Listing(entries, dots or dos, "\n".join(sorted(lines)), {})


def _check_list_resp(resp: str, path: str) -> None:
    """一覧の応答が「開けなかった」なら権限の失敗にする（応答の番号が成功でも中身が空に見えるサーバーがある）。"""
    if "failed to open" in (resp or "").lower():
        raise ftplib.error_perm(f"550 {path}: フォルダを開けなかった（{resp.strip()}）")


def _list_shows_dots(ftp: ftplib.FTP, path: str) -> bool:
    """LIST -a が . と .. を返す（＝隠しファイルも確実に出す）サーバーか。"""
    lines: list[str] = []
    try:
        ftp.cwd(path)
        ftp.retrlines("LIST -a", lines.append)
    except ftplib.all_errors:
        return False
    return _parse_list(lines)[1]


LOOP_CONFIRM_DEPTH = 8  # ループと決める前に、同じ一覧が続くかを確かめる深さ
LOOP_REPEAT_LIMIT = 3  # 今の道の上に同じ一覧がこの回数続いたら、確かめなしでループとみなす


def _deeper_equal(ftp: ftplib.FTP, ancestor: str, folder: str, listing: "Listing") -> bool:
    """祖先と一覧が同じフォルダについて、深いところまで同じ一覧が続くか（続けばリンクのループ）。

    ループなら folder は ancestor と同じ場所なので、最初のフォルダを辿ってもずっと同じ一覧が続く。本物の入れ子
    （/x/x/x を同じ秒に作った等）は、どこかで一方が終わるか中身が違う（1段だけ比べると誤った・試験で実測）。
    """
    a, f = ancestor, folder
    cur = listing
    for _ in range(LOOP_CONFIRM_DEPTH):
        dirs = sorted(n for n, k, *_ in cur.entries if k == "dir")
        if not dirs:
            return False  # ループなら祖先（＝自分）を含むので、フォルダが1つも無いことはない
        step = None
        for d in dirs:
            # 両側とも読めないフォルダは飛ばし、読める最初のフォルダで比べる（ループの中に読めないフォルダが名前順で
            # 先頭に来ると、ループと確かめられずに辿り続けた・実測）
            ea = eb = None
            try:
                la = _ftp_list(ftp, posixpath.join(a, d))
            except ftplib.all_errors as e:
                ea = str(e)[:3] or "err"
            try:
                lf = _ftp_list(ftp, posixpath.join(f, d))
            except ftplib.all_errors as e:
                eb = str(e)[:3] or "err"
            if ea or eb:
                if ea and eb and ea == eb:
                    continue  # 両側とも同じように読めない
                return False  # 一方だけ読めない＝同じ場所ではない
            step = (d, la, lf)
            break
        if step is None:
            return True  # どのフォルダも両側で同じように読めない（同じ場所の可能性が高い）
        d, la, lf = step
        if la.signature != lf.signature:
            return False
        a, f, cur = posixpath.join(a, d), posixpath.join(f, d), lf
    return True


def _parse_mdtm(text: str) -> float:
    m = re.search(r"(\d{14})(\.\d+)?", text or "")
    if not m:
        return 0.0
    dt = datetime.strptime(m.group(1), "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    return dt.timestamp() + (float(m.group(2)) if m.group(2) else 0.0)


def _mdtm(ftp: ftplib.FTP, path: str) -> float:
    """更新日時（UTC の UNIX 秒）。取れなければ 0。"""
    try:
        resp = ftp.sendcmd(f"MDTM {path}")
    except ftplib.error_perm:
        return 0.0
    return _parse_mdtm(resp)


FTP_MAX_DIRS = 200_000  # 1つの検査で辿る FTP のフォルダの数の上限（ループよけの最後の砦）


def ftp_walk(conn: Connection, password: str):
    """FTP のフォルダを辿り、walker.Entry を返す（リンクは辿らない・読めないフォルダは記録する）。"""
    from .walker import Entry

    base = conn.ftp_base()
    try:
        ftp = ftp_open(conn, password)
    except (ConnectError, NetworkLost) as e:
        lost = isinstance(e, NetworkLost) or getattr(e, "network", False)
        yield Entry("error", conn.root(), reason=str(e), network_lost=lost)
        return
    try:
        root = _start_dir(ftp, conn)
    except Exception as e:  # noqa: BLE001  pwd が取れない（切れた等）
        err = _ftp_error(e, conn)
        yield Entry("error", conn.root(), reason=str(err), network_lost=isinstance(err, NetworkLost))
        _quiet_quit(ftp)
        return
    try:
        # MLSD が隠しファイルを返すとは限らない（RFC は義務にしていない）。LIST -a が . と .. を返す（＝隠しファイルも
        # 確実に出す）サーバーなら、最初から最後まで LIST を使う（起点だけで突き合わせると、起点に隠しファイルが無いとき
        # 素通りになった・不具合の修正）。決めたことは、接続を開き直しても引き継ぐ
        use_mlsd = getattr(ftp, "_pii_mlsd", False) and not _list_shows_dots(ftp, root)
        ftp._pii_mlsd = use_mlsd  # type: ignore[attr-defined]
        stack = [root]
        sigs: dict[str, str] = {}  # 辿ったフォルダ → 一覧の指紋（ハッシュ）
        n_dirs = 0
        while stack:
            folder = stack.pop()
            n_dirs += 1
            if n_dirs > FTP_MAX_DIRS:
                yield Entry(
                    "error",
                    base + folder,
                    reason=f"フォルダが {FTP_MAX_DIRS:,} 個を超えた（サーバー側のリンクのループの可能性）。ここで辿るのを止めた",
                )
                return
            try:
                listing = _ftp_list(ftp, folder)
            except ftplib.error_perm as e:
                yield Entry("error", base + folder, reason=f"フォルダを開けなかった（権限が無い・見つからない）: {e}")
                continue
            except Exception as e:  # noqa: BLE001
                err = _ftp_error(e, conn)
                yield Entry("error", base + folder, reason=str(err), network_lost=isinstance(err, NetworkLost))
                if isinstance(err, NetworkLost):
                    return
                # 回線以外の失敗（文字コード等）の後は、制御用の接続の応答がずれていることがあるので開き直す
                # （そのままだと、次のフォルダで前の転送の残りの応答を読んで「接続が切れた」と誤った・実測）
                _quiet_quit(ftp)
                try:
                    ftp = ftp_open(conn, password)
                    ftp._pii_mlsd = use_mlsd  # type: ignore[attr-defined]
                except (ConnectError, NetworkLost) as e2:
                    lost = isinstance(e2, NetworkLost) or getattr(e2, "network", False)
                    yield Entry("error", base + folder, reason=str(e2), network_lost=lost)
                    return
                continue
            sig = hashlib.sha1(listing.signature.encode("utf-8", "surrogatepass")).hexdigest()
            # 祖先と同じ一覧が出たら、サーバーがリンクを辿って見せているループの疑い（FTP にはフォルダの識別子が無い）。
            # 本物の入れ子（x/x/x を同じ秒に作った等）も一覧が同じになりうるので、1段深い一覧も同じときだけループとみなす
            # （祖先は今辿っている道だけを遡る。辿った全フォルダと比べると、フォルダ数の2乗の手間になった・不具合の修正）
            loop_of = None
            same = []  # 今の道で、同じ一覧の祖先
            a = folder
            while a not in ("/", ""):
                a = posixpath.dirname(a)
                if sigs.get(a) == sig and listing.entries:
                    same.append(a)
                if a == root:
                    break
            if len(same) >= LOOP_REPEAT_LIMIT:
                loop_of = same[
                    -1
                ]  # 同じ一覧が道の上に何度も続く: 確かめなしでループとみなす（確かめが効かないときの予備）
            else:
                loop_of = next((x for x in same if _deeper_equal(ftp, x, folder, listing)), None)
            if loop_of:
                yield Entry(
                    "link",
                    base + folder,
                    reason=f"既に辿ったフォルダ（{base + loop_of}）と同じ中身が続いている（サーバー側のリンク等でループして"
                    "いる可能性）。この先は辿っていない",
                )
                continue
            sigs[folder] = sig
            if not listing.hidden_ok:
                yield Entry(
                    "error",
                    base + folder,
                    reason="このサーバーは一覧に隠しファイル（. で始まる名前）を出さない可能性があり、見落としがないと"
                    "言い切れない。サーバーの設定（vsftpd なら force_dot_files=YES）を変えるか、SMB 等で検査する",
                )
            for name, kind, size, target in sorted(listing.entries, key=lambda x: x[0].lower()):
                path = posixpath.join(folder, name)
                url = base + path
                if kind == "dir":
                    if path.count("/") > FTP_MAX_DEPTH:
                        yield Entry(
                            "link",
                            url,
                            reason=f"フォルダが {FTP_MAX_DEPTH} 段より深い（サーバー側のリンクでループしている可能性）。"
                            "この先は辿っていない",
                        )
                        continue
                    stack.append(path)
                elif kind == "file":
                    mtime = listing.mtimes.get(name, 0.0)
                    try:
                        if not mtime:
                            mtime = _mdtm(ftp, path)
                        if size is None:
                            size = ftp.size(path)
                    except Exception as e:  # noqa: BLE001
                        err = _ftp_error(e, conn)
                        if isinstance(err, NetworkLost):
                            yield Entry("error", url, reason=str(err), network_lost=True)
                            return
                    yield Entry("file", url, size, mtime)
                elif kind == "link":
                    yield Entry(
                        "link",
                        url,
                        reason=f"リンク（サーバー上の {target or '?'} を指す）。指す先は辿っていない。必要ならその場所を別に検査する",
                    )
                else:
                    yield Entry("error", url, reason=f"一覧の行を読み取れなかった（種類が分からない）: {name[:200]}")
    finally:
        _quiet_quit(ftp)


# プロセスごとに FTP の接続を使い回す（1件ごとにログインし直さない）。1つの接続を複数のスレッドが同時に使うと応答が
# 入れ替わるので、呼び出し全体を鍵で守る（Web 版で2つのジョブが同じサーバーへ同時に問い合わせうる）
_pool_lock = threading.RLock()
_pool: dict[tuple, ftplib.FTP] = {}
# ログインに失敗した接続先（同じプロセスでは試し直さない。ロックアウトの規則に掛からないように・不具合の修正）
_login_failed: set[tuple] = set()


def reset_login_failures() -> None:
    """ログインに失敗した記憶を消す（検査を始め直すとき）。"""
    with _pool_lock:
        _login_failed.clear()


def close_pool(conn: Connection | None = None) -> int:
    """使い回しの接続を閉じる（検査が終わったとき）。conn を渡すと、その接続先の分だけ閉じる。閉じた数を返す。

    閉じずに残すと、検査が終わってもサーバーへのログインがプロセスの終わりまで残る（サーバーの同時接続数を食う）。
    使っている最中の接続は閉じない（呼び出し全体を同じ鍵で守っているので、使い終わるまで待つ）。
    QUIT は送らずにソケットを閉じる（応答の無いサーバーだと、鍵を持ったまま時間切れまで待つことになる）。
    """
    n = 0
    with _pool_lock:
        for key in list(_pool):
            if conn is None or key[:4] == (conn.kind, conn.host, conn.ftp_port, conn.user):
                try:
                    _pool.pop(key).close()
                except Exception:  # noqa: BLE001  閉じる失敗では止めない
                    pass
                n += 1
    return n


def _pool_key(conn: Connection, password: str) -> tuple:
    return (conn.kind, conn.host, conn.ftp_port, conn.user, conn.encoding, conn.verify_cert, hash(password))


def _pooled(conn: Connection, password: str, fresh: bool = False) -> ftplib.FTP:
    key = _pool_key(conn, password)
    with _pool_lock:
        if key in _login_failed:
            raise ConnectError(f"{conn.ftp_base()}: ログインできない（このパスワードでは前にも失敗した）", auth=True)
        ftp = _pool.get(key)
        if ftp is not None and fresh:
            _quiet_quit(ftp)
            ftp = None
            _pool.pop(key, None)
        if ftp is None:
            try:
                ftp = ftp_open(conn, password)
            except ConnectError as e:
                if "ログインできない" in str(e):
                    _login_failed.add(key)
                raise
            _pool[key] = ftp
        return ftp


def _stat(ftp: ftplib.FTP, path: str) -> tuple[int, float]:
    return ftp.size(path), _mdtm(ftp, path)


def _pooled_call(conn: Connection, password: str, fn):
    """使い回しの接続で fn(ftp) を呼ぶ。壊れていたら1回つなぎ直す。失敗は SourceError の仲間（理由は日本語）。"""
    for again in (False, True):
        try:
            with _pool_lock:
                return fn(_pooled(conn, password, fresh=again))
        except SourceError:
            raise
        except ftplib.error_perm as e:
            raise SourceError(f"FTP サーバーが読み取りを断った（権限が無い・ファイルが消えた）: {e}") from e
        except ConnectError as e:
            if e.network:  # つなぎ直せない（サーバーが落ちた等）: 回線断として、つながってから読み直す
                raise NetworkLost(str(e)) from e
            if "ログインできない" in str(e):
                raise LoginLost(
                    f"{e}。検査の途中で{LOGIN_LOST_MARK}（パスワードの変更・アカウントのロック等）。"
                    "正しいパスワードで再開すると続きから検査する"
                ) from e
            raise SourceError(str(e)) from e
        except Exception as e:  # noqa: BLE001
            err = _ftp_error(e, conn)
            if not again:
                continue  # 使い回した接続が壊れていた可能性 → つなぎ直して1回だけ試す
            if isinstance(err, NetworkLost):
                raise err from e
            if isinstance(err, ConnectError) and err.network:
                raise NetworkLost(str(err)) from e
            # 写しの外へ例外を抜けさせない（抜けると「検査に失敗した」で確定し、再開でも読み直されなかった）
            raise SourceError(f"FTP で読めなかった: {err}") from e
    raise AssertionError("unreachable")


def ftp_stat(url: str, conn: Connection, password: str) -> tuple[int, float]:
    """今の大きさと更新日時（前回の結果を使い回してよいかを、写す直前の値で判定するため）。"""
    path = ftp_server_path(url)
    return _pooled_call(conn, password, lambda ftp: _stat(ftp, path))


def ftp_snapshot(
    url: str, dest: str, temp_folder: str, conn: Connection, password: str, retries: int = 2
) -> SourceInfo:
    """FTP のファイルを dest へ写す（読むだけ）。読む間に変わったら読み直す。失敗は SourceError（理由は日本語）。"""
    path = ftp_server_path(url)

    def copy(ftp: ftplib.FTP):
        size, mtime = _stat(ftp, path)
        ensure_free(temp_folder, size)
        digest = hashlib.sha256()
        copied = 0
        with open(dest, "wb") as out:

            def got(chunk: bytes) -> None:
                nonlocal copied
                digest.update(chunk)
                out.write(chunk)
                copied += len(chunk)

            ftp.retrbinary(f"RETR {path}", got, blocksize=CHUNK)
        return (size, mtime), _stat(ftp, path), copied, digest.hexdigest()

    for attempt in range(retries + 1):
        before, after, copied, sha = _pooled_call(conn, password, copy)
        if before == after and copied == before[0]:
            return SourceInfo(
                size=before[0],
                mtime_ns=int(round(before[1] * 1e9)),
                change_ns=0,
                file_id="",
                sha256=sha,
                atime_kept=False,  # FTP にはサーバー側の最終アクセス日時を保つ手段が無い
            )
        if attempt == retries:
            break
    raise ChangedWhileReading(
        "読んでいる間に元のファイルが書き換えられた（何度読み直しても変わり続けた）。使われていない時間に再検査する"
    )

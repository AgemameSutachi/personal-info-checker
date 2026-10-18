"""検査対象フォルダの列挙。

- 権限の無いフォルダ・読めないフォルダは「フォルダのエラー」として必ず記録する（黙って飛ばさない）。
- シンボリックリンク・ジャンクションの先は辿らず、リンクとして記録する（ループと二重検査を防ぐ）。
  OneDrive 等のクラウドの代替ファイル（リンクではない再解析ポイント）は通常のファイルとして読む。
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Iterator

from .engine import long_path
from .safeio import is_network_lost

FILE_ATTRIBUTE_REPARSE_POINT = 0x400


@dataclass
class Entry:
    """列挙の結果1件。kind は file / link / error。"""

    kind: str
    path: str
    size: int | None = None
    mtime: float | None = None
    reason: str = ""
    network_lost: bool = False  # NAS への接続が切れて読めなかった（フォルダの問題ではない。実行器は列挙を止める）


def _is_link(path: str, st) -> str | None:
    """リンク（シンボリックリンク・ジャンクション）なら指す先を返す。"""
    attrs = getattr(st, "st_file_attributes", None)
    if attrs is not None:
        # Windows では列挙の属性だけで分かる（普通のファイルごとに NAS へ問い合わせ直さない）
        if not attrs & FILE_ATTRIBUTE_REPARSE_POINT:
            return None
    elif not os.path.islink(path):
        return None
    try:
        target = os.readlink(long_path(path))
    except (OSError, ValueError):
        return None  # クラウドの代替ファイル等、リンクではない再解析ポイント
    return describe_link_target(path, target)


def describe_link_target(path: str, target: str) -> str:
    """リンクの指す先を人が読める形にする。

    NAS（UNC パス）の上のリンクが指すドライブ文字のパスはサーバー側の場所で、手元の同じ名前のドライブではない
    （SMB 越しの実測で `\\\\?\\C:\\...` と出て、手元の C: と取り違えやすかった・2026-10-17）。
    """
    for prefix in ("\\\\?\\UNC\\", "\\??\\UNC\\"):
        if target.startswith(prefix):
            return "\\\\" + target[len(prefix) :]
    for prefix in ("\\\\?\\", "\\??\\"):
        if target.startswith(prefix):
            target = target[len(prefix) :]
    if target.lower().startswith("volume{"):
        return f"ボリューム {target}（ドライブ文字の無いボリューム）"
    if _on_remote(path) and len(target) >= 2 and target[1] == ":":
        return f"サーバー上の {target}"
    return target


def _on_remote(path: str) -> bool:
    """NAS（UNC パス、またはネットワークドライブに割り当てたドライブ文字）の上か。"""
    if path.startswith("\\\\"):
        return True
    if os.name != "nt" or len(path) < 2 or path[1] != ":":
        return False
    import ctypes

    return ctypes.windll.kernel32.GetDriveTypeW(path[:2] + "\\") == 4  # DRIVE_REMOTE


def _really_lost(e: BaseException, root: str) -> bool:
    """回線断の番号でも、検査の起点（共有）にまだ届くなら回線断ではない。

    「予期しないネットワーク エラー」（59）は本物の回線断でも出るが、Samba では上のフォルダの一覧を取った後に権限の無い
    フォルダを開くと、アクセス拒否（5）ではなくこれが返った（VM の Samba で実測・2026-10-18）。回線断と取り違えると
    検査を中断し、再開しても同じところで止まり続ける。
    """
    if not is_network_lost(e):
        return False
    if getattr(e, "winerror", None) != 59:
        return True  # 53・64・121 等は回線断と決まる番号
    try:
        return not os.path.isdir(long_path(root))
    except OSError:
        return True


def _dir_identity(folder: str) -> str:
    """フォルダの識別子（取れなければ空。そのときは二重の判定をしない）。属性だけの開き方なので日時は変えない。"""
    if os.name == "nt":
        from .safeio import file_id_128

        fid = file_id_128(folder)  # ReFS でも一意な 128bit のファイル ID（取れなければ下の 64bit）
        if fid:
            return fid
    try:
        from .safeio import stat_identity

        fid = stat_identity(folder).file_id
    except (OSError, ValueError):
        return ""
    # ファイル番号が 0 のもの（識別子を返さないファイルシステム）は、別のフォルダと取り違えるので使わない
    return fid if fid and not fid.endswith("-0000000000000000") else ""


def walk(roots: list[str], connection: dict | None = None, password: str = "") -> Iterator[Entry]:
    """フォルダ（またはファイル）の一覧を順に返す。FTP の根（ftp://…）は接続方式の設定で辿る。"""
    from . import remote

    for root in roots:
        if remote.is_ftp_path(root):
            if not connection:
                yield Entry("error", root, reason="FTP の接続先の設定が無い（接続方式で始めたジョブから再開する）")
                continue
            yield from remote.ftp_walk(remote.Connection.from_dict(connection), password)
            continue
        root = os.path.normpath(root)
        if os.path.isfile(long_path(root)):
            st = os.stat(long_path(root))
            yield Entry("file", root, st.st_size, st.st_mtime)
            continue
        if not os.path.isdir(long_path(root)):
            # 回線断で届かないのか、本当に無いのかを見分ける（回線断なら実行器が列挙を止め、再開で列挙し直す）
            lost = False
            try:
                os.stat(long_path(root))
            except OSError as e:
                lost = is_network_lost(e)
            yield Entry(
                "error",
                root,
                reason="フォルダが見つからない・接続できない（パスとネットワークの接続を確認）",
                network_lost=lost,
            )
            continue
        stack = [root]
        # 辿ったフォルダの識別子（ボリューム＋ファイル番号）。Samba は既定でシンボリックリンクを辿って普通のフォルダとして
        # 見せるので、自分の親を指すリンクがあると同じフォルダが無限に続いて見える（VM の Samba で実測: 同じファイルを
        # 41 回別物として数え、最後は失敗した・2026-10-18）。同じフォルダへ戻る道は辿らずにリンクとして記録する
        seen_dirs: dict[str, str] = {}
        while stack:
            folder = stack.pop()
            fid = _dir_identity(folder)
            if fid:
                if fid in seen_dirs:
                    yield Entry(
                        "link",
                        folder,
                        reason=f"既に辿ったフォルダ（{seen_dirs[fid]}）と同じ場所（サーバー側のリンク等でループ・"
                        "二重になっている）。二重に辿っていない",
                    )
                    continue
                seen_dirs[fid] = folder
            try:
                with os.scandir(long_path(folder)) as it:
                    entries = list(it)
            except PermissionError as e:
                yield Entry("error", folder, reason=f"フォルダを開く権限がない: {e.strerror or e}")
                continue
            except OSError as e:
                lost = _really_lost(e, root)
                note = ""
                if is_network_lost(e) and not lost:
                    note = "（共有には届いているので回線断ではない。Samba では権限の無いフォルダでこう返ることがある）"
                yield Entry(
                    "error",
                    folder,
                    reason=f"フォルダを読めなかった: {e.strerror or e}{note}",
                    network_lost=lost,
                )
                continue
            for de in sorted(entries, key=lambda d: d.name.lower()):
                path = os.path.join(folder, de.name)
                try:
                    st = de.stat(follow_symlinks=False)
                except OSError as e:
                    yield Entry(
                        "error",
                        path,
                        reason=f"属性を読めなかった: {e.strerror or e}",
                        network_lost=_really_lost(e, root),
                    )
                    continue
                target = _is_link(path, st)
                if target is not None:
                    yield Entry(
                        "link",
                        path,
                        reason=(
                            f"リンク（{target} を指す）。指す先は辿っていない。必要ならその場所を別に検査する"
                            + (
                                "（サーバー上の場所は手元から指定できないので、そこを公開している共有のパスで検査する）"
                                if target.startswith("サーバー上の")
                                else ""
                            )
                        ),
                    )
                    continue
                try:
                    is_dir = de.is_dir(follow_symlinks=False)
                except OSError:
                    is_dir = False
                if is_dir:
                    stack.append(path)
                else:
                    yield Entry("file", path, st.st_size, st.st_mtime)

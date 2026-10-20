"""検出した個人情報への対処（T2-a: 土台・ファイルの削除・csv/tsv/txt・xlsx/xlsm、T2-a2: 書庫の中のファイル、
T2-b: SQLite・SQL のダンプ。Access・Oracle のダンプはファイルの削除だけ、T2-c: PDF の黒塗り・docx・pptx）。

決まり:
- 対処は、人が画面で選んで実行したときだけ。検査（scan）は何も書き込まない。自動では何もしない。
- 対象は「実行の時点でファイルを読み直して集めた、全部の検出の位置」（明細の上限 20 件ではない）。
  位置の集め直しと書き換えは別プロセス（検査と同じ pebble・メモリ上限・時間制限）で行う。生の値は位置に入れない。
- 退避の写しは作らない（個人情報のファイルを手元のディスクへ写さないため）。元のファイルはごみ箱へ送る。
- 書き換えの流れ（途中で落ちても、元か新のどちらかが必ず元の名前か「対処前」の名前で残る）:
  (1) 元と同じフォルダの一時の名前（~piichk-new-…）へ新しい中身を書く（flush・fsync）→ (2) 新しいファイルを検査し直して開けると
  確かめる（ここまで元に触らない）→ (3) 記録（remediations）に「始めた」と段取り（一時の新ファイル・改名後の元の名前）を書く →
  (4) ごみ箱のある場所: 元を「元の名前（対処前 日時）」に改名 → 新を元の名前へ改名 → 改名した元をごみ箱へ。各段のあとで記録の状態を進める／
  (5) ごみ箱の無い場所: os.replace で入れ替える（元は残らない。下見に出す）。
  (1)(2) は別プロセス（apply_task）、(3)〜(5) は親のプロセス（commit_rewrite）。
- 途中で止まった記録は、起動時と、同じファイルに対処を始める前に立て直す（recover_record）。「元に戻す」（退避の写しから戻す）は無い。
  ごみ箱へ送った場合は、ごみ箱から「元の名前（対処前 …）」を戻してもらう。ごみ箱の無い場所は戻せない。
- 「ファイルを削除」も退避しない。ごみ箱のある場所はごみ箱へ送り（SHFileOperationW）、無い場所（ネットワーク・外付け）はそのまま消す。
  どちらにしたかを結果・記録に残す。書庫ごとの削除・zip に作り直すときの元の書庫の削除も同じ扱い。
- 書庫の中のファイル（T2-a2）: item_path（検査のパス「外!内」）を対象に、取り出して同じ書き換えを当て、書庫全体を作り直す
  （archive_write.py）。rar など書けない形式は zip に作り直す（元の書庫は削除）。
"""

from __future__ import annotations

import ctypes
import json
import multiprocessing
import os
import secrets
import threading
import time
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import replace

from .archive_write import zip_target_for
from .models import PasswordBook, ScanOptions, Status
from .procguard import plan_workers, worker_init
from .remedy_write import (
    DUMMY_MODES,
    XLSX_WARNINGS,
    DummyMaker,
    RemedyError,
    Selection,
    rewrite_text_file,
    rewrite_xlsx_file,
    select_positions,
    sha256_file,
)
from .reveal import BYTES_PER_SEC, MAX_TIMEOUT, MIN_TIMEOUT

METHOD_LABELS = {
    "delete_file": "ファイルを削除（ごみ箱へ送る。ごみ箱が無い場所では完全に削除）",
    "delete_rows": "該当する行を削除",
    "delete_columns": "該当する列を削除",
    "dummy": "ダミー化（該当する値だけを置き換える）",
    "delete_sheet": "該当するシートを削除",
    "delete_table": "該当する表を削除（その表のデータはすべて消える）",
    # 書庫の中のファイルに対する方法（T2-a2）
    "remove_entry": "書庫から取り除く（中のファイルを削除）",
    "convert_zip": "zip に作り直す（形式が変わる）",
    # PDF・docx・pptx（T2-c）
    "redact": "黒塗り（文字ごと消す。元に戻せない）",
    "delete_pages": "該当するページを削除",
    "delete_paragraphs": "該当する段落を削除",
    "delete_slides": "該当するスライドを削除（ノートも）",
}
# 形式によって呼び方を変える方法（docx の行・列は表の行・列）
LAYOUT_LABELS = {
    ("docx", "delete_rows"): "表の該当する行を削除",
    ("docx", "delete_columns"): "表の該当する列を削除",
}
# 書庫の中のファイルにだけ使える方法
ARCHIVE_ONLY_METHODS = ("remove_entry", "convert_zip")
ARCHIVE_DELETE_LABEL = "書庫ごとファイルを削除（ごみ箱へ送る。ごみ箱が無い場所では完全に削除）"
CONF_RANKS = {"high": 3, "medium": 2, "low": 1}
RANK_LABELS = {3: "高", 2: "中", 1: "低"}
ANALYSIS_KEEP_SECONDS = 600  # 分析（位置の集まり）をメモリに持つ時間
MAX_ANALYSES = 4
MAX_RUNS_KEPT = 20
SAMPLE_ROWS = 20  # 下見に出す、変わる行の番号の数
FILE_ATTRIBUTE_READONLY = 0x1
# 形式（検査のときに決まる位置の意味）ごとに、できる方法
LAYOUT_METHODS = {
    "csv": ("delete_rows", "delete_columns", "dummy"),
    "lines": ("delete_rows", "dummy"),
    "xlsx": ("delete_rows", "delete_columns", "dummy", "delete_sheet"),
    "sqlite": ("delete_rows", "delete_columns", "dummy", "delete_table"),
    "sqldump": ("delete_rows", "delete_columns", "dummy", "delete_table"),
    "pdf": ("redact", "delete_pages"),
    "docx": ("dummy", "delete_paragraphs", "delete_rows", "delete_columns"),
    "pptx": ("dummy", "delete_slides"),
}
DB_LAYOUTS = ("sqlite", "sqldump")  # 位置の「シート」が表の名前になる形式
OFFICE_LAYOUTS = ("pdf", "docx", "pptx")  # 位置の「シート」がページ・部品・スライドになる形式（T2-c）
# ある形式にだけ出す方法
LAYOUT_ONLY_METHODS = {
    "delete_table": DB_LAYOUTS,
    "redact": ("pdf",),
    "delete_pages": ("pdf",),
    "delete_paragraphs": ("docx",),
    "delete_slides": ("pptx",),
}
XLSX_EXTS = (".xlsx", ".xlsm")
NEW_PREFIX = "~piichk-new-"  # 書き換えた新しいファイルを、元と同じフォルダへ一時に置くときの名前の頭
STATES_UNFINISHED = ("started", "renamed", "swapped")  # 途中で止まった記録の状態（立て直しの対象）


# ---------------------------------------------------------------- ごみ箱


def send_to_recycle_bin(path: str) -> None:
    """ファイルをごみ箱へ送る（SHFileOperationW。確認の窓・エラーの窓は出さない）。失敗は RemedyError。"""
    if os.name != "nt":
        raise RemedyError("ごみ箱へ送る機能は Windows だけで使えます")
    from ctypes import wintypes

    abs_path = os.path.abspath(path)
    if len(abs_path) >= 260:
        raise RemedyError("パスが長すぎて、ごみ箱へ送れません（ファイルは消していません）")

    class SHFILEOPSTRUCTW(ctypes.Structure):
        _pack_ = 1 if ctypes.sizeof(ctypes.c_void_p) == 4 else 8
        _fields_ = [
            ("hwnd", wintypes.HWND),
            ("wFunc", wintypes.UINT),
            ("pFrom", wintypes.LPCWSTR),
            ("pTo", wintypes.LPCWSTR),
            ("fFlags", ctypes.c_ushort),
            ("fAnyOperationsAborted", wintypes.BOOL),
            ("hNameMappings", ctypes.c_void_p),
            ("lpszProgressTitle", wintypes.LPCWSTR),
        ]

    FO_DELETE = 3
    FOF_SILENT, FOF_NOCONFIRMATION, FOF_ALLOWUNDO, FOF_NOERRORUI = 0x4, 0x10, 0x40, 0x400
    # ごみ箱の容量より大きくて完全に削除になるときだけ、Windows の確かめの窓を出す（黙って完全に消さない。取りやめれば中止）
    FOF_WANTNUKEWARNING = 0x4000
    op = SHFILEOPSTRUCTW()
    op.hwnd = None
    op.wFunc = FO_DELETE
    op.pFrom = abs_path + "\0"  # 二重の NUL で終える（ctypes が文字列の終わりにもう1つ付ける）
    op.pTo = None
    op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI | FOF_WANTNUKEWARNING
    ret = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op))
    if ret != 0 or op.fAnyOperationsAborted:
        raise RemedyError(
            f"ごみ箱へ送れませんでした（コード {ret}。ファイルが使用中・権限が無い可能性）。ファイルは消していません"
        )


def has_recycle_bin(path: str) -> bool:
    """そのファイルのある場所にごみ箱があるか（ネットワーク・外付けの場所は、ごみ箱を経由せず消える）。"""
    p = os.path.abspath(path)
    if p.startswith("\\\\"):
        return False
    if os.name != "nt":
        return True
    try:
        root = os.path.splitdrive(p)[0] + "\\"
        return ctypes.windll.kernel32.GetDriveTypeW(root) == 3  # DRIVE_FIXED
    except Exception:  # noqa: BLE001
        return True


def disposal_text(noun: str, name: str, recycle: bool) -> tuple[str, str]:
    """ファイル・書庫を消すときの、下見の1行目と警告（ごみ箱の有無で2通り）。警告が要らなければ空。"""
    if recycle:
        return f"{noun}「{name}」をごみ箱へ送ります（ごみ箱から戻せます）", ""
    msg = f"{noun}「{name}」を完全に削除します（この場所にはごみ箱がありません。元に戻せません）"
    return msg, msg + "。退避の写しも作りません"


def delete_original(path: str) -> str:
    """元のファイルを消す（退避はしない）。ごみ箱のある場所ならごみ箱へ送り、無い場所（ネットワーク・外付けなど）は、
    ごみ箱を経由せずにそのまま消す。どちらにしたかを "recycle_bin" / "permanent" で返す。失敗しても元のファイルは消えていない。"""
    if has_recycle_bin(path):
        send_to_recycle_bin(path)
        if os.path.exists(_long(path)):
            raise RemedyError("ごみ箱へ送ったはずのファイルが残っています。元のファイルは変えていません")
        return "recycle_bin"
    try:
        os.remove(_long(path))
    except OSError as e:
        raise RemedyError(f"ファイルを削除できませんでした（{e}）。元のファイルは変えていません") from None
    return "permanent"


# ---------------------------------------------------------------- 書き換えの確定（途中で落ちても、元か新のどちらかが必ず残る手順）


def _long(path: str) -> str:
    from .engine import long_path

    return long_path(path)


def _discard(path: str) -> None:
    """自分が作った一時のファイルを消す（無ければ何もしない）。"""
    try:
        os.remove(_long(path))
    except OSError:
        pass


def _exists(path: str | None) -> bool:
    return bool(path) and os.path.exists(_long(path))


def new_tmp_path(path: str) -> str:
    """書き換えた新しいファイルを一時に置く名前（元と同じフォルダの「~piichk-new-<英字8字>-元の名前」）。"""
    folder, name = os.path.split(path)
    while True:
        tag = "".join(secrets.choice("abcdefghijklmnop") for _ in range(8))
        cand = os.path.join(folder, f"{NEW_PREFIX}{tag}-{name}")
        if not os.path.exists(_long(cand)):
            return cand


def pre_rename_path(path: str) -> str:
    """ごみ箱へ送る前に、元のファイルを同じフォルダの中で改名する名前（元の名前（対処前 YYYYMMDD-HHMMSS）.拡張子）。"""
    folder, name = os.path.split(path)
    stem, ext = os.path.splitext(name)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    cand, n = os.path.join(folder, f"{stem}（対処前 {stamp}）{ext}"), 1
    while os.path.exists(_long(cand)):
        n += 1
        cand = os.path.join(folder, f"{stem}（対処前 {stamp}-{n}）{ext}")
    return cand


def fsync_path(path: str) -> None:
    """書き終えたファイルをディスクへ確実に書き出す（途中で電源が落ちても、新しいファイルが中途半端にならないように）。"""
    with open(_long(path), "r+b") as f:
        f.flush()
        os.fsync(f.fileno())


def _fs_rename(src: str, dst: str) -> None:
    """名前を変える（dst が既にあれば失敗する。上書きしない）。試験は、落ちた状態を作るためにこれを差し替える。"""
    os.rename(_long(src), _long(dst))


def rename_with_retry(src: str, dst: str, tries: int = 5) -> None:
    """名前を変える。他のプログラムが開いていて変えられないときは、少し待って数回試す。"""
    last: OSError | None = None
    for i in range(tries):
        try:
            _fs_rename(src, dst)
            return
        except PermissionError as e:
            last = e
            time.sleep(0.5 * (i + 1))
    raise RemedyError(
        f"ファイルの名前を変えられませんでした（他のプログラムが開いている・権限が無い可能性: {last}）。元のファイルは変えていません"
    )


def replace_with_retry(src: str, dst: str, tries: int = 5) -> None:
    """os.replace（中身の入れ替えが1回で起きる。元か新のどちらかが必ず残る）。開いていて置き換えられないときは、少し待って数回試す。"""
    last: OSError | None = None
    for i in range(tries):
        try:
            os.replace(_long(src), _long(dst))
            return
        except PermissionError as e:
            last = e
            time.sleep(0.5 * (i + 1))
    raise RemedyError(
        f"ファイルを置き換えられませんでした（他のプログラムが開いている・権限が無い可能性: {last}）。元のファイルは変えていません"
    )


def _as_remedy(e: Exception) -> RemedyError:
    return e if isinstance(e, RemedyError) else RemedyError(f"{type(e).__name__}: {e}")


def make_commit_plan(path: str, convert: bool) -> dict:
    """書き換えの確定の段取り（方法・一時の新ファイル・確定後の名前・改名後の元の名前）を決める。

    方法: recycle = ごみ箱のある場所（元を「対処前」の名前に改名 → 新を元の名前へ → 改名した元をごみ箱へ）／
    replace = ごみ箱の無い場所（os.replace で入れ替える。元は残らない）／convert = 別の名前の zip に作り直す（元の書庫は消す）。
    """
    if convert:
        from .archive_write import zip_target_for

        dest = zip_target_for(path)
        return {"mode": "convert", "tmp_new": new_tmp_path(dest), "dest": dest, "pre_path": None}
    if has_recycle_bin(path):
        return {"mode": "recycle", "tmp_new": new_tmp_path(path), "dest": path, "pre_path": pre_rename_path(path)}
    return {"mode": "replace", "tmp_new": new_tmp_path(path), "dest": path, "pre_path": None}


def commit_rewrite(store, rid: int, path: str, plan: dict, orig_sha256: str) -> dict:
    """出来上がって検査も済んだ一時の新ファイルを、元の名前へ確定する（親のプロセスで動く）。

    各段のあとで記録（remediations）の状態を進める。途中で落ちても、元の中身か新しい中身のどちらかが、必ず元の名前
    （か「対処前」の名前）で残る（立て直しは recover_record）。普通の失敗（Exception）は、その場で元の状態へ戻す。
    プロセスの強制終了のように Exception でないものは、わざと捕まえない（落ちた状態を、立て直しが読めるようにそのまま残す）。
    戻り値: {"disposal": "recycle_bin" | "replaced" | 元の書庫の扱い, "pre_name": 改名した元の名前（ごみ箱から戻すときの名前）}
    """
    mode, tmp_new, dest, pre = plan["mode"], plan["tmp_new"], plan["dest"], plan.get("pre_path")

    def state(s: str) -> None:
        store.update_remediation(rid, state=s)

    def cancel() -> None:  # 元に触る前の失敗: 一時の新ファイルを消して、記録も残さない
        _discard(tmp_new)
        store.delete_remediation(rid)

    def stuck(msg: str) -> RemedyError:  # 戻し切れなかった: 記録を残す（次の起動・次の対処の前に立て直す）
        return RemedyError(f"{msg}。途中の状態を記録に残しました（次に開くときに立て直します）")

    if sha256_file(path) != orig_sha256:
        cancel()
        raise RemedyError("対処している間に元のファイルが変わりました。何も変えていません")

    if mode == "replace":
        try:
            replace_with_retry(tmp_new, path)
        except Exception as e:
            cancel()
            raise _as_remedy(e) from None
        state("applied")
        return {"disposal": "replaced", "pre_name": None}

    if mode == "convert":
        try:
            _fs_rename(tmp_new, dest)
        except Exception as e:
            cancel()
            raise _as_remedy(e) from None
        state("swapped")
        try:
            disposal = delete_original(path)
        except Exception as e:
            try:
                _discard(dest)  # 元を消せなかったので、作った zip は片付けて、元を残す
                store.delete_remediation(rid)
            except Exception:  # noqa: BLE001
                raise stuck("元の書庫を消せず、作った zip も片付けられませんでした") from None
            raise _as_remedy(e) from None
        state("applied")
        return {"disposal": disposal, "pre_name": None}

    # recycle: 元を同じフォルダで改名 → 新を元の名前へ → 改名した元をごみ箱へ
    try:
        rename_with_retry(path, pre)
    except Exception as e:
        cancel()
        raise _as_remedy(e) from None
    state("renamed")
    try:
        _fs_rename(tmp_new, path)
    except Exception as e:
        try:
            _fs_rename(pre, path)
            cancel()
        except Exception:  # noqa: BLE001
            raise stuck("新しいファイルを置けず、元の名前にも戻せませんでした") from None
        raise _as_remedy(e) from None
    state("swapped")
    try:
        send_to_recycle_bin(pre)
        if _exists(pre):
            raise RemedyError("ごみ箱へ送ったはずのファイルが残っています")
    except Exception as e:
        try:
            _fs_rename(path, tmp_new)
            _fs_rename(pre, path)
            cancel()
        except Exception:  # noqa: BLE001
            raise stuck("元のファイルをごみ箱へ送れず、元の状態にも戻せませんでした") from None
        raise RemedyError(f"元のファイルをごみ箱へ送れなかったため、元の状態に戻しました（{_as_remedy(e)}）") from None
    state("applied")
    return {"disposal": "recycle_bin", "pre_name": os.path.basename(pre)}


def recover_record(rec: dict) -> tuple[str, str]:
    """途中で止まった対処の記録（始めた・元を改名した・新を置いた）を、ファイルの今の状態から立て直す。

    どの状態からでも、元の中身か新しい中身のどちらかが、元の名前（か「対処前」の名前）で必ず残るようにする。
    戻り値: （記録の新しい状態 "applied"=最後まで済んでいた／"recovered"=元の状態に戻した・そのまま, 利用者向けの説明）。
    """
    plan = rec.get("plan") or {}
    path = rec["top_path"]
    mode, tmp_new, dest, pre = plan.get("mode"), plan.get("tmp_new"), plan.get("dest") or path, plan.get("pre_path")
    new_sha = rec.get("new_sha256")

    def is_new(p: str) -> bool:
        try:
            return bool(new_sha) and sha256_file(p) == new_sha
        except OSError:
            return False

    if mode == "replace":
        # os.replace は1回で起きる。元の名前には元か新のどちらかがある（無ければ、残っている新を元の名前へ置く）
        if _exists(tmp_new):
            if _exists(path):
                _discard(tmp_new)
            else:
                _fs_rename(tmp_new, path)
                return (
                    "recovered",
                    "元の名前のファイルが無かったため、書き換え済みの新しいファイルを元の名前に置きました",
                )
        if _exists(path) and is_new(path):
            return "applied", "新しい中身への入れ替えは済んでいました"
        return "recovered", "入れ替えの前に止まっていました（元のファイルのまま。一時の新ファイルは消しました）"
    if mode == "convert":
        if _exists(tmp_new):
            _discard(tmp_new)
        if _exists(dest) and _exists(path):
            return (
                "recovered",
                "zip は作り終えていますが、元の書庫を消せていません（元の書庫と zip の両方が残っています）",
            )
        if _exists(dest):
            return "applied", "zip への作り直しと元の書庫の削除は済んでいました"
        return "recovered", "zip を作る前に止まっていました（元の書庫のまま）"
    # recycle
    if not _exists(path) and _exists(pre):
        _fs_rename(pre, path)
        if _exists(tmp_new):
            _discard(tmp_new)
        return "recovered", f"元の名前のファイルが無かったため、「{os.path.basename(pre)}」を元の名前に戻しました"
    if not _exists(path) and _exists(tmp_new):
        _fs_rename(tmp_new, path)
        return (
            "recovered",
            "元の名前のファイルが無く、対処前の名前のファイルも見つからなかったため、新しいファイルを元の名前に置きました",
        )
    if _exists(path) and _exists(pre):
        if is_new(path):
            _discard(tmp_new)
            try:
                send_to_recycle_bin(pre)
                if not _exists(pre):
                    return "applied", f"元のファイル（「{os.path.basename(pre)}」）をごみ箱へ送り直しました"
            except Exception:  # noqa: BLE001
                pass
            return (
                "recovered",
                f"新しいファイルは置けていますが、「{os.path.basename(pre)}」をごみ箱へ送れていません（不要なら削除してください）",
            )
        if _exists(tmp_new):
            _discard(tmp_new)
        return (
            "recovered",
            f"元の名前のファイルと「{os.path.basename(pre)}」の両方が残っています（どちらも消していません）",
        )
    if _exists(path):
        # 改名の前に止まっていた、またはごみ箱へ送り終えていた
        if _exists(tmp_new):
            _discard(tmp_new)
            return (
                "recovered",
                "元のファイルを変える前に止まっていました（元のファイルのまま。一時の新ファイルは消しました）",
            )
        if is_new(path):
            return "applied", "新しい中身への入れ替えと、元のファイルをごみ箱へ送るところまで済んでいました"
        return "recovered", "元のファイルを変える前に止まっていました（元のファイルのまま）"
    return "recovered", "元のファイルが見つかりません（移動・削除された可能性）。何も変えていません"


# ---------------------------------------------------------------- 別プロセスで動く部分


def _top_item(result, path: str):
    for it in result.items:
        if it.depth == 0 and it.path == path:
            return it
    return None


def _count_conf(items) -> dict:
    """項目群の「種類:確度」→件数の合計。"""
    total: dict[str, int] = {}
    for it in items:
        for k, n in it.conf_counts.items():
            total[k] = total.get(k, 0) + n
    return total


def _archive_env(options: ScanOptions, book: PasswordBook, top_path: str, workdir: str):
    """書庫を扱う環境（7-Zip の場所・検査のときにメモリにあるパスワード・作業フォルダ）。"""
    from .archive_write import ArchiveEnv
    from .formats.archive import find_7z

    return ArchiveEnv(find_7z(options.sevenzip), book.candidates_for(top_path), workdir)


def collect_inner_task(args: dict) -> dict:
    """書庫の中のファイル（item_path）だけを取り出して読み直し、位置を集める（別プロセスで動く）。

    戻り値は collect_task と同じ形（位置・形式は取り出したファイルのもの）に、書庫の情報（archive）を足したもの。
    source の SHA-256 は書庫ファイル全体のもの（下見のあとに書庫が変わったかの照合に使う）。
    """
    from . import archive_write as aw

    options = args["options"]
    book = args.get("book") or PasswordBook()
    top_path, item_path = args["path"], args["item_path"]
    workdir, owner = aw.make_workdir(options.temp_dir)
    try:
        env = _archive_env(options, book, top_path, workdir)
        res = aw.extract_target(top_path, item_path, env)
        got = collect_task({"path": res.leaf_path, "options": options, "book": book})
        got["archive"] = res.describe()
        got["leaf_name"] = res.leaf_name
        got["source"] = {"sha256": sha256_file(top_path)}
        return got
    finally:
        aw.remove_workdir(workdir, owner)


def collect_task(args: dict) -> dict:
    """ファイルを読み直して、構造の位置を全部集める（別プロセスで動く）。生の値は返さない。"""
    from .engine import scan_file

    if args.get("item_path"):
        return collect_inner_task(args)
    options = replace(args["options"], collect_positions=True, reveal=False)
    result = scan_file(args["path"], options, args.get("book") or PasswordBook())
    top = _top_item(result, args["path"])
    if result.source is None or top is None:
        reason = result.items[0].reason if result.items else ""
        raise RemedyError(f"元のファイルを読めませんでした: {reason}" if reason else "元のファイルを読めませんでした")
    others = sum(sum(it.finding_counts.values()) for it in result.items if it is not top)
    password_opened = any(
        "パスワードで開いた" in n for n in top.notes
    )  # 暗号化された PDF を、検査で入れたパスワードで開いた
    db_schema: dict = {}
    if top.pos_layout == "sqlite" and top.positions:
        from .remedy_sqlite import schema_notes

        try:
            db_schema = schema_notes(args["path"], sorted({k[0] for k in top.positions}))
        except Exception:  # noqa: BLE001  下見の注意が取れなくても、対処そのものは止めない
            db_schema = {}
    return {
        "source": result.source,
        "status": top.status.value,
        "reason": top.reason,
        "kind": top.kind,
        "layout": top.pos_layout,
        "overflow": top.pos_overflow,
        "positions": top.positions,
        "top_findings": sum(top.finding_counts.values()),
        "other_findings": others,
        "db_schema": db_schema,
        "password_opened": password_opened,
    }


def _rank_filter(ranks) -> set[int] | None:
    return None if ranks is None else {int(r) for r in ranks}


def select_from_args(positions: dict, args: dict) -> Selection:
    return select_positions(
        positions,
        types=set(args["types"]) if args.get("types") is not None else None,
        ranks=_rank_filter(args.get("ranks")),
        sheets=set(args["sheets"]) if args.get("sheets") is not None else None,
    )


def apply_task(args: dict) -> dict:
    """対処の実行のうち、別プロセスで動く部分。

    - ファイルの削除はここで済ませる（退避はしない。ごみ箱のある場所はごみ箱へ・無い場所はそのまま消す）。
    - 書き換えは、一時の新ファイルを書き（flush・fsync）、検査し直して開けると確かめるところまで（prepare）。
      元の名前への確定（改名・置き換え・ごみ箱）と記録の更新は、親のプロセスが行う（commit_rewrite）。
      ここまでは元のファイルに触らない。失敗したら一時の新ファイルを消して終わる。

    args: path・method・options（検査の設定）・tmp_new（一時の新ファイルの名前）・types・ranks・sheets・dummy_mode・expected_sha256
    """
    path = args["path"]
    method = args["method"]
    if not os.path.isfile(_long(path)):
        raise RemedyError("ファイルが見つかりません（移動・削除された可能性）")
    if method == "delete_file":
        # 個人情報を含むファイルを手元のディスクへ写さないため、削除は退避しない（ごみ箱から戻す・戻せない場合は下見で知らせる）
        disposal = delete_original(path)
        return {"deleted": True, "changed": {"files": 1, "disposal": disposal}}
    if args.get("item_path"):
        return prepare_inner(args)
    return prepare_plain(args)


def rewrite_file(
    src: str, dst: str, layout: str, method: str, sel: Selection, maker, name: str, passwords: list[str] | None = None
) -> dict:
    """形式（検査のときに決まる位置の意味）に応じて、一時の新ファイル dst へ書き換えた結果を書く。元の src には書かない。

    passwords は検査のときに入れたパスワードの候補（暗号化された PDF を開き、同じパスワードで暗号化し直すために使う）。
    """
    if layout == "pdf":
        from .remedy_pdf import rewrite_pdf_file

        return rewrite_pdf_file(src, dst, method, sel, maker, passwords)
    if layout in ("docx", "pptx"):
        from .remedy_office import rewrite_office_file

        return rewrite_office_file(src, dst, layout, method, sel, maker)
    if layout == "xlsx":
        return rewrite_xlsx_file(src, dst, method, sel, maker, keep_vba=name.lower().endswith(".xlsm"))
    if layout == "sqlite":
        from .remedy_sqlite import rewrite_sqlite_file

        return rewrite_sqlite_file(src, dst, method, sel, maker)
    if layout == "sqldump":
        from .remedy_sqldump import rewrite_sql_dump_file

        return rewrite_sql_dump_file(src, dst, method, sel, maker)
    return rewrite_text_file(src, dst, layout, method, sel, maker)


def _verify_new_file(tmp_new: str, options: ScanOptions, args: dict, dummies: list[str], book=None) -> dict:
    """出来上がった新ファイルを検査し直して、開けること・残った検出の数を確かめる（元には触らない）。"""
    try:
        summary = rescan_summary(tmp_new, options, args, dummies, book)
    except Exception as e:  # noqa: BLE001
        raise RemedyError(
            f"書き換えたファイルを検査し直せませんでした（{type(e).__name__}）。元のファイルは変えていません"
        ) from None
    if not summary["opened"]:
        raise RemedyError(
            "書き換えたファイルを開けなかったため、置き換えません（検査し直しで読めませんでした）。元のファイルは変えていません"
        )
    return summary


def prepare_plain(args: dict) -> dict:
    """実ファイル（csv・tsv・txt・xlsx・xlsm）の書き換えを、一時の新ファイルまで作って検査し直す。"""
    path, method, tmp_new = args["path"], args["method"], args["tmp_new"]
    book = args.get("book") or PasswordBook()
    # 実行の時点でファイルを読み直して、位置を集める
    got = collect_task({"path": path, "options": args["options"], "book": book})
    problem = unsupported_reason(method, path, got)
    if problem:
        raise RemedyError(problem)
    if args.get("expected_sha256") and got["source"].get("sha256") != args["expected_sha256"]:
        raise RemedyError(
            "下見のあとにファイルが変わりました。もう一度、下見からやり直してください（何も変えていません）"
        )
    sel = select_from_args(got["positions"], args)
    if not sel.detections:
        raise RemedyError("選んだ種類・確度の検出が、ファイルに見つかりませんでした（何も変えていません）")
    maker = DummyMaker(args.get("dummy_mode") or "same") if method == "dummy" else None
    orig_sha = sha256_file(path)
    try:
        stats = rewrite_file(
            path, tmp_new, got["layout"], method, sel, maker, path, passwords=book.candidates_for(path)
        )
        notes = stats.pop("notes", None) or []  # 結果に添える知らせ（PDF の制限が引き継がれないなど。値は含めない）
        fsync_path(tmp_new)
        if sha256_file(path) != orig_sha:
            raise RemedyError("書き換えている間に元のファイルが変わりました。何も変えていません")
        remaining = _verify_new_file(tmp_new, args["options"], args, sorted(maker.produced) if maker else [], book)
        new_sha = sha256_file(tmp_new)
    except BaseException:
        _discard(tmp_new)
        raise
    return {
        "tmp_new": tmp_new,
        "orig_sha256": orig_sha,
        "new_sha256": new_sha,
        "changed": stats,
        "remaining": remaining,
        "notes": notes,
    }


def prepare_inner(args: dict) -> dict:
    """書庫の中のファイルへの対処を、一時の新しい書庫まで作って検査し直す（別プロセスで動く）。

    流れ: 対象の項目だけを取り出す → T2-a と同じ書き換えを当てる（または取り除く）→ 書庫を作り直す（一時の名前）→
    書庫を検査し直す。入れ子は内側から作り直す。形式が rar・cab・iso など書けないものは、convert_zip=True のときだけ、
    同じフォルダの「元の名前.zip」に作り直す（元の書庫は確定のときに消す）。
    """
    from . import archive_write as aw

    path, item_path, method, tmp_new = args["path"], args["item_path"], args["method"], args["tmp_new"]
    options = args["options"]
    book = args.get("book") or PasswordBook()
    workdir, owner = aw.make_workdir(options.temp_dir)
    try:
        env = _archive_env(options, book, path, workdir)
        res = aw.extract_target(path, item_path, env)
        arch = res.describe()
        if args.get("expected_sha256") and sha256_file(path) != args["expected_sha256"]:
            raise RemedyError(
                "下見のあとに書庫が変わりました。もう一度、下見からやり直してください（何も変えていません）"
            )
        convert = bool(args.get("convert_zip")) and not arch["can_write"]
        if not arch["can_write"] and not convert:
            raise RemedyError(
                "この書庫は、そのままでは書き換えられません。「zip に作り直す」を選んでください（形式が変わります）"
            )
        new_leaf = None
        stats: dict = {"entries": 1}
        leaf_notes: list[str] = []
        maker = None
        if method == "remove_entry":
            problem = unsupported_reason(method, res.leaf_name, {"archive": arch})
            if problem:
                raise RemedyError(problem)
        else:
            got = collect_task({"path": res.leaf_path, "options": options, "book": book})
            got["archive"] = arch
            problem = unsupported_reason(method, res.leaf_name, got)
            if problem:
                raise RemedyError(problem)
            sel = select_from_args(got["positions"], args)
            if not sel.detections:
                raise RemedyError("選んだ種類・確度の検出が、ファイルに見つかりませんでした（何も変えていません）")
            maker = DummyMaker(args.get("dummy_mode") or "same") if method == "dummy" else None
            new_leaf = os.path.join(env.new_dir(), res.leaf_name)
            stats = rewrite_file(
                res.leaf_path,
                new_leaf,
                got["layout"],
                method,
                sel,
                maker,
                res.leaf_name,
                passwords=book.candidates_for(path),
            )
            leaf_notes = stats.pop("notes", None) or []
        dest = aw.zip_target_for(path) if convert else path
        if convert and os.path.exists(_long(dest)):
            raise RemedyError(
                f"同じ場所に「{os.path.basename(dest)}」があるため、zip に作り直せません。"
                "そのファイルの名前を変えるか移してから、もう一度お試しください（何も変えていません）"
            )
        orig_sha = sha256_file(path)
        try:
            notes = [*leaf_notes, *aw.rebuild_target(res, new_leaf, env, tmp_new, convert)]
            fsync_path(tmp_new)
            if sha256_file(path) != orig_sha:
                raise RemedyError("作り直している間に元の書庫が変わりました。何も変えていません")
            remaining = _verify_new_file(tmp_new, options, args, sorted(maker.produced) if maker else [], book)
            new_sha = sha256_file(tmp_new)
        except BaseException:
            _discard(tmp_new)
            raise
        return {
            "tmp_new": tmp_new,
            "orig_sha256": orig_sha,
            "new_sha256": new_sha,
            "changed": stats,
            "remaining": remaining,
            "converted_to": dest if convert else None,
            "notes": notes,
        }
    finally:
        aw.remove_workdir(workdir, owner)


def rescan_summary(
    path: str, options: ScanOptions, args: dict, dummies: list[str] | None = None, book: PasswordBook | None = None
) -> dict:
    """書き換えたファイルを検査し直し、残った検出の数（全体と、選んだ種類・確度の分）を返す。

    ダミーにした値そのもの（dummies。この回で自分が作った文字列）は数えない。列見出しが「メール」「氏名」などの列は、
    中身が何であれ値として拾う規則があり、ダミーまで検出として数えてしまうため。許可リストの仕組みを、この数え直しだけに使う
    （設定としては保存しない）。
    """
    from .engine import scan_file

    options = replace(
        options,
        collect_positions=False,
        reveal=False,
        allow_values=list(options.allow_values) + list(dummies or []),
    )
    result = scan_file(path, options, book or PasswordBook())
    counts = _count_conf(result.items)
    types = set(args["types"]) if args.get("types") is not None else None
    ranks = _rank_filter(args.get("ranks"))
    selected = 0
    by_type: dict[str, int] = {}
    for k, n in counts.items():
        pii_type, conf = k.split(":", 1)
        by_type[pii_type] = by_type.get(pii_type, 0) + n
        if (types is None or pii_type in types) and (ranks is None or CONF_RANKS[conf] in ranks):
            selected += n
    statuses = {it.status.value for it in result.items}
    top = _top_item(result, path)
    return {
        # 書庫・ファイルそのものが開けたか（中の項目の一部が読めないのは、元からそうだったかもしれないので数えない）
        "opened": top is not None and top.status.value not in (Status.UNCHECKABLE.value, Status.NEEDS_PASSWORD.value),
        "total": sum(counts.values()),
        "selected": selected,
        "by_type": by_type,
        "by_conf": {c: sum(n for k, n in counts.items() if k.endswith(":" + c)) for c in CONF_RANKS},
        "readable": not (statuses & {Status.UNCHECKABLE.value, Status.NEEDS_PASSWORD.value}),
    }


def unsupported_reason(method: str, path: str, info: dict) -> str:
    """この方法を選べない理由（選べるなら空）。info は分析の結果（status・layout・overflow）。"""
    if method == "delete_file":
        return ""
    arch = info.get("archive")
    if method in ARCHIVE_ONLY_METHODS:
        if not arch:
            return "書庫の中のファイルにだけ使える方法です"
        if method == "convert_zip":
            if arch["can_write"]:
                return "この形式は、書庫のまま書き換えられるため、作り直す必要はありません"
            return "" if arch["can_convert"] else arch["convert_reason"]
        if not (arch["can_write"] or arch["can_convert"]):
            return arch["convert_reason"] + "。書庫ごとの削除（ごみ箱）はできます"
        if arch["single"]:
            return (
                "1ファイルを包んだだけの形式（gz・bz2・xz など）では、中のファイルだけを取り除けません。"
                "書庫ごとの削除を選んでください"
            )
        return ""
    if arch and not (arch["can_write"] or arch["can_convert"]):
        return arch["convert_reason"] + "。書庫ごとの削除（ごみ箱）はできます"
    status = info.get("status")
    if status == Status.NEEDS_PASSWORD.value:
        return "パスワードが必要な（暗号化された）ファイルは、中身を書き換えられません。ファイルの削除はできます"
    kind_reason = file_only_reason(info.get("kind") or "")
    if kind_reason:
        return kind_reason
    if status != Status.SCANNED.value:
        return "中身を最後まで構造どおりに読めなかったファイルは、位置が分からないため中身を書き換えられません。ファイルの削除はできます"
    layout = info.get("layout") or ""
    family = "csv" if layout.startswith("csv") else layout
    if family not in LAYOUT_METHODS:
        return (
            "この形式の中身の書き換えには、まだ対応していません"
            "（対応: csv・tsv・txt・xlsx・xlsm・SQLite・SQL のダンプ・PDF・docx・pptx）。ファイルの削除はできます"
        )
    if family == "xlsx" and not path.lower().endswith(XLSX_EXTS):
        return "xlsx・xlsm 以外の Excel 形式は、中身を書き換えられません。ファイルの削除はできます"
    if info.get("overflow"):
        return "検出が多すぎて（200 万件超）位置を最後まで集められませんでした。ファイルの削除はできます"
    if method not in LAYOUT_METHODS[family]:
        return "この形式では選べない方法です"
    if family == "sqlite":
        from .remedy_sqlite import sidecar_problem, version_problem

        return sidecar_problem(path) or version_problem(method)
    return ""


def layout_from_kind(kind: str) -> str:
    """位置を集められなかったとき（パスワードが必要・読めなかった）に、方法の一覧の出し分けに使う形式（形式の名前から決める）。"""
    if kind == "PDF":
        return "pdf"
    if kind.startswith("Word（docx）"):
        return "docx"
    if kind.startswith("PowerPoint（pptx）"):
        return "pptx"
    return ""


def file_only_reason(kind: str) -> str:
    """中身の書き換えを作っていない形式（ファイルの削除だけできる）の理由。当てはまらなければ空。"""
    if kind.startswith("Access"):
        return (
            "Access（.accdb・.mdb）は、書き換えの手段（ODBC ドライバ・Access 本体）が環境によって違うため、"
            "いまはファイルの削除だけに対応しています"
        )
    if "Oracle" in kind and "ダンプ" in kind:
        return (
            "Oracle のダンプ（exp・expdp）は、長さ・区画の作りが細かく、書き換えて読み込める形を保つのが難しいため、"
            "いまはファイルの削除だけに対応しています（中身の対処は今後対応します）"
        )
    if "97-2003" in kind and ("doc" in kind or "ppt" in kind):
        what = "Word（doc）" if "Word" in kind else "PowerPoint（ppt）"
        return (
            f"旧形式の {what} は、書き換えて保存できる部品が無いため、ファイルの削除だけに対応しています"
            "（docx・pptx に変換してから検査し直すと、段落・スライドなどの対処ができます）"
        )
    if "暗号化された Office" in kind:
        return (
            "パスワードで暗号化された Office 文書は、中身を書き換えられないため、ファイルの削除だけに対応しています"
            "（パスワードを外して保存し直してから検査し直すと、中身の対処ができます）"
        )
    if "PostgreSQL" in kind and "custom" in kind:
        return (
            "PostgreSQL のカスタム形式（-Fc）のダンプは、いまはファイルの削除だけに対応しています"
            "（平文の SQL のダンプなら、行・列・表の対処ができます）"
        )
    return ""


def _run_in_process(kind: str, args: dict, timeout: int) -> dict:
    """collect / apply を別プロセス（検査と同じ pebble・メモリ上限）で走らせる。"""
    from pebble import ProcessPool
    from pebble.common import ProcessExpired

    fn = collect_task if kind == "collect" else apply_task
    _, memory_limit = plan_workers(1)
    ctx = multiprocessing.get_context("spawn")
    try:
        with ProcessPool(
            max_workers=1, max_tasks=1, context=ctx, initializer=worker_init, initargs=(memory_limit,)
        ) as pool:
            return pool.schedule(fn, args=(args,), timeout=timeout).result()
    except (FutureTimeout, TimeoutError):
        raise RemedyError(
            f"時間制限（{timeout // 60} 分）を超えたため打ち切りました。元のファイルは、置き換える前なら変わっていません"
        ) from None
    except ProcessExpired:
        raise RemedyError("途中でプロセスが終了しました（メモリ不足・壊れたファイルの可能性）") from None


def inline_runner(kind: str, args: dict, timeout: int) -> dict:
    """別プロセスにせず、このプロセスの中で走らせる（試験用）。"""
    return (collect_task if kind == "collect" else apply_task)(args)


# ---------------------------------------------------------------- サービス（画面の API から使う）


class Analysis:
    """1ファイルの分析（位置の集まりと、使える方法）。メモリの中だけに持つ。"""

    def __init__(self, job_id: str, top_path: str, item_path: str = ""):
        self.job_id = job_id
        self.top_path = top_path
        self.item_path = item_path  # 書庫の中のファイルが対象のとき、その検査のパス（外!内）。実ファイルなら空
        self.state = "running"
        self.started = time.time()
        self.finished = 0.0
        self.error = ""
        self.positions: dict = {}
        self.info: dict = {}
        self.size = 0

    def view(self) -> dict:
        if self.state == "error":
            return {"state": "error", "message": self.error}
        if self.state == "running":
            return {"state": "running", "elapsed": round(time.time() - self.started, 1)}
        counts: dict[str, dict[str, int]] = {}
        for (_sheet, pii_type, rank), arr in self.positions.items():
            d = counts.setdefault(pii_type, {})
            d[str(rank)] = d.get(str(rank), 0) + len(arr) // 4
        # 「対象にするシート・表」の絞り込みは、Excel と DB だけ（PDF・docx・pptx の「シート」はページ・部品・スライドの名前）
        sheets = [] if self.info.get("layout") in OFFICE_LAYOUTS else sorted({k[0] for k in self.positions if k[0]})
        return {"state": "done", **self.info, "counts": counts, "sheets": sheets}


class RunState:
    """実行（apply）1回の状態。"""

    def __init__(self, job_id: str, top_path: str, method: str):
        self.job_id, self.top_path, self.method = job_id, top_path, method
        self.state = "running"
        self.started = time.time()
        self.error = ""
        self.result: dict | None = None
        self.thread: threading.Thread | None = None  # 試験が終わりを待つために持つ

    def view(self) -> dict:
        if self.state == "done":
            return {"state": "done", **(self.result or {})}
        if self.state == "error":
            return {"state": "error", "message": self.error}
        return {"state": "running", "elapsed": round(time.time() - self.started, 1)}


class RemedyService:
    """分析・下見・実行・途中で止まった対処の立て直しの窓口。重い処理は別プロセス（runner_fn）。"""

    def __init__(self, store, runner_fn=None, registry=None):
        self.store = store
        # 検査を動かしているメモリのパスワード（書庫の中のファイルを取り出すときに使う。保存しない）を引く先
        self.registry = registry
        self._runner_fn = runner_fn or _run_in_process
        self._lock = threading.Lock()
        self._analyses: dict[tuple[str, str], Analysis] = {}
        self._runs: dict[str, RunState] = {}
        self._busy: set[tuple[str, str]] = set()  # 実行中のファイル（同じファイルを同時に対処しない）
        self._slots = threading.Semaphore(1)

    # ------------------------------------------------------------ 分析

    def request_analysis(self, job_id: str, top_path: str, item_path: str = "") -> dict:
        """分析を始める（結果がメモリにあれば使い回す）。いまの状態を返す。始める前に分かる理由は error で返す。

        item_path は書庫の中のファイルが対象のときの検査のパス（外!内）。分析の鍵は（ジョブ, 対象のパス）。
        """
        key = (job_id, item_path or top_path)
        with self._lock:
            self._purge()
            a = self._analyses.get(key)
            if a is not None:
                return a.view()
            try:
                plan = self._plan(job_id, top_path, item_path)
            except RemedyError as e:
                return {"state": "error", "message": str(e)}
            a = self._analyses[key] = Analysis(job_id, top_path, item_path)
            a.size = plan["size"]
        threading.Thread(target=self._analyze, args=(a, plan), daemon=True, name="pii-remedy-analyze").start()
        return a.view()

    def get_analysis(self, job_id: str, top_path: str, item_path: str = "") -> Analysis:
        with self._lock:
            self._purge()
            a = self._analyses.get((job_id, item_path or top_path))
        if a is None or a.state != "done":
            raise RemedyError(
                "分析の結果が見つかりません（時間が経って捨てました）。もう一度「対処する」から始めてください"
            )
        return a

    def _purge(self) -> None:
        now = time.time()
        for k in [
            k
            for k, a in self._analyses.items()
            if a.state != "running" and now - a.finished > (10 if a.state == "error" else ANALYSIS_KEEP_SECONDS)
        ]:
            del self._analyses[k]
        done = sorted(
            (k for k, a in self._analyses.items() if a.state != "running"), key=lambda k: self._analyses[k].finished
        )
        while len(self._analyses) > MAX_ANALYSES and done:
            del self._analyses[done.pop(0)]
        for rid in list(self._runs)[:-MAX_RUNS_KEPT]:
            if self._runs[rid].state != "running":
                del self._runs[rid]

    def forget_job(self, job_id: str) -> None:
        with self._lock:
            for k in [k for k in self._analyses if k[0] == job_id]:
                del self._analyses[k]

    def _book_for(self, job_id: str) -> PasswordBook:
        """検査を動かしているメモリのパスワードのコピー（書庫の中のファイルを取り出すときだけ使う。保存しない）。"""
        runner = self.registry.get(job_id, create=False) if self.registry is not None else None
        if runner is None:
            return PasswordBook()
        pw = runner.passwords
        return PasswordBook(
            common=list(pw.common),
            per_file={k: list(v) for k, v in pw.per_file.items()},
            connection_password=pw.connection_password,
        )

    def _plan(self, job_id: str, top_path: str, item_path: str = "") -> dict:
        """対処の前提を確かめ、検査の設定と時間制限を決める。できないときは RemedyError。"""
        from .remote import is_ftp_path
        from .runner import options_from_dict

        job = self.store.job(job_id)
        if not job:
            raise RemedyError("そのジョブは見つかりません")
        rows = self.store.query("SELECT size, state FROM files WHERE job_id=? AND top_path=?", (job_id, top_path))
        if not rows:
            raise RemedyError("そのファイルは、この検査の結果に見つかりません")
        if rows[0]["state"] != "done":
            raise RemedyError("そのファイルはまだ検査が終わっていません")
        if is_ftp_path(top_path):
            raise RemedyError("FTP の先のファイルは、書き換えられません（FTP は読み取りだけで使っています）")
        if not os.path.isfile(_long(top_path)):
            raise RemedyError("ファイルが見つかりません（移動・削除された可能性）")
        try:
            attrs = os.stat(_long(top_path)).st_file_attributes  # type: ignore[attr-defined]
        except (AttributeError, OSError):
            attrs = 0
        if attrs & FILE_ATTRIBUTE_READONLY:
            raise RemedyError("読み取り専用のファイルです。読み取り専用の設定を外してから、もう一度お試しください")
        options = options_from_dict(job["options"])
        temp_dir = options.temp_dir if options.temp_dir and os.path.isdir(options.temp_dir) else None
        options = replace(options, reveal=False, collect_positions=True, temp_dir=temp_dir, reuse=False)
        size = int(rows[0]["size"] or 0)
        timeout = min(MAX_TIMEOUT, max(MIN_TIMEOUT, size // BYTES_PER_SEC))
        # 検査のときに入れたパスワード（暗号化された PDF を開く・同じパスワードで暗号化し直すために使う。メモリの中だけ）
        plan = {
            "options": options,
            "size": size,
            "timeout": timeout,
            "roots": job["roots"],
            "book": self._book_for(job_id),
        }
        if item_path:
            if not item_path.startswith(top_path + "!"):
                raise RemedyError("書庫の中のパスが正しくありません")
            if not self.store.query(
                "SELECT 1 FROM items WHERE job_id=? AND top_path=? AND path=?", (job_id, top_path, item_path)
            ):
                raise RemedyError("その項目は、この検査の結果に見つかりません")
        return plan

    def _collect_args(self, a: Analysis, plan: dict) -> dict:
        args = {"path": a.top_path, "options": plan["options"], "book": plan["book"]}
        if a.item_path:
            args["item_path"] = a.item_path
        return args

    def _analyze(self, a: Analysis, plan: dict) -> None:
        try:
            with self._slots:
                got = self._runner_fn("collect", self._collect_args(a, plan), plan["timeout"])
            a.positions = got["positions"]
            inner = bool(a.item_path)
            leaf_name = got.get("leaf_name") or a.top_path
            methods = {}
            for m in METHOD_LABELS:
                if m in ARCHIVE_ONLY_METHODS and not inner:
                    continue  # 実ファイルには出さない（書庫の中のファイルにだけ使える方法）
                layout = got["layout"] or layout_from_kind(got.get("kind") or "")
                only = LAYOUT_ONLY_METHODS.get(m)
                if only is not None and layout not in only:
                    continue  # その形式にだけ出す方法（表の削除は DB・黒塗りは PDF など）
                if m == "delete_sheet" and layout in DB_LAYOUTS + OFFICE_LAYOUTS:
                    continue  # シートは Excel の言い方（DB は表）
                if layout in OFFICE_LAYOUTS and m not in ("delete_file", "convert_zip", *LAYOUT_METHODS[layout]):
                    continue  # PDF に行・列は無い・pptx に表の行・列の削除は無い
                reason = unsupported_reason(m, leaf_name, got)
                label = (
                    ARCHIVE_DELETE_LABEL
                    if (inner and m == "delete_file")
                    else LAYOUT_LABELS.get((layout, m), METHOD_LABELS[m])
                )
                methods[m] = {"label": label, "available": not reason, "reason": reason}
            a.info = {
                "layout": got["layout"],
                "kind": got["kind"],
                "sha256": got["source"].get("sha256"),
                "size": a.size,
                "methods": methods,
                "other_findings": got["other_findings"],
                "dummy_modes": DUMMY_MODES,
                "recycle_bin": has_recycle_bin(a.top_path),
                "db_schema": got.get("db_schema") or {},
                "password_opened": bool(got.get("password_opened")),
            }
            if inner:
                a.info["archive"] = got["archive"]
                a.info["leaf_name"] = leaf_name
            self._finish(a, "done")
        except RemedyError as e:
            self._finish(a, "error", str(e))
        except Exception as e:  # noqa: BLE001  想定外の失敗も画面に理由を返す（値は含めない）
            self._finish(a, "error", f"分析に失敗しました（{type(e).__name__}）")

    def _finish(self, a: Analysis, state: str, error: str = "") -> None:
        with self._lock:
            a.error = error
            a.finished = time.time()
            a.state = state

    # ------------------------------------------------------------ 下見

    def normalize(self, a: Analysis, params: dict) -> dict:
        """画面から来た選びを確かめて、使う形にする。誤りは RemedyError。"""
        method = params.get("method")
        if method not in METHOD_LABELS or method not in a.info["methods"]:
            raise RemedyError("方法が正しくありません")
        if method == "convert_zip":
            raise RemedyError("「zip に作り直す」は、ほかの方法と一緒に選びます（単独の方法ではありません）")
        arch = a.info.get("archive")
        convert = bool(params.get("convert_zip")) and bool(arch) and not arch["can_write"] and method != "delete_file"
        if arch and not arch["can_write"] and method != "delete_file" and not convert:
            raise RemedyError(
                "この書庫は、そのままでは書き換えられません。「zip に作り直す」も選んでください（形式が変わります）"
            )
        if convert and not a.info["methods"]["convert_zip"]["available"]:
            raise RemedyError(a.info["methods"]["convert_zip"]["reason"] or "zip に作り直せません")
        spec = a.info["methods"][method]
        if not spec["available"]:
            raise RemedyError(spec["reason"] or "この方法は選べません")
        present_types = sorted({k[1] for k in a.positions})
        types = params.get("types")
        if types is None:
            types = present_types
        if not isinstance(types, list) or not all(isinstance(t, str) for t in types):
            raise RemedyError("種類の指定が正しくありません")
        confs = params.get("confidences")
        if confs is None:
            confs = ["high", "medium"]
        if not isinstance(confs, list) or not all(c in CONF_RANKS for c in confs):
            raise RemedyError("確度の指定が正しくありません")
        sheets = params.get("sheets")
        if sheets is not None and (not isinstance(sheets, list) or not all(isinstance(s, str) for s in sheets)):
            raise RemedyError("シートの指定が正しくありません")
        mode = params.get("dummy_mode") or "same"
        if method == "dummy" and mode not in DUMMY_MODES:
            raise RemedyError("ダミーの作り方が正しくありません")
        out = {
            "method": method,
            "types": types,
            "ranks": sorted({CONF_RANKS[c] for c in confs}),
            "sheets": sheets,
            "dummy_mode": mode if method == "dummy" else None,
            "convert_zip": convert,
        }
        if method not in ("delete_file", "remove_entry") and not select_from_args(a.positions, out).detections:
            raise RemedyError("選んだ種類・確度の検出がありません")
        return out

    def preview(self, job_id: str, top_path: str, params: dict) -> dict:
        """変わる行・列・シートの数と例、注意を返す（何も書き換えない）。"""
        a = self.get_analysis(job_id, top_path, params.get("item_path") or "")
        p = self.normalize(a, params)
        method = p["method"]
        leaf = os.path.basename(top_path)
        arch = a.info.get("archive")
        out = {
            "method": method,
            "method_label": (
                ARCHIVE_DELETE_LABEL
                if (arch and method == "delete_file")
                else LAYOUT_LABELS.get((a.info.get("layout"), method), METHOD_LABELS[method])
            ),
            "file_name": leaf,
            "warnings": [],
            "expected_sha256": a.info.get("sha256"),
        }
        if arch:
            out["item_name"] = arch["item"]
            out["convert_zip"] = p["convert_zip"]
        recycle = bool(a.info.get("recycle_bin", True))
        if method == "delete_file":
            out["changes"] = {"files": 1}
            out["disposal"] = "recycle_bin" if recycle else "permanent"
            out["summary"], note = disposal_text("書庫" if arch else "ファイル", leaf, recycle)
            if note:
                out["warnings"].append(note)
            out["can_run"] = True
            return out
        if method == "remove_entry":
            out["changes"] = {"entries": 1}
            out["summary"] = f"書庫「{leaf}」の中のファイル「{arch['item']}」を取り除きます（書庫を作り直します）"
            self._archive_warnings(out, arch, top_path, p["convert_zip"], recycle)
            self._original_warning(out, leaf, recycle, bool(arch), p["convert_zip"])
            out["can_run"] = True
            return out
        sel = select_from_args(a.positions, p)
        layout = a.info["layout"]
        rows, cols = sel.rows(), sel.cols()
        n_rows = sum(len(v) for v in rows.values())
        n_cols = sum(len(v) for v in cols.values())
        schema = a.info.get("db_schema") or {}
        sample: list[str] = []
        for sheet in sorted(rows):
            for r in sorted(rows[sheet])[: SAMPLE_ROWS - len(sample)]:
                sample.append(row_label(layout, sheet, r, schema))
            if len(sample) >= SAMPLE_ROWS:
                break
        changes: dict = {"detections": sel.detections}
        if layout in OFFICE_LAYOUTS:
            changes = office_preview(layout, method, sel, p, out, sample, bool(a.info.get("password_opened")))
            out["sample_rows"] = sample
            out["sample_label"] = "変わる場所の例"
        elif method == "delete_rows":
            changes["rows"] = n_rows
            out["summary"] = f"{n_rows:,} 行を削除します（検出 {sel.detections:,} 件を含む行）"
            out["sample_rows"] = sample
            if any(1 in v for v in rows.values()):
                out["warnings"].append("1 行目（見出し行の可能性）も削除されます")
        elif method == "delete_columns":
            changes["cols"] = n_cols
            letters = [col_label(layout, s, c, schema) for s in sorted(cols) for c in sorted(cols[s])]
            out["summary"] = f"{n_cols:,} 列を削除します（検出 {sel.detections:,} 件を含む列）"
            out["sample_cols"] = letters[:SAMPLE_ROWS]
        elif method == "dummy":
            changes["cells"] = sel.cell_count()
            what = "行" if layout == "lines" else ("欄" if layout in DB_LAYOUTS else "セル")
            out["summary"] = (
                f"{changes['cells']:,} {what}の検出した値 {sel.detections:,} 件を置き換えます（{DUMMY_MODES[p['dummy_mode']]}）"
            )
            out["sample_rows"] = sample
            if layout == "xlsx":
                out["warnings"].append("数式のセルは書き換えません。数値だったセルは文字列のセルになります")
        elif method == "delete_sheet":
            targets = sel.sheets()
            changes["sheets"] = len(targets)
            changes["sheet_names"] = targets
            out["summary"] = f"{len(targets)} シートを削除します: " + "、".join(targets)
            out["warnings"].append("ブックのすべてのシートは削除できません（1つ以上のシートが残る選びにしてください）")
        elif method == "delete_table":
            targets = sel.sheets()
            changes["tables"] = len(targets)
            changes["table_names"] = targets
            out["summary"] = f"{len(targets)} 個の表を削除します: " + "、".join(targets)
        out["changes"] = changes
        if layout == "xlsx" and method != "dummy":
            out["warnings"].extend(XLSX_WARNINGS)
        if layout in DB_LAYOUTS:
            out["warnings"].extend(db_warnings(layout, method, sel, schema))
        if layout.startswith("csv") or layout == "lines":
            out["warnings"].append("文字コード・BOM・改行・区切り・引用符の付け方は元のまま保ちます")
        if a.info.get("other_findings"):
            out["warnings"].append(
                f"このファイルには、行・列の位置を持たない検出（コメント・内側のファイル・ファイル名など）も {a.info['other_findings']:,} 件あります。"
                "それらはこの対処では変わらず、実行のあとの検査し直しで残りとして出ます"
            )
        if arch:
            out["summary"] = f"書庫の中の「{arch['item']}」: {out['summary']}"
            self._archive_warnings(out, arch, top_path, p["convert_zip"], recycle)
        self._original_warning(out, leaf, recycle, bool(arch), p["convert_zip"])
        out["can_run"] = True
        return out

    @staticmethod
    def _original_warning(out: dict, leaf: str, recycle: bool, is_archive: bool, convert: bool) -> None:
        """書き換えのとき、元のファイルがどうなるか（退避の写しは作らない）を下見の最初に出す。zip への作り直しは別の文面。"""
        if convert:
            return  # _archive_warnings が、元の書庫の行き先を含めて出す
        noun = "書庫" if is_archive else "ファイル"
        if recycle:
            out["disposal"] = "recycle_bin"
            stem, ext = os.path.splitext(leaf)
            out["warnings"].insert(
                0,
                f"元の{noun}は、同じフォルダの中で「{stem}（対処前 年月日-時分秒）{ext}」の名前に変えてからごみ箱へ送ります"
                "（ごみ箱から戻すと、この名前で戻ります）。退避の写しは作らないので、このアプリの「元に戻す」はありません",
            )
        else:
            out["disposal"] = "replaced"
            out["warnings"].insert(
                0,
                f"元の{noun}は残りません（この場所にはごみ箱がありません）。中身を新しいものに入れ替えます。元に戻せません",
            )

    def _archive_warnings(self, out: dict, arch: dict, top_path: str, convert: bool, recycle: bool = True) -> None:
        """書庫の中のファイルへの対処の注意（書庫全体を作り直す・形式が変わる・署名・暗号など）を下見に足す。"""
        leaf = os.path.basename(top_path)
        kind = arch["top_kind"]
        if convert:
            new_name = os.path.basename(zip_target_for(top_path))
            out["disposal"] = "recycle_bin" if recycle else "permanent"
            gone = (
                f"元の「{leaf}」はごみ箱へ送ります（退避の写しは作りません。ごみ箱から戻せます）"
                if recycle
                else f"元の「{leaf}」は完全に削除します（この場所にはごみ箱がありません。退避もしないので、元に戻せません）"
            )
            out["warnings"].insert(
                0,
                f"形式が変わります: {arch['top_label']} → zip。「{leaf}」の代わりに同じフォルダへ「{new_name}」を作り、"
                f"{gone}。拡張子が変わるので、元の名前を参照しているものは見つからなくなります。"
                "ほかの項目は取り出して zip に詰め直します（日時は取り出した時点のもの・権限や所有者の情報は引き継がれません）",
            )
        else:
            same = "ほかの項目は、中身を変えずにそのまま写します"
            if kind == "zip":
                same += "（圧縮したままのデータ・日時・圧縮方式・属性・コメント・並び順を保ちます）"
            elif kind == "7z":
                same = "7-Zip の更新で作り直します。ほかの項目の中身は変わりません（まとめて圧縮した書庫は、含まれる塊を圧縮し直します）"
            elif kind == "tar":
                same += "（日時・権限・所有者などのメタデータも保ちます）"
            elif arch["levels"][-1]["single"]:
                same = "中身を書き換えて、同じ形式で包み直します"
            out["warnings"].insert(0, f"書庫「{leaf}」全体を作り直します。{same}")
        if len(arch["levels"]) > 1:
            names = " → ".join([leaf] + [lv["name"] for lv in arch["levels"]])
            out["warnings"].append(f"入れ子になっています（{names}）。内側の書庫から順に作り直します")
        out["warnings"].append(
            "同じ書庫の中の別の項目も対処するときは、1項目ずつ実行します（そのたびに書庫を作り直します）"
        )
        if arch["signed"]:
            out["warnings"].append(
                "署名つきの書庫（jar の署名など）です。作り直すと、署名の検証に通らなくなります（署名し直しが要ります）"
            )
        if arch["encrypted"] and not convert:
            out["warnings"].append(
                "パスワードつきです。検査のときに入れたパスワードで、同じ暗号方式（"
                + (arch["encryption"] or "元と同じ")
                + "）に暗号化し直します"
            )

    # ------------------------------------------------------------ 実行

    def _begin_run(
        self, job_id: str, top_path: str, params: dict, confirmed: bool, expected_sha256: str | None
    ) -> tuple[str, RunState, tuple]:
        """実行の準備（確認・前提の確かめ・途中で止まった対処の立て直し・書き換えなら記録の作成）。
        （run_id, RunState, _apply の引数）を返す。"""
        if confirmed is not True:
            raise RemedyError("確認の操作が必要です")
        item_path = params.get("item_path") or ""
        a = self.get_analysis(job_id, top_path, item_path)
        p = self.normalize(a, params)
        plan = self._plan(job_id, top_path, item_path)  # 実行の時点でも前提（ファイルの有無・読み取り専用）を確かめる
        key = (job_id, top_path)
        with self._lock:
            if key in self._busy:
                raise RemedyError("このファイルは、いま別の対処を実行中です")
            self._busy.add(key)
            rid = f"{int(time.time() * 1000)}-{len(self._runs)}"
            run = self._runs[rid] = RunState(job_id, top_path, p["method"])
        try:
            # 同じファイルに、前に途中で止まった対処が残っていれば、先に立て直す
            self._recover(top_path, ignore_busy=True)
            args = {
                "path": top_path,
                "method": p["method"],
                "options": plan["options"],
                "types": p["types"],
                "ranks": p["ranks"],
                "sheets": p["sheets"],
                "dummy_mode": p["dummy_mode"],
                "expected_sha256": expected_sha256 or a.info.get("sha256"),
            }
            if p["method"] != "delete_file":
                args["book"] = plan["book"]
            if item_path and p["method"] != "delete_file":
                args["item_path"] = item_path
                args["convert_zip"] = p["convert_zip"]
            filters = {k: p[k] for k in ("types", "ranks", "sheets", "dummy_mode")}
            if a.item_path:
                filters["item_path"] = a.item_path  # 書庫の中の対象（パスだけ。生の値は入れない）
                filters["convert_zip"] = p["convert_zip"]
            commit, record_id = None, None
            if p["method"] != "delete_file":
                # 書き換えは、元に触る前に「始めた」記録を作る（途中で落ちたとき、立て直しがこれを読む）
                commit = make_commit_plan(top_path, p["convert_zip"])
                args["tmp_new"] = commit["tmp_new"]
                if commit["dest"] != top_path:
                    filters["converted_to"] = commit["dest"]
                record_id = self.store.add_remediation(
                    job_id,
                    top_path,
                    p["method"],
                    filters,
                    {},
                    state="started",
                    note=json.dumps(commit, ensure_ascii=False),
                )
        except BaseException:
            with self._lock:
                self._busy.discard(key)
            raise
        return rid, run, (run, a, args, p, plan["timeout"], commit, record_id, filters)

    def start_run(self, job_id: str, top_path: str, params: dict, confirmed: bool, expected_sha256: str | None) -> dict:
        """対処の実行を始める（確認済みのときだけ）。run_id を返し、画面は状態を見に来る。"""
        rid, run, ctx = self._begin_run(job_id, top_path, params, confirmed, expected_sha256)
        run.thread = threading.Thread(target=self._apply, args=ctx, daemon=True, name="pii-remedy-apply")
        run.thread.start()
        return {"run_id": rid, **run.view()}

    def run_status(self, job_id: str, run_id: str) -> dict:
        with self._lock:
            run = self._runs.get(run_id)
        if run is None or run.job_id != job_id:
            raise RemedyError("その実行は見つかりません")
        return run.view()

    def _apply(
        self,
        run: RunState,
        a: Analysis,
        args: dict,
        p: dict,
        timeout: int,
        commit: dict | None,
        record_id: int | None,
        filters: dict,
    ) -> None:
        committing = False
        try:
            with self._slots:
                got = self._runner_fn("apply", args, timeout * 2)
            if got.get("deleted"):
                # ファイル・書庫ごとの削除（退避しない）。済んだあとに記録を残す
                changed, remaining, extra = got["changed"], None, {}
                rid = self.store.add_remediation(
                    run.job_id, run.top_path, p["method"], filters, changed, remaining=None, state="applied"
                )
            else:
                rid, remaining = record_id, got["remaining"]
                self.store.update_remediation(
                    rid,
                    changed=got["changed"],
                    remaining=remaining,
                    orig_sha256=got["orig_sha256"],
                    new_sha256=got["new_sha256"],
                )
                committing = True
                outcome = commit_rewrite(self.store, rid, run.top_path, commit, got["orig_sha256"])
                changed = {**got["changed"], "disposal": outcome["disposal"]}
                if outcome.get("pre_name"):
                    changed["pre_name"] = outcome["pre_name"]
                self.store.update_remediation(rid, changed=changed)
                extra = {"converted_to": got.get("converted_to"), "notes": got.get("notes") or []}
            with self._lock:
                # ファイルが変わったので、古い分析は捨てる（同じ書庫の中の別の項目の分析も）
                for k in [
                    k for k, an in self._analyses.items() if an.job_id == run.job_id and an.top_path == run.top_path
                ]:
                    del self._analyses[k]
                run.result = {
                    "remediation_id": rid,
                    "method": p["method"],
                    "method_label": (
                        ARCHIVE_DELETE_LABEL
                        if (a.item_path and p["method"] == "delete_file")
                        else METHOD_LABELS[p["method"]]
                    ),
                    "changed": changed,
                    "remaining": remaining,
                    "file_name": os.path.basename(run.top_path),
                    "item_name": (a.info.get("archive") or {}).get("item", ""),
                    # 元のファイルの行き先: recycle_bin=ごみ箱へ送った（ごみ箱から戻す）／permanent=完全に削除した／
                    # replaced=中身を入れ替えた（元は残らない）。退避の写しは作らないので、このアプリの「元に戻す」は無い
                    "disposal": changed.get("disposal"),
                    "pre_name": changed.get("pre_name"),
                    **extra,
                }
                run.state = "done"
        except RemedyError as e:
            self._abandon(run, commit, record_id, committing)
            run.error, run.state = str(e), "error"
        except Exception as e:  # noqa: BLE001
            self._abandon(run, commit, record_id, committing)
            run.error, run.state = (
                f"実行に失敗しました（{type(e).__name__}）。元のファイルは、名前を変える前なら変わっていません",
                "error",
            )
        finally:
            with self._lock:
                self._busy.discard((run.job_id, run.top_path))

    def _abandon(self, run: RunState, commit: dict | None, record_id: int | None, committing: bool) -> None:
        """元に触る前（確定の前）に失敗した実行の後片付け（一時の新ファイルと、始めた記録を消す）。

        確定の最中（committing）の失敗は、commit_rewrite が元へ戻して記録も整えているので、ここでは何もしない。
        """
        if committing or record_id is None:
            return
        try:
            if commit:
                _discard(commit["tmp_new"])
            self.store.delete_remediation(record_id)
        except Exception:  # noqa: BLE001  片付けの失敗で、本来の失敗の理由を隠さない
            pass

    # ------------------------------------------------------------ 途中で止まった対処の立て直し

    def recover(self, top_path: str | None = None) -> list[dict]:
        """途中で止まったままの対処（アプリが落ちた・電源が切れた）を立て直す。起動時と、同じファイルの対処を始める前に呼ぶ。

        どの状態からでも、元の中身か新しい中身のどちらかが、元の名前（か「対処前」の名前）で必ず残る（recover_record）。
        立て直した内容は記録（対処の記録タブ）に残る。立て直せなかったものは、そのまま残して次の機会に試す。
        """
        return self._recover(top_path, ignore_busy=False)

    def _recover(self, top_path: str | None, ignore_busy: bool) -> list[dict]:
        done: list[dict] = []
        for rec in self.store.unfinished_remediations(top_path):
            with self._lock:
                if not ignore_busy and (rec["job_id"], rec["top_path"]) in self._busy:
                    continue  # いま実行中の対処
            plan = dict(rec.get("plan") or {})
            try:
                state, msg = recover_record(rec)
            except Exception as e:  # noqa: BLE001
                plan["recovery"] = f"立て直せませんでした（{type(e).__name__}: {e}）。ファイルは消していません"
                self.store.update_remediation(rec["id"], note=json.dumps(plan, ensure_ascii=False))
                continue
            plan["recovery"] = msg
            self.store.update_remediation(rec["id"], state=state, note=json.dumps(plan, ensure_ascii=False))
            done.append({"id": rec["id"], "top_path": rec["top_path"], "state": state, "message": msg})
        return done


def row_label(layout: str, sheet: str, key: int, schema: dict | None = None) -> str:
    """下見に出す「変わる行」の呼び名（Excel・csv は行番号、SQLite は rowid、SQL のダンプは行番号・何組目か、
    PDF はページと行、docx は部品と段落の番号、pptx はスライドと段落の番号）。"""
    if layout == "pdf":
        return f"{sheet} {key} 行目"
    if layout == "docx":
        return f"{docx_part_label(sheet)} 段落 {key}"
    if layout == "pptx":
        from .ooxml_text import split_pptx_sheet

        return f"{split_pptx_sheet(sheet)[0]} 段落 {key}"
    if layout == "sqldump":
        from .formats.dbdump import ROW_KEY_SHIFT

        line, n = key >> ROW_KEY_SHIFT, key & ((1 << ROW_KEY_SHIFT) - 1)
        return f"{sheet}: {line} 行目" if n == 0 else f"{sheet}: {line} 行目〜の {n} 組目"
    if layout == "sqlite":
        info = ((schema or {}).get("tables") or {}).get(sheet)
        if info is not None and not info.get("has_rowid", True):
            return f"{sheet}: {key} 行目"
        return f"{sheet}: rowid {key}"
    return f"{sheet}!{key}" if sheet else str(key)


def docx_part_label(part: str) -> str:
    """docx の部品名の呼び方（下見に出す）。"""
    leaf = part.rsplit("/", 1)[-1].lower()
    for head, label in (
        ("document", "本文"),
        ("header", "ヘッダー"),
        ("footer", "フッター"),
        ("footnotes", "脚注"),
        ("endnotes", "文末脚注"),
        ("comments", "コメント"),
    ):
        if leaf.startswith(head):
            return label
    return part


def _page_of(sheet: str) -> int:
    import re

    m = re.match(r"^(\d+)ページ", sheet)
    return int(m.group(1)) if m else 0


def office_preview(
    layout: str, method: str, sel: Selection, p: dict, out: dict, sample: list[str], password_opened: bool
) -> dict:
    """PDF・docx・pptx の下見（変わる数・注意）を out に書き、changes を返す。何も書き換えない。値は含めない。"""
    from .ooxml_text import CODE_COL_MASK, CODE_ROW_MASK, CODE_ROW_SHIFT, CODE_TBL_SHIFT, split_pptx_sheet

    spans = set()  # 同じ場所を2通りの読み方で拾った検出（本文として・表の列見出しつき）を1つに数える
    cells = set()
    for (sheet, _t, _r), arr in sel.groups.items():
        for i in range(0, len(arr), 4):
            spans.add((sheet, arr[i], arr[i + 2], arr[i + 3]))
            cells.add((sheet, arr[i], arr[i + 1]))
    changes: dict = {"detections": len(spans)}
    notes = out["warnings"]
    props = (
        "文書のプロパティ（作成者・題など）・属性値・グラフなどの文字に、消した値や選んだ種類・確度の検出が残っていれば、それも取り除きます。"
        "文書の縮小画像（サムネイル）は、元の画面が写っているため取り除きます"
    )
    if layout == "pdf":
        pages = sorted({_page_of(k[0]) for k in sel.groups})
        ocr = any("OCR" in k[0] for k in sel.groups)
        if method == "redact":
            changes["pages"] = len(pages)
            out["summary"] = (
                f"{len(pages)} ページの検出 {len(spans):,} 件を黒塗りします（文字そのものを取り除きます。元に戻せません）"
            )
            notes.append(
                "黒塗りは、見た目だけを隠す注釈ではなく、ページの内容から文字そのものを取り除きます（黒い四角が残ります）。"
                "元に戻せません。コピーしても、文字の抽出をしても、値は出てきません"
            )
            if ocr:
                notes.append(
                    "画像の中の文字を OCR で読んだ検出は、画像のその部分の画素を黒く塗りつぶします"
                    "（OCR の位置は近似なので、少し広めに塗ります）"
                )
        else:
            changes["pages_removed"] = len(pages)
            out["summary"] = f"{len(pages)} ページを削除します: " + "、".join(str(n) for n in pages)
            notes.append(
                "削除したページの文字・画像は、ファイルに残りません（保存し直して、使われなくなった部品も取り除きます）"
            )
        notes.append(
            "文書情報（作成者・題など）・XMP・注釈・フォーム欄・しおり・リンク・埋め込みファイルに、消した値や選んだ種類・確度の検出が"
            "残っていれば、それも取り除きます"
        )
        notes.append(
            "PDF を保存し直します（増分保存にしないので、消した文字が古い版として残りません。ファイルの内部の作りは変わります）"
        )
        if password_opened:
            notes.append("パスワードつきの PDF です。検査のとき入れたパスワードで、同じ方式に暗号化し直して保存します")
        return changes
    if layout == "pptx":
        slides = sorted(
            {int(split_pptx_sheet(k[0])[0].replace("スライド", "").split("（")[0] or 0) for k in sel.groups}
        )
        if method == "delete_slides":
            changes["slides"] = len(slides)
            out["summary"] = f"{len(slides)} 枚のスライドを削除します: " + "、".join(str(n) for n in slides)
            notes.append(
                "スライドに使われていた画像・グラフ・埋め込み・ノートのうち、ほかのスライドで使われていないものも取り除きます。"
                "ほかのスライドからそのスライドへのリンクは外します。スライドの題の一覧（文書のプロパティ）も取り除きます"
            )
        else:
            changes["cells"] = len(cells)
            out["summary"] = (
                f"{len(cells):,} 個の段落の検出した値 {len(spans):,} 件を置き換えます（{DUMMY_MODES[p['dummy_mode']]}）"
            )
            notes.append("置き換えた文字の書式は、値の最初の文字の書式に合わせます。ノートの中の検出も対象です")
        notes.append(props)
        return changes
    # docx
    paras = {(k, r) for k, r, _c in cells}
    if method == "dummy":
        changes["cells"] = len(paras)
        out["summary"] = (
            f"{len(paras):,} 個の段落（表のセル・ヘッダー・フッター・脚注・コメント・テキストボックスの中を含む）の検出した値 "
            f"{len(spans):,} 件を置き換えます（{DUMMY_MODES[p['dummy_mode']]}）"
        )
        notes.append(
            "値が複数の文字の塊（run）に割れていても置き換えます。置き換えた文字の書式は、値の最初の文字の書式に合わせます。"
            "変更履歴（削除した文字・挿入した文字）やフィールドの命令の中の値も置き換えます"
        )
    elif method == "delete_paragraphs":
        changes["paragraphs"] = len(paras)
        out["summary"] = f"{len(paras):,} 個の段落を削除します（検出 {len(spans):,} 件を含む段落）"
        notes.append(
            "表のセル・テキストボックス・脚注などの最後の1つの段落、節の区切りを持つ段落は、取り除かずに中身を空にします"
        )
    else:
        rows, cols, outside = set(), set(), 0
        for sheet, row, code in cells:
            if not code:
                outside += 1
                continue
            tbl, r, c = code >> CODE_TBL_SHIFT, (code >> CODE_ROW_SHIFT) & CODE_ROW_MASK, code & CODE_COL_MASK
            rows.add((sheet, tbl, r))
            cols.add((sheet, tbl, c))
        if method == "delete_rows":
            changes["rows"] = len(rows)
            out["summary"] = f"表の {len(rows):,} 行を削除します（検出を含む行）"
            notes.append(
                "結合したセル（縦に結合）を含む行を消すと、表の見た目が崩れることがあります。行が全部なくなった表は、表ごと取り除きます"
            )
        else:
            changes["cols"] = len(cols)
            out["summary"] = f"表の {len(cols):,} 列を削除します（検出を含む列）"
            notes.append(
                "結合したセル（複数の列にまたがるセル）に検出があるときは、列を削除できません。列の幅は変わりません。列が全部なくなった表は、表ごと取り除きます"
            )
        if outside:
            notes.append(
                f"表の外にある検出（{outside:,} 箇所の段落）は、行・列の削除では変わりません。段落の削除かダミー化を選んでください"
            )
        if not rows:
            raise RemedyError("選んだ種類・確度の検出が、表の中にありません")
    notes.append(props)
    return changes


def col_label(layout: str, sheet: str, idx0: int, schema: dict | None = None) -> str:
    """下見に出す「変わる列」の呼び名（Excel は列の文字、DB は列名か何番目か）。"""
    if layout in DB_LAYOUTS:
        cols = (((schema or {}).get("tables") or {}).get(sheet) or {}).get("columns") or []
        return f"{sheet}.{cols[idx0]}" if idx0 < len(cols) else f"{sheet} の {idx0 + 1} 番目の列"
    return f"{sheet}!{_letters(idx0)}" if sheet else _letters(idx0)


def _key_columns(info: dict, cols: list, idxs, kinds: tuple) -> list[str]:
    """選んだ列のうち、主キー・一意の索引・外部キーなど（kinds のキー）に使われているものの名前。"""
    names = []
    for i in sorted(idxs):
        if i < len(cols) and any(cols[i] in (info.get(k) or []) for k in kinds):
            names.append(cols[i])
    return names


def db_warnings(layout: str, method: str, sel: Selection, schema: dict) -> list[str]:
    """SQLite・SQL のダンプの下見の注意（値は含めない）。"""
    out: list[str] = []
    tables = (schema or {}).get("tables") or {}
    if layout == "sqlite":
        out.append(
            "元のファイルは書き換えず、写しに SQL を当てて作ります。終わりに VACUUM（空き領域も詰める）をかけ、"
            "消した値がファイルの空きに残らないようにします（ファイルは小さくなることがあります）"
        )
        out.append(
            "外部キーの連鎖削除は動かしません。その表のトリガーは書き換えの間だけ外し、終わりに元の定義で作り直します"
        )
        for t in sel.sheets():
            info = tables.get(t) or {}
            by = "、".join(info.get("referenced_by") or [])
            if method == "delete_rows" and by:
                out.append(
                    f"表「{t}」は、ほかの表（{by}）が外部キーで参照しています。行を消すと、参照先が無くなる行ができます"
                )
            if method == "delete_table":
                extra = []
                if info.get("indexes"):
                    extra.append(f"索引 {info['indexes']} 個")
                if info.get("triggers"):
                    extra.append(f"トリガー {info['triggers']} 個")
                tail = f"。表に付いている{'・'.join(extra)}も一緒に消えます" if extra else ""
                out.append(f"表「{t}」のデータはすべて消えます（検出した行だけではありません）{tail}")
                if by:
                    out.append(f"表「{t}」は、ほかの表（{by}）が外部キーで参照しています")
                if info.get("dependents"):
                    out.append(
                        f"表「{t}」を使うビュー・トリガー（{'、'.join(info['dependents'])}）は、あとで動かなくなります"
                    )
        if method == "delete_columns":
            for t, idxs in sel.cols().items():
                info = tables.get(t) or {}
                cols = info.get("columns") or []
                for i in sorted(idxs):
                    if i >= len(cols):
                        continue
                    name = cols[i]
                    why = []
                    if name in (info.get("pk") or []):
                        why.append("主キー")
                    if name in (info.get("unique") or []):
                        why.append("一意の索引")
                    elif name in (info.get("indexed") or []):
                        why.append("索引")
                    if name in (info.get("fk_from") or []) or name in (info.get("referenced") or []):
                        why.append("外部キー")
                    deps = (info.get("col_deps") or {}).get(name)
                    if deps:
                        why.append(f"ビュー・トリガー（{'、'.join(deps)}）")
                    if why:
                        out.append(
                            f"表「{t}」の列「{name}」は{'・'.join(why)}に使われているため、SQLite が削除を断ることがあります"
                            "（断られたら何も変わりません）"
                        )
        if method == "dummy":
            for t, idxs in sel.cols().items():
                info = tables.get(t) or {}
                keyed = _key_columns(info, info.get("columns") or [], idxs, ("pk", "unique", "fk_from", "referenced"))
                if keyed:
                    out.append(
                        f"表「{t}」の列（{'、'.join(keyed)}）は主キー・一意の索引・外部キーに使われています。置き換えると、"
                        "ほかの表との突き合わせが壊れたり、一意の制約で失敗したりすることがあります（失敗したら何も変わりません）"
                    )
        out.append(
            "-wal・-shm・-journal の付属ファイルが元のファイルのそばにあるときは、他のプログラムが開いている可能性があるため実行を断ります"
        )
    else:
        out.append(
            "SQL のダンプを1行ずつ読みながら新しいファイルへ書きます。触らない行は元のバイト列のまま写し、文字コード・改行も元のままです"
        )
        if method == "delete_rows":
            out.append(
                "COPY のデータ行と、INSERT 文の VALUES の1組（1行）を取り除きます。組がすべて無くなった INSERT 文は文ごと消えます"
            )
        elif method == "delete_columns":
            out.append(
                "COPY の列・INSERT の列名と値・CREATE TABLE の列の定義を取り除きます。その列を使う索引・制約の文（CREATE INDEX・"
                "ALTER TABLE … ADD CONSTRAINT・列のコメント）も取り除きます。ほかの表の外部キーがその列を参照している場合は、読み込み時に失敗します"
            )
        elif method == "dummy":
            out.append("INSERT の値は、元の引用符・エスケープの流儀で書き直します（数値だった値は文字列になります）")
        elif method == "delete_table":
            out.append(
                "CREATE TABLE・COPY のブロック・INSERT 文・DROP TABLE・LOCK TABLES・索引・制約・権限・コメントなど、その表の文を取り除きます。"
                "表のデータはすべて消えます（検出した行だけではありません）。ほかの表の外部キーがその表を参照している場合は、読み込み時に失敗します"
            )
        out.append(
            "pg_dump のカスタム形式・ディレクトリ形式、Oracle のダンプは、いまはファイルの削除だけです（平文の SQL のみ対応）"
        )
    return out


def _letters(idx0: int) -> str:
    from openpyxl.utils import get_column_letter

    return get_column_letter(idx0 + 1)

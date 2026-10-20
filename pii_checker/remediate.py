"""検出した個人情報への対処（T2-a: 土台・ファイルの削除・csv/tsv/txt・xlsx/xlsm）。

決まり:
- 対処は、人が画面で選んで実行したときだけ。検査（scan）は何も書き込まない。自動では何もしない。
- 対象は「実行の時点でファイルを読み直して集めた、全部の検出の位置」（明細の上限 20 件ではない）。
  位置の集め直しと書き換えは別プロセス（検査と同じ pebble・メモリ上限・時間制限）で行う。生の値は位置に入れない。
- 流れ: 分析（位置を集める）→ 選ぶ → 下見（変わる行・列・シートの数）→ 実行。
  実行は (1) 元のファイルを退避の場所へ写して SHA-256 を確かめる (2) 同じフォルダに一時の名前で新しいファイルを書く
  (3) os.replace で置き換える (4) そのファイルを検査し直して、残った検出の数を返す (5) 記録（生の値は書かない）。
  途中で失敗したときは元のファイルを変えない。
- 「元に戻す」: 退避の写しを元の場所へ戻す。今のファイルが対処の直後から変わっていれば、上書きせずに断る。
- 「ファイルを削除」はごみ箱へ送る（SHFileOperationW）。送る前にも退避へ写す。
"""

from __future__ import annotations

import ctypes
import multiprocessing
import os
import shutil
import threading
import time
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import replace
from pathlib import Path

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
    "delete_file": "ファイルを削除（ごみ箱へ送る）",
    "delete_rows": "該当する行を削除",
    "delete_columns": "該当する列を削除",
    "dummy": "ダミー化（該当する値だけを置き換える）",
    "delete_sheet": "該当するシートを削除",
}
CONF_RANKS = {"high": 3, "medium": 2, "low": 1}
RANK_LABELS = {3: "高", 2: "中", 1: "低"}
ANALYSIS_KEEP_SECONDS = 600  # 分析（位置の集まり）をメモリに持つ時間
MAX_ANALYSES = 4
MAX_RUNS_KEPT = 20
SAMPLE_ROWS = 20  # 下見に出す、変わる行の番号の数
TMP_SUFFIX = ".piichk-tmp"
FILE_ATTRIBUTE_READONLY = 0x1
# 形式（検査のときに決まる位置の意味）ごとに、できる方法
LAYOUT_METHODS = {
    "csv": ("delete_rows", "delete_columns", "dummy"),
    "lines": ("delete_rows", "dummy"),
    "xlsx": ("delete_rows", "delete_columns", "dummy", "delete_sheet"),
}
XLSX_EXTS = (".xlsx", ".xlsm")
# 退避の置き場を環境変数で変える（試験・特別な運用用。設定の画面は無い）
BACKUP_ENV = "PII_CHECKER_BACKUP_DIR"


def default_backup_root() -> str:
    """退避の置き場の既定（%LOCALAPPDATA%\\個人情報チェッカー\\退避）。環境変数 PII_CHECKER_BACKUP_DIR で変えられる。"""
    env = os.environ.get(BACKUP_ENV)
    if env:
        return env
    base = os.environ.get("LOCALAPPDATA") or str(Path.home())
    return str(Path(base) / "個人情報チェッカー" / "退避")


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
    op = SHFILEOPSTRUCTW()
    op.hwnd = None
    op.wFunc = FO_DELETE
    op.pFrom = abs_path + "\0"  # 二重の NUL で終える（ctypes が文字列の終わりにもう1つ付ける）
    op.pTo = None
    op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI
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


# ---------------------------------------------------------------- 退避


def _long(path: str) -> str:
    from .engine import long_path

    return long_path(path)


def make_backup(path: str, backup_dir: str) -> tuple[str, str]:
    """元のファイルを退避の場所へ写し、写しの SHA-256 が元と同じことを確かめる。（退避先のパス, SHA-256）を返す。"""
    os.makedirs(_long(backup_dir), exist_ok=True)
    dest = os.path.join(backup_dir, os.path.basename(path))
    try:
        before = sha256_file(path)
        shutil.copy2(_long(path), _long(dest))
        after = sha256_file(dest)
    except OSError as e:
        _discard(dest)
        _rmdir_quiet(backup_dir)
        raise RemedyError(f"元のファイルを退避の場所へ写せませんでした（{e}）。何も変えていません") from None
    if before != after:
        _discard(dest)
        _rmdir_quiet(backup_dir)
        raise RemedyError(
            "退避の写しが元のファイルと一致しませんでした（写している間に元が変わった可能性）。何も変えていません"
        )
    return dest, before


def _discard(path: str) -> None:
    """自分が作った一時のファイルを消す（無ければ何もしない）。"""
    try:
        os.remove(_long(path))
    except OSError:
        pass


def _rmdir_quiet(path: str) -> None:
    try:
        os.rmdir(_long(path))
    except OSError:
        pass


def new_backup_dir(root: str, job_id: str) -> str:
    """退避先のフォルダ名（<root>\\<ジョブ ID>\\<時刻>）。同じ秒に重なったら番号を足す。"""
    base = os.path.join(root, job_id, time.strftime("%Y%m%d-%H%M%S"))
    cand, n = base, 1
    while os.path.exists(_long(cand)):
        n += 1
        cand = f"{base}-{n}"
    return cand


def replace_with_retry(src: str, dst: str, tries: int = 5) -> None:
    """os.replace。他のプログラムが開いていて置き換えられないときは、少し待って数回試す。"""
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


def collect_task(args: dict) -> dict:
    """ファイルを読み直して、構造の位置を全部集める（別プロセスで動く）。生の値は返さない。"""
    from .engine import scan_file

    options = replace(args["options"], collect_positions=True, reveal=False)
    result = scan_file(args["path"], options, args.get("book") or PasswordBook())
    top = _top_item(result, args["path"])
    if result.source is None or top is None:
        reason = result.items[0].reason if result.items else ""
        raise RemedyError(f"元のファイルを読めませんでした: {reason}" if reason else "元のファイルを読めませんでした")
    others = sum(sum(it.finding_counts.values()) for it in result.items if it is not top)
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
    """対処を実行する（別プロセスで動く）。退避 → 新しいファイルを書く → 置き換え → 検査し直し。

    args: path・method・options（検査の設定）・backup_dir・types・ranks・sheets・dummy_mode・expected_sha256
    戻り値: 変わった数・退避先・元と新の SHA-256・残った検出の数。失敗は RemedyError（元のファイルは変えない）。
    """
    path = args["path"]
    method = args["method"]
    if not os.path.isfile(_long(path)):
        raise RemedyError("ファイルが見つかりません（移動・削除された可能性）")
    if method == "delete_file":
        backup, sha = make_backup(path, args["backup_dir"])
        try:
            send_to_recycle_bin(path)
        except RemedyError:
            _discard(backup)
            _rmdir_quiet(os.path.dirname(backup))
            raise
        if os.path.exists(_long(path)):
            _discard(backup)
            _rmdir_quiet(os.path.dirname(backup))
            raise RemedyError("ごみ箱へ送ったはずのファイルが残っています。元のファイルは変えていません")
        return {
            "changed": {"files": 1},
            "backup_path": backup,
            "orig_sha256": sha,
            "new_sha256": None,
            "remaining": None,
        }

    # 実行の時点でファイルを読み直して、位置を集める
    got = collect_task({"path": path, "options": args["options"]})
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
    backup, orig_sha = make_backup(path, args["backup_dir"])
    tmp = path + TMP_SUFFIX
    try:
        if got["layout"] == "xlsx":
            stats = rewrite_xlsx_file(path, tmp, method, sel, maker, keep_vba=path.lower().endswith(".xlsm"))
        else:
            stats = rewrite_text_file(path, tmp, got["layout"], method, sel, maker)
        if sha256_file(path) != orig_sha:
            raise RemedyError("書き換えている間に元のファイルが変わりました。何も変えていません")
        replace_with_retry(tmp, path)
    except BaseException:
        _discard(tmp)
        _discard(backup)
        _rmdir_quiet(os.path.dirname(backup))
        raise
    new_sha = sha256_file(path)
    remaining = None
    try:
        remaining = rescan_summary(path, args["options"], args, sorted(maker.produced) if maker else [])
    except Exception:  # noqa: BLE001  書き換えは済んでいる。検査し直せなかっただけなので、残りは「不明」にして返す
        remaining = None
    return {
        "changed": stats,
        "backup_path": backup,
        "orig_sha256": orig_sha,
        "new_sha256": new_sha,
        "remaining": remaining,
    }


def rescan_summary(path: str, options: ScanOptions, args: dict, dummies: list[str] | None = None) -> dict:
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
    result = scan_file(path, options, PasswordBook())
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
    return {
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
    status = info.get("status")
    if status == Status.NEEDS_PASSWORD.value:
        return "パスワードが必要な（暗号化された）ファイルは、中身を書き換えられません。ファイルの削除はできます"
    if status != Status.SCANNED.value:
        return "中身を最後まで構造どおりに読めなかったファイルは、位置が分からないため中身を書き換えられません。ファイルの削除はできます"
    layout = info.get("layout") or ""
    family = "csv" if layout.startswith("csv") else layout
    if family not in LAYOUT_METHODS:
        return "この形式の中身の書き換えには、まだ対応していません（対応: csv・tsv・txt・xlsx・xlsm）。ファイルの削除はできます"
    if family == "xlsx" and not path.lower().endswith(XLSX_EXTS):
        return "xlsx・xlsm 以外の Excel 形式は、中身を書き換えられません。ファイルの削除はできます"
    if info.get("overflow"):
        return "検出が多すぎて（200 万件超）位置を最後まで集められませんでした。ファイルの削除はできます"
    if method not in LAYOUT_METHODS[family]:
        return "この形式では選べない方法です"
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

    def __init__(self, job_id: str, top_path: str):
        self.job_id = job_id
        self.top_path = top_path
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
        sheets = sorted({k[0] for k in self.positions if k[0]})
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
    """分析・下見・実行・元に戻すの窓口。重い処理は別プロセス（runner_fn）。"""

    def __init__(self, store, backup_root: str | None = None, runner_fn=None):
        self.store = store
        self.backup_root = backup_root or default_backup_root()
        self._runner_fn = runner_fn or _run_in_process
        self._lock = threading.Lock()
        self._analyses: dict[tuple[str, str], Analysis] = {}
        self._runs: dict[str, RunState] = {}
        self._busy: set[tuple[str, str]] = set()  # 実行中のファイル（同じファイルを同時に対処しない）
        self._slots = threading.Semaphore(1)

    # ------------------------------------------------------------ 分析

    def request_analysis(self, job_id: str, top_path: str) -> dict:
        """分析を始める（結果がメモリにあれば使い回す）。いまの状態を返す。始める前に分かる理由は error で返す。"""
        key = (job_id, top_path)
        with self._lock:
            self._purge()
            a = self._analyses.get(key)
            if a is not None:
                return a.view()
            try:
                plan = self._plan(job_id, top_path)
            except RemedyError as e:
                return {"state": "error", "message": str(e)}
            a = self._analyses[key] = Analysis(job_id, top_path)
            a.size = plan["size"]
        threading.Thread(target=self._analyze, args=(a, plan), daemon=True, name="pii-remedy-analyze").start()
        return a.view()

    def get_analysis(self, job_id: str, top_path: str) -> Analysis:
        with self._lock:
            self._purge()
            a = self._analyses.get((job_id, top_path))
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

    def _plan(self, job_id: str, top_path: str) -> dict:
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
        return {"options": options, "size": size, "timeout": timeout, "roots": job["roots"]}

    def _analyze(self, a: Analysis, plan: dict) -> None:
        try:
            with self._slots:
                got = self._runner_fn("collect", {"path": a.top_path, "options": plan["options"]}, plan["timeout"])
            a.positions = got["positions"]
            methods = {}
            for m in METHOD_LABELS:
                reason = unsupported_reason(m, a.top_path, got)
                methods[m] = {"label": METHOD_LABELS[m], "available": not reason, "reason": reason}
            a.info = {
                "layout": got["layout"],
                "kind": got["kind"],
                "sha256": got["source"].get("sha256"),
                "size": a.size,
                "methods": methods,
                "other_findings": got["other_findings"],
                "dummy_modes": DUMMY_MODES,
                "recycle_bin": has_recycle_bin(a.top_path),
                "backup_root": self.backup_root,
            }
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
        if method not in METHOD_LABELS:
            raise RemedyError("方法が正しくありません")
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
        }
        if method != "delete_file" and not select_from_args(a.positions, out).detections:
            raise RemedyError("選んだ種類・確度の検出がありません")
        return out

    def preview(self, job_id: str, top_path: str, params: dict) -> dict:
        """変わる行・列・シートの数と例、注意を返す（何も書き換えない）。"""
        a = self.get_analysis(job_id, top_path)
        p = self.normalize(a, params)
        method = p["method"]
        leaf = os.path.basename(top_path)
        out = {
            "method": method,
            "method_label": METHOD_LABELS[method],
            "file_name": leaf,
            "backup_root": self.backup_root,
            "warnings": [],
            "expected_sha256": a.info.get("sha256"),
        }
        if method == "delete_file":
            out["changes"] = {"files": 1}
            out["summary"] = f"ファイル「{leaf}」をごみ箱へ送ります"
            if not a.info.get("recycle_bin", True):
                out["warnings"].append(
                    "この場所（ネットワーク・外付けなど）にはごみ箱が無いため、ごみ箱を経由せずに消えます。"
                    "退避の写しは残るので、「元に戻す」で戻せます"
                )
            out["can_run"] = True
            return out
        sel = select_from_args(a.positions, p)
        layout = a.info["layout"]
        rows, cols = sel.rows(), sel.cols()
        n_rows = sum(len(v) for v in rows.values())
        n_cols = sum(len(v) for v in cols.values())
        sample: list[str] = []
        for sheet in sorted(rows):
            for r in sorted(rows[sheet])[: SAMPLE_ROWS - len(sample)]:
                sample.append(f"{sheet}!{r}" if sheet else str(r))
            if len(sample) >= SAMPLE_ROWS:
                break
        changes: dict = {"detections": sel.detections}
        if method == "delete_rows":
            changes["rows"] = n_rows
            out["summary"] = f"{n_rows:,} 行を削除します（検出 {sel.detections:,} 件を含む行）"
            out["sample_rows"] = sample
            if any(1 in v for v in rows.values()):
                out["warnings"].append("1 行目（見出し行の可能性）も削除されます")
        elif method == "delete_columns":
            changes["cols"] = n_cols
            letters = [f"{s}!{_letters(c)}" if s else _letters(c) for s in sorted(cols) for c in sorted(cols[s])]
            out["summary"] = f"{n_cols:,} 列を削除します（検出 {sel.detections:,} 件を含む列）"
            out["sample_cols"] = letters[:SAMPLE_ROWS]
        elif method == "dummy":
            changes["cells"] = sel.cell_count()
            what = "行" if layout == "lines" else "セル"
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
        out["changes"] = changes
        if layout == "xlsx" and method != "dummy":
            out["warnings"].extend(XLSX_WARNINGS)
        if layout.startswith("csv") or layout == "lines":
            out["warnings"].append("文字コード・BOM・改行・区切り・引用符の付け方は元のまま保ちます")
        if a.info.get("other_findings"):
            out["warnings"].append(
                f"このファイルには、行・列の位置を持たない検出（コメント・内側のファイル・ファイル名など）も {a.info['other_findings']:,} 件あります。"
                "それらはこの対処では変わらず、実行のあとの検査し直しで残りとして出ます"
            )
        out["can_run"] = True
        return out

    # ------------------------------------------------------------ 実行

    def start_run(self, job_id: str, top_path: str, params: dict, confirmed: bool, expected_sha256: str | None) -> dict:
        """対処の実行を始める（確認済みのときだけ）。run_id を返し、画面は状態を見に来る。"""
        if confirmed is not True:
            raise RemedyError("確認の操作が必要です")
        a = self.get_analysis(job_id, top_path)
        p = self.normalize(a, params)
        plan = self._plan(job_id, top_path)  # 実行の時点でも前提（ファイルの有無・読み取り専用）を確かめる
        from .safeio import output_inside_roots

        msg = output_inside_roots(self.backup_root, plan["roots"], "退避の置き場")
        if msg:
            raise RemedyError(msg)
        key = (job_id, top_path)
        with self._lock:
            if key in self._busy:
                raise RemedyError("このファイルは、いま別の対処を実行中です")
            self._busy.add(key)
            rid = f"{int(time.time() * 1000)}-{len(self._runs)}"
            run = self._runs[rid] = RunState(job_id, top_path, p["method"])
        args = {
            "path": top_path,
            "method": p["method"],
            "options": plan["options"],
            "backup_dir": new_backup_dir(self.backup_root, job_id),
            "types": p["types"],
            "ranks": p["ranks"],
            "sheets": p["sheets"],
            "dummy_mode": p["dummy_mode"],
            "expected_sha256": expected_sha256 or a.info.get("sha256"),
        }
        run.thread = threading.Thread(
            target=self._apply, args=(run, a, args, p, plan["timeout"]), daemon=True, name="pii-remedy-apply"
        )
        run.thread.start()
        return {"run_id": rid, **run.view()}

    def run_status(self, job_id: str, run_id: str) -> dict:
        with self._lock:
            run = self._runs.get(run_id)
        if run is None or run.job_id != job_id:
            raise RemedyError("その実行は見つかりません")
        return run.view()

    def _apply(self, run: RunState, a: Analysis, args: dict, p: dict, timeout: int) -> None:
        try:
            with self._slots:
                got = self._runner_fn("apply", args, timeout * 2)
            filters = {k: p[k] for k in ("types", "ranks", "sheets", "dummy_mode")}
            rid = self.store.add_remediation(
                run.job_id,
                run.top_path,
                p["method"],
                filters,
                got["changed"],
                remaining=got["remaining"],
                backup_path=got["backup_path"],
                orig_sha256=got["orig_sha256"],
                new_sha256=got["new_sha256"],
            )
            with self._lock:
                self._analyses.pop((run.job_id, run.top_path), None)  # ファイルが変わったので、古い分析は捨てる
                run.result = {
                    "remediation_id": rid,
                    "method": p["method"],
                    "method_label": METHOD_LABELS[p["method"]],
                    "changed": got["changed"],
                    "remaining": got["remaining"],
                    "backup_path": got["backup_path"],
                    "file_name": os.path.basename(run.top_path),
                }
                run.state = "done"
        except RemedyError as e:
            run.error, run.state = str(e), "error"
        except Exception as e:  # noqa: BLE001
            run.error, run.state = (
                f"実行に失敗しました（{type(e).__name__}）。元のファイルは、置き換える前なら変わっていません",
                "error",
            )
        finally:
            with self._lock:
                self._busy.discard((run.job_id, run.top_path))

    # ------------------------------------------------------------ 元に戻す

    def undo(self, job_id: str, rid: int) -> dict:
        """退避の写しを元の場所へ戻す。今のファイルが対処の直後から変わっていれば、上書きせずに断る。"""
        rec = self.store.remediation(job_id, rid)
        if rec is None:
            raise RemedyError("その対処の記録が見つかりません")
        if rec["state"] != "applied":
            raise RemedyError("この対処は、すでに元に戻しています")
        path, backup = rec["top_path"], rec["backup_path"]
        if not backup or not os.path.isfile(_long(backup)):
            raise RemedyError("退避の写しが見つかりません（退避の置き場から消えた可能性）。戻せません")
        if sha256_file(backup) != rec["orig_sha256"]:
            raise RemedyError("退避の写しが、対処の前の中身と一致しません（壊れた・書き換えられた可能性）。戻しません")
        exists = os.path.exists(_long(path))
        if rec["method"] == "delete_file":
            if exists:
                raise RemedyError(
                    "同じ場所にファイルがあるため、上書きせずに断りました。そのファイルを移してから戻してください"
                )
        elif exists and sha256_file(path) != rec["new_sha256"]:
            raise RemedyError(
                "対処のあとにファイルが変わっているため、上書きせずに断りました（退避の写しは残してあります）"
            )
        folder = os.path.dirname(path)
        if not os.path.isdir(_long(folder)):
            raise RemedyError("元のフォルダが見つかりません。フォルダを作り直してから戻してください")
        tmp = path + TMP_SUFFIX
        try:
            shutil.copy2(_long(backup), _long(tmp))
            if sha256_file(tmp) != rec["orig_sha256"]:
                raise RemedyError("戻す途中の写しが一致しませんでした。何も変えていません")
            replace_with_retry(tmp, path)
        except BaseException:
            _discard(tmp)
            raise
        self.store.mark_remediation_restored(rid)
        return {"ok": True, "restored_path": path, "message": f"元に戻しました: {os.path.basename(path)}"}


def _letters(idx0: int) -> str:
    from openpyxl.utils import get_column_letter

    return get_column_letter(idx0 + 1)

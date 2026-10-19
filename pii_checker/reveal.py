"""画面の詳細のために、検出した値そのものを得る（元のファイルを読み直す）。

決まり:
- ジョブの DB・Excel/CSV レポートには伏せた値だけを残す。ここで得る生の値は、メモリの中だけで画面へ返す
  （DB・ファイル・ログ・一時ファイル・途中経過のどこにも書かない）。
- 読み直しは検査と同じ engine.scan_file を、別プロセス（時間制限・メモリ上限つき）で reveal=True にして走らせる。
- 読み直した明細と DB の明細を（項目のパス・種類・場所・伏せた値）で突き合わせ、DB の行 ID ごとに生の値を返す。
  突き合わない明細（検査の後にファイルが変わった等）は返さない（画面は「表示できない」とする）。
- 同じファイルの結果は短時間（REVEAL_CACHE_SECONDS）だけメモリに持って使い回す。
"""

from __future__ import annotations

import multiprocessing
import os
import threading
import time
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import replace

from .models import PasswordBook, ScanOptions, Status
from .procguard import plan_workers, worker_init
from .remote import ConnectError, Connection, is_ftp_path

REVEAL_CACHE_SECONDS = 600  # 同じファイルの読み直しの結果をメモリに持つ時間（10 分）
MAX_CACHE_ENTRIES = 30  # 持つ件数の上限（超えたら古いものから捨てる）
MAX_CONCURRENT = 2  # 同時に読み直す数（超えた分は順番を待つ）
# 読み直しの時間制限（秒）。検査と同じ考え方で、最低限と、大きさを遅い読み取り速度で割った時間の長いほう
MIN_TIMEOUT = 10 * 60
MAX_TIMEOUT = 4 * 60 * 60
BYTES_PER_SEC = 512 * 1024
ERROR_KEEP_SECONDS = 10  # 失敗の結果を覚えておく時間（画面が見に来るまで。すぐ開き直せば読み直す）
# これ以上大きいファイルは、画面に時間がかかる旨を出す（API が返す）
BIG_FILE_BYTES = 50 * 1024**2


def _reveal_task(path: str, options: ScanOptions, book: PasswordBook) -> dict:
    """別プロセスで動く。scan_file を reveal=True で走らせ、画面に返す分だけを素朴な形で返す。"""
    from .engine import scan_file

    result = scan_file(path, options, book)
    findings = []
    for it in result.items:
        for f in it.findings:
            findings.append((it.path, f.pii_type, f.location, f.masked_value, f.raw_value, f.raw_context))
    items = [(it.path, it.status.value, it.reason) for it in result.items]
    return {"findings": findings, "items": items, "source": result.source}


def _run_in_process(path: str, options: ScanOptions, book: PasswordBook, timeout: int) -> dict:
    """読み直しを別プロセス（検査と同じ pebble・メモリ上限）で走らせる。失敗は RevealUnavailable。"""
    from pebble import ProcessPool
    from pebble.common import ProcessExpired

    _, memory_limit = plan_workers(1)
    ctx = multiprocessing.get_context("spawn")
    try:
        with ProcessPool(
            max_workers=1, max_tasks=1, context=ctx, initializer=worker_init, initargs=(memory_limit,)
        ) as pool:
            future = pool.schedule(_reveal_task, args=(path, options, book), timeout=timeout)
            return future.result()
    except (FutureTimeout, TimeoutError):
        raise RevealUnavailable(
            f"読み直しが時間制限（{timeout // 60} 分）を超えたため打ち切りました。大きなファイルは表示できないことがあります"
        ) from None
    except ProcessExpired:
        raise RevealUnavailable(
            "読み直しの途中でプロセスが終了しました（メモリ不足・壊れたファイルの可能性）"
        ) from None


class RevealUnavailable(Exception):
    """読み直せない（理由は利用者向けの日本語）。"""


class RevealEntry:
    """1ファイルの読み直しの状態と結果（メモリの中だけ）。"""

    def __init__(self) -> None:
        self.state = "running"  # running / done / error
        self.started = time.time()
        self.finished = 0.0
        self.error = ""
        self.result: dict | None = None

    def view(self) -> dict:
        if self.state == "done":
            return {"state": "done", **(self.result or {})}
        if self.state == "error":
            return {"state": "error", "message": self.error}
        return {"state": "running", "elapsed": round(time.time() - self.started, 1)}


class RevealService:
    """読み直しの実行・同時数の制限・結果のメモリでの使い回し。"""

    def __init__(self, store, registry, runner_fn=None):
        self.store = store
        self.registry = registry
        # 別プロセスで走らせる関数（試験では差し替えられる）
        self._runner_fn = runner_fn or _run_in_process
        self._lock = threading.Lock()
        self._entries: dict[tuple[str, str], RevealEntry] = {}
        self._slots = threading.Semaphore(MAX_CONCURRENT)

    # ------------------------------------------------------------ 公開

    def request(self, job_id: str, top_path: str) -> dict:
        """読み直しを始める（結果がメモリにあれば使い回す）。いまの状態を返す。事前に読み直せないと分かる理由は例外で返す。"""
        key = (job_id, top_path)
        with self._lock:
            self._purge()
            entry = self._entries.get(key)
            if entry is not None:
                return entry.view()
            try:
                plan = self._plan(job_id, top_path)
            except RevealUnavailable as e:
                return {"state": "error", "message": str(e)}  # 始める前に分かる理由。何も残さない
            entry = self._entries[key] = RevealEntry()
        threading.Thread(target=self._work, args=(entry, plan), daemon=True, name="pii-reveal").start()
        return entry.view()

    def forget_job(self, job_id: str) -> None:
        """ジョブを消すときに、そのジョブの読み直しの結果をメモリから捨てる。"""
        with self._lock:
            for k in [k for k in self._entries if k[0] == job_id]:
                del self._entries[k]

    # ------------------------------------------------------------ 内部

    def _purge(self) -> None:
        now = time.time()
        for k in [
            k
            for k, e in self._entries.items()
            if e.state != "running"
            and now - e.finished > (ERROR_KEEP_SECONDS if e.state == "error" else REVEAL_CACHE_SECONDS)
        ]:
            del self._entries[k]
        done = sorted(
            (k for k, e in self._entries.items() if e.state != "running"), key=lambda k: self._entries[k].finished
        )
        while len(self._entries) > MAX_CACHE_ENTRIES and done:
            del self._entries[done.pop(0)]

    def _plan(self, job_id: str, top_path: str) -> dict:
        """読み直しに使う設定・パスワード・時間制限を決める。読み直せないときは RevealUnavailable。"""
        from .runner import options_from_dict

        job = self.store.job(job_id)
        if not job:
            raise RevealUnavailable("そのジョブは見つかりません")
        rows = self.store.query(
            "SELECT size, mtime_ns, sha256, state FROM files WHERE job_id=? AND top_path=?", (job_id, top_path)
        )
        if not rows:
            raise RevealUnavailable("そのファイルは、この検査の結果に見つかりません")
        row = rows[0]
        if row["state"] != "done":
            raise RevealUnavailable("そのファイルはまだ検査が終わっていません")
        options = options_from_dict(job["options"])
        runner = self.registry.get(job_id, create=False)
        book = PasswordBook()
        if runner is not None:
            # パスワードは検査を動かしているメモリの分だけを使う（保存していない）。コピーを渡す
            book = PasswordBook(
                common=list(runner.passwords.common),
                per_file={k: list(v) for k, v in runner.passwords.per_file.items()},
                connection_password=runner.passwords.connection_password,
            )
        if is_ftp_path(top_path):
            if not options.connection:
                raise RevealUnavailable("FTP の接続先の設定が無いため、元のファイルを読み直せません")
            try:
                conn = Connection.from_dict(options.connection)
            except ConnectError as e:
                raise RevealUnavailable(
                    f"FTP の接続先の設定を読めないため、元のファイルを読み直せません（{e}）"
                ) from None
            if conn.user and not book.connection_password:
                raise RevealUnavailable(
                    "FTP サーバーのパスワードは保存していないため、アプリを開き直した後は読み直せません。"
                    "検査の画面でこのジョブの接続のパスワードを入れ直すと表示できます"
                )
        # 展開に使う一時フォルダが今は無いときは、既定の場所で読む
        temp_dir = options.temp_dir if options.temp_dir and os.path.isdir(options.temp_dir) else None
        options = replace(options, reveal=True, temp_dir=temp_dir)
        size = int(row["size"] or 0)
        timeout = min(MAX_TIMEOUT, max(MIN_TIMEOUT, size // BYTES_PER_SEC))
        return {
            "job_id": job_id,
            "top_path": top_path,
            "options": options,
            "book": book,
            "timeout": timeout,
            "size": size,
            "db_mtime_ns": row["mtime_ns"],
            "db_sha256": row["sha256"],
        }

    def _work(self, entry: RevealEntry, plan: dict) -> None:
        try:
            with self._slots:
                raw = self._runner_fn(plan["top_path"], plan["options"], plan["book"], plan["timeout"])
            self._finish(entry, "done", result=self._match(plan, raw))
        except RevealUnavailable as e:
            self._finish(entry, "error", error=str(e))
        except Exception as e:  # noqa: BLE001  想定外の失敗も画面に理由を返す（値は含めない）
            self._finish(entry, "error", error=f"読み直しに失敗しました（{type(e).__name__}）")

    def _finish(self, entry: RevealEntry, state: str, result: dict | None = None, error: str = "") -> None:
        with self._lock:
            entry.result = result
            entry.error = error
            entry.finished = time.time()
            entry.state = state  # 状態は最後に変える（_purge が finished を見るため）

    def _match(self, plan: dict, raw: dict) -> dict:
        """読み直した明細と DB の明細を突き合わせ、DB の行 ID → 生の値の対応を作る。"""
        items = raw["items"]
        source = raw.get("source") or None
        if source is None:
            # 元のファイルを写せなかった（移動・削除・権限・接続）。先頭の項目の理由をそのまま返す
            reason = items[0][2] if items else ""
            raise RevealUnavailable(
                f"元のファイルを読めませんでした: {reason}" if reason else "元のファイルを読めませんでした"
            )
        pool: dict[tuple, list[tuple[str, str]]] = {}
        for path, pii_type, location, masked, value, context in raw["findings"]:
            pool.setdefault((path, pii_type, location, masked), []).append((value, context))
        db_rows = self.store.query(
            "SELECT f.rowid AS fid, i.path AS path, f.pii_type, f.location, f.masked_value FROM findings f"
            " JOIN items i ON i.job_id=f.job_id AND i.top_path=f.top_path AND i.seq=f.item_seq"
            " WHERE f.job_id=? AND f.top_path=? ORDER BY f.item_seq, f.rowid",
            (plan["job_id"], plan["top_path"]),
        )
        values: dict[str, dict] = {}
        for r in db_rows:
            cands = pool.get((r["path"], r["pii_type"], r["location"], r["masked_value"]))
            if cands:
                value, context = cands.pop(0)
                values[str(r["fid"])] = {"value": value, "context": context}
        unmatched = len(db_rows) - len(values)
        mtime_changed = bool(
            plan["db_mtime_ns"] is not None
            and source.get("mtime_ns") is not None
            and int(plan["db_mtime_ns"]) != int(source["mtime_ns"])
        )
        content_changed = bool(plan["db_sha256"] and source.get("sha256") and plan["db_sha256"] != source["sha256"])
        notice = ""
        if content_changed or mtime_changed:
            notice = "検査のあとに元のファイルが変わっています（更新日時・中身が検査時と違います）。"
        needs_password = any(status == Status.NEEDS_PASSWORD.value for _, status, _ in items)
        if unmatched:
            if content_changed or mtime_changed:
                notice += "一致しない明細は、元のファイルが変わったため表示できません。"
            elif needs_password:
                notice += "パスワードが要る項目は、このアプリがパスワードを持っていないため表示できません。"
            else:
                notice += "一致しない明細は、元のファイルが変わったため表示できません。"
        return {
            "values": values,
            "total": len(db_rows),
            "unmatched": unmatched,
            "mtime_changed": mtime_changed,
            "content_changed": content_changed,
            "needs_password": needs_password,
            "notice": notice,
            "big_file": plan["size"] >= BIG_FILE_BYTES,
        }

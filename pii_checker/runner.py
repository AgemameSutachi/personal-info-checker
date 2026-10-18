"""検査ジョブの実行（列挙 → 並列検査 → 保存）。Web 版・アプリ版・CLI で共通に使う。

- ファイルごとに別プロセスで検査し、時間制限を超えたものは打ち切って「検査不能（時間切れ）」と記録する。
  壊れたファイルでワーカーが落ちても、全体は止まらない。
- パスワードは PasswordBook にメモリ上だけで持つ。受け取ったパスワードは、要パスワードの全ファイルと、
  これから検査する全ファイルに自動で試す（1ファイルずつ人に聞かない）。
"""

from __future__ import annotations

import multiprocessing
import os
import re
import threading
import time
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import fields

from .engine import scan_file, split_siblings
from .models import PasswordBook, ScanOptions, Status
from .procguard import plan_workers, worker_init
from .remote import LOGIN_LOST_MARK, Connection, LoginLost, ftp_stat, is_ftp_path, reset_login_failures
from .remote import close_pool as close_ftp_pool
from .safeio import NETWORK_LOST_MSG, NetworkLost, SourceInfo, free_bytes, is_disk_full, stat_identity
from .signature import engine_signature
from .store import Store
from .walker import walk

DEFAULT_TIMEOUT = 30 * 60  # 1ファイルあたりの時間制限（秒）。巨大な DB・イメージは設定で延ばす
GIT_PACK_TIMEOUT_FACTOR = 4  # git の pack は過去の全版を検査するので、時間制限を通常の4倍にする
HEARTBEAT_SECONDS = 10  # 生存記録の間隔（Store.reconcile_running の既定 120 秒より十分短く）
DB_MIN_FREE = 256 * 1024**2  # 結果の保存先のドライブにこれだけ空きが無くなったら、満杯になる前に止める
DISK_FULL_MESSAGE = (
    "結果を保存するドライブの空きが無くなったため、検査を中断した。空きを作ってから「再開」すると、続きから検査する"
)
# 回線断: 続けてこの件数が「接続が切れた」で読めなかったら、残りを1件ずつ失敗させずに止める
# （止めずに続けると、残り全部が「検査不能」で確定し、再開しても読み直されなかった。VM の SMB 共有で実測・2026-10-17）
NETWORK_HALT_STREAK = 3
NETWORK_MAX_RETRY = (
    3  # 1つのファイルだけが繰り返し「接続が切れた」になるときは、この回数で検査不能（理由は回線断）にする
)
NETWORK_HALT_MESSAGE = (
    "NAS・共有フォルダへ接続できなくなった（回線断・ログインできなくなった等）ため、検査を中断した。読めなかった"
    "ファイルは未検査のまま残してある。原因を除いてから「再開」すると、続きから検査する"
)


RE_PG_DATA = re.compile(r"\d+\.dat(\.gz)?")
RE_SPLIT_CONTINUATION = re.compile(r"\.(?!0*1$)\d{3}$|\.z\d{2}$|\.r\d{2}$|\.part(?!0*1\.rar$)\d+\.rar$")


def depends_on_neighbors(path: str) -> bool:
    """結果が隣のファイルにも左右される（そのファイルの識別情報だけでは使い回せない）か。

    分割アーカイブの1つ目（続きのファイルも読む）と、pg_dump の directory 形式のデータ（隣の toc.dat で列名を引く）。
    """
    if split_siblings(path):
        return True
    name = os.path.basename(path)
    if RE_SPLIT_CONTINUATION.search(name.lower()):
        return True  # 続き（.002・.z01・.part2.rar・.r00）: 1つ目の有無で「対象外」か「検査不能」かが変わる
    return bool(RE_PG_DATA.fullmatch(name)) and os.path.exists(os.path.join(os.path.dirname(path), "toc.dat"))


def options_from_dict(d: dict) -> ScanOptions:
    names = {f.name for f in fields(ScanOptions)}
    return ScanOptions(**{k: v for k, v in d.items() if k in names})


def _scan_task(path: str, options: ScanOptions, book: PasswordBook):
    """ワーカープロセスで動く。"""
    return scan_file(path, options, book)


class JobRunner:
    """1つのジョブを裏のスレッドで実行する。"""

    def __init__(
        self,
        store: Store,
        job_id: str,
        workers: int | None = None,
        timeout: int = DEFAULT_TIMEOUT,
        passwords: PasswordBook | None = None,
    ):
        self.store = store
        self.job_id = job_id
        job = store.job(job_id)
        if not job:
            raise ValueError(f"ジョブ {job_id} が見つからない")
        self.roots: list[str] = job["roots"]
        self.options = options_from_dict(job["options"])
        # ワーカー数は CPU と空きメモリから決める（指定があっても空きメモリに収まる数まで）
        self.workers, self.memory_limit = plan_workers(workers)
        self.timeout = timeout
        self.passwords = passwords or PasswordBook()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._requeue: list[str] = []
        self.current: set[str] = set()
        self.password_version = 0  # パスワードを受け取るたびに増やす（検査中だったファイルの再試行の判断に使う）
        self.phase = "待機"
        self.error = ""
        self.rechecking = False  # パスワードを受け取って再検査している最中か
        self.last_password_targets: list[str] = []  # 直近のパスワードを試したファイル（何件開いたかを示すため）
        self.passwords_tried = 0  # 受け取ったパスワードの数（値は持ち出さない）
        self.halt_reason = ""  # 安全のために自分から止めた理由（ドライブの満杯等）
        self._space_checked = 0.0
        self.engine_sig = engine_signature(self.options)  # 検査器の版（前回の結果を使い回してよいかの判定）
        self._net_streak_paths: set[str] = set()  # 続けて「接続が切れた」になった（別々の）ファイル
        self._net_retries: dict[str, int] = {}  # ファイルごとの「接続が切れた」の回数
        self._ftp_stat_off = False  # FTP の使い回しの問い合わせに失敗したら、その回はもう問い合わせない

    # ------------------------------------------------------------ 前回の結果の使い回し

    def _try_reuse(self, path: str) -> bool:
        """前回から変わっていないファイルなら前回の結果を写して True（検査を飛ばす）。

        条件: 同じパス・同じ検査器の版で、前回が言い切りを妨げない状態（store.REUSABLE_STATUSES）。
        さらに大きさ・更新日時・変更日時（ChangeTime。中身や代替データストリームが変わると進み、普通の道具では戻らない）・
        ファイル ID がすべて一致すること。中身は読まない（属性だけの開き方なので最終アクセス日時も変えない）。
        """
        if not self.options.reuse or depends_on_neighbors(path):
            return False
        prev = self.store.find_reusable(self.job_id, path, self.engine_sig)
        if not prev or prev.get("mtime_ns") is None:
            return False
        if is_ftp_path(path):
            # FTP には変更日時もファイル ID も無い。大きさと更新日時（秒）だけで比べる。値は列挙のときの一覧ではなく、
            # 今サーバーへ問い合わせて取る（再開では列挙し直さないので、古い一覧だと書き換わったファイルに前回の結果を
            # 使い、「全ファイルを中身まで検査した」と言い切った・実測）
            if self._ftp_stat_off:
                return False
            try:
                size, mtime = ftp_stat(
                    path, Connection.from_dict(self.options.connection or {}), self.passwords.connection_password
                )
            except LoginLost:
                self._halt(NETWORK_HALT_MESSAGE)  # ログインの失敗を重ねない（ロックアウトの規則に掛からないように）
                return False
            except NetworkLost:
                # 回線断の類: 1件ごとに待たせない（応答の無いサーバーだと、中止が効くまで長く待たせた・不具合の修正）
                self._ftp_stat_off = True
                return False
            except Exception:  # noqa: BLE001  1件が消えた等: そのファイルだけ読み直す（写す側で扱う）
                return False
            if not mtime:
                return False
            now = SourceInfo(size=size, mtime_ns=int(round(mtime * 1e9)), change_ns=0, file_id="")
        else:
            try:
                now = stat_identity(path)
            except OSError:
                return False
        if (now.size, now.mtime_ns, now.change_ns, now.file_id) != (
            prev["size"],
            prev["mtime_ns"],
            prev["change_ns"],
            prev["file_id"],
        ):
            return False
        self.store.copy_result(prev, self.job_id)
        return True

    # ------------------------------------------------------------ 制御

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name=f"job-{self.job_id}", daemon=True)
        self._thread.start()

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def cancel(self) -> None:
        self._stop.set()

    def wait(self, timeout: float | None = None) -> None:
        if self._thread:
            self._thread.join(timeout)

    def add_password(self, password: str, top_path: str | None = None) -> int:
        """パスワードを受け取り、要パスワードの全ファイルを再検査に回す。戻り値は再検査する件数。"""
        if not password:
            return 0
        with self._lock:  # 検査スレッドがパスワード帳を写している最中に書き換えない
            if top_path:
                self.passwords.per_file.setdefault(top_path, [])
                if password not in self.passwords.per_file[top_path]:
                    self.passwords.per_file[top_path].append(password)
            elif password not in self.passwords.common:
                self.passwords.common.append(password)
        self.password_version += 1
        self.passwords_tried += 1
        targets = self.store.files_with_status(self.job_id, [Status.NEEDS_PASSWORD.value])
        if top_path:
            targets = [t for t in targets if t == top_path] or targets
        self.last_password_targets = list(targets)
        self.rechecking = True
        self.store.mark_pending(self.job_id, targets)
        with self._lock:
            self._requeue.extend(targets)
        if not self.running:
            self.start()
        return len(targets)

    # ------------------------------------------------------------ 本体

    def _stopped_state(self) -> None:
        if self.halt_reason:
            self.error = self.halt_reason
            self._try_set_job(state="interrupted", message=self.halt_reason)
        else:
            self._try_set_job(state="cancelled", message="中止した（続きから再開できる）")

    def _try_set_job(self, **fields) -> None:
        """ジョブの状態を書く。書けなくても（ドライブの満杯等）止まらない。画面には self.error で伝わる。"""
        try:
            self.store.set_job(self.job_id, **fields)
        except Exception:
            pass

    def _run(self) -> None:
        cleanup_stale_temp([self.options.temp_dir])
        self.halt_reason = ""
        self.error = ""  # 前回止めた理由を、再開して最後まで終わったあとに残さない（実測）
        try:
            job = self.store.job(self.job_id)
            self.store.set_job(self.job_id, state="running", started=job.get("started") or time.time(), message="")
            self.store.heartbeat(self.job_id)
            beating = threading.Event()
            threading.Thread(target=self._heartbeat_loop, args=(beating,), daemon=True).start()
            if not job["enum_done"]:
                self._enumerate()
            if self._stop.is_set():
                self._stopped_state()
                return
            if not self.rechecking:
                # 前回、接続が切れて読めなかったファイルは、つながった今もう一度読む
                lost = self.store.files_with_reason_prefix(self.job_id, NETWORK_LOST_MSG)
                if lost:
                    self.store.mark_pending(self.job_id, lost)
            self._net_streak_paths.clear()
            self._net_retries.clear()
            self._ftp_stat_off = False
            reset_login_failures()  # ロックを外した後に同じパスワードで再開しても断り続けない
            self._scan_pending()
            if self._stop.is_set():
                self._stopped_state()
            else:
                self.store.set_job(self.job_id, state="done", finished=time.time())
        except Exception as e:  # 想定外でもジョブの状態に残す
            if is_disk_full(e):
                self.error = DISK_FULL_MESSAGE
                self._try_set_job(state="interrupted", message=self.error)
            else:
                self.error = f"{type(e).__name__}: {e}"
                self._try_set_job(state="error", message=self.error)
        finally:
            if "beating" in locals():
                beating.set()
            self._close_ftp_pool()
            self.phase = "待機"
            self.rechecking = False
            self.current.clear()

    def _close_ftp_pool(self) -> None:
        """前回の結果の使い回しの判定（ftp_stat）で開いた FTP の接続を閉じる（検査が終わった後まで残さない）。"""
        if not self.options.connection:
            return
        try:
            conn = Connection.from_dict(self.options.connection)
            if conn.is_ftp:
                close_ftp_pool(conn)
        except Exception:  # noqa: BLE001  後始末の失敗でジョブの状態を変えない
            pass

    def _timeout_for(self, path: str) -> int:
        """1ファイルの時間制限。git の pack は全部の版を検査するので長くする（中身は読まずにパスだけで決める）。"""
        p = path.replace("\\", "/").lower()
        if "/objects/pack/" in p and p.endswith(".pack"):
            return self.timeout * GIT_PACK_TIMEOUT_FACTOR
        return self.timeout

    def _heartbeat_loop(self, done: threading.Event) -> None:
        """動いている間は10秒ごとに生存を記録する（1ファイルの検査が長くても、別の窓や CLI から「中断」にされない）。"""
        while not done.wait(HEARTBEAT_SECONDS):
            try:
                self.store.heartbeat(self.job_id)
            except Exception:
                pass  # 保存先の満杯等。止める判断は検査の本体がする

    def _enumerate(self) -> None:
        self.phase = "ファイルの列挙"
        batch: list[tuple[str, int | None, float | None]] = []
        for entry in walk(self.roots, self.options.connection, self.passwords.connection_password):
            if self._stop.is_set():
                return
            if entry.kind == "file":
                batch.append((entry.path, entry.size, entry.mtime))
                if len(batch) >= 2000:
                    self.store.add_files(self.job_id, batch)
                    self.store.heartbeat(self.job_id)
                    batch.clear()
            elif entry.network_lost:
                # 列挙の途中で接続が切れた: そのフォルダを「開けなかった」で確定させず、列挙を済みにしないで止める
                # （再開すると列挙からやり直す。登録済みのファイルとフォルダのエラーは重ならない）
                if batch:
                    self.store.add_files(self.job_id, batch)
                self._halt(NETWORK_HALT_MESSAGE)
                return
            else:
                self.store.add_folder_error(self.job_id, entry.path, entry.kind, entry.reason)
        if batch:
            self.store.add_files(self.job_id, batch)
        self.store.set_job(self.job_id, enum_done=1)

    def _scan_pending(self) -> None:
        from pebble import ProcessPool
        from pebble.common import ProcessExpired

        self.phase = "パスワードで再検査" if self.rechecking else "検査"
        ctx = multiprocessing.get_context("spawn")
        with ProcessPool(
            max_workers=self.workers,
            max_tasks=50,
            context=ctx,
            initializer=worker_init,
            initargs=(self.memory_limit,),
        ) as pool:
            while not self._stop.is_set():
                pending = self.store.pending_files(self.job_id)
                with self._lock:
                    self._requeue.clear()
                if not pending:
                    break
                futures = {}
                it = iter(pending)
                exhausted = False
                while (futures or not exhausted) and not self._stop.is_set():
                    # 同時に投げる数を絞る（大量のファイルでもメモリを食わない）
                    while not exhausted and len(futures) < self.workers * 4 and self._db_space_ok():
                        try:
                            path = next(it)
                        except StopIteration:
                            exhausted = True
                            break
                        if not self.rechecking and self._try_reuse(path):
                            continue  # 前回から変わっていない（前回の結果を写した）
                        with self._lock:
                            book = PasswordBook(
                                common=list(self.passwords.common),
                                per_file={k: list(v) for k, v in self.passwords.per_file.items()},
                                connection_password=self.passwords.connection_password,
                            )
                        f = pool.schedule(_scan_task, args=(path, self.options, book), timeout=self._timeout_for(path))
                        futures[f] = (path, time.time(), self.password_version)
                        self.current.add(path)
                    done = [f for f in futures if f.done()]
                    if not done:
                        time.sleep(0.2)
                        continue
                    for f in done:
                        path, started, version = futures.pop(f)
                        self.current.discard(path)
                        self._save(f, path, started, ProcessExpired, version)
                if self._stop.is_set():
                    pool.stop()
                    break

    def _halt(self, reason: str) -> None:
        """検査を安全に止める（結果を保存できない等）。未検査のファイルは残るので、原因を除けば再開できる。"""
        if not self.halt_reason:
            self.halt_reason = reason
        self._stop.set()

    def _db_space_ok(self) -> bool:
        """結果の保存先のドライブに最低限の空きがあるか。無ければ満杯になる前に止める。"""
        now = time.time()
        if now - self._space_checked < 5:
            return True
        self._space_checked = now
        if free_bytes(os.path.dirname(os.path.abspath(self.store.path))) < DB_MIN_FREE:
            self._halt(DISK_FULL_MESSAGE)
            return False
        return True

    def _save(self, future, path: str, started: float, process_expired, version: int = 0) -> None:
        try:
            self._save_result(future, path, started, process_expired, version)
        except Exception as e:  # 結果そのものを保存できない（ドライブの満杯・DB の故障）→ 続けても無駄なので止める
            if is_disk_full(e):
                self._halt(DISK_FULL_MESSAGE)
            else:
                self._halt(
                    f"結果を保存できなかった（{type(e).__name__}: {e}）。原因を除いてから再開すると続きから検査する"
                )

    def _network_lost(self, path: str) -> bool:
        """接続が切れて読めなかった。未検査のまま残すなら True（続けて起きたら検査を止める）。

        1つのファイルだけが繰り返し切れる（他は読める）ときは、NETWORK_MAX_RETRY 回で False を返し、
        理由（回線断）つきの検査不能として保存させる（同じファイルを読み直し続けて終わらないのを防ぐ）。
        次に検査を始めたときに、その分も読み直しに回す（_run）。
        """
        n = self._net_retries[path] = self._net_retries.get(path, 0) + 1
        if n >= NETWORK_MAX_RETRY:
            # 先に1ファイルあたりの上限を見る（残りが同じ1件だけだと、続けて切れた数が先に上限に届き、
            # 再開のたびに止まって終わらなかった・実測）
            return False
        # 止めるかは「続けて切れた、別々のファイルの数」で決める（同じファイルの読み直しは数えない）
        self._net_streak_paths.add(path)
        if len(self._net_streak_paths) >= NETWORK_HALT_STREAK:
            self._halt(NETWORK_HALT_MESSAGE)
        return True

    def _save_result(self, future, path: str, started: float, process_expired, version: int) -> None:
        elapsed = time.time() - started
        try:
            result = future.result()
            if getattr(result, "network_lost", False) and any(
                LOGIN_LOST_MARK in (i.reason or "") for i in result.items
            ):
                # ログインできなくなった: 1回目で止める（別々のファイルで失敗を重ねると、ロックアウトの規則に掛かりうる）
                self._halt(NETWORK_HALT_MESSAGE)
                return
            if getattr(result, "network_lost", False) and self._network_lost(path):
                return  # 済みにせず未検査のまま残す（つながってから読み直す）
            if not getattr(result, "network_lost", False):
                self._net_streak_paths.clear()
            result.top_path = path  # 列挙したときの表記のまま保存する（列挙の結果と突き合わせるため）
            for it in result.items[:1]:
                if it.path != path and it.depth == 0:
                    it.path = path
            self.store.save_result(self.job_id, result, self.engine_sig)
            if version != self.password_version and any(i.status == Status.NEEDS_PASSWORD for i in result.items):
                # 検査中にパスワードを受け取っていたら、新しいパスワードでもう一度試す
                self.store.mark_pending(self.job_id, [path])
        except FutureTimeout:
            cleanup_stale_temp([self.options.temp_dir])  # 打ち切ったワーカーの一時フォルダをすぐ片付ける
            self.store.save_failure(
                self.job_id,
                path,
                f"時間切れ（{self._timeout_for(path) // 60}分）で打ち切った。巨大なファイルは設定で時間制限を延ばして再検査",
                elapsed,
            )
        except process_expired as e:
            cleanup_stale_temp([self.options.temp_dir])
            limit_gb = self.memory_limit / 1024**3
            self.store.save_failure(
                self.job_id,
                path,
                f"読み取り中に検査プロセスが異常終了した（1プロセスのメモリ上限 {limit_gb:.1f}GB を超えた・"
                f"壊れたファイルの可能性）: {e}",
                elapsed,
            )
        except Exception as e:
            if is_disk_full(e):
                raise
            self.store.save_failure(self.job_id, path, f"検査に失敗した（{type(e).__name__}: {e}）", elapsed)


def cleanup_stale_temp(extra_dirs: list[str | None] | tuple = (), no_mark_grace: float = 600.0) -> int:
    """持ち主のいない一時フォルダ（時間切れ・異常終了・電源断で残った展開・復号の中身）を片付ける。消した数を返す。

    検査中の一時フォルダには、持ち主のプロセスが開いたままの目印（engine.OWNER_MARK）がある。目印を消せたら持ち主は
    もういないので、年齢に関係なく消す（動いている他のジョブの一時フォルダは目印を消せないので残る）。
    目印の無いフォルダは、作られた直後（目印を置く前）でなければ持ち主はいないとみなす。設定した一時フォルダも見る。
    """
    import shutil
    import tempfile

    from .engine import OWNER_MARK, TEMP_PREFIX

    bases = []
    for b in [tempfile.gettempdir(), *extra_dirs]:
        if b and os.path.normcase(os.path.abspath(b)) not in [os.path.normcase(x) for x in bases]:
            bases.append(os.path.abspath(b))
    now = time.time()
    removed = 0
    for base in bases:
        try:
            names = os.listdir(base)
        except OSError:
            continue
        for name in names:
            if not name.startswith(TEMP_PREFIX):
                continue
            p = os.path.join(base, name)
            try:
                if not os.path.isdir(p):
                    continue
                mark = os.path.join(p, OWNER_MARK)
                if os.path.exists(mark):
                    os.remove(mark)  # 持ち主が生きていれば使用中で消せない（PermissionError）
                elif now - os.path.getctime(p) < no_mark_grace:
                    continue
            except OSError:
                continue
            shutil.rmtree(p, ignore_errors=True)
            removed += 1
    return removed


class RunnerRegistry:
    """Web 版・アプリ版で、動いているジョブを ID で引けるようにする。"""

    def __init__(self, store: Store):
        self.store = store
        self._runners: dict[str, JobRunner] = {}
        self._lock = threading.Lock()

    def get(self, job_id: str, create: bool = True, **kwargs) -> JobRunner | None:
        with self._lock:
            r = self._runners.get(job_id)
            if r is None and create:
                r = JobRunner(self.store, job_id, **kwargs)
                self._runners[job_id] = r
            return r

    def mark_interrupted(self) -> None:
        """前回の起動中に動いていて止まったままのジョブを「中断」にする（再開できる）。別の窓や CLI で動いているものは残す。"""
        self.store.reconcile_running()

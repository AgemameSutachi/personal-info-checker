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
from concurrent.futures import FIRST_COMPLETED
from concurrent.futures import TimeoutError as FutureTimeout
from concurrent.futures import wait as wait_futures
from dataclasses import fields

from .engine import checkpoint_path, read_checkpoint, scan_file, split_siblings
from .folderacl import AccessCache
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
# 巨大なファイルは、この速さ（遅めに見積もった読み取り速度）で読み切れるだけの時間を最低限あげる。
# 一律 30 分では、数 GB の DB のダンプが読み切れずに時間切れになっていた（3.3GB の Oracle ダンプで実測）
TIMEOUT_MIN_BYTES_PER_SEC = 512 * 1024
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


# 大きなファイル（この大きさ以上）は先に配る。名前の順に配ると、最後のほうに残った数 GB の zip 1〜2個だけが
# 何時間も動き、ほかのワーカーが空く（ドライブ全体 6.8 時間の検査で、終わりの約 6,200 秒は 7.8GB の zip 2つだけだった）
BIG_FILE_BYTES = 1024**3
# 大きなファイルを同時に配る本数の上限（一時領域・メモリを大きなファイルばかりで食わないように）。
# 実物の検査時間での模擬では、上限2で全部を大きい順にしたときとほぼ同じ速さ（ワーカー6本で 18,821→15,071 秒）
BIG_FILE_CONCURRENCY = 2
# ワーカーを作り直すまでの件数（形式ごとの読み込みが溜め込むメモリを手放すため）。作り直すたびにプロセスの起動と
# 1件目の準備（正規表現・形式の読み込み）で1〜2秒かかり、50件ごとでは小さなファイルばかりのフォルダで検査の
# 半分近くがこれに消えていた（ドライブ全体の検査で実測・2026-11-06）。溜まるメモリは、形式を混ぜた実物 476 件を
# 1プロセスで続けて検査して 50 件で +58MB・400〜476 件で +122〜140MB（私用 200MB 前後で頭打ち）。
# 1プロセスのメモリ上限（1.5GB 以上）に比べて小さく、上限に当たるかは1件ごとの重さで決まる
WORKER_MAX_TASKS = 500
# 配った仕事が終わるのを待つ最長の時間（どれか1件が終われば、すぐ起きて次を配る）
DONE_WAIT_SECONDS = 0.5


class PendingQueue:
    """未検査のファイルを配る順を決める（検査スレッドだけが使う）。

    大きなファイル（BIG_FILE_BYTES 以上）は大きい順に先に配り、同時に配っている大きなファイルは cap 本まで。
    ほかは名前の順。小さいファイルが尽きたら、上限を超えても大きなファイルを配る（ワーカーを空けない）。
    """

    def __init__(self, pending: list[tuple[str, int]], cap: int):
        self._big = sorted(((p, s) for p, s in pending if s >= BIG_FILE_BYTES), key=lambda x: (x[1], x[0]))
        self._small = [p for p, s in reversed(pending) if s < BIG_FILE_BYTES]  # 末尾から取る（名前の順）
        self.cap = max(1, cap)
        self._big_out: set[str] = set()

    def next(self) -> str | None:
        """次に配るファイル。尽きたら None。"""
        if self._big and (len(self._big_out) < self.cap or not self._small):
            path = self._big.pop()[0]  # 大きい順（末尾が一番大きい）
            self._big_out.add(path)
            return path
        if self._small:
            return self._small.pop()
        return None

    def done(self, path: str) -> None:
        """配ったファイルが終わった（検査した・使い回した・失敗した）。"""
        self._big_out.discard(path)


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
        self._acl = AccessCache()  # 検出のあったファイルの親フォルダのアクセス権（同じフォルダは1回だけ読む）
        self._cleanup = BackgroundCleanup()  # 持ち主のいない一時フォルダの片付け（配る側を止めないよう裏で）

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
        if prev.get("n_findings"):
            self._record_access(path)  # アクセス権は変わりうるので、使い回したファイルでも読み直す
        return True

    def _record_access(self, path: str) -> None:
        """検出のあったファイルの親フォルダのアクセス権を読んで記録する（同じフォルダは1回だけ読む）。

        読むだけで何も書き換えない（folderacl）。失敗しても検査は止めない（「読めなかった」として残る）。
        """
        try:
            acc = self._acl.for_file(path)
            self.store.set_access(self.job_id, path, acc.state, acc.who, acc.owner)
        except Exception:  # noqa: BLE001  アクセス権の記録は補足。検査の本体を止めない
            pass

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
        # 前の検査の残り（数万ファイルの展開など）を消すのに数分かかることがあり、終わるまで検査を始められなかった
        # （86万ファイルの検査の再開で7分。%TEMP% に残っていた 98 個も消していた・実測）。裏で消して、すぐ配り始める
        self._cleanup.request([self.options.temp_dir])
        if self._low_space():
            self._cleanup.wait()  # 空きが少ないときは、片付けで空くのを待ってから始める（満杯と判断して止めない）
        self.halt_reason = ""
        self.error = ""  # 前回止めた理由を、再開して最後まで終わったあとに残さない（実測）
        self._acl = AccessCache()  # 前の回に読んだアクセス権は使わない（その後で変わっていることがある）
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
            # 片付けはここで待たない（待つ間このスレッドが生きていて running が True のままになり、中止の後の再開や
            # パスワードでの再検査が黙って無視された・評価の指摘）。途中でプロセスが終わって消しかけで残っても、
            # 目印の無い古いフォルダとして次の片付けで消える
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
        """1ファイルの時間制限。git の pack は全部の版を検査するので長くする（中身は読まずにパスだけで決める）。

        巨大なファイルは、大きさを遅めの読み取り速度で割った時間を下回らないようにする（設定の時間制限は最低限の値）。
        """
        p = path.replace("\\", "/").lower()
        limit = (
            self.timeout * GIT_PACK_TIMEOUT_FACTOR if "/objects/pack/" in p and p.endswith(".pack") else self.timeout
        )
        try:
            size = self.store.file_size(self.job_id, path) or 0
        except Exception:  # noqa: BLE001  大きさが分からなければ設定の値のまま
            size = 0
        return max(limit, int(size / TIMEOUT_MIN_BYTES_PER_SEC))

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
            max_tasks=WORKER_MAX_TASKS,
            context=ctx,
            initializer=worker_init,
            initargs=(self.memory_limit,),
        ) as pool:
            while not self._stop.is_set():
                pending = self.store.pending_files_sized(self.job_id)
                with self._lock:
                    self._requeue.clear()
                if not pending:
                    break
                futures = {}
                queue = PendingQueue(pending, BIG_FILE_CONCURRENCY if self.workers >= 4 else 1)
                exhausted = False
                while (futures or not exhausted) and not self._stop.is_set():
                    # 同時に投げる数を絞る（大量のファイルでもメモリを食わない）
                    while not exhausted and len(futures) < self.workers * 4 and self._db_space_ok():
                        path = queue.next()
                        if path is None:
                            exhausted = True
                            break
                        if not self.rechecking and self._try_reuse(path):
                            queue.done(path)
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
                    if not futures:
                        continue  # 全部を使い回した・空きの確かめで止めた（次の周で終わる）
                    # 決まった時間だけ眠ると、短い仕事ばかりのときにワーカーが空いたまま待たされる（同時に32件・
                    # 0.2 秒ごとでは毎秒約160件が上限だった・実測）。どれか1件が終わったらすぐ起きる
                    done, _ = wait_futures(futures, timeout=DONE_WAIT_SECONDS, return_when=FIRST_COMPLETED)
                    if not done:
                        continue
                    for f in done:
                        path, started, version = futures.pop(f)
                        self.current.discard(path)
                        queue.done(path)
                        self._save(f, path, started, ProcessExpired, version)
                if self._stop.is_set():
                    pool.stop()
                    break

    def _halt(self, reason: str) -> None:
        """検査を安全に止める（結果を保存できない等）。未検査のファイルは残るので、原因を除けば再開できる。"""
        if not self.halt_reason:
            self.halt_reason = reason
        self._stop.set()

    def _low_space(self) -> bool:
        """結果の保存先か一時フォルダのドライブの空きが 1GB を切っているか（調べられなければ少ないとみなす）。"""
        import tempfile

        for d in (os.path.dirname(os.path.abspath(self.store.path)), self.options.temp_dir or tempfile.gettempdir()):
            try:
                if free_bytes(d) < 1024**3:
                    return True
            except Exception:  # noqa: BLE001
                return True
        return False

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
            self.store.save_result(self.job_id, result, self.engine_sig, wall_elapsed=elapsed)
            if any(i.finding_counts for i in result.items):
                self._record_access(path)
            if version != self.password_version and any(i.status == Status.NEEDS_PASSWORD for i in result.items):
                # 検査中にパスワードを受け取っていたら、新しいパスワードでもう一度試す
                self.store.mark_pending(self.job_id, [path])
        except FutureTimeout:
            # ワーカーが途中で書き出した項目を先に読む（それまでの検出を残す）。そのあと一時フォルダを片付ける
            partial = read_checkpoint(checkpoint_path(self.options, path))
            self._cleanup.request([self.options.temp_dir])  # 打ち切ったワーカーの一時フォルダを（裏で）すぐ片付ける
            limit = self._timeout_for(path)
            minutes = f"{limit // 60}分" if limit >= 60 else f"{limit}秒"  # 1分未満を「0分」と出さない
            if partial and any(i.finding_counts for i in partial):
                reason = (
                    f"時間切れ（{minutes}）で打ち切った。途中までに見つけた分は記録した（残りは未検査）。"
                    "巨大なファイルは設定で時間制限を延ばして再検査"
                )
            else:
                reason = f"時間切れ（{minutes}）で打ち切った。巨大なファイルは設定で時間制限を延ばして再検査"
            self.store.save_failure(self.job_id, path, reason, elapsed, partial=partial)
        except process_expired as e:
            partial = read_checkpoint(checkpoint_path(self.options, path))
            self._cleanup.request([self.options.temp_dir])
            limit_gb = self.memory_limit / 1024**3
            kept = (
                "途中までに見つけた分は記録した（残りは未検査）。"
                if partial and any(i.finding_counts for i in partial)
                else ""
            )
            self.store.save_failure(
                self.job_id,
                path,
                f"読み取り中に検査プロセスが異常終了した（1プロセスのメモリ上限 {limit_gb:.1f}GB を超えた・"
                f"壊れたファイルの可能性）。{kept}{e}",
                elapsed,
                partial=partial,
            )
        except Exception as e:
            if is_disk_full(e):
                raise
            self.store.save_failure(self.job_id, path, f"検査に失敗した（{type(e).__name__}: {e}）", elapsed)


class BackgroundCleanup:
    """cleanup_stale_temp を裏のスレッドで1本ずつ走らせる。

    走っている間に頼まれたら、終わった後にもう1回だけ走らせる（その間に打ち切ったワーカーの残りも消すため）。
    持ち主が生きている一時フォルダは目印を消せないので、検査と並べて走らせても使用中のものは消さない。
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._again = False
        self._dirs: list[str | None] = []
        self.removed = 0  # 消した数の合計（試験・調べ用）

    def request(self, extra_dirs: list[str | None]) -> None:
        with self._lock:
            self._dirs = list(extra_dirs)
            if self._thread is not None:
                self._again = True
                return
            self._thread = threading.Thread(target=self._loop, name="temp-cleanup", daemon=True)
            self._thread.start()

    def _loop(self) -> None:
        while True:
            with self._lock:
                dirs = self._dirs
                self._again = False
            try:
                self.removed += cleanup_stale_temp(dirs)
            except Exception:  # noqa: BLE001  片付けは補助。消せなかった分は次の機会にまた試す
                pass
            with self._lock:
                if not self._again:
                    self._thread = None
                    return

    def wait(self, timeout: float | None = None) -> None:
        with self._lock:
            t = self._thread
        if t is not None:
            t.join(timeout)


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
                    # 途中経過のファイル（engine.checkpoint_path）は検査中なら1分ごとに書き直される。1日更新の無いものは
                    # 持ち主のジョブが電源断などで消えた残り
                    if name.startswith(f"{TEMP_PREFIX}ckpt_") and now - os.path.getmtime(p) > 86400:
                        os.remove(p)
                        removed += 1
                    continue
                mark = os.path.join(p, OWNER_MARK)
                if os.path.exists(mark):
                    os.remove(mark)  # 持ち主が生きていれば使用中で消せない（PermissionError）
                elif now - os.path.getctime(p) < no_mark_grace:
                    continue
            except OSError:
                continue
            shutil.rmtree(p, onerror=_retry_writable)
            if not os.path.exists(p):
                removed += 1  # 消せたものだけ数える（消せなかったものは次の機会にまた試す）
    return removed


def _retry_writable(func, path, _exc) -> None:
    """rmtree が消せなかったものの読み取り専用を外して、もう一度だけ消す。

    展開した zip などの中身には読み取り専用のファイルがあり、Windows ではそのままでは消せず、一時フォルダが残っていた
    （2026-10-21 の検査の展開の残りが 98 個残っていた）。それでも消せなければ諦める（次の片付けでまた試す）。
    """
    import stat

    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except OSError:
        pass


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

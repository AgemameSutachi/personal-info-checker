"""検査ジョブの保存（SQLite）。

- 生の個人情報は保存しない（検出値はマスク済み、パスワードは一切保存しない）。
- 列挙したファイルを先に全部記録してから検査するので、中断しても続きから再開でき、
  「列挙した件数」と「結果の件数」が一致することを確かめられる。
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path

from . import reportflags
from .models import FileResult, ItemResult, ScanOptions, Status

SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    created REAL,
    name TEXT,
    roots TEXT,
    options TEXT,
    state TEXT,
    started REAL,
    finished REAL,
    enum_done INTEGER DEFAULT 0,
    message TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS files (
    job_id TEXT,
    top_path TEXT,
    state TEXT,
    worst_status TEXT,
    risk TEXT,
    size INTEGER,
    mtime REAL,
    elapsed REAL,
    n_findings INTEGER DEFAULT 0,
    PRIMARY KEY (job_id, top_path)
);
CREATE INDEX IF NOT EXISTS files_state ON files(job_id, state);
CREATE TABLE IF NOT EXISTS items (
    job_id TEXT,
    top_path TEXT,
    seq INTEGER,
    path TEXT,
    kind TEXT,
    status TEXT,
    reason TEXT,
    method TEXT,
    size INTEGER,
    mtime REAL,
    depth INTEGER,
    password_kind TEXT,
    counts TEXT,
    notes TEXT,
    conf_counts TEXT DEFAULT '{}',
    allowed INTEGER DEFAULT 0,
    PRIMARY KEY (job_id, top_path, seq)
);
CREATE INDEX IF NOT EXISTS items_status ON items(job_id, status);
CREATE TABLE IF NOT EXISTS findings (
    job_id TEXT,
    top_path TEXT,
    item_seq INTEGER,
    pii_type TEXT,
    confidence TEXT,
    masked_value TEXT,
    location TEXT,
    context TEXT,
    rule TEXT,
    method TEXT
);
CREATE INDEX IF NOT EXISTS findings_job ON findings(job_id, top_path);
CREATE TABLE IF NOT EXISTS folder_errors (
    job_id TEXT,
    path TEXT,
    kind TEXT,
    reason TEXT
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);
-- 対処（remediate）の記録。生の値は書かない（方法・絞り込みの種類と確度・数・退避先・ハッシュだけ）
CREATE TABLE IF NOT EXISTS remediations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT,
    at REAL,
    top_path TEXT,
    method TEXT,
    filters TEXT,
    changed TEXT,
    remaining TEXT,
    backup_path TEXT,
    orig_sha256 TEXT,
    new_sha256 TEXT,
    state TEXT,
    restored_at REAL,
    note TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS remediations_job ON remediations(job_id, at);
"""


# 後から足した files の列（古い版の DB にも足す）。再検査で同じファイルを飛ばす判定に使う
FILE_EXTRA_COLUMNS = {
    "mtime_ns": "INTEGER",  # 更新日時（ns）
    "change_ns": "INTEGER",  # 変更日時（ChangeTime）
    "file_id": "TEXT",  # ボリューム＋ファイル番号
    "sha256": "TEXT",  # 検査した中身のハッシュ
    "engine_sig": "TEXT",  # 検査器の版（signature.engine_signature）
    "reusable": "INTEGER DEFAULT 0",  # 次の検査で使い回してよいか（言い切りを妨げる状態を含まない）
    "reused_from": "TEXT",  # 使い回した元のジョブ
    "scanned_at": "REAL",  # 実際に中身を検査した時刻（使い回しても元の時刻を残す）
    "atime_kept": "INTEGER",  # 最終アクセス日時を保てたか
    # 異なる値の数（「種類:確度」→数の JSON。値もハッシュも持たない）。NULL は数えていない古い版の検査
    "distinct_counts": "TEXT",
    "flags": "TEXT",  # 漏えい時の報告の目安の印（reportflags.encode の形）
    "people_n": "INTEGER",  # 人の数の目安（異なる値が最も多い種類の数）。NULL は数えていない
    "people_type": "TEXT",  # 人の数の目安をどの種類で判断したか
    # 親フォルダのアクセス権（folderacl。broad / limited / unknown / ftp）。検出のあったファイルにだけ付ける
    "access": "TEXT",
    "access_who": "TEXT",  # 読み取りを許された「広く誰でも」の名前、または読めなかった理由
    "access_owner": "TEXT",  # 親フォルダの所有者の名前（取れたときだけ）
}
REUSABLE_STATUSES = (Status.SCANNED, Status.PARTIAL, Status.OUT_OF_SCOPE)


def _add_counts(acc: dict[str, int], text: str | dict | None) -> None:
    """「種類:確度」→件数（JSON の文字列か dict）を acc に足す。"""
    d = json.loads(text) if isinstance(text, str) else (text or {})
    for k, v in (d or {}).items():
        acc[k] = acc.get(k, 0) + int(v or 0)


def _pid_alive(pid: int) -> bool:
    """そのプロセスが今も動いているか。"""
    if pid == os.getpid():
        return True
    if os.name == "nt":
        import ctypes

        k32 = ctypes.windll.kernel32
        h = k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return False
        try:
            code = ctypes.c_ulong()
            return bool(k32.GetExitCodeProcess(h, ctypes.byref(code))) and code.value == 259  # STILL_ACTIVE
        finally:
            k32.CloseHandle(h)
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def default_db_path() -> str:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home())
    d = Path(base) / "PiiChecker"
    d.mkdir(parents=True, exist_ok=True)
    return str(d / "jobs.sqlite3")


class StoreOpenError(sqlite3.OperationalError):
    """検査結果の保存先を開けない（フォルダが作れない・書き込めない・使用中・満杯など）。文面はそのまま人に見せる。"""


class Store:
    """ジョブと結果の保存先。複数スレッドから使えるよう、操作ごとに鍵を掛ける。"""

    def __init__(self, path: str | None = None):
        self.path = path or default_db_path()
        self._lock = threading.RLock()
        self.recovered = ""  # 壊れていた DB を別名で残して作り直したときの知らせ
        if path:
            # --db で新しいフォルダを指したときも使えるように、置き場のフォルダを作っておく（作れなければ下で知らせる）
            try:
                Path(path).resolve().parent.mkdir(parents=True, exist_ok=True)
            except OSError:
                pass
        try:
            self._open()
        except sqlite3.DatabaseError as e:
            self._close_quietly()
            if isinstance(e, sqlite3.OperationalError):
                # 使用中（ロック）・満杯・置き場が無いなどは壊れていない。作り直さずに、何を確かめればよいかを添えて知らせる
                raise self._open_error(e) from e
            # 電源断などで壊れた DB は消さずに別名で残し、新しく作る（前の結果は別名のファイルに残る）
            stamp = time.strftime("%Y%m%d-%H%M%S")
            moved = []
            try:
                for suffix in ("", "-wal", "-shm"):
                    src = self.path + suffix
                    if os.path.exists(src):
                        dst = f"{self.path}.broken-{stamp}{suffix}"
                        os.replace(src, dst)
                        moved.append(dst)
                self._open()
            except (OSError, sqlite3.DatabaseError) as e2:
                self._close_quietly()
                err = self._open_error(e2, broken=True)
                if moved:  # 元のファイルが消えたように見えないよう、移した先を添える
                    err = StoreOpenError(f"{err} 前の結果は {moved[0]} に移してあります")
                raise err from e2
            self.recovered = (
                f"検査結果の保存先が壊れていたため（{e}）、新しく作り直しました。前の結果は {moved[0] if moved else '（なし）'} "
                "に残してあります"
            )

    def _close_quietly(self) -> None:
        """開きかけの接続を閉じる（ファイルを掴んだまま残さない）。まだ無ければ何もしない。"""
        try:
            self._conn.close()
        except Exception:
            pass

    def _open_error(self, e: Exception, broken: bool = False) -> StoreOpenError:
        """開けなかった理由に、人が次に何をすればよいかを添える。"""
        if "locked" in str(e):
            hint = "他の個人情報チェッカー（窓・Web 版・コマンド）を閉じてから、もう一度実行してください"
        else:
            hint = (
                "フォルダがあって書き込めるか・空きがあるか・他の個人情報チェッカーが使っていないかを確かめてください"
            )
        what = "壊れていたため作り直そうとしましたが、" if broken else ""
        return StoreOpenError(f"検査結果の保存先 {self.path} が{what}開けません（{e}）。{hint}")

    def _open(self) -> None:
        self._conn = sqlite3.connect(self.path, check_same_thread=False, timeout=60)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(SCHEMA)
        cols = {r[1] for r in self._conn.execute("PRAGMA table_info(items)")}
        if "conf_counts" not in cols:  # 古い版の DB に列を足す
            self._conn.execute("ALTER TABLE items ADD COLUMN conf_counts TEXT DEFAULT '{}'")
        if "allowed" not in cols:  # 許可リストで外した件数（古い版の DB に列を足す）
            self._conn.execute("ALTER TABLE items ADD COLUMN allowed INTEGER DEFAULT 0")
        if "distinct_counts" not in cols:  # 異なる値の数（古い版の DB では NULL のまま＝数えていない）
            self._conn.execute("ALTER TABLE items ADD COLUMN distinct_counts TEXT")
        if "rule_counts" not in cols:  # 利用者の規則の名前→件数（古い版の DB では空＝規則ごとに分けていない）
            self._conn.execute("ALTER TABLE items ADD COLUMN rule_counts TEXT DEFAULT '{}'")
        fcols = {r[1] for r in self._conn.execute("PRAGMA table_info(files)")}
        for name, decl in FILE_EXTRA_COLUMNS.items():
            if name not in fcols:
                self._conn.execute(f"ALTER TABLE files ADD COLUMN {name} {decl}")
        self._fill_old_flags()
        self._conn.execute("CREATE INDEX IF NOT EXISTS files_reuse ON files(top_path, engine_sig, reusable)")
        jcols = {r[1] for r in self._conn.execute("PRAGMA table_info(jobs)")}
        for name, decl in (("owner_pid", "INTEGER"), ("heartbeat", "REAL")):
            if (
                name not in jcols
            ):  # 動かしているプロセスと最終の生存時刻（電源断で「実行中」のまま残ったものを見分ける）
                self._conn.execute(f"ALTER TABLE jobs ADD COLUMN {name} {decl}")
        # 列挙をやり直しても（電源断の後の再開）開けなかったフォルダを二重に数えない
        self._conn.execute(
            "DELETE FROM folder_errors WHERE rowid NOT IN"
            " (SELECT MIN(rowid) FROM folder_errors GROUP BY job_id, path, kind)"
        )
        self._conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS folder_errors_once ON folder_errors(job_id, path, kind)")
        self._conn.commit()

    def _fill_old_flags(self) -> None:
        """古い版で検査したファイル（印の列が空）に、検出の件数から決まる印だけを付ける（異なる値は数えていないので付けない）。"""
        c = self._conn
        if not c.execute("SELECT 1 FROM files WHERE state='done' AND flags IS NULL LIMIT 1").fetchall():
            return
        agg: dict[tuple[str, str], dict[str, int]] = {}
        for job_id, top, cc in c.execute(
            "SELECT f.job_id, f.top_path, i.conf_counts FROM files f JOIN items i ON i.job_id=f.job_id"
            " AND i.top_path=f.top_path WHERE f.state='done' AND f.flags IS NULL AND i.conf_counts NOT IN ('{}', '')"
        ):
            d = agg.setdefault((job_id, top), {})
            _add_counts(d, cc)
        c.executemany(
            "UPDATE files SET flags=? WHERE job_id=? AND top_path=?",
            [(reportflags.encode(reportflags.compute(d, None)["flags"]), j, t) for (j, t), d in agg.items()],
        )
        c.execute("UPDATE files SET flags='' WHERE state='done' AND flags IS NULL")

    @contextmanager
    def tx(self):
        with self._lock:
            try:
                yield self._conn
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    def query(self, sql: str, args=()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, args).fetchall()

    def iter_query(self, sql: str, args=(), batch: int = 2000):
        """行を少しずつ返す（レポートの書き出し用。全行をメモリに載せない）。

        検査中にレポートを出すこともあるので、書き込みの接続を握り続けないよう、読み取り専用の別の接続で読む（WAL なので並行して読める）。
        """
        from urllib.parse import quote

        try:
            # % や # を含むパスでも開けるよう URI の形に符号化する
            uri = "file:" + quote(Path(self.path).as_posix(), safe="/:") + "?mode=ro"
            conn = sqlite3.connect(uri, uri=True, check_same_thread=False, timeout=60)
        except sqlite3.OperationalError:
            # UNC のパスなど URI で開けないときは、ふつうの接続で読む（読むだけなので書き込みは起きない）。
            # DB が無いときは空の DB を作らないよう、元の例外のまま返す
            if not os.path.exists(self.path):
                raise
            conn = sqlite3.connect(self.path, check_same_thread=False, timeout=60)
        conn.row_factory = sqlite3.Row
        try:
            cur = conn.execute(sql, args)
            while True:
                rows = cur.fetchmany(batch)
                if not rows:
                    break
                yield from rows
        finally:
            conn.close()

    # ------------------------------------------------------------ ジョブ

    @staticmethod
    def default_job_name(roots: list[str], limit: int = 200) -> str:
        """検査の名前（検査先を「、」でつないだもの）。長すぎるときはパスの途中で切らず、入りきらない分を「ほか N 件」にする。

        途中で切ると、画面が切れ端の最後の区切り（例: C:\\Users\\<ユーザー名>）を名前として出していた（2026-10-18 不具合の修正）。
        """
        parts: list[str] = []
        for i, r in enumerate(roots):
            if parts and len("、".join(parts + [r])) > limit:
                return "、".join(parts) + f" ほか {len(roots) - i} 件"
            parts.append(r)
        return "、".join(parts)

    def create_job(self, roots: list[str], options: ScanOptions, name: str = "") -> str:
        job_id = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
        saved_options = asdict(options)
        saved_options.pop("reveal", None)  # 読み直し専用の設定は保存しない
        saved_options.pop("collect_positions", None)  # 対処の位置集め専用の設定も保存しない
        with self.tx() as c:
            c.execute(
                "INSERT INTO jobs(id, created, name, roots, options, state) VALUES (?,?,?,?,?,?)",
                (
                    job_id,
                    time.time(),
                    name or self.default_job_name(roots),
                    json.dumps(roots, ensure_ascii=False),
                    json.dumps(saved_options, ensure_ascii=False),
                    "created",
                ),
            )
        return job_id

    def job(self, job_id: str) -> dict | None:
        rows = self.query("SELECT * FROM jobs WHERE id=?", (job_id,))
        if not rows:
            return None
        d = dict(rows[0])
        d["roots"] = json.loads(d["roots"])
        d["options"] = json.loads(d["options"])
        return d

    def jobs(self) -> list[dict]:
        return [
            dict(r)
            for r in self.query(
                "SELECT id, created, name, state, started, finished, message FROM jobs ORDER BY created DESC"
            )
        ]

    def set_job(self, job_id: str, **fields) -> None:
        if not fields:
            return
        cols = ", ".join(f"{k}=?" for k in fields)
        with self.tx() as c:
            c.execute(f"UPDATE jobs SET {cols} WHERE id=?", (*fields.values(), job_id))

    def heartbeat(self, job_id: str) -> None:
        """このプロセスがこのジョブを動かしていることを記録する（数秒ごとに呼ぶ）。"""
        self.set_job(job_id, owner_pid=os.getpid(), heartbeat=time.time())

    def reconcile_running(self, stale_after: float = 120.0, alive_stale_after: float = 3600.0) -> list[str]:
        """「実行中」のまま、動かしているプロセスがもういないジョブを「中断」にする（電源断・強制終了の後）。

        - 動かしているプロセスがもういない → 中断（電源断・強制終了）
        - プロセスが生きている → 生存記録が alive_stale_after より古いときだけ中断（pid が別のプロセスに使い回された場合）。
          スリープから戻った直後などで記録が少し古くても、動いているジョブを中断にしない（同じジョブが2つ走るのを防ぐ）
        - 持ち主の記録が無い（古い版で始めたジョブ）→ 生存記録が stale_after より古ければ中断
        """
        now = time.time()
        fixed = []
        for r in self.query("SELECT id, owner_pid, heartbeat FROM jobs WHERE state='running'"):
            age = now - float(r["heartbeat"]) if r["heartbeat"] else float("inf")
            if r["owner_pid"]:
                if _pid_alive(int(r["owner_pid"])) and age < alive_stale_after:
                    continue
            elif age < stale_after:
                continue
            self.set_job(
                r["id"],
                state="interrupted",
                message="途中で止まっていた（アプリの終了・電源断・強制終了など）。再開すると続きから検査する",
            )
            fixed.append(r["id"])
        return fixed

    def delete_job(self, job_id: str) -> None:
        with self.tx() as c:
            for t in ("findings", "items", "files", "folder_errors", "remediations"):
                c.execute(f"DELETE FROM {t} WHERE job_id=?", (job_id,))
            c.execute("DELETE FROM jobs WHERE id=?", (job_id,))

    # ------------------------------------------------------------ 対処の記録（生の値は書かない）

    def add_remediation(self, job_id: str, top_path: str, method: str, filters: dict, changed: dict, **kw) -> int:
        """対処の記録を1件足して ID を返す。kw: remaining・backup_path・orig_sha256・new_sha256・note。"""
        with self.tx() as c:
            cur = c.execute(
                "INSERT INTO remediations(job_id, at, top_path, method, filters, changed, remaining, backup_path,"
                " orig_sha256, new_sha256, state, note) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    job_id,
                    time.time(),
                    top_path,
                    method,
                    json.dumps(filters, ensure_ascii=False),
                    json.dumps(changed, ensure_ascii=False),
                    json.dumps(kw.get("remaining"), ensure_ascii=False),
                    kw.get("backup_path"),
                    kw.get("orig_sha256"),
                    kw.get("new_sha256"),
                    kw.get("state", "applied"),
                    kw.get("note", ""),
                ),
            )
            return int(cur.lastrowid)

    # 対処の記録の更新で書き換えてよい列（JSON の列は辞書で渡す）
    _REMEDIATION_FIELDS = (
        "state",
        "changed",
        "remaining",
        "backup_path",
        "orig_sha256",
        "new_sha256",
        "note",
        "restored_at",
    )

    def update_remediation(self, rid: int, **fields) -> None:
        """対処の記録（途中の状態・結果・立て直しの記録）を更新する。生の値は渡さない。"""
        sets, args = [], []
        for k, v in fields.items():
            if k not in self._REMEDIATION_FIELDS:
                raise ValueError(f"更新できない列: {k}")
            if k in ("changed", "remaining") and not isinstance(v, str):
                v = json.dumps(v, ensure_ascii=False)
            sets.append(f"{k}=?")
            args.append(v)
        if sets:
            with self.tx() as c:
                c.execute(f"UPDATE remediations SET {', '.join(sets)} WHERE id=?", (*args, rid))

    def delete_remediation(self, rid: int) -> None:
        """きれいに取りやめた実行の記録を消す（元に触る前に失敗した・元に戻し終えた）。"""
        with self.tx() as c:
            c.execute("DELETE FROM remediations WHERE id=?", (rid,))

    def unfinished_remediations(self, top_path: str | None = None) -> list[dict]:
        """途中で止まったままの対処の記録（始めた・元を改名した・新しいファイルを置いた）。立て直しの対象。"""
        sql = "SELECT * FROM remediations WHERE state IN ('started','renamed','swapped')"
        args: tuple = ()
        if top_path is not None:
            sql += " AND top_path=?"
            args = (top_path,)
        return [self._remediation_row(r) for r in self.query(sql + " ORDER BY id", args)]

    def remediation(self, job_id: str, rid: int) -> dict | None:
        rows = self.query("SELECT * FROM remediations WHERE job_id=? AND id=?", (job_id, rid))
        return self._remediation_row(rows[0]) if rows else None

    def remediations(self, job_id: str) -> list[dict]:
        rows = self.query("SELECT * FROM remediations WHERE job_id=? ORDER BY at DESC, id DESC", (job_id,))
        return [self._remediation_row(r) for r in rows]

    @staticmethod
    def _remediation_row(r) -> dict:
        d = dict(r)
        for k in ("filters", "changed", "remaining"):
            d[k] = json.loads(d[k]) if d.get(k) else None
        # 実行の段取り（方法・一時の新ファイル・改名後の元の名前・立て直しの結果）。note に JSON で持つ
        note = d.get("note") or ""
        try:
            d["plan"] = json.loads(note) if note.startswith("{") else {}
        except ValueError:
            d["plan"] = {}
        return d

    def mark_remediation_restored(self, rid: int) -> None:
        with self.tx() as c:
            c.execute("UPDATE remediations SET state='restored', restored_at=? WHERE id=?", (time.time(), rid))

    # ------------------------------------------------------------ 列挙

    def add_files(self, job_id: str, entries: list[tuple[str, int | None, float | None]]) -> None:
        with self.tx() as c:
            c.executemany(
                "INSERT OR IGNORE INTO files(job_id, top_path, state, size, mtime) VALUES (?,?,?,?,?)",
                [(job_id, p, "pending", s, m) for p, s, m in entries],
            )

    def add_folder_error(self, job_id: str, path: str, kind: str, reason: str) -> None:
        with self.tx() as c:
            c.execute(
                "INSERT OR IGNORE INTO folder_errors(job_id, path, kind, reason) VALUES (?,?,?,?)",
                (job_id, path, kind, reason),
            )

    def pending_files(self, job_id: str) -> list[str]:
        return [
            r[0]
            for r in self.query(
                "SELECT top_path FROM files WHERE job_id=? AND state='pending' ORDER BY top_path",
                (job_id,),
            )
        ]

    def mark_pending(self, job_id: str, top_paths: list[str]) -> None:
        with self.tx() as c:
            c.executemany(
                "UPDATE files SET state='pending' WHERE job_id=? AND top_path=?",
                [(job_id, p) for p in top_paths],
            )

    def files_with_status(self, job_id: str, statuses: list[str]) -> list[str]:
        marks = ",".join("?" * len(statuses))
        return [
            r[0]
            for r in self.query(
                f"SELECT DISTINCT top_path FROM items WHERE job_id=? AND status IN ({marks})",
                (job_id, *statuses),
            )
        ]

    def files_with_reason_prefix(self, job_id: str, prefix: str) -> list[str]:
        """理由が prefix で始まる項目を持つファイル（例: 接続が切れて読めなかったもの。隠しストリームだけのときも含む）。"""
        return [
            r[0]
            for r in self.query(
                "SELECT DISTINCT top_path FROM items WHERE job_id=? AND substr(reason, 1, ?) = ?",
                (job_id, len(prefix), prefix),
            )
        ]

    # ------------------------------------------------------------ 結果

    def save_result(self, job_id: str, result: FileResult, engine_sig: str | None = None) -> None:
        from .engine import risk_of, worst_status

        worst = worst_status(result.items) if result.items else Status.UNCHECKABLE
        risk = risk_of(result.items)
        n_findings = sum(sum(i.finding_counts.values()) for i in result.items)
        src = result.source or {}
        # 使い回してよいのは、元のファイルを写せていて（識別情報がある）、言い切りを妨げる状態を含まない結果だけ
        reusable = int(bool(src and engine_sig and worst in REUSABLE_STATUSES))
        conf_total: dict[str, int] = {}
        for it in result.items:
            _add_counts(conf_total, it.conf_counts)
        distinct = dict(result.distinct_counts or {})
        mark = reportflags.compute(conf_total, distinct)
        with self.tx() as c:
            c.execute(
                "DELETE FROM items WHERE job_id=? AND top_path=?",
                (job_id, result.top_path),
            )
            c.execute(
                "DELETE FROM findings WHERE job_id=? AND top_path=?",
                (job_id, result.top_path),
            )
            for seq, it in enumerate(result.items):
                c.execute(
                    "INSERT INTO items(job_id, top_path, seq, path, kind, status, reason, method, size, mtime, depth,"
                    " password_kind, counts, notes, conf_counts, allowed, distinct_counts, rule_counts)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        job_id,
                        result.top_path,
                        seq,
                        it.path,
                        it.kind,
                        it.status.value,
                        it.reason,
                        it.method,
                        it.size,
                        it.mtime,
                        it.depth,
                        it.password_kind,
                        json.dumps(it.finding_counts, ensure_ascii=False),
                        json.dumps(it.notes, ensure_ascii=False),
                        json.dumps(it.conf_counts, ensure_ascii=False),
                        it.allowed,
                        json.dumps(it.distinct_counts or {}, ensure_ascii=False),
                        json.dumps(it.rule_counts or {}, ensure_ascii=False),
                    ),
                )
                c.executemany(
                    "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?)",
                    [
                        (
                            job_id,
                            result.top_path,
                            seq,
                            f.pii_type,
                            f.confidence.value,
                            f.masked_value,
                            f.location,
                            f.context,
                            f.rule,
                            f.method,
                        )
                        for f in it.findings
                    ],
                )
            c.execute(
                "UPDATE files SET state='done', worst_status=?, risk=?, elapsed=?, n_findings=?,"
                " mtime_ns=?, change_ns=?, file_id=?, sha256=?, engine_sig=?, reusable=?, reused_from=NULL,"
                " scanned_at=?, atime_kept=?, distinct_counts=?, flags=?, people_n=?, people_type=?,"
                " access=NULL, access_who=NULL, access_owner=NULL WHERE job_id=? AND top_path=?",
                (
                    worst.value,
                    risk,
                    result.elapsed,
                    n_findings,
                    src.get("mtime_ns"),
                    src.get("change_ns"),
                    src.get("file_id"),
                    src.get("sha256"),
                    engine_sig,
                    reusable,
                    time.time(),
                    None if not src else int(bool(src.get("atime_kept"))),
                    json.dumps(distinct, ensure_ascii=False),
                    reportflags.encode(mark["flags"]),
                    mark["people_n"],
                    mark["people_type"],
                    job_id,
                    result.top_path,
                ),
            )

    # ------------------------------------------------------------ 前回の結果の使い回し

    def find_reusable(self, job_id: str, top_path: str, engine_sig: str) -> dict | None:
        """同じパス・同じ検査器の版で、使い回してよい最新の結果（別のジョブ）を返す。"""
        rows = self.query(
            "SELECT * FROM files WHERE top_path=? AND engine_sig=? AND reusable=1 AND job_id<>? AND state='done'"
            " ORDER BY scanned_at DESC LIMIT 1",
            (top_path, engine_sig, job_id),
        )
        return dict(rows[0]) if rows else None

    def copy_result(self, src: dict, job_id: str) -> None:
        """前回のジョブの結果（項目・検出）を、このジョブの結果として写す。元のジョブを消しても困らないよう行ごと写す。"""
        top = src["top_path"]
        with self.tx() as c:
            c.execute("DELETE FROM items WHERE job_id=? AND top_path=?", (job_id, top))
            c.execute("DELETE FROM findings WHERE job_id=? AND top_path=?", (job_id, top))
            c.execute(
                "INSERT INTO items(job_id, top_path, seq, path, kind, status, reason, method, size, mtime, depth,"
                " password_kind, counts, notes, conf_counts, allowed, distinct_counts, rule_counts) SELECT ?, top_path,"
                " seq, path, kind, status, reason, method, size, mtime, depth, password_kind, counts, notes, conf_counts,"
                " allowed, distinct_counts, rule_counts FROM items WHERE job_id=? AND top_path=?",
                (job_id, src["job_id"], top),
            )
            # 印は写さずに決め直す（印の決め方は検査器の版に含めないので、前回の後で変わっていることがある）
            conf_total: dict[str, int] = {}
            for (cc,) in c.execute(
                "SELECT conf_counts FROM items WHERE job_id=? AND top_path=? AND conf_counts NOT IN ('{}', '')",
                (job_id, top),
            ):
                _add_counts(conf_total, cc)
            distinct_text = src.get("distinct_counts")
            distinct = json.loads(distinct_text) if distinct_text else None
            mark = reportflags.compute(conf_total, distinct)
            c.execute(
                "INSERT INTO findings SELECT ?, top_path, item_seq, pii_type, confidence, masked_value, location,"
                " context, rule, method FROM findings WHERE job_id=? AND top_path=?",
                (job_id, src["job_id"], top),
            )
            origin = src.get("reused_from") or src["job_id"]
            c.execute(
                "UPDATE files SET state='done', worst_status=?, risk=?, elapsed=0, n_findings=?, mtime_ns=?,"
                " change_ns=?, file_id=?, sha256=?, engine_sig=?, reusable=1, reused_from=?, scanned_at=?,"
                " atime_kept=?, distinct_counts=?, flags=?, people_n=?, people_type=?, access=NULL, access_who=NULL,"
                " access_owner=NULL WHERE job_id=? AND top_path=?",
                (
                    src["worst_status"],
                    src["risk"],
                    src["n_findings"],
                    src["mtime_ns"],
                    src["change_ns"],
                    src["file_id"],
                    src["sha256"],
                    src["engine_sig"],
                    origin,
                    src["scanned_at"],
                    src["atime_kept"],
                    distinct_text,
                    reportflags.encode(mark["flags"]),
                    mark["people_n"],
                    mark["people_type"],
                    job_id,
                    top,
                ),
            )

    def set_access(self, job_id: str, top_path: str, access: str, who: str = "", owner: str = "") -> None:
        """ファイルの親フォルダのアクセス権（folderacl の結果）を記録する。"""
        with self.tx() as c:
            c.execute(
                "UPDATE files SET access=?, access_who=?, access_owner=? WHERE job_id=? AND top_path=?",
                (access, who, owner, job_id, top_path),
            )

    def save_failure(
        self, job_id: str, top_path: str, reason: str, elapsed: float = 0.0, partial: list[ItemResult] | None = None
    ) -> None:
        """ワーカーごと失敗した（時間切れ・異常終了）ファイルを、検査不能として記録する。

        partial はワーカーが途中で書き出した項目（engine.ScanContext.maybe_checkpoint）。あれば、それまでの検出を残したうえで
        検査不能にする（数 GB のダンプが時間切れになっても、見つけた個人情報が消えて「なし」に見えないように）。
        """
        if partial:
            items = list(partial)
            items[0].path = top_path
            items[0].status = Status.UNCHECKABLE
            items[0].reason = reason
            for it in items[1:]:
                if it.status == Status.PENDING:
                    it.status = Status.UNCHECKABLE
                    it.reason = "外側のファイルの時間切れで、途中までしか検査していない"
            self.save_result(job_id, FileResult(top_path=top_path, items=items, elapsed=elapsed))
            return
        item = ItemResult(path=top_path, kind="", status=Status.UNCHECKABLE, reason=reason)
        try:
            item.size = os.path.getsize(top_path)
        except OSError:
            pass
        self.save_result(job_id, FileResult(top_path=top_path, items=[item], elapsed=elapsed))

    def file_size(self, job_id: str, top_path: str) -> int | None:
        """列挙したときのファイルの大きさ（時間制限を大きさに合わせるのに使う）。"""
        rows = self.query("SELECT size FROM files WHERE job_id=? AND top_path=?", (job_id, top_path))
        return rows[0][0] if rows else None

    # ------------------------------------------------------------ 集計

    def summary(self, job_id: str) -> dict:
        """進捗と総合判定の材料。"""
        q = self.query
        files_total = q("SELECT COUNT(*) FROM files WHERE job_id=?", (job_id,))[0][0]
        files_done = q("SELECT COUNT(*) FROM files WHERE job_id=? AND state='done'", (job_id,))[0][0]
        status_counts = {
            r[0]: r[1]
            for r in q(
                "SELECT status, COUNT(*) FROM items WHERE job_id=? GROUP BY status",
                (job_id,),
            )
        }
        top_status = {
            r[0]: r[1]
            for r in q(
                "SELECT worst_status, COUNT(*) FROM files WHERE job_id=? AND state='done' GROUP BY worst_status",
                (job_id,),
            )
        }
        risk_counts = {
            r[0]: r[1]
            for r in q(
                "SELECT risk, COUNT(*) FROM files WHERE job_id=? AND state='done' GROUP BY risk",
                (job_id,),
            )
        }
        # 確度ごとの件数は明細ではなく全数（items.conf_counts）から数える
        conf_counts: dict[str, int] = {}
        for r in q(
            "SELECT conf_counts FROM items WHERE job_id=? AND conf_counts NOT IN ('{}', '')",
            (job_id,),
        ):
            for k, v in json.loads(r[0] or "{}").items():
                conf = k.split(":", 1)[1]
                conf_counts[conf] = conf_counts.get(conf, 0) + v
        type_counts: dict[str, int] = {}
        files_with_findings = 0
        for r in q("SELECT counts FROM items WHERE job_id=? AND counts != '{}'", (job_id,)):
            for k, v in json.loads(r[0]).items():
                type_counts[k] = type_counts.get(k, 0) + v
        files_with_findings = q("SELECT COUNT(*) FROM files WHERE job_id=? AND n_findings > 0", (job_id,))[0][0]
        folder_errors = q(
            "SELECT COUNT(*) FROM folder_errors WHERE job_id=? AND kind='error'",
            (job_id,),
        )[
            0
        ][0]
        links = q(
            "SELECT COUNT(*) FROM folder_errors WHERE job_id=? AND kind='link'",
            (job_id,),
        )[
            0
        ][0]
        password_files = len(self.files_with_status(job_id, [Status.NEEDS_PASSWORD.value]))
        allowed = q("SELECT COALESCE(SUM(allowed), 0) FROM items WHERE job_id=?", (job_id,))[0][0]
        job_opts = q("SELECT options FROM jobs WHERE id=?", (job_id,))
        try:
            opts = json.loads(job_opts[0][0]) if job_opts else {}
        except (TypeError, ValueError):
            opts = {}
        reused = q(
            "SELECT COUNT(*) FROM files WHERE job_id=? AND reused_from IS NOT NULL",
            (job_id,),
        )[
            0
        ][0]
        # 報告の目安の印ごとのファイル数と、検出のあったファイルの親フォルダのアクセス権の内訳
        flag_counts = {f: 0 for f in reportflags.FLAG_ORDER}
        access_counts: dict[str, int] = {}
        # ジョブ全体の、異なる値の数の合計（ファイルごとの数を足したもの。同じ人が複数のファイルにいれば重ねて数える）
        totals = {"my_number": 0, "people": 0, "uncounted_files": 0}
        for r in q(
            "SELECT flags, access, distinct_counts, people_n FROM files WHERE job_id=? AND state='done' AND n_findings > 0",
            (job_id,),
        ):
            for f in reportflags.decode(r[0]):
                flag_counts[f] += 1
            if r[1]:
                access_counts[r[1]] = access_counts.get(r[1], 0) + 1
            if r[2] is None:
                totals["uncounted_files"] += 1  # 異なる値を数えていない古い版の検査
            else:
                totals["my_number"] += reportflags.distinct_medium(json.loads(r[2] or "{}")).get("my_number", 0)
                totals["people"] += int(r[3] or 0)
        return {
            "flags": flag_counts,
            "access": access_counts,
            "distinct_totals": totals,
            "files_total": files_total,
            "files_done": files_done,
            "item_status": status_counts,
            "file_status": top_status,
            "risk": risk_counts,
            "confidence": conf_counts,
            "types": type_counts,
            "files_with_findings": files_with_findings,
            "folder_errors": folder_errors,
            "links": links,
            "password_files": password_files,
            "reused": reused,
            # 許可リストで外した検出の件数と、許可リスト・利用者の規則の数（判定の文・レポートに出す）
            "allowed": allowed,
            "allow_list": len(opts.get("allow_values") or []),
            "custom_rules": len(opts.get("custom_rules") or []),
        }

    # ------------------------------------------------------------ 画面の設定（前回の値を次の検査の欄に入れておく）

    def get_setting(self, key: str, default: str = "") -> str:
        rows = self.query("SELECT value FROM settings WHERE key=?", (key,))
        return rows[0][0] if rows and rows[0][0] is not None else default

    def set_setting(self, key: str, value: str) -> None:
        with self.tx() as c:
            c.execute(
                "INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

"""データベースの処理（Access・SQLite・dBase）。

Access は次の順で読めるものを使う:
  1. 64bit の ACE ODBC ドライバ（accdb/mdb）
  2. 32bit の補助プロセス（Jet4 ドライバ。Access 97 = Jet3 形式や、32bit Office しか無い PC）
  3. 同梱の Jackcess（Java。ACE の無い PC で .accdb を読む。読み取り専用で開く）
  4. 純 Python の access_parser
どれで読めても、加えてファイル全体を生データ走査する（削除済みレコードの残留を拾うため）。
元のファイルは一時フォルダへ複製してから開く（NAS 上にロックファイルを作らない・元を変えない）。
"""

from __future__ import annotations

import base64
import json
import re
import os
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

from ..engine import Blob, Collector, ItemResult, NeedPassword, PartialScan, ScanContext, Uncheckable, long_path
from ..models import Status
from ..textdecode import iter_strings_chunked

CREATE_NO_WINDOW = 0x08000000


def _dev_helper_pythons() -> list[str]:
    """開発時に Access 補助を動かす 32bit の Python の候補（上から順に試す）。

    補助は標準ライブラリだけで動くので、素の 32bit Python で足りる。
    環境変数 PIICHK_PYTHON32 → ~/temp/venv/personal-info-checker-32 → 標準のインストール先（新しい版から）。
    """
    found = []
    if os.environ.get("PIICHK_PYTHON32"):
        found.append(os.environ["PIICHK_PYTHON32"])
    found.append(str(Path.home() / "temp/venv/personal-info-checker-32/Scripts/python.exe"))
    local = os.environ.get("LOCALAPPDATA")
    if local:
        installs = sorted(
            Path(local, "Programs", "Python").glob("Python3*-32"),
            key=lambda p: [int(x) for x in re.findall(r"\d+", p.name)],
            reverse=True,
        )
        found += [str(p / "python.exe") for p in installs]
    return found


def _private_copy(ctx: ScanContext, blob: Blob, suffix: str) -> str:
    """元を触らないよう、一時フォルダへ複製したパスを返す。"""
    dst = os.path.join(ctx.new_tmp_subdir(), "db" + suffix)
    if blob.data is not None:
        with open(dst, "wb") as f:
            f.write(blob.data)
    else:
        shutil.copyfile(long_path(blob.path), dst)
    return dst


def _loc(table: str):
    return lambda r, c, cols=None: f"表「{table}」{r}行目"


def _raw_sweep(path: str, col: Collector, raw: bool) -> None:
    with open(path, "rb") as f:
        for s in iter_strings_chunked(f.read):
            col.add_text(s, "ファイル全体の生データ", method="生データ走査", raw=raw)


# ------------------------------------------------------------------ Access


def find_helper32(configured: str | None) -> list[str] | None:
    """32bit の Access 補助の起動コマンドを返す（無ければ None）。"""
    if configured:
        if configured.lower().endswith("python.exe"):
            script = Path(__file__).resolve().parent.parent / "access32_helper.py"
            return [configured, str(script)]
        if os.path.isfile(configured):
            return [configured]
    script = Path(__file__).resolve().parent.parent / "access32_helper.py"
    base = Path(sys.executable).parent
    roots = [base] + ([Path(sys._MEIPASS)] if getattr(sys, "_MEIPASS", None) else [])
    for root in roots:
        # 配布版: 32bit の埋め込み Python（python32/）と補助スクリプトを同梱する
        py32 = root / "python32" / "python.exe"
        bundled = root / "python32" / "access32_helper.py"
        if py32.is_file() and bundled.is_file():
            return [str(py32), str(bundled)]
        exe = root / "access32_helper.exe"
        if exe.is_file():
            return [str(exe)]
    if script.is_file():
        for py in _dev_helper_pythons():
            if os.path.isfile(py):
                return [py, str(script)]
    return None


def _is_password_error(msg: str) -> bool:
    m = msg.lower()
    return "-1905" in m or "password" in m or "パスワード" in msg


def _read_access_odbc(ctx: ScanContext, path: str, col: Collector, item: ItemResult, depth: int, display: str) -> str:
    """64bit ODBC で読む。戻り値は使ったドライバ名。読めなければ例外。"""
    import pyodbc

    drivers = [d for d in pyodbc.drivers() if "Access Driver" in d and ("accdb" in d or ".mdb" in d)]
    drivers.sort(key=lambda d: 0 if "accdb" in d else 1)
    if not drivers:
        raise RuntimeError("64bit の Access ODBC ドライバが入っていない")
    last: Exception | None = None
    password_failed = False
    for drv in drivers:
        for pw in [""] + ctx.password_candidates():
            # ACE は値を波括弧で囲むとパスワードが一致しなくなる。; や { を含むときだけ囲む
            pw_value = f"{{{pw}}}" if any(ch in pw for ch in ";{}") else pw
            conn_str = f"DRIVER={{{drv}}};DBQ={path};ReadOnly=1;Exclusive=1;" + (f"PWD={pw_value};" if pw else "")
            try:
                conn = pyodbc.connect(conn_str, autocommit=True, readonly=True)
            except pyodbc.Error as e:
                last = e
                if _is_password_error(str(e)):
                    password_failed = True
                    continue
                break  # パスワード以外の失敗は、このドライバでは無理
            try:
                _dump_odbc(ctx, conn, col, item, depth, display)
            finally:
                conn.close()
            if pw:
                item.notes.append("データベースパスワードで開いた")
            return drv
    if password_failed:
        raise NeedPassword("access", "Access にデータベースパスワードが掛かっている")
    raise RuntimeError(f"64bit ODBC で開けなかった: {last}")


def _dump_odbc(ctx: ScanContext, conn, col: Collector, item: ItemResult, depth: int, display: str) -> None:
    cur = conn.cursor()
    tables = []
    others = []
    for t in cur.tables():
        name, ttype = t.table_name, (t.table_type or "").upper()
        if name.startswith(("MSys", "~")):
            continue
        if ttype == "TABLE":
            tables.append(name)
        elif ttype in ("LINK", "SYNONYM", "ACCESS TABLE"):
            others.append(name)
    if others:
        item.notes.append("リンクテーブル（リンク先は別に検査が必要）: " + "、".join(others[:20]))
    for name in tables:
        c2 = conn.cursor()
        try:
            c2.execute(f"SELECT * FROM [{name}]")
        except Exception as e:
            _failed_table(ctx, display, name, f"表を読めなかった: {e}", depth)
            continue
        col.pos_sheet = name  # 対処のための位置: シートは表の名前、行は SELECT * の通し番号
        columns = [d[0] for d in c2.description]
        if col.collect_positions:
            col.pos_info.setdefault("tables", {})[name] = {"columns": list(columns)}  # 下見に出す列名（値は含まない）
        blob_cols = set()

        def rows(c2=c2, name=name, columns=columns):
            r_no = 0
            limit = ctx.options.max_rows_per_table
            while True:
                batch = c2.fetchmany(1000)
                if not batch:
                    break
                for row in batch:
                    r_no += 1
                    out = []
                    for ci, v in enumerate(row):
                        if isinstance(v, (bytes, bytearray)):
                            if len(v) > 64:
                                blob_cols.add(columns[ci])
                                _scan_ole_field(
                                    ctx, bytes(v), f"{display}!表「{name}」{r_no}行目 列「{columns[ci]}」", depth
                                )
                            out.append(None)
                        else:
                            out.append(v)
                    yield out
                    if limit and r_no >= limit:
                        return

        n = col.add_records(
            columns,
            rows(),
            lambda r, c, name=name, columns=columns: f"表「{name}」{r}行目 列「{columns[c]}」",
            method="表のレコード",
        )
        item.notes.append(f"表「{name}」{n}行")


def _failed_table(
    ctx: ScanContext, display: str, table: str, reason: str, depth: int, status: Status = Status.UNCHECKABLE
) -> None:
    """読めなかった表を、黙って捨てずに項目として残す。"""
    ctx.items.append(
        ItemResult(path=f"{display}!表「{table}」", kind="Access の表", status=status, reason=reason, depth=depth + 1)
    )


def _scan_ole_field(ctx: ScanContext, data: bytes, display: str, depth: int) -> None:
    """OLE オブジェクト型・バイナリ型の値の中のファイルを取り出して検査する。"""
    magics = (
        b"PK\x03\x04",
        b"%PDF",
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        b"\xff\xd8\xff",
        b"\x89PNG",
        b"{\\rtf",
        b"BM",
    )
    best = -1
    for m in magics:
        idx = data.find(m, 0, 8192)
        if idx >= 0 and (best < 0 or idx < best):
            best = idx
    payload = data[best:] if best >= 0 else data
    ctx.scan_nested(display, data=payload, depth=depth + 1, name_hint="field.bin")


def _read_access_helper32(
    ctx: ScanContext, path: str, col: Collector, item: ItemResult, depth: int, display: str
) -> str:
    cmd = find_helper32(ctx.options.access_helper32)
    if not cmd:
        raise RuntimeError("32bit の補助（access32_helper）が見つからない")
    args = cmd + [path]
    if ctx.password_candidates():
        args += ["--password-file", "-"]
    if ctx.options.max_rows_per_table:
        args += ["--max-rows-per-table", str(ctx.options.max_rows_per_table)]
    proc = subprocess.Popen(
        args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    import threading

    stderr_buf: list[bytes] = []
    t_err = threading.Thread(target=lambda: stderr_buf.append(proc.stderr.read()), daemon=True)
    t_err.start()
    try:
        if ctx.password_candidates():
            proc.stdin.write("\n".join(ctx.password_candidates()).encode("utf-8"))
        proc.stdin.close()
    except OSError:
        pass
    columns_by_table: dict[str, list[str]] = {}
    opened = None
    error = None
    done = False
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            try:
                msg = json.loads(line.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                continue
            t = msg.get("type")
            if t == "open":
                opened = msg
            elif t == "table":
                columns_by_table[msg["name"]] = msg["columns"]
                if col.collect_positions:
                    col.pos_info.setdefault("tables", {})[msg["name"]] = {"columns": list(msg["columns"])}
            elif t == "row":
                table = msg["table"]
                cols = columns_by_table.get(table, [])
                values = msg["values"]
                r = msg["row"]
                col.pos_sheet = table
                for ci, v in enumerate(values):
                    if v in (None, ""):
                        continue
                    header = cols[ci] if ci < len(cols) else None
                    col.cell_pos = (r, ci)  # 対処のための位置（行は補助が数えた通し番号）
                    try:
                        col.add_text(
                            str(v),
                            f"表「{table}」{r}行目 列「{header}」",
                            header=header,
                            method="表のレコード（32bit）",
                        )
                    finally:
                        col.cell_pos = None
            elif t == "blob":
                try:
                    data = base64.b64decode(msg["data_b64"])
                    _scan_ole_field(
                        ctx, data, f"{display}!表「{msg['table']}」{msg['row']}行目 列「{msg['column']}」", depth
                    )
                except Exception as e:
                    item.notes.append(f"OLE オブジェクトを取り出せなかった: {e}")
            elif t == "warning":
                message = msg.get("message", "")
                m_tbl = re.search(r"表「(.+?)」", message)
                if m_tbl and "読めませんでした" in message:
                    _failed_table(ctx, display, m_tbl.group(1), message, depth)
                elif m_tbl and "打ち切りました" in message:
                    _failed_table(ctx, display, m_tbl.group(1), message, depth, Status.PARTIAL)
                else:
                    item.notes.append(message)
            elif t == "error":
                error = msg
            elif t == "done":
                done = True
        proc.wait(timeout=60)
    finally:
        if proc.poll() is None:
            proc.kill()
    if error:
        if error.get("code") == "password":
            raise NeedPassword("access", "Access にデータベースパスワードが掛かっている")
        raise RuntimeError(f"32bit 補助で開けなかった: {error.get('message')}")
    if not done:
        t_err.join(timeout=5)
        err = b"".join(stderr_buf).decode("utf-8", errors="replace")[-300:]
        raise RuntimeError(f"32bit 補助が途中で終わった（終了コード {proc.returncode}）: {err}")
    for name in columns_by_table:
        item.notes.append(f"表「{name}」")
    return f"32bit {opened.get('driver') if opened else ''}（{opened.get('method') if opened else ''}）"


FORCED_READERS: list[str] | None = None  # 試験用: 検査の読み方をこれだけに絞る（odbc・helper32・jackcess・parser）
READERS_ENV = "PIICHK_ACCESS_READERS"  # 診断・別プロセスの試験用: 環境変数で読み方を絞る（コンマ区切り）
JACKCESS_STALL_SECONDS = 300  # Java から1行も来ないまま、これだけ経ったら止まったとみなして打ち切る


def forced_readers() -> list[str] | None:
    """検査の読み方を絞る指定（試験用の変数 → 環境変数の順）。無ければ None（全部、既定の順で）。"""
    if FORCED_READERS is not None:
        return FORCED_READERS
    raw = os.environ.get(READERS_ENV, "").strip()
    return [x.strip() for x in raw.split(",") if x.strip()] if raw else None


def _read_access_jackcess(
    ctx: ScanContext, path: str, col: Collector, item: ItemResult, depth: int, display: str
) -> str:
    """同梱の Jackcess（Java）で読む（ACE の無い PC の .accdb 用）。戻り値は手段の名前。読めなければ例外。

    表・行の数え方は remedy_access の JackcessSession.read（対処で書き換えるときの手段）と同じ。
    読み取り専用で開き、表は1行ずつ流れてくるので溜めない。
    """
    import threading
    import time

    from .. import remedy_access as ra

    if ra.access_format(path) != "ace":
        raise RuntimeError("Jackcess は .accdb（ACE 形式）だけ読む")
    env = ra.find_jackcess()
    if not env:
        raise RuntimeError("同梱の Jackcess（Java）が見つからない")
    # ヒープは対処（JackcessSession）と同じ小さめ（検査のワーカーのメモリ上限の内側で動かすため）
    cmd = [env["java"], "-Xmx768m", "-XX:+UseSerialGC", "-cp", os.pathsep.join(env["classpath"]), "AccessRewrite"]
    try:
        pipe = ra._Pipe(cmd)
    except OSError as e:
        raise RuntimeError(f"Java を起動できない: {e}") from None
    last_line = [time.monotonic()]
    finished = threading.Event()

    def watchdog() -> None:
        while not finished.wait(5):
            if time.monotonic() - last_line[0] > JACKCESS_STALL_SECONDS:
                pipe.proc.kill()  # 読み出し側は「途中で終わった」で失敗し、次の手段へ回る
                return

    threading.Thread(target=watchdog, daemon=True).start()

    def call(*fields: str):
        """命令を1つ送り、「end」までの行（タブで割ったもの）を1行ずつ返す。ok・err は1行だけ返して終わる。"""
        pipe.send("\t".join(fields))
        while True:
            try:
                parts = pipe.readline().split("\t")
            except ra.Unavailable as e:
                raise RuntimeError(f"Jackcess の補助が途中で終わった: {e}") from None
            last_line[0] = time.monotonic()
            if parts[0] == "err":
                msg = ra._unb64(parts[1]) if len(parts) > 1 else ""
                if _is_password_error(msg):
                    raise NeedPassword("access", "Access にデータベースパスワードが掛かっている")
                raise RuntimeError(f"Jackcess で読めなかった: {msg[:200]}")
            if parts[0] in ("ok", "end"):
                if parts[0] == "ok":
                    yield parts
                return
            yield parts

    try:
        list(call("openro", ra._b64(path)))
        names = [ra._unb64(p[1]) for p in call("tables") if p[0] == "table"]
        n_tables = 0
        for name in sorted(names):
            if name.startswith(("MSys", "~")):
                continue
            columns = [ra._unb64(p[1]) for p in call("columns", ra._b64(name)) if p[0] == "col"]
            n_tables += 1
            col.pos_sheet = name
            if col.collect_positions:
                col.pos_info.setdefault("tables", {})[name] = {"columns": list(columns)}
            limit = ctx.options.max_rows_per_table or 0

            def rows(name=name, columns=columns, limit=limit):
                width = len(columns)
                for p in call("readall", ra._b64(name), str(limit)):
                    if p[0] != "row":
                        continue
                    cells = [ra._parse_cell(t) for t in p[2:]][:width]
                    # バイナリ・OLE の列は ODBC と同じく空にする（中身は生データ走査が拾う）
                    yield [None if isinstance(v, ra.Binary) else v for v in cells] + [None] * (width - len(cells))

            stream = rows()
            col.add_records(
                columns,
                stream,
                lambda r, c, name=name, columns=columns: f"表「{name}」{r}行目 列「{columns[c]}」",
                method="表のレコード（Jackcess）",
            )
            # 途中で読むのをやめても、残りの行を読み捨てる（残すと次の命令の返事として読まれ、やり取りがずれる）
            for _ in stream:
                pass
        if n_tables == 0:
            raise RuntimeError("表を1つも読めなかった")
    finally:
        finished.set()
        try:
            pipe.send("close")
        except Exception:  # noqa: BLE001  既に終わっていてよい
            pass
        pipe.close()
    return "Jackcess（Java）"


def _read_access_parser(ctx: ScanContext, path: str, col: Collector, item: ItemResult) -> str:
    import contextlib
    import io as _io
    import logging

    from access_parser import AccessParser

    # access_parser は版の推測などを画面やログへ出すので黙らせる（進捗表示に混ざらないように）
    logging.getLogger("access_parser").setLevel(logging.CRITICAL)
    logging.getLogger("access_parser.access_parser").setLevel(logging.CRITICAL)
    quiet = _io.StringIO()
    with contextlib.redirect_stdout(quiet), contextlib.redirect_stderr(quiet):
        db = AccessParser(path)
    n_tables = 0
    for name in list(db.catalog.keys()):
        if name.startswith(("MSys", "~")):
            continue
        try:
            with contextlib.redirect_stdout(quiet), contextlib.redirect_stderr(quiet):
                table = db.parse_table(name)
        except Exception as e:
            _failed_table(ctx, item.path, name, f"表を読めなかった（access_parser）: {e}", 0)
            continue
        n_tables += 1
        col.pos_sheet = name
        columns = list(table.keys())
        if col.collect_positions:
            col.pos_info.setdefault("tables", {})[name] = {"columns": list(columns)}
        length = max((len(v) for v in table.values()), default=0)

        def rows(table=table, columns=columns, length=length):
            for i in range(length):
                yield [table[c][i] if i < len(table[c]) else None for c in columns]

        col.add_records(
            columns,
            rows(),
            lambda r, c, name=name, columns=columns: f"表「{name}」{r}行目 列「{columns[c]}」",
            method="表のレコード（純Python）",
        )
    if n_tables == 0:
        raise RuntimeError("表を1つも読めなかった")
    return "access_parser（純 Python）"


def handle_access(ctx: ScanContext, blob: Blob, item: ItemResult, col: Collector, depth: int) -> None:
    head = blob.head(0x80)
    version = head[0x14] if len(head) > 0x14 else -1
    item.kind = {0: "Access 97（Jet3・mdb）", 1: "Access 2000-2003（Jet4・mdb）"}.get(
        version, "Access 2007以降（ACE・accdb）"
    )
    path = _private_copy(
        ctx,
        blob,
        blob.ext if blob.ext in (".mdb", ".accdb", ".mde", ".accde") else (".mdb" if version in (0, 1) else ".accdb"),
    )
    attempts: list[str] = []
    used = None
    need_pw = False
    if col.collect_positions:
        col.pos_layout = "access"  # 対処（remedy_access）の位置: シートは表の名前、行は通し番号、列は列の番号
    readers = (
        ("odbc", "64bit ODBC", lambda: _read_access_odbc(ctx, path, col, item, depth, blob.display)),
        ("helper32", "32bit 補助", lambda: _read_access_helper32(ctx, path, col, item, depth, blob.display)),
        ("jackcess", "Jackcess", lambda: _read_access_jackcess(ctx, path, col, item, depth, blob.display)),
        ("parser", "access_parser", lambda: _read_access_parser(ctx, path, col, item)),
    )
    forced = forced_readers()
    for key, label, fn in readers:
        if forced is not None and key not in forced:
            continue
        try:
            used = fn()
            break
        except NeedPassword:
            need_pw = True
            attempts.append(f"{label}: パスワードが違う")
        except Exception as e:
            attempts.append(f"{label}: {type(e).__name__}: {str(e)[:200]}")
        if col.collect_positions:
            # 途中まで読んで失敗した方法の位置は捨てる（次の方法が、同じ表をもう一度最初から数えるため）
            col.positions.clear()
            col.pos_info.clear()
            col.pos_total = 0
    if ctx.options.raw_sweep:
        _raw_sweep(path, col, raw=used is not None)
    if used:
        item.method = f"{used} で全テーブル＋ファイル全体の生データ走査（削除済みレコードの残留を含む）"
        if attempts:
            item.notes.append("先に試して失敗した方法: " + " / ".join(attempts))
        return
    if need_pw:
        n = len(ctx.password_candidates())
        raise NeedPassword(
            "access",
            (
                f"Access にデータベースパスワードが掛かっている（受け取ったパスワード {n} 個を試したが開けなかった）"
                if n
                else "Access にデータベースパスワードが掛かっている（パスワードを入力すると再検査できる）"
            ),
        )
    raise Uncheckable(
        "Access の表を読めなかった（生データ走査のみ。数値型の列は検査できていない）: " + " / ".join(attempts)
    )


# ------------------------------------------------------------------ SQLite


def handle_sqlite(ctx: ScanContext, blob: Blob, item: ItemResult, col: Collector, depth: int) -> None:
    path = _private_copy(ctx, blob, ".sqlite")
    try:
        conn = sqlite3.connect(f"file:{Path(path).as_posix()}?mode=ro&immutable=1", uri=True)
    except sqlite3.Error as e:
        raise Uncheckable(f"SQLite を開けなかった: {e}")
    ok = False
    try:
        names = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        # 対処のための位置集め: 行は rowid（rowid の無い表は通し番号）で残す。仮想表などは書き換えないので位置を集めない
        collecting = col.collect_positions
        unsafe = set()
        if collecting:
            from ..remedy_sqlite import unsafe_tables

            col.pos_layout = "sqlite"
            unsafe = unsafe_tables(conn)
        for name in names:
            alias = None
            if collecting:
                from ..remedy_sqlite import row_key_alias

                col.pos_sheet = name
                col.pos_off = name in unsafe
                alias = None if col.pos_off else row_key_alias(conn, name)
            q = '"' + name.replace(chr(34), chr(34) * 2) + '"'
            cur = conn.execute(f"SELECT {alias}, * FROM {q}" if alias else f"SELECT * FROM {q}")
            columns = [d[0] for d in cur.description][1 if alias else 0 :]
            cur_key = [0]  # いま読んでいる行の rowid

            def rows(cur=cur, alias=alias, cur_key=cur_key):
                while True:
                    batch = cur.fetchmany(1000)
                    if not batch:
                        break
                    if alias:
                        for row in batch:
                            cur_key[0] = row[0]
                            yield row[1:]
                    else:
                        yield from batch

            col.row_key = (lambda r, cur_key=cur_key: cur_key[0]) if alias else None
            try:
                col.add_records(
                    columns,
                    rows(),
                    lambda r, c, name=name, columns=columns: f"表「{name}」{r}行目 列「{columns[c]}」",
                    method="表のレコード",
                )
            finally:
                col.row_key = None
                col.pos_off = False
        ok = True
    except sqlite3.DatabaseError as e:
        item.notes.append(f"表を読めなかった（暗号化された SQLite の可能性）: {e}")
    finally:
        conn.close()
    _raw_sweep(path, col, raw=ok)
    item.method = ("全テーブル＋" if ok else "") + "ファイル全体の生データ走査（空き領域の残留を含む）"
    if not ok:
        raise Uncheckable("SQLite の表を読めなかった（暗号化の可能性。生データ走査のみ）")


# ------------------------------------------------------------------ dBase


def handle_dbf(ctx: ScanContext, blob: Blob, item: ItemResult, col: Collector, depth: int) -> None:
    data = blob.read_all()
    try:
        n_records = int.from_bytes(data[4:8], "little")
        header_len = int.from_bytes(data[8:10], "little")
        record_len = int.from_bytes(data[10:12], "little")
        fields = []
        pos = 32
        while pos + 32 <= header_len and data[pos] != 0x0D:
            name = data[pos : pos + 11].split(b"\x00", 1)[0].decode("cp932", errors="replace")
            length = data[pos + 16]
            fields.append((name, length))
            pos += 32
    except Exception as e:
        raise Uncheckable(f"dBase の見出しを読めなかった: {e}")
    columns = [f[0] for f in fields]
    deleted = 0
    truncated: list[int] = []

    def rows():
        nonlocal deleted
        for i in range(n_records):
            start = header_len + i * record_len
            rec = data[start : start + record_len]
            if len(rec) < record_len:
                truncated.append(i)
                break
            if rec[:1] == b"*":
                deleted += 1
            p = 1
            out = []
            for _, length in fields:
                out.append(rec[p : p + length].decode("cp932", errors="replace").strip())
                p += length
            yield out

    n = col.add_records(columns, rows(), lambda r, c: f"{r}行目 列「{columns[c]}」", method="レコード")
    item.method = f"dBase の全レコード {n} 件（削除フラグ付き {deleted} 件を含む）"
    if truncated:
        raise PartialScan(
            f"dBase のレコードが途中で切れている（見出しの件数 {n_records} 件のうち {truncated[0]} 件まで読んだ）"
        )

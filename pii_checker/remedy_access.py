"""対処（remediate）で、Access（.accdb・.mdb）を書き換える部分（T2-e）。

方法: 行を削除・列を削除・ダミー化・表を削除（ファイルの削除は remediate.py）。マクロ・フォーム・レポート・VBA・クエリ・
リレーションシップなど、表以外のオブジェクトは残す（表だけを新しいファイルへ写し直す作りはしない）。

決まり:
- 元のファイルは開いて書き換えない。元の写しを一時の名前（呼び出し側が決める）に作り、その写しの中を直接書き換える。
- 書き換えの手段は、次の順で、使えるものを使う（どれも、写しの中で直接書き換える）:
  1. ACE: 64bit の ACE ODBC ドライバ（pyodbc）で DELETE・UPDATE・ALTER TABLE DROP COLUMN・DROP TABLE → 最適化
     （DAO.DBEngine.120 の CompactDatabase。全オブジェクトを保つ）。
  2. Jet: .mdb で ACE が無いとき、Windows 標準の Jet 4.0（32bit のみ）を、同梱の 32bit Python の補助
     （access32_rewrite.py）で ODBC から動かして書き換え → JRO.JetEngine の CompactDatabase で最適化。
  3. Jackcess: ACE の無い .accdb は、Jackcess（Apache 2.0・Java）を同梱の Java 実行環境で動かす補助（tools/jackcess）で、
     写しの中の行を直接消す・値を直す。Jackcess は最適化できず、表・列そのものも消せないので、表は「全行の削除」・列は
     「全行の値を空に」で代え、書き換えたあとに access_scrub で消した行の跡と空き領域を 0 で塗りつぶす。
- 行の特定: 位置の行は「SELECT * の順の通し番号」（検査と同じ数え方）。書き換えるときにその場で行を読み直し、行の値
  （文字・整数・真偽。長さ 255 以下の文字列）の一致で行を特定する。主キーの有無に関わらない。消した行の数が位置の数と
  食い違えば、何も変えずに失敗する（写しは捨てる）。生の値は位置にも記録にも入れない。
- どの手段でも、書き換えたあとに、選んだ値（メモリの中だけに持つ）が写しのバイト列に1つでも残っていれば、確定させずに
  失敗する（消えた行の残りまで拾う）。最適化・塗りつぶしの出来を、値そのもので確かめる。
- 手段がどれも使えないときは、理由を出して失敗する（ファイルの削除だけができる）。
"""

from __future__ import annotations

import base64
import json
import mmap
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from . import detectors
from .remedy_write import DummyMaker, RemedyError, Selection, _orig_bounds, replace_spans

ACCESS_EXTS = (".accdb", ".mdb", ".accde", ".mde")
CREATE_NO_WINDOW = 0x08000000
# これより短い値（2 文字の姓など）は、ほかの場所に同じ並びが普通にあるので、バイト列の確かめの対象にしない
MIN_SECRET_CHARS = 3
MAX_SECRETS = 100_000
# 値の数 × ファイルの大きさ（バイト）の上限。これを超える確かめは、時間がかかりすぎるので断る
MAX_VERIFY_WORK = 4 * 10**11
STRATEGY_LABELS = {
    "ace": "ACE（64bit の ODBC ドライバ）",
    "jet": "Jet 4.0（Windows 標準・32bit の補助）",
    "jackcess": "Jackcess（Java）",
}
OPEN_TRIES = 3
OPEN_RETRY_SECONDS = 0.5
PASSWORD_REASON = (
    "データベースパスワードの掛かった Access は、いまは中身を書き換えられません。元のファイルは変えていません。"
    "ファイルの削除はできます"
)
LOCK_SUFFIXES = (".laccdb", ".ldb")
FORCED_STRATEGIES: list[str] | None = None  # 試験用: 手段をこれだけに絞る（ace・jet・jackcess）
STRATEGY_ENV = (
    "PIICHK_ACCESS_STRATEGY"  # 診断・別プロセスの試験用: 環境変数で手段を絞る（ace・jet・jackcess のコンマ区切り）
)


class Unavailable(Exception):
    """この手段では、このファイルを開けない・使えない（次の手段へ進む）。理由は利用者に見せない詳細。"""


@dataclass
class ColInfo:
    """表の列（SELECT * の順）。kind は text・memo・int・float・bool・date・bin・other。"""

    name: str
    kind: str


def bracket(name: str) -> str:
    """表名・列名を角括弧で囲む（] は ]] に）。"""
    return "[" + name.replace("]", "]]") + "]"


def sql_text(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


# ---------------------------------------------------------------- 使える手段の調べ方


def access_format(path: str) -> str:
    """ファイルの先頭から形式を返す（"jet3"・"jet4"・"ace"。Access でなければ空）。"""
    from .engine import long_path

    try:
        with open(long_path(path), "rb") as f:
            head = f.read(0x20)
    except OSError:
        return ""
    if head[4:19] == b"Standard Jet DB" and len(head) > 0x14:
        return "jet3" if head[0x14] == 0 else "jet4"
    if head[4:19] == b"Standard ACE DB":
        return "ace"
    return ""


def lock_file_problem(path: str) -> str:
    """元のファイルの隣にロックファイル（.laccdb・.ldb）があれば、断る理由（無ければ空）。他のプログラムが開いている印。"""
    if not os.path.isabs(path):
        return ""
    from .engine import long_path

    base, _ext = os.path.splitext(path)
    for suffix in LOCK_SUFFIXES:
        if os.path.exists(long_path(base + suffix)):
            return (
                f"ロックファイル「{os.path.basename(base + suffix)}」があるため、書き換えを取りやめます（Access などで"
                "開いている印です）。Access を閉じてから、もう一度実行してください。だれも開いていないのに残っている場合は、"
                "前に正しく閉じられなかった名残なので、そのロックファイルを消してから実行してください"
            )
    return ""


@lru_cache(maxsize=1)
def ace_odbc_driver() -> str | None:
    """64bit の ACE ODBC ドライバの名前（無ければ None）。"""
    try:
        import pyodbc
    except ImportError:
        return None
    for d in pyodbc.drivers():
        if "Access Driver" in d and "accdb" in d:
            return d
    return None


def find_rewrite_helper32(configured: str | None = None) -> list[str] | None:
    """32bit の書き換え補助（access32_rewrite.py）の起動コマンド（無ければ None）。検査用の補助と同じ置き場から探す。"""
    from .formats.database import find_helper32

    cmd = find_helper32(configured)
    if not cmd or len(cmd) < 2 or not cmd[0].lower().endswith("python.exe"):
        return None
    script = os.path.join(os.path.dirname(cmd[1]), "access32_rewrite.py")
    return [cmd[0], script] if os.path.isfile(script) else None


@lru_cache(maxsize=4)
def jet_available(cmd_key: tuple | None) -> bool:
    """Jet 4.0 の ODBC ドライバを、32bit の補助が使えるか（補助を一度起動して確かめる）。"""
    if not cmd_key:
        return False
    try:
        with HelperProcess(list(cmd_key)) as hp:
            reply = hp.call({"op": "probe"})
        return bool(reply.get("ok") and reply.get("drivers"))
    except Exception:  # noqa: BLE001  起動できなければ使えない
        return False


def _bundle_roots() -> list[Path]:
    roots = [Path(sys.executable).parent]
    if getattr(sys, "_MEIPASS", None):
        roots.insert(0, Path(sys._MEIPASS))
    return roots


def find_jackcess() -> dict | None:
    """Jackcess の補助を動かす環境（{"java": java.exe, "classpath": [jar...]}）。揃っていなければ None。

    探す場所: 環境変数 PIICHK_JACKCESS_DIR（jar の置き場）・PIICHK_JAVA（java.exe）→ 配布版の jackcess/・java/
    → 開発時のリポジトリの vendor/jackcess（jar の置き場）と、JAVA_HOME・PATH の java。
    jar は jackcess・commons-lang3・commons-logging と、補助そのもの（piichk-access.jar）の4つが要る。
    """
    jar_dirs: list[Path] = []
    if os.environ.get("PIICHK_JACKCESS_DIR"):
        jar_dirs.append(Path(os.environ["PIICHK_JACKCESS_DIR"]))
    java_candidates: list[str] = []
    if os.environ.get("PIICHK_JAVA"):
        java_candidates.append(os.environ["PIICHK_JAVA"])
    for root in _bundle_roots():
        jar_dirs.append(root / "jackcess")
        java_candidates.append(str(root / "java" / "bin" / "java.exe"))
    jar_dirs.append(Path(__file__).resolve().parent.parent / "vendor" / "jackcess")
    if os.environ.get("JAVA_HOME"):
        java_candidates.append(str(Path(os.environ["JAVA_HOME"]) / "bin" / "java.exe"))
    which = shutil.which("java")
    if which:
        java_candidates.append(which)
    java = next((j for j in java_candidates if os.path.isfile(j)), None)
    if not java:
        return None
    for d in jar_dirs:
        if not d.is_dir():
            continue
        jars = {p.name: p for p in d.glob("*.jar")}
        pick = []
        for prefix in ("jackcess-", "commons-lang3-", "commons-logging-", "piichk-access"):
            found = sorted(p for n, p in jars.items() if n.startswith(prefix))
            if not found:
                break
            pick.append(str(found[-1]))
        else:
            return {"java": java, "classpath": pick}
    return None


def forced_strategies() -> list[str] | None:
    """手段を絞る指定（試験用の変数 → 環境変数の順）。無ければ None（使えるものを全部、既定の順で）。"""
    if FORCED_STRATEGIES is not None:
        return FORCED_STRATEGIES
    raw = os.environ.get(STRATEGY_ENV, "").strip()
    return [x.strip() for x in raw.split(",") if x.strip()] if raw else None


def plan_strategies(path: str, fmt: str | None = None, only: list[str] | None = None) -> list[str]:
    """このファイルに、使える書き換えの手段を、試す順に返す（ACE → Jet → Jackcess）。"""
    fmt = fmt if fmt is not None else access_format(path)
    out: list[str] = []
    if fmt in ("jet4", "ace") and ace_odbc_driver():
        out.append("ace")
    if fmt in ("jet3", "jet4"):
        helper = find_rewrite_helper32()
        if helper and jet_available(tuple(helper)):
            out.append("jet")
    if fmt == "ace" and find_jackcess():
        out.append("jackcess")
    only = only if only is not None else forced_strategies()
    if only is not None:
        out = [s for s in out if s in only]
    return out


def unavailable_reason(path: str, fmt: str | None = None) -> str:
    """書き換えの手段がどれも無いときの理由（文面は利用者に見せる）。"""
    fmt = fmt if fmt is not None else access_format(path)
    if not fmt:
        return "Access のファイルとして読めません。ファイルの削除はできます"
    if fmt == "jet3":
        return (
            "この PC には、Access 97 の形式のファイルを書き換える部品がありません。Access で開いて新しい形式（.accdb）に"
            "保存し直してから、検査し直してください。ファイルの削除はできます"
        )
    if fmt == "jet4":
        return (
            "この PC には、この .mdb を書き換える部品がありません。IT 担当の方に「Microsoft Access Database Engine"
            "（64bit）」を入れてもらうと書き換えられます。ファイルの削除はできます"
        )
    return (
        "この PC には、この .accdb を書き換える部品がありません。IT 担当の方に「Microsoft Access Database Engine"
        "（64bit）」を入れてもらうと書き換えられます。ファイルの削除はできます（詳細: 同梱の Java 実行環境も見つかりません）"
    )


def format_from_kind(kind: str) -> str:
    """検査の種類名（「Access 2007以降（ACE・accdb）」など）から形式を返す（分からなければ空）。"""
    if "Jet3" in kind or "Access 97" in kind:
        return "jet3"
    if "Jet4" in kind:
        return "jet4"
    if "ACE" in kind:
        return "ace"
    return ""


def availability_reason(path: str, method: str, kind: str = "") -> str:
    """この方法を選べない理由（選べるなら空）。ファイルは開かない（形式の見出しと、使える部品の有無だけ）。

    圧縮ファイルの中のファイルは、分析のときには取り出した実ファイルが無い（path は中の名前）ので、形式を種類名 kind から決める。
    """
    problem = lock_file_problem(path)
    if problem:
        return problem
    fmt = access_format(path) if os.path.isabs(path) else ""
    if not fmt:
        fmt = format_from_kind(kind)
    if plan_strategies(path, fmt):
        return ""
    return unavailable_reason(path, fmt)


# ---------------------------------------------------------------- 補助プロセス（JSON の行・Jackcess の行）


class _Pipe:
    """子プロセス（32bit の補助・Java）と、1行ずつ話す。"""

    def __init__(self, cmd: list[str]):
        self.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            creationflags=CREATE_NO_WINDOW if os.name == "nt" else 0,
        )

    def send(self, line: str) -> None:
        assert self.proc.stdin is not None
        try:
            self.proc.stdin.write((line + "\n").encode("utf-8"))
            self.proc.stdin.flush()
        except OSError as e:
            raise Unavailable(f"補助プロセスへ送れません: {e}") from None

    def readline(self) -> str:
        assert self.proc.stdout is not None
        raw = self.proc.stdout.readline()
        if not raw:
            raise Unavailable("補助プロセスが途中で終わりました")
        return raw.decode("utf-8", errors="replace").rstrip("\r\n")

    def close(self) -> None:
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        if self.proc.stdout:
            self.proc.stdout.close()


class HelperProcess(_Pipe):
    """32bit の書き換え補助（access32_rewrite.py）。JSON の行で話す。"""

    def __enter__(self) -> "HelperProcess":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def call(self, req: dict) -> dict:
        self.send(json.dumps(req, ensure_ascii=False))
        try:
            return json.loads(self.readline())
        except ValueError:
            raise Unavailable("補助プロセスの返事を読めません") from None


# ---------------------------------------------------------------- 値の読み書き（ACE・Jet 共通の SQL）


class Binary:
    """バイナリの値（中身は持たない）。"""


def untag(v):
    """32bit の補助が型の目印つきで返した値を、Python の値に戻す。"""
    import datetime

    if isinstance(v, dict):
        if "i" in v:
            return int(v["i"])
        if "f" in v:
            try:
                return float(v["f"])
            except ValueError:
                return v["f"]
        if "d" in v:
            try:
                return datetime.datetime.fromisoformat(v["d"].replace(" ", "T"))
            except ValueError:
                return v["d"]
        return Binary()
    return v


def kind_from_pyodbc(type_code, size) -> str:
    import datetime
    import decimal

    if type_code is bool:
        return "bool"
    if type_code is int:
        return "int"
    if type_code in (float, decimal.Decimal):
        return "float"
    if type_code is str:
        return "text" if size and size <= 255 else "memo"
    if type_code in (datetime.datetime, datetime.date, datetime.time):
        return "date"
    if type_code in (bytes, bytearray):
        return "bin"
    return "other"


class OdbcBackend:
    """64bit の ACE ODBC ドライバで開く（pyodbc）。"""

    strategy = "ace"

    def __init__(self, path: str, driver: str):
        import pyodbc

        self._pyodbc = pyodbc
        from .engine import long_path

        msg = ""
        for attempt in range(OPEN_TRIES):
            try:
                self.conn = pyodbc.connect(f"DRIVER={{{driver}}};DBQ={long_path(path)};Exclusive=1;", autocommit=True)
                return
            except pyodbc.Error as e:
                msg = str(e)
                time.sleep(
                    OPEN_RETRY_SECONDS * (attempt + 1)
                )  # 書いたばかりのファイルを他のプログラムが一瞬つかむことがある
        if "-1905" in msg or "password" in msg.lower() or "パスワード" in msg:
            raise RemedyError(PASSWORD_REASON + f"（詳細: {_driver_message_text(msg)}）")
        raise Unavailable(f"ACE で開けません: {msg[:200]}")

    def _reading(self, what):
        """読み取りの失敗（ドライバのエラー）を、利用者向けの断りにする。"""
        try:
            return what()
        except self._pyodbc.Error as e:
            raise RemedyError(
                f"Access の表を読めませんでした。元のファイルは変えていません（詳細: {_driver_message(e)}）"
            ) from None

    def tables(self) -> list[str]:
        return self._reading(self._tables)

    def columns(self, table: str) -> list[ColInfo]:
        return self._reading(lambda: self._columns(table))

    def read_rows(self, table: str, wanted: set[int]) -> dict[int, list]:
        return self._reading(lambda: self._read_rows(table, wanted))

    def count(self, table: str) -> int:
        return self._reading(lambda: self._count(table))

    def _tables(self) -> list[str]:
        cur = self.conn.cursor()
        names = []
        for t in cur.tables():
            name, ttype = t.table_name, (t.table_type or "").upper()
            if name and not name.startswith(("MSys", "~")) and ttype == "TABLE":
                names.append(name)
        return names

    def _columns(self, table: str) -> list[ColInfo]:
        cur = self.conn.cursor()
        cur.execute(f"SELECT * FROM {bracket(table)} WHERE 1=0")
        return [ColInfo(d[0], kind_from_pyodbc(d[1], d[3])) for d in cur.description]

    def _read_rows(self, table: str, wanted: set[int]) -> dict[int, list]:
        out: dict[int, list] = {}
        last = max(wanted) if wanted else 0
        cur = self.conn.cursor()
        cur.execute(f"SELECT * FROM {bracket(table)}")
        n = 0
        while n < last:
            batch = cur.fetchmany(500)
            if not batch:
                break
            for row in batch:
                n += 1
                if n in wanted:
                    out[n] = [Binary() if isinstance(v, (bytes, bytearray)) else v for v in row]
                if n >= last:
                    break
        cur.close()
        return out

    def _count(self, table: str) -> int:
        cur = self.conn.cursor()
        try:
            cur.execute(f"SELECT COUNT(*) FROM {bracket(table)}")
            return int(cur.fetchone()[0])
        finally:
            cur.close()

    def execute(self, sql: str) -> int:
        cur = self.conn.cursor()
        try:
            cur.execute(sql)
            return cur.rowcount
        except self._pyodbc.Error as e:
            raise RemedyError(
                f"Access が操作を断りました。元のファイルは変えていません（詳細: {_driver_message(e)}）"
            ) from None
        finally:
            cur.close()

    def close(self) -> None:
        try:
            self.conn.close()
        except Exception:  # noqa: BLE001
            pass


# Jackcess の断り（英語）の、よくあるものの言い換え（小文字で探す）
JACKCESS_REASONS = (
    (
        "uniqueness",
        "置き換えた値が、重複を許さない列（一意の索引）の別の行の値と同じになるため、Access に断られました。"
        "「同じ値は同じダミー」を選ぶか（列の長さに収まらないときは）、行の削除を選んでください。",
    ),
    ("cannot be null", "空にできない列（必須の列）のため、Access に断られました。ダミーに置き換えを選んでください。"),
    (
        "too long",
        "置き換えた値が列の長さに収まらないため、Access に断られました。「固定の＊＊＊」のダミーを選んでください。",
    ),
    ("foreign key", "ほかの表から参照されている値のため、Access に断られました。ダミーに置き換えを選んでください。"),
)


def _detail_of(e: Exception) -> str:
    """断りの文から「詳細: …」の部分だけを取り出す（無ければ「詳細: 」＋全文）。入れ子の括弧を避けるため。"""
    text = str(e)
    at = text.find("詳細: ")
    return text[at:].rstrip("）") if at >= 0 else "詳細: " + text


def _driver_message_text(msg: str) -> str:
    """ドライバの返事の文を、短く1行にする（SQL の文・値は含まれない）。"""
    msg = msg.split("] ")[-1] if "] " in msg else msg
    return " ".join(msg.split())[:120]  # 改行・連続した空白を1つの空白にする


def _driver_message(e: Exception) -> str:
    """ドライバのエラーから、短い説明だけを取り出す（SQL の文・値は含まれない形に切る）。"""
    args = getattr(e, "args", ())
    msg = str(args[1]) if len(args) >= 2 else str(e)
    msg = msg.split("] ")[-1] if "] " in msg else msg
    return msg.replace("\r", " ").replace("\n", " ")[:160]


class HelperBackend:
    """32bit の補助（Jet 4.0 の ODBC）で開く。"""

    strategy = "jet"

    def __init__(self, path: str, cmd: list[str]):
        reply: dict = {}
        for attempt in range(OPEN_TRIES):
            self.helper = HelperProcess(cmd)
            try:
                reply = self.helper.call({"op": "open", "path": path})
            except Unavailable:
                self.helper.close()
                raise
            if reply.get("ok"):
                self.driver = reply.get("driver", "")
                return
            self.helper.close()
            time.sleep(
                OPEN_RETRY_SECONDS * (attempt + 1)
            )  # 書いたばかりのファイルを他のプログラムが一瞬つかむことがある
        if reply.get("code") == "password":
            raise RemedyError(PASSWORD_REASON + f"（詳細: {_driver_message_text(str(reply.get('message')))}）")
        raise Unavailable(f"Jet で開けません: {str(reply.get('message'))[:200]}")

    def _ok(self, req: dict) -> dict:
        reply = self.helper.call(req)
        if not reply.get("ok"):
            raise RemedyError(
                f"Access が操作を断りました。元のファイルは変えていません（詳細: {_driver_message_text(str(reply.get('message')))}）"
            )
        return reply

    def tables(self) -> list[str]:
        return list(self._ok({"op": "tables"})["tables"])

    def columns(self, table: str) -> list[ColInfo]:
        return [ColInfo(c["name"], c["kind"]) for c in self._ok({"op": "columns", "table": table})["columns"]]

    def read_rows(self, table: str, wanted: set[int]) -> dict[int, list]:
        reply = self._ok({"op": "read_rows", "table": table, "rows": sorted(wanted)})
        return {n: [untag(v) for v in values] for n, values in reply["rows"]}

    def count(self, table: str) -> int:
        return int(self._ok({"op": "count", "table": table})["count"])

    def execute(self, sql: str) -> int:
        return int(self._ok({"op": "execute", "sql": sql})["count"])

    def close(self) -> None:
        try:
            self.helper.call({"op": "close"})
        except Unavailable:
            pass
        self.helper.close()


def sql_literal(v) -> str | None:
    """WHERE・SET に書く値の形（書けない値は None）。"""
    if v is None:
        return "NULL"
    if isinstance(v, bool):
        return "True" if v else "False"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return sql_text(v)
    return None


def where_clause(cols: list[ColInfo], values: list) -> str:
    """行を特定する WHERE の中身。文字（255 字以下）・整数・真偽・空の列で一致させる（実数・日付・メモ・バイナリは使わない）。"""
    parts = []
    for c, v in zip(cols, values):
        q = bracket(c.name)
        if v is None:
            parts.append(f"{q} IS NULL")
        elif isinstance(v, bool) and c.kind == "bool":
            parts.append(f"{q}={'True' if v else 'False'}")
        elif isinstance(v, int) and not isinstance(v, bool) and c.kind == "int":
            parts.append(f"{q}={v}")
        elif isinstance(v, str) and c.kind == "text" and len(v) <= 255:
            parts.append(f"{q}={sql_text(v)}")
    if not parts:
        raise RemedyError(
            "行を特定できる列（文字・整数・真偽の列）が無いため、行を書き換えられません。ファイルの削除はできます"
        )
    return " AND ".join(parts)


class SqlSession:
    """ACE・Jet の、SQL で書き換える手段。"""

    def __init__(self, backend):
        self.b = backend
        self.strategy = backend.strategy

    def tables(self) -> list[str]:
        return self.b.tables()

    def columns(self, table: str) -> list[ColInfo]:
        return self.b.columns(table)

    def read_rows(self, table: str, wanted: set[int]) -> dict[int, list]:
        return self.b.read_rows(table, wanted)

    def count(self, table: str) -> int:
        return self.b.count(table)

    def delete_rows(self, table: str, cols: list[ColInfo], rows: dict[int, list]) -> int:
        signatures: dict[str, int] = {}
        for values in rows.values():
            w = where_clause(cols, values)
            signatures[w] = signatures.get(w, 0) + 1
        total = 0
        for w in signatures:
            n = self.b.execute(f"DELETE FROM {bracket(table)} WHERE {w}")
            total += max(n, 0)
        if total != len(rows):
            raise RemedyError(
                f"表「{table}」で、検査のときの位置と行の数が食い違いました（{len(rows)} 行のはずが {total} 行）。"
                "同じ内容の行が選ばなかった側にある、またはリレーションシップの連鎖削除で先に消えた可能性があります。"
                "何も変えていません"
            )
        return total

    def update_cells(
        self, table: str, cols: list[ColInfo], rows: dict[int, list], edits: dict[int, dict[int, str | int]]
    ) -> int:
        signatures: dict[tuple[str, str], int] = {}
        for r, cells in edits.items():
            sets = ",".join(f"{bracket(cols[c].name)}={sql_literal(v)}" for c, v in cells.items())
            key = (where_clause(cols, rows[r]), sets)
            signatures[key] = signatures.get(key, 0) + 1
        total = 0
        for (w, sets), expected in signatures.items():
            n = self.b.execute(f"UPDATE {bracket(table)} SET {sets} WHERE {w}")
            if n != expected:
                raise RemedyError(
                    f"表「{table}」で、置き換える行を特定できませんでした（{expected} 行のはずが {n} 行）。"
                    "リレーションシップの連鎖更新で、先に値が変わった可能性があります。何も変えていません"
                )
            total += n
        return total

    def drop_columns(self, table: str, names: list[str]) -> None:
        for name in names:
            try:
                self.b.execute(f"ALTER TABLE {bracket(table)} DROP COLUMN {bracket(name)}")
            except RemedyError as e:
                raise RemedyError(
                    f"表「{table}」の列「{name}」は、主キー・索引・リレーションシップ・検証規則などに使われているため、"
                    f"削除を断られました。元のファイルは変えていません。この列は「ダミーに置き換え」を選んでください"
                    f"（{_detail_of(e)}）"
                ) from None

    def drop_table(self, table: str) -> None:
        try:
            self.b.execute(f"DROP TABLE {bracket(table)}")
        except RemedyError as e:
            raise RemedyError(
                f"表「{table}」は、ほかの表からリレーションシップで参照されているため、削除を断られました。"
                f"元のファイルは変えていません。「行の削除」か「ダミーに置き換え」を選んでください（{_detail_of(e)}）"
            ) from None

    def close(self) -> None:
        self.b.close()


class JackcessSession:
    """ACE の無い .accdb の、Jackcess（Java）で書き換える手段。表・列そのものは消せないので、中身だけを消す。"""

    strategy = "jackcess"
    structure_kept = True  # 表・列の枠は残る（全行の削除・全行の値を空に）

    def __init__(self, path: str, env: dict):
        # ヒープは小さめにする（検査のワーカーの Job Object のメモリ上限の内側で動かすため。Jackcess は表を丸ごとは持たない）
        cmd = [env["java"], "-Xmx768m", "-XX:+UseSerialGC", "-cp", os.pathsep.join(env["classpath"]), "AccessRewrite"]
        try:
            self.pipe = _Pipe(cmd)
        except OSError as e:
            raise Unavailable(f"Java を起動できません: {e}") from None
        try:
            self._call("open", _b64(path))
        except Unavailable:
            self.pipe.close()
            raise
        except RemedyError as e:
            self.pipe.close()
            raise Unavailable(f"Jackcess で開けません: {e}") from None

    def _call(self, *fields: str, extra_lines: list[str] | None = None) -> list[list[str]]:
        """命令を1つ送り、「end」か「ok」か「err」までの行（タブで割ったもの）を返す。"""
        self.pipe.send("\t".join(fields))
        for line in extra_lines or []:
            self.pipe.send(line)
        out: list[list[str]] = []
        while True:
            parts = self.pipe.readline().split("\t")
            head = parts[0]
            if head == "err":
                msg = _unb64(parts[1]) if len(parts) > 1 else ""
                msg = re.sub(r"\[[^\]]*\]", "[…]", msg)  # 「New row [1, 山田, …] violates …」のような行の値は出さない
                msg = re.sub(r"\(Db=[^;)]*;?", "(", msg)  # 一時のファイル名は出さない
                for needle, plain in JACKCESS_REASONS:
                    if needle in msg.lower():
                        raise RemedyError(f"{plain}元のファイルは変えていません（詳細: {_driver_message_text(msg)}）")
                raise RemedyError(
                    f"Access の操作を断られました。元のファイルは変えていません（詳細: {_driver_message_text(msg)}）"
                )
            if head == "ok":
                return [parts]
            if head == "end":
                return out
            out.append(parts)

    def tables(self) -> list[str]:
        return [_unb64(p[1]) for p in self._call("tables") if p[0] == "table" and not _unb64(p[1]).startswith("~")]

    def columns(self, table: str) -> list[ColInfo]:
        return [ColInfo(_unb64(p[1]), p[2]) for p in self._call("columns", _b64(table)) if p[0] == "col"]

    def read_rows(self, table: str, wanted: set[int]) -> dict[int, list]:
        out: dict[int, list] = {}
        for p in self._call("read", _b64(table), ",".join(str(n) for n in sorted(wanted))):
            if p[0] == "row":
                out[int(p[1])] = [_parse_cell(t) for t in p[2:]]
        return out

    def count(self, table: str) -> int:
        return int(self._call("count", _b64(table))[0][1])

    def delete_rows(self, table: str, cols: list[ColInfo], rows: dict[int, list]) -> int:
        n = int(self._call("delete", _b64(table), ",".join(str(r) for r in sorted(rows)))[0][1])
        if n != len(rows):
            raise RemedyError(
                f"表「{table}」で、検査のときの位置と行の数が食い違いました（{len(rows)} 行のはずが {n} 行）。何も変えていません"
            )
        return n

    def update_cells(
        self, table: str, cols: list[ColInfo], rows: dict[int, list], edits: dict[int, dict[int, str | int]]
    ) -> int:
        lines = []
        for r in sorted(edits):
            cells = []
            for c, v in edits[r].items():
                token = "s" + _b64(v) if isinstance(v, str) else "i" + str(v)
                cells += [str(c), token]
            lines.append("\t".join([str(r), *cells]))
        n = int(self._call("update", _b64(table), str(len(lines)), extra_lines=lines)[0][1])
        if n != len(edits):
            raise RemedyError(f"表「{table}」で、置き換える行を特定できませんでした。何も変えていません")
        return n

    def drop_columns(self, table: str, names: list[str]) -> None:
        cols = [c.name for c in self.columns(table)]
        idx = ",".join(str(cols.index(n)) for n in names)
        self._call("clearcols", _b64(table), idx)

    def drop_table(self, table: str) -> None:
        self._call("emptytable", _b64(table))

    def close(self) -> None:
        try:
            self._call("close")
        except (Unavailable, RemedyError):
            pass
        self.pipe.close()


def _b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def _unb64(s: str) -> str:
    return base64.b64decode(s).decode("utf-8", errors="replace")


def _parse_cell(token: str):
    if token == "-":
        return None
    kind, body = token[0], token[1:]
    if kind == "s":
        return _unb64(body)
    if kind == "i":
        return int(body)
    if kind == "f":
        try:
            return float(body)
        except ValueError:
            return body
    if kind == "b":
        return body == "1"
    if kind == "d":
        return body
    return Binary()


# ---------------------------------------------------------------- 最適化（ACE・Jet）


_COMPACT_JS = r"""
function dec(h) { var s = ""; for (var i = 0; i + 4 <= h.length; i += 4) { s += String.fromCharCode(parseInt(h.substr(i, 4), 16)); } return s; }
var mode = WScript.StdIn.ReadLine();
var src = dec(WScript.StdIn.ReadLine());
var dst = dec(WScript.StdIn.ReadLine());
var extra = WScript.StdIn.ReadLine();
if (mode == "dao") {
  var eng = new ActiveXObject(extra);
  eng.CompactDatabase(src, dst);
} else {
  var jro = new ActiveXObject("JRO.JetEngine");
  var prov = "Provider=Microsoft.Jet.OLEDB.4.0;Data Source=";
  jro.CompactDatabase(prov + src, prov + dst + ";Jet OLEDB:Engine Type=" + extra);
}
WScript.Echo("compacted");
"""


def _hex_utf16(s: str) -> str:
    return "".join(f"{unit:04x}" for unit in memoryview(s.encode("utf-16-le")).cast("H"))


def _cscript(bits: int) -> str | None:
    """bits ビットの cscript.exe のパス（64bit の Windows では、64bit が System32・32bit が SysWOW64）。"""
    windir = os.environ.get("WINDIR", r"C:\Windows")
    if bits == 32:
        cands = [os.path.join(windir, "SysWOW64", "cscript.exe"), os.path.join(windir, "System32", "cscript.exe")]
    elif struct_bits() == 32:
        cands = [os.path.join(windir, "Sysnative", "cscript.exe")]  # 32bit のプロセスから 64bit の System32 を見る別名
    else:
        cands = [os.path.join(windir, "System32", "cscript.exe")]
    return next((c for c in cands if os.path.isfile(c)), None)


def struct_bits() -> int:
    import ctypes

    return ctypes.sizeof(ctypes.c_void_p) * 8


def compact_database(src: str, dst: str, strategy: str, fmt: str, timeout: int = 600) -> None:
    """Access の最適化（CompactDatabase）で、src を整理した新しいファイル dst を作る。全オブジェクトを保つ。失敗は Unavailable。

    ACE は 64bit の cscript で DAO.DBEngine.120、Jet は 32bit の cscript で JRO.JetEngine（Jet 4 は Engine Type=5、
    Access 97 は 4）。パスは UTF-16 の16進で標準入力から渡す（cscript の引数の文字コードに左右されないように）。
    """
    if os.name != "nt":
        raise Unavailable("最適化は Windows でだけ使えます")
    if strategy == "ace":
        cscript = _cscript(64)
        mode, extra = "dao", "DAO.DBEngine.120"
    else:
        cscript = _cscript(32)
        mode, extra = "jro", "4" if fmt == "jet3" else "5"
    if not cscript:
        raise Unavailable("cscript.exe が見つかりません")
    fd_path = None
    try:
        import tempfile

        fd, fd_path = tempfile.mkstemp(prefix="piichk_compact_", suffix=".js")
        with os.fdopen(fd, "w", encoding="ascii") as fh:
            fh.write(_COMPACT_JS)
        proc = subprocess.run(
            [cscript, "//nologo", "//E:jscript", fd_path],
            input=f"{mode}\r\n{_hex_utf16(src)}\r\n{_hex_utf16(dst)}\r\n{extra}\r\n".encode("ascii"),
            capture_output=True,
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        raise Unavailable(f"最適化を実行できません: {type(e).__name__}") from None
    finally:
        if fd_path:
            try:
                os.remove(fd_path)
            except OSError:
                pass
    if proc.returncode != 0 or not os.path.isfile(dst):
        raise Unavailable("最適化に失敗しました: " + proc.stderr.decode("cp932", errors="replace").strip()[:200])


# ---------------------------------------------------------------- 値が残っていないかの確かめ


def secret_values(text: str, spans: list[tuple[int, int, str]]) -> set[str]:
    """セルの文字 text の、検出した部分（正規化後の位置 spans）の値を返す（元の書き方と、正規化した書き方の両方）。"""
    norm = detectors.normalize(text)
    bounds = _orig_bounds(text, norm)
    out: set[str] = set()
    for s, e, _t in spans:
        if not (0 <= s < min(e, len(norm))):
            continue
        e = min(e, len(norm))
        out.add(norm[s:e])
        if bounds is not None:
            os_, oe = bounds(s, e)
            out.add(text[os_:oe])
    return out


def _patterns(secret: str) -> set[bytes]:
    """値が、Access のファイルに入りうる書き方（UTF-16LE・圧縮 Unicode と ANSI の ASCII・UTF-8・cp932）。"""
    pats = set()
    for enc in ("utf-16-le", "utf-8", "cp932", "latin-1"):
        try:
            pats.add(secret.encode(enc))
        except UnicodeEncodeError:
            continue
    return pats


def count_remaining(path: str, secrets: set[str], produced: set[str] | None = None) -> int:
    """ファイルのバイト列に、残っている値の種類数を数える（値そのものは返さない）。短すぎる値は対象にしない。"""
    from .engine import long_path

    wanted = {s for s in secrets if len(s) >= MIN_SECRET_CHARS and s.strip() and not (produced and s in produced)}
    if not wanted:
        return 0
    size = os.path.getsize(long_path(path))
    if len(wanted) > MAX_SECRETS or len(wanted) * size > MAX_VERIFY_WORK:
        raise RemedyError(
            "消す値の数が多すぎて、書き換えたあとに値が残っていないかを確かめきれません（時間がかかりすぎるため）。"
            "範囲を絞って、何回かに分けてお試しください。何も変えていません"
        )
    found = 0
    with open(long_path(path), "rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            for s in wanted:
                if any(mm.find(p) >= 0 for p in _patterns(s)):
                    found += 1
    return found


# ---------------------------------------------------------------- 書き換え本体


def _cell_text(v) -> str:
    from .engine import _cell_to_str

    if v is None or isinstance(v, Binary):
        return ""
    return _cell_to_str(v)


def _apply(session, method: str, sel: Selection, maker: DummyMaker | None) -> tuple[dict, set[str]]:
    """選びを、開いた手段で書き換える。(件数, 選んだ値の集まり（メモリの中だけ）) を返す。"""
    stats = {"rows": 0, "cols": 0, "tables": 0, "cells": 0, "detections": 0}
    secrets: set[str] = set()
    existing = set(session.tables())
    spans_by_table = sel.spans()
    rows_by_table = sel.rows()
    cols_by_table = sel.cols()
    # 書き換えより前に、選んだ表の行をすべて読んでおく（前の表の書き換えが、連鎖削除で後の表の行の番号をずらすため）
    loaded: dict[str, tuple[list[ColInfo], dict[int, list]]] = {}
    for table in sel.sheets():
        if table not in existing:
            raise RemedyError(
                f"表「{table}」が見つかりません（検査のあとにファイルが変わった可能性）。何も変えていません"
            )
        cols = session.columns(table)
        wanted = set(rows_by_table[table])
        data = session.read_rows(table, wanted)
        missing = wanted - set(data)
        if missing:
            raise RemedyError(
                f"表「{table}」で、検査のときの位置の行が見つかりません（{len(missing)} 行）。何も変えていません"
            )
        for (r, c), lst in spans_by_table[table].items():
            if c >= len(cols) or c >= len(data[r]):
                raise RemedyError(f"表「{table}」の列の数が検査のときと合いません。何も変えていません")
            secrets |= secret_values(_cell_text(data[r][c]), lst)
        loaded[table] = (cols, data)
    # 連鎖削除（リレーションシップ）で、ほかの表（選んだ表を含む）の行まで消えていないかを、表を1つ処理するたびに
    # 全表の行数を予定と比べて確かめる
    expected = {t: session.count(t) for t in sorted(existing)}
    for table, (cols, data) in loaded.items():
        if method == "delete_rows":
            n = session.delete_rows(table, cols, data)
            stats["rows"] += n
            expected[table] -= n
        elif method == "delete_columns":
            idxs = sorted(cols_by_table[table])
            if len(idxs) >= len(cols):
                raise RemedyError(
                    f"表「{table}」のすべての列は削除できません（列が1つも残りません）。表ごと消すなら「表を削除」を選んでください"
                )
            session.drop_columns(table, [cols[i].name for i in idxs])
            stats["cols"] += len(idxs)
        elif method == "delete_table":
            session.drop_table(table)
            stats["tables"] += 1
            if getattr(session, "structure_kept", False):
                expected[table] = 0  # 表の枠は残り、全行が消える
            else:
                expected.pop(table)
        elif method == "dummy":
            edits = _dummy_edits(table, cols, data, spans_by_table[table], maker, stats)
            if edits:
                session.update_cells(table, cols, data, edits)
        else:
            raise RemedyError("この方法は Access に使えません")
        changed = [t for t, n in expected.items() if session.count(t) != n]
        if changed:
            raise RemedyError(
                "表「"
                + "」「".join(changed[:5])
                + "」の行が、リレーションシップの連鎖削除で一緒に消えたため、書き換えを取りやめました（選んでいない行が"
                "消えないようにするため）。元のファイルは変えていません。親と子の表を両方選んでいるときは、子の表だけ・"
                "親の表だけと分けて実行するか、ダミーに置き換えを選んでください"
            )
    if method == "dummy" and stats["cells"] == 0:
        raise RemedyError(
            "書き換える値が見つかりませんでした（文字・整数の列だけが対象です）。元のファイルは変えていません"
        )
    return stats, secrets


def _dummy_edits(table, cols, data, spans, maker, stats) -> dict[int, dict[int, str | int]]:
    edits: dict[int, dict[int, str | int]] = {}
    for (r, c), lst in sorted(spans.items()):
        v = data[r][c]
        text = _cell_text(v)
        if not text:
            continue
        if not (isinstance(v, str) or (isinstance(v, int) and not isinstance(v, bool))):
            raise RemedyError(
                f"表「{table}」の列「{cols[c].name}」は、文字・整数以外の型（{cols[c].kind}）のため、ダミーに置き換えられません。"
                "行の削除か、列の削除を選んでください"
            )
        new = replace_spans(text, lst, maker)
        if new == text:
            continue
        if isinstance(v, int):
            try:
                edits.setdefault(r, {})[c] = int(new)
            except ValueError:
                raise RemedyError(
                    f"表「{table}」の列「{cols[c].name}」は整数の列のため、文字のダミーを入れられません。"
                    "行の削除か、列の削除を選んでください"
                ) from None
        else:
            edits.setdefault(r, {})[c] = new
        stats["cells"] += 1
        stats["detections"] += len(lst)
    return edits


def _remove_locks(path: str) -> None:
    from .engine import long_path

    base, _ext = os.path.splitext(path)
    for suffix in LOCK_SUFFIXES:
        try:
            os.remove(long_path(base + suffix))
        except OSError:
            pass


def _open_session(strategy: str, path: str):
    if strategy == "ace":
        return SqlSession(OdbcBackend(path, ace_odbc_driver() or ""))
    if strategy == "jet":
        cmd = find_rewrite_helper32()
        if not cmd:
            raise Unavailable("32bit の補助が見つかりません")
        return SqlSession(HelperBackend(path, cmd))
    env = find_jackcess()
    if not env:
        raise Unavailable("Jackcess の部品が見つかりません")
    return JackcessSession(path, env)


def _copy(src: str, dst: str) -> None:
    from .engine import long_path

    shutil.copyfile(long_path(src), long_path(dst))


def _discard(path: str) -> None:
    from .engine import long_path

    try:
        os.remove(long_path(path))
    except OSError:
        pass


def rewrite_access_file(
    src: str,
    dst: str,
    method: str,
    sel: Selection,
    maker: DummyMaker | None,
    strategies: list[str] | None = None,
) -> dict:
    """Access のファイル src の写しを dst に作り、選んだ方法で書き換える（最適化・検査つき）。元の src には書かない。

    strategies は試す手段を絞る（試験用。ACE・Jet・Jackcess の名前）。戻り値は件数・使った手段・知らせ（notes）。
    """
    problem = lock_file_problem(src)
    if problem:
        raise RemedyError(problem)
    fmt = access_format(src)
    if not fmt:
        raise RemedyError("Access のファイルとして読めません。元のファイルは変えていません")
    plan = plan_strategies(src, fmt, strategies)
    if not plan:
        raise RemedyError(unavailable_reason(src, fmt))
    notes: list[str] = []
    session = None
    used = ""
    for strategy in plan:
        try:
            _copy(src, dst)
            session = _open_session(strategy, dst)
            used = strategy
            break
        except Unavailable as e:
            notes.append(f"{STRATEGY_LABELS[strategy]}では開けませんでした（{str(e)[:160]}）")
            _remove_locks(dst)
            _discard(dst)
    if session is None:
        _discard(dst)
        raise RemedyError(
            "この Access ファイルを開けませんでした（ほかのプログラムが使っている、または壊れている可能性があります）。"
            "元のファイルは変えていません。開いているプログラムを閉じてからもう一度実行するか、ファイルの削除を選んでください"
            "（詳細: " + " / ".join(notes) + "）"
        )
    secrets: set[str] = set()
    try:
        try:
            stats, secrets = _apply(session, method, sel, maker)
        finally:
            session.close()
            _remove_locks(dst)
        compacted = _optimize(dst, used, fmt, notes, secrets)
        produced = set(maker.produced) if maker else set()
        left = count_remaining(dst, secrets, produced)
        if left:
            raise RemedyError(
                f"書き換えたあとのファイルに、消すはずの値が {left} 種類まだ残っていたため、書き換えを取りやめました"
                "（値は表示しません）。元のファイルは変えていません。選んでいない行・列・表（確度の低い検出を含む）に"
                "同じ値があるのが主な原因です。選ぶ確度を広げるか、表の削除、またはファイルの削除を選んでください"
            )
    except BaseException:
        _remove_locks(dst)
        _discard(dst)
        raise
    stats["engine"] = STRATEGY_LABELS[used]
    stats["compacted"] = compacted
    stats["verified_values"] = len([s for s in secrets if len(s) >= MIN_SECRET_CHARS])
    summary = (
        ("Access の整理（最適化）をかけ、" if compacted else "消した行の跡と空き領域を消し、")
        + f"消した値 {stats['verified_values']:,} 種類が、ファイルの中に残っていないことを確かめました"
        + f"（詳細: {STRATEGY_LABELS[used]}）"
    )
    kept = (
        ["表・列の枠は残し、中身だけを消しました（この部品では表・列そのものを消せないため）"]
        if used == "jackcess" and method in ("delete_columns", "delete_table")
        else []
    )
    stats["notes"] = [summary, *kept, *notes]
    return stats


def _optimize(dst: str, strategy: str, fmt: str, notes: list[str], secrets: set[str]) -> bool:
    """書き換えた写しを最適化する（ACE・Jet）か、消した跡を塗りつぶす（Jackcess。最適化できなかったときの代わりにも）。

    最適化したかどうか（True）を返す。塗りつぶしだけのときは False。
    """
    from .access_scrub import ScrubUnsupported, scrub_file, scrub_orphan_long_values

    if strategy in ("ace", "jet"):
        from .remediate import CMP_PREFIX

        tmp = os.path.join(os.path.dirname(dst) or ".", CMP_PREFIX + os.path.basename(dst))
        _discard(tmp)
        try:
            compact_database(dst, tmp, strategy, fmt)
            os.replace(tmp, dst)
            return True
        except Unavailable as e:
            notes.append(
                f"Access の整理（最適化）ができなかったため、代わりに消した行の跡を直接消しました（詳細: {e}）"
            )
        finally:
            _discard(tmp)
    try:
        scrub_file(dst)
        scrub_orphan_long_values(dst)
    except ScrubUnsupported as e:
        raise RemedyError(f"消した行の跡を片付けられません（{e}）。元のファイルは変えていません") from None
    return False


# ---------------------------------------------------------------- 下見

ENGINE_NOTES = {
    "ace": "この PC の Access の部品で、写しを書き換えます",
    "jet": "Windows に入っている古い Access の部品で、写しを書き換えます",
    "jackcess": "同梱の Access 読み書き部品で、写しを書き換えます",
}


def engine_summary(path: str) -> dict:
    """下見に出す、使う手段（試す順）。ファイルは開かない。"""
    plan = plan_strategies(path)
    return {"strategies": plan, "engine": STRATEGY_LABELS[plan[0]] if plan else "", "format": access_format(path)}


def access_warnings(method: str, sel: Selection, schema: dict) -> tuple[list[str], list[str]]:
    """Access の下見の注意（値は含めない）。(warnings＝消える・戻せない・壊れうるもの, notes＝仕組み・保たれるもの)。"""
    info = (schema or {}).get("access") or {}
    plan = info.get("strategies") or []
    first = plan[0] if plan else ""
    warnings: list[str] = []
    notes: list[str] = []
    if first:
        notes.append(f"{ENGINE_NOTES[first]}（元のファイルは書き換えません。詳細: {STRATEGY_LABELS[first]}）")
    if first in ("ace", "jet"):
        notes.append(
            "書き換えたあと Access の整理（最適化）をかけ、消した行の残りもファイルから取り除きます。"
            "フォーム・マクロ・レポート・VBA・クエリ・リレーションシップなど、表以外のものはそのまま残ります"
        )
    elif first == "jackcess":
        notes.append(
            "書き換えたあと、消した行の跡と空き領域を、ファイルの中から直接消します。"
            "フォーム・マクロ・レポート・VBA・クエリ・リレーションシップなど、表以外のものはそのまま残ります"
        )
    notes.append(
        "書き換えたあと、消した値がファイルの中に残っていないか調べ、1つでも残っていれば取りやめます（何も変わりません）。"
        "2 文字以下の短い値は、ほかの場所の同じ並びと区別できないため調べません"
    )
    if method == "delete_rows":
        if first == "jackcess":
            warnings.append(
                "この部品はリレーションシップの連鎖削除を行わないため、この表を参照する別の表の行は、そのまま残ります"
            )
        else:
            warnings.append(
                "この表を参照する別の表の行も一緒に消える設定（連鎖削除）のときは、選んでいない行まで消えるため取りやめます"
                "（何も変わりません）"
            )
    if method == "delete_columns":
        if first == "jackcess":
            warnings.append(
                "この部品では列そのものは消せないため、列は残り、全行の値が空になります。その列を使うフォーム・クエリは"
                "開けますが、中身は空になります（空にできない必須の列なら取りやめます。何も変わりません）"
            )
        else:
            warnings.append(
                "その列を使うフォーム・クエリ・レポートは、あとで動かなくなります。主キー・索引・検証規則に使われている列は"
                "削除を断られ、取りやめます（何も変わりません）"
            )
    if method == "delete_table":
        if first == "jackcess":
            warnings.append(
                "この部品では表そのものは消せないため、表の枠（列の定義・索引）は残り、全行が消えます。"
                "表のデータはすべて消えます（検出した行だけではありません）"
            )
        else:
            warnings.append(
                "その表を使うフォーム・クエリ・レポート・マクロは、あとで動かなくなります。表のデータはすべて消えます"
                "（検出した行だけではありません）"
            )
    if method == "dummy":
        warnings.append(
            "文字・整数の列だけを置き換えます。列の長さに収まらないダミーや、一意の索引・検証規則に反するダミーは取りやめます"
            "（何も変わりません。「固定の＊＊＊」「形を保つ」のほうが収まりやすいです）"
        )
    return warnings, notes

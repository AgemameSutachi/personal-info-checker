"""Access データベースを 32bit プロセスで読み、内容を JSON Lines で標準出力へ流す補助スクリプト。

64bit の本体が ACE ドライバで読めなかったとき（Access 97 = Jet3 形式、64bit の ACE が無い PC、
32bit Office しか無い PC 等）に、本体が子プロセスとして呼び出す。

呼び方::

    python access32_helper.py <dbパス> [--password-file <ファイル>] [--max-rows-per-table N]

依存は標準ライブラリだけで動く（ODBC は ctypes で直接呼ぶ）。pyodbc が入っていればそちらを
優先して使い、pywin32 が入っていれば DAO（DBEngine.36 / .120）での読み取りも試す。
``pii_checker`` パッケージは import しない（単独の exe にするため）。

出力（1行1件・UTF-8・ensure_ascii=False）::

    {"type":"open","driver":...,"method":"odbc"|"dao","password_used":bool}
    {"type":"table","name":...,"columns":[...]}
    {"type":"row","table":...,"row":n,"values":[...]}
    {"type":"blob","table":...,"column":...,"row":n,"data_b64":...}
    {"type":"warning","message":...}
    {"type":"error","code":"password"|"driver_missing"|"corrupt"|"unsupported"|"other","message":...}
    {"type":"done","tables":n,"rows":n}

終了コード: 正常 0、致命的な失敗（error を出したとき）2。
DB ファイルは読み取り専用で開き、決して変更しない。
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import datetime
import decimal
import json
import os
import sys
from typing import Any, Callable, Iterator

# 1件のバイナリをこれより大きければ出力しない（本体側のメモリと JSON 1行の大きさを守るため）
MAX_BLOB_BYTES = 50 * 1024 * 1024
# 一度に取り出す行数（巨大な表でもメモリを食い潰さないため）
FETCH_BATCH = 200

ODBC_DRIVER_ACE = "Microsoft Access Driver (*.mdb, *.accdb)"
ODBC_DRIVER_JET = "Microsoft Access Driver (*.mdb)"
DAO_PROGIDS = ("DAO.DBEngine.36", "DAO.DBEngine.120")

EXIT_OK = 0
EXIT_ERROR = 2


# ---------------------------------------------------------------------------
# 出力
# ---------------------------------------------------------------------------
class Emitter:
    """JSON Lines を標準出力へ1行ずつ書いて flush する。"""

    def __init__(self, stream=None) -> None:
        self._stream = stream if stream is not None else sys.stdout.buffer

    def emit(self, obj: dict) -> None:
        """1件を書き出す。"""
        line = json.dumps(obj, ensure_ascii=False) + "\n"
        self._stream.write(line.encode("utf-8"))
        self._stream.flush()

    def warning(self, message: str) -> None:
        """警告（処理は続ける）を書き出す。"""
        self.emit({"type": "warning", "message": message})


class OversizeBlob:
    """上限を超えたバイナリの代わりに返す目印。"""

    def __init__(self, size_at_least: int) -> None:
        self.size_at_least = size_at_least


class AccessOpenError(Exception):
    """DB を開けなかったときの例外。code は本体との約束の分類。"""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class DriverError(Exception):
    """ドライバが返した失敗。sqlstate・native は ODBC のもの（DAO では native に DAO のエラー番号）。"""

    def __init__(self, message: str, sqlstate: str = "", native: int = 0) -> None:
        super().__init__(message)
        self.message = message
        self.sqlstate = sqlstate
        self.native = native


# ---------------------------------------------------------------------------
# ctypes による ODBC（pyodbc が無い環境用。PyInstaller の exe を小さく保つ意味もある）
# ---------------------------------------------------------------------------
SQL_HANDLE_ENV = 1
SQL_HANDLE_DBC = 2
SQL_HANDLE_STMT = 3
SQL_SUCCESS = 0
SQL_SUCCESS_WITH_INFO = 1
SQL_NO_DATA = 100
SQL_NULL_DATA = -1
SQL_NO_TOTAL = -4
SQL_NTS = -3
SQL_ATTR_ODBC_VERSION = 200
SQL_OV_ODBC3 = 3
SQL_ATTR_ACCESS_MODE = 101
SQL_MODE_READ_ONLY = 1
SQL_DRIVER_NOPROMPT = 0
SQL_FETCH_NEXT = 1
SQL_FETCH_FIRST = 2
SQL_CLOSE = 0
SQL_C_WCHAR = -8
SQL_C_BINARY = -2

# 列の型（SQLDescribeCol の DataType）
SQL_BINARY_TYPES = {-2, -3, -4}
SQL_TIMESTAMP_TYPES = {93, 11, 9, 91}  # TIMESTAMP（ODBC3/2）・DATE
SQL_BIT = -7

_GETDATA_CHUNK = 64 * 1024

SQLHANDLE = ctypes.c_void_p
SQLLEN = ctypes.c_ssize_t
SQLULEN = ctypes.c_size_t
SQLSMALLINT = ctypes.c_short
SQLUSMALLINT = ctypes.c_ushort
SQLINTEGER = ctypes.c_int
SQLRETURN = ctypes.c_short


def _ok(ret: int) -> bool:
    """SQLRETURN が成功（情報つき成功を含む）か。"""
    return ret in (SQL_SUCCESS, SQL_SUCCESS_WITH_INFO)


class CtypesOdbc:
    """odbc32.dll を ctypes で直接呼ぶ最小限の ODBC ラッパー。"""

    def __init__(self) -> None:
        dll = ctypes.WinDLL("odbc32")
        self._dll = dll
        f = dll.SQLAllocHandle
        f.argtypes = [SQLSMALLINT, SQLHANDLE, ctypes.POINTER(SQLHANDLE)]
        f.restype = SQLRETURN
        f = dll.SQLFreeHandle
        f.argtypes = [SQLSMALLINT, SQLHANDLE]
        f.restype = SQLRETURN
        f = dll.SQLSetEnvAttr
        f.argtypes = [SQLHANDLE, SQLINTEGER, ctypes.c_void_p, SQLINTEGER]
        f.restype = SQLRETURN
        f = dll.SQLSetConnectAttrW
        f.argtypes = [SQLHANDLE, SQLINTEGER, ctypes.c_void_p, SQLINTEGER]
        f.restype = SQLRETURN
        f = dll.SQLDriverConnectW
        f.argtypes = [
            SQLHANDLE,
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            SQLSMALLINT,
            ctypes.c_wchar_p,
            SQLSMALLINT,
            ctypes.POINTER(SQLSMALLINT),
            SQLUSMALLINT,
        ]
        f.restype = SQLRETURN
        f = dll.SQLDisconnect
        f.argtypes = [SQLHANDLE]
        f.restype = SQLRETURN
        f = dll.SQLGetDiagRecW
        f.argtypes = [
            SQLSMALLINT,
            SQLHANDLE,
            SQLSMALLINT,
            ctypes.c_wchar_p,
            ctypes.POINTER(SQLINTEGER),
            ctypes.c_wchar_p,
            SQLSMALLINT,
            ctypes.POINTER(SQLSMALLINT),
        ]
        f.restype = SQLRETURN
        f = dll.SQLDriversW
        f.argtypes = [
            SQLHANDLE,
            SQLUSMALLINT,
            ctypes.c_wchar_p,
            SQLSMALLINT,
            ctypes.POINTER(SQLSMALLINT),
            ctypes.c_wchar_p,
            SQLSMALLINT,
            ctypes.POINTER(SQLSMALLINT),
        ]
        f.restype = SQLRETURN
        f = dll.SQLTablesW
        f.argtypes = [
            SQLHANDLE,
            ctypes.c_wchar_p,
            SQLSMALLINT,
            ctypes.c_wchar_p,
            SQLSMALLINT,
            ctypes.c_wchar_p,
            SQLSMALLINT,
            ctypes.c_wchar_p,
            SQLSMALLINT,
        ]
        f.restype = SQLRETURN
        f = dll.SQLExecDirectW
        f.argtypes = [SQLHANDLE, ctypes.c_wchar_p, SQLINTEGER]
        f.restype = SQLRETURN
        f = dll.SQLNumResultCols
        f.argtypes = [SQLHANDLE, ctypes.POINTER(SQLSMALLINT)]
        f.restype = SQLRETURN
        f = dll.SQLDescribeColW
        f.argtypes = [
            SQLHANDLE,
            SQLUSMALLINT,
            ctypes.c_wchar_p,
            SQLSMALLINT,
            ctypes.POINTER(SQLSMALLINT),
            ctypes.POINTER(SQLSMALLINT),
            ctypes.POINTER(SQLULEN),
            ctypes.POINTER(SQLSMALLINT),
            ctypes.POINTER(SQLSMALLINT),
        ]
        f.restype = SQLRETURN
        f = dll.SQLFetch
        f.argtypes = [SQLHANDLE]
        f.restype = SQLRETURN
        f = dll.SQLGetData
        f.argtypes = [
            SQLHANDLE,
            SQLUSMALLINT,
            SQLSMALLINT,
            ctypes.c_void_p,
            SQLLEN,
            ctypes.POINTER(SQLLEN),
        ]
        f.restype = SQLRETURN
        f = dll.SQLFreeStmt
        f.argtypes = [SQLHANDLE, SQLUSMALLINT]
        f.restype = SQLRETURN

        env = SQLHANDLE()
        if not _ok(dll.SQLAllocHandle(SQL_HANDLE_ENV, None, ctypes.byref(env))):
            raise DriverError("ODBC の環境ハンドルを確保できませんでした。")
        dll.SQLSetEnvAttr(env, SQL_ATTR_ODBC_VERSION, ctypes.c_void_p(SQL_OV_ODBC3), 0)
        self._env = env

    def diag(self, handle_type: int, handle) -> DriverError:
        """直前の失敗の診断情報を DriverError にまとめる。"""
        msgs = []
        first_state = ""
        first_native = 0
        for rec in range(1, 6):
            state = ctypes.create_unicode_buffer(6)
            native = SQLINTEGER()
            msg = ctypes.create_unicode_buffer(1024)
            length = SQLSMALLINT()
            ret = self._dll.SQLGetDiagRecW(
                handle_type,
                handle,
                rec,
                state,
                ctypes.byref(native),
                msg,
                1024,
                ctypes.byref(length),
            )
            if not _ok(ret):
                break
            if rec == 1:
                first_state = state.value
                first_native = native.value
            msgs.append(f"{msg.value} (SQLSTATE={state.value}, native={native.value})")
        return DriverError(
            " / ".join(msgs) or "ODBC の詳細な情報を取得できませんでした。",
            first_state,
            first_native,
        )

    def drivers(self) -> list[str]:
        """この（32bit/64bit の）プロセスから見える ODBC ドライバ名の一覧。"""
        names = []
        direction = SQL_FETCH_FIRST
        for _ in range(500):
            desc = ctypes.create_unicode_buffer(512)
            attrs = ctypes.create_unicode_buffer(2048)
            dlen = SQLSMALLINT()
            alen = SQLSMALLINT()
            ret = self._dll.SQLDriversW(
                self._env,
                direction,
                desc,
                512,
                ctypes.byref(dlen),
                attrs,
                2048,
                ctypes.byref(alen),
            )
            if not _ok(ret):
                break
            names.append(desc.value)
            direction = SQL_FETCH_NEXT
        return names

    def connect(self, connstr: str, readonly: bool = True) -> "CtypesConnection":
        """接続文字列で接続する。失敗したら DriverError。"""
        dll = self._dll
        dbc = SQLHANDLE()
        if not _ok(dll.SQLAllocHandle(SQL_HANDLE_DBC, self._env, ctypes.byref(dbc))):
            raise self.diag(SQL_HANDLE_ENV, self._env)
        if readonly:
            dll.SQLSetConnectAttrW(dbc, SQL_ATTR_ACCESS_MODE, ctypes.c_void_p(SQL_MODE_READ_ONLY), 0)
        out = ctypes.create_unicode_buffer(2048)
        outlen = SQLSMALLINT()
        ret = dll.SQLDriverConnectW(
            dbc,
            None,
            connstr,
            SQL_NTS,
            out,
            2048,
            ctypes.byref(outlen),
            SQL_DRIVER_NOPROMPT,
        )
        if not _ok(ret):
            err = self.diag(SQL_HANDLE_DBC, dbc)
            dll.SQLFreeHandle(SQL_HANDLE_DBC, dbc)
            raise err
        return CtypesConnection(self, dbc)


class CtypesConnection:
    """ctypes ODBC の接続。"""

    def __init__(self, odbc: CtypesOdbc, dbc) -> None:
        self._odbc = odbc
        self._dll = odbc._dll
        self._dbc = dbc

    def _new_stmt(self):
        stmt = SQLHANDLE()
        if not _ok(self._dll.SQLAllocHandle(SQL_HANDLE_STMT, self._dbc, ctypes.byref(stmt))):
            raise self._odbc.diag(SQL_HANDLE_DBC, self._dbc)
        return stmt

    def _free_stmt(self, stmt) -> None:
        self._dll.SQLFreeHandle(SQL_HANDLE_STMT, stmt)

    def _describe(self, stmt) -> list[tuple[str, int]]:
        ncols = SQLSMALLINT()
        if not _ok(self._dll.SQLNumResultCols(stmt, ctypes.byref(ncols))):
            raise self._odbc.diag(SQL_HANDLE_STMT, stmt)
        cols = []
        for i in range(1, ncols.value + 1):
            name = ctypes.create_unicode_buffer(512)
            nlen = SQLSMALLINT()
            dtype = SQLSMALLINT()
            size = SQLULEN()
            digits = SQLSMALLINT()
            nullable = SQLSMALLINT()
            ret = self._dll.SQLDescribeColW(
                stmt,
                i,
                name,
                512,
                ctypes.byref(nlen),
                ctypes.byref(dtype),
                ctypes.byref(size),
                ctypes.byref(digits),
                ctypes.byref(nullable),
            )
            if not _ok(ret):
                raise self._odbc.diag(SQL_HANDLE_STMT, stmt)
            cols.append((name.value, dtype.value))
        return cols

    def _get_value(self, stmt, col: int, dtype: int) -> Any:
        """1つの値を取り出す（長い値は分割して読む）。"""
        binary = dtype in SQL_BINARY_TYPES
        ctype = SQL_C_BINARY if binary else SQL_C_WCHAR
        buf = ctypes.create_string_buffer(_GETDATA_CHUNK)
        ind = SQLLEN()
        parts: list[bytes] = []
        total = 0
        while True:
            ret = self._dll.SQLGetData(stmt, col, ctype, buf, _GETDATA_CHUNK, ctypes.byref(ind))
            if ret == SQL_NO_DATA:
                break
            if not _ok(ret):
                raise self._odbc.diag(SQL_HANDLE_STMT, stmt)
            if ind.value == SQL_NULL_DATA:
                return None
            # 文字列は終端の NUL（2バイト）の分だけ1回に入る量が減る
            avail = _GETDATA_CHUNK if binary else _GETDATA_CHUNK - 2
            truncated = ret == SQL_SUCCESS_WITH_INFO and (ind.value == SQL_NO_TOTAL or ind.value > avail)
            n = avail if truncated else ind.value
            parts.append(buf.raw[:n])
            total += n
            if binary and total > MAX_BLOB_BYTES:
                return OversizeBlob(total)
            if not truncated:
                break
        data = b"".join(parts)
        if binary:
            return data
        text = data.decode("utf-16-le", errors="replace")
        if dtype == SQL_BIT:
            return text.strip() not in ("0", "")
        if dtype in SQL_TIMESTAMP_TYPES:
            return _odbc_datetime_text(text)
        return text

    def tables(self) -> list[tuple[str, str]]:
        """(表名, 表の種別) の一覧。"""
        stmt = self._new_stmt()
        try:
            ret = self._dll.SQLTablesW(stmt, None, 0, None, 0, None, 0, None, 0)
            if not _ok(ret):
                raise self._odbc.diag(SQL_HANDLE_STMT, stmt)
            result = []
            while True:
                ret = self._dll.SQLFetch(stmt)
                if ret == SQL_NO_DATA:
                    break
                if not _ok(ret):
                    raise self._odbc.diag(SQL_HANDLE_STMT, stmt)
                name = self._get_value(stmt, 3, 12)
                ttype = self._get_value(stmt, 4, 12)
                result.append((name or "", (ttype or "").upper()))
            return result
        finally:
            self._free_stmt(stmt)

    def query(self, sql: str) -> tuple[list[tuple[str, int]], Iterator[list[Any]]]:
        """SELECT を実行し、(列[(名前, 型)], 行のイテレータ) を返す。行は1件ずつ取り出す。"""
        stmt = self._new_stmt()
        ret = self._dll.SQLExecDirectW(stmt, sql, SQL_NTS)
        if not _ok(ret):
            err = self._odbc.diag(SQL_HANDLE_STMT, stmt)
            self._free_stmt(stmt)
            raise err
        try:
            cols = self._describe(stmt)
        except Exception:
            self._free_stmt(stmt)
            raise

        def rows() -> Iterator[list[Any]]:
            try:
                while True:
                    r = self._dll.SQLFetch(stmt)
                    if r == SQL_NO_DATA:
                        return
                    if not _ok(r):
                        raise self._odbc.diag(SQL_HANDLE_STMT, stmt)
                    yield [self._get_value(stmt, i + 1, dtype) for i, (_, dtype) in enumerate(cols)]
            finally:
                self._free_stmt(stmt)

        return cols, rows()

    def execute(self, sql: str) -> None:
        """結果を返さない SQL を実行する（試験で DB を作るとき用。読み取りでは使わない）。"""
        stmt = self._new_stmt()
        try:
            ret = self._dll.SQLExecDirectW(stmt, sql, SQL_NTS)
            if not _ok(ret) and ret != SQL_NO_DATA:
                raise self._odbc.diag(SQL_HANDLE_STMT, stmt)
        finally:
            self._free_stmt(stmt)

    def close(self) -> None:
        """切断する。"""
        if self._dbc is not None:
            self._dll.SQLDisconnect(self._dbc)
            self._dll.SQLFreeHandle(SQL_HANDLE_DBC, self._dbc)
            self._dbc = None


def _odbc_datetime_text(text: str) -> str:
    """ODBC の日時文字列（'2020-01-02 03:04:05'）を ISO 形式（'2020-01-02T03:04:05'）にする。"""
    text = text.strip()
    if len(text) >= 19 and text[10] == " ":
        text = text[:10] + "T" + text[11:]
    if text.endswith(".000"):
        text = text[:-4]
    return text


# ---------------------------------------------------------------------------
# pyodbc（入っていれば優先して使う）
# ---------------------------------------------------------------------------
class PyodbcConnection:
    """pyodbc の接続を CtypesConnection と同じ形で包む。"""

    def __init__(self, pyodbc_module, conn) -> None:
        self._pyodbc = pyodbc_module
        self._conn = conn

    def tables(self) -> list[tuple[str, str]]:
        cur = self._conn.cursor()
        try:
            return [(row.table_name or "", (row.table_type or "").upper()) for row in cur.tables()]
        finally:
            cur.close()

    def query(self, sql: str) -> tuple[list[tuple[str, int]], Iterator[list[Any]]]:
        cur = self._conn.cursor()
        try:
            cur.execute(sql)
        except self._pyodbc.Error as exc:
            cur.close()
            raise _pyodbc_error(exc) from exc
        cols = [(d[0], -4 if d[1] in (bytes, bytearray) else 0) for d in cur.description]

        def rows() -> Iterator[list[Any]]:
            try:
                while True:
                    try:
                        batch = cur.fetchmany(FETCH_BATCH)
                    except self._pyodbc.Error as exc:
                        raise _pyodbc_error(exc) from exc
                    if not batch:
                        return
                    for r in batch:
                        out = []
                        for v in r:
                            if isinstance(v, (bytes, bytearray)):
                                v = bytes(v)
                                if len(v) > MAX_BLOB_BYTES:
                                    v = OversizeBlob(len(v))
                            out.append(v)
                        yield out
            finally:
                cur.close()

        return cols, rows()

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass


def _pyodbc_error(exc: Exception) -> DriverError:
    """pyodbc の例外を DriverError に直す。"""
    args = getattr(exc, "args", ())
    state = args[0] if len(args) >= 1 and isinstance(args[0], str) else ""
    msg = args[1] if len(args) >= 2 else str(exc)
    native = 0
    # メッセージ末尾の "(-1905)" のような native 番号を拾う
    for token in str(msg).replace(")", " ").replace("(", " ").split():
        if token.lstrip("-").isdigit() and token.startswith("-"):
            native = int(token)
            break
    return DriverError(str(msg), state, native)


# ---------------------------------------------------------------------------
# 値の文字列化
# ---------------------------------------------------------------------------
def value_to_text(v: Any) -> str | None:
    """1つの値を出力用の文字列にする（バイナリは呼び出し側で別扱い）。"""
    if v is None:
        return None
    if isinstance(v, str):
        return v
    if isinstance(v, bool):
        return "True" if v else "False"
    if isinstance(v, datetime.datetime):
        return datetime.datetime(v.year, v.month, v.day, v.hour, v.minute, v.second).isoformat()
    if isinstance(v, (datetime.date, datetime.time)):
        return v.isoformat()
    if isinstance(v, float):
        return repr(v) if v != int(v) or abs(v) >= 1e16 else str(int(v))
    if isinstance(v, (int, decimal.Decimal)):
        return str(v)
    return str(v)


def bracket(name: str) -> str:
    """表名・列名を角括弧で囲む（] は ]] に）。"""
    return "[" + name.replace("]", "]]") + "]"


def odbc_value(value: str) -> str:
    """接続文字列の値を、必要なときだけ波括弧で囲む。

    Access の ODBC ドライバは DBQ を波括弧で囲むと「Not a valid file name」で失敗するため
    （実測）、; などの区切り文字を含むときだけ囲む。
    """
    if any(ch in value for ch in ";{}") or value != value.strip():
        return "{" + value.replace("}", "}}") + "}"
    return value


def format_link_target(connect: str, source_table: str | None) -> str:
    """リンクテーブルの接続情報を人が読める形にする（';DATABASE=' を外し、元の表名を添える）。"""
    target = connect or ""
    upper = target.upper()
    marker = ";DATABASE="
    if marker in upper:
        idx = upper.index(marker) + len(marker)
        rest = target[idx:]
        target = rest.split(";", 1)[0] if ";" in rest else rest
        prefix = connect[: upper.index(marker)].strip(";")
        if prefix:
            target = f"{target}（{prefix}）"
    if source_table:
        target = f"{target}（表: {source_table}）"
    return target


# 32bit の cscript で DAO を呼び、リンクテーブルの接続情報だけを取り出す JScript。
# pywin32 が無い環境でも、Windows 標準の DAO.DBEngine.36 でリンク先を引けるようにするため。
# cscript の //U（UTF-16 入出力）はパイプでは何も出力しない（実測）ため、入出力は ASCII に
# 限り、パスワードは UTF-16 の16進、出力は JSON の \uXXXX で運ぶ。
_LINKS_JSCRIPT = r"""
function enc(s) {
  var r = "";
  s = String(s);
  for (var k = 0; k < s.length; k++) {
    var c = s.charCodeAt(k);
    if (c >= 32 && c < 127 && c != 34 && c != 92) { r += s.charAt(k); }
    else { r += "\\u" + ("0000" + c.toString(16)).slice(-4); }
  }
  return '"' + r + '"';
}
var path = WScript.Arguments(0);
var hex = WScript.StdIn.ReadLine();
var pw = "";
for (var h = 0; h + 4 <= hex.length; h += 4) {
  pw += String.fromCharCode(parseInt(hex.substr(h, 4), 16));
}
var progids = ["DAO.DBEngine.36", "DAO.DBEngine.120"];
var eng = null;
for (var i = 0; i < progids.length && eng === null; i++) {
  try { eng = new ActiveXObject(progids[i]); } catch (e) {}
}
if (eng === null) { WScript.Quit(3); }
var db = eng.OpenDatabase(path, false, true, pw ? ";PWD=" + pw : "");
for (var j = 0; j < db.TableDefs.Count; j++) {
  var td = db.TableDefs(j);
  if (td.Connect) {
    WScript.Echo("[" + enc(td.Name) + "," + enc(td.Connect) + "," + enc(td.SourceTableName) + "]");
  }
}
db.Close();
"""


def lookup_link_targets_dao(path: str, password: str | None) -> dict[str, str]:
    """DAO でリンク先を引く（pywin32 → 32bit cscript の順）。引けなければ空。"""
    try:
        import pythoncom  # noqa: WPS433
        import win32com.client  # noqa: WPS433

        pythoncom.CoInitialize()
        for progid in DAO_PROGIDS:
            try:
                engine = win32com.client.Dispatch(progid)
            except Exception:
                continue
            db = engine.OpenDatabase(path, False, True, f";PWD={password}" if password else "")
            try:
                out = {}
                tds = db.TableDefs
                for i in range(tds.Count):
                    td = tds(i)
                    if td.Connect:
                        out[td.Name] = format_link_target(td.Connect, td.SourceTableName)
                return out
            finally:
                db.Close()
    except Exception:
        pass
    return _lookup_link_targets_cscript(path, password)


def _cscript_path() -> str | None:
    """32bit の cscript.exe のパス（64bit の Windows では SysWOW64 側）。"""
    windir = os.environ.get("WINDIR", r"C:\Windows")
    candidates = []
    if struct_pointer_bits() == 32:
        # 32bit プロセスからは System32 が SysWOW64 へ振り替えられる
        candidates.append(os.path.join(windir, "System32", "cscript.exe"))
    candidates.append(os.path.join(windir, "SysWOW64", "cscript.exe"))
    candidates.append(os.path.join(windir, "System32", "cscript.exe"))
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def struct_pointer_bits() -> int:
    """このプロセスのビット数（32 / 64）。"""
    return ctypes.sizeof(ctypes.c_void_p) * 8


def _lookup_link_targets_cscript(path: str, password: str | None) -> dict[str, str]:
    """cscript 経由で DAO を呼び、リンク先を引く。

    パスワードはコマンド行に出さないよう標準入力で渡す（UTF-16 の16進文字列）。
    """
    import subprocess  # noqa: WPS433
    import tempfile  # noqa: WPS433

    cscript = _cscript_path()
    if cscript is None:
        return {}
    fd, js_path = tempfile.mkstemp(prefix="access32_links_", suffix=".js")
    try:
        with os.fdopen(fd, "w", encoding="ascii") as fh:
            fh.write(_LINKS_JSCRIPT)
        pw_hex = "".join(f"{unit:04x}" for unit in memoryview((password or "").encode("utf-16-le")).cast("H"))
        proc = subprocess.run(
            [cscript, "//nologo", "//E:jscript", js_path, path],
            input=(pw_hex + "\r\n").encode("ascii"),
            capture_output=True,
            timeout=60,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        out = {}
        for line in proc.stdout.decode("ascii", errors="replace").splitlines():
            line = line.strip()
            if not line.startswith("["):
                continue
            try:
                name, connect, source = json.loads(line)
            except ValueError:
                continue
            out[name] = format_link_target(connect, source)
        return out
    except Exception:
        return {}
    finally:
        try:
            os.remove(js_path)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# セッション（ODBC / DAO の差を吸収）
# ---------------------------------------------------------------------------
class OdbcSession:
    """ODBC で開いた DB。"""

    method = "odbc"

    def __init__(self, conn, driver: str, path: str = "", password: str | None = None) -> None:
        self.conn = conn
        self.driver = driver
        self.path = path
        self.password = password

    def list_tables(self) -> list[tuple[str, str, str | None]]:
        """(表名, 種別 'table'|'link', リンク先) の一覧（システム表・クエリは除く）。"""
        result = []
        links = []
        for name, ttype in self.conn.tables():
            if not name or name.upper().startswith("MSYS"):
                continue
            if ttype == "TABLE":
                result.append((name, "table", None))
            elif "LINK" in ttype or ttype == "SYNONYM":
                links.append(name)
            # VIEW（クエリ）・SYSTEM TABLE・ACCESS TABLE は読まない
        targets = self._link_targets() if links else {}
        for name in links:
            result.append((name, "link", targets.get(name)))
        return result

    def _link_targets(self) -> dict[str, str]:
        """リンク先を引く。MSysObjects → DAO（pywin32 か 32bit の cscript 経由）の順。"""
        targets = self._link_targets_from_msys()
        if not targets and self.path:
            targets = lookup_link_targets_dao(self.path, self.password)
        return targets

    def _link_targets_from_msys(self) -> dict[str, str]:
        """MSysObjects からリンク先を引く。

        既定のワークグループでは ODBC から MSysObjects を読む権限が無く
        「no read permission on 'MSysObjects'」(native=-1907) になることが多い（実測）。
        そのときは空を返す。
        """
        try:
            _, rows = self.conn.query(
                "SELECT [Name], [Database], [Connect], [ForeignName] FROM MSysObjects" " WHERE [Type] IN (4, 6)"
            )
            out = {}
            for name, database, connect, foreign in rows:
                out[str(name)] = format_link_target(database or connect or "", foreign)
            return out
        except DriverError:
            return {}

    def read_table(self, name: str):
        cols, rows = self.conn.query("SELECT * FROM " + bracket(name))
        return [c[0] for c in cols], rows

    def close(self) -> None:
        self.conn.close()


class DaoSession:
    """DAO（pywin32 の win32com）で開いた DB。"""

    method = "dao"
    DB_SYSTEM_OBJECT = -2147483646  # 0x80000002
    DB_HIDDEN_OBJECT = 1
    DB_OPEN_SNAPSHOT = 4
    DB_FORWARD_ONLY = 8
    DB_LONG_BINARY = 11
    DB_BINARY = 9

    def __init__(self, engine, db, driver: str) -> None:
        self.engine = engine
        self.db = db
        self.driver = driver

    def list_tables(self) -> list[tuple[str, str, str | None]]:
        result = []
        tds = self.db.TableDefs
        for i in range(tds.Count):
            td = tds(i)
            name = td.Name
            if name.upper().startswith("MSYS") or (td.Attributes & self.DB_SYSTEM_OBJECT) == self.DB_SYSTEM_OBJECT:
                continue
            connect = td.Connect or ""
            if connect:
                result.append((name, "link", format_link_target(connect, td.SourceTableName)))
            else:
                result.append((name, "table", None))
        return result

    def read_table(self, name: str):
        rs = self.db.OpenRecordset(
            "SELECT * FROM " + bracket(name),
            self.DB_OPEN_SNAPSHOT,
            self.DB_FORWARD_ONLY,
        )
        fields = rs.Fields
        n = fields.Count
        names = [fields(i).Name for i in range(n)]
        binary = [fields(i).Type in (self.DB_LONG_BINARY, self.DB_BINARY) for i in range(n)]

        def rows() -> Iterator[list[Any]]:
            try:
                while not rs.EOF:
                    out = []
                    for i in range(n):
                        f = fields(i)
                        v = f.Value
                        if binary[i] and v is not None:
                            size = f.FieldSize if binary[i] else 0
                            if size and size > MAX_BLOB_BYTES:
                                v = OversizeBlob(size)
                            else:
                                v = bytes(v)
                        out.append(v)
                    yield out
                    rs.MoveNext()
            finally:
                try:
                    rs.Close()
                except Exception:
                    pass

        return names, rows()

    def close(self) -> None:
        try:
            self.db.Close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# 開く（ドライバの順番・エラーの分類）
# ---------------------------------------------------------------------------
def read_header(path: str) -> bytes:
    """ファイル先頭を読む（形式の判定用）。"""
    with open(path, "rb") as fh:
        return fh.read(0x20)


def detect_format(header: bytes) -> str | None:
    """'jet3' / 'jet4' / 'ace' / None（Access ではない）を返す。"""
    if len(header) < 0x15:
        return None
    if header[4:19] == b"Standard Jet DB":
        return "jet3" if header[0x14] == 0 else "jet4"
    if header[4:19] == b"Standard ACE DB":
        return "ace"
    return None


def classify_driver_error(err: DriverError) -> str:
    """ドライバの失敗を本体との約束の分類（password / corrupt / unsupported / other）に寄せる。"""
    text = err.message.lower()
    if "password" in text or "パスワード" in err.message or err.native in (-1905, 3031):
        return "password"
    if "unrecognized database format" in text or "認識できません" in err.message or err.native in (-1028, 3343):
        return "unrecognized"
    if "im002" in err.sqlstate.lower():
        return "driver_missing"
    return "other"


def odbc_driver_order(installed: list[str]) -> list[str]:
    """試す ODBC ドライバの順。ACE → Jet4 の英語名 → それ以外の Access 用（各国語の別名）。

    Windows には同じ Jet ドライバが「Driver do Microsoft Access (*.mdb)」
    「Microsoft Access-Treiber (*.mdb)」のような各国語の別名でも登録されている（実測）。
    中身は同じドライバなので、英語名が1つも無い環境に限ってそれらを試す。
    """
    order = [d for d in (ODBC_DRIVER_ACE, ODBC_DRIVER_JET) if d in installed]
    if order:
        return order
    for d in installed:
        if d not in order and "access" in d.lower() and "*.mdb" in d.lower():
            order.append(d)
    return order


def build_connstr(driver: str, path: str, password: str | None) -> str:
    """読み取り専用の ODBC 接続文字列を作る。"""
    parts = [
        f"DRIVER={{{driver}}}",
        "DBQ=" + odbc_value(path),
        "ReadOnly=1",
        "Exclusive=0",
    ]
    if password:
        parts.append("PWD=" + odbc_value(password))
    return ";".join(parts) + ";"


class Opener:
    """決められた順でドライバを試し、開けたセッションを返す。"""

    def __init__(self, path: str, passwords: list[str], emitter: Emitter) -> None:
        self.path = path
        self.passwords = passwords
        self.emitter = emitter
        self.failures: list[tuple[str, str, DriverError]] = []  # (方法, 分類, 例外)
        self.tried_any = False

    def _candidates(self) -> list[str | None]:
        """試すパスワードの順（空 → 各パスワード）。"""
        return [None] + [p for p in self.passwords if p]

    def _odbc_backend(self):
        """pyodbc があれば pyodbc、無ければ ctypes の ODBC を返す。(種別, 接続関数, ドライバ一覧)"""
        try:
            import pyodbc  # noqa: WPS433（任意の依存）

            def connect(connstr: str):
                try:
                    return PyodbcConnection(pyodbc, pyodbc.connect(connstr, autocommit=True, readonly=True))
                except pyodbc.Error as exc:
                    raise _pyodbc_error(exc) from exc

            return connect, list(pyodbc.drivers())
        except ImportError:
            odbc = CtypesOdbc()
            return (lambda connstr: odbc.connect(connstr, readonly=True)), odbc.drivers()

    def _try_with_passwords(self, label: str, open_one: Callable[[str | None], Any]):
        """空パスワード→各パスワードの順で試す。パスワード以外の失敗ならそこで打ち切る。"""
        for pw in self._candidates():
            try:
                session = open_one(pw)
                return session, pw is not None
            except DriverError as err:
                kind = classify_driver_error(err)
                self.failures.append((label, kind, err))
                if kind != "password":
                    return None, False
        return None, False

    def open(self):
        """開けたら (セッション, password_used)。開けなければ AccessOpenError。"""
        try:
            connect, drivers = self._odbc_backend()
        except Exception as exc:  # odbc32.dll が無い等
            connect, drivers = None, []
            self.failures.append(("odbc", "other", DriverError(str(exc))))
        for driver in odbc_driver_order(drivers):
            if connect is None:
                break
            self.tried_any = True

            def open_odbc(pw, driver=driver):
                conn = connect(build_connstr(driver, self.path, pw))
                return OdbcSession(conn, driver, self.path, pw)

            session, used = self._try_with_passwords(f"ODBC「{driver}」", open_odbc)
            if session is not None:
                return session, used

        for progid in DAO_PROGIDS:
            engine = self._dao_engine(progid)
            if engine is None:
                continue
            self.tried_any = True

            def open_dao(pw, engine=engine, progid=progid):
                connect_str = f";PWD={pw}" if pw else ""
                try:
                    db = engine.OpenDatabase(self.path, False, True, connect_str)
                except Exception as exc:
                    raise _com_error(exc) from exc
                return DaoSession(engine, db, progid)

            session, used = self._try_with_passwords(f"DAO {progid}", open_dao)
            if session is not None:
                return session, used

        raise self._final_error()

    def _dao_engine(self, progid: str):
        """DAO の DBEngine を作る（pywin32 が無い・登録が無ければ None）。"""
        try:
            import pythoncom  # noqa: WPS433
            import win32com.client  # noqa: WPS433
        except ImportError:
            return None
        try:
            pythoncom.CoInitialize()
            return win32com.client.Dispatch(progid)
        except Exception:
            return None

    def _final_error(self) -> AccessOpenError:
        """どの方法でも開けなかったときの分類と、日本語の原因・対処。"""
        name = os.path.basename(self.path)
        details = "；".join(f"{label}: {err.message}" for label, _, err in self.failures)
        kinds = {kind for _, kind, _ in self.failures}
        fmt = None
        try:
            fmt = detect_format(read_header(self.path))
        except OSError:
            pass
        if "password" in kinds:
            if self.passwords:
                msg = (
                    f"「{name}」はパスワードで保護されており、指定されたパスワードのどれでも開けませんでした。"
                    "正しいパスワードをパスワードファイルに追加してください。"
                )
            else:
                msg = (
                    f"「{name}」はパスワードで保護されています。"
                    "パスワードファイル（1行1パスワード）を指定してください。"
                )
            return AccessOpenError("password", msg + f"（詳細: {details}）")
        if fmt == "ace":
            return AccessOpenError(
                "driver_missing",
                f"「{name}」は Access 2007 以降の形式（.accdb 等）ですが、この 32bit プロセスでは "
                "ACE ドライバ（Microsoft Access Driver (*.mdb, *.accdb)）が使えませんでした。"
                "32bit の Microsoft Access Database Engine を入れるか、64bit 側の ACE で読んでください。"
                + (f"（詳細: {details}）" if details else ""),
            )
        if not self.tried_any:
            return AccessOpenError(
                "driver_missing",
                "Access を読めるドライバが 32bit で1つも見つかりませんでした"
                f"（ODBC「{ODBC_DRIVER_ACE}」「{ODBC_DRIVER_JET}」・DAO）。"
                "Windows 標準の Jet 4.0 ドライバか、32bit の Microsoft Access Database Engine を入れてください。",
            )
        if "unrecognized" in kinds:
            return AccessOpenError(
                "corrupt",
                f"「{name}」をデータベースとして認識できませんでした。ファイルが壊れているか、"
                "対応していない形式の可能性があります。Access で開けるか確かめてください。"
                f"（詳細: {details}）",
            )
        return AccessOpenError(
            "other",
            f"「{name}」を開けませんでした。ほかのプログラムが排他で開いていないか、"
            f"読み取り権限があるかを確かめてください。（詳細: {details}）",
        )


def _com_error(exc: Exception) -> DriverError:
    """pywin32 の com_error を DriverError に直す。"""
    args = getattr(exc, "args", ())
    message = str(exc)
    native = 0
    if len(args) >= 3 and args[2]:
        info = args[2]
        if len(info) >= 3 and info[2]:
            message = str(info[2])
        if len(info) >= 6 and info[5]:
            native = int(info[5]) & 0xFFFF
    return DriverError(message, "", native)


# ---------------------------------------------------------------------------
# 本体
# ---------------------------------------------------------------------------
def load_passwords(path: str | None) -> list[str]:
    """パスワードファイル（UTF-8・1行1パスワード）を読む。"""
    if not path:
        return []
    if path == "-":  # 本体からは標準入力で渡す（パスワードを一時ファイルに残さない）
        data = sys.stdin.buffer.read().decode("utf-8-sig")
        return [line.rstrip("\r") for line in data.split("\n") if line.rstrip("\r")]
    with open(path, "r", encoding="utf-8-sig") as fh:
        return [line.rstrip("\r\n") for line in fh if line.rstrip("\r\n")]


def dump_table(session, name: str, emitter: Emitter, max_rows: int | None) -> int:
    """1つの表を出力し、出した行数を返す。"""
    columns, rows = session.read_table(name)
    emitter.emit({"type": "table", "name": name, "columns": columns})
    count = 0
    for values in rows:
        if max_rows is not None and count >= max_rows:
            emitter.warning(f"表「{name}」は {max_rows} 行を超えるため、{max_rows} 行で打ち切りました。")
            break
        count += 1
        out = []
        for col, v in zip(columns, values):
            if isinstance(v, OversizeBlob):
                emitter.warning(
                    f"表「{name}」の {count} 行目・列「{col}」のバイナリは "
                    f"{v.size_at_least // (1024 * 1024)}MB を超えるため出力しませんでした。"
                )
                out.append(None)
            elif isinstance(v, (bytes, bytearray, memoryview)):
                out.append(None)
            else:
                out.append(value_to_text(v))
        emitter.emit({"type": "row", "table": name, "row": count, "values": out})
        for col, v in zip(columns, values):
            if isinstance(v, (bytes, bytearray, memoryview)) and len(v) > 0:
                emitter.emit(
                    {
                        "type": "blob",
                        "table": name,
                        "column": col,
                        "row": count,
                        "data_b64": base64.b64encode(bytes(v)).decode("ascii"),
                    }
                )
    if hasattr(rows, "close"):
        rows.close()
    return count


def run(path: str, passwords: list[str], max_rows: int | None, emitter: Emitter) -> int:
    """DB を開いて全表を出力する。終了コードを返す。"""
    if not os.path.isfile(path):
        emitter.emit(
            {
                "type": "error",
                "code": "other",
                "message": f"ファイルが見つかりません: {path}",
            }
        )
        return EXIT_ERROR
    try:
        fmt = detect_format(read_header(path))
    except OSError as exc:
        emitter.emit(
            {
                "type": "error",
                "code": "other",
                "message": f"ファイルを読めませんでした（{exc}）。読み取り権限や、ほかのプログラムが使用中でないかを確かめてください。",
            }
        )
        return EXIT_ERROR
    if fmt is None:
        emitter.emit(
            {
                "type": "error",
                "code": "corrupt",
                "message": f"「{os.path.basename(path)}」は Access のデータベースとして認識できません（先頭の形式情報が違います）。ファイルが壊れているか、拡張子だけが Access のものです。",
            }
        )
        return EXIT_ERROR

    opener = Opener(path, passwords, emitter)
    try:
        session, password_used = opener.open()
    except AccessOpenError as exc:
        emitter.emit({"type": "error", "code": exc.code, "message": exc.message})
        return EXIT_ERROR
    emitter.emit(
        {
            "type": "open",
            "driver": session.driver,
            "method": session.method,
            "password_used": password_used,
        }
    )
    tables = 0
    total_rows = 0
    try:
        for name, kind, target in session.list_tables():
            if kind == "link":
                where = target if target else "（リンク先は取得できませんでした）"
                emitter.warning(f"表「{name}」はリンクテーブルのため読みませんでした。リンク先: {where}")
                continue
            try:
                total_rows += dump_table(session, name, emitter, max_rows)
                tables += 1
            except DriverError as err:
                emitter.warning(f"表「{name}」を読めませんでした: {err.message}")
            except Exception as exc:  # DAO の com_error 等
                emitter.warning(f"表「{name}」を読めませんでした: {exc}")
    finally:
        session.close()
    emitter.emit({"type": "done", "tables": tables, "rows": total_rows})
    return EXIT_OK


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Access データベースを 32bit で読み、JSON Lines で出力する補助スクリプト"
    )
    parser.add_argument("db_path", help="読む .mdb / .accdb / .mde / .accde のパス")
    parser.add_argument("--password-file", help="UTF-8・1行1パスワードのファイル")
    parser.add_argument("--max-rows-per-table", type=int, default=None, help="1表あたりの最大行数")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    emitter = Emitter()
    try:
        try:
            passwords = load_passwords(args.password_file)
        except (OSError, UnicodeDecodeError) as exc:
            emitter.emit(
                {
                    "type": "error",
                    "code": "other",
                    "message": f"パスワードファイルを読めませんでした（{exc}）。UTF-8 の 1行1パスワードで用意してください。",
                }
            )
            return EXIT_ERROR
        max_rows = args.max_rows_per_table
        if max_rows is not None and max_rows < 0:
            max_rows = None
        return run(os.path.abspath(args.db_path), passwords, max_rows, emitter)
    except BrokenPipeError:
        return EXIT_ERROR
    except Exception as exc:  # 想定外でも必ず error 行を出して終わる
        try:
            emitter.emit(
                {
                    "type": "error",
                    "code": "other",
                    "message": f"想定外のエラーで読み取りを中断しました: {type(exc).__name__}: {exc}",
                }
            )
        except Exception:
            pass
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())

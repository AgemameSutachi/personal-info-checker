"""Access データベースを 32bit プロセスで書き換える補助スクリプト（対処で使う。Jet 4.0 の ODBC ドライバを使う）。

64bit の本体は、ACE（64bit の ODBC）が無い PC で .mdb を書き換えるとき、この補助を子プロセスとして起動する。
Windows 標準の Jet 4.0（msjet40.dll）は 32bit 版しか無いため、同梱の 32bit Python（python32/）で動かす。
読み取り専用の access32_helper.py（検査用）とは別に、書き込みを許す。標準ライブラリだけで動く（ODBC は ctypes）。
``pii_checker`` パッケージは import しない。access32_helper.py と同じフォルダに置く（そこの ODBC の部品を使う）。

呼び方::

    python access32_rewrite.py

標準入力から JSON を1行ずつ読み、標準出力へ JSON を1行ずつ返す（UTF-8）。命令（op）:

    {"op":"probe"}                              → {"ok":true,"drivers":[...]}
    {"op":"open","path":...}                    → {"ok":true,"driver":...} / {"ok":false,"code":...,"message":...}
    {"op":"tables"}                             → {"ok":true,"tables":[...]}
    {"op":"columns","table":...}                → {"ok":true,"columns":[{"name":...,"kind":...},...]}
    {"op":"read_rows","table":...,"rows":[...]} → {"ok":true,"rows":[[通し番号,[値...]],...]}
    {"op":"count","table":...}                  → {"ok":true,"count":行数}
    {"op":"execute","sql":...}                  → {"ok":true,"count":影響した行数}
    {"op":"close"}                              → {"ok":true}（終了）
    {"op":"create_db","path":...[,"jet3":true]} → {"ok":true}（試験の検体用: 空の .mdb（jet3 は Access 97 形式）を作る）

値の形: 文字列はそのまま・空は null・真偽は true/false・整数は {"i":"123"}・実数は {"f":"1.5"}・日時は {"d":"…"}・
バイナリは {"x":長さ}（中身は渡さない）。通し番号は「SELECT * の順の 1 始まり」（検査と同じ数え方）。
失敗は {"ok":false,"message":...}。
"""

from __future__ import annotations

import ctypes
import json
import os
import sys

try:
    import access32_helper as ah  # 同じフォルダの検査用補助（ODBC を ctypes で呼ぶ部品）
except ImportError:  # パッケージの中から読み込まれたとき（試験）
    from pii_checker import access32_helper as ah

SQL_INT_TYPES = {4, 5, -6, -5}
SQL_FLOAT_TYPES = {2, 3, 6, 7, 8}
SQL_TEXT_TYPES = {1, 12, -8, -9}
SQL_MEMO_TYPES = {-1, -10}


def kind_of(dtype: int) -> str:
    """ODBC の型から、本体との約束の種類（text・memo・int・float・bool・date・bin・other）にする。"""
    if dtype in SQL_TEXT_TYPES:
        return "text"
    if dtype in SQL_MEMO_TYPES:
        return "memo"
    if dtype in SQL_INT_TYPES:
        return "int"
    if dtype in SQL_FLOAT_TYPES:
        return "float"
    if dtype == ah.SQL_BIT:
        return "bool"
    if dtype in ah.SQL_TIMESTAMP_TYPES:
        return "date"
    if dtype in ah.SQL_BINARY_TYPES:
        return "bin"
    return "other"


def tag_value(v, dtype: int):
    """1つの値を、JSON で運べる形（型の目印つき）にする。"""
    if v is None:
        return None
    if isinstance(v, ah.OversizeBlob):
        return {"x": 0}
    if isinstance(v, (bytes, bytearray)):
        return {"x": len(v)}
    if isinstance(v, bool):
        return v
    if dtype in SQL_INT_TYPES:
        try:
            return {"i": str(int(v))}
        except (TypeError, ValueError):
            return str(v)
    if dtype in SQL_FLOAT_TYPES:
        return {"f": str(v)}
    if dtype in ah.SQL_TIMESTAMP_TYPES:
        return {"d": str(v)}
    return str(v)


def execute_count(conn, sql: str) -> int:
    """結果を返さない SQL を実行し、影響した行数を返す。"""
    dll = conn._dll
    stmt = conn._new_stmt()
    try:
        ret = dll.SQLExecDirectW(stmt, sql, ah.SQL_NTS)
        if not ah._ok(ret) and ret != ah.SQL_NO_DATA:
            raise conn._odbc.diag(ah.SQL_HANDLE_STMT, stmt)
        dll.SQLRowCount.argtypes = [ah.SQLHANDLE, ctypes.POINTER(ah.SQLLEN)]
        dll.SQLRowCount.restype = ah.SQLRETURN
        n = ah.SQLLEN()
        if not ah._ok(dll.SQLRowCount(stmt, ctypes.byref(n))):
            return -1
        return int(n.value)
    finally:
        conn._free_stmt(stmt)


class Server:
    """1つの Access ファイルを書き換え可能で開き、命令を処理する。"""

    def __init__(self, emitter: ah.Emitter) -> None:
        self.emit = emitter.emit
        self.odbc = None
        self.conn = None
        self.driver = ""

    def op_probe(self, req: dict) -> dict:
        odbc = ah.CtypesOdbc()
        return {"ok": True, "drivers": ah.odbc_driver_order(odbc.drivers())}

    def op_open(self, req: dict) -> dict:
        path = req["path"]
        self.odbc = ah.CtypesOdbc()
        drivers = ah.odbc_driver_order(self.odbc.drivers())
        if not drivers:
            return {
                "ok": False,
                "code": "driver_missing",
                "message": "Jet・ACE の ODBC ドライバが 32bit で見つかりません",
            }
        last = None
        for drv in drivers:
            connstr = f"DRIVER={{{drv}}};DBQ={ah.odbc_value(path)};Exclusive=1;"
            try:
                self.conn = self.odbc.connect(connstr, readonly=False)
                self.driver = drv
                return {"ok": True, "driver": drv}
            except ah.DriverError as err:
                last = err
        kind = ah.classify_driver_error(last) if last else "other"
        return {"ok": False, "code": kind, "message": last.message if last else "開けませんでした"}

    def op_tables(self, req: dict) -> dict:
        names = []
        for name, ttype in self.conn.tables():
            if name and not name.startswith(("MSys", "~")) and ttype == "TABLE":
                names.append(name)
        return {"ok": True, "tables": names}

    def op_columns(self, req: dict) -> dict:
        cols, rows = self.conn.query("SELECT * FROM " + ah.bracket(req["table"]) + " WHERE 1=0")
        for _ in rows:  # 空。最後まで回して文のハンドルを解放する
            pass
        return {"ok": True, "columns": [{"name": n, "kind": kind_of(t)} for n, t in cols]}

    def op_read_rows(self, req: dict) -> dict:
        wanted = set(req["rows"])
        last = max(wanted) if wanted else 0
        cols, rows = self.conn.query("SELECT * FROM " + ah.bracket(req["table"]))
        out = []
        n = 0
        for values in rows:
            n += 1
            if n in wanted:
                out.append([n, [tag_value(v, cols[i][1]) for i, v in enumerate(values)]])
            if n >= last:
                break
        rows.close()  # 途中で止めたときも、文のハンドルを解放する
        return {"ok": True, "rows": out}

    def op_count(self, req: dict) -> dict:
        _cols, rows = self.conn.query("SELECT COUNT(*) FROM " + ah.bracket(req["table"]))
        n = 0
        for values in rows:
            n = int(values[0])
        return {"ok": True, "count": n}

    def op_execute(self, req: dict) -> dict:
        return {"ok": True, "count": execute_count(self.conn, req["sql"])}

    def op_create_db(self, req: dict) -> dict:
        """空の Access ファイルを作る（試験の検体用。ODBC のドライバの設定 API を使う）。"""
        odbc = ah.CtypesOdbc()
        drivers = ah.odbc_driver_order(odbc.drivers())
        if not drivers:
            return {"ok": False, "message": "Jet・ACE の ODBC ドライバが 32bit で見つかりません"}
        drv = drivers[0]
        key = "CREATE_DBV12" if "accdb" in drv else ("CREATE_DBV3" if req.get("jet3") else "CREATE_DB")
        attrs = f"{key}={req['path']}" + (" General" if key in ("CREATE_DB", "CREATE_DBV3") else "") + "\0\0"
        dll = ctypes.windll.odbccp32
        dll.SQLConfigDataSourceW.argtypes = [ctypes.c_void_p, ctypes.c_ushort, ctypes.c_wchar_p, ctypes.c_wchar_p]
        ok = dll.SQLConfigDataSourceW(None, 1, drv, attrs)
        return {"ok": bool(ok) and os.path.isfile(req["path"]), "message": "作れませんでした"}

    def op_close(self, req: dict) -> dict:
        if self.conn is not None:
            self.conn.close()
            self.conn = None
        return {"ok": True}

    def handle(self, req: dict) -> dict:
        fn = getattr(self, "op_" + str(req.get("op")), None)
        if fn is None:
            return {"ok": False, "message": f"知らない命令: {req.get('op')}"}
        try:
            return fn(req)
        except ah.DriverError as err:
            return {"ok": False, "message": err.message, "code": ah.classify_driver_error(err)}
        except Exception as exc:  # noqa: BLE001  想定外でも、本体へ失敗として返す
            return {"ok": False, "message": f"{type(exc).__name__}: {exc}"}


def main() -> int:
    emitter = ah.Emitter()
    server = Server(emitter)
    for raw in sys.stdin.buffer:
        try:
            req = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            continue
        reply = server.handle(req)
        emitter.emit(reply)
        if req.get("op") == "close":
            return 0
    server.op_close({})
    return 0


if __name__ == "__main__":
    sys.exit(main())

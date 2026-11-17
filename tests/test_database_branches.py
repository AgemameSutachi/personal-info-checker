"""データベースの処理（formats/database.py）の、本物の Access が無くても通せる分岐の試験。

ODBC（pyodbc）と 32bit の補助は差し替えて、表の一覧・添付・OLE の値・補助の知らせ（警告・誤り・途中の終わり）の
扱いを確かめる。dBase は削除の印と途中で切れたレコードを、ファイルを作って確かめる。
値はすべて試験のために作ったもので、実在の人の情報ではない。
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pii_checker.engine import Collector, NeedPassword, scan_file  # noqa: E402
from pii_checker.formats import database  # noqa: E402
from pii_checker.models import ItemResult, ScanOptions, Status  # noqa: E402

PHONE = "090-1234-5678"


class _Ctx(SimpleNamespace):
    """ScanContext の代わり（使う属性だけ）。入れ子の検査は呼ばれた引数を残すだけ。"""

    def __init__(self, passwords=(), max_rows=0, helper=None):
        super().__init__(
            options=SimpleNamespace(access_helper32=helper, max_rows_per_table=max_rows),
            items=[],
            nested=[],
        )
        self._passwords = list(passwords)

    def password_candidates(self):
        return list(self._passwords)

    def scan_nested(self, display, data=None, path=None, depth=1, name_hint=""):
        self.nested.append((display, data, depth, name_hint))


def _collector():
    item = ItemResult(path="t", kind="", status=Status.PENDING)
    return item, Collector(item, 20)


# ------------------------------------------------------------------ 32bit の補助の探し方


def test_find_helper32_configured_python(tmp_path):
    """設定に python.exe を書いたら、同梱の補助の台本をそれで動かす（ファイルの有無は見ない）。"""
    py = str(tmp_path / "python.exe")
    cmd = database.find_helper32(py)
    assert cmd[0] == py and cmd[1].endswith("access32_helper.py")


def test_find_helper32_configured_exe(tmp_path):
    """設定に在る exe を書いたら、それだけを起動する。"""
    exe = tmp_path / "access32_helper.exe"
    exe.write_bytes(b"")
    assert database.find_helper32(str(exe)) == [str(exe)]


def test_dev_helper_pythons_order(tmp_path, monkeypatch):
    """環境変数 → 開発用の venv → 標準のインストール先（新しい版から）の順に並べる。"""
    monkeypatch.setenv("PIICHK_PYTHON32", "X:/py32/python.exe")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    for name in ("Python39-32", "Python311-32", "Python310-32"):
        (tmp_path / "Programs" / "Python" / name).mkdir(parents=True)
    found = database._dev_helper_pythons()
    assert found[0] == "X:/py32/python.exe"
    assert found[1].replace("\\", "/").endswith("temp/venv/personal-info-checker-32/Scripts/python.exe")
    assert [Path(p).parent.name for p in found[2:]] == ["Python311-32", "Python310-32", "Python39-32"]


# ------------------------------------------------------------------ 32bit の補助の知らせ


def _fake_helper(tmp_path, monkeypatch, messages, ctx, exit_code=0):
    """決めた JSON Lines を出すだけの台本を補助の代わりに置く。受け取った引数と標準入力も残す。"""
    data = tmp_path / "lines.jsonl"
    lines = [m if isinstance(m, str) else json.dumps(m, ensure_ascii=False) for m in messages]  # 文字列は JSON でない行
    data.write_text("".join(s + "\n" for s in lines), encoding="utf-8")
    seen = tmp_path / "seen.json"
    script = tmp_path / "fake_helper.py"
    script.write_text(
        "import json, sys\n"
        "stdin = sys.stdin.buffer.read().decode('utf-8')\n"
        f"open({str(seen)!r}, 'w', encoding='utf-8').write(json.dumps({{'argv': sys.argv[2:], 'stdin': stdin}}))\n"
        "sys.stdout.buffer.write(open(sys.argv[1], 'rb').read())\n"
        "sys.stdout.flush()\n"
        f"sys.exit({exit_code})\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(database, "find_helper32", lambda configured: [sys.executable, str(script), str(data)])
    item, col = _collector()

    def run():
        return database._read_access_helper32(ctx, "dummy.mdb", col, item, 0, "db.mdb")

    return item, run, seen


def test_helper32_missing(monkeypatch):
    """補助が見つからなければ、次の手段へ回すための例外を出す。"""
    monkeypatch.setattr(database, "find_helper32", lambda configured: None)
    item, col = _collector()
    with pytest.raises(RuntimeError, match="見つからない"):
        database._read_access_helper32(_Ctx(), "dummy.mdb", col, item, 0, "db.mdb")


def test_helper32_passes_passwords_and_row_limit(tmp_path, monkeypatch):
    """パスワードは引数でなく標準入力で渡し、表の行数の上限は引数で渡す。"""
    ctx = _Ctx(passwords=["秘密1", "pw2"], max_rows=50)
    msgs = [{"type": "open", "driver": "Jet", "method": "ODBC"}, {"type": "done"}]
    _item, run, seen = _fake_helper(tmp_path, monkeypatch, msgs, ctx)
    assert run() == "32bit Jet（ODBC）"
    got = json.loads(seen.read_text(encoding="utf-8"))
    assert got["argv"] == ["dummy.mdb", "--password-file", "-", "--max-rows-per-table", "50"]
    assert got["stdin"] == "秘密1\npw2"


def test_helper32_blob_warning_and_notes(tmp_path, monkeypatch):
    """OLE の値は中のファイルの頭から入れ子で検査し、壊れた値・警告は黙って捨てずに残す。"""
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
    msgs = [
        {"type": "open", "driver": "Jet", "method": "ODBC"},
        {"type": "table", "name": "名簿", "columns": ["氏名", "電話"]},
        {"type": "row", "table": "名簿", "row": 1, "values": ["架空 太郎", PHONE]},
        {
            "type": "blob",
            "table": "名簿",
            "row": 1,
            "column": "写真",
            "data_b64": base64.b64encode(b"OLE" + png).decode(),
        },
        {"type": "blob", "table": "名簿", "row": 2, "column": "写真", "data_b64": "a"},
        {"type": "warning", "message": "表「壊れ」を読めませんでした"},
        {"type": "warning", "message": "表「大きい」は 100 行で打ち切りました"},
        {"type": "warning", "message": "そのほかの注意"},
        "読めない行",
        {"type": "done"},
    ]
    ctx = _Ctx()
    item, run, _seen = _fake_helper(tmp_path, monkeypatch, msgs, ctx)
    run()
    assert item.finding_counts.get("phone"), item.finding_counts
    assert [(d, data, depth, hint) for d, data, depth, hint in ctx.nested] == [
        ("db.mdb!表「名簿」1行目 列「写真」", png, 1, "field.bin")
    ]
    assert any(n.startswith("OLE オブジェクトを取り出せなかった") for n in item.notes), item.notes
    assert "そのほかの注意" in item.notes and "表「名簿」" in item.notes
    failed = {i.path: i.status for i in ctx.items}
    assert failed == {"db.mdb!表「壊れ」": Status.UNCHECKABLE, "db.mdb!表「大きい」": Status.PARTIAL}


def test_helper32_password_error(tmp_path, monkeypatch):
    """補助がパスワード違いを知らせたら、パスワードを尋ねる側へ回す。"""
    msgs = [{"type": "error", "code": "password", "message": "x"}, {"type": "done"}]
    _item, run, _seen = _fake_helper(tmp_path, monkeypatch, msgs, _Ctx())
    with pytest.raises(NeedPassword):
        run()


def test_helper32_other_error(tmp_path, monkeypatch):
    msgs = [{"type": "error", "code": "open", "message": "壊れている"}, {"type": "done"}]
    _item, run, _seen = _fake_helper(tmp_path, monkeypatch, msgs, _Ctx())
    with pytest.raises(RuntimeError, match="32bit 補助で開けなかった: 壊れている"):
        run()


def test_helper32_ended_without_done(tmp_path, monkeypatch):
    """終わりの知らせが来ないまま補助が終わったら、終了コードとともに失敗にする（読めた所までで済ませない）。"""
    msgs = [{"type": "open", "driver": "Jet", "method": "ODBC"}]
    _item, run, _seen = _fake_helper(tmp_path, monkeypatch, msgs, _Ctx(), exit_code=3)
    with pytest.raises(RuntimeError, match="途中で終わった（終了コード 3）"):
        run()


# ------------------------------------------------------------------ OLE の値


def test_ole_field_takes_earliest_magic():
    """値の中で一番前にあるファイルの頭から取り出す（OLE の包みの見出しを外す）。"""
    ctx = _Ctx()
    data = b"head" + b"%PDF-1.4 x" + b"PK\x03\x04rest"
    database._scan_ole_field(ctx, data, "d", 0)
    assert ctx.nested[0][1] == data[4:]


def test_ole_field_without_magic_is_scanned_whole():
    ctx = _Ctx()
    database._scan_ole_field(ctx, b"plain bytes", "d", 2)
    assert ctx.nested == [("d", b"plain bytes", 3, "field.bin")]


# ------------------------------------------------------------------ ODBC（pyodbc を差し替える）


class _FakeCursor:
    def __init__(self, conn):
        self.conn = conn
        self.rows: list = []
        self.description = None

    def tables(self):
        return [SimpleNamespace(table_name=n, table_type=t) for n, t in self.conn.catalog]

    def execute(self, sql):
        self.conn.sql.append(sql)
        if sql.startswith("SELECT * FROM "):
            name = sql[len("SELECT * FROM [") : -1]
            if name in self.conn.broken:
                raise RuntimeError("壊れた表")
            columns, self.rows = self.conn.data[name]
            self.description = [(c, str, None, size) for c, size in columns]
            self.rows = list(self.rows)
            return
        for cname, rows in self.conn.attachments.items():
            if f".[{cname}].[FileName]" in sql:
                if "WHERE 1=0" in sql:
                    self.rows = []
                elif rows is None:
                    raise RuntimeError("添付を読めない")
                else:
                    self.rows = list(rows)
                return
        raise RuntimeError("添付の列ではない")

    def fetchmany(self, n):
        out, self.rows = self.rows[:n], self.rows[n:]
        return out

    def fetchone(self):
        return self.rows.pop(0) if self.rows else None

    def close(self):
        pass


class _FakeConn:
    def __init__(self, catalog, data, broken=(), attachments=None):
        self.catalog, self.data, self.broken = catalog, data, set(broken)
        self.attachments = attachments or {}
        self.sql: list[str] = []
        self.closed = False

    def cursor(self):
        return _FakeCursor(self)

    def close(self):
        self.closed = True


def test_dump_odbc_tables_links_and_blobs(monkeypatch):
    """システムの表を飛ばし、リンクテーブルは注記に、読めない表は項目に残す。長いバイナリだけ中を検査する。"""
    memo = database.MEMO_SIZE
    conn = _FakeConn(
        catalog=[("MSysObjects", "SYSTEM TABLE"), ("名簿", "TABLE"), ("壊れ", "TABLE"), ("外部", "LINK")],
        data={
            "名簿": (
                [("氏名", 255), ("電話", 255), ("写真", 0), ("添付", memo), ("備考", memo)],
                [["架空 太郎", PHONE, b"\x01" * 100, "a.txt", "x"], ["架空 花子", "", b"short", None, None]],
            )
        },
        broken=["壊れ"],
        attachments={"添付": [("a.txt", b"x"), ("空.txt", None)]},
    )
    monkeypatch.setattr(database, "ATTACHMENT_LIMIT", 1024)
    ctx = _Ctx()
    item, col = _collector()
    database._dump_odbc(ctx, conn, col, item, 0, "db.accdb")
    assert item.finding_counts.get("phone") == 1, item.finding_counts
    assert "リンクテーブル（リンク先は別に検査が必要）: 外部" in item.notes
    assert "表「名簿」2行" in item.notes
    assert "表「名簿」の添付ファイル型の列「添付」: ファイル 1 件" in item.notes
    assert not any("備考" in n for n in item.notes)  # 添付の列でないメモは添付として数えない
    assert [i.path for i in ctx.items] == ["db.accdb!表「壊れ」"]
    assert database.ACCESS_REPAIR_HINT in ctx.items[0].reason
    shown = [d for d, *_ in ctx.nested]
    assert shown == ["db.accdb!表「名簿」1行目 列「写真」", "db.accdb!表「名簿」列「添付」の添付「a.txt」"]
    assert not any("MSys" in s for s in conn.sql)


def test_odbc_attachment_unreadable_big_and_limit(monkeypatch):
    """添付の中身を読めない列は項目に残し、大きすぎる添付は取り出さずに残す。行数の上限で止める。"""
    memo = database.MEMO_SIZE
    conn = _FakeConn(
        catalog=[("t", "TABLE")],
        data={"t": ([("a", memo), ("b", memo)], [["x", "y"]])},
        attachments={"a": None, "b": [("big.bin", b"\x00" * 2048), ("1.txt", b"1"), ("2.txt", b"2")]},
    )
    monkeypatch.setattr(database, "ATTACHMENT_LIMIT", 1024)
    ctx = _Ctx(max_rows=2)
    item, col = _collector()
    database._dump_odbc(ctx, conn, col, item, 0, "db.accdb")
    reasons = {i.path: i.reason for i in ctx.items}
    assert "添付ファイル型の列「a」を読めなかった" in reasons["db.accdb!表「t」"]
    big = reasons["db.accdb!表「t」列「b」の添付「big.bin」"]
    assert big.startswith("添付ファイルが大きすぎる（0MB）")
    assert [d for d, *_ in ctx.nested] == [
        "db.accdb!表「t」列「b」の添付「1.txt」"
    ]  # 上限2件（大きいものも1件と数える）
    assert "表「t」の添付ファイル型の列「b」: ファイル 2 件" in item.notes


def test_odbc_row_limit_stops_reading():
    conn = _FakeConn(catalog=[("t", "TABLE")], data={"t": ([("v", 10)], [[str(i)] for i in range(5)])})
    item, col = _collector()
    database._dump_odbc(_Ctx(max_rows=3), conn, col, item, 0, "db.accdb")
    assert "表「t」3行" in item.notes


def _fake_pyodbc(monkeypatch, drivers, connect):
    class Error(Exception):
        pass

    mod = SimpleNamespace(drivers=lambda: drivers, connect=lambda s, **kw: connect(s, Error), Error=Error)
    monkeypatch.setitem(sys.modules, "pyodbc", mod)


def test_odbc_no_driver(monkeypatch):
    _fake_pyodbc(monkeypatch, ["SQL Server"], lambda s, E: None)
    item, col = _collector()
    with pytest.raises(RuntimeError, match="ODBC ドライバが入っていない"):
        database._read_access_odbc(_Ctx(), "a.accdb", col, item, 0, "a.accdb")


def test_odbc_password_tried_then_opened(monkeypatch):
    """パスワードの候補を順に試し、開けたら注記を残す。; を含むパスワードだけ波括弧で囲む。"""
    tried = []
    conn = _FakeConn(catalog=[], data={})

    def connect(s, Error):
        tried.append(s)
        if "PWD=" not in s or "PWD={a;b}" not in s:
            raise Error("Not a valid password. (-1905)")
        return conn

    _fake_pyodbc(monkeypatch, ["Microsoft Access Driver (*.mdb, *.accdb)"], connect)
    item, col = _collector()
    drv = database._read_access_odbc(_Ctx(passwords=["x", "a;b"]), "a.accdb", col, item, 0, "a.accdb")
    assert drv.startswith("Microsoft Access Driver")
    assert len(tried) == 3 and "PWD=x;" in tried[1]
    assert "データベースパスワードで開いた" in item.notes and conn.closed


def test_odbc_password_all_wrong(monkeypatch):
    def connect(s, Error):
        raise Error("パスワードが違います")

    _fake_pyodbc(monkeypatch, ["Microsoft Access Driver (*.mdb, *.accdb)"], connect)
    item, col = _collector()
    with pytest.raises(NeedPassword):
        database._read_access_odbc(_Ctx(passwords=["x"]), "a.accdb", col, item, 0, "a.accdb")


def test_odbc_other_error_moves_to_next_driver(monkeypatch):
    """パスワード以外の失敗は、そのドライバでの残りの候補を試さずに次のドライバへ。"""
    tried = []

    def connect(s, Error):
        tried.append(s)
        raise Error("ファイルが壊れている")

    _fake_pyodbc(monkeypatch, ["Microsoft Access Driver (*.mdb)", "Microsoft Access Driver (*.mdb, *.accdb)"], connect)
    item, col = _collector()
    with pytest.raises(RuntimeError, match="64bit ODBC で開けなかった: ファイルが壊れている"):
        database._read_access_odbc(_Ctx(passwords=["x"]), "a.accdb", col, item, 0, "a.accdb")
    assert len(tried) == 2 and "*.accdb" in tried[0]  # accdb のドライバを先に


# ------------------------------------------------------------------ dBase


def _dbf(records: list[bytes], declared: int | None = None) -> bytes:
    """列「NAME」（20 バイト）だけの dBase を作る。"""
    header_len = 32 + 32 + 1
    head = b"\x03\x7a\x0b\x07" + (declared if declared is not None else len(records)).to_bytes(4, "little")
    head += header_len.to_bytes(2, "little") + (21).to_bytes(2, "little") + b"\x00" * 20
    field = b"NAME".ljust(11, b"\x00") + b"C" + b"\x00" * 4 + bytes([20]) + b"\x00" * 15
    return head + field + b"\x0d" + b"".join(records)


def _rec(flag: bytes, text: str) -> bytes:
    return flag + text.encode("cp932").ljust(20, b" ")


def test_dbase_counts_deleted_records(tmp_path):
    """削除の印の付いたレコードも検査し、件数を方法の欄に出す。"""
    p = tmp_path / "list.dbf"
    p.write_bytes(_dbf([_rec(b" ", "a"), _rec(b"*", PHONE)]))
    item = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path))).items[0]
    assert item.method == "dBase の全レコード 2 件（削除フラグ付き 1 件を含む）"
    assert item.finding_counts.get("phone") == 1


def test_dbase_truncated_records_is_partial(tmp_path):
    """見出しの件数よりレコードが短ければ、読めた所までを検査して一部だけと知らせる。"""
    p = tmp_path / "list.dbf"
    p.write_bytes(_dbf([_rec(b" ", PHONE), b" short"], declared=5))
    item = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path))).items[0]
    assert item.status == Status.PARTIAL, (item.status, item.reason)
    assert "見出しの件数 5 件のうち 1 件まで読んだ" in item.reason
    assert item.finding_counts.get("phone") == 1

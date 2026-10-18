"""access32_helper.py（32bit で Access を読む補助スクリプト）の試験。

32bit の Python で実行すること::

    <32bit の Python>/python.exe -m pytest tests/test_access32_helper.py

試験用の DB は tmp_path の下に Jet の ODBC（SQLConfigDataSource の CREATE_DB / CREATE_DBV3）で
作る。.accdb とリンクテーブル・大きなバイナリは 64bit 側の ACE DAO（64bit venv の pywin32）で作り、
64bit venv が無ければその試験は飛ばす。個人情報はすべて架空。
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import subprocess
import sys
import textwrap

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
HELPER = os.path.normpath(os.path.join(HERE, "..", "pii_checker", "access32_helper.py"))
sys.path.insert(0, os.path.dirname(HELPER))
import access32_helper as h  # noqa: E402

# .accdb 等を作る 64bit の Python（環境変数 PIICHK_PYTHON64 で変えられる。無ければその検体は作らない）
PYTHON64 = os.environ.get(
    "PIICHK_PYTHON64", os.path.join(os.path.expanduser("~"), "temp/venv/personal-info-checker/Scripts/python.exe")
)
PASSWORD = "Kasou#2024"

pytestmark = pytest.mark.skipif(h.struct_pointer_bits() != 32, reason="32bit の Python で実行する試験")


# ---------------------------------------------------------------------------
# 試験 DB を作る道具
# ---------------------------------------------------------------------------
def create_mdb(path: str, jet3: bool = False) -> None:
    """Jet の ODBC で空の mdb を作る（jet3=True なら Access 97 形式）。"""
    cp = ctypes.WinDLL("odbccp32")
    cp.SQLConfigDataSourceW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_ushort,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
    ]
    # 既存のファイルがあると古い中身のまま試験が進むおそれがあるので、新規に限る
    assert not os.path.exists(path), f"試験 DB が既にあります: {path}"
    keyword = "CREATE_DBV3" if jet3 else "CREATE_DB"
    ok = cp.SQLConfigDataSourceW(None, 1, h.ODBC_DRIVER_JET, f'{keyword}="{path}" General\0\0')
    assert ok, f"{keyword} に失敗しました: {path}"


def connect_rw(path: str, ansi92: bool = False):
    """試験データを書き込むための排他・書き込み可能な接続。"""
    extra = "ExtendedAnsiSQL=1;" if ansi92 else ""
    return h.CtypesOdbc().connect(
        f"DRIVER={{{h.ODBC_DRIVER_JET}}};DBQ={path};Exclusive=1;{extra}",
        readonly=False,
    )


def fill_sample(path: str, view: bool = False) -> None:
    """日本語の表名・列名と架空データを入れる。"""
    conn = connect_rw(path, ansi92=view)
    try:
        conn.execute(
            "CREATE TABLE [顧客 一覧] ([氏名] TEXT(50), [住所] TEXT(100), [電話番号] TEXT(20),"
            " [生年月日] DATETIME, [金額] CURRENCY, [有効] BIT, [写真] LONGBINARY,"
            " [備考] LONGTEXT)"
        )
        conn.execute(
            "INSERT INTO [顧客 一覧] VALUES ('山田 太郎', '東京都千代田区架空町1-2-3',"
            " '03-0000-1111', #1980-04-01 12:34:56#, 1234.5, True, 0x89504E470D0A, 'メモ')"
        )
        conn.execute("INSERT INTO [顧客 一覧] ([氏名]) VALUES ('佐藤 花子')")
        conn.execute("CREATE TABLE [住所録-2024 (旧)] ([電話 番号] TEXT(20), [ID] INTEGER)")
        conn.execute("INSERT INTO [住所録-2024 (旧)] VALUES ('090-0000-2222', 7)")
        if view:
            conn.execute(
                # CREATE VIEW の名前は角括弧で囲むと「not a valid name」になる（実測）
                "CREATE VIEW 顧客ビュー AS SELECT [氏名] FROM [顧客 一覧]"
            )
    finally:
        conn.close()


def fill_many(path: str, n: int) -> None:
    """行数の多い表と、64KB を超える長いメモを入れる。"""
    conn = connect_rw(path)
    try:
        conn.execute("CREATE TABLE [多い表] ([番号] INTEGER, [氏名] TEXT(50))")
        for i in range(1, n + 1):
            conn.execute(f"INSERT INTO [多い表] VALUES ({i}, '架空 {i}号')")
        conn.execute("CREATE TABLE [長文] ([本文] LONGTEXT)")
        conn.execute("INSERT INTO [長文] VALUES ('" + "住所東京都" * 200 + "')")
        for _ in range(7):  # 1000 文字 → 128000 文字
            conn.execute("UPDATE [長文] SET [本文] = [本文] & [本文]")
    finally:
        conn.close()


def set_password(path: str, password: str) -> None:
    """DB にパスワードを付ける（ANSI-92 モードの ALTER DATABASE PASSWORD）。"""
    conn = connect_rw(path, ansi92=True)
    try:
        conn.execute(f"ALTER DATABASE PASSWORD [{password}] NULL")
    finally:
        conn.close()


SCRIPT64 = textwrap.dedent(r"""
    import sys
    import pythoncom
    import win32com.client
    pythoncom.CoInitialize()
    eng = win32com.client.Dispatch("DAO.DBEngine.120")
    accdb, mdb, src = sys.argv[1], sys.argv[2], sys.argv[3]
    db = eng.CreateDatabase(accdb, ";LANGID=0x0411;CP=932;COUNTRY=0")
    db.Execute("CREATE TABLE [顧客] ([氏名] TEXT(50), [住所] TEXT(100), [電話番号] TEXT(20))")
    db.Execute("INSERT INTO [顧客] VALUES ('鈴木 一郎', '大阪府架空市1-1', '06-0000-3333')")
    db.Close()
    sdb = eng.OpenDatabase(src)
    sdb.Execute("CREATE TABLE [元表] ([氏名] TEXT(50))")
    sdb.Close()
    db = eng.OpenDatabase(mdb)
    td = db.CreateTableDef("リンク表")
    td.Connect = ";DATABASE=" + src
    td.SourceTableName = "元表"
    db.TableDefs.Append(td)
    db.Execute("CREATE TABLE [大きい] ([番号] INTEGER, [写真] LONGBINARY)")
    rs = db.OpenRecordset("大きい")
    rs.AddNew()
    rs.Fields("番号").Value = 1
    rs.Fields("写真").AppendChunk(bytes(range(256)) * 400)
    rs.Update()
    rs.Close()
    db.Close()
    print("ok")
    """)


@pytest.fixture(scope="module")
def dbs(tmp_path_factory) -> dict[str, str]:
    """試験 DB 一式を作って {名前: パス} を返す。"""
    d = tmp_path_factory.mktemp("access32")
    paths = {
        "jet4": str(d / "jet4.mdb"),
        "jet3": str(d / "jet3_access97.mdb"),
        "pw4": str(d / "password4.mdb"),
        "pw3": str(d / "password3_access97.mdb"),
        "many": str(d / "many.mdb"),
        "linked": str(d / "linked.mdb"),
        "src": str(d / "link_source.mdb"),
        "accdb": str(d / "ace.accdb"),
    }
    create_mdb(paths["jet4"])
    fill_sample(paths["jet4"], view=True)
    create_mdb(paths["jet3"], jet3=True)
    fill_sample(paths["jet3"])
    create_mdb(paths["pw4"])
    fill_sample(paths["pw4"])
    set_password(paths["pw4"], PASSWORD)
    create_mdb(paths["pw3"], jet3=True)
    fill_sample(paths["pw3"])
    set_password(paths["pw3"], PASSWORD)
    create_mdb(paths["many"])
    fill_many(paths["many"], 1000)
    create_mdb(paths["linked"])
    fill_sample(paths["linked"])
    create_mdb(paths["src"])
    paths["has64"] = ""
    if os.path.isfile(PYTHON64):
        script = d / "make64.py"
        script.write_text(SCRIPT64, encoding="utf-8")
        proc = subprocess.run(
            [PYTHON64, str(script), paths["accdb"], paths["linked"], paths["src"]],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
        if proc.returncode == 0:
            paths["has64"] = "1"
    return paths


def file_state(path: str) -> tuple[str, int, float]:
    """(SHA-256, サイズ, 更新時刻)。"""
    with open(path, "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
    st = os.stat(path)
    return digest, st.st_size, st.st_mtime


def run_helper(*args: str, exe: str | None = None) -> tuple[int, list[dict]]:
    """補助スクリプトを子プロセスで走らせ、(終了コード, JSON の一覧) を返す。DB の不変も確かめる。"""
    db_path = args[0]
    before = file_state(db_path) if os.path.isfile(db_path) else None
    cmd = [exe] if exe else [sys.executable, HELPER]
    proc = subprocess.run(cmd + list(args), capture_output=True, timeout=300)
    lines = [json.loads(line) for line in proc.stdout.decode("utf-8").splitlines() if line.strip()]
    if before is not None:
        assert file_state(db_path) == before, "DB ファイルが変更されました"
    return proc.returncode, lines


def by_type(lines: list[dict], kind: str) -> list[dict]:
    return [x for x in lines if x["type"] == kind]


def rows_of(lines: list[dict], table: str) -> list[list]:
    return [x["values"] for x in lines if x["type"] == "row" and x["table"] == table]


def check_sample(lines: list[dict]) -> None:
    """fill_sample で入れた中身が読めていること。"""
    tables = {t["name"]: t["columns"] for t in by_type(lines, "table")}
    assert tables["顧客 一覧"] == [
        "氏名",
        "住所",
        "電話番号",
        "生年月日",
        "金額",
        "有効",
        "写真",
        "備考",
    ]
    assert tables["住所録-2024 (旧)"] == ["電話 番号", "ID"]
    rows = rows_of(lines, "顧客 一覧")
    assert rows[0] == [
        "山田 太郎",
        "東京都千代田区架空町1-2-3",
        "03-0000-1111",
        "1980-04-01T12:34:56",
        "1234.5000",
        "True",
        None,
        "メモ",
    ]
    assert rows[1][0] == "佐藤 花子"
    assert rows[1][1] is None
    assert rows_of(lines, "住所録-2024 (旧)") == [["090-0000-2222", "7"]]
    blobs = by_type(lines, "blob")
    assert blobs[0]["table"] == "顧客 一覧"
    assert blobs[0]["column"] == "写真"
    assert blobs[0]["row"] == 1
    assert blobs[0]["data_b64"] == "iVBORw0K"  # 0x89504E470D0A
    # システム表は出さない
    assert not [n for n in tables if n.upper().startswith("MSYS")]
    done = lines[-1]
    assert done["type"] == "done"
    assert done["rows"] == sum(1 for x in lines if x["type"] == "row")


# ---------------------------------------------------------------------------
# 試験
# ---------------------------------------------------------------------------
def test_jet3_file_is_really_access97(dbs):
    """CREATE_DBV3 で作った DB が Jet3（Access 97）形式であること（ヘッダの版 0）。"""
    assert h.detect_format(h.read_header(dbs["jet3"])) == "jet3"
    assert h.detect_format(h.read_header(dbs["jet4"])) == "jet4"


def test_read_jet4(dbs):
    code, lines = run_helper(dbs["jet4"])
    assert code == 0
    assert lines[0] == {
        "type": "open",
        "driver": h.ODBC_DRIVER_JET,
        "method": "odbc",
        "password_used": False,
    }
    check_sample(lines)
    # クエリ（ビュー）は読まない
    assert "顧客ビュー" not in [t["name"] for t in by_type(lines, "table")]


def test_read_jet3_access97(dbs):
    """Access 97（Jet3）形式を日本語ごと読めること。"""
    code, lines = run_helper(dbs["jet3"])
    assert code == 0
    assert lines[0]["type"] == "open"
    check_sample(lines)


@pytest.mark.parametrize("key", ["pw4", "pw3"])
def test_password_missing(dbs, key):
    code, lines = run_helper(dbs[key])
    assert code == 2
    assert len(lines) == 1
    assert lines[0]["type"] == "error"
    assert lines[0]["code"] == "password"
    assert "パスワード" in lines[0]["message"]


@pytest.mark.parametrize("key", ["pw4", "pw3"])
def test_password_file(dbs, key, tmp_path):
    pw_file = tmp_path / "pw.txt"
    pw_file.write_text("違うパスワード\nwrong\n" + PASSWORD + "\n", encoding="utf-8")
    code, lines = run_helper(dbs[key], "--password-file", str(pw_file))
    assert code == 0
    assert lines[0]["type"] == "open"
    assert lines[0]["password_used"] is True
    check_sample(lines)


def test_password_file_all_wrong(dbs, tmp_path):
    pw_file = tmp_path / "pw.txt"
    pw_file.write_text("wrong1\nwrong2\n", encoding="utf-8")
    code, lines = run_helper(dbs["pw4"], "--password-file", str(pw_file))
    assert code == 2
    assert lines[-1]["code"] == "password"
    assert "指定されたパスワード" in lines[-1]["message"]


def test_no_password_needed_reports_unused(dbs, tmp_path):
    """パスワード不要の DB では、ファイルを渡しても password_used は False。"""
    pw_file = tmp_path / "pw.txt"
    pw_file.write_text(PASSWORD + "\n", encoding="utf-8")
    code, lines = run_helper(dbs["jet4"], "--password-file", str(pw_file))
    assert code == 0
    assert lines[0]["password_used"] is False


def test_many_rows_and_long_memo(dbs):
    code, lines = run_helper(dbs["many"])
    assert code == 0
    rows = rows_of(lines, "多い表")
    assert len(rows) == 1000
    assert rows[-1] == ["1000", "架空 1000号"]
    assert [x["row"] for x in lines if x.get("table") == "多い表" and x["type"] == "row"][:3] == [1, 2, 3]
    memo = rows_of(lines, "長文")[0][0]
    assert memo == "住所東京都" * 200 * 128  # 64KB 超を分割読みで欠けずに読む


def test_max_rows_per_table(dbs):
    code, lines = run_helper(dbs["many"], "--max-rows-per-table", "10")
    assert code == 0
    assert len(rows_of(lines, "多い表")) == 10
    assert any("10 行で打ち切り" in w["message"] for w in by_type(lines, "warning"))
    assert lines[-1]["rows"] == 11  # 多い表 10 行 + 長文 1 行


def test_linked_table_and_big_blob(dbs):
    if not dbs["has64"]:
        pytest.skip("64bit の ACE DAO で試験 DB を作れなかった")
    code, lines = run_helper(dbs["linked"])
    assert code == 0
    names = [t["name"] for t in by_type(lines, "table")]
    assert "リンク表" not in names
    warns = [w["message"] for w in by_type(lines, "warning") if "リンク表" in w["message"]]
    assert len(warns) == 1
    assert dbs["src"] in warns[0]
    assert "元表" in warns[0]
    big = [b for b in by_type(lines, "blob") if b["table"] == "大きい"]
    assert len(big) == 1
    import base64

    assert base64.b64decode(big[0]["data_b64"]) == bytes(range(256)) * 400


def test_accdb_without_32bit_ace(dbs):
    if not dbs["has64"]:
        pytest.skip("64bit の ACE DAO で .accdb を作れなかった")
    code, lines = run_helper(dbs["accdb"])
    if h.ODBC_DRIVER_ACE in h.CtypesOdbc().drivers():
        # 32bit の ACE がある PC なら読めるはず
        assert code == 0
        assert rows_of(lines, "顧客") == [["鈴木 一郎", "大阪府架空市1-1", "06-0000-3333"]]
    else:
        assert code == 2
        assert lines[-1]["type"] == "error"
        assert lines[-1]["code"] == "driver_missing"
        assert "ACE" in lines[-1]["message"]


def test_not_access_file(tmp_path):
    p = tmp_path / "偽物.mdb"
    p.write_bytes(b"this is not an access database" * 10)
    code, lines = run_helper(str(p))
    assert code == 2
    assert lines == [lines[0]]
    assert lines[0]["code"] == "corrupt"


def test_truncated_file_is_corrupt(dbs, tmp_path):
    """先頭だけ本物で中身が欠けた mdb は corrupt（または other）で止まり、落ちないこと。"""
    with open(dbs["jet4"], "rb") as fh:
        head = fh.read(4096)
    p = tmp_path / "壊れ.mdb"
    p.write_bytes(head)
    code, lines = run_helper(str(p))
    assert code == 2
    assert lines[-1]["type"] == "error"
    assert lines[-1]["code"] in ("corrupt", "other")


def test_missing_file(tmp_path):
    code, lines = run_helper(str(tmp_path / "無い.mdb"))
    assert code == 2
    assert lines[0]["type"] == "error"
    assert "見つかりません" in lines[0]["message"]


# ---------------------------------------------------------------------------
# 単体の試験
# ---------------------------------------------------------------------------
def test_bracket():
    assert h.bracket("顧客 一覧") == "[顧客 一覧]"
    assert h.bracket("a]b") == "[a]]b]"


def test_odbc_value():
    assert h.odbc_value(r"C:\a b\c.mdb") == r"C:\a b\c.mdb"
    assert h.odbc_value("p;w") == "{p;w}"
    assert h.odbc_value("p}w") == "{p}}w}"


def test_value_to_text():
    import datetime
    import decimal

    assert h.value_to_text(None) is None
    assert h.value_to_text(True) == "True"
    assert h.value_to_text(3) == "3"
    assert h.value_to_text(1.5) == "1.5"
    assert h.value_to_text(2.0) == "2"
    assert h.value_to_text(decimal.Decimal("12.50")) == "12.50"
    assert h.value_to_text(datetime.datetime(2020, 1, 2, 3, 4, 5)) == "2020-01-02T03:04:05"


def test_format_link_target():
    assert h.format_link_target(";DATABASE=C:\\x\\y.mdb", "T") == "C:\\x\\y.mdb（表: T）"
    assert h.format_link_target("MS Access;PWD=;DATABASE=C:\\y.mdb", None) == "C:\\y.mdb（MS Access;PWD=）"


def test_odbc_driver_order():
    jet = h.ODBC_DRIVER_JET
    ace = h.ODBC_DRIVER_ACE
    assert h.odbc_driver_order([jet, ace, "SQL Server"]) == [ace, jet]
    assert h.odbc_driver_order(["Microsoft Access-Treiber (*.mdb)", "SQL Server"]) == [
        "Microsoft Access-Treiber (*.mdb)"
    ]


def test_classify_driver_error():
    assert h.classify_driver_error(h.DriverError("Not a valid password.", "42000", -1905)) == "password"
    assert h.classify_driver_error(h.DriverError("x", "HY000", -1028)) == "unrecognized"
    assert h.classify_driver_error(h.DriverError("x", "IM002", 0)) == "driver_missing"


def test_helper_exe_reads_jet3(dbs):
    """ビルド済みの exe があれば、exe でも Jet3 を読めること。"""
    exe = os.path.normpath(os.path.join(HERE, "..", "dist_helper32", "access32_helper.exe"))
    if not os.path.isfile(exe):
        pytest.skip("dist_helper32/access32_helper.exe が無い（build_helper32.ps1 で作る）")
    code, lines = run_helper(dbs["jet3"], exe=exe)
    assert code == 0
    check_sample(lines)

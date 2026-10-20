"""Access（.accdb・.mdb）への対処（T2-e）の試験。

使える手段ごとに（無い手段の試験は skip）: ACE（64bit の ODBC）・Jet（Windows 標準の 32bit・同梱の 32bit Python の補助）・
Jackcess（Java。tools/jackcess の補助を試験の中で javac でビルドして使う）。守ること:
- 各方法のあと検査し直して消え、関係ない行・表が元のまま・消した値がファイルのバイト列に残らない（最適化・塗りつぶしの確認）
- フォーム・クエリなど表以外のオブジェクト・索引が残る（ACE・Jet では、MSysObjects の表以外の種類別の数でも確かめる）
- 明細の上限（20 件）を超える行数（120 行）でも全部に効く
- 値が残ったときは確定しない・手段が無いときはファイルの削除だけ
- 確定の手順（ごみ箱・一時の新ファイル・記録）に載る・記録とジョブの DB に生の値が入らない（陽性対照つき）
検体はすべて pytest の tmp_path に作る。本物のごみ箱へは送らない（送る関数を差し替える）。画面・Access 本体は起動しない。
"""

from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from pii_checker import access_scrub, engine, remediate, remedy_access as ra  # noqa: E402
from pii_checker.models import PasswordBook, ScanOptions  # noqa: E402
from pii_checker.remedy_write import DummyMaker, RemedyError, select_positions  # noqa: E402
from test_remediate import (  # noqa: E402
    ALL_RANKS,
    FakeTrash,
    _leak,
    analyze,
    make_service,
    new_tmp_files,
    person_rows,
    run,
    scan_counts,
)

N = 120  # 明細の上限（20 件）を大きく超える行数
ROOT = Path(__file__).resolve().parent.parent
DEPENDENCY_JARS = ("jackcess-", "commons-lang3-", "commons-logging-")


@pytest.fixture(autouse=True)
def trash(tmp_path, monkeypatch):
    """どの試験でも、ごみ箱へ送る関数を差し替える（本物のごみ箱へ送らない）。ごみ箱のある場所として扱う。"""
    t = FakeTrash(tmp_path / "_trash")
    monkeypatch.setattr(remediate, "send_to_recycle_bin", t)
    monkeypatch.setattr(remediate, "has_recycle_bin", lambda path: True)
    return t


# ---------------------------------------------------------------- 使える手段の調べ方（Jackcess は試験の中でビルドする）


def _javac() -> tuple[str, str] | None:
    """（javac.exe, jar.exe）。java.exe と同じ場所・JAVA_HOME・PATH から探す。"""
    homes = []
    java = shutil.which("java")
    if java:
        homes.append(Path(java).resolve().parent)
    if os.environ.get("JAVA_HOME"):
        homes.append(Path(os.environ["JAVA_HOME"]) / "bin")
    for h in homes:
        javac, jar = h / "javac.exe", h / "jar.exe"
        if javac.is_file() and jar.is_file():
            return str(javac), str(jar)
    return None


@pytest.fixture(scope="session")
def jackcess_dir(tmp_path_factory):
    """Jackcess の補助を動かす jar の置き場（4つ揃ったフォルダ）。作れなければ None。

    すでに環境変数 PIICHK_JACKCESS_DIR に揃っていればそれを使う。無ければ、vendor/jackcess（依存の jar の置き場。
    build.py --fetch-jackcess で入る）の jar を写し、tools/jackcess の Java のソースを javac でビルドして足す。
    """
    if ra.find_jackcess():
        return None  # すでに使える（環境の指定のまま）
    deps = ROOT / "vendor" / "jackcess"
    tools = _javac()
    if not deps.is_dir() or not tools or not shutil.which("java"):
        return False
    out = tmp_path_factory.mktemp("jackcess")
    for prefix in DEPENDENCY_JARS:
        found = sorted(deps.glob(prefix + "*.jar"))
        if not found:
            return False
        shutil.copy2(found[-1], out)
    classes = out / "classes"
    classes.mkdir()
    cp = os.pathsep.join(str(p) for p in out.glob("*.jar"))
    src = ROOT / "tools" / "jackcess" / "AccessRewrite.java"
    for cmd in (
        [tools[0], "-encoding", "UTF-8", "--release", "11", "-cp", cp, "-d", str(classes), str(src)],
        [tools[1], "cf", str(out / "piichk-access.jar"), "-C", str(classes), "."],
    ):
        if subprocess.run(cmd, capture_output=True).returncode != 0:
            return False
    return str(out)


@pytest.fixture(scope="session", autouse=True)
def jackcess_env(jackcess_dir):
    """Jackcess の補助を、この試験の間だけ探せるようにする。"""
    if jackcess_dir:
        old = os.environ.get("PIICHK_JACKCESS_DIR")
        os.environ["PIICHK_JACKCESS_DIR"] = jackcess_dir
        yield
        if old is None:
            os.environ.pop("PIICHK_JACKCESS_DIR", None)
        else:
            os.environ["PIICHK_JACKCESS_DIR"] = old
    else:
        yield


def available(strategy: str) -> bool:
    if strategy == "ace":
        return ra.ace_odbc_driver() is not None
    if strategy == "jet":
        cmd = ra.find_rewrite_helper32()
        return bool(cmd and ra.jet_available(tuple(cmd)))
    return ra.find_jackcess() is not None


# ---------------------------------------------------------------- 検体の作り方


def people(n: int = N) -> list[tuple[int, list[str]]]:
    """（id, [備考, 氏名, 電話, メール, メモ]）。5行に1行は個人情報なし。メモは長い文章（長い値のページに入る）。"""
    out = []
    for i, r in enumerate(person_rows(n)[1:]):
        memo = (f"連絡メモ{i}: " + "あ" * 400 + f" {r[3]}") if r[3] else (f"メモ{i} " + "い" * 400)
        out.append((i + 1, [*r, memo]))
    return out


def has_pii(row: list[str]) -> bool:
    return bool(row[3])


def needles_of(rows) -> list[str]:
    return [v for _i, r in rows for v in r[1:4] if v] + [r[3] for _i, r in rows if r[3]]


PEOPLE_DDL = (
    "CREATE TABLE people (id LONG, [備考] TEXT(50), [氏名] TEXT(50), [電話] TEXT(50), [メール] TEXT(100), [メモ] MEMO)"
)


def build_with_sql(backend, rows) -> None:
    """ACE・Jet の SQL で表を作る（索引・クエリ（ビュー）つき）。"""
    ex = backend.execute
    ex(PEOPLE_DDL)
    ex("CREATE INDEX idx_note ON people ([備考])")
    for i, r in rows:
        values = ",".join([str(i), *(ra.sql_text(v) for v in r)])
        ex(f"INSERT INTO people (id, [備考], [氏名], [電話], [メール], [メモ]) VALUES ({values})")
    ex("CREATE TABLE categories (cid LONG PRIMARY KEY, [cname] TEXT(20))")
    for c in range(3):
        ex(f"INSERT INTO categories (cid, [cname]) VALUES ({c}, 'カテゴリ{c}')")
    ex("CREATE TABLE items (sku TEXT(20), [label] TEXT(50), cid LONG)")
    for i in range(30):
        ex(f"INSERT INTO items (sku, [label], cid) VALUES ('A-{i:03d}', '商品{i}', {i % 3})")
    ex("ALTER TABLE items ADD CONSTRAINT fk_items_cat FOREIGN KEY (cid) REFERENCES categories (cid)")
    ex("CREATE VIEW v_people AS SELECT id FROM people")


def create_empty_ace(path: Path) -> None:
    """ODBC のドライバの設定 API で、空の Access ファイルを作る（.accdb は ACE 形式・.mdb は Jet 4 形式）。"""
    key = "CREATE_DBV12" if path.suffix == ".accdb" else "CREATE_DBV4"
    dll = ctypes.windll.odbccp32
    dll.SQLConfigDataSourceW.argtypes = [ctypes.c_void_p, ctypes.c_ushort, ctypes.c_wchar_p, ctypes.c_wchar_p]
    ok = dll.SQLConfigDataSourceW(None, 1, ra.ace_odbc_driver(), f"{key}={path}\0\0")
    assert ok and path.is_file()


def build_db(path: Path, rows=None) -> None:
    rows = rows if rows is not None else people()
    path.parent.mkdir(parents=True, exist_ok=True)
    if available("ace"):
        create_empty_ace(path)
        backend = ra.OdbcBackend(str(path), ra.ace_odbc_driver())
        try:
            build_with_sql(backend, rows)
        finally:
            backend.close()
    elif path.suffix == ".mdb" and available("jet"):
        cmd = ra.find_rewrite_helper32()
        with ra.HelperProcess(cmd) as hp:
            assert hp.call({"op": "create_db", "path": str(path)})["ok"]
        backend = ra.HelperBackend(str(path), cmd)
        try:
            build_with_sql(backend, rows)
        finally:
            backend.close()
    elif path.suffix == ".accdb" and available("jackcess"):
        build_with_jackcess(path, rows)
    else:
        pytest.skip("検体を作る手段（ACE・Jet・Jackcess）が無い")
    for suffix in ra.LOCK_SUFFIXES:
        lock = path.with_suffix(suffix)
        if lock.exists():
            lock.unlink()


def build_with_jackcess(path: Path, rows) -> None:
    env = ra.find_jackcess()
    cmd = [env["java"], "-cp", os.pathsep.join(env["classpath"]), "AccessRewrite"]
    pipe = ra._Pipe(cmd)
    sess = ra.JackcessSession.__new__(ra.JackcessSession)
    sess.pipe = pipe
    try:
        sess._call("create", ra._b64(str(path)))
        cols = [
            ("id", "long"),
            ("備考", "text"),
            ("氏名", "text"),
            ("電話", "text"),
            ("メール", "text"),
            ("メモ", "memo"),
        ]
        sess._call("newtable", ra._b64("people"), str(len(cols)), extra_lines=[f"{ra._b64(n)}\t{k}" for n, k in cols])
        lines = []
        for i, r in rows:
            cells = [f"i{i}"] + [("s" + ra._b64(v)) if v else "-" for v in r]
            lines.append("\t".join(cells))
        sess._call("insert", ra._b64("people"), str(len(lines)), extra_lines=lines)
        sess._call(
            "newtable", ra._b64("items"), "2", extra_lines=[f"{ra._b64('sku')}\ttext", f"{ra._b64('label')}\ttext"]
        )
        items = [f"s{ra._b64(f'A-{i:03d}')}\ts{ra._b64(f'商品{i}')}" for i in range(30)]
        sess._call("insert", ra._b64("items"), str(len(items)), extra_lines=items)
    finally:
        sess.close()


def snapshot(path: Path, tmp: Path) -> dict[str, list[tuple]]:
    """各表の行を（並びに依らない形で）読む。写しを作って、使える手段のどれかで開く（元に Access のロックファイルを作らない）。"""
    copy = tmp / ("snap" + path.suffix)
    shutil.copyfile(path, copy)
    try:
        if available("ace"):
            sess = ra.SqlSession(ra.OdbcBackend(str(copy), ra.ace_odbc_driver()))
        elif path.suffix == ".mdb" and available("jet"):
            sess = ra.SqlSession(ra.HelperBackend(str(copy), ra.find_rewrite_helper32()))
        else:
            sess = ra.JackcessSession(str(copy), ra.find_jackcess())
        try:
            out = {}
            for t in sess.tables():
                rows = sess.read_rows(t, set(range(1, 5001)))
                out[t] = sorted(
                    (tuple(None if isinstance(v, ra.Binary) else v for v in rows[k]) for k in rows), key=repr
                )
            return out
        finally:
            sess.close()
    finally:
        for f in tmp.glob("snap*"):
            f.unlink()


def non_table_objects(path: Path) -> dict | None:
    """表以外のオブジェクト（クエリ・リレーションシップ・フォームなどの入れ物・索引）の数。DAO（pywin32）が無ければ None。

    MSysObjects は DAO でも読み取り権限が無いので、DAO の集まり（QueryDefs・Relations・Containers・Indexes）で数える。
    """
    try:
        import pythoncom
        import win32com.client
    except ImportError:
        return None
    pythoncom.CoInitialize()
    try:
        eng = win32com.client.Dispatch("DAO.DBEngine.120")
        db = eng.OpenDatabase(str(path), False, True)
        try:
            return {
                "queries": sorted(q.Name for q in db.QueryDefs),
                "relations": sorted(r.Name for r in db.Relations),
                "containers": {
                    c.Name: c.Documents.Count for c in db.Containers if c.Name not in ("Tables", "Databases")
                },
                "indexes": {t.Name: t.Indexes.Count for t in db.TableDefs if not t.Name.startswith("MSys")},
            }
        finally:
            db.Close()
    except Exception:  # noqa: BLE001  DAO が使えない環境
        return None


CASES = [
    pytest.param(("ace", ".accdb"), id="ace-accdb"),
    pytest.param(("ace", ".mdb"), id="ace-mdb"),
    pytest.param(("jet", ".mdb"), id="jet-mdb"),
    pytest.param(("jackcess", ".accdb"), id="jackcess-accdb"),
]


@pytest.fixture
def case(request, tmp_path, monkeypatch):
    strategy, ext = request.param
    if not available(strategy):
        pytest.skip(f"{strategy} が使えない環境")
    p = tmp_path / "src" / f"people{ext}"
    build_db(p)
    monkeypatch.setattr(ra, "FORCED_STRATEGIES", [strategy])
    svc, store, job = make_service(tmp_path, [p])
    return strategy, p, svc, store, job


def with_case(fn):
    return pytest.mark.parametrize("case", CASES, indirect=True)(fn)


def pii_ids() -> list[int]:
    return [i for i, r in people() if has_pii(r)]


# ---------------------------------------------------------------- 位置を集める・下見


@pytest.mark.parametrize("ext", [".accdb", ".mdb"])
def test_collect_positions_numbers_rows_and_has_no_raw_values(tmp_path, ext):
    if not (available("ace") or available("jet") or available("jackcess")):
        pytest.skip("Access を読める手段が無い")
    p = tmp_path / "src" / f"people{ext}"
    build_db(p)
    got = remediate.collect_task({"path": str(p), "options": ScanOptions(temp_dir=str(tmp_path))})
    assert got["layout"] == "access" and got["status"] == "scanned" and not got["overflow"]
    emails = got["positions"][("people", "email", 2)]
    # 検出のある行は、メールの列とメモの列の2か所。明細の上限（20 件）を超えた分も全部
    assert sorted(set(emails[0::4])) == pii_ids() and len(pii_ids()) > 20
    assert all(isinstance(v, int) for arr in got["positions"].values() for v in arr)  # 位置は数値だけ
    schema = got["db_schema"]
    assert schema["tables"]["people"]["columns"] == ["id", "備考", "氏名", "電話", "メール", "メモ"]
    assert schema["access"]["strategies"] and schema["access"]["format"] in ("ace", "jet4")
    assert "user1@example.com" not in repr(schema)


def test_scrub_data_page_zeroes_only_deleted_rows_and_free_space():
    """合成したデータページで、削除済みの行と空き領域だけが 0 になり、生きている行・見出しは変わらない。"""
    page = bytearray(4096)
    page[0:2] = b"\x01\x01"
    rows = [b"A" * 100, b"SECRET-ROW-VALUE" * 4, b"C" * 50]
    n = len(rows)
    page[12:14] = n.to_bytes(2, "little")
    end = 4096
    offsets = []
    for i, r in enumerate(rows):
        start = end - len(r)
        page[start:end] = r
        offsets.append(start | (0x8000 if i == 1 else 0))
        end = start
    for i, off in enumerate(offsets):
        page[14 + 2 * i : 16 + 2 * i] = off.to_bytes(2, "little")
    page[14 + 2 * n : end] = b"LEFTOVER" * ((end - 14 - 2 * n) // 8) + bytes((end - 14 - 2 * n) % 8)
    before = bytes(page)
    cleared = access_scrub.scrub_data_page(page)
    assert cleared > 0 and b"SECRET" not in page and b"LEFTOVER" not in page
    assert bytes(page[4096 - 100 : 4096]) == rows[0] and bytes(page[end : end + 50]) == rows[2]
    assert page[: 14 + 2 * n] == before[: 14 + 2 * n]  # 見出しと行の位置の表は変えない
    # 見慣れない作り（行の位置が表より前）のページには触らない
    bad = bytearray(before)
    bad[14:16] = (8).to_bytes(2, "little")
    assert access_scrub.scrub_data_page(bad) == 0 and bytes(bad) == bytes(bad)


@pytest.mark.parametrize("ext", [".accdb", ".mdb"])
def test_positions_are_the_same_whichever_reader_scans(tmp_path, monkeypatch, ext):
    """検査の読み方（64bit ODBC・32bit 補助・純 Python）が違っても、位置（表・行の通し番号・列・値の範囲）は同じになる。
    書き換える手段が、検査と別の読み方でも、同じ行・同じ列に当たるための前提。"""
    from pii_checker.formats import database

    if not available("ace"):
        pytest.skip("基準にする ACE が使えない環境")
    p = tmp_path / "src" / f"people{ext}"
    build_db(p)

    def positions() -> dict:
        got = remediate.collect_task({"path": str(p), "options": ScanOptions(temp_dir=str(tmp_path))})
        assert got["layout"] == "access" and got["status"] == "scanned"
        return {k: list(v) for k, v in got["positions"].items()}

    base = positions()
    assert base
    refuse = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("試験: 使わない"))  # noqa: E731
    monkeypatch.setattr(database, "_read_access_odbc", refuse)
    if ext == ".mdb" and available("jet"):
        assert positions() == base  # 32bit 補助（Jet）
    monkeypatch.setattr(database, "_read_access_helper32", refuse)
    assert positions() == base  # 純 Python（access_parser）


def _synthetic_page(rows: list[tuple[bytes, int]]) -> tuple[bytearray, list[int]]:
    """データページを作る。rows は（行の本体, 位置につける印）。行はページの末尾から詰める。戻り値は（ページ, 各行の開始位置）。"""
    page = bytearray(4096)
    page[0:2] = b"\x01\x01"
    page[12:14] = len(rows).to_bytes(2, "little")
    end, starts = 4096, []
    for i, (body, flag) in enumerate(rows):
        start = end - len(body)
        page[start:end] = body
        page[14 + 2 * i : 16 + 2 * i] = (start | flag).to_bytes(2, "little")
        starts.append(start)
        end = start
    return page, starts


def test_scrub_keeps_rows_that_a_live_overflow_pointer_points_to():
    """行が更新で大きくなると、元の場所には指し示し（印 0x4000）だけが残り、本体は移った先に「削除済み」の印のまま生きている。
    その行まで消すと、更新した行が丸ごと消える（実物で確かめた事故）ので、生きている指し示しの行き先は残す。"""
    pointer = (3).to_bytes(1, "little") + (7).to_bytes(3, "little")  # 行 3・ページ 7 への指し示し
    page, _ = _synthetic_page([(pointer, 0x4000), (b"LIVE-MOVED-ROW" * 3, 0x8000), (b"DEAD-ROW" * 3, 0x8000)])
    assert access_scrub.live_overflow_targets(page) == [(7, 3)]
    target, _ = _synthetic_page([(b"x" * 8, 0), (b"y" * 8, 0), (b"z" * 8, 0), (b"MOVED-BODY" * 3, 0x8000)])
    assert access_scrub.scrub_data_page(target, keep=None) > 0 and b"MOVED-BODY" not in target  # 印だけでは消えてしまう
    target, _ = _synthetic_page([(b"x" * 8, 0), (b"y" * 8, 0), (b"z" * 8, 0), (b"MOVED-BODY" * 3, 0x8000)])
    access_scrub.scrub_data_page(target, keep={3})
    assert b"MOVED-BODY" in target  # 行き先は残る
    # 指し示し自体が削除済みなら、行き先は生きていると数えない
    dead, _ = _synthetic_page([(pointer, 0xC000)])
    assert access_scrub.live_overflow_targets(dead) == []


def test_orphan_long_values_are_all_zeroed_but_live_values_and_chains_are_kept(tmp_path):
    """指されていない長い値の本文の塗りつぶし（合成したページ）:
    - 指されていない本文は、選んだ値を含まなくても消す（消した行のほかの列のメモ・ページの境目で割れた値が残らないように）
    - ほかの長い値の中身に、見出しと同じ形の並びが偶然あっても、それを参照と数えない（実物の .accdb で、消すべき本文が残った）
    - 表の行から印 0x40 で指されている本文と、印 0 で指されている鎖（2つ目以降は表の行から直接は指されない）は残す
    """
    import struct

    def ptr(pg: int, row: int) -> bytes:
        return struct.pack("<I", (pg << 8) | row)

    def header(length: int, flag: int, pg: int, row: int) -> bytes:
        return length.to_bytes(3, "little") + bytes([flag]) + ptr(pg, row) + b"\x00" * 4

    def lval(rows):
        page, _ = _synthetic_page(rows)
        page[4:8] = b"LVAL"
        return page

    head = (0).to_bytes(1, "little") + (3).to_bytes(3, "little") + b"H" * 200  # 鎖の先頭（次はページ 3 の行 0）
    cont = b"\x00\x00\x00\x00" + b"tail of a live long memo " * 3  # 鎖の2つ目（次は無い）
    live = b"LIVE-SINGLE-MEMO " * 5
    bait = (
        header(len(b"x"), 0x40, 2, 1) + b"ORPHAN-WITH-BAIT " * 5
    )  # 偶然、本文 (2,1) を指す見出しの形を含む（それ自体も孤児）
    orphan = b"ORPHAN-MEMO-OF-A-DELETED-ROW " * 4  # 選んだ値を含まない、消した行のメモ
    table_page, _ = _synthetic_page(
        [(b"\x05\x00" + header(5000, 0, 2, 0) + header(len(live), 0x40, 2, 3) + b"r" * 20, 0)]
    )
    table_page[4:8] = (0x99).to_bytes(4, "little")  # 表の定義のページ番号（LVAL ではない）
    pages = [
        bytearray(4096),
        table_page,
        lval([(head, 0), (orphan, 0), (bait, 0), (live, 0)]),
        lval([(cont, 0)]),
    ]
    p = tmp_path / "x.accdb"
    p.write_bytes(b"".join(bytes(pg) for pg in pages))
    assert access_scrub.scrub_orphan_long_values(str(p)) == 2
    data = p.read_bytes()
    assert b"ORPHAN" not in data  # 指されていない本文は、選んだ値を含まなくても消える
    assert b"H" * 200 in data and b"tail of a live long memo" in data  # 生きている鎖は先頭も続きも残る
    assert live in data  # 印 0x40 で指されている本文は残る
    assert data[4096 : 2 * 4096] == bytes(table_page)  # 表のページは変えない


@pytest.mark.parametrize("child_selected", [False, True])
def test_cascade_delete_into_other_tables_is_refused(child_selected):
    """リレーションシップの連鎖削除で、選んでいない行まで消えるなら、書き換えを取りやめる。
    子の表も選んでいるとき（親が先に処理される）も止める: 親の削除で子の行の番号がずれ、選んでいない子の行を消して、
    選んだ子の行が残ったまま確定した（評価2周目の高）。"""
    tables = ["parent", "child"] if child_selected else ["parent"]

    class FakeSel:
        def sheets(self):
            return tables

        def spans(self):
            return {t: {(1, 1): [(0, 17, "email")]} for t in tables}

        def rows(self):
            return {t: {1} for t in tables}

        def cols(self):
            return {t: {1} for t in tables}

    class FakeSession:
        def __init__(self, cascade: bool):
            self.counts = {"parent": 3, "child": 9, "other": 4}
            self.cascade = cascade
            self.read_after_delete = False

        def tables(self):
            return list(self.counts)

        def count(self, table):
            return self.counts[table]

        def columns(self, table):
            return [ra.ColInfo("id", "int"), ra.ColInfo("mail", "text")]

        def read_rows(self, table, wanted):
            if self.counts["parent"] < 3:
                self.read_after_delete = True  # 書き換えのあとに読んでいる（番号がずれうる）
            return {1: [1, f"{table[0]}as1@example.com"]}

        def delete_rows(self, table, cols, rows):
            self.counts[table] -= 1
            if self.cascade and table == "parent":
                self.counts["child"] -= 3  # 親の1行に連なる子の3行も消える
            return 1

    with pytest.raises(RemedyError, match="「child」.*連鎖削除"):
        ra._apply(FakeSession(cascade=True), "delete_rows", FakeSel(), None)
    ok = FakeSession(cascade=False)
    stats, secrets = ra._apply(ok, "delete_rows", FakeSel(), None)
    assert stats["rows"] == len(tables) and "pas1@example.com" in secrets
    assert not ok.read_after_delete  # 選んだ表は、どれも書き換えの前に読む


def test_scrub_freed_long_value_page():
    page = bytearray(4096)
    page[0:8] = b"\x09\x01\xea\x0fLVAL"
    page[100:120] = b"SECRET-MEMO-BODY1234"
    assert (
        access_scrub.scrub_freed_long_value_page(page) > 0
        and b"SECRET" not in page
        and page[:8] == b"\x09\x01\xea\x0fLVAL"
    )
    other = bytearray(4096)
    other[0:8] = b"\x01\x01\xea\x0fLVAL"
    other[100:104] = b"LIVE"
    assert access_scrub.scrub_freed_long_value_page(other) == 0 and b"LIVE" in other  # 生きているページには触らない


def test_sql_literal_and_where_clause():
    cols = [ra.ColInfo("id", "int"), ra.ColInfo("a'b", "text"), ra.ColInfo("m", "memo"), ra.ColInfo("f", "float")]
    w = ra.where_clause(cols, [5, "x'y", "long memo", 1.5])
    assert w == "[id]=5 AND [a'b]='x''y'"  # メモ・実数は使わない。引用符は二重にする
    with pytest.raises(RemedyError):
        ra.where_clause([ra.ColInfo("m", "memo")], ["x"])  # 行を特定できる列が無ければ断る


# ---------------------------------------------------------------- 各方法（手段ごと）


def run_ok(svc, job, p, **params) -> dict:
    r = run(svc, job, p, confidences=ALL_RANKS, **params)
    assert r["state"] == "done", r
    return r


def check_clean(p: Path, tmp_path: Path, trash, original: bytes) -> None:
    assert _leak([str(p)], needles_of(people())) == []  # 消した値は、ファイルのバイト列に残らない
    assert [f.read_bytes() for f in trash.files()] == [original]  # 元はごみ箱へ
    assert not new_tmp_files(p.parent)
    assert not [f for f in p.parent.iterdir() if f.suffix in ra.LOCK_SUFFIXES]


@with_case
def test_delete_rows(case, trash, tmp_path):
    strategy, p, svc, store, job = case
    before = snapshot(p, tmp_path)
    objects_before = non_table_objects(p)
    original = p.read_bytes()
    assert _leak([str(p)], needles_of(people())), "陽性対照: 元のファイルには値がある"
    r = run_ok(svc, job, p, method="delete_rows")
    assert r["changed"]["rows"] == len(pii_ids()) == 96 and r["remaining"]["total"] == 0
    after = snapshot(p, tmp_path)
    keep = sorted((tuple(row) for row in before["people"] if row[0] not in pii_ids()), key=repr)
    assert after["people"] == keep and after["items"] == before["items"]
    check_clean(p, tmp_path, trash, original)
    total, values = scan_counts(p, tmp_path)
    assert total == 0 and not values
    if objects_before is not None:
        assert non_table_objects(p) == objects_before  # クエリなど、表以外のオブジェクトが残る
    assert r["changed"]["engine"] == ra.STRATEGY_LABELS[strategy]
    assert r["changed"]["compacted"] is (strategy != "jackcess")


def test_access_inside_zip_can_be_rewritten(tmp_path, trash):
    """圧縮ファイルの中の Access も、中身を書き換えられる（分析のときに実ファイルが無くても、形式を種類名から決める）。"""
    import zipfile

    from test_remediate_archive import find_item, make_archive_service, run_inner

    if not (available("ace") or available("jackcess")):
        pytest.skip(".accdb を書き換える手段が無い")
    db = tmp_path / "work" / "people.accdb"
    build_db(db)
    archive = tmp_path / "src" / "box.zip"
    archive.parent.mkdir()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(db, "data/people.accdb")
    svc, store, job = make_archive_service(tmp_path, archive)
    item = find_item(store, job, archive, "data/people.accdb")
    r, pv = run_inner(svc, job, archive, item, method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    out = tmp_path / "out.accdb"
    with zipfile.ZipFile(archive) as z:
        out.write_bytes(z.read("data/people.accdb"))
    assert _leak([str(out)], needles_of(people())) == []  # 中の Access から、消した値が無くなった


@with_case
def test_delete_columns(case, trash, tmp_path):
    strategy, p, svc, store, job = case
    before = snapshot(p, tmp_path)
    objects_before = non_table_objects(p)
    original = p.read_bytes()
    r = run_ok(svc, job, p, method="delete_columns")
    assert r["changed"]["cols"] == 4 and r["remaining"]["total"] == 0  # 氏名・電話・メール・メモ
    after = snapshot(p, tmp_path)
    check_clean(p, tmp_path, trash, original)
    assert after["items"] == before["items"] and len(after["people"]) == N
    if strategy == "jackcess":
        # 列そのものは消せないので、列は残って全行の値が空になる
        assert all(row[2:] == (None, None, None, None) for row in after["people"])
        assert sorted((row[0], row[1]) for row in after["people"]) == sorted((r0[0], r0[1]) for r0 in before["people"])
    else:
        assert sorted((row[0], row[1]) for row in after["people"]) == sorted((r0[0], r0[1]) for r0 in before["people"])
        assert all(len(row) == 2 for row in after["people"])
    total, values = scan_counts(p, tmp_path)
    assert total == 0
    if objects_before is not None:
        assert non_table_objects(p) == objects_before  # 索引（備考）・クエリ・リレーションシップが残る


@pytest.mark.parametrize("mode", ["same", "shape", "fixed"])
@with_case
def test_dummy(case, mode, trash, tmp_path):
    strategy, p, svc, store, job = case
    before = snapshot(p, tmp_path)
    objects_before = non_table_objects(p)
    original = p.read_bytes()
    r = run_ok(svc, job, p, method="dummy", dummy_mode=mode)
    assert r["changed"]["cells"] > 0 and r["remaining"]["selected"] == 0
    after = snapshot(p, tmp_path)
    check_clean(p, tmp_path, trash, original)
    assert len(after["people"]) == N and after["items"] == before["items"]
    if objects_before is not None:
        assert non_table_objects(p) == objects_before
    # 個人情報の無い行（5行に1行）は、メモも含めて元のまま
    keep = sorted((tuple(row) for row in before["people"] if row[0] not in pii_ids()), key=repr)
    assert sorted((row for row in after["people"] if row[0] not in pii_ids()), key=repr) == keep
    if mode == "same":
        # 同じ値は同じダミー: 氏名・電話・メールの値の種類の数が変わらない（突き合わせが壊れない）
        kinds = lambda snap, c: len({row[c] for row in snap["people"] if row[c]})  # noqa: E731
        assert [kinds(after, c) for c in (2, 3, 4)] == [kinds(before, c) for c in (2, 3, 4)]


@with_case
def test_delete_table(case, trash, tmp_path):
    strategy, p, svc, store, job = case
    before = snapshot(p, tmp_path)
    objects_before = non_table_objects(p)
    original = p.read_bytes()
    r = run_ok(svc, job, p, method="delete_table")
    assert r["changed"]["tables"] == 1 and r["remaining"]["total"] == 0
    after = snapshot(p, tmp_path)
    check_clean(p, tmp_path, trash, original)
    assert after["items"] == before["items"]
    if strategy == "jackcess":
        assert after["people"] == []  # 表の枠は残り、全行が消える
    else:
        assert "people" not in after
    if objects_before is not None and strategy != "jackcess":
        objects_before["indexes"].pop(
            "people"
        )  # 消えた表の索引は無くなる。そのほか（クエリ・リレーションシップ・ほかの表の索引）は残る
        objects_after = non_table_objects(p)
        objects_after["queries"] = sorted(objects_after["queries"])
        assert objects_after == objects_before


@with_case
def test_preview_names_engine_and_keeps_no_raw_values(case, tmp_path):
    strategy, p, svc, store, job = case
    analyze(svc, job, p)
    pv = svc.preview(job, str(p), {"method": "delete_rows", "confidences": ALL_RANKS})
    text = "\n".join(pv["warnings"] + pv["notes"])
    assert ra.STRATEGY_LABELS[strategy] in text
    assert "表以外のもの" in text and "残ります" in text and "ファイルの中に残っていないか" in text
    assert ("整理（最適化）" in text) is (strategy != "jackcess")
    assert ("直接消します" in text) is (strategy == "jackcess")
    assert "1 行目" not in text  # データベースの表に見出し行は無い
    assert not any(n in repr(pv) for n in needles_of(people()))
    assert pv["changes"]["rows"] == 96 and pv["can_run"]
    pv2 = svc.preview(job, str(p), {"method": "delete_table", "confidences": ALL_RANKS})
    assert ("枠" in "\n".join(pv2["warnings"])) is (strategy == "jackcess")


# ---------------------------------------------------------------- 値が残ったとき・手段が無いとき・その他の断り


def pick_available() -> str:
    for s in ("ace", "jet", "jackcess"):
        if available(s):
            return s
    pytest.skip("書き換えの手段が無い")


def test_remaining_values_block_commit(tmp_path, monkeypatch, trash):
    """書き換えのあとに選んだ値が残っていれば、確定しない（一時の新ファイルも残さない・元はそのまま）。"""
    strategy = pick_available()
    ext = ".mdb" if strategy == "jet" else ".accdb"
    p = tmp_path / "src" / f"people{ext}"
    build_db(p)
    monkeypatch.setattr(ra, "FORCED_STRATEGIES", [strategy])
    original = p.read_bytes()
    got = remediate.collect_task({"path": str(p), "options": ScanOptions(temp_dir=str(tmp_path))})
    sel = select_positions(got["positions"], types={"email"}, ranks={2, 3})
    dst = tmp_path / "src" / "~piichk-new-x.accdb"
    # 本物の最適化・塗りつぶしを止めると、Jackcess では消した値が残る。ACE・Jet では、ファイルに残る別の値を選んだ値に足して同じ状況にする
    real_apply = ra._apply

    def apply_with_leftover(session, method, selection, maker):
        stats, secrets = real_apply(session, method, selection, maker)
        return stats, secrets | {"商品7"}  # 消していない表（items）の値

    monkeypatch.setattr(ra, "_apply", apply_with_leftover)
    with pytest.raises(RemedyError, match="まだ残っていた"):
        ra.rewrite_access_file(str(p), str(dst), "delete_rows", sel, None)
    assert not dst.exists() and p.read_bytes() == original and not new_tmp_files(p.parent)
    assert not [f for f in p.parent.iterdir() if f.suffix in ra.LOCK_SUFFIXES]
    # サービスの流れでも、確定せずに失敗し、元のファイルはそのまま・ごみ箱は空
    svc, store, job = make_service(tmp_path, [p])
    r = run(svc, job, p, method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "error" and "まだ残っていた" in r["message"]
    assert p.read_bytes() == original and not trash.files() and not new_tmp_files(p.parent)


def test_jackcess_without_scrub_leaves_values_and_is_refused(tmp_path, monkeypatch):
    """塗りつぶしを止めた Jackcess は、消した行の跡に値が残る。それを確かめの門が止める（塗りつぶしが要る理由の確認）。"""
    if not available("jackcess"):
        pytest.skip("Jackcess が使えない環境")
    p = tmp_path / "src" / "people.accdb"
    build_db(p)
    monkeypatch.setattr(ra, "FORCED_STRATEGIES", ["jackcess"])
    got = remediate.collect_task({"path": str(p), "options": ScanOptions(temp_dir=str(tmp_path))})
    sel = select_positions(got["positions"], types={"email"}, ranks={2, 3})
    monkeypatch.setattr(ra, "_optimize", lambda *a, **k: False)
    dst = tmp_path / "src" / "~piichk-new-y.accdb"
    with pytest.raises(RemedyError, match="まだ残っていた"):
        ra.rewrite_access_file(str(p), str(dst), "delete_rows", sel, None)
    assert not dst.exists()


def test_no_strategy_only_file_deletion(tmp_path, monkeypatch):
    if not (available("ace") or available("jet") or available("jackcess")):
        pytest.skip("検体を作る手段が無い")
    p = tmp_path / "src" / "people.accdb"
    build_db(p)
    svc, store, job = make_service(tmp_path, [p])
    monkeypatch.setattr(ra, "FORCED_STRATEGIES", [])  # 使える手段が1つも無い状況
    a = analyze(svc, job, p)
    methods = a.info["methods"]
    assert methods["delete_file"]["available"]
    for m in ("delete_rows", "delete_columns", "dummy", "delete_table"):
        assert not methods[m]["available"] and "ファイルの削除はできます" in methods[m]["reason"], m
    with pytest.raises(RemedyError):
        ra.rewrite_access_file(
            str(p), str(tmp_path / "src" / "~piichk-new-z.accdb"), "delete_rows", select_positions({}), None
        )
    r = run(svc, job, p, method="delete_file")
    assert r["state"] == "done" and not p.exists()


def test_lock_file_refused(tmp_path):
    if not (available("ace") or available("jet") or available("jackcess")):
        pytest.skip("検体を作る手段が無い")
    p = tmp_path / "src" / "people.accdb"
    build_db(p)
    lock = p.with_suffix(".laccdb")
    lock.write_bytes(b"x" * 64)
    reason = ra.availability_reason(str(p), "delete_rows")
    assert "ロックファイル" in reason and "閉じてから" in reason
    with pytest.raises(RemedyError, match="ロックファイル"):
        ra.rewrite_access_file(
            str(p), str(tmp_path / "src" / "~piichk-new-w.accdb"), "delete_rows", select_positions({}), None
        )


@pytest.mark.parametrize("strategy", ["ace", "jet", "jackcess"])
def test_real_worker_process_runs_access_rewrite(strategy, tmp_path, trash, monkeypatch):
    """検査と同じ別プロセス（pebble・Job Object のメモリ上限）の中でも、ACE・Jet・Jackcess の子プロセスが動いて書き換えられる。"""
    if not available(strategy):
        pytest.skip(f"{strategy} が使えない環境")
    p = tmp_path / "src" / ("people.mdb" if strategy == "jet" else "people.accdb")
    build_db(p)
    original = p.read_bytes()
    monkeypatch.setenv(ra.STRATEGY_ENV, strategy)  # 別プロセスへ引き継がれる
    svc, store, job = make_service(tmp_path, [p], runner=remediate._run_in_process)
    r = run_ok(svc, job, p, method="delete_rows")
    assert r["changed"]["rows"] == len(pii_ids()) and r["remaining"]["total"] == 0
    assert r["changed"]["engine"] == ra.STRATEGY_LABELS[strategy]
    assert _leak([str(p)], needles_of(people())) == [] and [f.read_bytes() for f in trash.files()] == [original]


def test_password_protected_access_cannot_be_rewritten(tmp_path):
    """検査のときパスワードで開けた Access は、書き換えのために開き直せないので、選べない理由を出す（ファイルの削除はできる）。"""
    info = {"status": "scanned", "layout": "access", "kind": "Access 2007以降（ACE・accdb）", "password_opened": True}
    for m in ("delete_rows", "delete_columns", "dummy", "delete_table"):
        assert "データベースパスワード" in remediate.unsupported_reason(m, str(tmp_path / "a.accdb"), info)
    assert remediate.unsupported_reason("delete_file", str(tmp_path / "a.accdb"), info) == ""


def test_wrong_file_is_refused(tmp_path):
    p = tmp_path / "fake.accdb"
    p.write_bytes(b"not an access file" * 100)
    assert ra.access_format(str(p)) == ""
    with pytest.raises(RemedyError):
        ra.rewrite_access_file(str(p), str(tmp_path / "~piichk-new-v.accdb"), "delete_rows", select_positions({}), None)


def test_compaction_failure_falls_back_to_scrub_and_still_verifies(tmp_path, monkeypatch):
    """ACE・Jet で最適化できなかったとき、消した行の跡を塗りつぶして確かめる（確かめは同じ）。"""
    strategy = "ace" if available("ace") else ("jet" if available("jet") else None)
    if strategy is None:
        pytest.skip("ACE・Jet が使えない環境")
    p = tmp_path / "src" / ("people.mdb" if strategy == "jet" else "people.accdb")
    build_db(p)
    monkeypatch.setattr(ra, "FORCED_STRATEGIES", [strategy])

    def broken(*a, **k):
        raise ra.Unavailable("試験: 最適化が使えない")

    monkeypatch.setattr(ra, "compact_database", broken)
    got = remediate.collect_task({"path": str(p), "options": ScanOptions(temp_dir=str(tmp_path))})
    sel = select_positions(got["positions"], types={"email"}, ranks={2, 3})
    dst = tmp_path / "src" / ("~piichk-new-u" + p.suffix)
    stats = ra.rewrite_access_file(str(p), str(dst), "delete_rows", sel, None)
    # 最適化できなくても、塗りつぶして値の確かめを通る（通らなければ rewrite_access_file が失敗する）
    assert stats["compacted"] is False and any("直接消しました" in n for n in stats["notes"])
    assert dst.is_file()


# ---------------------------------------------------------------- 確定の手順・記録


@with_case
def test_records_and_job_db_have_no_raw_values(case, trash, tmp_path):
    import glob

    strategy, p, svc, store, job = case
    needles = needles_of(people())
    # 実際のジョブの検査（DB に伏せた値の明細が入る）も同じ DB に走らせておく
    from pii_checker.runner import JobRunner
    from pii_checker.models import ScanOptions as SO

    full = store.create_job([str(p.parent)], SO(temp_dir=str(tmp_path / "scantmp")))
    runner = JobRunner(store, full, workers=1)
    runner.start()
    runner.wait(300)
    r = run_ok(svc, job, p, method="dummy", dummy_mode="same")
    db_files = glob.glob(str(tmp_path / "jobs.sqlite3*"))
    assert db_files and _leak(db_files, needles) == []
    for table in ("jobs", "files", "items", "findings", "remediations"):
        for row in store.query(f"SELECT * FROM {table}"):
            for v in tuple(row):
                if isinstance(v, str):
                    assert not any(n in v for n in needles), (table, v[:80])
    rec = store.remediations(job)[0]
    assert rec["method"] == "dummy" and rec["backup_path"] is None and rec["state"] == "applied"
    assert r["disposal"] == "recycle_bin" and r["pre_name"]
    # 陽性対照: 生の値を入れた DB なら、この探し方で見つかる
    import sqlite3

    q = tmp_path / "control.sqlite3"
    con = sqlite3.connect(q)
    con.execute("CREATE TABLE t(a TEXT)")
    con.execute("INSERT INTO t VALUES (?)", (needles[0],))
    con.commit()
    con.close()
    assert _leak([str(q)], needles)

"""データベースへの対処（T2-b: SQLite・SQL のダンプ。Access はファイルの削除だけ。Oracle のダンプは tests/test_remediate_oracle.py）の試験。

守ること: T2-a と同じ（検査は何も書き込まない・書き換えは一時の名前の新ファイルから確定・失敗で元を壊さない・記録とジョブの DB に生の値を入れない）に加えて、
- SQLite: 各方法のあと検査し直して消え、関係ない行・表・索引・ビュー・トリガーが元のまま・integrity_check が ok・消した値がファイルのバイト列に残らない
- SQL のダンプ: 触らない行がバイト単位で同じ・文字コード・改行を保つ・巨大の経路（丸ごと読む上限を小さくした経路）でも同じ結果
検体はすべて pytest の tmp_path に作る。本物のごみ箱へは送らない（送る関数を差し替える）。
"""

from __future__ import annotations

import glob
import re
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from pii_checker import engine, remediate  # noqa: E402
from pii_checker.formats import dbdump, misc  # noqa: E402
from pii_checker.models import PasswordBook, ScanOptions  # noqa: E402
from pii_checker.remedy_write import DummyMaker, RemedyError, sha256_file, shape_of  # noqa: E402
from test_remediate import (  # noqa: E402
    ALL_RANKS,
    FakeTrash,
    SimulatedCrash,
    _leak,
    analyze,
    crash_after,
    make_service,
    new_tmp_files,
    person_rows,
    run,
    run_until_crash,
    scan_counts,
)

N = 100  # 明細の上限（20 件）を大きく超える行数


@pytest.fixture(autouse=True)
def trash(tmp_path, monkeypatch):
    """どの試験でも、ごみ箱へ送る関数を差し替える（本物のごみ箱へ送らない）。ごみ箱のある場所として扱う。"""
    t = FakeTrash(tmp_path / "_trash")
    monkeypatch.setattr(remediate, "send_to_recycle_bin", t)
    monkeypatch.setattr(remediate, "has_recycle_bin", lambda path: True)
    return t


def people(n: int = N) -> list[tuple[int, list[str]]]:
    """（id, [備考, 氏名, 電話, メール]）。5行に1行は個人情報なし。"""
    return [(i + 1, r) for i, r in enumerate(person_rows(n)[1:])]


def has_pii(row: list[str]) -> bool:
    return bool(row[3])


def needles_of(rows) -> list[str]:
    return [v for _i, r in rows for v in r[1:] if v]


# ---------------------------------------------------------------- SQLite の検体


def build_sqlite(path: Path, n: int = N, trigger_copies_mail: bool = False, wal: bool = False) -> None:
    con = sqlite3.connect(path)
    if wal:
        con.execute("PRAGMA journal_mode=WAL")
    con.execute('CREATE TABLE people (id INTEGER PRIMARY KEY, "備考" TEXT, "氏名" TEXT, "電話" TEXT, "メール" TEXT)')
    con.execute('CREATE INDEX idx_note ON people("備考")')
    con.executemany("INSERT INTO people VALUES (?,?,?,?,?)", [(i, *r) for i, r in people(n)])
    con.execute("CREATE TABLE items (sku TEXT, label TEXT)")
    con.executemany("INSERT INTO items VALUES (?,?)", [(f"A-{i:03d}", f"商品{i}") for i in range(30)])
    con.execute("CREATE VIEW v_items AS SELECT sku FROM items")
    con.execute("CREATE TABLE audit (msg TEXT)")
    copied = 'old."メール"' if trigger_copies_mail else "old.id"
    con.execute(f"CREATE TRIGGER trg_del AFTER DELETE ON people BEGIN INSERT INTO audit VALUES ({copied}); END")
    con.execute(f"CREATE TRIGGER trg_upd AFTER UPDATE ON people BEGIN INSERT INTO audit VALUES ({copied}); END")
    con.commit()
    con.close()


def build_sqlite_without_rowid(path: Path, n: int = N) -> None:
    """主キーが個人情報そのもの（メールアドレス）の WITHOUT ROWID の表。"""
    con = sqlite3.connect(path)
    con.execute('CREATE TABLE accounts (login TEXT PRIMARY KEY, "氏名" TEXT, memo TEXT) WITHOUT ROWID')
    rows = []
    for i in range(n):
        if i % 5 == 4:
            rows.append((f"guest{i:03d}", "", f"メモ{i}"))
        else:
            rows.append((f"user{i:03d}@example.com", f"山田太郎{i}", f"メモ{i}"))
    con.executemany("INSERT INTO accounts VALUES (?,?,?)", rows)
    con.execute("CREATE TABLE items (sku TEXT, label TEXT)")
    con.executemany("INSERT INTO items VALUES (?,?)", [(f"A-{i:03d}", f"商品{i}") for i in range(30)])
    con.commit()
    con.close()


def dump_db(path: Path) -> dict:
    """SQLite の中身（表・索引・ビュー・トリガーの定義と、各表の行）を、比べられる形にして返す。"""
    con = sqlite3.connect(f"file:{path.as_posix()}?mode=ro&immutable=1", uri=True)
    try:
        schema = {n: (t, s) for n, t, s in con.execute("SELECT name, type, sql FROM sqlite_master")}
        data = {}
        for (name,) in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
            data[name] = sorted(con.execute(f'SELECT * FROM "{name}"').fetchall(), key=repr)
        return {"schema": schema, "data": data}
    finally:
        con.close()


def integrity(path: Path) -> list:
    con = sqlite3.connect(f"file:{path.as_posix()}?mode=ro&immutable=1", uri=True)
    try:
        return con.execute("PRAGMA integrity_check").fetchall()
    finally:
        con.close()


@pytest.fixture
def sqlite_case(tmp_path):
    p = tmp_path / "src" / "people.sqlite"
    p.parent.mkdir()
    build_sqlite(p)
    svc, store, job = make_service(tmp_path, [p])
    return p, svc, store, job


def sqlite_needles() -> list[str]:
    return needles_of(people())


def test_sqlite_collect_positions_use_rowid_and_cover_all_rows(tmp_path):
    p = tmp_path / "src" / "people.sqlite"
    p.parent.mkdir()
    build_sqlite(p)
    got = remediate.collect_task({"path": str(p), "options": ScanOptions(temp_dir=str(tmp_path))})
    assert got["layout"] == "sqlite" and got["status"] == "scanned" and not got["overflow"]
    emails = got["positions"][("people", "email", 2)]
    pii_ids = [i for i, r in people() if has_pii(r)]
    assert sorted(emails[0::4]) == pii_ids and len(pii_ids) > 20  # 明細の上限を超えた分も、rowid で全部
    # 位置は数値だけ（生の値を持たない）。構造の情報にも値は無い
    assert all(isinstance(v, int) for arr in got["positions"].values() for v in arr)
    schema = got["db_schema"]["tables"]["people"]
    assert (
        schema["columns"] == ["id", "備考", "氏名", "電話", "メール"] and schema["pk"] == ["id"] and schema["has_rowid"]
    )
    assert schema["triggers"] == 2 and "備考" in schema["indexed"]
    assert "user1@example.com" not in repr(got["db_schema"])


def test_sqlite_delete_rows(sqlite_case, trash, tmp_path):
    p, svc, store, job = sqlite_case
    before = dump_db(p)
    original = p.read_bytes()
    assert _leak([str(p)], sqlite_needles())  # 陽性対照: 元のファイルには値がある
    r = run(svc, job, p, method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    after = dump_db(p)
    pii = [i for i, row in people() if has_pii(row)]
    assert r["changed"]["rows"] == len(pii) == 80 and r["remaining"]["total"] == 0
    # 該当行だけが消え、関係ない行・表・索引・ビュー・トリガーは元のまま
    assert after["data"]["people"] == [row for row in before["data"]["people"] if row[0] not in pii]
    assert after["data"]["items"] == before["data"]["items"]
    assert after["schema"] == before["schema"]
    assert after["data"]["audit"] == []  # 削除のトリガーは動かしていない（消した値を写さない）
    assert integrity(p) == [("ok",)]
    assert _leak([str(p)], sqlite_needles()) == []  # VACUUM のあと、消した値はファイルのバイト列に残らない
    assert [f.read_bytes() for f in trash.files()] == [original]  # 元はごみ箱へ
    total, values = scan_counts(p, tmp_path)
    assert total == 0 and not values
    assert not new_tmp_files(p.parent) and not list(p.parent.glob("*-journal")) and not list(p.parent.glob("*-wal"))


def test_sqlite_trigger_that_copies_values_does_not_keep_them(tmp_path):
    p = tmp_path / "src" / "people.sqlite"
    p.parent.mkdir()
    build_sqlite(p, trigger_copies_mail=True)
    svc, store, job = make_service(tmp_path, [p])
    r = run(svc, job, p, method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    assert dump_db(p)["data"]["audit"] == []
    assert _leak([str(p)], sqlite_needles()) == []
    assert "trg_del" in dump_db(p)["schema"] and "メール" in dump_db(p)["schema"]["trg_del"][1]


def test_sqlite_delete_columns(sqlite_case, tmp_path):
    p, svc, store, job = sqlite_case
    before = dump_db(p)
    r = run(svc, job, p, method="delete_columns", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    con = sqlite3.connect(p)
    try:
        assert [x[1] for x in con.execute("PRAGMA table_info(people)")] == ["id", "備考"]
        assert con.execute("SELECT count(*) FROM people").fetchone()[0] == N
        assert sorted(con.execute("SELECT id, 備考 FROM people").fetchall()) == sorted(
            (i, row[0]) for i, row in people()
        )
        assert con.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
    finally:
        con.close()
    after = dump_db(p)
    assert after["data"]["items"] == before["data"]["items"]
    assert after["schema"]["idx_note"] == before["schema"]["idx_note"] and "v_items" in after["schema"]
    assert "trg_del" in after["schema"] and "trg_upd" in after["schema"]  # トリガーは元の定義で作り直してある
    assert r["changed"]["cols"] == 3 and r["remaining"]["total"] == 0
    assert _leak([str(p)], sqlite_needles()) == []


@pytest.mark.parametrize("mode", ["same", "shape", "fixed"])
def test_sqlite_dummy(sqlite_case, mode, tmp_path):
    p, svc, store, job = sqlite_case
    before = dump_db(p)
    r = run(svc, job, p, method="dummy", dummy_mode=mode, confidences=ALL_RANKS)
    assert r["state"] == "done", r
    after = dump_db(p)
    assert len(after["data"]["people"]) == N
    assert after["data"]["items"] == before["data"]["items"] and after["schema"] == before["schema"]
    rows = {row[0]: row for row in after["data"]["people"]}
    for i, orig in people():
        _id, note, name, phone, mail = rows[i]
        assert note == orig[0]  # 関係ない列は元のまま
        if has_pii(orig):
            assert (name, phone, mail) != (orig[1], orig[2], orig[3])
            if mode == "fixed":
                assert (name, phone, mail) == ("＊＊＊",) * 3
            if mode == "shape":
                assert (name, phone, mail) == (shape_of(orig[1]), shape_of(orig[2]), shape_of(orig[3]))
        else:
            assert (name, phone, mail) == (orig[1], orig[2], orig[3])
    assert dump_db(p)["data"]["audit"] == []  # 更新のトリガーも動かしていない
    assert integrity(p) == [("ok",)]
    assert _leak([str(p)], sqlite_needles()) == []
    assert r["remaining"]["total"] == 0


def test_sqlite_dummy_same_gives_same_value_the_same_dummy(tmp_path):
    p = tmp_path / "src" / "d.sqlite"
    p.parent.mkdir()
    con = sqlite3.connect(p)
    con.execute('CREATE TABLE t (id INTEGER PRIMARY KEY, "氏名" TEXT)')
    con.executemany("INSERT INTO t VALUES (?,?)", [(1, "同名太郎"), (2, "同名太郎"), (3, "別人花子")])
    con.commit()
    con.close()
    svc, store, job = make_service(tmp_path, [p])
    r = run(svc, job, p, method="dummy", dummy_mode="same", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    rows = dict(sqlite3.connect(p).execute("SELECT id, 氏名 FROM t").fetchall())
    assert rows[1] == rows[2] != rows[3]


def test_sqlite_delete_table(sqlite_case, tmp_path):
    p, svc, store, job = sqlite_case
    before = dump_db(p)
    r = run(svc, job, p, method="delete_table", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    after = dump_db(p)
    assert "people" not in after["data"] and "idx_note" not in after["schema"] and "trg_del" not in after["schema"]
    assert after["data"]["items"] == before["data"]["items"] and after["data"]["audit"] == []
    assert after["schema"]["v_items"] == before["schema"]["v_items"]
    assert r["changed"]["tables"] == 1 and r["remaining"]["total"] == 0
    assert integrity(p) == [("ok",)]
    assert _leak([str(p)], sqlite_needles()) == []


def test_sqlite_without_rowid_table_uses_primary_key(tmp_path):
    p = tmp_path / "src" / "acc.sqlite"
    p.parent.mkdir()
    build_sqlite_without_rowid(p)
    got = remediate.collect_task({"path": str(p), "options": ScanOptions(temp_dir=str(tmp_path))})
    assert got["layout"] == "sqlite" and got["db_schema"]["tables"]["accounts"]["has_rowid"] is False
    before = dump_db(p)
    svc, store, job = make_service(tmp_path, [p])
    r = run(svc, job, p, method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    after = dump_db(p)
    assert after["data"]["accounts"] == [row for row in before["data"]["accounts"] if row[0].startswith("guest")]
    assert len(after["data"]["accounts"]) == 20 and after["data"]["items"] == before["data"]["items"]
    assert integrity(p) == [("ok",)] and r["remaining"]["total"] == 0
    assert _leak([str(p)], ["user000@example.com", "山田太郎0"]) == []


def test_sqlite_without_rowid_dummy_changes_the_primary_key_too(tmp_path):
    p = tmp_path / "src" / "acc.sqlite"
    p.parent.mkdir()
    build_sqlite_without_rowid(p)
    svc, store, job = make_service(tmp_path, [p])
    r = run(svc, job, p, method="dummy", dummy_mode="same", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    rows = sqlite3.connect(p).execute("SELECT login, 氏名, memo FROM accounts").fetchall()
    assert len(rows) == N and len({x[0] for x in rows}) == N  # 主キーはダミーでも重ならない
    assert sorted(x[2] for x in rows) == sorted(f"メモ{i}" for i in range(N))
    assert sum(1 for x in rows if x[0].startswith("guest")) == 20
    assert integrity(p) == [("ok",)]
    assert _leak([str(p)], ["user000@example.com", "山田太郎0", "user001@example.com"]) == []


def test_sqlite_refuses_dropping_primary_key_column_and_keeps_original(tmp_path, trash):
    p = tmp_path / "src" / "acc.sqlite"
    p.parent.mkdir()
    build_sqlite_without_rowid(p)
    original = p.read_bytes()
    svc, store, job = make_service(tmp_path, [p])
    r = run(svc, job, p, method="delete_columns", confidences=ALL_RANKS)
    assert r["state"] == "error" and "削除できません" in r["message"]
    assert p.read_bytes() == original and not trash.files() and not new_tmp_files(p.parent)
    assert store.remediations(job) == []


def test_sqlite_preview_warns_about_keys_triggers_and_vacuum(sqlite_case):
    p, svc, store, job = sqlite_case
    analyze(svc, job, p)
    pv = svc.preview(job, str(p), {"method": "delete_table", "confidences": ALL_RANKS})
    text = "\n".join(pv["warnings"])
    assert "VACUUM" in text and "すべて消えます" in text and "トリガー 2 個" in text and "索引 1 個" in text
    assert "v_items" not in text  # 無関係のビューは出さない
    pv = svc.preview(job, str(p), {"method": "delete_rows", "confidences": ALL_RANKS})
    assert pv["sample_rows"][0].startswith("people: rowid ")
    assert "トリガー" in "\n".join(pv["warnings"])


@pytest.mark.parametrize("suffix", ["-wal", "-shm", "-journal"])
def test_sqlite_with_sidecar_files_is_refused(tmp_path, suffix):
    p = tmp_path / "src" / "people.sqlite"
    p.parent.mkdir()
    build_sqlite(p)
    side = Path(str(p) + suffix)
    side.write_bytes(b"\x00" * 32)
    got = remediate.collect_task({"path": str(p), "options": ScanOptions(temp_dir=str(tmp_path))})
    reason = remediate.unsupported_reason("delete_rows", str(p), got)
    assert suffix in reason and "他のプログラム" in reason
    assert remediate.unsupported_reason("delete_file", str(p), got) == ""
    svc, store, job = make_service(tmp_path, [p])
    original = p.read_bytes()
    plan = svc._plan(job, str(p))
    a = remediate.Analysis(job, str(p))
    svc._analyze(a, plan)
    assert not a.info["methods"]["delete_rows"]["available"] and a.info["methods"]["delete_file"]["available"]
    with pytest.raises(RemedyError, match="付属ファイル"):
        from pii_checker.remedy_sqlite import rewrite_sqlite_file
        from pii_checker.remedy_write import select_positions

        rewrite_sqlite_file(
            str(p), str(tmp_path / "new.sqlite"), "delete_rows", select_positions(got["positions"]), None
        )
    assert p.read_bytes() == original and not (tmp_path / "new.sqlite").exists()


def test_sqlite_in_wal_mode_is_written_back_in_wal_mode(tmp_path):
    p = tmp_path / "src" / "w.sqlite"
    p.parent.mkdir()
    build_sqlite(p, wal=True)
    for suffix in ("-wal", "-shm"):  # 閉じたあとに付属ファイルは無いはず（残っていれば、この試験の前提が違う）
        assert not Path(str(p) + suffix).exists()
    assert p.read_bytes()[18:20] == b"\x02\x02"
    svc, store, job = make_service(tmp_path, [p])
    r = run(svc, job, p, method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    assert p.read_bytes()[18:20] == b"\x02\x02"  # WAL のまま
    assert not Path(str(p) + "-wal").exists() and integrity(p) == [("ok",)]
    assert _leak([str(p)], sqlite_needles()) == []


def test_sqlite_goes_through_temp_file_and_commit_rewrite(sqlite_case, monkeypatch, trash):
    p, svc, store, job = sqlite_case
    orig_sha = sha256_file(str(p))
    seen = {}
    real_rewrite, real_commit, real_fsync = remediate.rewrite_file, remediate.commit_rewrite, remediate.fsync_path

    def spy_rewrite(src, dst, *a, **k):
        seen["dst"] = dst
        out = real_rewrite(src, dst, *a, **k)
        assert sha256_file(src) == orig_sha  # 書いている間、元は変わらない
        assert Path(dst).exists() and Path(dst).name.startswith(remediate.NEW_PREFIX)
        return out

    def spy_commit(store_, rid, path, plan, orig):
        seen["plan"] = plan
        assert sha256_file(path) == orig_sha and Path(plan["tmp_new"]).exists()  # 確定の前も、元は変わらない
        return real_commit(store_, rid, path, plan, orig)

    def spy_fsync(path):
        seen["fsync"] = path
        return real_fsync(path)

    monkeypatch.setattr(remediate, "rewrite_file", spy_rewrite)
    monkeypatch.setattr(remediate, "commit_rewrite", spy_commit)
    monkeypatch.setattr(remediate, "fsync_path", spy_fsync)
    r = run(svc, job, p, method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    plan = seen["plan"]
    assert plan["mode"] == "recycle" and plan["tmp_new"] == seen["dst"] == seen["fsync"]
    assert r["disposal"] == "recycle_bin" and "（対処前 " in r["pre_name"]
    assert [f.name for f in trash.files()] == [f"1-{r['pre_name']}"]
    assert not new_tmp_files(p.parent)
    rec = store.remediations(job)[0]
    assert rec["state"] == "applied" and rec["backup_path"] is None


@pytest.mark.parametrize("kind,nth", [("rename", 1), ("rename", 2), ("state", 3)])
def test_sqlite_crash_during_commit_is_recovered(tmp_path, monkeypatch, trash, kind, nth):
    p = tmp_path / "src" / "people.sqlite"
    p.parent.mkdir()
    build_sqlite(p)
    original = p.read_bytes()
    svc, store, job = make_service(tmp_path, [p])
    if kind == "rename":
        crash_after(monkeypatch, remediate, "_fs_rename", nth)
    else:
        crash_after(monkeypatch, store, "update_remediation", nth)
    with pytest.raises(SimulatedCrash):
        run_until_crash(svc, job, p, {"method": "delete_rows", "confidences": ALL_RANKS})
    monkeypatch.undo()
    monkeypatch.setattr(remediate, "send_to_recycle_bin", trash)
    monkeypatch.setattr(remediate, "has_recycle_bin", lambda path: True)
    RemedyService = remediate.RemedyService
    RemedyService(store, runner_fn=remediate.inline_runner).recover()
    assert store.unfinished_remediations() == []
    final = p.read_bytes()
    pii = [i for i, row in people() if has_pii(row)]
    if final != original:  # 新しい中身が入っていた: 開けて、該当の行が無い
        rows = dump_db(p)["data"]["people"]
        assert len(rows) == N - len(pii) and integrity(p) == [("ok",)]
    everywhere = [final] + [f.read_bytes() for f in trash.files()]
    assert original in everywhere
    assert not new_tmp_files(p.parent) and not list(p.parent.glob("*対処前*"))


def test_access_and_pg_custom_only_allow_file_delete():
    """Access・pg_dump のカスタム形式は、ファイルの削除だけ（Oracle のダンプは T2-d で中身の対処に対応した。tests/test_remediate_oracle.py）。"""
    access = {"status": "scanned", "kind": "Access 2007以降（ACE・accdb）", "layout": ""}
    pgc = {"status": "scanned", "kind": "PostgreSQL ダンプ（custom 形式）", "layout": ""}
    for info, word in ((access, "Access"), (pgc, "カスタム形式")):
        for method in ("delete_rows", "delete_columns", "dummy", "delete_sheet"):
            reason = remediate.unsupported_reason(method, "x.bin", info)
            assert word in reason and "ファイルの削除" in reason, (info["kind"], method)
        assert remediate.unsupported_reason("delete_file", "x.bin", info) == ""


def test_access_file_gives_reason_through_analysis(tmp_path, monkeypatch):
    """実ファイルの分析で、Access は理由つきでファイルの削除だけが選べる（形式の名前から決まる）。"""
    p = tmp_path / "src" / "a.accdb"
    p.parent.mkdir()
    p.write_bytes(b"\x00\x01\x00\x00Standard ACE DB" + b"\x00" * 600)
    svc, store, job = make_service(tmp_path, [p])
    a = analyze(svc, job, p)
    assert a.info["methods"]["delete_file"]["available"]
    for m in ("delete_rows", "delete_columns", "dummy"):
        assert not a.info["methods"][m]["available"]
    assert "delete_table" not in a.info["methods"]


# ---------------------------------------------------------------- SQL のダンプの検体

SPECIAL_NAME_APOS = "田中'次郎"  # 引用符を含む氏名
SPECIAL_NAME_BACKSLASH = "山田\\太郎"  # バックスラッシュを含む氏名


def dump_rows() -> list[tuple[int, list[str]]]:
    rows = people()
    rows[2] = (3, [rows[2][1][0], SPECIAL_NAME_APOS, rows[2][1][2], rows[2][1][3]])
    rows[5] = (6, [rows[5][1][0], SPECIAL_NAME_BACKSLASH, rows[5][1][2], rows[5][1][3]])
    rows[7] = (8, [rows[7][1][0], "同名花子", rows[7][1][2], rows[7][1][3]])
    rows[8] = (9, [rows[8][1][0], "同名花子", rows[8][1][2], rows[8][1][3]])
    return rows


FIELDS = ["備考", "氏名", "電話", "メール"]


def _mysql_q(v: str) -> str:
    return "'" + v.replace("\\", "\\\\").replace("'", "\\'") + "'"


def mysql_dump(pairs, fields=FIELDS, people_mode="full", nl="\n") -> str:
    """mysqldump 形式（1文に多数の VALUES・複数行の INSERT・LOCK・KEYS の文）。"""
    keep = [FIELDS.index(f) for f in fields]
    lines = [
        "-- MySQL dump 10.13  Distrib 8.0.33, for Linux (x86_64)",
        "/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;",
        "DROP TABLE IF EXISTS `items`;",
        "CREATE TABLE `items` (",
        "  `sku` varchar(20) DEFAULT NULL,",
        "  `label` varchar(50) DEFAULT NULL",
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
        "LOCK TABLES `items` WRITE;",
        "INSERT INTO `items` VALUES ('A-001','商品1'),('A-002','商品2');",
        "UNLOCK TABLES;",
    ]
    if people_mode == "full":
        lines += ["DROP TABLE IF EXISTS `people`;", "CREATE TABLE `people` ("]
        lines.append("  `id` int NOT NULL,")
        for k in keep:
            lines.append(f"  `{FIELDS[k]}` varchar(100) DEFAULT NULL,")
        has_mail = "メール" in fields
        lines.append("  PRIMARY KEY (`id`)" + ("," if has_mail else ""))
        if has_mail:
            lines.append("  KEY `idx_mail` (`メール`)")
        lines.append(") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;")
        lines.append("LOCK TABLES `people` WRITE;")
        lines.append("/*!40000 ALTER TABLE `people` DISABLE KEYS */;")

        def tup(i, row):
            return "(" + ",".join([str(i)] + [_mysql_q(row[k]) for k in keep]) + ")"

        first = [tup(i, r) for i, r in pairs if i <= 50]
        second = [tup(i, r) for i, r in pairs if i > 50]
        if first:
            lines.append("INSERT INTO `people` VALUES " + ",".join(first) + ";")
        if second:
            cols = ",".join(["`id`"] + [f"`{FIELDS[k]}`" for k in keep])
            lines.append(f"INSERT INTO `people` ({cols}) VALUES")
            lines.append(",\n".join(second) + ";")
        lines.append("/*!40000 ALTER TABLE `people` ENABLE KEYS */;")
    if people_mode in ("full", "gone"):
        lines.append("UNLOCK TABLES;")
    lines.append("-- Dump completed")
    return "\n".join(lines).replace("\n", nl) + nl


def _pg_cell(v: str) -> str:
    if v == "":
        return "\\N"
    return v.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n")


def pg_dump(pairs, fields=FIELDS, people_mode="full", nl="\n") -> str:
    """pg_dump の平文形式（COPY・\\N・エスケープ・ALTER TABLE ONLY・CREATE INDEX）。"""
    keep = [FIELDS.index(f) for f in fields]
    lines = [
        "--",
        "-- PostgreSQL database dump",
        "--",
        "",
        "SET statement_timeout = 0;",
        "SET client_encoding = 'UTF8';",
        "",
        "CREATE TABLE public.items (",
        "    sku text,",
        "    label text",
        ");",
        "",
        "ALTER TABLE public.items OWNER TO postgres;",
        "",
        "COPY public.items (sku, label) FROM stdin;",
        "A-001\t商品1",
        "A-002\t商品2",
        "\\.",
        "",
    ]
    full = people_mode == "full"  # gone: people の文は消え、文のあとの空行だけが残る

    def stmt(*body: str) -> None:
        if full:
            lines.extend(body)
        lines.append("")

    cols = ["    id integer NOT NULL"] + [f'    "{FIELDS[k]}" text' for k in keep]
    stmt("CREATE TABLE public.people (", ",\n".join(cols), ");")
    stmt("ALTER TABLE public.people OWNER TO postgres;")
    header = ", ".join(["id"] + [f'"{FIELDS[k]}"' for k in keep])
    stmt(
        f"COPY public.people ({header}) FROM stdin;",
        *["\t".join([str(i)] + [_pg_cell(row[k]) for k in keep]) for i, row in pairs],
        "\\.",
    )
    stmt("ALTER TABLE ONLY public.people", "    ADD CONSTRAINT people_pkey PRIMARY KEY (id);")
    if "メール" in fields or not full:
        stmt('CREATE INDEX idx_people_mail ON public.people USING btree ("メール");')
    else:
        lines.append("")  # 列の削除では、索引の文が消えて空行だけが残る
    lines += ["-- PostgreSQL database dump complete"]
    return "\n".join(lines).replace("\n", nl) + nl


ENCODINGS = [
    pytest.param("utf-8", "\n", id="utf8-lf"),
    pytest.param("cp932", "\r\n", id="cp932-crlf"),
    pytest.param("utf-8-sig", "\r\n", id="utf8bom-crlf"),
    pytest.param("euc_jp", "\n", id="eucjp-lf"),
    pytest.param("utf-16", "\r\n", id="utf16bom-crlf"),
]
DUMPS = [pytest.param(mysql_dump, id="mysqldump"), pytest.param(pg_dump, id="pgdump")]


def encode(text: str, enc: str) -> bytes:
    if enc == "utf-8-sig":
        return b"\xef\xbb\xbf" + text.encode("utf-8")
    return text.encode(enc)


def make_dump(tmp_path: Path, build, enc: str, nl: str, huge: bool, monkeypatch, name: str = "dump.sql"):
    p = tmp_path / "src" / name
    p.parent.mkdir(exist_ok=True)
    p.write_bytes(encode(build(dump_rows(), nl=nl), enc))
    if huge:
        monkeypatch.setattr(misc, "TEXT_READ_ALL_LIMIT", 1024)  # 巨大の経路（少しずつ読む）で検査・書き換える
    svc, store, job = make_service(tmp_path, [p])
    return p, svc, store, job


HUGE = pytest.mark.parametrize("huge", [False, True], ids=["whole", "huge"])


def kept_rows():
    return [(i, r) for i, r in dump_rows() if not has_pii(r)]


@pytest.mark.parametrize("enc,nl", ENCODINGS)
@pytest.mark.parametrize("build", DUMPS)
@HUGE
def test_dump_delete_rows(tmp_path, monkeypatch, build, enc, nl, huge, trash):
    p, svc, store, job = make_dump(tmp_path, build, enc, nl, huge, monkeypatch)
    original = p.read_bytes()
    r = run(svc, job, p, method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    # 触らない行はバイト単位で同じ（文字コード・BOM・改行を含む）。期待は独立に組み立てた文字列
    assert p.read_bytes() == encode(build(kept_rows(), nl=nl), enc)
    assert r["changed"]["rows"] == N - len(kept_rows()) == 80 and r["remaining"]["total"] == 0
    assert [f.read_bytes() for f in trash.files()] == [original]
    total, values = scan_counts(p, tmp_path)
    assert total == 0 and not values


@pytest.mark.parametrize("enc,nl", ENCODINGS)
@pytest.mark.parametrize("build", DUMPS)
@HUGE
def test_dump_delete_columns(tmp_path, monkeypatch, build, enc, nl, huge):
    p, svc, store, job = make_dump(tmp_path, build, enc, nl, huge, monkeypatch)
    r = run(svc, job, p, method="delete_columns", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    # CREATE TABLE の列の定義・COPY の列・INSERT の列と値・その列の索引の文が消え、備考の列だけが残る
    assert p.read_bytes() == encode(build(dump_rows(), fields=["備考"], nl=nl), enc)
    assert r["changed"]["cols"] == 3 and r["remaining"]["total"] == 0


@pytest.mark.parametrize("enc,nl", ENCODINGS)
@pytest.mark.parametrize("build", DUMPS)
@HUGE
def test_dump_delete_table(tmp_path, monkeypatch, build, enc, nl, huge):
    p, svc, store, job = make_dump(tmp_path, build, enc, nl, huge, monkeypatch)
    r = run(svc, job, p, method="delete_table", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    assert p.read_bytes() == encode(build(dump_rows(), people_mode="gone", nl=nl), enc)
    assert r["changed"]["tables"] == 1 and r["remaining"]["total"] == 0
    text = p.read_bytes().decode(enc)
    assert "people" not in text and "items" in text


def parse_mysql_people(text: str) -> list[list]:
    """出力の people の INSERT から、行（[id, 備考, 氏名, 電話, メール]）を取り出す。"""
    rows = []
    for m in re.finditer(r"^INSERT INTO `people`[^\n]*?VALUES\s*", text, re.M):
        end = text.index(";\n", m.end()) if ";\n" in text[m.end() :] else len(text)
        stmt = text[m.start() : end + 1].replace("\r\n", "\n")
        mm = dbdump.RE_INSERT.search(stmt)
        values, _ = dbdump._parse_values(stmt, mm.end())
        rows.extend(values)
    return rows


def parse_pg_people(text: str) -> list[list]:
    lines = text.replace("\r\n", "\n").split("\n")
    start = next(i for i, ln in enumerate(lines) if ln.startswith("COPY public.people"))
    out = []
    for ln in lines[start + 1 :]:
        if ln == "\\.":
            break
        out.append([dbdump._unescape_copy(v) for v in ln.split("\t")])
    return out


@pytest.mark.parametrize("enc,nl", ENCODINGS)
@pytest.mark.parametrize(
    "build,parse", [(mysql_dump, parse_mysql_people), (pg_dump, parse_pg_people)], ids=["mysqldump", "pgdump"]
)
@pytest.mark.parametrize("mode", ["same", "shape", "fixed"])
@HUGE
def test_dump_dummy(tmp_path, monkeypatch, build, parse, enc, nl, mode, huge):
    p, svc, store, job = make_dump(tmp_path, build, enc, nl, huge, monkeypatch)
    original = p.read_bytes()
    r = run(svc, job, p, method="dummy", dummy_mode=mode, confidences=ALL_RANKS)
    assert r["state"] == "done", r
    data = p.read_bytes()
    text = data.decode(enc)
    rows = parse(text)
    assert len(rows) == N
    by_id = {int(x[0]): x for x in rows}
    for i, orig in dump_rows():
        got = by_id[i]
        assert got[1] == orig[0]  # 関係ない列は元のまま
        if has_pii(orig):
            if mode == "fixed":
                assert got[2:5] == ["＊＊＊"] * 3
            elif mode == "shape":
                assert got[2:5] == [shape_of(orig[1]), shape_of(orig[2]), shape_of(orig[3])]
            else:
                assert got[2:5] != orig[1:4] and all(g and "_" in g for g in got[2:5])
        else:
            assert [(g or "") for g in got[2:5]] == orig[1:4]
    if mode == "same":
        assert by_id[8][2] == by_id[9][2]  # 同じ値は同じダミー
        assert by_id[8][2] != by_id[3][2]
    assert _leak([str(p)], needles_of(dump_rows())) == []

    # 触らない行（people 以外の文・行）は、元のバイト列のまま
    def outside(t: str) -> list[str]:
        return [ln for ln in t.splitlines(keepends=True) if "people" not in ln and "\t" not in ln or "items" in ln]

    keep_lines = [ln for ln in outside(original.decode(enc)) if "A-00" in ln or "items" in ln or "SET " in ln]
    assert keep_lines and all(ln in outside(text) for ln in keep_lines)
    assert r["remaining"]["total"] == 0


def test_dump_dummy_keeps_quote_style_and_prefix(tmp_path):
    """引用符・エスケープの流儀・接頭辞（N・_utf8mb4）・前後の空白・数値だった値を、壊さずにダミーにする。"""
    text = (
        "CREATE TABLE `t` (\n  `id` int,\n  `氏名` varchar(50),\n  `電話` bigint\n);\n"
        "INSERT INTO `t` VALUES (1, N'山田太郎' ,09012345678),(2,_utf8mb4'田中\\'次郎',NULL),( 3 ,'佐藤''三郎','x');\n"
    )
    p = tmp_path / "src" / "t.sql"
    p.parent.mkdir()
    p.write_text(text, encoding="utf-8", newline="")
    svc, store, job = make_service(tmp_path, [p])
    r = run(svc, job, p, method="dummy", dummy_mode="shape", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    out = p.read_text(encoding="utf-8")
    stmt = out[out.index("INSERT") :]
    mm = dbdump.RE_INSERT.search(stmt)
    tuples, _ = dbdump.parse_values_spans(stmt, mm.end())
    assert len(tuples) == 3 and all(t[2] for t in tuples)
    rows = [[c[2] for c in t[3]] for t in tuples]
    assert rows[0] == ["1", "N〇〇〇〇", "00000000000"]
    assert rows[1] == ["2", "_utf8mb4〇〇'〇〇", None]
    assert rows[2][1] == "〇〇'〇〇" and rows[2][2] == "x"
    assert "N'" in out and "_utf8mb4'" in out and "NULL" in out  # 接頭辞・NULL は元のまま
    assert out[: out.index("INSERT")] == text[: text.index("INSERT")]  # CREATE 文は触らない


def test_dump_without_trailing_newline_and_blank_lines_are_kept(tmp_path):
    rows = people(10)
    text = mysql_dump(rows, nl="\n").rstrip("\n").replace("-- Dump completed", "\n\n-- Dump completed")
    p = tmp_path / "src" / "d.sql"
    p.parent.mkdir()
    p.write_bytes(text.encode("utf-8"))
    svc, store, job = make_service(tmp_path, [p])
    r = run(svc, job, p, method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    out = p.read_bytes()
    assert (
        not out.endswith(b"\n") and b"UNLOCK TABLES;\n\n\n-- Dump completed" in out
    )  # 末尾の改行の無さ・空行はそのまま
    assert b"INSERT INTO `people` VALUES" in out and out.count(b"INSERT INTO") == 2


def test_dump_insert_statement_is_dropped_when_every_row_goes(tmp_path):
    text = "INSERT INTO `people` (`氏名`,`メール`) VALUES ('山田太郎','a@example.com'),('佐藤花子','b@example.com');\nSELECT 1;\n"
    p = tmp_path / "src" / "d.sql"
    p.parent.mkdir()
    p.write_text(text, encoding="utf-8", newline="")
    svc, store, job = make_service(tmp_path, [p])
    r = run(svc, job, p, method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    assert p.read_text(encoding="utf-8") == "SELECT 1;\n"


def test_dump_unreadable_values_are_refused_and_original_kept(tmp_path, trash):
    """関数呼び出しの括弧のように読み解けない INSERT は、壊さずに断る。"""
    text = "INSERT INTO `p` (`氏名`,`メール`,`日時`) VALUES ('山田太郎','a@example.com',NOW()),('佐藤花子','b@example.com',NOW());\n"
    p = tmp_path / "src" / "d.sql"
    p.parent.mkdir()
    p.write_text(text, encoding="utf-8", newline="")
    original = p.read_bytes()
    svc, store, job = make_service(tmp_path, [p])
    r = run(svc, job, p, method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "error" and "読み解けない" in r["message"]
    assert p.read_bytes() == original and not trash.files() and not new_tmp_files(p.parent)


def test_dump_all_columns_cannot_be_dropped(tmp_path, trash):
    text = "INSERT INTO `p` (`氏名`,`メール`) VALUES ('山田太郎','a@example.com');\n"
    p = tmp_path / "src" / "d.sql"
    p.parent.mkdir()
    p.write_text(text, encoding="utf-8", newline="")
    svc, store, job = make_service(tmp_path, [p])
    r = run(svc, job, p, method="delete_columns", confidences=ALL_RANKS)
    assert r["state"] == "error" and "すべての列" in r["message"]
    assert p.read_text(encoding="utf-8") == text


def test_dump_preview_labels_and_notes(tmp_path):
    p = tmp_path / "src" / "d.sql"
    p.parent.mkdir()
    p.write_bytes(pg_dump(dump_rows()).encode("utf-8"))
    svc, store, job = make_service(tmp_path, [p])
    analyze(svc, job, p)
    pv = svc.preview(job, str(p), {"method": "delete_rows", "confidences": ALL_RANKS})
    assert pv["sample_rows"][0].startswith("public.people: ") and "行目" in pv["sample_rows"][0]
    assert "1行ずつ" in "\n".join(pv["warnings"])
    pv = svc.preview(job, str(p), {"method": "delete_table", "confidences": ALL_RANKS})
    assert "1 個の表を削除します: public.people" in pv["summary"] and "すべて消えます" in "\n".join(pv["warnings"])
    a = svc.get_analysis(job, str(p))
    assert (
        a.info["layout"] == "sqldump"
        and "delete_table" in a.info["methods"]
        and "delete_sheet" not in a.info["methods"]
    )


def test_dump_positions_cover_all_rows_and_rows_are_keyed_by_line(tmp_path):
    p = tmp_path / "src" / "d.sql"
    p.parent.mkdir()
    p.write_bytes(mysql_dump(dump_rows()).encode("utf-8"))
    got = remediate.collect_task({"path": str(p), "options": ScanOptions(temp_dir=str(tmp_path))})
    assert got["layout"] == "sqldump" and not got["overflow"]
    emails = got["positions"][("people", "email", 2)]
    keys = emails[0::4]
    assert len(keys) == 80 > 20
    lines = p.read_bytes().decode("utf-8").split("\n")
    first_insert = next(i for i, ln in enumerate(lines, start=1) if ln.startswith("INSERT INTO `people` VALUES"))
    assert {k >> dbdump.ROW_KEY_SHIFT for k in keys if (k >> dbdump.ROW_KEY_SHIFT) == first_insert}
    assert all(0 < (k & ((1 << dbdump.ROW_KEY_SHIFT) - 1)) for k in keys)  # INSERT の組には、文の中の番号が入る


def test_dump_pg_directory_and_custom_formats_are_file_only(tmp_path):
    """pg_dump のカスタム形式は、ファイルの削除だけ（平文の SQL ではないため）。"""
    p = tmp_path / "src" / "backup.dump"
    p.parent.mkdir()
    p.write_bytes(b"PGDMP\x01\x0e\x00" + b"\x00" * 600)
    svc, store, job = make_service(tmp_path, [p])
    a = analyze(svc, job, p)
    assert a.info["methods"]["delete_file"]["available"]
    assert not a.info["methods"]["delete_rows"]["available"]


# ---------------------------------------------------------------- 検査との読み方の突き合わせ


@pytest.mark.parametrize(
    "stmt",
    [
        "(1,'a','b'),(2,NULL,'c');",
        "( 1 , 'it''s' ,\n 'x\\'y' ),\n(2,N'山田',_utf8mb4'z');",
        "(1,2,3),(4,5",
        "(1,'a\\\\','\\n'),(2,'')",
        "(1,NOW()),(2,3);",
        "",
        "(1,'abc'  ,  null  )  ;  ",
    ],
)
def test_parse_values_spans_agrees_with_parse_values(stmt):
    rows, end = dbdump._parse_values(stmt, 0)
    tuples, end2 = dbdump.parse_values_spans(stmt, 0)
    assert end == end2 and rows == [[c[2] for c in t[3]] for t in tuples]
    for s, e, closed, cells in tuples:
        if closed:
            assert stmt[s:e] == "(" + ",".join(stmt[cs:ce] for cs, ce, _v, _q in cells) + ")"  # 元の文字列に戻せる


def test_dummy_helpers_escape_correctly():
    from pii_checker.remedy_sqldump import dummy_copy_cell, dummy_insert_cell

    maker = DummyMaker("shape")
    spans = [(0, 5, "name")]
    assert dummy_copy_cell("山田\\\\太郎", [(0, 5, "name")], maker) == "〇〇\\\\〇〇"  # 値は 山田\太郎
    assert dummy_copy_cell("\\N", spans, maker) == "\\N"
    assert (
        dummy_copy_cell("山田\\b太郎", [(0, 6, "name")], DummyMaker("fixed")) == "＊＊＊"
    )  # 検査が外さないエスケープは全体
    assert dummy_insert_cell("'山田太郎'", "山田太郎", [(0, 4, "name")], maker) == "'〇〇〇〇'"
    assert dummy_insert_cell("  '山田太郎'  ", "山田太郎", [(0, 4, "name")], maker) == "  '〇〇〇〇'  "
    assert dummy_insert_cell("'a''b'", "a'b", [(0, 3, "name")], DummyMaker("fixed")) == "'＊＊＊'"
    assert dummy_insert_cell("123", "123", [(0, 3, "phone")], maker) == "'000'"


# ---------------------------------------------------------------- 記録・ジョブの DB に生の値が入らない


def _db_files(tmp_path: Path) -> list[str]:
    return glob.glob(str(tmp_path / "jobs.sqlite3*"))


@pytest.mark.parametrize("kind", ["sqlite", "mysql", "pg"])
def test_records_and_job_db_have_no_raw_values(tmp_path, trash, kind):
    from pii_checker.runner import JobRunner

    p = tmp_path / "src" / ("people.sqlite" if kind == "sqlite" else "dump.sql")
    p.parent.mkdir()
    if kind == "sqlite":
        build_sqlite(p)
    else:
        p.write_bytes((mysql_dump if kind == "mysql" else pg_dump)(dump_rows()).encode("utf-8"))
    needles = needles_of(dump_rows() if kind != "sqlite" else people())
    svc, store, job = make_service(tmp_path, [p])
    full = store.create_job([str(p.parent)], ScanOptions(temp_dir=str(tmp_path / "scantmp")))
    runner = JobRunner(store, full, workers=1)
    runner.start()
    runner.wait(300)
    r = run(svc, job, p, method="dummy", dummy_mode="same", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    assert _leak(_db_files(tmp_path), needles) == []
    for table in ("jobs", "files", "items", "findings", "remediations"):
        for row in store.query(f"SELECT * FROM {table}"):
            for v in tuple(row):
                if isinstance(v, str):
                    assert not any(n in v for n in needles), (table, v[:80])
    rec = store.remediations(job)[0]
    assert rec["method"] == "dummy" and rec["backup_path"] is None
    # 陽性対照: 生の値を入れた DB なら、この探し方で見つかる
    q = tmp_path / "control.sqlite3"
    con = sqlite3.connect(q)
    con.execute("CREATE TABLE t(a TEXT)")
    con.execute("INSERT INTO t VALUES (?)", (f"x {needles[0]} y",))
    con.commit()
    con.close()
    assert _leak([str(q)], needles) == [needles[0]]
    # 書き換えた結果に元の値は無い。元の値があるのは、ごみ箱へ送った元のファイルだけ
    assert _leak([str(p)], needles) == []
    assert _leak([str(f) for f in trash.files()], needles)


def test_scan_alone_never_writes_db_files(tmp_path):
    """検査（位置の集め直しを含む）は、SQLite・SQL のダンプのどちらも書き換えない。"""
    a = tmp_path / "src" / "a.sqlite"
    b = tmp_path / "src" / "b.sql"
    a.parent.mkdir()
    build_sqlite(a)
    b.write_bytes(mysql_dump(dump_rows()).encode("utf-8"))
    before = {x: x.read_bytes() for x in (a, b)}
    for x in (a, b):
        engine.scan_file(str(x), ScanOptions(temp_dir=str(tmp_path)), PasswordBook())
        remediate.collect_task({"path": str(x), "options": ScanOptions(temp_dir=str(tmp_path))})
    assert {x: x.read_bytes() for x in (a, b)} == before
    assert sorted(f.name for f in a.parent.iterdir()) == ["a.sqlite", "b.sql"]


def test_normal_scan_result_is_unchanged_by_collecting_positions(tmp_path):
    a = tmp_path / "src" / "a.sqlite"
    b = tmp_path / "src" / "b.sql"
    a.parent.mkdir()
    build_sqlite(a)
    b.write_bytes(pg_dump(dump_rows()).encode("utf-8"))
    for x in (a, b):
        plain = engine.scan_file(str(x), ScanOptions(temp_dir=str(tmp_path)), PasswordBook())
        withpos = engine.scan_file(str(x), ScanOptions(temp_dir=str(tmp_path), collect_positions=True), PasswordBook())
        assert [it.conf_counts for it in plain.items] == [it.conf_counts for it in withpos.items]
        assert not any(it.positions for it in plain.items)


# ---------------------------------------------------------------- 書庫の中・確定の手順


def test_sqlite_and_dump_inside_zip(tmp_path, trash):
    """書庫の中の SQLite・SQL のダンプにも、同じ書き換えが効く（書庫は作り直され、ほかの項目は元のまま）。"""
    import zipfile

    from test_remediate_archive import DEFLATED, build_zip, item_of, make_archive_service, run_inner

    s = tmp_path / "_s.sqlite"
    build_sqlite(s)
    sqlite_bytes = s.read_bytes()
    s.unlink()
    dump = pg_dump(dump_rows()).encode("utf-8")
    other = "ほかの項目です\n".encode("utf-8")
    archive = tmp_path / "src" / "pack.zip"
    archive.parent.mkdir()
    build_zip(
        archive,
        [
            ("a/people.sqlite", sqlite_bytes, DEFLATED, (2022, 1, 2, 3, 4, 6)),
            ("b/dump.sql", dump, DEFLATED, (2022, 5, 6, 7, 8, 10)),
            ("c/other.txt", other, DEFLATED, (2022, 9, 10, 11, 12, 14)),
        ],
    )
    svc, store, job = make_archive_service(tmp_path, archive)
    r, _ = run_inner(svc, job, archive, item_of(archive, "b/dump.sql"), method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    with zipfile.ZipFile(archive) as z:
        assert z.read("b/dump.sql") == pg_dump(kept_rows()).encode("utf-8")
        assert z.read("c/other.txt") == other and z.read("a/people.sqlite") == sqlite_bytes
    assert 0 < r["remaining"]["total"] < 400  # 書庫の中の SQLite の分が残っている
    svc.forget_job(job)
    svc2, store2, job2 = make_archive_service(tmp_path / "second", archive)
    r2, _ = run_inner(
        svc2, job2, archive, item_of(archive, "a/people.sqlite"), method="delete_table", confidences=ALL_RANKS
    )
    assert r2["state"] == "done", r2
    assert r2["remaining"]["total"] == 0  # ダンプも SQLite も直したので、書庫全体で残りが無い
    out = tmp_path / "out.sqlite"
    with zipfile.ZipFile(archive) as z:
        out.write_bytes(z.read("a/people.sqlite"))
        assert z.read("b/dump.sql") == pg_dump(kept_rows()).encode("utf-8")
    assert "people" not in dump_db(out)["data"] and integrity(out) == [("ok",)]


@pytest.mark.parametrize("build", DUMPS)
def test_dump_goes_through_temp_file_and_commit_rewrite(tmp_path, monkeypatch, trash, build):
    p, svc, store, job = make_dump(tmp_path, build, "utf-8", "\n", False, monkeypatch)
    orig_sha = sha256_file(str(p))
    seen = {}
    real_rewrite, real_commit = remediate.rewrite_file, remediate.commit_rewrite

    def spy_rewrite(src, dst, layout, *a, **k):
        seen["dst"], seen["layout"] = dst, layout
        out = real_rewrite(src, dst, layout, *a, **k)
        assert sha256_file(src) == orig_sha and Path(dst).name.startswith(remediate.NEW_PREFIX)
        return out

    def spy_commit(store_, rid, path, plan, orig):
        seen["plan"] = plan
        assert sha256_file(path) == orig_sha and Path(plan["tmp_new"]).exists()
        return real_commit(store_, rid, path, plan, orig)

    monkeypatch.setattr(remediate, "rewrite_file", spy_rewrite)
    monkeypatch.setattr(remediate, "commit_rewrite", spy_commit)
    r = run(svc, job, p, method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    assert seen["layout"] == "sqldump" and seen["plan"]["tmp_new"] == seen["dst"] and seen["plan"]["mode"] == "recycle"
    assert [f.name for f in trash.files()] == [f"1-{r['pre_name']}"] and not new_tmp_files(p.parent)
    assert store.remediations(job)[0]["state"] == "applied"


def test_dump_without_recycle_bin_replaces_in_one_step(tmp_path, monkeypatch, trash):
    p, svc, store, job = make_dump(tmp_path, pg_dump, "utf-8", "\n", False, monkeypatch)
    monkeypatch.setattr(remediate, "has_recycle_bin", lambda path: False)
    r = run(svc, job, p, method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "done" and r["disposal"] == "replaced", r
    assert p.read_bytes() == pg_dump(kept_rows()).encode("utf-8") and not trash.files()


def test_dump_unsupported_encoding_is_refused_before_touching(tmp_path, monkeypatch, trash):
    """検査が読めた文字コード以外（ISO-2022-JP など）は、元に戻せるか分からないので書き換えない。"""
    text = pg_dump(dump_rows(), nl="\n")
    p = tmp_path / "src" / "d.sql"
    p.parent.mkdir()
    p.write_bytes(text.encode("iso2022_jp", errors="replace"))
    svc, store, job = make_service(tmp_path, [p])
    original = p.read_bytes()
    r = run(svc, job, p, method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "error"
    assert p.read_bytes() == original and not trash.files() and not new_tmp_files(p.parent)

"""書庫の中のファイルへの対処（T2-a2）の試験。

守ること: T2-a と同じ（検査は何も書き込まない・元は退避・書き換えは一時の名前から置き換え・失敗で元を壊さない・元に戻せる・
記録とジョブの DB に生の値を入れない）に加えて、書庫を作り直しても、ほかの項目が元のまま（zip は圧縮済みのデータ・日時・圧縮方式・
属性・コメント・並び順まで同じ）であること。
検体はすべて pytest の tmp_path に作る。本物のごみ箱へは送らない（送る関数を差し替える）。7-Zip が要る試験は見つからなければ skip。
"""

from __future__ import annotations

import gzip
import io
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import types
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from pii_checker import archive_write as aw  # noqa: E402
from pii_checker import engine, remediate  # noqa: E402
from pii_checker.formats.archive import find_7z  # noqa: E402
from pii_checker.models import PasswordBook, ScanOptions  # noqa: E402
from pii_checker.remediate import Analysis, RemedyService, inline_runner  # noqa: E402
from pii_checker.remedy_write import RemedyError  # noqa: E402
from pii_checker.store import Store  # noqa: E402
from test_remediate import (  # noqa: E402
    ALL_RANKS,
    FakeTrash,
    SimulatedCrash,
    _leak,
    build_xlsx,
    encode_csv,
    person_rows,
    raw_needles,
    read_sheet,
)

SEVENZIP = find_7z(None)
needs_7z = pytest.mark.skipif(SEVENZIP is None, reason="7-Zip（7z.exe）が見つからない")
STORED, DEFLATED, BZIP2, LZMA = zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA


# ---------------------------------------------------------------- 検体の作り方


def csv_bytes(rows=None) -> bytes:
    return encode_csv(rows or person_rows(), "utf-8", "\r\n")


def txt_bytes(n: int = 12) -> bytes:
    lines = ["社員名簿（試験）"]
    for i in range(n):
        lines.append(f"メモ{i} 連絡先 090-{2000 + i:04d}-{6000 + i:04d} user{i}@example.org")
    lines.append("以上")
    return ("\n".join(lines) + "\n").encode("utf-8")


def xlsx_bytes(tmp_path: Path) -> bytes:
    p = tmp_path / "_x.xlsx"
    build_xlsx(p, 12)
    data = p.read_bytes()
    p.unlink()
    return data


PLAIN = [
    ("readme.txt", "これは説明です。\n".encode("utf-8"), STORED, (2020, 1, 2, 3, 4, 6)),
    ("data.bin", bytes(range(256)) * 40, DEFLATED, (2021, 5, 6, 7, 8, 10)),
]


def build_zip(path: Path, members, comment: bytes = b"", extra_for: dict | None = None) -> None:
    """members: [(名前, 中身, 圧縮方式, 日時)]。ディレクトリの項目は名前を / で終える。"""
    with zipfile.ZipFile(path, "w") as z:
        for name, data, ctype, dt in members:
            zi = zipfile.ZipInfo(name, date_time=dt)
            zi.compress_type = ctype
            zi.external_attr = (0o755 << 16 | 0x10) if name.endswith("/") else (0o644 << 16)
            zi.comment = f"c:{name}".encode("ascii", "replace")[:30]
            if extra_for and name in extra_for:
                zi.extra = extra_for[name]
            z.writestr(zi, data)
        z.comment = comment


def raw_payload(path: Path, info: zipfile.ZipInfo) -> bytes:
    with open(path, "rb") as f:
        f.seek(info.header_offset)
        h = f.read(30)
        fn, el = struct.unpack("<HH", h[26:30])
        f.seek(info.header_offset + 30 + fn + el)
        return f.read(info.compress_size)


def snapshot(path: Path) -> list[dict]:
    """zip の項目ごとの、圧縮済みのバイト列・メタデータの控え。"""
    out = []
    with zipfile.ZipFile(path) as z:
        for i in z.infolist():
            out.append(
                {
                    "name": i.filename,
                    "orig": i.orig_filename,
                    "method": i.compress_type,
                    "crc": i.CRC,
                    "csize": i.compress_size,
                    "size": i.file_size,
                    "date": i.date_time,
                    "ext": i.external_attr,
                    "int": i.internal_attr,
                    "comment": i.comment,
                    "flags": i.flag_bits,
                    "system": i.create_system,
                    "extra": i.extra,
                    "raw": raw_payload(path, i),
                }
            )
    return out


def others(snap: list[dict], name: str) -> list[dict]:
    return [s for s in snap if s["name"] != name]


@pytest.fixture(autouse=True)
def trash(tmp_path, monkeypatch):
    """どの試験でも、ごみ箱へ送る関数を差し替える（本物のごみ箱へ送らない）。ごみ箱のある場所として扱う。"""
    t = FakeTrash(tmp_path / "_trash")
    monkeypatch.setattr(remediate, "send_to_recycle_bin", t)
    monkeypatch.setattr(remediate, "has_recycle_bin", lambda path: True)
    return t


def restore_from_trash(trash: FakeTrash, path: Path) -> None:
    """利用者がごみ箱から戻したのと同じ: 最後にごみ箱へ入った「元の名前（対処前 …）」を、元の名前へ戻す。"""
    cands = [f for f in trash.files() if "（対処前 " in f.name]
    latest = max(cands, key=lambda x: int(x.name.split("-", 1)[0]))
    os.replace(latest, path)


class FakeRegistry:
    """検査を動かしているメモリのパスワード（本物のレジストリの代わり）。"""

    def __init__(self, book: PasswordBook):
        self.book = book

    def get(self, job_id, create=False):
        return types.SimpleNamespace(passwords=self.book)


def make_archive_service(tmp_path: Path, archive: Path, passwords=(), runner=inline_runner):
    scan_tmp = tmp_path / "scantmp"
    scan_tmp.mkdir(exist_ok=True, parents=True)
    store = Store(str(tmp_path / "jobs.sqlite3"))
    options = ScanOptions(temp_dir=str(scan_tmp), sevenzip=SEVENZIP)
    job = store.create_job([str(archive.parent)], options)
    st = archive.stat()
    store.add_files(job, [(str(archive), st.st_size, st.st_mtime)])
    book = PasswordBook(common=list(passwords))
    store.save_result(job, engine.scan_file(str(archive), options, book))
    svc = RemedyService(store, runner_fn=runner, registry=FakeRegistry(book))
    return svc, store, job


def analyze_inner(svc: RemedyService, job: str, archive: Path, item: str) -> Analysis:
    plan = svc._plan(job, str(archive), item)
    a = Analysis(job, str(archive), item)
    a.size = plan["size"]
    svc._analyze(a, plan)
    assert a.state == "done", a.error
    svc._analyses[(job, item)] = a
    return a


def run_inner(svc: RemedyService, job: str, archive: Path, item: str, **params):
    """分析 → 下見 → 実行を終わりまで走らせ、（実行の結果, 下見）を返す。"""
    analyze_inner(svc, job, archive, item)
    params["item_path"] = item
    pv = svc.preview(job, str(archive), params)
    started = svc.start_run(job, str(archive), params, True, pv.get("expected_sha256"))
    svc._runs[started["run_id"]].thread.join(300)
    return svc.run_status(job, started["run_id"]), pv


def item_of(archive: Path, name: str) -> str:
    return f"{archive}!{name}"


def find_item(store: Store, job: str, archive: Path, name: str) -> str:
    """検査の結果（DB）にある、その項目の検査のパス（7-Zip 経由の項目は区切りがバックスラッシュになる）。"""
    want = f"{archive}!{name}".replace("\\", "/")
    for r in store.query("SELECT path FROM items WHERE job_id=? AND top_path=?", (job, str(archive))):
        if r["path"].replace("\\", "/") == want:
            return r["path"]
    raise AssertionError(f"検査の結果に無い項目: {name}")


def inner_values(archive: Path, tmp_path: Path, item: str, passwords=()) -> list[tuple[str, str]]:
    """書庫を読み直して、その項目の検出（種類, 生の値）を返す。"""
    options = ScanOptions(temp_dir=str(tmp_path / "scantmp2"), reveal=True, sevenzip=SEVENZIP)
    (tmp_path / "scantmp2").mkdir(exist_ok=True)
    res = engine.scan_file(str(archive), options, PasswordBook(common=list(passwords)))
    return [(f.pii_type, f.raw_value) for it in res.items if it.path == item for f in it.findings]


def total_detections(archive: Path, tmp_path: Path, passwords=(), skip_item: str = "") -> int:
    options = ScanOptions(temp_dir=str(tmp_path / "scantmp2"), sevenzip=SEVENZIP)
    (tmp_path / "scantmp2").mkdir(exist_ok=True)
    res = engine.scan_file(str(archive), options, PasswordBook(common=list(passwords)))
    return sum(sum(it.conf_counts.values()) for it in res.items if it.path != skip_item)


def zip_member(path: Path, name: str, pwd: bytes | None = None) -> bytes:
    with zipfile.ZipFile(path) as z:
        return z.read(name, pwd=pwd)


def sevenzip_run(args: list[str], cwd: Path | None = None) -> bytes:
    r = subprocess.run([SEVENZIP] + args, cwd=cwd, capture_output=True, stdin=subprocess.DEVNULL)
    assert r.returncode == 0, (r.stdout + r.stderr).decode("utf-8", "replace")
    return r.stdout


def sevenzip_cat(archive: Path, name: str, pw: str = "") -> bytes:
    return sevenzip_run(["x", "-so", "-y", "-spd", f"-p{pw or 'x'}", str(archive), name])


def leftover_workdirs(tmp_path: Path) -> list[str]:
    """作業用の一時フォルダの残り（取り出したファイルが残っていないこと）。"""
    return [p.name for p in (tmp_path / "scantmp").glob(f"{engine.TEMP_PREFIX}*") if p.is_dir()]


@pytest.fixture
def zip_case(tmp_path):
    """target の csv と、個人情報のない項目・日時の違う項目・ディレクトリを持つ zip。"""
    root = tmp_path / "src"
    root.mkdir()
    archive = root / "pack.zip"
    members = [
        PLAIN[0],
        ("data/", b"", STORED, (2019, 3, 4, 5, 6, 8)),
        ("data/people.csv", csv_bytes(), DEFLATED, (2022, 7, 8, 9, 10, 12)),
        PLAIN[1],
        ("last.txt", "最後の項目\n".encode("utf-8"), BZIP2, (2023, 9, 10, 11, 12, 14)),
    ]
    ut = struct.pack("<HHBL", 0x5455, 5, 1, 1_700_000_000)  # 拡張タイムスタンプの追加フィールド（そのまま残ること）
    build_zip(archive, members, comment=b"archive comment", extra_for={"readme.txt": ut})
    svc, store, job = make_archive_service(tmp_path, archive)
    return {
        "tmp": tmp_path,
        "archive": archive,
        "svc": svc,
        "store": store,
        "job": job,
        "item": item_of(archive, "data/people.csv"),
    }


# ---------------------------------------------------------------- zip: 中のファイルへの対処


def assert_zip_others_untouched(before: list[dict], after: list[dict], name: str, keep_target: bool = True) -> None:
    if keep_target:
        assert [s["name"] for s in after] == [s["name"] for s in before]  # 並び順
    else:
        assert [s["name"] for s in after] == [s["name"] for s in before if s["name"] != name]
    assert others(after, name) == others(
        before, name
    )  # 圧縮方式・CRC・圧縮後の大きさ・日時・属性・コメント・バイト列まで同じ


def test_zip_csv_delete_rows(zip_case, trash):
    c = zip_case
    archive, rows = c["archive"], person_rows()
    before = snapshot(archive)
    original = archive.read_bytes()
    r, pv = run_inner(c["svc"], c["job"], archive, c["item"], method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    after = snapshot(archive)
    assert_zip_others_untouched(before, after, "data/people.csv")
    kept = [rows[0]] + [x for x in rows[1:] if not x[3]]
    assert zip_member(archive, "data/people.csv") == encode_csv(kept, "utf-8", "\r\n")
    t_before = next(s for s in before if s["name"] == "data/people.csv")
    t_after = next(s for s in after if s["name"] == "data/people.csv")
    assert t_after["method"] == t_before["method"] == DEFLATED and t_after["date"] == t_before["date"]
    assert (
        t_after["crc"] != t_before["crc"]
        and t_after["comment"] == t_before["comment"]
        and t_after["ext"] == t_before["ext"]
    )
    with zipfile.ZipFile(archive) as z:
        assert z.comment == b"archive comment" and z.testzip() is None
    assert r["remaining"]["total"] == 0 and r["changed"]["rows"] == len(rows) - len(kept)
    assert inner_values(archive, c["tmp"], c["item"]) == []
    assert [f.read_bytes() for f in trash.files()] == [original]  # 元の書庫は書庫ごと、ごみ箱へ（退避はしない）
    assert not list(archive.parent.glob(remediate.NEW_PREFIX + "*")) and leftover_workdirs(c["tmp"]) == []
    # 下見の文面: 書庫全体を作り直す・ほかの項目は中身を変えずに写す・1項目ずつ
    text = "\n".join(pv["warnings"])
    assert "全体を作り直します" in text and "そのまま写します" in text and "1項目ずつ" in text
    assert pv["item_name"] == "data/people.csv" and pv["file_name"] == "pack.zip"


def test_zip_csv_delete_columns_and_dummy(zip_case, trash):
    c = zip_case
    archive, rows = c["archive"], person_rows()
    before = snapshot(archive)
    r, _ = run_inner(c["svc"], c["job"], archive, c["item"], method="delete_columns", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    assert zip_member(archive, "data/people.csv") == encode_csv([[x[0]] for x in rows], "utf-8", "\r\n")
    assert_zip_others_untouched(before, snapshot(archive), "data/people.csv")
    # ごみ箱から戻して、ダミー化も
    restore_from_trash(trash, archive)
    assert snapshot(archive) == before
    r2, _ = run_inner(c["svc"], c["job"], archive, c["item"], method="dummy", dummy_mode="shape", confidences=ALL_RANKS)
    assert r2["state"] == "done", r2
    body = zip_member(archive, "data/people.csv").decode("utf-8")
    assert not any(n in body for n in raw_needles(rows))
    assert "000-0000-0000" in body and r2["remaining"]["total"] == 0
    assert_zip_others_untouched(before, snapshot(archive), "data/people.csv")


def test_zip_txt_and_xlsx(tmp_path, trash):
    root = tmp_path / "src"
    root.mkdir()
    archive = root / "docs.zip"
    xl = xlsx_bytes(tmp_path)
    build_zip(
        archive,
        [
            PLAIN[0],
            ("note/memo.txt", txt_bytes(), DEFLATED, (2022, 1, 2, 3, 4, 6)),
            ("sheet/c.xlsx", xl, STORED, (2024, 2, 4, 6, 8, 10)),
            PLAIN[1],
        ],
    )
    svc, store, job = make_archive_service(tmp_path, archive)
    before = snapshot(archive)
    # txt: 該当する行を削除
    r, _ = run_inner(svc, job, archive, item_of(archive, "note/memo.txt"), method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    lines = zip_member(archive, "note/memo.txt").decode("utf-8").splitlines()
    assert lines == ["社員名簿（試験）", "以上"] or all("090-" not in x for x in lines)
    assert_zip_others_untouched(before, snapshot(archive), "note/memo.txt")
    # xlsx: ダミー化（図形・書式などほかの部品は触らない）
    mid = snapshot(archive)
    r, _ = run_inner(
        svc, job, archive, item_of(archive, "sheet/c.xlsx"), method="dummy", dummy_mode="fixed", confidences=ALL_RANKS
    )
    assert r["state"] == "done", r
    assert_zip_others_untouched(mid, snapshot(archive), "sheet/c.xlsx")
    out = tmp_path / "out.xlsx"
    out.write_bytes(zip_member(archive, "sheet/c.xlsx"))
    new = read_sheet(out, "顧客")
    assert new[1][1] == "＊＊＊" and r["remaining"]["selected"] == 0
    # xlsx: 行の削除・列の削除・シートの削除（ダミー化を戻してから）
    restore_from_trash(trash, archive)
    for method in ("delete_rows", "delete_columns"):
        r, _ = run_inner(svc, job, archive, item_of(archive, "sheet/c.xlsx"), method=method, confidences=ALL_RANKS)
        assert r["state"] == "done", r
        assert_zip_others_untouched(mid, snapshot(archive), "sheet/c.xlsx")
        out.write_bytes(zip_member(archive, "sheet/c.xlsx"))
        assert r["remaining"]["total"] == 0
        restore_from_trash(trash, archive)
    r, _ = run_inner(svc, job, archive, item_of(archive, "sheet/c.xlsx"), method="delete_sheet", confidences=ALL_RANKS)
    assert r["state"] == "done" and r["changed"]["sheets"] == 1, r
    out.write_bytes(zip_member(archive, "sheet/c.xlsx"))
    import openpyxl

    wb = openpyxl.load_workbook(out)
    assert "顧客" not in wb.sheetnames
    wb.close()


def test_zip_remove_entry(zip_case, trash):
    c = zip_case
    archive = c["archive"]
    before = snapshot(archive)
    r, pv = run_inner(c["svc"], c["job"], archive, c["item"], method="remove_entry")
    assert r["state"] == "done", r
    after = snapshot(archive)
    assert_zip_others_untouched(before, after, "data/people.csv", keep_target=False)
    assert "data/people.csv" not in [s["name"] for s in after]
    assert r["changed"]["entries"] == 1 and "取り除きます" in pv["summary"]
    assert r["remaining"]["total"] == 0
    restore_from_trash(trash, archive)
    assert snapshot(archive) == before


def test_zip_nested_two_levels(tmp_path, trash):
    root = tmp_path / "src"
    root.mkdir()
    inner = root / "inner.zip"
    build_zip(
        inner,
        [
            ("people.csv", csv_bytes(), DEFLATED, (2022, 7, 8, 9, 10, 12)),
            ("keep.txt", b"keep me\n", STORED, (2018, 1, 2, 3, 4, 6)),
        ],
    )
    outer = root / "outer.zip"
    build_zip(outer, [PLAIN[0], ("deep/inner.zip", inner.read_bytes(), DEFLATED, (2023, 3, 3, 3, 3, 4)), PLAIN[1]])
    inner.unlink()
    svc, store, job = make_archive_service(tmp_path, outer)
    item = f"{outer}!deep/inner.zip!people.csv"
    before = snapshot(outer)
    inner_before = None
    with zipfile.ZipFile(outer) as z:
        inner_path = tmp_path / "_inner_before.zip"
        inner_path.write_bytes(z.read("deep/inner.zip"))
        inner_before = snapshot(inner_path)
    r, pv = run_inner(svc, job, outer, item, method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    assert_zip_others_untouched(before, snapshot(outer), "deep/inner.zip")
    new_inner = tmp_path / "_inner_after.zip"
    new_inner.write_bytes(zip_member(outer, "deep/inner.zip"))
    inner_after = snapshot(new_inner)
    assert_zip_others_untouched(inner_before, inner_after, "people.csv")
    kept = [person_rows()[0]] + [x for x in person_rows()[1:] if not x[3]]
    assert zip_member(new_inner, "people.csv") == encode_csv(kept, "utf-8", "\r\n")
    assert r["remaining"]["total"] == 0
    assert "入れ子" in "\n".join(pv["warnings"])
    restore_from_trash(trash, outer)
    assert snapshot(outer) == before


def test_zip_inner_item_resolution_with_exclamation_in_name(tmp_path):
    root = tmp_path / "src"
    root.mkdir()
    archive = root / "ex.zip"
    build_zip(archive, [("a!b/people.csv", csv_bytes(), DEFLATED, (2022, 1, 1, 1, 1, 2)), PLAIN[0]])
    svc, store, job = make_archive_service(tmp_path, archive)
    r, _ = run_inner(svc, job, archive, f"{archive}!a!b/people.csv", method="remove_entry")
    assert r["state"] == "done", r
    assert [s["name"] for s in snapshot(archive)] == ["readme.txt"]


# ---------------------------------------------------------------- zip の細部（記述子・ZIP64・名前の符号化）


class Unseekable:
    """書き込みだけできる出力（zip がデータ記述子を使う書き方になる）。"""

    def __init__(self, f):
        self.f = f

    def write(self, b):
        return self.f.write(b)

    def flush(self):
        self.f.flush()


def test_zip_with_data_descriptors_is_copied_as_is(tmp_path):
    root = tmp_path / "src"
    root.mkdir()
    archive = root / "stream.zip"
    with open(archive, "wb") as f, zipfile.ZipFile(Unseekable(f), "w") as z:
        for name, data, ctype, dt in [PLAIN[0], ("p.csv", csv_bytes(), DEFLATED, (2022, 1, 2, 3, 4, 6)), PLAIN[1]]:
            zi = zipfile.ZipInfo(name, date_time=dt)
            zi.compress_type = ctype
            with z.open(zi, "w") as w:
                w.write(data)
    with zipfile.ZipFile(archive) as z:
        assert all(i.flag_bits & 0x8 for i in z.infolist()), "検体がデータ記述子を使っていること"
    svc, store, job = make_archive_service(tmp_path, archive)
    before = snapshot(archive)
    r, _ = run_inner(svc, job, archive, item_of(archive, "p.csv"), method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    after = snapshot(archive)
    assert_zip_others_untouched(before, after, "p.csv")
    with zipfile.ZipFile(archive) as z:
        assert z.testzip() is None


def test_zip_utf8_names_and_force_zip64_local_headers(tmp_path):
    root = tmp_path / "src"
    root.mkdir()
    archive = root / "z64.zip"
    with zipfile.ZipFile(archive, "w") as z:
        for name, data in (("日本語/メモ.txt", "メモです\n".encode("utf-8")), ("big.dat", b"a" * 5000)):
            zi = zipfile.ZipInfo(name, date_time=(2022, 2, 2, 2, 2, 2))
            zi.compress_type = DEFLATED
            with z.open(zi, "w", force_zip64=True) as w:  # 局所ヘッダーに ZIP64 の追加フィールドを持つ
                w.write(data)
        zi = zipfile.ZipInfo("日本語/名簿.csv", date_time=(2022, 3, 3, 3, 3, 4))
        zi.compress_type = DEFLATED
        z.writestr(zi, csv_bytes())
    before = snapshot(archive)
    assert before[0]["flags"] & 0x800, "UTF-8 の名前の印"
    svc, store, job = make_archive_service(tmp_path, archive)
    r, _ = run_inner(
        svc, job, archive, item_of(archive, "日本語/名簿.csv"), method="delete_rows", confidences=ALL_RANKS
    )
    assert r["state"] == "done", r
    after = snapshot(archive)
    assert_zip_others_untouched(before, after, "日本語/名簿.csv")
    assert next(s for s in after if s["name"] == "日本語/名簿.csv")["flags"] & 0x800


def test_zip_with_zip64_end_record_keeps_it(tmp_path, monkeypatch):
    root = tmp_path / "src"
    root.mkdir()
    archive = root / "many.zip"
    with monkeypatch.context() as mp:
        mp.setattr(zipfile, "ZIP_FILECOUNT_LIMIT", 2)  # 項目が 3 つ以上なら ZIP64 の終端レコードを書く
        build_zip(
            archive,
            [
                PLAIN[0],
                ("p.csv", csv_bytes(), DEFLATED, (2022, 1, 2, 3, 4, 6)),
                PLAIN[1],
                ("z.txt", b"z", STORED, (2020, 1, 1, 0, 0, 0)),
            ],
        )
    assert aw._had_zip64_end(str(archive))
    svc, store, job = make_archive_service(tmp_path, archive)
    before = snapshot(archive)
    r, _ = run_inner(svc, job, archive, item_of(archive, "p.csv"), method="delete_columns", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    assert aw._had_zip64_end(str(archive))  # 元が持っていたので、作り直しても持つ
    assert_zip_others_untouched(before, snapshot(archive), "p.csv")


def test_central_record_writes_zip64_extra_for_huge_values():
    """4GB を超える大きさ・位置は、ZIP64 の追加フィールドで書かれ、zipfile が同じ値に読み戻す（実データは作らない）。"""
    info = zipfile.ZipInfo("huge.bin", date_time=(2022, 2, 2, 2, 2, 2))
    info.compress_type = DEFLATED
    info.CRC = 0x12345678
    info.file_size = 6 * 1024**3
    info.compress_size = 5 * 1024**3
    info.extract_version = 20
    info.extra = struct.pack("<HHBL", 0x5455, 5, 1, 1_700_000_000)
    rec = aw._central_record(info, b"huge.bin", 0, 7 * 1024**3)
    buf = io.BytesIO()
    buf.write(rec)
    aw._write_end(buf, 1, 0, len(rec), b"", False)
    buf.seek(0)
    with zipfile.ZipFile(buf) as z:
        got = z.infolist()[0]
    assert (got.file_size, got.compress_size, got.header_offset) == (6 * 1024**3, 5 * 1024**3, 7 * 1024**3)
    assert got.CRC == 0x12345678 and got.date_time == (2022, 2, 2, 2, 2, 2)
    assert 0x5455 in aw._zip_extra_ids(got.extra)  # ZIP64 以外の追加フィールドは残る


@needs_7z
def test_zip_with_cp932_names_keeps_raw_name_bytes(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    (work / "氏名.csv").write_bytes(csv_bytes())
    (work / "説明.txt").write_bytes("説明\n".encode("utf-8"))
    archive = tmp_path / "src" / "jp.zip"
    archive.parent.mkdir()
    sevenzip_run(["a", "-tzip", "-mcp=932", "-mcu=off", str(archive), "氏名.csv", "説明.txt"], cwd=work)
    before = snapshot(archive)
    assert not any(s["flags"] & 0x800 for s in before), "検体は cp932 の名前（UTF-8 の印なし）であること"
    svc, store, job = make_archive_service(tmp_path, archive)
    item = [i["path"] for i in store.query("SELECT path FROM items WHERE job_id=? AND depth=1", (job,))]
    csv_item = next(p for p in item if p.endswith("csv"))
    assert csv_item.endswith("!氏名.csv")  # 検査のパスは cp932 として読み直した名前
    r, _ = run_inner(svc, job, archive, csv_item, method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    after = snapshot(archive)
    assert [s["orig"] for s in after] == [s["orig"] for s in before]  # 名前のバイト列（cp437 として読んだ形）まで同じ
    assert not any(s["flags"] & 0x800 for s in after)
    tgt = next(x["name"] for x in before if x["size"] == len(csv_bytes()))
    assert_zip_others_untouched(before, after, tgt)


# ---------------------------------------------------------------- パスワードつき zip（ZipCrypto・AES）と 7z


def make_encrypted_zip(tmp_path: Path, archive: Path, mem: str, pw: str = "pw-1") -> None:
    work = tmp_path / f"work_{mem}"
    (work / "data").mkdir(parents=True)
    (work / "readme.txt").write_bytes("説明です\n".encode("utf-8"))
    (work / "data" / "people.csv").write_bytes(csv_bytes())
    (work / "other.txt").write_bytes("ほかの項目\n".encode("utf-8"))
    archive.parent.mkdir(exist_ok=True)
    sevenzip_run(
        ["a", "-tzip", f"-p{pw}", f"-mem={mem}", str(archive), "readme.txt", "data/people.csv", "other.txt"], cwd=work
    )


@needs_7z
@pytest.mark.parametrize("mem", ["ZipCrypto", "AES256"])
def test_encrypted_zip_is_rebuilt_with_same_password_and_method(tmp_path, mem, trash):
    pw = "aesSecret-1" if mem == "AES256" else "zipSecret-1"
    archive = tmp_path / "src" / "enc.zip"
    make_encrypted_zip(tmp_path, archive, mem, pw)
    before = snapshot(archive)
    target = "data/people.csv"
    tb = next(s for s in before if s["name"] == target)
    assert tb["flags"] & 1 and (tb["method"] == 99) == (mem == "AES256")
    svc, store, job = make_archive_service(tmp_path, archive, passwords=[pw])
    item = find_item(store, job, archive, target)
    # パスワードが手元に無ければ、理由つきで断る
    svc_nopw = RemedyService(store, runner_fn=inline_runner, registry=FakeRegistry(PasswordBook()))
    plan = svc_nopw._plan(job, str(archive), item)
    a0 = Analysis(job, str(archive), item)
    svc_nopw._analyze(a0, plan)
    assert a0.state == "error" and "パスワード" in a0.error
    r, pv = run_inner(svc, job, archive, item, method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    after = snapshot(archive)
    assert_zip_others_untouched(before, after, target)  # ほかの項目は暗号化されたままのバイト列まで同じ
    ta = next(s for s in after if s["name"] == target)
    assert ta["flags"] & 1 and ta["method"] == tb["method"]  # 同じ暗号方式（AES は 99・ZipCrypto は元の圧縮方式）
    rows = person_rows()
    kept = [rows[0]] + [x for x in rows[1:] if not x[3]]
    if mem == "ZipCrypto":
        assert zip_member(archive, target, pwd=pw.encode("utf-8")) == encode_csv(kept, "utf-8", "\r\n")
    assert sevenzip_cat(archive, target, pw) == encode_csv(kept, "utf-8", "\r\n")  # 同じパスワードで開ける
    assert sevenzip_cat(archive, "readme.txt", pw) == "説明です\n".encode("utf-8")
    assert "パスワードつき" in "\n".join(pv["warnings"])
    assert r["remaining"]["total"] == 0
    restore_from_trash(trash, archive)
    assert snapshot(archive) == before


@needs_7z
def test_encrypted_zip_remove_entry(tmp_path):
    archive = tmp_path / "src" / "enc.zip"
    make_encrypted_zip(tmp_path, archive, "AES256", "pw-remove")
    before = snapshot(archive)
    svc, store, job = make_archive_service(tmp_path, archive, passwords=["pw-remove"])
    r, _ = run_inner(svc, job, archive, find_item(store, job, archive, "data/people.csv"), method="remove_entry")
    assert r["state"] == "done", r
    assert_zip_others_untouched(before, snapshot(archive), "data/people.csv", keep_target=False)


def list_7z(archive: Path, pw: str = "") -> dict[str, tuple[str, str]]:
    out = sevenzip_run(["l", "-slt", "-sccUTF-8", f"-p{pw or 'x'}", str(archive)]).decode("utf-8", "replace")
    entries, cur = {}, {}
    for line in out.split("----------", 1)[1].splitlines() + [""]:
        if not line.strip():
            if "Path" in cur and "Folder" in cur and cur["Folder"] != "+":
                entries[cur["Path"].replace("\\", "/")] = (cur.get("CRC", ""), cur.get("Size", ""))
            cur = {}
        elif " = " in line:
            k, v = line.split(" = ", 1)
            cur[k] = v
    return entries


def make_7z(tmp_path: Path, archive: Path, *flags: str) -> None:
    work = tmp_path / "work7z"
    (work / "data").mkdir(parents=True, exist_ok=True)
    (work / "readme.txt").write_bytes("説明です\n".encode("utf-8"))
    (work / "data" / "people.csv").write_bytes(csv_bytes())
    (work / "other.txt").write_bytes("ほかの項目\n".encode("utf-8") * 50)
    archive.parent.mkdir(exist_ok=True)
    sevenzip_run(["a", "-t7z", *flags, str(archive), "readme.txt", "data/people.csv", "other.txt"], cwd=work)


@needs_7z
@pytest.mark.parametrize(
    "flags,pw",
    [
        pytest.param((), "", id="solid"),
        pytest.param(("-ms=off",), "", id="non-solid"),
        pytest.param(("-ppw7z-secret", "-mhe=on"), "pw7z-secret", id="encrypted-header"),
    ],
)
def test_7z_rebuilt_with_7zip_keeping_other_items(tmp_path, flags, pw, trash):
    archive = tmp_path / "src" / "pack.7z"
    make_7z(tmp_path, archive, *flags)
    before = list_7z(archive, pw)
    svc, store, job = make_archive_service(tmp_path, archive, passwords=[pw] if pw else [])
    item = find_item(store, job, archive, "data/people.csv")
    r, pv = run_inner(svc, job, archive, item, method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    after = list_7z(archive, pw)
    sevenzip_run(["t", "-y", f"-p{pw or 'x'}", str(archive)])  # 壊れていない
    assert set(after) == set(before)
    for name in before:
        if name != "data/people.csv":
            assert after[name] == before[name], name  # ほかの項目の CRC・大きさは同じ
    rows = person_rows()
    kept = [rows[0]] + [x for x in rows[1:] if not x[3]]
    assert sevenzip_cat(archive, "data/people.csv", pw) == encode_csv(kept, "utf-8", "\r\n")
    assert r["remaining"]["total"] == 0
    if pw:  # 見出しの暗号化も保つ（パスワードが違えば一覧も取れない）
        bad = subprocess.run(
            [SEVENZIP, "l", "-slt", "-pwrong", str(archive)], capture_output=True, stdin=subprocess.DEVNULL
        )
        assert bad.returncode != 0
    assert "7-Zip" in "\n".join(pv["warnings"])
    restore_from_trash(trash, archive)
    assert list_7z(archive, pw) == before


@needs_7z
def test_7z_remove_entry_and_dummy(tmp_path, trash):
    archive = tmp_path / "src" / "pack.7z"
    make_7z(tmp_path, archive, "-ms=off")
    before = list_7z(archive)
    svc, store, job = make_archive_service(tmp_path, archive)
    item = find_item(store, job, archive, "data/people.csv")
    r, _ = run_inner(svc, job, archive, item, method="dummy", dummy_mode="fixed", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    body = sevenzip_cat(archive, "data/people.csv").decode("utf-8")
    assert not any(n in body for n in raw_needles(person_rows())) and "＊＊＊" in body
    restore_from_trash(trash, archive)
    r2, _ = run_inner(svc, job, archive, item, method="remove_entry")
    assert r2["state"] == "done", r2
    after = list_7z(archive)
    assert "data/people.csv" not in after and {k: v for k, v in before.items() if k != "data/people.csv"} == after


# ---------------------------------------------------------------- tar 系・gz（1ファイル）


def build_tar(path: Path) -> None:
    members = [
        ("readme.txt", "説明\n".encode("utf-8")),
        ("dir/people.csv", csv_bytes()),
        ("other.bin", bytes(range(200)) * 30),
    ]
    with tarfile.open(path, "w") as tf:
        for i, (name, data) in enumerate(members):
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            ti.mtime = 1_600_000_000 + i * 1000
            ti.mode = 0o640
            ti.uid, ti.gid, ti.uname, ti.gname = 1001, 1002, "alice", "staff"
            tf.addfile(ti, io.BytesIO(data))
        d = tarfile.TarInfo("emptydir")
        d.type = tarfile.DIRTYPE
        d.mtime = 1_600_005_000
        d.mode = 0o755
        tf.addfile(d)


def tar_view(data: bytes) -> list[tuple]:
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        out = []
        for m in tf.getmembers():
            body = tf.extractfile(m).read() if m.isfile() else b""
            out.append((m.name, m.type, m.mtime, m.mode, m.uid, m.gid, m.uname, m.gname, m.size, body))
        return out


def gz_header(data: bytes) -> tuple[int, bytes]:
    assert data[3] & 8
    return struct.unpack("<I", data[4:8])[0], data[10 : data.index(b"\0", 10)]


@pytest.mark.parametrize("ext", ["tar", "tar.gz", "tgz", "tar.bz2", "tar.xz"])
def test_tar_family_rebuild_keeps_other_members(tmp_path, ext, trash):
    import bz2
    import lzma

    root = tmp_path / "src"
    root.mkdir()
    plain = root / "_pack.tar"
    build_tar(plain)
    tar_data = plain.read_bytes()
    plain.unlink()
    archive = root / f"pack.{ext}"
    if ext == "tar":
        archive.write_bytes(tar_data)
        item = f"{archive}!dir/people.csv"
    else:
        if ext in ("tar.gz", "tgz"):
            with (
                open(archive, "wb") as f,
                gzip.GzipFile(filename="pack.tar", mode="wb", fileobj=f, mtime=1_650_000_000) as gz,
            ):
                gz.write(tar_data)
        elif ext == "tar.bz2":
            archive.write_bytes(bz2.compress(tar_data, 9))
        else:
            archive.write_bytes(lzma.compress(tar_data))
        item = f"{archive}!pack.tar!dir/people.csv"
    before_view = tar_view(tar_data)
    svc, store, job = make_archive_service(tmp_path, archive)
    r, pv = run_inner(svc, job, archive, item, method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    raw = archive.read_bytes()
    if ext in ("tar.gz", "tgz"):
        assert raw[:2] == b"\x1f\x8b" and gz_header(raw) == (1_650_000_000, b"pack.tar")  # 見出しの日時・元の名前を保つ
        new_tar = gzip.decompress(raw)
    elif ext == "tar.bz2":
        assert raw[:3] == b"BZh" and raw[3:4] == b"9"
        new_tar = bz2.decompress(raw)
    elif ext == "tar.xz":
        assert raw[:6] == b"\xfd7zXZ\x00"
        new_tar = lzma.decompress(raw)
    else:
        new_tar = raw
    after_view = tar_view(new_tar)
    by_name = {v[0]: v for v in after_view}
    for v in before_view:
        if v[0] != "dir/people.csv":
            assert by_name[v[0]] == v, v[0]  # 名前・種別・日時・権限・所有者・中身が同じ
    assert [v[0] for v in after_view] == [v[0] for v in before_view]  # 並び順
    new_csv = by_name["dir/people.csv"]
    rows = person_rows()
    kept = [rows[0]] + [x for x in rows[1:] if not x[3]]
    assert new_csv[9] == encode_csv(kept, "utf-8", "\r\n")
    assert new_csv[2] == 1_600_001_000 and new_csv[3] == 0o640 and new_csv[6] == "alice"
    assert r["remaining"]["total"] == 0
    restore_from_trash(trash, archive)
    assert archive.read_bytes() != raw  # ごみ箱から戻した元の書庫（書き換える前のもの）


def test_tar_remove_entry_inside_tgz(tmp_path):
    root = tmp_path / "src"
    root.mkdir()
    plain = root / "_pack.tar"
    build_tar(plain)
    archive = root / "pack.tgz"
    with open(archive, "wb") as f, gzip.GzipFile(filename="pack.tar", mode="wb", fileobj=f, mtime=1) as gz:
        gz.write(plain.read_bytes())
    plain.unlink()
    svc, store, job = make_archive_service(tmp_path, archive)
    r, _ = run_inner(svc, job, archive, f"{archive}!pack.tar!dir/people.csv", method="remove_entry")
    assert r["state"] == "done", r
    names = [v[0] for v in tar_view(gzip.decompress(archive.read_bytes()))]
    assert names == ["readme.txt", "other.bin", "emptydir"]


@pytest.mark.parametrize("ext", ["gz", "bz2", "xz"])
def test_single_compressed_file_is_rewrapped(tmp_path, ext, trash):
    import bz2
    import lzma

    root = tmp_path / "src"
    root.mkdir()
    archive = root / f"people.csv.{ext}"
    data = csv_bytes()
    if ext == "gz":
        with (
            open(archive, "wb") as f,
            gzip.GzipFile(filename="people.csv", mode="wb", fileobj=f, mtime=1_640_000_000) as gz,
        ):
            gz.write(data)
    elif ext == "bz2":
        archive.write_bytes(bz2.compress(data, 5))
    else:
        archive.write_bytes(lzma.compress(data, check=lzma.CHECK_CRC32))
    svc, store, job = make_archive_service(tmp_path, archive)
    item = f"{archive}!people.csv"
    a = analyze_inner(svc, job, archive, item)
    assert not a.info["methods"]["remove_entry"]["available"]  # 1ファイルを包んだだけ: 中のファイルだけは取り除けない
    assert "書庫ごと" in a.info["methods"]["remove_entry"]["reason"]
    r, _ = run_inner(svc, job, archive, item, method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    raw = archive.read_bytes()
    rows = person_rows()
    expect = encode_csv([rows[0]] + [x for x in rows[1:] if not x[3]], "utf-8", "\r\n")
    if ext == "gz":
        assert gz_header(raw) == (1_640_000_000, b"people.csv") and gzip.decompress(raw) == expect
    elif ext == "bz2":
        assert raw[3:4] == b"5" and bz2.decompress(raw) == expect
    else:
        assert raw[7] & 0x0F == lzma.CHECK_CRC32 and lzma.decompress(raw) == expect
    assert r["remaining"]["total"] == 0
    restore_from_trash(trash, archive)
    assert archive.read_bytes() != raw


# ---------------------------------------------------------------- 書けない形式（rar・cab・iso・wim など）: zip に作り直す


class StubHandler(aw.Handler):
    """形式の判定だけを試すための手下（本物の rar を作れないので）。"""

    def __init__(self, kind: str, writable: bool, single: bool = False):
        self.kind, self.writable, self.single = kind, writable, single

    def entries(self):
        return []

    def signed(self) -> bool:
        return False


def stub_resolved(*specs: tuple[str, bool]) -> aw.Resolved:
    hops = [
        aw.Hop(StubHandler(kind, writable), aw.Entry(f"e{n}", f"e{n}"), f"p{n}", f"p{n}")
        for n, (kind, writable) in enumerate(specs)
    ]
    return aw.Resolved(hops, "leaf", "leaf.csv", "e0")


def test_unwritable_formats_are_classified():
    for kind in ("rar", "cab", "iso", "wim", "lzh", "arj", "zstd"):
        assert kind in aw.ARCHIVE_KINDS and kind not in aw.WRITABLE_KINDS
    for kind in ("zip", "7z", "tar", "gzip", "bzip2", "xz"):
        assert kind in aw.WRITABLE_KINDS
    for kind in ("xlsx", "docx", "pptx", "odf", "ooxml"):
        assert kind not in aw.ARCHIVE_KINDS  # Office 文書は書庫として扱わない（形式の対処）
    d = stub_resolved(("rar", False)).describe()
    assert not d["can_write"] and d["can_convert"] and d["top_label"] == "rar"
    got = {"archive": d, "status": "scanned", "layout": "csv,", "overflow": False}
    assert remediate.unsupported_reason("delete_file", "x.csv", got) == ""
    assert remediate.unsupported_reason("convert_zip", "x.csv", got) == ""
    assert remediate.unsupported_reason("remove_entry", "x.csv", got) == ""
    assert remediate.unsupported_reason("dummy", "x.csv", got) == ""
    # 書ける形式では「zip に作り直す」は要らない
    w = stub_resolved(("zip", True)).describe()
    assert w["can_write"] and "必要はありません" in remediate.unsupported_reason("convert_zip", "x.csv", {"archive": w})
    # 入れ子の途中に書けない形式があれば、作り直せない（書庫ごとの削除だけ）
    n = stub_resolved(("zip", True), ("rar", False)).describe()
    assert not n["can_write"] and not n["can_convert"] and "入れ子の途中" in n["convert_reason"]
    got = {"archive": n, "status": "scanned", "layout": "csv,"}
    assert "書庫ごとの削除" in remediate.unsupported_reason("dummy", "x.csv", got)
    assert "書庫ごとの削除" in remediate.unsupported_reason("remove_entry", "x.csv", got)
    assert remediate.unsupported_reason("delete_file", "x.csv", got) == ""
    # 実ファイルには使えない方法
    assert "書庫の中" in remediate.unsupported_reason("remove_entry", "x.csv", {"status": "scanned"})


def make_wim(tmp_path: Path) -> Path:
    work = tmp_path / "workwim"
    (work / "data").mkdir(parents=True)
    (work / "data" / "people.csv").write_bytes(csv_bytes())
    (work / "readme.txt").write_bytes(b"hi\n")
    archive = tmp_path / "src" / "pack.wim"
    archive.parent.mkdir(exist_ok=True)
    r = subprocess.run(
        [SEVENZIP, "a", "-twim", str(archive), "data", "readme.txt"],
        cwd=work,
        capture_output=True,
        stdin=subprocess.DEVNULL,
    )
    if r.returncode != 0 or not archive.exists():
        pytest.skip("この 7-Zip では wim を作れない")
    return archive


@needs_7z
def test_unwritable_archive_can_become_zip(tmp_path, monkeypatch, trash):
    archive = make_wim(tmp_path)
    original = archive.read_bytes()
    svc, store, job = make_archive_service(tmp_path, archive)
    item = find_item(store, job, archive, "data/people.csv")
    a = analyze_inner(svc, job, archive, item)
    m = a.info["methods"]
    arch = a.info["archive"]
    assert arch["top_kind"] == "wim" and not arch["can_write"] and arch["can_convert"]
    assert m["delete_file"]["available"] and m["delete_file"]["label"].startswith("書庫ごと")
    assert m["convert_zip"]["available"] and m["remove_entry"]["available"] and m["delete_rows"]["available"]
    # 「zip に作り直す」を選ばずに実行しようとすると断る
    with pytest.raises(RemedyError, match="zip に作り直す"):
        svc.preview(job, str(archive), {"method": "delete_rows", "item_path": item, "confidences": ALL_RANKS})
    params = {"method": "delete_rows", "item_path": item, "confidences": ALL_RANKS, "convert_zip": True}
    pv = svc.preview(job, str(archive), params)
    first = pv["warnings"][0]
    assert "形式が変わります" in first and "pack.zip" in first and pv["convert_zip"]
    assert "ごみ箱へ送ります" in first and "退避の写しは作りません" in first and "拡張子が変わる" in first
    started = svc.start_run(job, str(archive), params, True, pv["expected_sha256"])
    svc._runs[started["run_id"]].thread.join(300)
    r = svc.run_status(job, started["run_id"])
    assert r["state"] == "done", r
    new_zip = archive.with_suffix(".zip")
    assert new_zip.exists() and not archive.exists() and trash.sent == [str(archive)]
    assert r["converted_to"] == str(new_zip) and r["disposal"] == "recycle_bin"
    with zipfile.ZipFile(new_zip) as z:
        assert sorted(z.namelist()) == ["data/people.csv", "readme.txt"] and z.read("readme.txt") == b"hi\n"
        rows = person_rows()
        assert z.read("data/people.csv") == encode_csv([rows[0]] + [x for x in rows[1:] if not x[3]], "utf-8", "\r\n")
    assert r["remaining"]["total"] == 0
    # 元の書庫は、退避せずにごみ箱へ（中身はバイト単位で元のまま）
    assert [f.read_bytes() for f in trash.files()] == [original] and not (tmp_path / "backup").exists()
    rec = store.remediation(job, r["remediation_id"])
    assert rec["filters"]["converted_to"] == str(new_zip) and rec["filters"]["item_path"] == item
    assert rec["backup_path"] is None and rec["changed"]["disposal"] == "recycle_bin" and rec["state"] == "applied"
    assert rec["plan"]["mode"] == "convert" and not list(archive.parent.glob(remediate.NEW_PREFIX + "*"))


@needs_7z
def test_convert_to_zip_without_recycle_bin_deletes_original_permanently(tmp_path, monkeypatch, trash):
    archive = make_wim(tmp_path)
    svc, store, job = make_archive_service(tmp_path, archive)
    item = find_item(store, job, archive, "data/people.csv")
    monkeypatch.setattr(remediate, "has_recycle_bin", lambda path: False)
    analyze_inner(svc, job, archive, item)
    params = {"method": "remove_entry", "item_path": item, "convert_zip": True}
    pv = svc.preview(job, str(archive), params)
    assert "完全に削除します" in pv["warnings"][0] and "ごみ箱がありません" in pv["warnings"][0]
    assert "元に戻せません" in pv["warnings"][0] and pv["disposal"] == "permanent"
    started = svc.start_run(job, str(archive), params, True, pv["expected_sha256"])
    svc._runs[started["run_id"]].thread.join(300)
    r = svc.run_status(job, started["run_id"])
    assert r["state"] == "done", r
    assert not archive.exists() and archive.with_suffix(".zip").exists()
    assert r["disposal"] == "permanent" and trash.sent == [] and trash.files() == []
    with zipfile.ZipFile(archive.with_suffix(".zip")) as z:
        assert z.namelist() == ["readme.txt"]


@needs_7z
def test_archive_delete_file_uses_same_two_messages(tmp_path):
    archive = make_wim(tmp_path)
    svc, store, job = make_archive_service(tmp_path, archive)
    item = find_item(store, job, archive, "data/people.csv")
    analyze_inner(svc, job, archive, item)
    a = svc.get_analysis(job, str(archive), item)
    a.info["recycle_bin"] = True
    assert svc.preview(job, str(archive), {"method": "delete_file", "item_path": item})["summary"] == (
        "書庫「pack.wim」をごみ箱へ送ります（ごみ箱から戻せます）"
    )
    a.info["recycle_bin"] = False
    pv = svc.preview(job, str(archive), {"method": "delete_file", "item_path": item})
    assert pv["summary"] == "書庫「pack.wim」を完全に削除します（この場所にはごみ箱がありません。元に戻せません）"
    assert any("完全に削除します" in w for w in pv["warnings"])


@needs_7z
def test_convert_zip_refuses_when_target_name_exists(tmp_path):
    archive = make_wim(tmp_path)
    original = archive.read_bytes()
    svc, store, job = make_archive_service(tmp_path, archive)
    item = find_item(store, job, archive, "data/people.csv")
    (archive.parent / "pack.zip").write_bytes(b"another file")
    r, _ = run_inner(svc, job, archive, item, method="remove_entry", convert_zip=True)
    assert r["state"] == "error" and "pack.zip" in r["message"] and "同じ場所" in r["message"]
    assert archive.read_bytes() == original and (archive.parent / "pack.zip").read_bytes() == b"another file"
    assert store.remediations(job) == [] and not list(archive.parent.glob(remediate.NEW_PREFIX + "*"))


@needs_7z
def test_convert_failure_keeps_original_and_removes_new_zip(tmp_path, monkeypatch):
    archive = make_wim(tmp_path)
    original = archive.read_bytes()
    svc, store, job = make_archive_service(tmp_path, archive)
    item = find_item(store, job, archive, "data/people.csv")

    def fail(path):
        raise RemedyError("ごみ箱へ送れませんでした（試験）")

    monkeypatch.setattr(remediate, "send_to_recycle_bin", fail)
    r, _ = run_inner(svc, job, archive, item, method="remove_entry", convert_zip=True)
    assert r["state"] == "error" and archive.read_bytes() == original
    assert not archive.with_suffix(".zip").exists() and not list(archive.parent.glob(remediate.NEW_PREFIX + "*"))
    assert store.remediations(job) == []


# ---------------------------------------------------------------- 失敗・変更・元はごみ箱へ・記録


def test_failure_while_rebuilding_keeps_original(zip_case, monkeypatch, trash):
    c = zip_case
    archive = c["archive"]
    original = archive.read_bytes()

    def broken(res, new_leaf, env, dst, convert):
        Path(dst).write_bytes(b"half written")  # 書きかけで落ちる
        raise OSError("disk full (simulated)")

    monkeypatch.setattr(aw, "rebuild_target", broken)
    r, _ = run_inner(c["svc"], c["job"], archive, c["item"], method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "error"
    assert archive.read_bytes() == original
    assert not list(archive.parent.glob(remediate.NEW_PREFIX + "*")) and leftover_workdirs(c["tmp"]) == []
    assert trash.sent == [] and c["store"].remediations(c["job"]) == []


def test_failure_at_rename_keeps_original(zip_case, monkeypatch, trash):
    c = zip_case
    original = c["archive"].read_bytes()

    def locked(src, dst):
        raise PermissionError("in use (simulated)")

    monkeypatch.setattr(remediate, "_fs_rename", locked)
    monkeypatch.setattr(remediate.time, "sleep", lambda s: None)
    r, _ = run_inner(c["svc"], c["job"], c["archive"], c["item"], method="remove_entry")
    assert r["state"] == "error" and "名前を変えられませんでした" in r["message"]
    assert c["archive"].read_bytes() == original and not list(c["archive"].parent.glob(remediate.NEW_PREFIX + "*"))
    assert trash.sent == [] and c["store"].remediations(c["job"]) == []


def test_archive_changed_since_preview_is_refused(zip_case):
    c = zip_case
    archive = c["archive"]
    analyze_inner(c["svc"], c["job"], archive, c["item"])
    params = {"method": "delete_rows", "item_path": c["item"], "confidences": ALL_RANKS}
    pv = c["svc"].preview(c["job"], str(archive), params)
    with zipfile.ZipFile(archive, "a") as z:  # 下見のあとに書庫が変わった
        z.writestr("added.txt", "x")
    changed = archive.read_bytes()
    started = c["svc"].start_run(c["job"], str(archive), params, True, pv["expected_sha256"])
    c["svc"]._runs[started["run_id"]].thread.join(120)
    r = c["svc"].run_status(c["job"], started["run_id"])
    assert r["state"] == "error" and "変わりました" in r["message"] and archive.read_bytes() == changed


def test_original_archive_goes_to_recycle_bin_whole_and_can_be_restored_from_it(zip_case, trash):
    c = zip_case
    archive = c["archive"]
    original = archive.read_bytes()
    before = snapshot(archive)
    r, _ = run_inner(c["svc"], c["job"], archive, c["item"], method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "done"
    assert archive.read_bytes() != original
    # 元の書庫は書庫ごと、「元の名前（対処前 日時）.zip」の名前で、ごみ箱へ。退避の写しは作らない
    sent = Path(trash.sent[0])
    assert sent.parent == archive.parent and re.fullmatch(r"pack（対処前 \d{8}-\d{6}）\.zip", sent.name)
    assert r["pre_name"] == sent.name and r["disposal"] == "recycle_bin"
    restore_from_trash(trash, archive)  # 利用者がごみ箱から戻したのと同じ
    assert archive.read_bytes() == original and snapshot(archive) == before  # 書庫ごと、バイト単位で元のまま
    assert not (c["tmp"] / "backup").exists()


def test_run_requires_confirmation_for_inner_item(zip_case):
    c = zip_case
    original = c["archive"].read_bytes()
    analyze_inner(c["svc"], c["job"], c["archive"], c["item"])
    for bad in (False, None, "yes", 1):
        with pytest.raises(RemedyError, match="確認"):
            c["svc"].start_run(
                c["job"], str(c["archive"]), {"method": "remove_entry", "item_path": c["item"]}, bad, None
            )
    assert c["archive"].read_bytes() == original


@pytest.mark.parametrize("nth", [1, 2], ids=["after-rename-original", "after-put-new-in-place"])
def test_crash_while_rebuilding_archive_is_recovered(zip_case, monkeypatch, trash, nth):
    """書庫の確定の途中に落ちても、立て直しのあとに元か新の書庫が、元の名前でバイト単位で残る。"""
    c = zip_case
    archive = c["archive"]
    original = archive.read_bytes()
    real = remediate._fs_rename
    calls = {"n": 0}

    def crashing(src, dst):
        calls["n"] += 1
        real(src, dst)
        if calls["n"] == nth:
            raise SimulatedCrash("rename")

    monkeypatch.setattr(remediate, "_fs_rename", crashing)
    analyze_inner(c["svc"], c["job"], archive, c["item"])
    params = {"method": "delete_rows", "item_path": c["item"], "confidences": ALL_RANKS}
    pv = c["svc"].preview(c["job"], str(archive), params)
    _, _, ctx = c["svc"]._begin_run(c["job"], str(archive), params, True, pv["expected_sha256"])
    with pytest.raises(SimulatedCrash):
        c["svc"]._apply(*ctx)
    monkeypatch.setattr(remediate, "_fs_rename", real)
    done = c["svc"].recover()
    assert c["store"].unfinished_remediations() == [] and done
    now = archive.read_bytes()
    assert now == original or zipfile.ZipFile(archive).testzip() is None  # どちらかの完全な書庫
    assert original in [now] + [f.read_bytes() for f in trash.files()]  # 元の書庫は失われていない
    assert not list(archive.parent.glob(remediate.NEW_PREFIX + "*")) and not list(archive.parent.glob("*対処前*"))


def test_records_job_db_and_temp_have_no_raw_values(tmp_path, trash):
    import glob
    import sqlite3

    root = tmp_path / "src"
    root.mkdir()
    archive = root / "pack.zip"
    build_zip(archive, [PLAIN[0], ("data/people.csv", csv_bytes(), DEFLATED, (2022, 7, 8, 9, 10, 12)), PLAIN[1]])
    svc, store, job = make_archive_service(tmp_path, archive)
    needles = raw_needles(person_rows())
    r, _ = run_inner(
        svc, job, archive, item_of(archive, "data/people.csv"), method="dummy", dummy_mode="same", confidences=ALL_RANKS
    )
    assert r["state"] == "done", r
    db_files = glob.glob(str(tmp_path / "jobs.sqlite3*"))
    assert db_files and _leak(db_files, needles) == []
    for table in ("jobs", "files", "items", "findings", "remediations"):
        for row in store.query(f"SELECT * FROM {table}"):
            for v in tuple(row):
                if isinstance(v, str):
                    assert not any(n in v for n in needles), (table, v[:80])
    rec = store.remediations(job)[0]
    assert rec["method"] == "dummy" and rec["filters"]["item_path"].endswith("!data/people.csv")
    assert rec["backup_path"] is None and not (tmp_path / "backup").exists()  # 退避は作らない
    # 作業用の一時フォルダ・検査の一時フォルダに、取り出したファイルが残っていない
    scan_files = [str(p) for p in (tmp_path / "scantmp").rglob("*") if p.is_file()]
    assert _leak(scan_files, needles) == [] and leftover_workdirs(tmp_path) == []
    # 陽性対照: 生の値を入れた DB・取り出した元のファイルなら、この探し方で見つかる
    q = tmp_path / "control.sqlite3"
    con = sqlite3.connect(q)
    con.execute("CREATE TABLE t(a TEXT)")
    con.execute("INSERT INTO t VALUES (?)", (f"x {needles[0]} y",))
    con.commit()
    con.close()
    assert _leak([str(q)], needles) == [needles[0]]
    extracted = tmp_path / "extracted_original.csv"
    extracted.write_bytes(zip_member(trash.files()[0], "data/people.csv"))
    assert _leak([str(extracted)], needles)  # ごみ箱へ送った元の書庫の中には元の値がある
    assert not any(n.encode("utf-8") in zip_member(archive, "data/people.csv") for n in needles)


def test_office_documents_are_not_treated_as_archives(tmp_path):
    x = tmp_path / "book.xlsx"
    build_xlsx(x, 5)
    workdir, owner = aw.make_workdir(str(tmp_path))
    try:
        env = aw.ArchiveEnv(SEVENZIP, [], workdir)
        with pytest.raises(RemedyError, match="書庫として扱わない"):
            aw.open_handler(str(x), env, "book.xlsx")
        with pytest.raises(RemedyError, match="書庫として扱わない"):
            aw.extract_target(str(x), f"{x}!xl/workbook.xml", env)
    finally:
        aw.remove_workdir(workdir, owner)


def test_signed_archive_warns_and_plain_file_has_no_archive_methods(tmp_path):
    root = tmp_path / "src"
    root.mkdir()
    jar = root / "app.jar"
    build_zip(
        jar,
        [
            ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n", DEFLATED, (2022, 1, 1, 1, 1, 2)),
            ("META-INF/CERT.SF", b"Signature-Version: 1.0\n", DEFLATED, (2022, 1, 1, 1, 1, 2)),
            ("META-INF/CERT.RSA", b"\x30\x82" + b"\x00" * 40, DEFLATED, (2022, 1, 1, 1, 1, 2)),
            ("people.csv", csv_bytes(), DEFLATED, (2022, 1, 1, 1, 1, 2)),
        ],
    )
    svc, store, job = make_archive_service(tmp_path, jar)
    analyze_inner(svc, job, jar, item_of(jar, "people.csv"))
    pv = svc.preview(
        job, str(jar), {"method": "delete_rows", "item_path": item_of(jar, "people.csv"), "confidences": ALL_RANKS}
    )
    assert any("署名" in w and "壊れ" not in w or "検証に通らなく" in w for w in pv["warnings"])
    # 書庫の中でないファイル（実ファイル）の分析には、書庫用の方法を出さない
    plain = root / "a.csv"
    plain.write_bytes(csv_bytes())
    svc2, store2, job2 = make_archive_service(tmp_path / "two", plain)
    plan = svc2._plan(job2, str(plain))
    a = Analysis(job2, str(plain))
    a.size = plan["size"]
    svc2._analyze(a, plan)
    assert a.state == "done" and "remove_entry" not in a.info["methods"] and "convert_zip" not in a.info["methods"]


def test_item_not_in_job_or_wrong_path_is_refused(zip_case):
    c = zip_case
    with pytest.raises(RemedyError, match="見つかりません"):
        c["svc"]._plan(c["job"], str(c["archive"]), item_of(c["archive"], "no/such.csv"))
    with pytest.raises(RemedyError, match="正しくありません"):
        c["svc"]._plan(c["job"], str(c["archive"]), "C:/elsewhere.zip!data/people.csv")


def test_second_item_after_first_needs_fresh_analysis_and_both_stay_clean(tmp_path):
    root = tmp_path / "src"
    root.mkdir()
    archive = root / "two.zip"
    build_zip(
        archive,
        [
            ("a.csv", csv_bytes(), DEFLATED, (2022, 1, 1, 1, 1, 2)),
            ("b.csv", csv_bytes(), STORED, (2023, 1, 1, 1, 1, 2)),
            PLAIN[0],
        ],
    )
    svc, store, job = make_archive_service(tmp_path, archive)
    ia, ib = item_of(archive, "a.csv"), item_of(archive, "b.csv")
    analyze_inner(svc, job, archive, ia)
    analyze_inner(svc, job, archive, ib)
    pa = {"method": "delete_rows", "item_path": ia, "confidences": ALL_RANKS}
    pv = svc.preview(job, str(archive), pa)
    assert "1項目ずつ" in "\n".join(pv["warnings"])
    started = svc.start_run(job, str(archive), pa, True, pv["expected_sha256"])
    svc._runs[started["run_id"]].thread.join(120)
    assert svc.run_status(job, started["run_id"])["state"] == "done"
    with pytest.raises(
        RemedyError, match="分析の結果が見つかりません"
    ):  # 書庫が変わったので、別の項目の古い分析も捨てる
        svc.preview(job, str(archive), {"method": "delete_rows", "item_path": ib, "confidences": ALL_RANKS})
    r, _ = run_inner(svc, job, archive, ib, method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    assert inner_values(archive, tmp_path, ia) == [] and inner_values(archive, tmp_path, ib) == []
    assert total_detections(archive, tmp_path) == 0


# ---------------------------------------------------------------- API・実際の別プロセス


def _free_port() -> int:
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_api_inner_item_end_to_end(tmp_path, trash):
    import threading
    import time
    import urllib.error
    import urllib.request

    import uvicorn

    from pii_checker.web.server import create_app

    root = tmp_path / "src"
    root.mkdir()
    archive = root / "pack.zip"
    build_zip(archive, [PLAIN[0], ("data/people.csv", csv_bytes(), DEFLATED, (2022, 7, 8, 9, 10, 12)), PLAIN[1]])
    svc0, store, job = make_archive_service(tmp_path, archive)
    before = snapshot(archive)
    token = "inner-test-token"
    app = create_app(
        db=str(tmp_path / "jobs.sqlite3"),
        token=token,
        remedy_runner=inline_runner,
    )
    port = _free_port()
    srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    th = threading.Thread(target=srv.run, daemon=True)
    th.start()
    for _ in range(100):
        if srv.started:
            break
        time.sleep(0.05)
    base = f"http://127.0.0.1:{port}"

    def call(path, method="GET", body=None):
        headers = {"X-Token": token, "Content-Type": "application/json"}
        if method != "GET":
            headers["X-Requested-With"] = "pii-checker"
        req = urllib.request.Request(
            base + path, data=json.dumps(body).encode() if body is not None else None, method=method, headers=headers
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.status, json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    try:
        item = item_of(archive, "data/people.csv")
        for _ in range(200):
            code, a = call(f"/api/jobs/{job}/remedy/analyze", "POST", {"top_path": str(archive), "item_path": item})
            assert code == 200
            if a["state"] != "running":
                break
            time.sleep(0.1)
        assert a["state"] == "done", a
        assert a["archive"]["top_kind"] == "zip" and a["archive"]["can_write"] and "remove_entry" in a["methods"]
        assert a["methods"]["delete_file"]["label"].startswith("書庫ごと")
        body = {"top_path": str(archive), "item_path": item, "method": "delete_rows", "confidences": ALL_RANKS}
        code, pv = call(f"/api/jobs/{job}/remedy/preview", "POST", body)
        assert (
            code == 200 and pv["item_name"] == "data/people.csv" and "全体を作り直します" in "\n".join(pv["warnings"])
        )
        code, bad = call(f"/api/jobs/{job}/remedy/preview", "POST", {**body, "item_path": 5})
        assert code == 400
        code, started = call(
            f"/api/jobs/{job}/remedy/run", "POST", {**body, "confirmed": True, "expected_sha256": pv["expected_sha256"]}
        )
        assert code == 200, started
        for _ in range(300):
            code, st = call(f"/api/jobs/{job}/remedy/runs/{started['run_id']}")
            if st["state"] != "running":
                break
            time.sleep(0.1)
        assert st["state"] == "done" and st["item_name"] == "data/people.csv", st
        code, listing = call(f"/api/jobs/{job}/remediations")
        row = listing["rows"][0]
        assert row["item_path"] == item and row["method"] == "delete_rows" and row["file_name"] == "pack.zip"
        assert row["disposal"] == "recycle_bin" and row["pre_name"].startswith("pack（対処前 ")
        assert "backup_root" not in listing
        code, _ = call(f"/api/jobs/{job}/remediations/{row['id']}/undo", "POST", {})
        assert code in (404, 405)  # 退避の写しから戻す「元に戻す」は無い
        restore_from_trash(trash, archive)  # ごみ箱から戻したのと同じ
        assert snapshot(archive) == before
    finally:
        srv.should_exit = True
        th.join(timeout=10)


def test_real_worker_process_round_trip_for_archive(tmp_path):
    """実際の別プロセス（pebble・メモリ上限つき）で、分析 → 実行まで通る（書庫の情報・パスワード入れ物の受け渡し）。"""
    root = tmp_path / "src"
    root.mkdir()
    archive = root / "pack.zip"
    build_zip(archive, [PLAIN[0], ("data/people.csv", csv_bytes(), DEFLATED, (2022, 7, 8, 9, 10, 12)), PLAIN[1]])
    svc, store, job = make_archive_service(tmp_path, archive, passwords=["x-unused"], runner=remediate._run_in_process)
    before = snapshot(archive)
    item = item_of(archive, "data/people.csv")
    plan = svc._plan(job, str(archive), item)
    a = Analysis(job, str(archive), item)
    a.size = plan["size"]
    svc._analyze(a, plan)
    assert a.state == "done", a.error
    svc._analyses[(job, item)] = a
    params = {"method": "remove_entry", "item_path": item}
    pv = svc.preview(job, str(archive), params)
    started = svc.start_run(job, str(archive), params, True, pv["expected_sha256"])
    svc._runs[started["run_id"]].thread.join(300)
    r = svc.run_status(job, started["run_id"])
    assert r["state"] == "done", r
    assert_zip_others_untouched(before, snapshot(archive), "data/people.csv", keep_target=False)

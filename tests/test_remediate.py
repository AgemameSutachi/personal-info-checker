"""検出した個人情報への対処（remediate。T2-a: 土台・ファイルの削除・csv/tsv/txt・xlsx/xlsm）の試験。

守ること: 検査は何も書き込まない。対処は人が選んで実行したときだけ。元は元の写しへ写し、書き換えは新しいファイルへ書いてから置き換え、
途中の失敗で元を壊さず、「元に戻す」で戻せる。記録とジョブの DB に生の値を入れない。
検体はすべて pytest の tmp_path に作る。本物のごみ箱へは送らない（送る関数を差し替える）。元の写しの置き場も tmp_path。
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import shutil
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pii_checker import engine, remediate, remedy_write  # noqa: E402
from pii_checker.models import PasswordBook, ScanOptions  # noqa: E402
from pii_checker.remediate import Analysis, RemedyService, inline_runner  # noqa: E402
from pii_checker.remedy_write import DummyMaker, RemedyError  # noqa: E402
from pii_checker.store import Store  # noqa: E402

TOKEN = "remedy-test-token"
N_ROWS = 30  # 明細の上限（20 件）を超える数


# ---------------------------------------------------------------- 本物のごみ箱を使わない（差し替え）

REAL_SEND_TO_RECYCLE_BIN = remediate.send_to_recycle_bin  # 差し替える前の本物（長すぎるパスの試験だけが使う）


class FakeTrash:
    """ごみ箱の代わり（tmp_path の中のフォルダへ移すだけ）。本物のごみ箱へは送らない。"""

    def __init__(self, root: Path):
        self.root = root
        self.sent: list[str] = []
        root.mkdir(parents=True, exist_ok=True)

    def __call__(self, path: str) -> None:
        self.sent.append(path)
        shutil.move(path, str(self.root / f"{len(self.sent)}-{Path(path).name}"))

    def files(self) -> list[Path]:
        return sorted(p for p in self.root.iterdir() if p.is_file())


@pytest.fixture(autouse=True)
def trash(tmp_path, monkeypatch):
    """どの試験でも、ごみ箱へ送る関数を差し替える（本物のごみ箱へ送らない）。ごみ箱のある場所として扱う。"""
    t = FakeTrash(tmp_path / "_trash")
    monkeypatch.setattr(remediate, "send_to_recycle_bin", t)
    monkeypatch.setattr(remediate, "has_recycle_bin", lambda path: True)
    return t


def trash_sent_nothing(tmp_path: Path) -> bool:
    return not (tmp_path / "_trash").exists() or not list((tmp_path / "_trash").iterdir())


def new_tmp_files(folder: Path) -> list[Path]:
    """書き換えの途中の一時の新ファイル（~piichk-new-…）の残り。"""
    return list(folder.glob(remediate.NEW_PREFIX + "*"))


# ---------------------------------------------------------------- 検体の作り方


def person_rows(n: int = N_ROWS) -> list[list[str]]:
    """見出し1行＋データ n 行（5行に1行は個人情報なし）。見出しの行・「備考」の列は検出に当たらない形にしてある。"""
    rows = [["備考", "氏名", "電話", "メール"]]
    for i in range(n):
        if i % 5 == 4:
            rows.append([f"メモ{i}", "", "", ""])
        else:
            rows.append([f"メモ{i}", f"山田太郎{i}", f"090-{1000 + i:04d}-{5000 + i:04d}", f"user{i}@example.com"])
    return rows


def raw_needles(rows: list[list[str]]) -> list[str]:
    return [v for r in rows[1:] for v in r[1:] if v]


def encode_csv(rows, enc: str, newline: str, quoting=csv.QUOTE_MINIMAL, delimiter: str = ",") -> bytes:
    buf = io.StringIO(newline="")
    csv.writer(buf, delimiter=delimiter, quoting=quoting, lineterminator=newline).writerows(rows)
    text = buf.getvalue()
    if enc == "utf-8-sig":
        return b"\xef\xbb\xbf" + text.encode("utf-8")
    if enc == "utf-16":
        return b"\xff\xfe" + text.encode("utf-16-le")
    return text.encode(enc)


CSV_VARIANTS = [
    pytest.param("utf-8-sig", "\r\n", csv.QUOTE_MINIMAL, id="utf8bom-crlf"),
    pytest.param("cp932", "\r\n", csv.QUOTE_ALL, id="cp932-crlf-quoted"),
    pytest.param("utf-8", "\n", csv.QUOTE_MINIMAL, id="utf8-lf"),
    pytest.param("utf-16", "\r\n", csv.QUOTE_MINIMAL, id="utf16bom-crlf"),
]


def scan_counts(path: Path, tmp: Path) -> tuple[int, list[tuple[str, str]]]:
    """（検出の総数, [(種類, 生の値)]）。値は読み直し（reveal）から得る。"""
    res = engine.scan_file(str(path), ScanOptions(temp_dir=str(tmp), reveal=True), PasswordBook())
    total = sum(sum(it.conf_counts.values()) for it in res.items)
    return total, [(f.pii_type, f.raw_value) for it in res.items for f in it.findings]


def make_service(tmp_path: Path, files: list[Path], runner=inline_runner):
    scan_tmp = tmp_path / "scantmp"
    scan_tmp.mkdir(exist_ok=True)
    store = Store(str(tmp_path / "jobs.sqlite3"))
    job = store.create_job([str(files[0].parent)], ScanOptions(temp_dir=str(scan_tmp)))
    store.add_files(job, [(str(f), f.stat().st_size, f.stat().st_mtime) for f in files])
    with store.tx() as c:
        c.execute("UPDATE files SET state='done' WHERE job_id=?", (job,))
    svc = RemedyService(store, runner_fn=runner)
    return svc, store, job


def analyze(svc: RemedyService, job: str, path: Path) -> Analysis:
    plan = svc._plan(job, str(path))
    a = Analysis(job, str(path))
    a.size = plan["size"]
    svc._analyze(a, plan)
    assert a.state == "done", a.error
    svc._analyses[(job, str(path))] = a
    return a


def run(svc: RemedyService, job: str, path: Path, **params) -> dict:
    """分析 → 下見 → 実行（同じ流れ）を終わりまで走らせ、実行の結果（state・message・changed ...）を返す。"""
    analyze(svc, job, path)
    pv = svc.preview(job, str(path), params)
    started = svc.start_run(job, str(path), params, True, pv.get("expected_sha256"))
    svc._runs[started["run_id"]].thread.join(180)
    return svc.run_status(job, started["run_id"])


ALL_RANKS = ["high", "medium", "low"]


# ---------------------------------------------------------------- 位置を集める（全部・生の値なし）


def test_collect_positions_beyond_sample_limit(tmp_path):
    """明細は種類ごとに 20 件までだが、位置は全部（30 行分）集める。生の値は持たない。"""
    rows = person_rows()
    p = tmp_path / "src" / "a.csv"
    p.parent.mkdir()
    p.write_bytes(encode_csv(rows, "utf-8", "\n"))
    got = remediate.collect_task({"path": str(p), "options": ScanOptions(temp_dir=str(tmp_path))})
    assert got["status"] == "scanned" and got["layout"] == "csv," and not got["overflow"]
    emails = got["positions"][("", "email", 2)]
    assert len(emails) // 4 == len([r for r in rows[1:] if r[3]]) > 20
    plain = engine.scan_file(str(p), ScanOptions(temp_dir=str(tmp_path)), PasswordBook())
    assert max(len([f for f in it.findings if f.pii_type == "email"]) for it in plain.items) == 20
    # 通常の検査の結果は、位置を集めても変わらない
    withpos = engine.scan_file(str(p), ScanOptions(temp_dir=str(tmp_path), collect_positions=True), PasswordBook())
    assert [it.conf_counts for it in plain.items] == [it.conf_counts for it in withpos.items]
    assert not any(it.positions for it in plain.items)


def test_preview_while_still_analyzing_says_so(tmp_path):
    """読み直しの途中で下見を求めたら「捨てました」ではなく「途中です」と返す（VM で API を試して紛らわしかった文面）。"""
    p = tmp_path / "a.csv"
    p.write_text("氏名\n山田太郎\n", encoding="utf-8")
    svc, _store, job = make_service(tmp_path, [p])
    svc._analyses[(job, str(p))] = Analysis(job, str(p))  # 状態は running のまま
    with pytest.raises(RemedyError, match="途中"):
        svc.preview(job, str(p), {"method": "delete_rows"})


def test_positions_option_is_not_saved_and_not_in_signature(tmp_path):
    from pii_checker.signature import engine_signature

    store = Store(str(tmp_path / "jobs.sqlite3"))
    job = store.create_job([str(tmp_path)], ScanOptions(collect_positions=True))
    assert "collect_positions" not in store.job(job)["options"]
    assert engine_signature(ScanOptions(collect_positions=True)) == engine_signature(ScanOptions())


def test_positions_overflow_is_flagged(tmp_path, monkeypatch):
    monkeypatch.setattr(engine, "POSITIONS_LIMIT", 5)
    p = tmp_path / "src" / "a.csv"
    p.parent.mkdir()
    p.write_bytes(encode_csv(person_rows(), "utf-8", "\n"))
    got = remediate.collect_task({"path": str(p), "options": ScanOptions(temp_dir=str(tmp_path))})
    assert got["overflow"]
    reason = remediate.unsupported_reason("delete_rows", str(p), got)
    assert "多すぎ" in reason
    assert remediate.unsupported_reason("delete_file", str(p), got) == ""


# ---------------------------------------------------------------- csv


@pytest.mark.parametrize("enc,newline,quoting", CSV_VARIANTS)
def test_csv_delete_rows(tmp_path, enc, newline, quoting, trash):
    rows = person_rows()
    p = tmp_path / "src" / "a.csv"
    p.parent.mkdir()
    p.write_bytes(encode_csv(rows, enc, newline, quoting))
    original = p.read_bytes()
    svc, store, job = make_service(tmp_path, [p])
    r = run(svc, job, p, method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    kept = [rows[0]] + [x for x in rows[1:] if not x[3]]
    assert p.read_bytes() == encode_csv(kept, enc, newline, quoting)  # 触らない行は文字コード・改行・引用符も元のまま
    assert r["changed"]["rows"] == len(rows) - len(kept)
    assert r["remaining"]["total"] == 0
    assert [f.read_bytes() for f in trash.files()] == [original]  # 元はごみ箱へ（元の写しは作らない）
    total, values = scan_counts(p, tmp_path)
    assert total == 0 and not values


@pytest.mark.parametrize("enc,newline,quoting", CSV_VARIANTS)
def test_csv_delete_columns(tmp_path, enc, newline, quoting):
    rows = person_rows()
    p = tmp_path / "src" / "a.csv"
    p.parent.mkdir()
    p.write_bytes(encode_csv(rows, enc, newline, quoting))
    svc, store, job = make_service(tmp_path, [p])
    r = run(svc, job, p, method="delete_columns", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    assert p.read_bytes() == encode_csv([[x[0]] for x in rows], enc, newline, quoting)
    assert r["changed"]["cols"] == 3 and r["remaining"]["total"] == 0


@pytest.mark.parametrize("enc,newline,quoting", CSV_VARIANTS)
@pytest.mark.parametrize("mode", ["fixed", "shape", "same"])
def test_csv_dummy(tmp_path, enc, newline, quoting, mode):
    rows = person_rows()
    p = tmp_path / "src" / "a.csv"
    p.parent.mkdir()
    p.write_bytes(encode_csv(rows, enc, newline, quoting))
    svc, store, job = make_service(tmp_path, [p])
    r = run(svc, job, p, method="dummy", dummy_mode=mode, confidences=ALL_RANKS)
    assert r["state"] == "done", r
    assert r["remaining"]["total"] == 0, r["remaining"]
    body = p.read_bytes()
    # 文字コード・BOM・改行が元のまま
    assert body[:3] == (b"\xef\xbb\xbf" if enc == "utf-8-sig" else body[:3])
    assert body[:2] == (b"\xff\xfe" if enc == "utf-16" else body[:2])
    text = {"utf-8-sig": lambda b: b[3:].decode("utf-8"), "utf-16": lambda b: b[2:].decode("utf-16-le")}.get(
        enc, lambda b: b.decode(enc)
    )(body)
    assert text.count("\r\n") == (len(rows) if newline == "\r\n" else 0)
    new_rows = list(csv.reader(io.StringIO(text, newline="")))
    assert len(new_rows) == len(rows)
    assert new_rows[0] == rows[0]  # 見出しの行はそのまま
    for old, new in zip(rows[1:], new_rows[1:]):
        assert new[0] == old[0]  # 触らない列は元のまま
        if not old[3]:
            assert new == old  # 個人情報のない行は丸ごと元のまま
        else:
            assert all(a != b for a, b in zip(old[1:], new[1:]))
    # 元の値はファイルのどこにも残らない
    for needle in raw_needles(rows):
        assert needle not in text
    if mode == "fixed":
        assert new_rows[1][1:] == ["＊＊＊"] * 3
    if mode == "shape":
        assert new_rows[1][2] == "000-0000-0000" and "@" in new_rows[1][3] and "user" not in new_rows[1][3]
    if mode == "same":
        assert len({r[3] for r in new_rows[1:] if r[3]}) == len([r for r in rows[1:] if r[3]])  # 別の値は別のダミー


def test_csv_dummy_same_value_gives_same_dummy_and_key_differs_per_run(tmp_path):
    rows = [["備考", "氏名", "電話", "メール"]] + [
        ["a", "山田太郎", "090-1234-5678", "same@example.com"],
        ["b", "鈴木花子", "080-1111-2222", "same@example.com"],
        ["c", "佐藤次郎", "070-3333-4444", "other@example.com"],
    ]
    outs = []
    for k in range(2):
        d = tmp_path / f"r{k}"
        (d / "src").mkdir(parents=True)
        p = d / "src" / "a.csv"
        p.write_bytes(encode_csv(rows, "utf-8", "\n"))
        svc, store, job = make_service(d, [p])
        r = run(svc, job, p, method="dummy", dummy_mode="same", confidences=ALL_RANKS)
        assert r["state"] == "done", r
        outs.append(list(csv.reader(io.StringIO(p.read_text(encoding="utf-8")))))
    first = outs[0]
    assert first[1][3] == first[2][3] and first[1][3] != first[3][3]  # 同じ値は同じダミー
    assert first[1][3] != outs[1][1][3]  # 鍵はジョブごと（保存しない）


def test_csv_quoted_fields_and_embedded_newlines_are_kept(tmp_path):
    """引用符つきの欄・欄の中の改行・区切りを含む欄は、触らない行では元のまま、触る欄では引用符を保つ。"""
    text = (
        "備考,氏名,メール\r\n"
        '"a,1",山田太郎,"taro@example.com"\r\n'
        '"line1\r\nline2",,\r\n'
        'plain,"鈴木 ""花子""",hanako@example.com\r\n'
    )
    p = tmp_path / "src" / "q.csv"
    p.parent.mkdir()
    p.write_bytes(text.encode("utf-8"))
    svc, store, job = make_service(tmp_path, [p])
    r = run(svc, job, p, method="dummy", dummy_mode="fixed", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    assert p.read_bytes().decode("utf-8") == (
        "備考,氏名,メール\r\n" '"a,1",＊＊＊,"＊＊＊"\r\n' '"line1\r\nline2",,\r\n' 'plain,"＊＊＊",＊＊＊\r\n'
    )


def test_tsv_delete_rows(tmp_path):
    rows = person_rows()
    p = tmp_path / "src" / "a.tsv"
    p.parent.mkdir()
    p.write_bytes(encode_csv(rows, "cp932", "\r\n", delimiter="\t"))
    svc, store, job = make_service(tmp_path, [p])
    r = run(svc, job, p, method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    kept = [rows[0]] + [x for x in rows[1:] if not x[3]]
    assert p.read_bytes() == encode_csv(kept, "cp932", "\r\n", delimiter="\t")


def test_csv_filter_by_type_and_confidence(tmp_path):
    """種類を絞ると、その種類を含む行・列・値だけが変わる。"""
    rows = person_rows()
    p = tmp_path / "src" / "a.csv"
    p.parent.mkdir()
    p.write_bytes(encode_csv(rows, "utf-8", "\n"))
    svc, store, job = make_service(tmp_path, [p])
    r = run(svc, job, p, method="dummy", dummy_mode="fixed", types=["email"], confidences=ALL_RANKS)
    assert r["state"] == "done", r
    new_rows = list(csv.reader(io.StringIO(p.read_text(encoding="utf-8"))))
    assert [x[1:3] for x in new_rows] == [x[1:3] for x in rows]  # 氏名・電話はそのまま
    assert all(x[3] in ("", "＊＊＊", "メール") for x in new_rows)
    # 残りは選ばなかった種類（氏名・電話）の分
    assert r["remaining"]["selected"] == 0 and r["remaining"]["total"] > 0


# ---------------------------------------------------------------- txt


def txt_lines(n: int = 120) -> list[str]:
    out = []
    for i in range(n):
        out.append(f"お知らせ{i}番です")
        out.append(f"メール: user{i}@example.com")
    return out


@pytest.mark.parametrize("enc,newline", [("utf-8", "\n"), ("cp932", "\r\n"), ("utf-8-sig", "\r\n")])
def test_txt_delete_rows_and_dummy(tmp_path, enc, newline):
    lines = txt_lines()
    bom = b"\xef\xbb\xbf" if enc == "utf-8-sig" else b""
    codec = "utf-8" if enc == "utf-8-sig" else enc
    data = bom + (newline.join(lines) + newline).encode(codec)
    # 行削除
    d1 = tmp_path / "a"
    (d1 / "src").mkdir(parents=True)
    p = d1 / "src" / "n.txt"
    p.write_bytes(data)
    svc, store, job = make_service(d1, [p])
    r = run(svc, job, p, method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    kept = [x for x in lines if "@" not in x]
    assert p.read_bytes() == bom + (newline.join(kept) + newline).encode(codec)
    assert r["changed"]["rows"] == 120 > 20 and r["remaining"]["total"] == 0
    # ダミー化（値の部分だけ）
    d2 = tmp_path / "b"
    (d2 / "src").mkdir(parents=True)
    q = d2 / "src" / "n.txt"
    q.write_bytes(data)
    svc, store, job = make_service(d2, [q])
    r = run(svc, job, q, method="dummy", dummy_mode="fixed", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    expected = [x if "@" not in x else "メール: ＊＊＊" for x in lines]
    assert q.read_bytes() == bom + (newline.join(expected) + newline).encode(codec)
    assert r["remaining"]["total"] == 0


def test_txt_delete_columns_is_not_available(tmp_path):
    p = tmp_path / "src" / "n.txt"
    p.parent.mkdir()
    p.write_bytes(("\n".join(txt_lines(3)) + "\n").encode("utf-8"))
    svc, store, job = make_service(tmp_path, [p])
    a = analyze(svc, job, p)
    assert not a.info["methods"]["delete_columns"]["available"]
    with pytest.raises(RemedyError):
        svc.preview(job, str(p), {"method": "delete_columns"})


# ---------------------------------------------------------------- ダミーの部品


def test_replace_spans_maps_back_from_normalized_text():
    """全角で書かれた値でも、正規化後の位置を元の文字へ直して、その部分だけを置き換える。"""
    from pii_checker import detectors

    text = "連絡先：０９０－１２３４－５６７８（携帯）です"
    norm = detectors.normalize(text)
    hits = detectors.detect(norm)
    spans = [(h.start, h.end, h.pii_type) for h in hits if h.pii_type == "phone"]
    assert spans
    out = remedy_write.replace_spans(text, spans, DummyMaker("fixed"))
    assert out.startswith("連絡先：＊＊＊") and out.endswith("（携帯）です") and "０９０" not in out


def test_dummy_shapes():
    assert remedy_write.shape_of("090-1234-5678") == "000-0000-0000"
    assert remedy_write.shape_of("山田 太郎") == "〇〇 〇〇"
    assert remedy_write.shape_of("a.b@example.com") == "〇.〇@〇〇〇〇〇〇〇.〇〇〇"


def test_same_mode_is_keyed_and_stable():
    a, b = DummyMaker("same", key=b"k" * 32), DummyMaker("same", key=b"j" * 32)
    assert a.make("email", "x@example.com") == a.make("email", "X@Example.com")  # 正規化して同じ値は同じダミー
    assert a.make("email", "x@example.com") != a.make("email", "y@example.com")
    assert a.make("email", "x@example.com") != b.make("email", "x@example.com")
    assert a.make("email", "x@example.com") != a.make("phone", "x@example.com")


# ---------------------------------------------------------------- xlsx


def build_xlsx(path: Path, n: int = N_ROWS) -> list[list[str]]:
    import openpyxl
    from openpyxl.styles import Font, PatternFill

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "顧客"
    rows = person_rows(n)
    for r in rows:
        ws.append(r)
    ws["G1"] = "文字数"  # 見出しの隣に置くと、横持ちの表の読み方で見出しの文字が値として拾われるので、2列あける
    for i in range(2, len(rows) + 1):
        ws[f"G{i}"] = f"=LEN(A{i})"  # 数式（個人情報を指さない列）
    for c in ws[1]:
        c.font = Font(bold=True)
        c.fill = PatternFill("solid", fgColor="DDEEFF")
    for letter, w in zip("ABCDEFG", (14, 18, 22, 30, 10, 10, 12)):
        ws.column_dimensions[letter].width = w
    ws.row_dimensions[3].height = 30
    ws.row_dimensions[len(rows)].height = 40
    ws["A2"].number_format = "@"
    memo = wb.create_sheet("メモ")
    memo.append(["項目", "内容"])
    memo.append(["日付", "2026年"])
    memo.append(["注意", "ここには個人情報はありません"])
    wb.create_sheet("その他").append(["x", "y"])
    wb.save(path)
    return rows


def read_sheet(path: Path, name: str) -> list[list]:
    import openpyxl

    wb = openpyxl.load_workbook(path)
    try:
        return [[c.value for c in row] for row in wb[name].iter_rows()]
    finally:
        wb.close()


def zip_parts(path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path) as z:
        return {n: z.read(n) for n in z.namelist()}


def contains_text(path: Path, needles: list[str]) -> list[str]:
    parts = zip_parts(path)
    return [n for n in needles if any(n.encode("utf-8") in b for b in parts.values())]


@pytest.fixture
def xlsx_case(tmp_path):
    p = tmp_path / "src" / "customers.xlsx"
    p.parent.mkdir()
    rows = build_xlsx(p)
    svc, store, job = make_service(tmp_path, [p])
    return {"path": p, "rows": rows, "svc": svc, "store": store, "job": job, "tmp": tmp_path, "orig": p.read_bytes()}


def test_xlsx_dummy_keeps_everything_else(xlsx_case):
    c = xlsx_case
    p, rows = c["path"], c["rows"]
    before = zip_parts(p)
    assert contains_text(p, raw_needles(rows)), "元のファイルには値がある（探し方の確認）"
    r = run(c["svc"], c["job"], p, method="dummy", dummy_mode="fixed", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    assert r["remaining"]["total"] == 0, r["remaining"]
    assert contains_text(p, raw_needles(rows)) == []  # 共有文字列を含め、元の値がファイルのどこにも残らない
    new = read_sheet(p, "顧客")
    assert new[0][:4] == rows[0]  # 見出し
    for old_row, new_row in zip(rows[1:], new[1:]):
        assert new_row[0] == old_row[0]
        if old_row[3]:
            assert new_row[1:4] == ["＊＊＊"] * 3
        else:
            assert new_row[1:4] == [None, None, None] or new_row[1:4] == ["", "", ""]
    # 数式・見出し・ほかのシートは元のまま
    assert new[1][6] == "=LEN(A2)" and new[0][6] == "文字数"
    assert read_sheet(p, "メモ")[2][1] == "ここには個人情報はありません"
    assert read_sheet(p, "その他") == [["x", "y"]]
    import openpyxl

    wb = openpyxl.load_workbook(p)
    ws = wb["顧客"]
    assert ws["A1"].font.b and ws["A1"].fill.fgColor.rgb.endswith("DDEEFF")
    assert ws.column_dimensions["D"].width == 30 and ws.row_dimensions[3].height == 30
    assert ws["A2"].number_format == "@"
    wb.close()
    # 触っていない部品はバイト単位で同じ（図形・書式・ほかのシートを壊さない）
    after = zip_parts(p)
    assert list(after) == list(before)
    changed = {n for n in before if before[n] != after[n]}
    assert changed <= {"xl/worksheets/sheet1.xml", "xl/sharedStrings.xml"}, changed


def test_xlsx_dummy_shape_and_same(xlsx_case):
    c = xlsx_case
    r = run(c["svc"], c["job"], c["path"], method="dummy", dummy_mode="shape", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    new = read_sheet(c["path"], "顧客")
    assert new[1][2] == "000-0000-0000" and "@" in new[1][3] and r["remaining"]["total"] == 0


def test_xlsx_dummy_skips_formula_cells(tmp_path):
    import openpyxl

    p = tmp_path / "src" / "f.xlsx"
    p.parent.mkdir()
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(["氏名", "メール"])
    ws.append(["山田太郎", "taro@example.com"])
    ws["C2"] = "=B2"  # 計算結果の控えは openpyxl では作れないので、数式のセルは書き換えの対象外のまま残ることだけを見る
    wb.save(p)
    svc, store, job = make_service(tmp_path, [p])
    r = run(svc, job, p, method="dummy", dummy_mode="fixed", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    assert read_sheet(p, "Sheet")[1][:3] == ["＊＊＊", "＊＊＊", "=B2"]


def test_xlsx_delete_rows(xlsx_case):
    c = xlsx_case
    p, rows = c["path"], c["rows"]
    r = run(c["svc"], c["job"], p, method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    new = read_sheet(p, "顧客")
    kept = [rows[0]] + [x for x in rows[1:] if not x[3]]
    assert [[v or "" for v in row[:4]] for row in new] == [[*k] for k in kept]
    assert r["changed"]["rows"] == len(rows) - len(kept) and r["remaining"]["total"] == 0
    assert contains_text(p, raw_needles(rows)) == []
    import openpyxl

    wb = openpyxl.load_workbook(p)
    ws = wb["顧客"]
    assert ws["A1"].font.b  # 見出しの書式
    assert ws.column_dimensions["D"].width == 30  # 列の幅
    # 行の高さは、詰めた後の行に付いてくる（元の 3 行目 = 山田…1 は 2 行目に、元の最終行は個人情報なしなので詰まる）
    assert ws.row_dimensions[len(kept)].height == 40
    assert read_sheet(p, "メモ") == [["項目", "内容"], ["日付", "2026年"], ["注意", "ここには個人情報はありません"]]
    wb.close()


def test_xlsx_delete_columns(xlsx_case):
    c = xlsx_case
    p, rows = c["path"], c["rows"]
    r = run(c["svc"], c["job"], p, method="delete_columns", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    new = read_sheet(p, "顧客")
    assert [row[0] for row in new] == [x[0] for x in rows]
    assert new[0][3] == "文字数" and new[1][3] == "=LEN(A2)"  # 右の列が詰まる（数式は元の文字のまま。参照は直さない）
    assert r["changed"]["cols"] == 3 and r["remaining"]["total"] == 0
    import openpyxl

    wb = openpyxl.load_workbook(p)
    ws = wb["顧客"]
    assert ws.column_dimensions["A"].width == 14 and ws.column_dimensions["B"].width == 10
    wb.close()


def test_xlsx_delete_sheet(xlsx_case):
    c = xlsx_case
    r = run(c["svc"], c["job"], c["path"], method="delete_sheet", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    import openpyxl

    wb = openpyxl.load_workbook(c["path"])
    assert wb.sheetnames == ["メモ", "その他"]
    wb.close()
    assert contains_text(c["path"], raw_needles(c["rows"])) == [] and r["remaining"]["total"] == 0


def test_xlsx_delete_all_sheets_is_refused_and_original_kept(tmp_path):
    import openpyxl

    p = tmp_path / "src" / "one.xlsx"
    p.parent.mkdir()
    wb = openpyxl.Workbook()
    wb.active.append(["氏名", "メール"])
    wb.active.append(["山田太郎", "taro@example.com"])
    wb.save(p)
    original = p.read_bytes()
    svc, store, job = make_service(tmp_path, [p])
    r = run(svc, job, p, method="delete_sheet", confidences=ALL_RANKS)
    assert r["state"] == "error" and "すべてのシート" in r["message"]
    assert p.read_bytes() == original
    assert not new_tmp_files(p.parent) and trash_sent_nothing(tmp_path)


def test_xlsm_is_supported(tmp_path):
    p = tmp_path / "src" / "m.xlsm"
    p.parent.mkdir()
    build_xlsx(p)
    svc, store, job = make_service(tmp_path, [p])
    a = analyze(svc, job, p)
    assert a.info["layout"] == "xlsx" and a.info["methods"]["dummy"]["available"]
    r = run(svc, job, p, method="dummy", dummy_mode="fixed", confidences=ALL_RANKS)
    assert r["state"] == "done", r


def test_old_xls_and_other_formats_only_allow_file_delete(tmp_path):
    """旧形式・書庫・対応していない形式は、ファイルの削除だけ（理由を出す）。"""
    z = tmp_path / "src" / "pack.zip"
    z.parent.mkdir()
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("inner/list.txt", "メール: zip.inner@example.com\n")
    svc, store, job = make_service(tmp_path, [z])
    a = analyze(svc, job, z)
    m = a.info["methods"]
    assert m["delete_file"]["available"]
    for k in ("delete_rows", "delete_columns", "dummy", "delete_sheet"):
        assert not m[k]["available"] and m[k]["reason"]


# ---------------------------------------------------------------- 元はごみ箱へ（写しは作らない）・失敗・立て直し


def test_original_goes_to_recycle_bin_under_pre_name(tmp_path, trash):
    rows = person_rows()
    p = tmp_path / "src" / "a.csv"
    p.parent.mkdir()
    p.write_bytes(encode_csv(rows, "cp932", "\r\n"))
    original = p.read_bytes()
    svc, store, job = make_service(tmp_path, [p])
    r = run(svc, job, p, method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    assert p.read_bytes() != original
    # 元は、同じフォルダの中で「元の名前（対処前 日時）」に改名してから、ごみ箱へ送られた（中身はバイト単位で元のまま）
    sent = Path(trash.sent[0])
    assert sent.parent == p.parent and re.fullmatch(r"a（対処前 \d{8}-\d{6}）\.csv", sent.name)
    assert [f.read_bytes() for f in trash.files()] == [original]
    assert r["disposal"] == "recycle_bin" and r["pre_name"] == sent.name
    assert r["changed"]["pre_name"] == sent.name and "backup_path" not in r
    rec = store.remediation(job, r["remediation_id"])
    import hashlib

    assert rec["state"] == "applied" and rec["backup_path"] is None
    assert rec["orig_sha256"] == hashlib.sha256(original).hexdigest()
    assert rec["new_sha256"] == hashlib.sha256(p.read_bytes()).hexdigest()
    assert rec["plan"]["mode"] == "recycle" and rec["plan"]["pre_path"] == str(sent)
    assert not new_tmp_files(p.parent) and not list(p.parent.glob("*対処前*"))  # 一時の新ファイル・改名した元は残らない
    assert not (tmp_path / "backup").exists()  # 元の写しのフォルダは作られない
    assert not hasattr(svc, "undo")  # 元の写しから戻す「元に戻す」は無い


def test_preview_splits_warnings_and_notes(tmp_path, trash, monkeypatch):
    """下見の注意は2種類に分ける。warnings＝消える・戻せない・壊れうるもの、notes＝仕組み・保たれるもの。"""
    p = tmp_path / "src" / "a.csv"
    p.parent.mkdir()
    p.write_bytes(encode_csv(person_rows(), "utf-8", "\n"))
    svc, store, job = make_service(tmp_path, [p])
    analyze(svc, job, p)
    pv = svc.preview(job, str(p), {"method": "delete_rows", "confidences": ALL_RANKS})
    # ごみ箱へ送る・文字コードを保つ、は仕組み（notes）。赤く出す注意には入らない
    assert any("ごみ箱へ送ります" in n for n in pv["notes"])
    assert any("文字コード" in n for n in pv["notes"])
    assert not any("文字コード" in w or "ごみ箱へ送ります" in w for w in pv["warnings"])
    # ごみ箱の無い場所では、元が残らないことが warnings の先頭に出る
    monkeypatch.setattr(remediate, "has_recycle_bin", lambda path: False)
    analyze(svc, job, p)
    pv = svc.preview(job, str(p), {"method": "delete_rows", "confidences": ALL_RANKS})
    assert "元のファイルは残りません" in pv["warnings"][0] and not any("ごみ箱へ送ります" in n for n in pv["notes"])


def test_without_recycle_bin_content_is_replaced_in_one_step(tmp_path, trash, monkeypatch):
    """ごみ箱の無い場所: os.replace で入れ替える（元は残らない）。下見にそう出る。"""
    rows = person_rows()
    p = tmp_path / "src" / "a.csv"
    p.parent.mkdir()
    p.write_bytes(encode_csv(rows, "utf-8", "\n"))
    svc, store, job = make_service(tmp_path, [p])
    monkeypatch.setattr(remediate, "has_recycle_bin", lambda path: False)
    analyze(svc, job, p)
    pv = svc.preview(job, str(p), {"method": "delete_rows", "confidences": ALL_RANKS})
    assert pv["disposal"] == "replaced"
    assert "元のファイルは残りません（この場所にはごみ箱がありません）" in pv["warnings"][0]
    calls: list[tuple[str, str]] = []
    real_replace = remediate.replace_with_retry
    monkeypatch.setattr(
        remediate, "replace_with_retry", lambda s, d, tries=5: (calls.append((s, d)), real_replace(s, d))[1]
    )
    monkeypatch.setattr(remediate, "_fs_rename", lambda s, d: pytest.fail("ごみ箱の無い場所では改名の段を使わない"))
    started = svc.start_run(
        job, str(p), {"method": "delete_rows", "confidences": ALL_RANKS}, True, pv["expected_sha256"]
    )
    svc._runs[started["run_id"]].thread.join(180)
    r = svc.run_status(job, started["run_id"])
    assert r["state"] == "done", r
    kept = [rows[0]] + [x for x in rows[1:] if not x[3]]
    assert p.read_bytes() == encode_csv(kept, "utf-8", "\n")
    assert len(calls) == 1 and calls[0][1] == str(p) and Path(calls[0][0]).name.startswith(remediate.NEW_PREFIX)
    assert trash.sent == [] and trash.files() == []  # ごみ箱へは送らない（元は残らない）
    assert r["disposal"] == "replaced" and r["pre_name"] is None
    rec = store.remediation(job, r["remediation_id"])
    assert rec["state"] == "applied" and rec["plan"]["mode"] == "replace" and rec["changed"]["disposal"] == "replaced"
    assert not new_tmp_files(p.parent) and not list(p.parent.glob("*対処前*"))


def test_failure_while_writing_keeps_original(tmp_path, monkeypatch, trash):
    rows = person_rows()
    p = tmp_path / "src" / "a.csv"
    p.parent.mkdir()
    p.write_bytes(encode_csv(rows, "utf-8", "\n"))
    original = p.read_bytes()
    svc, store, job = make_service(tmp_path, [p])

    def broken(src, dst, *a, **k):
        Path(dst).write_bytes(b"half written")  # 書きかけで落ちる
        raise OSError("disk full (simulated)")

    monkeypatch.setattr(remediate, "rewrite_text_file", broken)
    r = run(svc, job, p, method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "error"
    assert p.read_bytes() == original
    assert not new_tmp_files(p.parent)  # 一時の新ファイルは片付く
    assert trash.sent == [] and store.remediations(job) == []  # 元に触らない・記録も残さない


def test_unreadable_new_file_is_not_put_in_place(tmp_path, monkeypatch, trash):
    """新しいファイルを検査し直せない（開けない）ときは、元に触らず、一時の新ファイルを消して終わる。"""
    p = tmp_path / "src" / "a.csv"
    p.parent.mkdir()
    p.write_bytes(encode_csv(person_rows(), "utf-8", "\n"))
    original = p.read_bytes()
    svc, store, job = make_service(tmp_path, [p])

    def boom(*a, **k):
        raise RuntimeError("cannot scan (simulated)")

    monkeypatch.setattr(remediate, "rescan_summary", boom)
    r = run(svc, job, p, method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "error" and "検査し直せませんでした" in r["message"]
    assert p.read_bytes() == original and not new_tmp_files(p.parent) and trash.sent == []
    assert store.remediations(job) == []


def test_failure_when_original_cannot_be_renamed_keeps_original(tmp_path, monkeypatch, trash):
    """他のプログラムが開いていて名前を変えられない。元はそのまま・一時の新ファイルは消える・記録は残らない。"""
    p = tmp_path / "src" / "a.csv"
    p.parent.mkdir()
    p.write_bytes(encode_csv(person_rows(), "utf-8", "\n"))
    original = p.read_bytes()
    svc, store, job = make_service(tmp_path, [p])

    def locked(src, dst):
        raise PermissionError("in use (simulated)")

    monkeypatch.setattr(remediate, "_fs_rename", locked)
    monkeypatch.setattr(remediate.time, "sleep", lambda s: None)
    r = run(svc, job, p, method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "error" and "名前を変えられませんでした" in r["message"]
    assert p.read_bytes() == original and not new_tmp_files(p.parent) and trash.sent == []
    assert store.remediations(job) == []


def test_failure_at_replace_keeps_original(tmp_path, monkeypatch, trash):
    p = tmp_path / "src" / "a.csv"
    p.parent.mkdir()
    p.write_bytes(encode_csv(person_rows(), "utf-8", "\n"))
    original = p.read_bytes()
    svc, store, job = make_service(tmp_path, [p])
    monkeypatch.setattr(remediate, "has_recycle_bin", lambda path: False)

    def deny(src, dst, tries=5):
        raise RemedyError("置き換えられませんでした（試験）")

    monkeypatch.setattr(remediate, "replace_with_retry", deny)
    r = run(svc, job, p, method="dummy", dummy_mode="fixed", confidences=ALL_RANKS)
    assert r["state"] == "error" and "置き換え" in r["message"]
    assert p.read_bytes() == original and not new_tmp_files(p.parent) and store.remediations(job) == []


def test_failure_sending_to_recycle_bin_restores_original(tmp_path, monkeypatch, trash):
    """ごみ箱へ送れなかった: 新しいファイルを置いたあとでも、元の状態（元の中身が元の名前）へ戻す。"""
    p = tmp_path / "src" / "a.csv"
    p.parent.mkdir()
    p.write_bytes(encode_csv(person_rows(), "utf-8", "\n"))
    original = p.read_bytes()
    svc, store, job = make_service(tmp_path, [p])

    def fail(path):
        raise RemedyError("ごみ箱へ送れませんでした（試験）")

    monkeypatch.setattr(remediate, "send_to_recycle_bin", fail)
    r = run(svc, job, p, method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "error" and "元の状態に戻しました" in r["message"]
    assert p.read_bytes() == original  # 元の中身が元の名前で残る
    assert not new_tmp_files(p.parent) and not list(p.parent.glob("*対処前*")) and store.remediations(job) == []


def test_changed_while_working_is_refused_before_touching(tmp_path, trash):
    p = tmp_path / "src" / "a.csv"
    p.parent.mkdir()
    p.write_bytes(encode_csv(person_rows(), "utf-8", "\n"))
    svc, store, job = make_service(tmp_path, [p])
    analyze(svc, job, p)
    pv = svc.preview(job, str(p), {"method": "delete_rows", "confidences": ALL_RANKS})
    rid, run_state, ctx = svc._begin_run(
        job, str(p), {"method": "delete_rows", "confidences": ALL_RANKS}, True, pv["expected_sha256"]
    )
    # 準備（一時の新ファイルを作る）のあと、確定の前に、人が元のファイルを編集した
    run_state_args = ctx
    got = inline_runner("apply", ctx[2], 10)
    p.write_bytes(p.read_bytes() + "追記,でした\n".encode("utf-8"))
    edited = p.read_bytes()
    commit = ctx[5]
    with pytest.raises(RemedyError, match="変わりました"):
        remediate.commit_rewrite(store, ctx[6], str(p), commit, got["orig_sha256"])
    assert p.read_bytes() == edited and not new_tmp_files(p.parent) and trash.sent == []
    assert store.remediations(job) == [] and run_state_args


# ---------------------------------------------------------------- 途中で落ちた状態からの立て直し


class SimulatedCrash(BaseException):
    """プロセスの強制終了・電源断の代わり。Exception ではないので、確定の処理は元へ戻さず、落ちた状態をそのまま残す。"""


def crash_after(monkeypatch, target, name: str, nth: int = 1, before: bool = False):
    """target.name を nth 回目に呼んだ直後（before=True なら直前）に SimulatedCrash を起こす。"""
    real = getattr(target, name)
    count = {"n": 0}

    def wrapper(*a, **k):
        count["n"] += 1
        hit = count["n"] == nth
        if hit and before:
            raise SimulatedCrash(name)
        out = real(*a, **k)
        if hit:
            raise SimulatedCrash(name)
        return out

    monkeypatch.setattr(target, name, wrapper)


def run_until_crash(svc, job, p, params):
    """_begin_run と _apply を同じスレッドで走らせる（SimulatedCrash をそのまま受け取るため）。"""
    analyze(svc, job, p)
    pv = svc.preview(job, str(p), params)
    rid, run_state, ctx = svc._begin_run(job, str(p), params, True, pv["expected_sha256"])
    svc._apply(*ctx)
    return rid, run_state


def _crash_stages():
    """確定の各段（改名・改名・ごみ箱）の直後と、記録の状態を進めた直後。"""
    return [
        ("a1-元を改名した直後（記録はまだ始めたのまま）", "rename", 1),
        ("a2-元の改名を記録した直後", "state", 2),
        ("b1-新を元の名前へ改名した直後（記録は改名済みのまま）", "rename", 2),
        ("b2-新の改名を記録した直後", "state", 3),
        ("c1-ごみ箱へ送った直後（記録は置いた済みのまま）", "trash", 1),
        ("c2-ごみ箱へ送って記録を済みにした直後", "state", 4),
    ]


@pytest.mark.parametrize("stage", _crash_stages(), ids=lambda s: s[0])
def test_crash_in_each_commit_stage_is_recovered(tmp_path, monkeypatch, trash, stage):
    """確定の各段の直後に落ちた状態を作り、立て直しのあとに、元か新の中身が元の名前（か対処前の名前）で、バイト単位で残る。"""
    _, kind, nth = stage
    rows = person_rows()
    p = tmp_path / "src" / "a.csv"
    p.parent.mkdir()
    p.write_bytes(encode_csv(rows, "utf-8", "\n"))
    original = p.read_bytes()
    kept = encode_csv([rows[0]] + [x for x in rows[1:] if not x[3]], "utf-8", "\n")
    svc, store, job = make_service(tmp_path, [p])
    if kind == "rename":
        crash_after(monkeypatch, remediate, "_fs_rename", nth)
    elif kind == "state":
        crash_after(
            monkeypatch, store, "update_remediation", nth
        )  # 1=準備後の結果の記録, 2=改名済み, 3=置いた済み, 4=済み
    else:

        def trash_then_crash(path):
            trash(path)  # ごみ箱へ送り終えた直後に落ちる
            raise SimulatedCrash("trash")

        monkeypatch.setattr(remediate, "send_to_recycle_bin", trash_then_crash)
    with pytest.raises(SimulatedCrash):
        run_until_crash(svc, job, p, {"method": "delete_rows", "confidences": ALL_RANKS})
    # 落ちた状態（記録は途中のまま）。どの状態でも、中身が失われていない
    states_before = [x["state"] for x in store.unfinished_remediations()]
    assert len(states_before) <= 1 and set(states_before) <= {"started", "renamed", "swapped"}
    present = {f.name: f.read_bytes() for f in p.parent.iterdir() if f.is_file()}
    present.update({f"trash:{f.name}": f.read_bytes() for f in trash.files()})
    assert original in present.values() or kept in present.values()
    monkeypatch.undo()
    monkeypatch.setattr(remediate, "send_to_recycle_bin", trash)
    monkeypatch.setattr(remediate, "has_recycle_bin", lambda path: True)
    # 立て直し（アプリの起動時・同じファイルの対処を始める前に走る）
    svc2 = RemedyService(store, runner_fn=inline_runner)
    done = svc2.recover()
    assert store.unfinished_remediations() == []
    final = p.read_bytes()
    assert final in (original, kept)  # 元か新のどちらかが、元の名前で残る
    assert not new_tmp_files(p.parent) and not list(p.parent.glob("*対処前*"))  # 一時の新ファイル・改名した元は残らない
    # ファイルが1つも失われていない: 元の中身はどこかに（元の名前か、ごみ箱に）ある。新の中身を置いたなら新も
    everywhere = [final] + [f.read_bytes() for f in trash.files()]
    assert original in everywhere
    recs = store.remediations(job)
    assert len(recs) == 1 and recs[0]["state"] in ("applied", "recovered")
    assert recs[0]["plan"].get("recovery") or not done
    # 落ちたあとの立て直しは、2回目は何もしない
    assert svc2.recover() == []


def test_crash_after_new_file_written_leaves_original_and_recovery_removes_tmp(tmp_path, monkeypatch, trash):
    """1・2 の段（新ファイルを書き、検査し直した）の直後に落ちた: 元は無傷。記録（始めた）から一時の新ファイルを片付ける。"""
    p = tmp_path / "src" / "a.csv"
    p.parent.mkdir()
    p.write_bytes(encode_csv(person_rows(), "utf-8", "\n"))
    original = p.read_bytes()
    svc, store, job = make_service(tmp_path, [p])
    crash_after(monkeypatch, store, "update_remediation", 1)  # 新ファイルを書き・検査し直し終えた直後（記録の更新の前）
    with pytest.raises(SimulatedCrash):
        run_until_crash(svc, job, p, {"method": "delete_rows", "confidences": ALL_RANKS})
    assert p.read_bytes() == original and len(new_tmp_files(p.parent)) == 1  # 一時の新ファイルが残っている
    assert [x["state"] for x in store.unfinished_remediations()] == ["started"]
    monkeypatch.undo()
    monkeypatch.setattr(remediate, "send_to_recycle_bin", trash)
    monkeypatch.setattr(remediate, "has_recycle_bin", lambda path: True)
    done = RemedyService(store, runner_fn=inline_runner).recover()
    assert p.read_bytes() == original and not new_tmp_files(p.parent) and trash.sent == []
    assert done[0]["state"] == "recovered" and "変える前" in done[0]["message"]


def test_crash_after_replace_without_recycle_bin(tmp_path, monkeypatch, trash):
    """ごみ箱の無い場所で、os.replace の直後に落ちた（記録は始めたのまま）: 新が入っている。記録を済みにして終える。"""
    rows = person_rows()
    p = tmp_path / "src" / "a.csv"
    p.parent.mkdir()
    p.write_bytes(encode_csv(rows, "utf-8", "\n"))
    kept = encode_csv([rows[0]] + [x for x in rows[1:] if not x[3]], "utf-8", "\n")
    svc, store, job = make_service(tmp_path, [p])
    monkeypatch.setattr(remediate, "has_recycle_bin", lambda path: False)
    crash_after(monkeypatch, remediate, "replace_with_retry", 1)
    with pytest.raises(SimulatedCrash):
        run_until_crash(svc, job, p, {"method": "delete_rows", "confidences": ALL_RANKS})
    assert p.read_bytes() == kept and not new_tmp_files(p.parent)
    monkeypatch.undo()
    monkeypatch.setattr(remediate, "send_to_recycle_bin", trash)
    monkeypatch.setattr(remediate, "has_recycle_bin", lambda path: False)
    done = RemedyService(store, runner_fn=inline_runner).recover()
    assert done[0]["state"] == "applied" and p.read_bytes() == kept


def test_recovery_restores_when_original_name_is_missing(tmp_path, trash):
    """記録が途中のまま・元の名前のファイルが無く「対処前」の名前がある → 元の名前へ戻す。一時の新ファイルは消す。"""
    p = tmp_path / "src" / "a.csv"
    p.parent.mkdir()
    original = encode_csv(person_rows(), "utf-8", "\n")
    pre = p.parent / "a（対処前 20261020-101010）.csv"
    pre.write_bytes(original)
    tmp_new = p.parent / (remediate.NEW_PREFIX + "abcdefgh-a.csv")
    tmp_new.write_bytes(b"new")
    store = Store(str(tmp_path / "jobs.sqlite3"))
    job = store.create_job([str(p.parent)], ScanOptions())
    plan = {"mode": "recycle", "tmp_new": str(tmp_new), "dest": str(p), "pre_path": str(pre)}
    store.add_remediation(job, str(p), "delete_rows", {}, {}, state="renamed", note=json.dumps(plan))
    done = RemedyService(store, runner_fn=inline_runner).recover()
    assert p.read_bytes() == original and not pre.exists() and not tmp_new.exists()
    assert done[0]["state"] == "recovered" and "元の名前に戻しました" in done[0]["message"]
    rec = store.remediations(job)[0]
    assert rec["state"] == "recovered" and "戻しました" in rec["plan"]["recovery"]  # 画面の対処の記録に出る


def test_recovery_keeps_both_files_when_unsure_and_never_deletes_unknown(tmp_path, trash):
    """元の名前のファイルと「対処前」の名前の両方があり、元の名前の中身が新と一致しない → どちらも消さない。"""
    p = tmp_path / "src" / "a.csv"
    p.parent.mkdir()
    p.write_bytes(b"current content")
    pre = p.parent / "a（対処前 20261020-101010）.csv"
    pre.write_bytes(b"older content")
    store = Store(str(tmp_path / "jobs.sqlite3"))
    job = store.create_job([str(p.parent)], ScanOptions())
    plan = {
        "mode": "recycle",
        "tmp_new": str(p.parent / "~piichk-new-zzzzzzzz-a.csv"),
        "dest": str(p),
        "pre_path": str(pre),
    }
    store.add_remediation(
        job, str(p), "delete_rows", {}, {}, state="swapped", new_sha256="0" * 64, note=json.dumps(plan)
    )
    done = RemedyService(store, runner_fn=inline_runner).recover()
    assert p.read_bytes() == b"current content" and pre.read_bytes() == b"older content" and trash.sent == []
    assert done[0]["state"] == "recovered" and "両方が残っています" in done[0]["message"]


def test_recovery_runs_at_app_start(tmp_path, trash):
    from pii_checker.web.server import create_app

    p = tmp_path / "src" / "a.csv"
    p.parent.mkdir()
    original = encode_csv(person_rows(), "utf-8", "\n")
    pre = p.parent / "a（対処前 20261020-101010）.csv"
    pre.write_bytes(original)  # 改名のあとで落ちた（元の名前が無い）
    db = tmp_path / "jobs.sqlite3"
    store = Store(str(db))
    job = store.create_job([str(p.parent)], ScanOptions())
    plan = {
        "mode": "recycle",
        "tmp_new": str(p.parent / "~piichk-new-zzzzzzzz-a.csv"),
        "dest": str(p),
        "pre_path": str(pre),
    }
    store.add_remediation(job, str(p), "delete_rows", {}, {}, state="renamed", note=json.dumps(plan))
    app = create_app(db=str(db), token=TOKEN, remedy_runner=inline_runner)  # アプリの起動で立て直す
    assert p.read_bytes() == original and not pre.exists()
    assert app.state.remedy_recovered and app.state.remedy_recovered[0]["state"] == "recovered"
    rows = app.state.store.remediations(job)
    assert rows[0]["state"] == "recovered" and "戻しました" in rows[0]["plan"]["recovery"]


def test_recovery_runs_before_the_same_file_is_processed_again(tmp_path, trash):
    p = tmp_path / "src" / "a.csv"
    p.parent.mkdir()
    rows = person_rows()
    p.write_bytes(encode_csv(rows, "utf-8", "\n"))
    svc, store, job = make_service(tmp_path, [p])
    # 前に落ちて、一時の新ファイルと「始めた」の記録が残っている
    leftover = p.parent / (remediate.NEW_PREFIX + "qqqqqqqq-a.csv")
    leftover.write_bytes(b"half")
    plan = {
        "mode": "recycle",
        "tmp_new": str(leftover),
        "dest": str(p),
        "pre_path": str(p.parent / "a（対処前 20261020-101010）.csv"),
    }
    old = store.add_remediation(job, str(p), "delete_rows", {}, {}, state="started", note=json.dumps(plan))
    r = run(svc, job, p, method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    assert not leftover.exists()  # 実行を始める前に立て直した
    recs = {x["id"]: x for x in store.remediations(job)}
    assert recs[old]["state"] == "recovered" and recs[r["remediation_id"]]["state"] == "applied"


def test_changed_since_preview_is_refused(tmp_path):
    rows = person_rows()
    p = tmp_path / "src" / "a.csv"
    p.parent.mkdir()
    p.write_bytes(encode_csv(rows, "utf-8", "\n"))
    svc, store, job = make_service(tmp_path, [p])
    a = analyze(svc, job, p)
    pv = svc.preview(job, str(p), {"method": "delete_rows", "confidences": ALL_RANKS})
    p.write_bytes(encode_csv(rows[:5], "utf-8", "\n"))  # 下見のあとにファイルが変わった
    changed = p.read_bytes()
    started = svc.start_run(
        job, str(p), {"method": "delete_rows", "confidences": ALL_RANKS}, True, pv["expected_sha256"]
    )
    svc._runs[started["run_id"]].thread.join(120)
    r = svc.run_status(job, started["run_id"])
    assert r["state"] == "error" and "変わりました" in r["message"]
    assert p.read_bytes() == changed and a.state == "done"


def test_run_requires_confirmation(tmp_path):
    p = tmp_path / "src" / "a.csv"
    p.parent.mkdir()
    p.write_bytes(encode_csv(person_rows(), "utf-8", "\n"))
    original = p.read_bytes()
    svc, store, job = make_service(tmp_path, [p])
    analyze(svc, job, p)
    for bad in (False, None, "yes", 1):
        with pytest.raises(RemedyError, match="確認"):
            svc.start_run(job, str(p), {"method": "delete_rows"}, bad, None)
    assert p.read_bytes() == original


def test_scan_alone_never_writes(tmp_path):
    """検査（scan）と分析（位置を集める）は、元のファイルも隣にも何も書かない。"""
    p = tmp_path / "src" / "a.csv"
    p.parent.mkdir()
    p.write_bytes(encode_csv(person_rows(), "utf-8", "\n"))
    snapshot = {x.name: x.read_bytes() for x in p.parent.iterdir()}
    mtime = p.stat().st_mtime_ns
    svc, store, job = make_service(tmp_path, [p])
    analyze(svc, job, p)
    svc.preview(job, str(p), {"method": "delete_rows"})
    assert {x.name: x.read_bytes() for x in p.parent.iterdir()} == snapshot and p.stat().st_mtime_ns == mtime
    assert not (tmp_path / "backup").exists()


# ---------------------------------------------------------------- ごみ箱（差し替えて確かめる）


def test_delete_file_sends_to_recycle_without_backup(tmp_path, trash):
    """ごみ箱のある場所: ごみ箱へ送る。元の写しは作らない（個人情報のファイルを手元のディスクへ写さない）。"""
    p = tmp_path / "src" / "a.csv"
    p.parent.mkdir()
    original = encode_csv(person_rows(), "utf-8", "\n")
    p.write_bytes(original)
    svc, store, job = make_service(tmp_path, [p])
    analyze(svc, job, p)
    pv = svc.preview(job, str(p), {"method": "delete_file"})
    assert pv["summary"] == "ファイル「a.csv」をごみ箱へ送ります（ごみ箱から戻せます）"
    assert pv["disposal"] == "recycle_bin" and pv["warnings"] + pv["notes"] == []
    started = svc.start_run(job, str(p), {"method": "delete_file"}, True, None)
    svc._runs[started["run_id"]].thread.join(180)
    r = svc.run_status(job, started["run_id"])
    assert r["state"] == "done", r
    assert trash.sent == [str(p)] and not p.exists()
    assert [f.read_bytes() for f in trash.files()] == [
        original
    ]  # ごみ箱の中にある（このテストではごみ箱の代わりのフォルダ）
    assert not (tmp_path / "backup").exists() and "backup_path" not in r  # 元の写しは作らない
    assert r["disposal"] == "recycle_bin" and r["changed"] == {"files": 1, "disposal": "recycle_bin"}
    rec = store.remediation(job, r["remediation_id"])
    assert rec["backup_path"] is None and rec["changed"]["disposal"] == "recycle_bin" and rec["state"] == "applied"


def test_delete_file_without_recycle_bin_deletes_permanently(tmp_path, monkeypatch, trash):
    """ごみ箱の無い場所（ネットワーク・外付けなど）: ごみ箱を経由せずに消す。下見・結果・記録で「完全に削除」と分かる。"""
    p = tmp_path / "src" / "a.csv"
    p.parent.mkdir()
    p.write_bytes(encode_csv(person_rows(), "utf-8", "\n"))
    svc, store, job = make_service(tmp_path, [p])
    monkeypatch.setattr(remediate, "has_recycle_bin", lambda path: False)
    analyze(svc, job, p)
    pv = svc.preview(job, str(p), {"method": "delete_file"})
    line = "ファイル「a.csv」を完全に削除します（この場所にはごみ箱がありません。元に戻せません）"
    assert pv["summary"] == line and pv["disposal"] == "permanent"
    assert any(line in w for w in pv["warnings"] + pv["notes"])
    started = svc.start_run(job, str(p), {"method": "delete_file"}, True, None)
    svc._runs[started["run_id"]].thread.join(180)
    r = svc.run_status(job, started["run_id"])
    assert r["state"] == "done", r
    assert not p.exists() and trash.sent == [] and trash.files() == []  # ごみ箱にも写しにも何も残らない
    assert not (tmp_path / "backup").exists() and r["disposal"] == "permanent"
    rec = store.remediation(job, r["remediation_id"])
    assert rec["changed"] == {"files": 1, "disposal": "permanent"} and rec["backup_path"] is None


def test_delete_file_failure_keeps_file_and_makes_no_backup(tmp_path, monkeypatch, trash):
    p = tmp_path / "src" / "a.csv"
    p.parent.mkdir()
    p.write_bytes(encode_csv(person_rows(), "utf-8", "\n"))
    original = p.read_bytes()
    svc, store, job = make_service(tmp_path, [p])

    def fail(path):
        raise RemedyError("ごみ箱へ送れませんでした（試験）")

    monkeypatch.setattr(remediate, "send_to_recycle_bin", fail)
    r = run(svc, job, p, method="delete_file")
    assert r["state"] == "error" and p.read_bytes() == original
    assert not (tmp_path / "backup").exists() and store.remediations(job) == []
    # ごみ箱の無い場所で、削除そのものが失敗したとき（他のプログラムが開いている等）も、ファイルは残る
    monkeypatch.setattr(remediate, "has_recycle_bin", lambda path: False)

    def locked(path):
        raise PermissionError("in use (simulated)")

    monkeypatch.setattr(os, "remove", locked)
    r = run(svc, job, p, method="delete_file")
    monkeypatch.undo()
    assert r["state"] == "error" and "削除できませんでした" in r["message"] and p.read_bytes() == original
    assert store.remediations(job) == []


def test_recycle_function_refuses_very_long_path(tmp_path):
    with pytest.raises(RemedyError, match="長すぎ"):
        REAL_SEND_TO_RECYCLE_BIN(str(tmp_path / ("x" * 300) / "a.txt"))  # 本物の関数（長すぎるパスは触る前に断る）


# ---------------------------------------------------------------- できないもの


def test_unavailable_files_give_reasons(tmp_path):
    folder = tmp_path / "src"
    folder.mkdir()
    ro = folder / "ro.csv"
    ro.write_bytes(encode_csv(person_rows(), "utf-8", "\n"))
    os.chmod(ro, 0o444)  # Windows では読み取り専用の属性になる
    store = Store(str(tmp_path / "jobs.sqlite3"))
    job = store.create_job([str(folder)], ScanOptions())
    ftp = "ftp://u@192.0.2.1:21/a.csv"
    inner = str(folder / "pack.zip") + "!inner.csv"
    store.add_files(job, [(str(ro), 10, 1.0), (ftp, 10, 1.0), (inner, 10, 1.0)])
    with store.tx() as c:
        c.execute("UPDATE files SET state='done' WHERE job_id=?", (job,))
    svc = RemedyService(store, runner_fn=inline_runner)
    r = svc.request_analysis(job, str(ro))
    assert r["state"] == "error" and "読み取り専用" in r["message"]
    r = svc.request_analysis(job, ftp)
    assert r["state"] == "error" and "FTP" in r["message"]
    r = svc.request_analysis(job, inner)  # 書庫の中のファイルは、実在する場所ではない（ファイルの削除もできない）
    assert r["state"] == "error"
    r = svc.request_analysis(job, str(folder / "not-in-job.csv"))
    assert r["state"] == "error" and "見つかりません" in r["message"]
    os.chmod(ro, 0o666)


# ---------------------------------------------------------------- 記録に生の値を入れない


def _leak(paths: list[str], needles: list[str]) -> list[str]:
    found = []
    for path in paths:
        data = Path(path).read_bytes()
        for n in needles:
            for enc in ("utf-8", "utf-16-le", "cp932"):
                if n.encode(enc) in data:
                    found.append(n)
    return found


def test_records_and_job_db_have_no_raw_values(tmp_path, trash):
    import glob

    rows = person_rows()
    p = tmp_path / "src" / "a.csv"
    p.parent.mkdir()
    p.write_bytes(encode_csv(rows, "utf-8", "\n"))
    svc, store, job = make_service(tmp_path, [p])
    # 実際のジョブの検査（DB に伏せた値の明細が入る）も同じ DB に走らせておく
    from pii_checker.runner import JobRunner

    full = store.create_job([str(p.parent)], ScanOptions(temp_dir=str(tmp_path / "scantmp")))
    runner = JobRunner(store, full, workers=1)
    runner.start()
    runner.wait(300)
    needles = raw_needles(rows)
    r = run(svc, job, p, method="dummy", dummy_mode="same", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    db_files = glob.glob(str(tmp_path / "jobs.sqlite3*"))
    assert db_files and _leak(db_files, needles) == []
    for table in ("jobs", "files", "items", "findings", "remediations"):
        for row in store.query(f"SELECT * FROM {table}"):
            for v in tuple(row):
                if isinstance(v, str):
                    assert not any(n in v for n in needles), (table, v[:80])
    rec = store.remediations(job)[0]
    assert rec["method"] == "dummy" and rec["filters"]["dummy_mode"] == "same" and rec["backup_path"] is None
    assert not (tmp_path / "backup").exists()  # 元の写しのフォルダは作られない
    # 陽性対照: 生の値を入れた DB なら、この探し方で見つかる
    import sqlite3

    q = tmp_path / "control.sqlite3"
    con = sqlite3.connect(q)
    con.execute("CREATE TABLE t(a TEXT)")
    con.execute("INSERT INTO t VALUES (?)", (f"x {needles[0]} y",))
    con.commit()
    con.close()
    assert _leak([str(q)], needles) == [needles[0]]
    # ダミー化のあとのファイル（書き換えた結果）に元の値は無い。元の値があるのは、ごみ箱へ送った元のファイルだけ
    assert _leak([str(p)], needles) == []
    assert _leak([str(f) for f in trash.files()], needles)


# ---------------------------------------------------------------- API


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def api(tmp_path):
    import uvicorn

    from pii_checker.web.server import create_app

    rows = person_rows()
    p = tmp_path / "src" / "a.csv"
    p.parent.mkdir()
    p.write_bytes(encode_csv(rows, "utf-8", "\n"))
    store = Store(str(tmp_path / "jobs.sqlite3"))
    job = store.create_job([str(p.parent)], ScanOptions(temp_dir=str(tmp_path / "scantmp")))
    (tmp_path / "scantmp").mkdir()
    store.add_files(job, [(str(p), p.stat().st_size, p.stat().st_mtime)])
    with store.tx() as c:
        c.execute("UPDATE files SET state='done' WHERE job_id=?", (job,))
    app = create_app(
        db=str(tmp_path / "jobs.sqlite3"),
        token=TOKEN,
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
    yield {"base": f"http://127.0.0.1:{port}", "job": job, "path": p, "rows": rows}
    srv.should_exit = True
    th.join(timeout=10)


def call(base, path, method="GET", body=None, token=TOKEN, xrw=True):
    headers = {}
    if token:
        headers["X-Token"] = token
    if method != "GET" and xrw:
        headers["X-Requested-With"] = "pii-checker"
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(
        base + path, data=json.dumps(body).encode() if body is not None else None, method=method, headers=headers
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, raw


def test_api_requires_token_and_header(api):
    base, job, top = api["base"], api["job"], str(api["path"])
    original = api["path"].read_bytes()
    for path, body in (
        (f"/api/jobs/{job}/remedy/analyze", {"top_path": top}),
        (f"/api/jobs/{job}/remedy/preview", {"top_path": top, "method": "delete_rows"}),
        (f"/api/jobs/{job}/remedy/run", {"top_path": top, "method": "delete_rows", "confirmed": True}),
    ):
        assert call(base, path, "POST", body, token=None)[0] == 401
        assert call(base, path, "POST", body, token="wrong")[0] == 401
        assert call(base, path, "POST", body, xrw=False)[0] == 403  # 書き込み系の独自ヘッダーも要る
    assert call(base, f"/api/jobs/{job}/remediations", token=None)[0] == 401
    assert call(base, f"/api/jobs/{job}/remedy/runs/x", token=None)[0] == 401
    assert api["path"].read_bytes() == original  # 断られたものは何も変えていない


def test_api_end_to_end(api, trash):
    base, job, p = api["base"], api["job"], api["path"]
    top = str(p)
    original = p.read_bytes()
    # 分析（すぐ終わる試験用の runner。本番は別プロセス）
    for _ in range(300):
        st, a = call(base, f"/api/jobs/{job}/remedy/analyze", "POST", {"top_path": top})
        assert st == 200, a
        if a["state"] != "running":
            break
        time.sleep(0.1)
    assert a["state"] == "done" and a["methods"]["delete_rows"]["available"], a
    assert not a["methods"]["delete_sheet"]["available"]
    assert a["counts"]["email"]["2"] == len([r for r in api["rows"][1:] if r[3]])
    # 下見は何も書き換えない
    st, pv = call(base, f"/api/jobs/{job}/remedy/preview", "POST", {"top_path": top, "method": "delete_rows"})
    assert st == 200 and pv["changes"]["rows"] == len([r for r in api["rows"][1:] if r[3]]) and pv["can_run"]
    assert pv["file_name"] == "a.csv" and pv["sample_rows"]
    assert p.read_bytes() == original
    # 選べない方法は理由つきで断る
    st, err = call(base, f"/api/jobs/{job}/remedy/preview", "POST", {"top_path": top, "method": "delete_sheet"})
    assert st == 400 and err["detail"]
    # 確認の操作なしの実行は断る
    st, err = call(base, f"/api/jobs/{job}/remedy/run", "POST", {"top_path": top, "method": "delete_rows"})
    assert st == 400 and "確認" in err["detail"] and p.read_bytes() == original
    # 実行
    body = {"top_path": top, "method": "delete_rows", "confirmed": True, "expected_sha256": pv["expected_sha256"]}
    st, started = call(base, f"/api/jobs/{job}/remedy/run", "POST", body)
    assert st == 200, started
    for _ in range(300):
        st, status = call(base, f"/api/jobs/{job}/remedy/runs/{started['run_id']}")
        if status["state"] != "running":
            break
        time.sleep(0.1)
    assert status["state"] == "done", status
    assert status["remaining"]["total"] > 0 or status["remaining"]["total"] == 0
    assert p.read_bytes() != original
    st, lst = call(base, f"/api/jobs/{job}/remediations")
    assert st == 200 and len(lst["rows"]) == 1
    row = lst["rows"][0]
    assert row["state"] == "applied" and row["method"] == "delete_rows" and row["file_name"] == "a.csv"
    assert not any(n in json.dumps(lst, ensure_ascii=False) for n in raw_needles(api["rows"]))
    # 元はごみ箱へ（元の写しは作らない）。「元に戻す」の API は無い
    assert row["disposal"] == "recycle_bin" and row["pre_name"].startswith("a（対処前 ") and row["recovery"] == ""
    assert status["disposal"] == "recycle_bin" and "backup_path" not in status
    assert [f.read_bytes() for f in trash.files()] == [original]
    assert "backup_root" not in lst and lst["recovered_at_start"] == []
    st, _ = call(base, f"/api/jobs/{job}/remediations/{row['id']}/undo", "POST", {})
    assert st in (404, 405)
    st, _ = call(base, "/api/jobs/no-such/remedy/analyze", "POST", {"top_path": top})
    assert st == 404
    st, _ = call(base, f"/api/jobs/{job}/remedy/analyze", "POST", {})
    assert st == 400


# ---------------------------------------------------------------- xlsx の細部（結合・リンク・数値・共有文字列）


def test_delete_rows_and_cols_shift_merged_ranges_and_hyperlinks():
    import openpyxl

    wb = openpyxl.Workbook()
    ws = wb.active
    for r in range(1, 11):
        for c in range(1, 5):
            ws.cell(r, c, f"r{r}c{c}")
    ws.merge_cells("B5:C6")
    ws["A8"].hyperlink = "https://example.com/"
    ws.row_dimensions[8].height = 33
    remedy_write._delete_rows(ws, [2, 3])
    assert ws["B3"].value == "r5c2" and [str(m) for m in ws.merged_cells.ranges] == ["B3:C4"]
    assert ws["A6"].value == "r8c1" and ws["A6"].hyperlink.ref == "A6" and ws.row_dimensions[6].height == 33
    assert ws.max_row == 8
    remedy_write._delete_cols(ws, [1])
    assert ws["A3"].value == "r5c2" and [str(m) for m in ws.merged_cells.ranges] == ["A3:B4"]
    assert ws.max_column == 3


def test_xlsx_dummy_numeric_cell_and_sheet_filter_keep_shared_string(tmp_path):
    import openpyxl

    p = tmp_path / "src" / "n.xlsx"
    p.parent.mkdir()
    wb = openpyxl.Workbook()
    a = wb.active
    a.title = "A"
    a.append(["氏名", "電話", "メール"])
    a.append(["山田太郎", 9012345678, "dup@example.com"])
    a.append(["鈴木花子", "080-1111-2222", "dup@example.com"])
    b = wb.create_sheet("B")
    b.append(["氏名", "メール"])
    b.append(["佐藤次郎", "dup@example.com"])  # 別のシートの同じ値。シートを絞れば残る
    wb.save(p)
    svc, store, job = make_service(tmp_path, [p])
    r = run(svc, job, p, method="dummy", dummy_mode="fixed", sheets=["A"], confidences=ALL_RANKS)
    assert r["state"] == "done", r
    assert read_sheet(p, "A")[1] == ["＊＊＊", "＊＊＊", "＊＊＊"] and read_sheet(p, "A")[2] == ["＊＊＊"] * 3
    assert read_sheet(p, "B")[1] == ["佐藤次郎", "dup@example.com"]  # 対象外のシートは元のまま
    assert contains_text(p, ["dup@example.com"])  # B シートが参照している共有文字列は残す
    assert contains_text(p, ["山田太郎", "09012345678", "9012345678"]) == []  # A だけが参照していた値は消える
    assert r["remaining"]["total"] > 0  # B の分が残る（残りを正直に数える）


def test_real_worker_process_round_trip(tmp_path, trash):
    """本番と同じ別プロセス（pebble・メモリ上限）で、分析・準備・確定が通る（位置の集まりも受け渡せる）。"""
    rows = person_rows()
    p = tmp_path / "src" / "a.csv"
    p.parent.mkdir()
    p.write_bytes(encode_csv(rows, "cp932", "\r\n"))
    original = p.read_bytes()
    svc, store, job = make_service(tmp_path, [p], runner=remediate._run_in_process)
    r = run(svc, job, p, method="delete_rows", confidences=ALL_RANKS)
    assert r["state"] == "done", r
    kept = [rows[0]] + [x for x in rows[1:] if not x[3]]
    assert p.read_bytes() == encode_csv(kept, "cp932", "\r\n")
    assert r["remaining"]["total"] == 0
    assert [f.read_bytes() for f in trash.files()] == [original]  # 別プロセスで準備し、確定は親が行って、元はごみ箱へ


def test_same_dummy_is_not_counted_as_remaining():
    """「同じ値は同じダミー」（種類_xxxxxxxx）が、ダミーの一部だけ検出し直されて「残り」に数えられない。

    保険証の記号番号・雇用保険は語の後ろの英数字を拾い、口座番号は語の後ろの 7 桁を拾うので、
    末尾だけが当たっていた（乱数の鍵しだいで、口座は約 2%、保険証はほぼ毎回）。
    """
    from pii_checker import detectors
    from pii_checker.remedy_write import DummyMaker

    for pii_type in detectors.PII_TYPES:
        for i in range(300):
            maker = DummyMaker("same", i.to_bytes(4, "big") * 8)
            dummy = maker.make(pii_type, f"元の値{i}")
            assert not re.search(r"\d{6}", dummy), dummy
            left = [dummy[h.start : h.end] for h in detectors.detect(dummy)]
            assert all(v in maker.produced for v in left), (dummy, left)

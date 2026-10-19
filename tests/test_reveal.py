"""画面に検出した値そのものを出す機能（reveal）の試験。

守ること: ジョブの DB・Excel/CSV レポートには伏せた値だけを残し、生の値はどこにも保存しない。
画面の詳細では、元のファイルを読み直して値を返す（メモリの中だけ）。
"""

from __future__ import annotations

import glob
import json
import os
import re
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

from pii_checker import engine, reveal as reveal_mod  # noqa: E402
from pii_checker.models import PasswordBook, ScanOptions  # noqa: E402
from pii_checker.runner import JobRunner  # noqa: E402
from pii_checker.store import Store  # noqa: E402

TOKEN = "reveal-test-token"
# 生の値（これらが DB・レポートに出たら漏れ）。種類ごとに別の値にして、取り違えを見つけられるようにする
TXT_EMAIL = "taro.yamada@example.com"
TXT_PHONE = "090-1234-5678"
XLSX_EMAIL = "xlsx.hanako@example.com"
SQL_EMAIL = "sql.user@example.com"
ZIP_EMAIL = "zip.inner@example.com"
RAW_NEEDLES = [TXT_EMAIL, TXT_PHONE, XLSX_EMAIL, SQL_EMAIL, ZIP_EMAIL]


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


def make_samples(folder: Path) -> dict[str, Path]:
    """テキスト・xlsx・SQL ダンプ・zip の検体を folder に作る（検査先ではなく pytest の一時フォルダ）。"""
    import openpyxl

    folder.mkdir(parents=True, exist_ok=True)
    txt = folder / "meibo.txt"
    txt.write_text(f"氏名: 山田太郎\n電話番号: {TXT_PHONE}\nメール: {TXT_EMAIL}\n", encoding="utf-8")
    xlsx = folder / "list.xlsx"
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(["氏名", "メールアドレス"])
    ws.append(["山田花子", XLSX_EMAIL])
    wb.save(xlsx)
    sql = folder / "dump.sql"
    sql.write_text(
        "CREATE TABLE users (id int, name text, email text);\n"
        f"INSERT INTO users VALUES (1,'山田太郎','{SQL_EMAIL}');\n",
        encoding="utf-8",
    )
    zp = folder / "pack.zip"
    with zipfile.ZipFile(zp, "w") as zf:
        zf.writestr("inner/list.txt", f"氏名: 鈴木一郎\nメール: {ZIP_EMAIL}\n")
    return {"txt": txt, "xlsx": xlsx, "sql": sql, "zip": zp}


def raw_pairs(result) -> list[tuple[str, str]]:
    """FileResult の明細から (種類, 生の値) の一覧。"""
    return [(f.pii_type, f.raw_value) for it in result.items for f in it.findings]


def all_texts(result) -> str:
    return "\n".join(
        f"{f.masked_value}\n{f.context}\n{f.location}\n{f.rule}" for it in result.items for f in it.findings
    )


# ---------------------------------------------------------------- 生の値が返ること


@pytest.mark.parametrize(
    "key,needle", [("txt", TXT_EMAIL), ("xlsx", XLSX_EMAIL), ("sql", SQL_EMAIL), ("zip", ZIP_EMAIL)]
)
def test_reveal_returns_raw_values(tmp_path, key, needle):
    files = make_samples(tmp_path / "src")
    opts = ScanOptions(temp_dir=str(tmp_path), reveal=True)
    res = engine.scan_file(str(files[key]), opts, PasswordBook())
    findings = [f for it in res.items for f in it.findings]
    values = [f.raw_value for f in findings]
    assert needle in values, values
    f = next(f for f in findings if f.raw_value == needle)
    assert f.masked_value != needle and needle not in f.masked_value  # 伏せた値は生の値ではない
    assert f"【{needle}】" in f.raw_context  # 生の文脈は検出箇所を【】で示す
    assert needle not in f.context  # 通常の文脈は伏せたまま
    # 値を持たない通常の検査と同じ明細（種類・場所・伏せた値）が並ぶ
    plain = engine.scan_file(str(files[key]), ScanOptions(temp_dir=str(tmp_path)), PasswordBook())
    key_of = lambda r: [
        (it.path, f.pii_type, f.location, f.masked_value) for it in r.items for f in it.findings
    ]  # noqa: E731
    assert key_of(res) == key_of(plain)


def test_reveal_phone_value(tmp_path):
    files = make_samples(tmp_path / "src")
    res = engine.scan_file(str(files["txt"]), ScanOptions(temp_dir=str(tmp_path), reveal=True), PasswordBook())
    phones = [v for t, v in raw_pairs(res) if t == "phone"]
    assert any(_digits(v) == _digits(TXT_PHONE) for v in phones), phones


def test_plain_scan_has_no_raw_in_memory(tmp_path):
    files = make_samples(tmp_path / "src")
    res = engine.scan_file(str(files["txt"]), ScanOptions(temp_dir=str(tmp_path)), PasswordBook())
    assert res.items and all(f.raw_value == "" and f.raw_context == "" for it in res.items for f in it.findings)


def test_reveal_option_is_not_saved_in_job(tmp_path):
    store = Store(str(tmp_path / "jobs.sqlite3"))
    job = store.create_job([str(tmp_path)], ScanOptions(reveal=True))
    assert "reveal" not in store.job(job)["options"]
    from pii_checker.signature import engine_signature

    assert engine_signature(ScanOptions(reveal=True)) == engine_signature(ScanOptions())


# ---------------------------------------------------------------- 途中経過を書かない


def test_reveal_writes_no_checkpoint(tmp_path, monkeypatch):
    work = tmp_path / "work"
    work.mkdir()
    src = tmp_path / "src"
    src.mkdir()
    big = src / "many.txt"
    big.write_text("".join(f"氏名: 山田{i}\nメール: user{i}@example.com\n" for i in range(300)), encoding="utf-8")
    monkeypatch.setattr(engine, "CHECKPOINT_SECONDS", 0)
    monkeypatch.setattr(engine, "CHECKPOINT_EVERY", 1)
    seen = {"files": 0}
    orig = engine.ScanContext.maybe_checkpoint

    def spy(self):
        orig(self)
        seen["files"] += len(glob.glob(str(work / "*ckpt_*")))

    monkeypatch.setattr(engine.ScanContext, "maybe_checkpoint", spy)
    # 陽性対照: reveal でない通常の検査は途中経過を書く（この観測の仕組みが働いている証拠）
    engine.scan_file(str(big), ScanOptions(temp_dir=str(work)), PasswordBook())
    assert seen["files"] > 0
    seen["files"] = 0
    res = engine.scan_file(str(big), ScanOptions(temp_dir=str(work), reveal=True), PasswordBook())
    assert any(f.raw_value for it in res.items for f in it.findings)
    assert seen["files"] == 0
    assert glob.glob(str(work / "*ckpt_*")) == []


# ---------------------------------------------------------------- 通常の検査は生の値を残さない


def contains_any(paths: list[str], needles: list[str]) -> list[str]:
    """ファイルのバイト列（zip の中身も開く）に needles のどれかがあれば、その needle を返す。"""
    found = []
    for p in paths:
        blobs = [Path(p).read_bytes()]
        if zipfile.is_zipfile(p):
            with zipfile.ZipFile(p) as zf:
                blobs += [zf.read(n) for n in zf.namelist()]
        for b in blobs:
            for n in needles:
                for enc in ("utf-8", "utf-16-le"):
                    if n.encode(enc) in b:
                        found.append(n)
    return found


@pytest.fixture(scope="module")
def scanned(tmp_path_factory):
    """4種の検体を実際のジョブ（別プロセス）で検査し、DB とレポートを作る。"""
    from pii_checker.report import write_csv, write_xlsx

    work = tmp_path_factory.mktemp("reveal")
    files = make_samples(work / "src")
    store = Store(str(work / "jobs.sqlite3"))
    tmp = work / "tmp"
    tmp.mkdir()
    job = store.create_job([str(work / "src")], ScanOptions(temp_dir=str(tmp)))
    runner = JobRunner(store, job, workers=1)
    runner.start()
    runner.wait(300)
    out = work / "out"
    out.mkdir()
    xlsx_path = out / "report.xlsx"
    write_xlsx(store, job, str(xlsx_path))
    csv_paths = write_csv(store, job, str(out))
    return {
        "work": work,
        "files": files,
        "store": store,
        "job": job,
        "runner": runner,
        "xlsx": str(xlsx_path),
        "csv": [str(p) for p in csv_paths],
        "tmp": tmp,
    }


def test_job_db_and_reports_have_only_masked_values(scanned):
    store, job = scanned["store"], scanned["job"]
    work = scanned["work"]
    # 検出が DB に入っている（伏せた値が載っている）こと
    masked = [r[0] for r in store.query("SELECT masked_value FROM findings WHERE job_id=?", (job,))]
    assert masked and any("example.com" in m and "@" in m for m in masked), masked
    # DB のファイル（WAL を含む）・レポート・一時フォルダ・検体以外のあらゆる出力に生の値が無いこと
    db_files = glob.glob(str(work / "jobs.sqlite3*"))
    assert db_files
    assert contains_any(db_files, RAW_NEEDLES) == []
    assert contains_any([scanned["xlsx"], *scanned["csv"]], RAW_NEEDLES) == []
    leftovers = [str(p) for p in Path(scanned["tmp"]).rglob("*") if p.is_file()]
    assert contains_any(leftovers, RAW_NEEDLES) == []
    # DB の全テキスト列を生の値で探す
    for table in ("jobs", "files", "items", "findings"):
        for row in store.query(f"SELECT * FROM {table}"):
            for v in tuple(row):
                if isinstance(v, str):
                    assert not any(n in v for n in RAW_NEEDLES), (table, v[:80])


def test_leak_search_has_positive_control(tmp_path):
    """探し方そのものが働くことの確認（生の値を入れたファイルは見つかる）。"""
    import sqlite3

    p = tmp_path / "x.sqlite3"
    con = sqlite3.connect(p)
    con.execute("CREATE TABLE t(a TEXT)")
    con.execute("INSERT INTO t VALUES (?)", (f"x {TXT_EMAIL} y",))
    con.commit()
    con.close()
    assert contains_any([str(p)], RAW_NEEDLES) == [TXT_EMAIL]
    z = tmp_path / "x.zip"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.txt", SQL_EMAIL * 3)
    assert contains_any([str(z)], RAW_NEEDLES) == [SQL_EMAIL]


def test_store_does_not_write_raw_columns(tmp_path):
    """store が Finding を保存するときに raw_* を書かない（reveal の結果をそのまま保存しても漏れない）。"""
    files = make_samples(tmp_path / "src")
    res = engine.scan_file(str(files["txt"]), ScanOptions(temp_dir=str(tmp_path), reveal=True), PasswordBook())
    assert any(f.raw_value for it in res.items for f in it.findings)
    store = Store(str(tmp_path / "jobs.sqlite3"))
    job = store.create_job([str(tmp_path)], ScanOptions())
    store.add_files(job, [(str(files["txt"]), 10, 1.0)])
    store.save_result(job, res, "sig")
    assert store.query("SELECT COUNT(*) FROM findings WHERE job_id=?", (job,))[0][0] > 0
    assert contains_any(glob.glob(str(tmp_path / "jobs.sqlite3*")), RAW_NEEDLES) == []


# ---------------------------------------------------------------- 読み直しの突き合わせ（サービス）


class _Registry:
    def __init__(self, runner=None):
        self.runner = runner

    def get(self, job_id, create=True, **kw):
        return self.runner


def _wait_service(svc, job, top, limit=120):
    for _ in range(limit * 10):
        r = svc.request(job, top)
        if r["state"] != "running":
            return r
        time.sleep(0.1)
    raise AssertionError("読み直しが終わらない")


def _in_process(path, options, book, timeout):
    return reveal_mod._reveal_task(path, options, book)


def test_service_matches_db_rows_and_returns_values(scanned):
    svc = reveal_mod.RevealService(scanned["store"], _Registry(scanned["runner"]), runner_fn=_in_process)
    top = str(scanned["files"]["xlsx"])
    r = _wait_service(svc, scanned["job"], top)
    assert r["state"] == "done", r
    assert r["unmatched"] == 0 and not r["mtime_changed"] and not r["content_changed"]
    assert XLSX_EMAIL in [v["value"] for v in r["values"].values()]
    # 行 ID は DB の行（findings の rowid）を指す
    for fid in r["values"]:
        assert scanned["store"].query("SELECT 1 FROM findings WHERE rowid=?", (int(fid),))
    # zip の中の1つ（項目のパスは「外側!内側」）
    r2 = _wait_service(svc, scanned["job"], str(scanned["files"]["zip"]))
    assert r2["state"] == "done" and ZIP_EMAIL in [v["value"] for v in r2["values"].values()]
    # 使い回し: 2回目は別プロセスを使わない
    calls = []
    svc2 = reveal_mod.RevealService(
        scanned["store"], _Registry(scanned["runner"]), runner_fn=lambda *a: calls.append(1) or _in_process(*a)
    )
    _wait_service(svc2, scanned["job"], top)
    _wait_service(svc2, scanned["job"], top)
    assert len(calls) == 1


def test_changed_file_is_not_shown(scanned, tmp_path):
    """検査のあとに元のファイルが変わったら「表示できない」（別の値を出さない）。"""
    store, job = scanned["store"], scanned["job"]
    txt = scanned["files"]["txt"]
    original = txt.read_bytes()
    try:
        txt.write_text("氏名: 山田太郎\nメール: other.person@example.org\n", encoding="utf-8")
        svc = reveal_mod.RevealService(store, _Registry(scanned["runner"]), runner_fn=_in_process)
        r = _wait_service(svc, job, str(txt))
        assert r["state"] == "done", r
        assert r["unmatched"] > 0
        assert r["content_changed"] or r["mtime_changed"]
        assert "変わ" in r["notice"]
        shown = [v["value"] for v in r["values"].values()]
        assert TXT_EMAIL not in shown and "other.person@example.org" not in shown
    finally:
        txt.write_bytes(original)


def test_missing_file_gives_reason(scanned):
    store, job = scanned["store"], scanned["job"]
    gone = scanned["work"] / "src" / "gone.txt"
    gone.write_text(f"メール: {TXT_EMAIL}\n", encoding="utf-8")
    # 検査結果に無いファイルは読み直せない（理由つき）
    svc = reveal_mod.RevealService(store, _Registry(scanned["runner"]), runner_fn=_in_process)
    r = svc.request(job, str(gone))
    assert r["state"] == "error" and "見つかりません" in r["message"]
    gone.unlink()


def test_ftp_without_password_gives_reason(tmp_path):
    store = Store(str(tmp_path / "jobs.sqlite3"))
    conn = {"kind": "ftp", "host": "192.0.2.1", "port": 21, "share": "", "path": "/", "user": "u", "encoding": "auto"}
    job = store.create_job(["ftp://u@192.0.2.1:21/"], ScanOptions(connection=conn))
    top = "ftp://u@192.0.2.1:21/a.txt"
    store.add_files(job, [(top, 5, 1.0)])
    with store.tx() as c:
        c.execute("UPDATE files SET state='done' WHERE job_id=?", (job,))
    svc = reveal_mod.RevealService(store, _Registry(None), runner_fn=_in_process)
    r = svc.request(job, top)
    assert r["state"] == "error", r
    assert "パスワード" in r["message"] or "接続" in r["message"]


# ---------------------------------------------------------------- API（トークンの守り・実際の別プロセス）


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def api_server(scanned):
    import uvicorn

    from pii_checker.web.server import create_app

    app = create_app(db=str(scanned["work"] / "jobs.sqlite3"), token=TOKEN)
    port = _free_port()
    srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    th = threading.Thread(target=srv.run, daemon=True)
    th.start()
    for _ in range(100):
        if srv.started:
            break
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
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
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def test_api_requires_token(api_server, scanned):
    path = f"/api/jobs/{scanned['job']}/reveal"
    body = {"top_path": str(scanned["files"]["txt"])}
    st, data = call(api_server, path, "POST", body, token=None)
    assert st == 401 and TXT_EMAIL.encode() not in data
    st, _ = call(api_server, path, "POST", body, token="wrong")
    assert st == 401
    st, _ = call(api_server, path, "POST", body, xrw=False)  # 書き込み系と同じ独自ヘッダーも要る
    assert st == 403
    st, _ = call(api_server, path, "GET")
    assert st in (404, 405)


def test_api_reveal_end_to_end(api_server, scanned):
    job = scanned["job"]
    top = str(scanned["files"]["txt"])
    # 検出明細の API に行 ID が付く
    st, data = call(api_server, f"/api/jobs/{job}/findings?top_path={urllib.request.quote(top)}")
    rows = json.loads(data)["rows"]
    assert st == 200 and rows and all("fid" in r for r in rows)
    assert all(TXT_EMAIL not in json.dumps(r, ensure_ascii=False) for r in rows)  # 通常の API は伏せたまま
    r = {}
    for _ in range(600):
        st, data = call(api_server, f"/api/jobs/{job}/reveal", "POST", {"top_path": top})
        assert st == 200, data
        r = json.loads(data)
        if r["state"] != "running":
            break
        time.sleep(0.2)
    assert r["state"] == "done", r
    by_fid = r["values"]
    email_row = next(x for x in rows if x["type"] == "メールアドレス" or "@" in x["value"])
    assert by_fid[str(email_row["fid"])]["value"] == TXT_EMAIL
    # 値を返したあとも、通常の API・保存は伏せたまま
    st, data = call(api_server, f"/api/jobs/{job}/findings?top_path={urllib.request.quote(top)}")
    assert TXT_EMAIL not in data.decode("utf-8")
    assert contains_any(glob.glob(str(scanned["work"] / "jobs.sqlite3*")), RAW_NEEDLES) == []
    # 不正な指定
    st, _ = call(api_server, f"/api/jobs/{job}/reveal", "POST", {})
    assert st == 400
    st, _ = call(api_server, "/api/jobs/no-such-job/reveal", "POST", {"top_path": top})
    assert st == 404
    assert os.path.exists(top)

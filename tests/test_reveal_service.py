"""読み直し（reveal）のサービスの細かい枝の試験（別プロセス・実際の検査は使わない）。

test_reveal.py は実際のジョブで値の漏れと突き合わせを確かめる。ここでは、読み直せない理由の文・
突き合わせの注記・結果の使い回しの期限と上限・別プロセスの失敗の言い換えを、軽い材料で確かめる。
"""

from __future__ import annotations

import sys
import threading
import time
from concurrent.futures import TimeoutError as FutureTimeout
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pii_checker import reveal as reveal_mod  # noqa: E402
from pii_checker.models import PasswordBook, ScanOptions, Status  # noqa: E402
from pii_checker.store import Store  # noqa: E402

FTP_CONN = {"kind": "ftp", "host": "192.0.2.1", "port": 21, "share": "", "path": "/", "user": "u", "encoding": "auto"}


class _Registry:
    def __init__(self, runner=None):
        self.runner = runner

    def get(self, job_id, create=True, **kw):
        return self.runner


class _Runner:
    """検査を動かしているメモリのパスワードだけを持つ代わり。"""

    def __init__(self, book: PasswordBook):
        self.passwords = book


def _job_with_file(tmp_path, top: str, options: ScanOptions, size: int = 5, state: str = "done"):
    store = Store(str(tmp_path / "jobs.sqlite3"))
    job = store.create_job([top], options)
    store.add_files(job, [(top, size, 1.0)])
    with store.tx() as c:
        c.execute("UPDATE files SET state=? WHERE job_id=?", (state, job))
    return store, job


# ---------------------------------------------------------------- 始める前に分かる理由（_plan）


def test_unknown_job_gives_reason(tmp_path):
    svc = reveal_mod.RevealService(Store(str(tmp_path / "jobs.sqlite3")), _Registry())
    r = svc.request("no-such-job", "C:/x.txt")
    assert r == {"state": "error", "message": "そのジョブは見つかりません"}
    assert svc._entries == {}  # 始める前の失敗は何も残さない


def test_file_not_done_yet_gives_reason(tmp_path):
    top = str(tmp_path / "a.txt")
    store, job = _job_with_file(tmp_path, top, ScanOptions(), state="pending")
    r = reveal_mod.RevealService(store, _Registry()).request(job, top)
    assert r["state"] == "error" and "まだ検査が終わっていません" in r["message"]


def test_ftp_without_connection_setting_gives_reason(tmp_path):
    top = "ftp://u@192.0.2.1:21/a.txt"
    store, job = _job_with_file(tmp_path, top, ScanOptions())
    r = reveal_mod.RevealService(store, _Registry()).request(job, top)
    assert r["state"] == "error" and "接続先の設定が無い" in r["message"]


def test_ftp_with_broken_connection_setting_gives_reason(tmp_path):
    top = "ftp://u@192.0.2.1:21/a.txt"
    store, job = _job_with_file(tmp_path, top, ScanOptions(connection={**FTP_CONN, "port": "abc"}))
    r = reveal_mod.RevealService(store, _Registry()).request(job, top)
    assert r["state"] == "error"
    assert "接続先の設定を読めない" in r["message"] and "ポート（abc）" in r["message"]


def test_plan_copies_passwords_from_running_job(tmp_path):
    """FTP のパスワードは検査を動かしているメモリにだけある。それを写して使い、元の帳面は渡さない。"""
    top = "ftp://u@192.0.2.1:21/a.txt"
    store, job = _job_with_file(tmp_path, top, ScanOptions(connection=FTP_CONN))
    book = PasswordBook(common=["c1"], per_file={top: ["p1"]}, connection_password="secret")
    plan = reveal_mod.RevealService(store, _Registry(_Runner(book)))._plan(job, top)
    got = plan["book"]
    assert got is not book and got.per_file is not book.per_file and got.per_file[top] is not book.per_file[top]
    assert (got.common, got.per_file, got.connection_password) == (["c1"], {top: ["p1"]}, "secret")
    assert plan["options"].reveal is True


def test_plan_drops_missing_temp_dir_and_clamps_timeout(tmp_path):
    top = str(tmp_path / "a.txt")
    gone = str(tmp_path / "no-such-dir")
    store, job = _job_with_file(tmp_path, top, ScanOptions(temp_dir=gone), size=10)
    svc = reveal_mod.RevealService(store, _Registry())
    plan = svc._plan(job, top)
    assert plan["options"].temp_dir is None  # 今は無い一時フォルダは既定の場所で読む
    assert plan["timeout"] == reveal_mod.MIN_TIMEOUT
    # 在る一時フォルダはそのまま・とても大きいファイルは上限で止める
    (tmp_path / "b").mkdir()
    store2, job2 = _job_with_file(
        tmp_path / "b", top, ScanOptions(temp_dir=str(tmp_path)), size=reveal_mod.BYTES_PER_SEC * 10**6
    )
    plan2 = reveal_mod.RevealService(store2, _Registry())._plan(job2, top)
    assert plan2["options"].temp_dir == str(tmp_path)
    assert plan2["timeout"] == reveal_mod.MAX_TIMEOUT


# ---------------------------------------------------------------- 突き合わせ（_match）


class _FakeStore:
    def __init__(self, rows):
        self.rows = rows

    def query(self, sql, args=()):
        return self.rows


def _plan(size=10, mtime_ns=100, sha="abc"):
    return {"job_id": "j", "top_path": "t", "size": size, "db_mtime_ns": mtime_ns, "db_sha256": sha}


def _row(fid, path="t", pii="メールアドレス", loc="1行目", masked="a***@x"):
    return {"fid": fid, "path": path, "pii_type": pii, "location": loc, "masked_value": masked}


def test_match_without_source_returns_first_reason():
    svc = reveal_mod.RevealService(_FakeStore([]), _Registry())
    with pytest.raises(reveal_mod.RevealUnavailable, match="元のファイルを読めませんでした: 権限がありません"):
        svc._match(_plan(), {"items": [("t", "error", "権限がありません")], "findings": [], "source": None})
    with pytest.raises(reveal_mod.RevealUnavailable, match=r"^元のファイルを読めませんでした$"):
        svc._match(_plan(), {"items": [], "findings": [], "source": {}})


def test_match_pairs_same_key_in_order_and_flags_big_file():
    """同じ（パス・種類・場所・伏せた値）の明細が2つあれば、DB の行の順に1つずつ当てる。"""
    rows = [_row(1), _row(2)]
    raw = {
        "items": [("t", "done", "")],
        "findings": [
            ("t", "メールアドレス", "1行目", "a***@x", "v1", "c1"),
            ("t", "メールアドレス", "1行目", "a***@x", "v2", "c2"),
        ],
        "source": {"mtime_ns": 100, "sha256": "abc"},
    }
    r = reveal_mod.RevealService(_FakeStore(rows), _Registry())._match(_plan(size=reveal_mod.BIG_FILE_BYTES), raw)
    assert r["values"] == {"1": {"value": "v1", "context": "c1"}, "2": {"value": "v2", "context": "c2"}}
    assert (r["unmatched"], r["notice"], r["big_file"]) == (0, "", True)


def test_match_notice_for_password_items():
    """中身が変わっていないのに合わない明細があり、パスワードの要る項目があるときは、その理由を出す。"""
    raw = {
        "items": [("t", "done", ""), ("t!x.zip", Status.NEEDS_PASSWORD.value, "")],
        "findings": [],
        "source": {"mtime_ns": 100, "sha256": "abc"},
    }
    r = reveal_mod.RevealService(_FakeStore([_row(1)]), _Registry())._match(_plan(), raw)
    assert r["needs_password"] and r["unmatched"] == 1 and not r["mtime_changed"] and not r["content_changed"]
    assert r["notice"] == "パスワードが要る項目は、このアプリがパスワードを持っていないため表示できません。"
    assert not r["big_file"]


def test_match_notice_when_unmatched_without_visible_change():
    raw = {"items": [("t", "done", "")], "findings": [], "source": {"mtime_ns": None, "sha256": ""}}
    r = reveal_mod.RevealService(_FakeStore([_row(1)]), _Registry())._match(_plan(), raw)
    assert not r["mtime_changed"] and not r["content_changed"]  # 比べられない値は変わったと見なさない
    assert r["notice"] == "一致しない明細は、元のファイルが変わったため表示できません。"


def test_match_mtime_only_change_is_noticed_even_if_all_match():
    raw = {
        "items": [("t", "done", "")],
        "findings": [("t", "メールアドレス", "1行目", "a***@x", "v1", "c1")],
        "source": {"mtime_ns": 200, "sha256": "abc"},
    }
    r = reveal_mod.RevealService(_FakeStore([_row(1)]), _Registry())._match(_plan(), raw)
    assert r["mtime_changed"] and not r["content_changed"] and r["unmatched"] == 0
    assert r["notice"].startswith("検査のあとに元のファイルが変わっています")
    assert "一致しない明細" not in r["notice"]


# ---------------------------------------------------------------- 走らせる・使い回す（_work・_purge）


def _ready_service(tmp_path, runner_fn):
    top = str(tmp_path / "a.txt")
    store, job = _job_with_file(tmp_path, top, ScanOptions())
    return reveal_mod.RevealService(store, _Registry(), runner_fn=runner_fn), job, top


def _wait(svc, job, top):
    for _ in range(200):
        r = svc.request(job, top)
        if r["state"] != "running":
            return r
        time.sleep(0.02)
    raise AssertionError("読み直しが終わらない")


def test_unexpected_error_returns_only_type_name(tmp_path):
    """想定外の失敗の文には例外の型だけを出し、例外の文（値が入りうる）は出さない。"""

    def boom(*a):
        raise ValueError("taro.yamada@example.com を読めない")

    svc, job, top = _ready_service(tmp_path, boom)
    r = _wait(svc, job, top)
    assert r == {"state": "error", "message": "読み直しに失敗しました（ValueError）"}


def test_running_state_reports_elapsed_and_is_not_restarted(tmp_path):
    gate = threading.Event()
    calls = []

    def slow(*a):
        calls.append(1)
        gate.wait(10)
        raise reveal_mod.RevealUnavailable("止めた")

    svc, job, top = _ready_service(tmp_path, slow)
    first = svc.request(job, top)
    second = svc.request(job, top)
    assert first["state"] == "running" and second["state"] == "running" and "elapsed" in second
    gate.set()
    assert _wait(svc, job, top) == {"state": "error", "message": "止めた"}
    assert len(calls) == 1


def test_error_is_kept_briefly_then_retried(tmp_path, monkeypatch):
    calls = []

    def fail(*a):
        calls.append(1)
        raise reveal_mod.RevealUnavailable("読めない")

    svc, job, top = _ready_service(tmp_path, fail)
    assert _wait(svc, job, top)["state"] == "error"
    assert svc.request(job, top)["state"] == "error" and len(calls) == 1  # 画面が見に来る間は覚えている
    entry = svc._entries[(job, top)]
    entry.finished -= reveal_mod.ERROR_KEEP_SECONDS + 1
    _wait(svc, job, top)
    assert len(calls) == 2  # 期限を過ぎた失敗は読み直す


def test_done_result_expires_and_cache_is_capped(monkeypatch):
    svc = reveal_mod.RevealService(_FakeStore([]), _Registry())
    monkeypatch.setattr(reveal_mod, "MAX_CACHE_ENTRIES", 2)
    now = time.time()

    def entry(state, age):
        e = reveal_mod.RevealEntry()
        e.state, e.finished = state, now - age
        return e

    svc._entries = {
        ("j", "old"): entry("done", reveal_mod.REVEAL_CACHE_SECONDS + 1),  # 期限切れ
        ("j", "a"): entry("done", 30),
        ("j", "b"): entry("done", 20),
        ("j", "c"): entry("done", 10),
        ("j", "run"): reveal_mod.RevealEntry(),  # 走っている間の finished は 0（古い順に並べると先頭に来る）
    }
    svc._purge()
    # 期限切れを捨て、上限を超えた分は終わったものの古い順に捨てる。走っているものは捨てない
    assert set(svc._entries) == {("j", "run"), ("j", "c")}


def test_forget_job_drops_only_that_job():
    svc = reveal_mod.RevealService(_FakeStore([]), _Registry())
    svc._entries = {("j1", "a"): reveal_mod.RevealEntry(), ("j1", "b"): reveal_mod.RevealEntry()}
    svc._entries[("j2", "a")] = reveal_mod.RevealEntry()
    svc.forget_job("j1")
    assert set(svc._entries) == {("j2", "a")}


# ---------------------------------------------------------------- 別プロセスの失敗の言い換え（_run_in_process）


class _FakeFuture:
    def __init__(self, exc):
        self.exc = exc

    def result(self):
        raise self.exc


def _fake_pool(exc):
    class _Pool:
        def __init__(self, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def schedule(self, fn, args=(), timeout=None):
            return _FakeFuture(exc)

    return _Pool


@pytest.mark.parametrize(
    "make_exc, words",
    [
        (lambda: FutureTimeout(), "時間制限（10 分）を超えた"),
        (lambda: TimeoutError(), "時間制限（10 分）を超えた"),
        (
            lambda: __import__("pebble.common", fromlist=["ProcessExpired"]).ProcessExpired("x", code=-9),
            "プロセスが終了",
        ),
    ],
)
def test_run_in_process_turns_failures_into_reasons(monkeypatch, make_exc, words):
    import pebble

    monkeypatch.setattr(pebble, "ProcessPool", _fake_pool(make_exc()))
    with pytest.raises(reveal_mod.RevealUnavailable, match=words):
        reveal_mod._run_in_process("a.txt", ScanOptions(), PasswordBook(), 600)

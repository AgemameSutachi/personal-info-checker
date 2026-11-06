"""コマンドの進み具合の表示（cli._ProgressPrinter）と Store.biggest_of の試験。"""

from __future__ import annotations

import io

import pytest

from pii_checker import cli, runner
from pii_checker.models import ScanOptions
from pii_checker.store import Store


class FakeStore:
    def __init__(self):
        self.done = 0
        self.biggest = ("D:/共有/大きな.zip", 8 * 1024**3)
        self.asked = []

    def progress_cached(self, job_id):
        return self.progress(job_id)

    def progress(self, job_id):
        return {
            "files_total": 10,
            "files_done": self.done,
            "item_status": {"uncheckable": 1},
            "files_with_findings": 2,
        }

    def biggest_of(self, job_id, paths):
        self.asked.append(sorted(paths))
        return self.biggest


class FakeRunner:
    job_id = "j1"
    phase = "検査"
    error = ""

    def __init__(self):
        self.current = {"D:/共有/大きな.zip", "D:/共有/小さい.txt"}


class Out(io.StringIO):
    def __init__(self, tty):
        super().__init__()
        self._tty = tty

    def isatty(self):
        return self._tty


@pytest.fixture
def clock(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(cli.time, "monotonic", lambda: now[0])
    return now


def test_log_output_is_one_line_per_interval(clock):
    """端末でない出力（ログのファイル）には、毎秒の書き換えではなく LOG_INTERVAL 秒ごとに改行つきの1行を足す。"""
    store, out = FakeStore(), Out(tty=False)
    p = cli._ProgressPrinter(store, FakeRunner(), out)
    for _ in range(150):  # 150 秒
        store.done += 1
        p.tick()
        clock[0] += 1
    p.final()
    text = out.getvalue()
    assert "\r" not in text
    lines = text.splitlines()
    assert len(lines) == 4  # 0・60・120 秒と最後
    assert lines[0].startswith("[検査] 1/10 ファイル")
    assert lines[-1].startswith("[完了] 150/10 ファイル")
    assert "検査不能 1" in lines[-1] and "検出あり 2" in lines[-1]


def test_stall_hint_names_biggest_file(clock):
    """済んだ数が STALL_SECONDS 秒進まないと、検査中の一番大きなファイルの名前と大きさを添える。進めば消す。"""
    store, out = FakeStore(), Out(tty=False)
    p = cli._ProgressPrinter(store, FakeRunner(), out)
    p.tick()
    clock[0] += cli.STALL_SECONDS - 1
    p.tick()
    assert p.hint is None  # まだ待つ
    clock[0] += 1
    p.tick()
    assert p._hint_text() == "  大きなファイルを検査中: 大きな.zip（8.0 GB）"
    assert store.asked == [["D:/共有/大きな.zip", "D:/共有/小さい.txt"]]
    clock[0] += cli.LOG_INTERVAL
    p.tick()
    assert len(store.asked) == 2  # 30 秒たてば調べ直す
    p.tick()
    assert len(store.asked) == 2  # 30 秒は調べ直さない
    assert out.getvalue().splitlines()[-1].endswith("大きなファイルを検査中: 大きな.zip（8.0 GB）")
    store.done += 1
    p.tick()
    assert p.hint is None


def test_stall_hint_survives_lookup_failure(clock):
    store = FakeStore()

    def broken(job_id, paths):
        raise RuntimeError("database is locked")

    store.biggest_of = broken
    p = cli._ProgressPrinter(store, FakeRunner(), Out(tty=False))
    p.tick()
    clock[0] += cli.STALL_SECONDS
    p.tick()  # 落ちない
    assert p.hint is None


def test_terminal_rewrites_line_and_fits_width(clock, monkeypatch):
    """端末では同じ行を書き換え、幅を超えない（折り返すと行頭へ戻れず毎秒新しい行が増える）。短くなれば消し残しを埋める。"""
    import os

    monkeypatch.setattr(cli.shutil, "get_terminal_size", lambda fallback=None: os.terminal_size((80, 24)))
    store, out = FakeStore(), Out(tty=True)
    store.biggest = ("D:/共有/" + "とても長い名前" * 10 + ".zip", 5 * 1024**2)
    p = cli._ProgressPrinter(store, FakeRunner(), out)
    p.tick()
    clock[0] += cli.STALL_SECONDS
    p.tick()
    writes = out.getvalue().split("\r")[1:]
    assert len(writes) == 2
    assert all(cli._display_width(w) <= 79 for w in writes)
    # 80 桁では件数の側を短くして、名前を縮めて添える
    assert writes[1].startswith("[検査] 0/10 ファイル  大きなファイルを検査中: とても")
    assert "…" in writes[1] and writes[1].endswith(".zip（5.0 MB）")
    assert "検出あり" not in writes[1]
    store.done += 1
    clock[0] += 1
    p.tick()
    last = out.getvalue().split("\r")[-1]
    assert cli._display_width(last) == cli._display_width(writes[1])  # 空白で埋めて同じ幅
    assert "大きなファイル" not in last
    p.final()
    assert out.getvalue().endswith("\n")


def test_helpers():
    assert cli._size_text(512) == "512 B"
    assert cli._size_text(1536) == "1.5 KB"
    assert cli._size_text(3 * 1024**3) == "3.0 GB"
    assert cli._short_name("C:\\a\\b.txt") == "b.txt"
    short = cli._short_name("x" * 100 + ".zip", limit=21)
    assert len(short) == 21 and short.startswith("x" * 10) and short.endswith("x" * 6 + ".zip")
    assert cli._short_name("abcdef.zip", 0) == ""
    assert cli._short_name("abcdef.zip", 2) == "ab"
    assert cli._short_name("abcdef.zip", 4) == "a…ip"
    assert cli._fit("あいう", 5) == "あい"


def test_terminal_keeps_counts_when_wide(clock, monkeypatch):
    """広い端末では件数を全部出したうえで名前を添える。"""
    import os

    monkeypatch.setattr(cli.shutil, "get_terminal_size", lambda fallback=None: os.terminal_size((200, 24)))
    store, out = FakeStore(), Out(tty=True)
    p = cli._ProgressPrinter(store, FakeRunner(), out)
    p.tick()
    clock[0] += cli.STALL_SECONDS
    p.tick()
    last = out.getvalue().split("\r")[-1].rstrip()
    assert "検出あり 2" in last and last.endswith("大きなファイルを検査中: 大きな.zip（8.0 GB）")


@pytest.fixture
def scanned(tmp_path):
    folder = tmp_path / "data"
    folder.mkdir()
    (folder / "small.txt").write_text("小さい", encoding="utf-8")
    (folder / "big.txt").write_text("大きい" * 1000, encoding="utf-8")
    store = Store(str(tmp_path / "jobs.sqlite3"))
    job = store.create_job([str(folder)], ScanOptions(temp_dir=str(tmp_path)))
    r = runner.JobRunner(store, job, workers=1)
    r.start()
    r.wait(180)
    assert store.job(job)["state"] == "done"
    return store, job, folder


def test_biggest_of_reads_enumerated_size(scanned):
    store, job, folder = scanned
    paths = [r[0] for r in store.query("SELECT top_path FROM files WHERE job_id=?", (job,))]
    assert len(paths) == 2
    path, size = store.biggest_of(job, paths)
    assert path.endswith("big.txt") and size == (folder / "big.txt").stat().st_size
    assert store.biggest_of(job, []) is None
    assert store.biggest_of(job, ["Z:/無い.txt"]) is None
    assert store.biggest_of("other-job", paths) is None

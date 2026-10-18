"""途中の電源断・強制終了への備えと、検査先へ書かない決まりの試験。"""

import gc
import os
import subprocess
import sys
import time

import pytest

from pii_checker import safeio
from pii_checker.models import ScanOptions
from pii_checker.report import write_csv, write_xlsx
from pii_checker.store import Store


def test_broken_db_is_kept_and_recreated(tmp_path):
    db = tmp_path / "jobs.sqlite3"
    db.write_bytes(b"this is not a database" * 100)
    store = Store(str(db))
    assert store.recovered and "作り直しました" in store.recovered
    broken = [p for p in os.listdir(tmp_path) if ".broken-" in p]
    assert broken  # 壊れたファイルは消さずに別名で残す
    assert (tmp_path / broken[0]).read_bytes().startswith(b"this is not")
    job = store.create_job([str(tmp_path)], ScanOptions())
    assert store.job(job)


def test_folder_errors_are_not_doubled(tmp_path):
    store = Store(str(tmp_path / "j.sqlite3"))
    job = store.create_job([str(tmp_path)], ScanOptions())
    for _ in range(2):  # 電源断の後に列挙をやり直した
        store.add_folder_error(job, r"\\nas\share\secret", "error", "権限がない")
    assert store.summary(job)["folder_errors"] == 1


def test_stale_running_job_becomes_interrupted(tmp_path):
    store = Store(str(tmp_path / "j.sqlite3"))
    dead = store.create_job([str(tmp_path)], ScanOptions())
    live = store.create_job([str(tmp_path)], ScanOptions())
    # 止まったプロセス（もういない pid）が動かしていたジョブ
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait()
    store.set_job(dead, state="running", owner_pid=p.pid, heartbeat=time.time())
    # 今動いているプロセス（自分）が動かしているジョブ
    store.set_job(live, state="running")
    store.heartbeat(live)
    fixed = store.reconcile_running()
    assert fixed == [dead]
    assert store.job(dead)["state"] == "interrupted"
    assert store.job(live)["state"] == "running"
    # 生きていて生存記録が少し古い（スリープから戻った直後など）だけなら中断にしない
    store.set_job(live, heartbeat=time.time() - 600)
    assert store.reconcile_running() == []
    # 生きていても生存記録がとても古ければ、pid が別のプロセスに使い回されたとみなす
    store.set_job(live, heartbeat=time.time() - 7200)
    assert store.reconcile_running() == [live]


def test_heartbeat_keeps_beating_during_long_file(tmp_path, monkeypatch):
    """1ファイルの検査が長くても生存記録が進み続ける（別の窓や CLI から「中断」にされない。不具合の修正）。"""
    import threading

    from pii_checker import runner

    store = Store(str(tmp_path / "j.sqlite3"))
    job = store.create_job([str(tmp_path)], ScanOptions())
    store.set_job(job, state="running", owner_pid=os.getpid(), heartbeat=0.0)
    monkeypatch.setattr(runner, "HEARTBEAT_SECONDS", 0.05)
    r = runner.JobRunner(store, job, workers=1)
    done = threading.Event()
    t = threading.Thread(target=r._heartbeat_loop, args=(done,))
    t.start()
    time.sleep(0.5)
    first = store.job(job)["heartbeat"]
    time.sleep(0.3)
    second = store.job(job)["heartbeat"]
    done.set()
    t.join(5)
    assert first > 0 and second > first  # 検査の本体が何もしなくても進む
    assert store.reconcile_running(stale_after=1.0) == []


def test_reserve_is_reasonable(monkeypatch):
    """残しておく空きが大きすぎて、ふつうの PC で全部が検査不能にならない。"""
    import collections

    gb = 1024**3
    Usage = collections.namedtuple("Usage", "total used free")
    for total, free in ((1024 * gb, 40 * gb), (256 * gb, 10 * gb), (2048 * gb, 80 * gb)):
        monkeypatch.setattr(safeio.shutil, "disk_usage", lambda folder, t=total, f=free: Usage(t, t - f, f))
        assert safeio.reserve_bytes("C:/") <= 5 * gb
        safeio.ensure_free("C:/", 1 * gb)  # 1GB のファイルは写せる


# save を途中で失敗させると openpyxl の書きかけのシートの生成器が閉じられずに残り、
# 回収されるときに警告が出る（想定どおり）。この試験の中で回収して、後の試験へ持ち越さない
@pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
def test_report_written_atomically(tmp_path, monkeypatch):
    store = Store(str(tmp_path / "j.sqlite3"))
    job = store.create_job([str(tmp_path / "x")], ScanOptions())
    out = tmp_path / "out.xlsx"
    out.write_bytes(b"old report")

    import openpyxl.workbook.workbook as wbmod

    def broken_save(self, filename):
        with open(filename, "wb") as f:
            f.write(b"half")
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(wbmod.Workbook, "save", broken_save)
    try:
        write_xlsx(store, job, str(out))
    except OSError:
        pass
    gc.collect()
    assert out.read_bytes() == b"old report"  # 前のレポートは壊れずに残る
    assert [p for p in os.listdir(tmp_path) if p.endswith(".tmp")] == []  # 書きかけは残さない
    monkeypatch.undo()
    write_xlsx(store, job, str(out))
    assert out.read_bytes()[:2] == b"PK"
    paths = write_csv(store, job, str(tmp_path))
    assert all(os.path.exists(p) for p in paths)


def test_output_inside_roots():
    roots = [r"\\nas01\総務", r"D:\共有"]
    assert safeio.output_inside_roots(r"\\NAS01\総務\結果.xlsx", roots, "出力先")
    assert safeio.output_inside_roots(r"D:\共有", roots, "一時フォルダ")
    assert safeio.output_inside_roots(r"D:\共有2\a.xlsx", roots, "出力先") is None
    assert safeio.output_inside_roots(r"C:\Users\me\Documents\a.xlsx", roots, "出力先") is None
    assert safeio.output_inside_roots(None, roots, "出力先") is None

"""未検査のファイルを配る順（大きなファイルを先に・同時の本数の上限つき）の試験。"""

from pii_checker import runner
from pii_checker.runner import BIG_FILE_BYTES, PendingQueue
from pii_checker.models import ScanOptions
from pii_checker.store import Store

GB = BIG_FILE_BYTES


def _drain(q: PendingQueue, finish_each: bool) -> list[str]:
    out = []
    while (p := q.next()) is not None:
        out.append(p)
        if finish_each:
            q.done(p)
    return out


def test_big_files_first_in_size_order():
    pending = [("a.txt", 10), ("b.zip", 3 * GB), ("c.txt", 20), ("d.db", 7 * GB), ("e.gz", GB)]
    # 配るたびに終わる（上限に掛からない）: 大きい順に全部 → 小さいものは名前の順
    assert _drain(PendingQueue(pending, 2), finish_each=True) == ["d.db", "b.zip", "e.gz", "a.txt", "c.txt"]


def test_big_files_capped_while_small_remain():
    pending = [("a.txt", 10), ("b.zip", 3 * GB), ("c.txt", 20), ("d.db", 7 * GB), ("e.gz", GB), ("f.txt", 5)]
    q = PendingQueue(pending, 2)
    # 終わらないまま配り続ける: 大きなものは2本まで、残りは小さいものが尽きてから
    assert _drain(q, finish_each=False) == ["d.db", "b.zip", "a.txt", "c.txt", "f.txt", "e.gz"]


def test_finished_big_file_frees_slot():
    q = PendingQueue([("a.txt", 1), ("b.txt", 2), ("x.zip", 2 * GB), ("y.zip", 3 * GB)], 1)
    assert q.next() == "y.zip"
    assert q.next() == "a.txt"  # 上限1本に達している
    q.done("y.zip")
    assert q.next() == "x.zip"
    assert q.next() == "b.txt"
    assert q.next() is None


def test_unknown_size_is_small():
    # 大きさの分からないもの（0）は小さいものとして、渡された順（Store の名前の順）のまま
    assert _drain(PendingQueue([("a", 0), ("b", 0), ("c", GB)], 2), finish_each=True) == ["c", "a", "b"]


def test_pending_files_sized(tmp_path):
    store = Store(str(tmp_path / "jobs.sqlite3"))
    job = store.create_job([str(tmp_path)], ScanOptions(temp_dir=str(tmp_path)))
    store.add_files(job, [("p2", 5, 0.0), ("p1", None, 0.0)])
    assert store.pending_files_sized(job) == [("p1", 0), ("p2", 5)]
    assert store.pending_files(job) == ["p1", "p2"]


def test_runner_uses_queue_order(tmp_path, monkeypatch):
    """検査スレッドが PendingQueue の順でワーカーへ配ること（大きなファイルが最初に配られる）。"""
    store = Store(str(tmp_path / "jobs.sqlite3"))
    job = store.create_job([str(tmp_path)], ScanOptions(temp_dir=str(tmp_path), reuse=False))
    store.add_files(job, [("a.txt", 10, 0.0), ("big.zip", 2 * GB, 0.0), ("c.txt", 10, 0.0)])
    r = runner.JobRunner(store, job, workers=4)
    order = []

    class FakeFuture:
        def __init__(self, path):
            self.path = path

        def done(self):
            return True

    class FakePool:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def schedule(self, fn, args, timeout):
            order.append(args[0])
            return FakeFuture(args[0])

        def stop(self):
            pass

    def fake_save(future, path, started, expired, version=0):
        store.save_failure(job, path, "試験")

    import pebble

    monkeypatch.setattr(pebble, "ProcessPool", FakePool)
    monkeypatch.setattr(r, "_save", fake_save)
    r._scan_pending()
    assert order == ["big.zip", "a.txt", "c.txt"]

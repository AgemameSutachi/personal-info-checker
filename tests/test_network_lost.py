"""NAS への接続が切れたときの扱いの試験。

本物の回線断（Hyper-V の VM の SMB 共有で、検査中にネットワークを切る）は tests/smb_check.py の drop の場面で確かめる。
ここでは、そこで分かった不具合（理由が「削除された」と出る・残り全部が検査不能で確定し再開しても読み直さない）を
偽の結果で再現して、実行器の判断を確かめる。
"""

import os

import pytest

from pii_checker import runner, safeio, walker
from pii_checker.engine import _source_failure
from pii_checker.models import FileResult, ItemResult, ScanOptions, Status
from pii_checker.store import Store


def _net_error(code=53):
    # winerror 53 は Python では FileNotFoundError になる（「削除された」と取り違えやすい元）
    return OSError(None, "ネットワーク パスが見つかりません。", r"\\nas\share\a.txt", code)


class _Done:
    """pebble の future の代わり（結果を返すだけ）。"""

    def __init__(self, result):
        self._result = result

    def result(self):
        return self._result


def _lost(path):
    item = _source_failure(path, _net_error())
    return FileResult(top_path=path, items=[item], network_lost=True)


def _ok(path):
    return FileResult(top_path=path, items=[ItemResult(path=path, kind="text", status=Status.SCANNED)])


def _runner(tmp_path, paths):
    store = Store(str(tmp_path / "j.sqlite3"))
    job = store.create_job([str(tmp_path)], ScanOptions())
    store.add_files(job, [(p, 1, 0.0) for p in paths])
    store.set_job(job, enum_done=1)
    return store, job, runner.JobRunner(store, job, workers=1)


def test_reason_says_network_not_deleted():
    e = _net_error()
    assert isinstance(e, FileNotFoundError)
    assert safeio.is_network_lost(e)
    item = _source_failure(r"\\nas\share\a.txt", e)
    assert item.reason.startswith(safeio.NETWORK_LOST_MSG)
    assert "削除" not in item.reason
    # 陽性対照: 本当に見つからない（ローカルの ENOENT）は従来どおり
    gone = _source_failure("C:/x/a.txt", FileNotFoundError(2, "見つからない"))
    assert "見つからない" in gone.reason and not safeio.is_network_lost(FileNotFoundError(2, "x"))


def test_streak_halts_and_leaves_files_pending(tmp_path):
    paths = [str(tmp_path / f"f{i}.txt") for i in range(6)]
    store, job, r = _runner(tmp_path, paths)
    r._save_result(_Done(_ok(paths[0])), paths[0], 0.0, Exception, 0)
    for p in paths[1:4]:
        r._save_result(_Done(_lost(p)), p, 0.0, Exception, 0)
    assert r._stop.is_set() and r.halt_reason == runner.NETWORK_HALT_MESSAGE
    pending = set(store.pending_files(job))
    # 切れて読めなかった分は済みにしない（つながってから再開すると読み直す）
    assert set(paths[1:]) <= pending and paths[0] not in pending
    assert store.files_with_status(job, ["uncheckable"]) == []


def test_success_resets_streak(tmp_path):
    paths = [str(tmp_path / f"f{i}.txt") for i in range(5)]
    store, job, r = _runner(tmp_path, paths)
    for p in (paths[0], paths[1]):
        r._save_result(_Done(_lost(p)), p, 0.0, Exception, 0)
    r._save_result(_Done(_ok(paths[2])), paths[2], 0.0, Exception, 0)
    r._save_result(_Done(_lost(paths[3])), paths[3], 0.0, Exception, 0)
    assert not r._stop.is_set()  # 一瞬の切断で止めない


def test_one_file_repeatedly_lost_is_recorded_then_retried_on_next_run(tmp_path):
    """1つだけが繰り返し切れる（他は読める）ときは、回数の上限で理由つきの検査不能にし、次に始めたとき読み直しに回す。"""
    paths = [str(tmp_path / f"f{i}.txt") for i in range(2)]
    store, job, r = _runner(tmp_path, paths)
    bad = paths[0]
    for _ in range(runner.NETWORK_MAX_RETRY):
        r._save_result(_Done(_lost(bad)), bad, 0.0, Exception, 0)
        r._save_result(_Done(_ok(paths[1])), paths[1], 0.0, Exception, 0)  # 他は読める（続けて切れてはいない）
    assert not r._stop.is_set()
    assert store.files_with_status(job, ["uncheckable"]) == [bad]
    assert bad not in store.pending_files(job)
    assert store.files_with_reason_prefix(job, safeio.NETWORK_LOST_MSG) == [bad]


def test_resume_rereads_network_failures(tmp_path, monkeypatch):
    """再開すると、前回接続が切れて検査不能になったファイルを読み直しに回す（_run の入口）。"""
    paths = [str(tmp_path / "a.txt")]
    store, job, r = _runner(tmp_path, paths)
    store.save_result(job, _lost(paths[0]))
    seen = {}
    monkeypatch.setattr(r, "_scan_pending", lambda: seen.setdefault("pending", store.pending_files(job)))
    r._run()
    assert seen["pending"] == paths


def test_enumeration_halts_on_network_loss(tmp_path, monkeypatch):
    """列挙の途中で切れたら、そのフォルダを「開けなかった」で確定させず、列挙を済みにしないで止める。"""
    root = tmp_path / "root"
    (root / "sub").mkdir(parents=True)
    (root / "a.txt").write_text("x", encoding="utf-8")
    real = os.scandir

    def flaky(path):
        if str(path).rstrip("\\/").endswith("sub"):
            raise _net_error(64)
        return real(path)

    monkeypatch.setattr(walker.os, "scandir", flaky)
    entries = list(walker.walk([str(root)]))
    assert any(e.kind == "error" and e.network_lost for e in entries)
    store = Store(str(tmp_path / "j.sqlite3"))
    job = store.create_job([str(root)], ScanOptions())
    r = runner.JobRunner(store, job, workers=1)
    r._enumerate()
    assert r._stop.is_set() and r.halt_reason == runner.NETWORK_HALT_MESSAGE
    assert not store.job(job)["enum_done"]
    assert store.summary(job)["folder_errors"] == 0


@pytest.mark.parametrize("code", sorted(safeio.NETWORK_WINERRORS))
def test_all_network_codes(code):
    assert safeio.is_network_lost(OSError(None, "x", None, code))
    assert safeio.is_network_lost(safeio.SourceInUse("x")) is False


def test_single_remaining_file_does_not_halt_forever(tmp_path):
    """残りが同じ1件だけで毎回切れるとき、止め続けずに上限の回数で理由つきの検査不能にする（評価2周目で実測した穴）。"""
    paths = [str(tmp_path / "only.txt")]
    store, job, r = _runner(tmp_path, paths)
    for _ in range(runner.NETWORK_MAX_RETRY):
        r._save_result(_Done(_lost(paths[0])), paths[0], 0.0, Exception, 0)
    assert not r._stop.is_set()
    assert store.files_with_status(job, ["uncheckable"]) == paths


def test_error_is_cleared_when_run_again(tmp_path, monkeypatch):
    """前回止めた理由は、再開して最後まで終わったら残さない（画面に「中断した」が残っていた）。"""
    store, job, r = _runner(tmp_path, [str(tmp_path / "a.txt")])
    r.error = runner.NETWORK_HALT_MESSAGE
    monkeypatch.setattr(r, "_scan_pending", lambda: None)
    r._run()
    assert r.error == "" and store.job(job)["state"] == "done"


def test_unreachable_root_is_network_lost(tmp_path, monkeypatch):
    """検査するフォルダそのものに回線断で届かないときも、列挙を止めて再開で列挙し直す。"""
    monkeypatch.setattr(walker.os.path, "isdir", lambda p: False)
    monkeypatch.setattr(walker.os.path, "isfile", lambda p: False)

    def stat(p, *a, **k):
        raise _net_error(53)

    monkeypatch.setattr(walker.os, "stat", stat)
    entries = list(walker.walk([r"\nas01\share"]))
    assert len(entries) == 1 and entries[0].network_lost
    monkeypatch.undo()
    # 陽性対照: 本当に無いフォルダは回線断ではない
    gone = list(walker.walk([str(tmp_path / "nothing")]))
    assert len(gone) == 1 and gone[0].kind == "error" and not gone[0].network_lost


def test_stream_list_failure_is_not_silent(tmp_path, monkeypatch):
    """隠しストリームの一覧を取れないとき、黙って「無し」にせず項目に残す。回線断ならファイルごと読み直しに回す。"""
    from pii_checker import engine
    from pii_checker.engine import scan_file

    src = tmp_path / "a.txt"
    src.write_text("会議の議題\n", encoding="utf-8")
    for code, network in ((64, True), (5, False)):

        def fail(path, code=code):
            raise OSError(None, "x", path, code)

        monkeypatch.setattr(engine, "alternate_streams", fail)
        res = scan_file(str(src), ScanOptions(temp_dir=str(tmp_path)))
        ads = [i for i in res.items if i.depth == 1]
        assert res.network_lost is network
        assert ads and ads[0].status == Status.UNCHECKABLE
        if not network:
            assert "一覧を取れなかった" in ads[0].reason
    monkeypatch.undo()
    # 陽性対照: 一覧を取れれば項目は本体だけ
    res = scan_file(str(src), ScanOptions(temp_dir=str(tmp_path)))
    assert not res.network_lost and all(i.depth == 0 for i in res.items)


def test_stream_only_network_failure_is_reread(tmp_path):
    """隠しストリームの項目だけが回線断のファイルも、再開で読み直しに回す（depth で絞っていた）。"""
    store, job, r = _runner(tmp_path, [str(tmp_path / "a.txt")])
    top = ItemResult(path=str(tmp_path / "a.txt"), kind="text", status=Status.SCANNED)
    ads = _source_failure(str(tmp_path / "a.txt") + ":secret", _net_error(64))
    ads.depth = 1
    store.save_result(job, FileResult(top_path=str(tmp_path / "a.txt"), items=[top, ads]))
    assert store.files_with_reason_prefix(job, safeio.NETWORK_LOST_MSG) == [str(tmp_path / "a.txt")]


def test_verdict_interrupted_before_any_file():
    """列挙の最初で止めた（0 件）ときは「見つからない・アクセス権を確かめて」ではなく「途中で止めた・再開して」。"""
    from pii_checker.verdict import decide

    summary = {
        "item_status": {},
        "confidence": {},
        "files_total": 0,
        "files_done": 0,
        "folder_errors": 0,
        "links": 0,
        "files_with_findings": 0,
        "reused": 0,
    }
    v = decide(summary, "interrupted", target="cli")
    assert "途中で止めた" in v.title and "再開" in v.next_step
    assert "見つからない" in decide(summary, "done", target="cli").title  # 陽性対照: 終わって 0 件なら従来どおり


def test_web_resume_rereads_network_failures(tmp_path, monkeypatch):
    """Web 版の「再開」も、未検査が無くても回線断で検査不能のファイルがあれば始める（CLI の --resume と同じ）。"""
    from pii_checker.web.server import create_app

    db = str(tmp_path / "jobs.sqlite3")
    store = Store(db)
    p = str(tmp_path / "a.txt")
    job = store.create_job([str(tmp_path)], ScanOptions())
    store.add_files(job, [(p, 1, 0.0)])
    store.set_job(job, enum_done=1, state="done")
    store.save_result(job, _lost(p))
    app = create_app(db=db, token="t", allowed_hosts={"testserver"})
    started = []
    monkeypatch.setattr(runner.JobRunner, "start", lambda self: started.append(self.job_id))
    # 試験用の HTTP クライアント（httpx）を増やさないよう、再開のルートの関数を直接呼ぶ
    resume = next(r.endpoint for r in app.routes if getattr(r, "path", "") == "/api/jobs/{job_id}/resume")
    res = resume(job_id=job, payload={})
    assert res.get("ok") and "message" not in res and started == [job]
    # 陽性対照: 回線断の無い終わったジョブは始めない
    job2 = store.create_job([str(tmp_path)], ScanOptions())
    store.set_job(job2, enum_done=1, state="done")
    res = resume(job_id=job2, payload={})
    assert "未検査のファイルはありません" in res.get("message", "") and started == [job]


def test_volume_without_streams_skips_listing(tmp_path, monkeypatch):
    """ストリームを持てないボリューム（FAT・CD・一部の NAS）では一覧を取りに行かない（知らない番号で全件が検査不能にならない）。"""
    import ctypes

    from pii_checker import engine

    src = tmp_path / "a.txt"
    src.write_text("x", encoding="utf-8")
    monkeypatch.setattr(engine, "_volume_has_streams", lambda p: False)
    real_windll = ctypes.WinDLL

    class Boom:
        def __init__(self, *a, **k):
            self._k = real_windll(*a, **k)

        def __getattr__(self, name):
            if name == "FindFirstStreamW":
                raise AssertionError("ストリームを持てないボリュームで一覧を取りに行った")
            return getattr(self._k, name)

    monkeypatch.setattr(ctypes, "WinDLL", Boom)
    assert engine.alternate_streams(str(src)) == []
    monkeypatch.undo()
    # 陽性対照: NTFS の手元では、ストリームを持てると分かる
    assert engine._volume_has_streams(str(src)) is True

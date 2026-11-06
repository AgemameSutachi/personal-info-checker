"""tools/scan_timing.py（結果 DB の時間の内訳の集計）の試験。"""

import sqlite3
import sys
from pathlib import Path

import pytest

from pii_checker.store import Store

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import scan_timing  # noqa: E402


def _make_db(tmp_path, rows):
    """本物の版の DB（Store が作る形）に files の行を足す。rows は (path, elapsed, save, wall, scanned_at)。"""
    path = tmp_path / "jobs.sqlite3"
    Store(str(path))
    con = sqlite3.connect(path)
    for p, el, sv, wl, at in rows:
        con.execute(
            "INSERT INTO files (job_id, top_path, state, elapsed, save_elapsed, wall_elapsed, scanned_at, n_findings)"
            " VALUES ('J', ?, 'done', ?, ?, ?, ?, 0)",
            (p, el, sv, wl, at),
        )
    # 使い回しの行（時間の内訳が NULL）と別のジョブの行は数えない
    con.execute(
        "INSERT INTO files (job_id, top_path, state, elapsed, scanned_at) VALUES ('J', 'reused', 'done', 0, 50)"
    )
    con.execute(
        "INSERT INTO files (job_id, top_path, state, elapsed, save_elapsed, wall_elapsed, scanned_at)"
        " VALUES ('K', 'other', 'done', 99, 99, 99, 60)"
    )
    con.commit()
    con.close()
    return path


def test_summary_counts_work_save_and_wait(tmp_path):
    rows = [
        ("a", 2.0, 0.1, 2.5, 100.0),
        ("big", 1.0, 5.0, 1.0, 101.0),  # 保存の長いファイル
        ("b", 1.0, 0.1, 4.0, 102.0),  # その直後は待ちが伸びる
        ("c", 1.0, 0.1, 1.5, 110.0),
    ]
    db = _make_db(tmp_path, rows)
    with scan_timing.open_readonly(str(db)) as con:
        got = scan_timing.load_rows(con, "J")
    assert [r["top_path"] for r in got] == ["a", "big", "b", "c"]
    s = scan_timing.summarize(got, workers=2, top=2, after=1)
    assert s["files"] == 4
    # 手元を離れていた区間 [97.5,100]・[100,101]・[98,102]・[108.5,110] を重ねると 4.5＋1.5 秒（6.5 秒の空きは短いので数えない）
    assert s["whole"] == pytest.approx(12.5)
    assert s["span"] == pytest.approx(6.0)
    assert s["pauses"] == 0
    assert s["work"] == pytest.approx(5.0)
    assert s["save"] == pytest.approx(5.3)
    assert s["wait"] == pytest.approx(0.5 + 0 + 3.0 + 0.5)
    assert s["busy"] == pytest.approx(5.0 / 12.0)
    assert s["long_save_count"] == 1
    assert s["wait_after_long_save"] == pytest.approx(3.0)
    assert [r["path"] for r in s["long_saves"]] == ["big", "a"]
    text = scan_timing.report(s, after=1)
    assert "稼働 42%" in text and "big" in text
    assert "配られていない" not in text


def test_pause_is_excluded_but_long_file_is_not(tmp_path):
    """どのファイルも配られていない区間は除き、大きなファイルだけが走っていた区間は除かない。"""
    rows = [("a", 1.0, 0.0, 1.0, 100.0), ("b", 1.0, 0.0, 1.0, 300.0)]
    db = _make_db(tmp_path, rows)
    with scan_timing.open_readonly(str(db)) as con:
        got = scan_timing.load_rows(con, "J")
    s = scan_timing.summarize(got, workers=1)
    assert (s["whole"], s["span"], s["pauses"], s["paused"]) == (
        pytest.approx(201.0),
        pytest.approx(2.0),
        1,
        pytest.approx(199.0),
    )
    assert "1 区間" in scan_timing.report(s, after=20)

    db2 = _make_db(tmp_path / "x", rows + [("huge", 250.0, 0.0, 250.0, 350.0)])
    with scan_timing.open_readonly(str(db2)) as con:
        got = scan_timing.load_rows(con, "J")
    s = scan_timing.summarize(got, workers=1)
    assert s["pauses"] == 0
    assert s["span"] == pytest.approx(251.0)  # [99,350] は huge が走っていた


def test_empty_job_and_old_db(tmp_path):
    db = _make_db(tmp_path, [])
    with scan_timing.open_readonly(str(db)) as con:
        assert scan_timing.load_rows(con, "none") == []
    assert "ありません" in scan_timing.report(scan_timing.summarize([]), after=20)

    old = tmp_path / "old.sqlite3"
    con = sqlite3.connect(old)
    con.execute("CREATE TABLE files (job_id TEXT, top_path TEXT, state TEXT, elapsed REAL)")
    con.close()
    with scan_timing.open_readonly(str(old)) as con:
        with pytest.raises(ValueError, match="記録する前の版"):
            scan_timing.load_rows(con, "J")


def test_missing_db_is_not_created(tmp_path, capsys):
    missing = tmp_path / "nothing.sqlite3"
    assert scan_timing.main([str(missing), "J"]) == 1
    assert not missing.exists()
    assert "見つかりません" in capsys.readouterr().err

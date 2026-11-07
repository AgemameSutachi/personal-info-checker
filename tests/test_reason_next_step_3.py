"""想定外の失敗・開けなかった・見えなくなったときの理由の文が、使い手の次の手を先に出し、詳細を後ろへ回すかの試験。"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pii_checker import engine, safeio, sniff  # noqa: E402
from pii_checker.engine import _source_failure  # noqa: E402
from pii_checker.models import ScanOptions, Status  # noqa: E402


def _scan_raising(tmp_path, monkeypatch, error):
    """形式の読み手が error を投げるときの、最上位の項目を返す。"""

    def handler(ctx, blob, item, collector, depth):
        raise error

    monkeypatch.setattr(sniff, "handler_for", lambda kind: handler)
    p = tmp_path / "a.txt"
    p.write_text("会議の議題\n", encoding="utf-8")
    return engine.scan_file(str(p), ScanOptions(temp_dir=str(tmp_path))).items[0]


def test_unexpected_error_leads_with_next_step(tmp_path, monkeypatch):
    """想定外の失敗は、型の名前や内部の場所より先に、使い手が取れる手（写しを検査・取り直す・報告）を出す。"""
    item = _scan_raising(tmp_path, monkeypatch, KeyError("x"))
    assert item.status == Status.UNCHECKABLE
    assert item.reason.startswith("読み取りの途中で想定外のエラーになり、検査できなかった（要目視）。"), item.reason
    assert engine.UNEXPECTED_HINT in item.reason, item.reason
    head, detail = item.reason.split("（詳細: ", 1)
    assert "KeyError" not in head and ".py:" not in head, item.reason  # 詳細は後ろの括弧だけ
    assert detail.startswith("KeyError: 'x'・test_reason_next_step_3.py:"), item.reason


@pytest.mark.skipif(sys.platform != "win32", reason="winerror は Windows の例外だけが持つ")
@pytest.mark.parametrize(
    "winerror, expect, absent",
    [
        (32, "他のプログラムがこのファイルを使用中", "権限がない"),
        (33, "他のプログラムがこのファイルを使用中", "権限がない"),
        (5, "アクセスが拒否された（読む権限がない）。読む権限のあるアカウントで再検査するか", "使用中"),
        (65, "アクセスが拒否された（読む権限がない）。", "使用中"),  # NAS の共有の権限なし
        (23, "ディスクから読めなかった（ディスク・記録媒体の不具合の可能性。権限の問題ではない）", "権限がない"),
        (30, "ディスクから読めなかった", "権限がない"),
        (108, "ドライブがロックされていて読めなかった（BitLocker など）", "ディスク・記録媒体の不具合"),
        (16, "読む権限がないか、他のプログラムが使用中）", "ディスク・記録媒体の不具合"),  # 言い切らない番号
        (None, "読む権限がないか、他のプログラムが使用中）。そのファイルを開いているアプリを閉じるか", None),
    ],
)
def test_permission_error_splits_in_use_and_no_right(tmp_path, monkeypatch, winerror, expect, absent):
    """使用中（WinError 32/33）なら権限の話をせず、権限なし（WinError 5）なら使用中の話をしない。

    CRC の誤り（WinError 23）のような装置の誤りも PermissionError になるが、権限の話にしない。NAS の権限なし（65）は
    権限の話にし、ドライブのロック（108）はロックの解除を出す。番号が無い・言い切れない番号なら両方を挙げる。
    """
    error = OSError(13, "拒否", None, winerror) if winerror is not None else PermissionError(13, "拒否")
    assert isinstance(error, PermissionError)
    for item in (_scan_raising(tmp_path, monkeypatch, error), _source_failure("C:/x/a.txt", error)):
        assert item.status == Status.UNCHECKABLE
        assert expect in item.reason, item.reason
        head = item.reason.split("（詳細: ", 1)[0]
        if absent:
            assert absent not in head, item.reason
        assert "（詳細: " in item.reason, item.reason


def test_source_in_use_keeps_its_own_reason(tmp_path, monkeypatch):
    """理由の文を持つ SourceInUse（PermissionError の仲間）は、「アクセスが拒否された」で包まずにそのまま出す。"""
    item = _scan_raising(tmp_path, monkeypatch, safeio.SourceInUse(safeio.IN_USE_READ_MSG))
    assert item.reason == safeio.IN_USE_READ_MSG, item.reason


def test_not_found_names_next_step(tmp_path, monkeypatch):
    """検査の途中で見えなくなったファイルは、置き場所を確かめる手を出す。"""
    for item in (
        _scan_raising(tmp_path, monkeypatch, FileNotFoundError(2, "無い")),
        _source_failure("C:/x/a.txt", FileNotFoundError(2, "無い")),
    ):
        assert item.reason.startswith("ファイルが見つからない（検査中に移動・削除された可能性）。"), item.reason
        assert engine.NOT_FOUND_HINT in item.reason, item.reason


def test_source_unexpected_failure_names_next_step():
    """元のファイルを写せなかった想定外の失敗は、手元へ写して検査する手を出し、詳細を後ろへ回す。"""
    item = _source_failure("C:/x/a.txt", ValueError("変な中身"))
    assert item.reason.startswith("元のファイルを読めなかった。エクスプローラーで開けるかを確かめ"), item.reason
    assert item.reason.endswith("（詳細: ValueError: 変な中身）"), item.reason  # 投げていないので場所は無い


def test_source_disk_full_uses_temp_dir_hint():
    """写す先の一時フォルダが満杯なら、画面の項目名とコマンドの引数で次の手を出す。"""
    import errno

    item = _source_failure("C:/x/a.txt", OSError(errno.ENOSPC, "No space left on device"))
    assert engine.TEMP_DIR_HINT in item.reason, item.reason

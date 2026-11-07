"""7-Zip（7z.exe）が見つからないときの理由の文言の試験。

画面・Web の版には 7z.exe の場所の設定が無いので、「設定で指定」とは案内しない（指定できるのはコマンドの版の --sevenzip だけ）。
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pii_checker.formats.archive as archive  # noqa: E402
from pii_checker import archive_write as aw  # noqa: E402
from pii_checker.engine import scan_file  # noqa: E402
from pii_checker.models import ScanOptions, Status  # noqa: E402
from pii_checker.remedy_write import RemedyError  # noqa: E402


def assert_hint(reason: str) -> None:
    assert "設定で" not in reason, reason
    assert "Program Files" in reason and "--sevenzip" in reason, reason
    assert "_internal\\7z" in reason, reason  # 配布版は同梱しているので、欠けたときは配布物を置き直す


def test_rar_without_7z_names_what_the_user_can_do(tmp_path, monkeypatch):
    monkeypatch.setattr(archive, "find_7z", lambda configured: None)
    p = tmp_path / "a.rar"
    p.write_bytes(b"Rar!\x1a\x07\x00" + b"\x00" * 64)
    item = scan_file(str(p), ScanOptions()).items[0]
    assert item.status == Status.UNCHECKABLE
    assert "7-Zip（7z.exe）が要るが見つからない" in item.reason
    assert_hint(item.reason)


def test_disk_image_without_7z_names_what_the_user_can_do(tmp_path, monkeypatch):
    monkeypatch.setattr(archive, "find_7z", lambda configured: None)
    p = tmp_path / "disk.vhdx"
    p.write_bytes(b"vhdxfile" + b"\x00" * 64)
    item = scan_file(str(p), ScanOptions()).items[0]
    assert item.status == Status.UNCHECKABLE
    assert "ディスクイメージの展開には 7-Zip" in item.reason
    assert_hint(item.reason)


def test_remedy_without_7z_names_what_the_user_can_do(tmp_path):
    env = aw.ArchiveEnv(None, [], str(tmp_path))
    with pytest.raises(RemedyError) as e:
        aw._need_sevenzip(env, "7z 圧縮ファイルを作り直す")
    assert_hint(str(e.value))

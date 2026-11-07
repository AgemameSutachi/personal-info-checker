"""フォルダの列挙・FTP・DB のダンプ・PST の理由の文に、使い手が次にできることが書いてあるかの試験。"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pii_checker import walker  # noqa: E402
from pii_checker.engine import Uncheckable, scan_file  # noqa: E402
from pii_checker.models import ScanOptions, Status  # noqa: E402


def test_pst_unknown_encryption_names_next_step(tmp_path):
    """未対応の暗号化方式の PST は、書き出したメールを検査する・持ち主に確かめてもらう手を出す。"""
    head = bytearray(1024)
    head[0:4] = b"!BDN"
    head[10:12] = (23).to_bytes(2, "little")  # Unicode の PST
    head[0x201] = 0x10  # 0（なし）・1（圧縮可能）・2（強い暗号化）のどれでもない
    p = tmp_path / "mail.pst"
    p.write_bytes(bytes(head))
    item = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path))).items[0]
    assert item.status == Status.UNCHECKABLE, item.reason
    assert "未対応の暗号化方式（0x10" in item.reason, item.reason
    assert "書き出したもの（msg・eml）を検査するか" in item.reason, item.reason


def test_pg_custom_bad_header_names_next_step():
    """見出しの読めない custom 形式のダンプは、取り直す手を出す。"""
    from pii_checker.formats import dbdump

    with pytest.raises(Uncheckable) as e:
        dbdump._scan_pg_custom_bytes(b"NOTPG" + bytes(64), None, None)
    assert "元のファイルを取り直してください" in str(e.value)


def test_folder_permission_names_next_step(tmp_path, monkeypatch):
    """開く権限の無いフォルダは、権限のあるアカウントで検査する・権限を頼む手を出す。"""
    real = walker.os.scandir

    def deny(path):
        if str(path).rstrip("\\/").endswith("secret"):
            raise PermissionError(13, "アクセスが拒否されました")
        return real(path)

    (tmp_path / "secret").mkdir()
    monkeypatch.setattr(walker.os, "scandir", deny)
    errors = [e for e in walker.walk([str(tmp_path)]) if e.kind == "error"]
    assert errors, "権限の無いフォルダが記録されていない"
    assert "フォルダを開く権限がない" in errors[0].reason, errors[0].reason
    assert "管理者に読む権限を頼んでから再検査してください" in errors[0].reason, errors[0].reason

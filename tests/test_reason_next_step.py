"""検査不能の理由の文に、使い手が次にできることが書いてあるかの試験。

壊れた・暗号化されたファイルは「〜の可能性」だけで終わっていたので、作ったアプリで開いて
写しを作る・元のファイルを取り直す、といった次の手を添える。
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pii_checker.engine import scan_file  # noqa: E402
from pii_checker.models import ScanOptions, Status  # noqa: E402


@pytest.mark.parametrize(
    "name, data, start, hint",
    [
        # 見出しだけ SQLite で中身が壊れている（暗号化された SQLite も同じ形で読めない）
        (
            "app.sqlite",
            b"SQLite format 3\x00" + b"\xff" * 4096,
            "SQLite の表を読めなかった",
            "暗号を外した写しを作れるなら、その写しを検査してください",
        ),
        # 署名だけ OLE 複合文書（Office97-2003）で中身が壊れている
        (
            "old.doc",
            b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 600,
            "OLE 複合文書として開けなかった",
            "別名で保存した写しを検査してください",
        ),
    ],
)
def test_broken_file_reason_names_next_step(tmp_path, name, data, start, hint):
    p = tmp_path / name
    p.write_bytes(data)
    item = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path))).items[0]
    assert item.status == Status.UNCHECKABLE, item.reason
    assert start in item.reason and hint in item.reason, item.reason

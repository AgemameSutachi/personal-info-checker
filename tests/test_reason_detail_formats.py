"""形式ごとの検査不能の理由で、ライブラリの生の文（英語の例外文）が次の手より前に出ないかの試験。

「画像を開けなかった（…）: cannot identify image file …」のように生の文が理由の末尾に付き、英語の文が
次の手と同じ重みで読まれていた。次の手を先に書き、生の文は末尾の（詳細: …）へ回す。
"""

from __future__ import annotations

import gzip
import io
import os
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pii_checker.engine import scan_file  # noqa: E402
from pii_checker.models import ScanOptions, Status  # noqa: E402


def _assert_detail_last(reason: str, start: str, hint: str) -> None:
    """理由が start で始まり、次の手 hint が（詳細: …）より前にあり、詳細が末尾の1つだけであること。"""
    assert reason.startswith(start), reason
    assert hint in reason, reason
    assert "（詳細: " in reason and reason.endswith("）"), reason
    assert reason.index(hint) < reason.index("（詳細: "), reason
    assert reason.count("（詳細: ") == 1, reason
    assert "）: " not in reason, reason  # 生の文を「…）: 」で後ろに付ける古い形が残っていない


def _scan(tmp_path, name: str, data: bytes):
    p = tmp_path / name
    p.write_bytes(data)
    return scan_file(str(p), ScanOptions(temp_dir=str(tmp_path))).items


def test_unopenable_image(tmp_path):
    item = _scan(tmp_path, "photo.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)[0]
    assert item.status == Status.UNCHECKABLE, item.reason
    _assert_detail_last(item.reason, "画像を開けなかった（壊れているか未対応の形式）。", "取り直してください")


def test_broken_pdf(tmp_path):
    item = _scan(tmp_path, "broken.pdf", b"%PDF-1.7\n" + b"\x00\xff" * 64)[0]
    assert item.status == Status.UNCHECKABLE, item.reason
    _assert_detail_last(item.reason, "PDF を開けなかった（壊れている可能性）。", "別名で保存した写しを検査してください")


def test_broken_ole(tmp_path):
    item = _scan(tmp_path, "old.doc", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 600)[0]
    assert item.status == Status.UNCHECKABLE, item.reason
    _assert_detail_last(item.reason, "OLE 複合文書として開けなかった（壊れている可能性）。", "取り直してください")


def test_broken_parquet(tmp_path):
    pytest.importorskip("pyarrow")
    item = _scan(tmp_path, "t.parquet", b"PAR1" + b"\x00\xff" * 200 + b"\x10\x00\x00\x00PAR1")[0]
    assert item.status == Status.UNCHECKABLE, item.reason
    _assert_detail_last(item.reason, "parquet の表の定義を読めなかった（", "CSV に書き出した写しを検査してください")


def test_truncated_gzip_is_partial_with_next_step(tmp_path):
    """途中で切れた gz は、展開できた分を検査した簡易検査になり、取り直す手を出す。"""
    raw = gzip.compress(os.urandom(256 * 1024) + "090-1234-5678\n".encode() * 100)
    items = _scan(tmp_path, "data.txt.gz", raw[: len(raw) // 2])
    item = items[0]
    assert item.status == Status.PARTIAL, (item.status, item.reason)
    _assert_detail_last(item.reason, "圧縮データが途中で切れていた。展開できた ", "元のファイルを取り直してください")


def test_corrupt_zip_member(tmp_path):
    """書庫の中の1ファイルが壊れていて取り出せないときも、展開・取り直しの手を出す。"""
    buf = io.BytesIO()
    body = "氏名,電話\n山田太郎,090-1234-5678\n".encode() * 200
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("list.csv", body)
    data = bytearray(buf.getvalue())
    # 圧縮データの中ほどを壊す（ローカルの見出し 30 バイト＋名前の後ろ）
    start = 30 + len("list.csv") + 20
    for i in range(start, start + 40):
        data[i] ^= 0xFF
    items = _scan(tmp_path, "a.zip", bytes(data))
    failed = [i for i in items if i.path.endswith("list.csv") and i.status == Status.UNCHECKABLE]
    assert failed, [(i.path, i.status, i.reason) for i in items]
    _assert_detail_last(
        failed[0].reason, "zip から取り出せなかった（壊れている可能性）。", "展開したフォルダを検査してください"
    )

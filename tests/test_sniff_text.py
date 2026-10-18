"""先頭の数バイトだけで「対象外」「中身なし」に振らない試験（不具合の修正）。

個人情報入りのテキストが、たまたま動画・音声・実行ファイル・フォント・ダンプの目印と同じ文字で始まっても、
中身を読まずに対象外・検査済みにしてはいけない（そのフォルダが「個人情報なし」と言い切られてしまう）。
"""

import zipfile

import pytest

from pii_checker.engine import scan_file
from pii_checker.models import ScanOptions, Status

BODY = "氏名,電話,マイナンバー\n山田太郎,090-1234-5678,123456789018\n"

HEADS = ["MZ-100,型番", "ID3,タグ", "OggS,x", "fLaC,x", "FLV,x", "MThd,x", "PGDMP,メモ", "BM,x", "RIFF1234WAVE,x"]


@pytest.mark.parametrize("head", HEADS)
def test_text_with_binary_like_head_is_read(tmp_path, head):
    p = tmp_path / "list.csv"
    p.write_text(head + "\n" + BODY, encoding="utf-8")
    res = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path)))
    top = res.items[0]
    found = {k for it in res.items for k in it.finding_counts}
    assert top.status != Status.OUT_OF_SCOPE, top.kind
    assert {"phone", "my_number"} <= found, (top.kind, top.status, found)


def test_ftyp_and_mpeg_ts_like_text_is_read(tmp_path):
    # 4〜7 バイト目が ftyp・188 バイトごとに G が来る固定長のテキスト
    ftyp = "1234ftypmemo\n" + BODY
    row = ("G" + "x" * 186 + "\n") * 3
    for name, text in (("a.txt", ftyp), ("b.txt", row + BODY)):
        p = tmp_path / name
        p.write_text(text, encoding="utf-8")
        res = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path)))
        assert {"phone", "my_number"} <= {k for it in res.items for k in it.finding_counts}, name


def test_real_media_is_still_out_of_scope(tmp_path):
    """陽性対照: 本物のバイナリ（NUL を含む）は従来どおり対象外。"""
    p = tmp_path / "a.mp3"
    p.write_bytes(b"ID3\x03\x00\x00\x00\x00\x0f\x76" + bytes(range(256)) * 20)
    res = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path)))
    assert res.items[0].status == Status.OUT_OF_SCOPE


def test_split_continuation_inside_archive_is_not_out_of_scope(tmp_path):
    """アーカイブの中の分割の続きは、1つ目の有無を確かめられないので対象外にしない（言い切らない）。"""
    import os

    z = tmp_path / "x.zip"
    with zipfile.ZipFile(z, "w") as f:
        f.writestr("backup.7z.002", os.urandom(512))
    res = scan_file(str(z), ScanOptions(temp_dir=str(tmp_path)))
    inner = [it for it in res.items if it.depth == 1]
    assert inner and inner[0].status == Status.UNCHECKABLE

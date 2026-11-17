"""Outlook のデータファイル（PST/OST）の文字列走査の試験。

本物の PST は作れないので、見出し（版・暗号化の印）だけを本物の位置に置き、後ろへ文字列を並べたものを使う。
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pii_checker import engine  # noqa: E402
from pii_checker.formats import pst  # noqa: E402
from pii_checker.models import ScanOptions, Status  # noqa: E402

UNICODE = 23  # Unicode の PST（版 23 以上）
ANSI = 14  # 旧い ANSI の PST

# 置換表は「暗号化された値の位置に元の値」なので、その逆が暗号化
_ENCRYPT = bytearray(256)
for _i, _v in enumerate(pst._COMPRESSIBLE):
    _ENCRYPT[_v] = _i
_ENCRYPT = bytes(_ENCRYPT)

BODY = b"\x00\x00From: taro.yamada@example.com TEL 090-1234-5678\x00\x00"


def _write_pst(path: Path, version: int, crypt: int, body: bytes) -> Path:
    head = bytearray(1024)
    head[0:4] = b"!BDN"
    head[10:12] = version.to_bytes(2, "little")
    if version >= UNICODE:
        head[0x201] = crypt
    else:
        head[0x1CD] = crypt
        head[0x201] = 2  # ANSI では読まない位置（ここを読むと「強い暗号化」と誤る）
    path.write_bytes(bytes(head) + body)
    return path


def _scan(path: Path, tmp_path: Path):
    res = engine.scan_file(str(path), ScanOptions(temp_dir=str(tmp_path), reuse=False))
    assert len(res.items) == 1
    return res.items[0]


def _types(item) -> set[str]:
    return {f.pii_type for f in item.findings}


def test_unicode_plain_pst_is_partial_with_findings(tmp_path):
    item = _scan(_write_pst(tmp_path / "mail.pst", UNICODE, 0, BODY), tmp_path)
    assert item.kind == "Outlook データファイル（Unicode PST/OST）"
    assert item.status == Status.PARTIAL, item.reason
    assert "添付ファイル" in item.reason and "msg/eml" in item.reason
    assert item.method == "件名・本文・宛先などの文字列を走査"
    assert {"email", "phone"} <= _types(item), item.findings


def test_compressible_encryption_is_undone(tmp_path):
    item = _scan(_write_pst(tmp_path / "mail.pst", UNICODE, 1, BODY.translate(_ENCRYPT)), tmp_path)
    assert item.status == Status.PARTIAL, item.reason
    assert item.method.startswith("置換暗号を戻して")
    assert {"email", "phone"} <= _types(item), item.findings


def test_encrypted_body_is_not_found_without_undoing(tmp_path):
    # 陰性対照: 同じ暗号化した中身を「暗号なし」の印で置くと拾えない（上の試験が置換を戻したから拾えたことの確かめ）
    item = _scan(_write_pst(tmp_path / "mail.pst", UNICODE, 0, BODY.translate(_ENCRYPT)), tmp_path)
    assert item.status == Status.PARTIAL, item.reason
    assert not ({"email", "phone"} & _types(item)), item.findings


def test_compressible_utf16_strings_are_found(tmp_path):
    # Unicode の PST は文字列を UTF-16LE で持つ
    body = b"\x00\x00" + "連絡先 taro.yamada@example.com".encode("utf-16-le") + b"\x00\x00"
    item = _scan(_write_pst(tmp_path / "mail.ost", UNICODE, 1, body.translate(_ENCRYPT)), tmp_path)
    assert item.status == Status.PARTIAL, item.reason
    assert "email" in _types(item), item.findings


def test_strong_encryption_is_uncheckable(tmp_path):
    item = _scan(_write_pst(tmp_path / "mail.pst", UNICODE, 2, BODY), tmp_path)
    assert item.status == Status.UNCHECKABLE, item.reason
    assert "「強い暗号化」の PST" in item.reason
    assert item.findings == []
    assert item.kind == "Outlook データファイル（Unicode PST/OST）"


def test_ansi_pst_reads_its_own_encryption_byte(tmp_path):
    item = _scan(_write_pst(tmp_path / "old.pst", ANSI, 1, BODY.translate(_ENCRYPT)), tmp_path)
    assert item.kind == "Outlook データファイル（ANSI PST/OST）"
    assert item.status == Status.PARTIAL, item.reason
    assert {"email", "phone"} <= _types(item), item.findings


def test_ansi_pst_strong_encryption_is_uncheckable(tmp_path):
    path = _write_pst(tmp_path / "old.pst", ANSI, 2, BODY)
    item = _scan(path, tmp_path)
    assert item.status == Status.UNCHECKABLE, item.reason
    assert "「強い暗号化」の PST" in item.reason

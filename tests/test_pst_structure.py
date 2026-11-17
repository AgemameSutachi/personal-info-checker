"""Outlook のデータファイル（PST/OST）の構造を読む検査の試験。

試験用の書き手（pst_writer）で作った PST を使う。読み手が実物の PST を読めることは、公開の見本で別に確かめた。
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from pst_writer import (  # noqa: E402
    PT_BINARY,
    PT_MV_UNICODE,
    PT_STRING8,
    PT_SYSTIME,
    PT_UNICODE,
    Attachment,
    Folder,
    Message,
    build_pst,
)

from pii_checker import engine  # noqa: E402
from pii_checker.formats import pst_ndb  # noqa: E402
from pii_checker.models import ScanOptions, Status  # noqa: E402


def _scan(tmp_path: Path, data: bytes, name: str = "mail.pst"):
    p = tmp_path / name
    p.write_bytes(data)
    res = engine.scan_file(str(p), ScanOptions(temp_dir=str(tmp_path), reuse=False))
    return res.items


def _top(items):
    return items[0]


def _types(item) -> set[str]:
    return {f.pii_type for f in item.findings}


def _mail(body: str = "", subject: str = "打ち合わせ", **extra) -> Message:
    props = {0x0037: (PT_UNICODE, subject)}
    if body:
        props[0x1000] = (PT_UNICODE, body)
    for pid, v in extra.items():
        props[int(pid[1:], 16)] = v
    return Message(props=props)


@pytest.mark.parametrize("version", [23, 36])
@pytest.mark.parametrize("crypt", [0, 1])
def test_body_and_recipients_are_read_as_structure(tmp_path, version, crypt):
    m = _mail("折り返しは 090-1234-5678 まで")
    m.recipients = [{0x3001: "宛先の人", 0x3003: "hanako.suzuki@example.com"}]
    item = _top(_scan(tmp_path, build_pst([Folder("受信トレイ", [m])], version, crypt)))
    assert item.status == Status.SCANNED, item.reason
    assert item.method == "構造を読んで件名・本文・宛先・添付を検査"
    assert {"email", "phone"} <= _types(item), item.findings
    locs = {f.pii_type: f.location for f in item.findings}
    assert locs["phone"].startswith("受信トレイ/1件目の本文"), locs
    assert locs["email"] == "受信トレイ/1件目の宛先表のアドレス", locs


def test_compressible_encryption_is_needed_to_read(tmp_path):
    # 陰性対照: 置換暗号で書いた PST の印を「暗号なし」に変えると、B 木（暗号化されない）は読めるが
    # フォルダとメールの中身を読めず、文字列の走査でも暗号のままの本文は拾えない
    data = bytearray(build_pst([Folder("受信トレイ", [_mail("TEL 090-1234-5678")])], 23, 1))
    data[0x201] = 0
    item = _top(_scan(tmp_path, bytes(data)))
    assert item.status == Status.PARTIAL, item.reason
    assert "2 件の項目" in item.reason
    assert "phone" not in _types(item), item.findings


def test_file_attachment_is_scanned_as_inner_file(tmp_path):
    m = _mail("添付をご確認ください")
    m.attachments = [Attachment("名簿.csv", "氏名,電話\n山田太郎,090-1111-2222\n".encode("utf-8"))]
    items = _scan(tmp_path, build_pst([Folder("受信トレイ", [m])]))
    top = _top(items)
    assert top.status == Status.SCANNED, top.reason
    inner = [it for it in items if it.path.endswith("!受信トレイ/1件目/名簿.csv")]
    assert len(inner) == 1, [it.path for it in items]
    assert "phone" in _types(inner[0]), inner[0].findings


def test_large_attachment_split_into_blocks_is_joined(tmp_path):
    # 外部ブロック1つ（8176 バイト）に収まらない添付は XBLOCK で分かれる。境目をまたぐ値も拾う
    pad = "あ" * 2724 + "\n"  # UTF-8 で 8173 バイト＋改行
    text = pad + "連絡先 090-3333-4444\n" + "い" * 4000
    m = _mail()
    m.attachments = [Attachment("memo.txt", text.encode("utf-8"))]
    items = _scan(tmp_path, build_pst([Folder("受信トレイ", [m])]))
    inner = [it for it in items if it.path.endswith("/memo.txt")]
    assert len(inner) == 1, [it.path for it in items]
    assert inner[0].size == len(text.encode("utf-8"))
    assert "phone" in _types(inner[0]), inner[0].findings


def test_attachment_over_memory_limit_goes_through_temp_file(tmp_path, monkeypatch):
    from pii_checker.formats import pst

    monkeypatch.setattr(pst, "IN_MEMORY_LIMIT", 1000)
    text = "x" * 9000 + "\n電話 090-3333-4444\n"
    m = _mail()
    m.attachments = [Attachment("big.txt", text.encode("utf-8"))]
    items = _scan(tmp_path, build_pst([Folder("受信トレイ", [m])]))
    inner = [it for it in items if it.path.endswith("/big.txt")]
    assert len(inner) == 1 and inner[0].size == len(text.encode("utf-8")), [it.path for it in items]
    assert "phone" in _types(inner[0]), inner[0].findings


def test_embedded_message_is_followed(tmp_path):
    inner_mail = _mail("転送元: taro.yamada@example.com")
    inner_mail.attachments = [Attachment("note.txt", "TEL 03-1234-5678".encode("utf-8"))]
    m = _mail("転送します")
    m.attachments = [Attachment("元のメール", message=inner_mail)]
    items = _scan(tmp_path, build_pst([Folder("受信トレイ", [m])]))
    top = _top(items)
    assert top.status == Status.SCANNED, top.reason
    emails = [f for f in top.findings if f.pii_type == "email"]
    assert emails and emails[0].location.startswith("受信トレイ/1件目に添付したメールの本文"), emails
    inner = [it for it in items if it.path.endswith("!受信トレイ/1件目に添付したメール/note.txt")]
    assert len(inner) == 1 and "phone" in _types(inner[0]), [it.path for it in items]


def test_html_and_rtf_bodies_are_read(tmp_path):
    import compressed_rtf

    rtf = compressed_rtf.compress(rb"{\rtf1\ansi TEL 090-5555-6666\par}")
    m = _mail(
        x1013=(PT_BINARY, b"<html><body><p>hanako@example.com</p></body></html>"),
        x1009=(PT_BINARY, rtf),
    )
    item = _top(_scan(tmp_path, build_pst([Folder("受信トレイ", [m])])))
    assert item.status == Status.SCANNED, item.reason
    locs = {f.pii_type: f.location for f in item.findings}
    assert locs.get("email", "").startswith("受信トレイ/1件目のHTML本文"), locs
    assert locs.get("phone", "").startswith("受信トレイ/1件目のRTF本文"), locs


def test_ansi_strings_and_multi_value_strings(tmp_path):
    m = _mail(
        x0C1A=(PT_STRING8, "山田 太郎"),
        x0C1F=(PT_STRING8, "taro@example.co.jp"),
        x8010=(PT_MV_UNICODE, ["メモ", "携帯 080-7777-8888"]),
    )
    item = _top(_scan(tmp_path, build_pst([Folder("連絡先", [m])])))
    locs = {f.pii_type: f.location for f in item.findings}
    assert locs.get("email") == "連絡先/1件目の差出人のアドレス", locs
    assert locs.get("phone") == "連絡先/1件目の追加の欄（0x8010）", locs


def test_subject_is_not_put_in_location_but_date_is(tmp_path):
    # 件名は個人情報を含みうるので場所の文字に使わず、受信日時で探せるようにする
    ft = (13_000_000_000 * 10_000_000) + 116_444_736_000_000_000  # 2381 年ごろ（値は何でもよい）
    m = _mail("TEL 090-1234-5678", subject="山田太郎様の件", x0E06=(PT_SYSTIME, struct.pack("<Q", ft)))
    item = _top(_scan(tmp_path, build_pst([Folder("受信トレイ", [m])])))
    assert item.findings
    for f in item.findings:
        assert "山田" not in f.location, f.location
    phone = [f for f in item.findings if f.pii_type == "phone"][0]
    assert phone.location.startswith("受信トレイ/1件目（"), phone.location


def test_broken_message_falls_back_to_strings_for_its_part(tmp_path):
    good = _mail("TEL 090-1234-5678")
    bad = _mail("hanako.suzuki@example.com")
    bad.broken = True
    item = _top(_scan(tmp_path, build_pst([Folder("受信トレイ", [good, bad])])))
    assert item.status == Status.PARTIAL, item.reason
    assert "1 件の項目" in item.reason and "msg/eml" in item.reason
    assert item.method == "構造を読んで件名・本文・宛先・添付を検査＋文字列の走査"
    # 読めた分は構造で、読めなかったメールの文字は全体の走査で拾う
    assert {"email", "phone"} <= _types(item), item.findings


def test_broken_rtf_does_not_skip_the_rest_of_the_message(tmp_path):
    m = _mail("hanako@example.com", x1009=(PT_BINARY, b"\x00" * 32))  # 圧縮 RTF の見出しになっていない
    m.recipients = [{0x3003: "taro@example.com"}]
    m.attachments = [Attachment("memo.txt", "TEL 090-1234-5678".encode("utf-8"))]
    items = _scan(tmp_path, build_pst([Folder("受信トレイ", [m])]))
    top = _top(items)
    assert top.status == Status.PARTIAL and "1 件の項目" in top.reason, top.reason
    assert {f.location for f in top.findings if f.pii_type == "email"} >= {
        "受信トレイ/1件目の本文 1行目",
        "受信トレイ/1件目の宛先表のアドレス",
    }, top.findings
    inner = [it for it in items if it.path.endswith("/memo.txt")]
    assert len(inner) == 1 and "phone" in _types(inner[0])


def test_attachment_without_temp_space_is_uncheckable_alone(tmp_path, monkeypatch):
    from pii_checker.formats import pst

    monkeypatch.setattr(pst, "IN_MEMORY_LIMIT", 10)

    def no_space(self, nbytes, what=""):
        raise engine.Uncheckable("一時フォルダの空きが足りない")

    monkeypatch.setattr(engine.ScanContext, "ensure_space", no_space)
    m = _mail("TEL 090-1234-5678")
    m.attachments = [Attachment("big.txt", b"x" * 100)]
    items = _scan(tmp_path, build_pst([Folder("受信トレイ", [m])]))
    top = _top(items)
    assert top.status == Status.SCANNED and "phone" in _types(top), top.reason
    inner = [it for it in items if it.path.endswith("/big.txt")]
    assert len(inner) == 1 and inner[0].status == Status.UNCHECKABLE, [(it.path, it.status) for it in items]
    assert "空きが足りない" in inner[0].reason


def test_ole_attachment_is_scanned_as_file(tmp_path):
    m = _mail()
    m.attachments = [Attachment("oleobj.txt", "TEL 090-2222-3333".encode("utf-8"), ole=True)]
    items = _scan(tmp_path, build_pst([Folder("受信トレイ", [m])]))
    assert _top(items).status == Status.SCANNED, _top(items).reason
    inner = [it for it in items if it.path.endswith("/oleobj.txt")]
    assert len(inner) == 1 and "phone" in _types(inner[0]), [it.path for it in items]


def test_too_deep_embedded_messages_are_reported(tmp_path):
    from pii_checker.formats import pst

    deepest = _mail("hanako@example.com")
    m = deepest
    for _ in range(pst._MAX_EMBED + 1):
        outer = _mail("転送")
        outer.attachments = [Attachment("転送", message=m)]
        m = outer
    item = _top(_scan(tmp_path, build_pst([Folder("受信トレイ", [m])])))
    # 黙って飛ばさず、読めなかった項目として知らせる（文字列の走査で補う）
    assert item.status == Status.PARTIAL, item.reason
    assert "1 件の項目" in item.reason


def test_xblock_pointing_same_block_twice_is_rejected():
    data = struct.pack("<BBHI", 1, 1, 2, 16) + struct.pack("<QQ", 8, 8)
    with pytest.raises(pst_ndb.PstFormatError):
        pst_ndb.PstFile._children(None, 6, data)


def test_bth_loop_is_rejected():
    from pst_writer import _heap

    # BTH の見出し（1段・根は番地 0x40）と、自分自身を指す中間の記録
    items = [struct.pack("<BBBBI", 0xB5, 2, 6, 1, 2 << 5), struct.pack("<HI", 1, 2 << 5)]
    heap = pst_ndb.Heap.__new__(pst_ndb.Heap)
    heap.blocks = [_heap(0xBC, items, 0)]
    with pytest.raises(pst_ndb.PstFormatError):
        heap.bth(1 << 5)


def test_compressed_block_cannot_inflate_beyond_its_size():
    import io
    import zlib

    bomb = zlib.compress(b"\x00" * 1_000_000)
    pst = pst_ndb.PstFile.__new__(pst_ndb.PstFile)
    pst.f = io.BytesIO(b"\x00" * 16 + bomb)
    pst.size = 16 + len(bomb)
    pst.bbt = {4: (16, len(bomb), 4096)}
    with pytest.raises(pst_ndb.PstFormatError):
        pst._raw_block(4)


def test_reader_rejects_loops_and_out_of_file_pointers(tmp_path):
    import io

    data = bytearray(build_pst([Folder("受信トレイ", [_mail("x")])]))
    nbt_ib = struct.unpack_from("<Q", data, 0xE0)[0]
    # B 木のページの印を壊すと、読み手は果てしなく辿らずに PstFormatError を投げる
    data[nbt_ib + 496] = 0x00
    with pytest.raises(pst_ndb.PstFormatError):
        pst_ndb.PstFile(io.BytesIO(bytes(data)), 23, 0)
    data = bytearray(build_pst([Folder("受信トレイ", [_mail("x")])]))
    struct.pack_into("<Q", data, 0xE0, len(data) + 4096)
    with pytest.raises(pst_ndb.PstFormatError):
        pst_ndb.PstFile(io.BytesIO(bytes(data)), 23, 0)

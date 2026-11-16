"""OLE 複合文書（Office 97-2003・Outlook の msg ほか）の読み取りの試験。

これまで doc・xls・ppt・msg の検体は本物の Office で作る台本（make_corpus.py）でしか確かめておらず、
CI では handle_ole の構造の読み取りが1行も通っていなかった。試験用の最小の CFB の書き手（olebuild.py）で
検体を組み立て、種類ごとの読み方・埋め込みの取り出し・読めないときの扱いを確かめる。
"""

from __future__ import annotations

import io
import struct
import sys
import zipfile
import zlib
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import olebuild as ob  # noqa: E402
from pii_checker.engine import scan_file  # noqa: E402
from pii_checker.formats import office  # noqa: E402
from pii_checker.models import ScanOptions, Status  # noqa: E402

PHONE = "090-1234-5678"
PHONE2 = "03-1234-5678"
EMAIL = "taro.yamada@example.com"


def _scan(tmp_path, name: str, data: bytes):
    p = tmp_path / name
    p.write_bytes(data)
    return scan_file(str(p), ScanOptions(temp_dir=str(tmp_path))).items


def _types(item) -> set[str]:
    return set(item.finding_counts)


def _locations(item, pii_type: str) -> list[str]:
    return [f.location for f in item.findings if f.pii_type == pii_type]


def _child(items, part: str):
    found = [it for it in items[1:] if part in it.path]
    assert found, [it.path for it in items]
    return found[0]


# ------------------------------------------------------------------ 試験の道具そのもの


def test_olebuild_round_trip_through_mini_and_regular_sectors():
    """書き手の往復: ミニストリーム（4096 バイト未満）と通常のセクター（以上）の両方、FAT が複数セクターになる大きさ。"""
    import olefile

    sizes = [0, 1, 63, 64, 4095, 4096, 4097, 20000]
    streams = {f"S{n}": bytes((i * 7 + n) % 256 for i in range(n)) for n in sizes}
    streams.update({f"Many/P{i:03d}": bytes([i % 256]) * 4000 for i in range(150)})  # FAT が2セクター以上
    ole = olefile.OleFileIO(ob.build(streams))
    for path, data in streams.items():
        assert ole.openstream(path).read() == data, path


def test_large_doc_body_in_regular_sectors(tmp_path):
    wd, table = ob.doc_stream([("あ" * 3000 + f"\r電話 {PHONE}\r", False)])
    assert len(wd) >= ob.CUTOFF
    item = _scan(tmp_path, "long.doc", ob.build({"WordDocument": wd, "1Table": table}))[0]
    assert item.status == Status.SCANNED, item.reason
    assert any(loc.startswith("本文 ") for loc in _locations(item, "phone")), item.findings


# ------------------------------------------------------------------ Word 97-2003


def test_doc_piece_table_reads_both_unicode_and_compressed_pieces(tmp_path):
    wd, table = ob.doc_stream(
        [(f"連絡先は {PHONE} です\r", False), (f"mail: {EMAIL}\r", True)],
        prc=b"\x00\x00\x00",  # 書式の塊（Prc）は読み飛ばす
    )
    items = _scan(tmp_path, "letter.doc", ob.build({"WordDocument": wd, "1Table": table}))
    item = items[0]
    assert item.status == Status.SCANNED, item.reason
    assert item.kind == "Word 97-2003（doc）"
    assert item.method.startswith("本文（piece table"), item.method
    assert {"phone", "email"} <= _types(item)
    # 位置まで見る（ASCII のメールは生データ走査でも拾えるので、種類だけでは圧縮 piece を読めたか分からない）
    assert all(loc.startswith("本文 ") for loc in _locations(item, "phone")), item.findings
    assert all(loc.startswith("本文 ") for loc in _locations(item, "email")), item.findings


def test_doc_control_characters_become_separators():
    """段落・セル・フィールドの制御文字が区切りになり、隣の値とつながらない。"""
    import olefile

    wd, table = ob.doc_stream([("A\x07B\rC\x13D\x15", False)])
    ole = olefile.OleFileIO(ob.build({"WordDocument": wd, "1Table": table}))
    assert office._doc_text(ole) == "A\tB\nC D "


@pytest.mark.parametrize(
    "patch, message",
    [
        (lambda wd, tb: (wd[:2] + struct.pack("<H", 100) + wd[4:], tb), "Word 6.0/95 以前の形式"),
        (lambda wd, tb: (wd, tb[:16] + b"\x05" + tb[17:]), "piece table が見つからない"),
        (lambda wd, tb: (wd[:0x800], tb), "本文の文字を取り出せなかった"),
    ],
)
def test_doc_unreadable_body_falls_back_to_raw_sweep(tmp_path, patch, message):
    wd, table = ob.doc_stream([(f"電話 {PHONE}", False)])
    wd, table = patch(wd, table)
    item = _scan(tmp_path, "old.doc", ob.build({"WordDocument": wd, "1Table": table}))[0]
    assert item.kind == "Word（doc）"
    assert any(message in n for n in item.notes), item.notes
    # 構造として読めなかったので簡易検査として残す（読めたことにしない）
    assert item.status == Status.PARTIAL, item.reason
    assert "構造を解釈していない" in item.reason


# ------------------------------------------------------------------ Excel 97-2003


def test_xls_cells_are_read_with_sheet_and_cell_location(tmp_path):
    wb = ob.xls_workbook({"名簿": [["氏名", "電話"], ["山田太郎", PHONE]]})
    item = _scan(tmp_path, "list.xls", ob.build({"Workbook": wb}))[0]
    assert item.status == Status.SCANNED, item.reason
    assert item.kind == "Excel 97-2003（xls）"
    assert item.method.startswith("xlrd で全シートのセル"), item.method
    assert "名簿!B2" in _locations(item, "phone"), item.findings


def test_xls_book_stream_is_excel95(tmp_path):
    wb = ob.xls_workbook({"Sheet1": [["電話"], [PHONE]]})
    item = _scan(tmp_path, "old95.xls", ob.build({"Book": wb}))[0]
    assert item.kind == "Excel 5.0/95（xls）"
    assert item.status == Status.SCANNED, item.reason
    assert "Sheet1!A2" in _locations(item, "phone"), item.findings  # xlrd でセルとして読めた


def test_xls_broken_workbook_stream_is_partial(tmp_path):
    item = _scan(tmp_path, "broken.xls", ob.build({"Workbook": b"\x01\x02" * 40 + f" {PHONE} ".encode()}))[0]
    assert any("xlrd でセルを読めなかった" in n for n in item.notes), item.notes
    assert item.status == Status.PARTIAL, item.reason
    assert "phone" in _types(item)  # 生データ走査では拾う


def test_embedded_workbook_inside_other_document(tmp_path):
    wd, table = ob.doc_stream([("本文", False)])
    wb = ob.xls_workbook({"表": [["電話"], [PHONE]]})
    data = ob.build({"WordDocument": wd, "1Table": table, "ObjectPool/_1/Workbook": wb})
    item = _scan(tmp_path, "with_table.doc", data)[0]
    assert any(
        loc.startswith("埋め込み表 ObjectPool/_1/Workbook 表!") for loc in _locations(item, "phone")
    ), item.findings


def _biff2(rtype: int, body: bytes) -> bytes:
    return struct.pack("<HH", rtype, len(body)) + body


def test_xls_biff2_legacy_cells(tmp_path):
    """Excel 2.x の BIFF は OLE に入らずレコードがそのまま並ぶ。"""
    rows = [["電話"], [PHONE]]
    data = _biff2(0x0009, struct.pack("<HH", 0x0002, 0x0010))
    data += _biff2(0x0000, struct.pack("<HHHH", 0, len(rows), 0, 1))
    for r, row in enumerate(rows):
        for c, v in enumerate(row):
            raw = v.encode("cp932")
            data += _biff2(0x0004, struct.pack("<HH", r, c) + b"\x00\x00\x00" + bytes([len(raw)]) + raw)
    data += _biff2(0x000A, b"")
    item = _scan(tmp_path, "ancient.xls", data)[0]
    assert item.status == Status.SCANNED, item.reason
    assert item.method == "xlrd でセル＋生データ走査"
    assert any(loc.endswith("!A2") for loc in _locations(item, "phone")), item.findings


def test_xls_biff_legacy_unreadable_is_uncheckable_but_raw_sweeps(tmp_path):
    data = b"\x09\x04" + b"\xff" * 30 + f" {PHONE} ".encode() + b"\xff" * 30
    item = _scan(tmp_path, "ancient.xls", data)[0]
    assert item.status == Status.UNCHECKABLE, item.reason
    assert item.reason.startswith("古い Excel 形式のセルを構造として読めず")
    assert item.method == "生データ走査"
    assert any("xlrd でセルを読めなかった" in n for n in item.notes), item.notes


# ------------------------------------------------------------------ PowerPoint 97-2003


def _ppt(*records: bytes) -> bytes:
    return ob.ppt_container(0x03E8, ob.ppt_container(0x03F0, *records))


def test_ppt_texts_from_nested_containers(tmp_path):
    doc = _ppt(
        ob.ppt_record(0x0FA0, f"電話 {PHONE}".encode("utf-16-le")),
        ob.ppt_record(0x0FA8, f"mail {EMAIL}".encode("latin-1")),
        ob.ppt_record(0x0FBA, "CString の文字".encode("utf-16-le")),  # 0x0FBA は CString（表題などの文字）
    )
    item = _scan(tmp_path, "slides.ppt", ob.build({"PowerPoint Document": doc}))[0]
    assert item.status == Status.SCANNED, item.reason
    assert item.kind == "PowerPoint 97-2003（ppt）"
    assert item.method.startswith("スライド・ノートの文字 3 件・埋め込み 0 件"), item.method
    assert {"phone", "email"} <= _types(item)
    assert all(loc.startswith("スライドの文字 ") for loc in _locations(item, "phone"))


def test_ppt_embedded_objects_compressed_and_raw(tmp_path):
    inner = f"埋め込みの電話 {PHONE2}\n".encode("utf-8")
    compressed = struct.pack("<I", len(inner)) + zlib.compress(inner)
    doc = _ppt(
        ob.ppt_record(0x1011, compressed, inst=1),
        ob.ppt_record(0x1011, b"plain object " + PHONE.encode()),
        ob.ppt_record(0x1011, struct.pack("<I", 10) + b"not zlib data", inst=1),  # 解けなければそのまま渡す
    )
    items = _scan(tmp_path, "objects.ppt", ob.build({"PowerPoint Document": doc}))
    assert "埋め込み 3 件" in items[0].method, items[0].method
    assert "phone" in _types(_child(items, "埋め込みオブジェクト1"))
    assert "phone" in _types(_child(items, "埋め込みオブジェクト2"))
    _child(items, "埋め込みオブジェクト3")
    # 解けなかった圧縮は、レコードの中身をそのまま渡す
    _, objects = office._ppt_parse(doc)
    assert objects[2] == struct.pack("<I", 10) + b"not zlib data"


def test_ppt_embedded_object_over_limit_is_noted(tmp_path, monkeypatch):
    monkeypatch.setattr(office, "PPT_OBJECT_LIMIT", 1024)
    inner = b"A" * 4096
    doc = _ppt(
        ob.ppt_record(0x0FA0, f"電話 {PHONE}".encode("utf-16-le")),
        ob.ppt_record(0x1011, struct.pack("<I", len(inner)) + zlib.compress(inner), inst=1),
    )
    item = _scan(tmp_path, "bomb.ppt", ob.build({"PowerPoint Document": doc}))[0]
    assert any("スライドを構造として読めなかった" in n and "展開上限" in n for n in item.notes), item.notes
    assert item.status == Status.PARTIAL, item.reason
    assert "phone" in _types(item)  # 生データ走査では拾う


# ------------------------------------------------------------------ Outlook msg


def test_msg_subject_body_and_attachment(tmp_path):
    streams = ob.msg_streams(f"至急 {EMAIL}", f"折り返しは {PHONE} まで", [("memo.txt", f"控え {PHONE2}\n".encode())])
    items = _scan(tmp_path, "mail.msg", ob.build(streams))
    item = items[0]
    assert item.status == Status.SCANNED, item.reason
    assert item.kind == "Outlook メール（msg）"
    assert item.method.startswith("件名・差出人・宛先・本文・添付"), item.method
    assert "件名" in _locations(item, "email"), item.findings
    assert any(loc.startswith("本文 ") for loc in _locations(item, "phone")), item.findings
    assert "phone" in _types(_child(items, "mail.msg!memo.txt"))


def test_msg_unreadable_structure_is_partial(tmp_path):
    # 添付の属性（添付の方法など）が空の msg は extract_msg が規格違反として断る
    streams = ob.msg_streams("件名", f"本文 {PHONE}")
    streams["__attach_version1.0_#00000000/__properties_version1.0"] = b"\x00" * 8
    streams["__properties_version1.0"] = b"\x00" * 8 + struct.pack("<IIII", 0, 1, 0, 1) + b"\x00" * 8
    item = _scan(tmp_path, "broken.msg", ob.build(streams))[0]
    assert item.kind == "Outlook メール（msg）"
    assert any("msg を構造として読めなかった" in n for n in item.notes), item.notes
    assert item.status == Status.PARTIAL, item.reason


# ------------------------------------------------------------------ 読めないものの扱い


def test_irm_protected_document_is_uncheckable(tmp_path):
    data = ob.build({"\x06DataSpaces/Version": b"\x00" * 16, "Contents": b"\x00" * 16})
    item = _scan(tmp_path, "secret.doc", data)[0]
    assert item.status == Status.UNCHECKABLE
    assert item.reason.startswith("IRM（Information Rights Management）で保護された文書")


def test_encrypted_package_of_unknown_method_is_uncheckable(tmp_path):
    data = ob.build({"EncryptedPackage": b"\x00" * 64, "EncryptionInfo": b"\xff" * 16})
    item = _scan(tmp_path, "locked.docx", data)[0]
    assert item.kind == "暗号化された Office 文書（docx/xlsx/pptx）"
    assert item.status == Status.UNCHECKABLE
    assert item.reason.startswith("暗号化された Office 文書だが、暗号化の方式を判別できず")


def _encrypted_docx(password: str) -> bytes:
    import docx
    from msoffcrypto.format.ooxml import OOXMLFile

    d = docx.Document()
    d.add_paragraph(f"電話 {PHONE}")
    plain, enc = io.BytesIO(), io.BytesIO()
    d.save(plain)
    plain.seek(0)
    OOXMLFile(plain).encrypt(password, enc)
    return enc.getvalue()


def test_encrypted_docx_with_default_password_is_decrypted(tmp_path):
    items = _scan(tmp_path, "auto.docx", _encrypted_docx("VelvetSweatshop"))
    assert items[0].method == "暗号化を解除して中身を検査"
    assert any("復号した" in n for n in items[0].notes), items[0].notes
    assert "phone" in _types(_child(items, "auto.docx!（復号した中身）"))


def test_encrypted_docx_needs_password_then_opens_with_it(tmp_path):
    from pii_checker.models import PasswordBook

    data = _encrypted_docx("secret123")
    item = _scan(tmp_path, "locked.docx", data)[0]
    assert item.status == Status.NEEDS_PASSWORD, item.reason
    assert item.password_kind == "office"

    p = tmp_path / "locked2.docx"
    p.write_bytes(data)
    items = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path)), PasswordBook(common=["wrong", "secret123"])).items
    assert items[0].method == "暗号化を解除して中身を検査"
    assert "phone" in _types(_child(items, "locked2.docx!（復号した中身）"))


def test_unknown_ole_is_partial_raw_sweep(tmp_path):
    item = _scan(tmp_path, "mystery.bin", ob.build({"Contents": f"value {PHONE} end".encode("utf-16-le")}))[0]
    assert item.status == Status.PARTIAL, item.reason
    assert item.reason.startswith("この OLE 形式は構造を解釈していない")
    assert item.method == "全ストリーム 1 本の生データ走査"
    assert "phone" in _types(item)


def test_ichitaro_is_partial_even_though_named(tmp_path):
    item = _scan(tmp_path, "draft.jtd", ob.build({"DocumentText": f"電話 {PHONE}".encode("utf-16-le")}))[0]
    assert item.kind == "一太郎"
    assert item.status == Status.PARTIAL, item.reason
    assert item.reason.startswith("一太郎は構造を解釈していない")
    assert "phone" in _types(item)


# ------------------------------------------------------------------ 埋め込みの取り出し


def _zip_with(name: str, text: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(name, text)
    return buf.getvalue()


def test_ole10native_payload_is_carved(tmp_path):
    payload = f"添付の電話 {PHONE2}\n".encode()
    body = (
        b"\x02\x00"
        + "メモ.txt".encode("cp932")
        + b"\x00"
        + b"C:\\memo.txt\x00"
        + b"\x00\x00\x03\x00"
        + struct.pack("<I", 4)
        + b"tmp\x00"
        + struct.pack("<I", len(payload))
        + payload
    )
    native = struct.pack("<I", len(body)) + body  # 先頭は続く中身の長さ（コードは読まない）
    items = _scan(tmp_path, "pkg.bin", ob.build({"ObjectPool/_1/\x01Ole10Native": native}))
    assert "埋め込み 1 件" in items[0].method, items[0].method
    child = _child(items, "（埋め込み メモ.txt）")
    assert "phone" in _types(child)


def test_stream_starting_with_zip_is_carved(tmp_path):
    z = _zip_with("in.txt", f"電話 {PHONE}\n")
    items = _scan(tmp_path, "obj.bin", ob.build({"ObjectPool/_2/Package": b"\x00" * 10 + z}))
    child = _child(items, "ObjectPool/_2/Package（埋め込み）")
    assert any("phone" in _types(it) for it in items[1:] if it.path.startswith(child.path)), [
        (it.path, it.finding_counts) for it in items
    ]


def test_ole_stream_at_start_is_not_carved_unless_package():
    """先頭が OLE の印のストリームは、Package・CONTENTS のときだけ埋め込みとして取り出す（自分自身の写しを数えない）。"""
    sig = ob.SIGNATURE + b"\x00" * 100
    assert list(office._carve_embedded("Other", sig)) == []
    assert [n for n, _ in office._carve_embedded("ObjectPool/Package", sig)] == ["ObjectPool/Package（埋め込み）"]


def test_thumbs_db_images_are_carved(tmp_path):
    jpeg = b"\xff\xd8\xff\xe0" + b"\x00" * 300
    data = ob.build({"Catalog": b"\x00" * 16, "1": b"\x0c\x00" * 40 + jpeg})
    items = _scan(tmp_path, "Thumbs.db", data)
    assert items[0].kind == "Thumbs.db（縮小画像の控え）"
    assert items[0].status == Status.SCANNED, items[0].reason
    _child(items, "1（縮小画像）")


def test_pictures_stream_yields_every_image():
    png = b"\x89PNG\r\n\x1a\n" + b"\x01" * 300
    jpeg = b"\xff\xd8\xff\xe0" + b"\x02" * 300
    tiny = b"\xff\xd8\xff\xe0" + b"\x03" * 10  # 256 バイト以下の切れ端は取り出さない
    data = b"\x00" * 200 + png + jpeg + tiny
    assert list(office._carve_embedded("Pictures", data)) == []
    got = list(office._carve_all_images("Pictures", data))
    assert [n for n, _ in got] == ["Pictures（画像1）", "Pictures（画像2）"]
    assert got[0][1] == png
    assert got[1][1] == jpeg  # 次の画像の印の手前で切る


def test_pictures_stream_is_carved_during_scan(tmp_path):
    wd, table = ob.doc_stream([("本文", False)])
    png = b"\x89PNG\r\n\x1a\n" + b"\x01" * 300
    items = _scan(tmp_path, "pic.doc", ob.build({"WordDocument": wd, "1Table": table, "Data": b"\x00" * 200 + png}))
    assert "埋め込み 1 件" in items[0].method, items[0].method
    _child(items, "Data（画像1）")

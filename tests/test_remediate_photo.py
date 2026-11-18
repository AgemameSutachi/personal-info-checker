"""写真（JPEG・PNG）の情報を消す対処（remedy_photo）の試験。

守ること: EXIF・XMP・IPTC・コメント・PNG の文字の塊・画像の後ろのデータは消え、画素（JPEG の圧縮したデータ・PNG の IDAT）は
元のまま・向きと色（ICC）は残る・壊れた写真は書き換えずに断る・OCR を切った検査（要目視）でも対処できる・書庫の中の写真もできる。
検体はすべて pytest の tmp_path に作る。本物のごみ箱へは送らない（送る関数を差し替える）。画面は開かない。
"""

from __future__ import annotations

import io
import sys
import zipfile
from pathlib import Path

import pytest
from PIL import Image, ImageCms, PngImagePlugin

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from pii_checker import remediate, remedy_photo  # noqa: E402
from pii_checker.engine import scan_file  # noqa: E402
from pii_checker.models import ScanOptions  # noqa: E402
from pii_checker.remedy_write import RemedyError, select_positions  # noqa: E402
from test_photo_metadata import _jpeg_with_xmp, _xmp_packet  # noqa: E402
from test_remediate import FakeTrash, analyze, make_service, run  # noqa: E402
from test_remediate_archive import find_item, make_archive_service, run_inner  # noqa: E402

ARTIST = "氏名 山田太郎"
MAIL = "taro.yamada@example.jp"
PHONE = "090-1234-5678"
NEEDLES = [ARTIST.encode("utf-8"), MAIL.encode(), PHONE.encode(), "丸の内".encode("utf-8")]


@pytest.fixture(autouse=True)
def trash(tmp_path, monkeypatch):
    """どの試験でも、ごみ箱へ送る関数を差し替える（本物のごみ箱へ送らない）。ごみ箱のある場所として扱う。"""
    t = FakeTrash(tmp_path / "_trash")
    monkeypatch.setattr(remediate, "send_to_recycle_bin", t)
    monkeypatch.setattr(remediate, "has_recycle_bin", lambda path: True)
    return t


def _pattern(size=(96, 64)) -> Image.Image:
    """画素の比べに意味があるよう、色の変わる絵にする（一色だと違う画素でも同じに見えうる）。"""
    img = Image.new("RGB", size)
    img.putdata([((x * 7) % 256, (y * 11) % 256, (x * y) % 256) for y in range(size[1]) for x in range(size[0])])
    return img


def _exif(orientation: int | None = None) -> Image.Exif:
    exif = Image.Exif()
    exif[0x013B] = ARTIST.encode("utf-8")  # 撮影者（道具と同じく UTF-8 のバイト列で書く）
    exif[0x010E] = f"連絡先 {MAIL}"
    exif.get_ifd(0x8769)[0x9003] = "2026:11:18 10:00:00"  # 撮影日時
    g = exif.get_ifd(0x8825)
    g[1], g[2], g[3], g[4] = "N", (35.0, 40.0, 50.0), "E", (139.0, 46.0, 1.0)
    if orientation:
        exif[0x0112] = orientation
    return exif


def photo_jpeg(size=(96, 64), orientation=None, progressive=False, icc=True, comment=True) -> bytes:
    """撮影者・説明（EXIF）・作成者の連絡先（XMP）・IPTC・コメント・ICC の入った JPEG。"""
    buf = io.BytesIO()
    kw = {"exif": _exif(orientation).tobytes(), "quality": 90, "progressive": progressive}
    if icc:
        kw["icc_profile"] = ImageCms.ImageCmsProfile(ImageCms.createProfile("sRGB")).tobytes()
    if comment:
        kw["comment"] = f"memo {PHONE}".encode()
    _pattern(size).save(buf, "JPEG", **kw)
    data = buf.getvalue()
    iptc = b"Photoshop 3.0\x008BIM\x04\x04\x00\x00\x00\x00\x00\x10\x1c\x02P\x00\x0c" + ARTIST.encode("utf-8")[:12]
    app13 = b"\xff\xed" + (len(iptc) + 2).to_bytes(2, "big") + iptc
    body = b"http://ns.adobe.com/xap/1.0/\x00" + _xmp_packet()
    app1 = b"\xff\xe1" + (len(body) + 2).to_bytes(2, "big") + body
    return data[:2] + app1 + app13 + data[2:]


def photo_png(size=(96, 64), orientation=None) -> bytes:
    info = PngImagePlugin.PngInfo()
    info.add_text("Author", ARTIST)
    info.add_itxt("Comment", f"連絡先 {MAIL}", zip=True)
    info.add_text("XML:com.adobe.xmp", _xmp_packet().decode("utf-8"))
    buf = io.BytesIO()
    _pattern(size).save(buf, "PNG", pnginfo=info, exif=_exif(orientation).tobytes())
    return buf.getvalue()


def pixels(data: bytes) -> tuple:
    with Image.open(io.BytesIO(data)) as im:
        im.load()
        return im.mode, im.size, im.tobytes()


def jpeg_markers(data: bytes) -> list[tuple[int, bytes]]:
    """SOS までの区切りの（印, 中身の頭 16 バイト）。"""
    out, pos = [], 2
    while data[pos + 1] != 0xDA:
        size = 2 + int.from_bytes(data[pos + 2 : pos + 4], "big")
        out.append((data[pos + 1], data[pos + 4 : pos + 20]))
        pos += size
    return out


def png_chunks(data: bytes) -> list[bytes]:
    out, pos = [], 8
    while pos < len(data):
        length = int.from_bytes(data[pos : pos + 4], "big")
        out.append(data[pos + 4 : pos + 8])
        pos += 12 + length
    return out


def assert_no_needles(data: bytes) -> None:
    for n in NEEDLES:
        assert n not in data, n
    assert b"<x:xmpmeta" not in data


# ---------------------------------------------------------------- 取り除く部品（単体）


def test_strip_jpeg_keeps_pixels_icc_and_jfif():
    data = photo_jpeg()
    new, stats = remedy_photo.strip_jpeg(data)
    assert_no_needles(new)
    assert b"Exif\x00\x00" not in new and b"Photoshop 3.0" not in new
    markers = [m for m, _ in jpeg_markers(new)]
    assert 0xE1 not in markers and 0xED not in markers and 0xFE not in markers
    assert markers[0] == 0xE0  # JFIF は先頭のまま
    assert any(m == 0xE2 and head.startswith(b"ICC_PROFILE") for m, head in jpeg_markers(new))
    assert stats["meta_blocks"] == 4  # XMP・IPTC・EXIF・コメント
    assert stats["trailer_bytes"] == 0
    assert pixels(new) == pixels(data)
    # 画像のデータ（SOS から終わりまで）はバイト列のまま
    assert new[new.index(b"\xff\xda") :] == data[data.index(b"\xff\xda") :]


def test_strip_jpeg_keeps_only_orientation():
    """向きが 1 以外なら、向きだけの EXIF を置き直す（撮影者・GPS・日時は残さない）。"""
    data = photo_jpeg(orientation=6)
    new, _ = remedy_photo.strip_jpeg(data, orientation=6)
    with Image.open(io.BytesIO(new)) as im:
        exif = im.getexif()
        assert dict(exif) == {0x0112: 6}
        assert not exif.get_ifd(0x8825) and not exif.get_ifd(0x8769)
    assert_no_needles(new)
    assert pixels(new) == pixels(data)


def test_strip_progressive_jpeg_and_trailer():
    """プログレッシブ（走査の間に表が入る）でも終わりを見つけ、後ろに付いた別の画像は取り除く。"""
    data = photo_jpeg(progressive=True)
    assert data.count(b"\xff\xda") > 1
    extra = photo_jpeg(size=(16, 16), icc=False)  # 連写・深度などの別の画像の代わり（写真の情報入り）
    new, stats = remedy_photo.strip_jpeg(data + extra)
    assert stats["trailer_bytes"] == len(extra)
    assert new.endswith(b"\xff\xd9") and new.count(b"\xff\xd8") == 1
    assert_no_needles(new)
    assert pixels(new) == pixels(data)


def _app(marker: int, body: bytes) -> bytes:
    return bytes([0xFF, marker]) + (len(body) + 2).to_bytes(2, "big") + body


def test_strip_jpeg_removes_thumbnails_in_app0():
    """JFXX（縮小版の画像）と縮小版を持つ JFIF は消し、縮小版の無い最初の JFIF だけ残す。"""
    data = photo_jpeg()
    assert data[2:4] == b"\xff\xe1"  # 検体は XMP が先頭。JFIF は後ろにある
    jfif_with_thumb = b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x01\x01" + b"SECRETTHUMB"
    jfxx = b"JFXX\x00\x10" + b"SECRETNAME-thumb"
    sos = data.index(b"\xff\xda")
    mixed = data[:sos] + _app(0xE0, jfif_with_thumb) + _app(0xE0, jfxx) + data[sos:]
    new, stats = remedy_photo.strip_jpeg(mixed)
    assert b"SECRET" not in new
    assert [m for m, _ in jpeg_markers(new)].count(0xE0) == 1  # 元の 0×0 の JFIF だけ
    assert pixels(new) == pixels(mixed)


def test_strip_progressive_jpeg_removes_segments_between_scans():
    """走査の間に置かれた APPn・コメントも消す（画素は変わらない）。"""
    data = photo_jpeg(progressive=True)
    second = data.index(b"\xff\xda", data.index(b"\xff\xda") + 2)
    between = _app(0xE1, b"Exif\x00\x00SECRET-between") + _app(0xFE, b"SECRET-comment")
    mixed = data[:second] + between + data[second:]
    new, _ = remedy_photo.strip_jpeg(mixed)
    assert b"SECRET" not in new
    assert pixels(new) == pixels(data)


@pytest.mark.parametrize(
    "broken",
    [
        b"\xff\xd8\xff\xe1\x00",  # 区切りの途中で切れている
        b"\xff\xd8\xff\xe1\x00\x50abc",  # 長さが残りより長い
        b"\xff\xd8\xff\xd9",  # 画像のデータが無い
        b"\x89PNG",  # JPEG でない
    ],
)
def test_strip_jpeg_refuses_broken(broken):
    with pytest.raises(RemedyError):
        remedy_photo.strip_jpeg(broken)


def test_strip_jpeg_refuses_truncated_image_data():
    data = photo_jpeg()
    with pytest.raises(RemedyError, match="終わりの印"):
        remedy_photo.strip_jpeg(data[: len(data) - 40])


def test_strip_png_keeps_idat_and_orientation():
    data = photo_png(orientation=8)
    new, stats = remedy_photo.strip_png(data, orientation=8)
    chunks = png_chunks(new)
    assert not {b"tEXt", b"zTXt", b"iTXt"} & set(chunks)
    assert chunks.count(b"eXIf") == 1 and chunks.index(b"eXIf") < chunks.index(b"IDAT")
    assert stats["meta_blocks"] >= 4  # tEXt・iTXt・XMP の iTXt（か tEXt）・元の eXIf
    assert_no_needles(new)
    with Image.open(io.BytesIO(new)) as im:
        assert dict(im.getexif()) == {0x0112: 8}
    assert pixels(new) == pixels(data)
    with pytest.raises(RemedyError, match="IEND"):
        remedy_photo.strip_png(data[:-12])


def test_rewrite_refuses_when_pixels_would_change(tmp_path, monkeypatch):
    """取り除いた結果の画素が元と違えば、新しいファイルを書かずに断る。"""
    src = tmp_path / "a.jpg"
    src.write_bytes(photo_jpeg())
    dst = tmp_path / "b.jpg"
    sel = select_positions({("写真の情報", "email", 3): [1, 0, 0, 5]})
    real = remedy_photo.strip_jpeg
    monkeypatch.setattr(remedy_photo, "strip_jpeg", lambda d, o=1: (photo_jpeg(size=(97, 64)), real(d, o)[1]))
    with pytest.raises(RemedyError, match="画像が変わって"):
        remedy_photo.rewrite_photo_file(str(src), str(dst), "strip_photo_meta", sel)
    assert not dst.exists()
    src.write_bytes(b"GIF89a" + b"\x00" * 20)
    with pytest.raises(RemedyError, match="JPEG と PNG"):
        remedy_photo.rewrite_photo_file(str(src), str(dst), "strip_photo_meta", sel)


# ---------------------------------------------------------------- 検査で位置を集める


def test_collect_positions_for_photo(tmp_path):
    p = tmp_path / "src" / "photo.jpg"
    p.parent.mkdir()
    p.write_bytes(photo_jpeg())
    got = remediate.collect_task({"path": str(p), "options": ScanOptions(temp_dir=str(tmp_path), ocr=False)})
    assert got["layout"] == "photo"
    assert got["status"] == "uncheckable"  # 96px は OCR の対象。OCR を切ったので要目視
    rows = {arr[i] for arr in got["positions"].values() for i in range(0, len(arr), 4)}
    assert rows == {1, 2}  # EXIF と XMP
    assert {k[0] for k in got["positions"]} == {"写真の情報"}
    # GIF などは写真の情報を消す対象にしない
    g = tmp_path / "src" / "a.gif"
    _pattern().save(g, "GIF")
    assert remediate.collect_task({"path": str(g), "options": ScanOptions(temp_dir=str(tmp_path))})["layout"] == ""


# ---------------------------------------------------------------- 分析 → 下見 → 実行


@pytest.mark.parametrize("kind", ["jpeg", "png", "small"])
def test_run_strip_photo_meta(tmp_path, trash, kind):
    """OCR を切った検査（要目視）でも、小さな画像（検査不要）でも、写真の情報を消せる。画素は元のまま・元はごみ箱へ。"""
    src = tmp_path / "src"
    src.mkdir()
    if kind == "png":
        data = photo_png(orientation=6)
        p = src / "photo.png"
    else:
        data = photo_jpeg(size=(24, 24) if kind == "small" else (96, 64), orientation=6)
        p = src / "photo.jpg"
    p.write_bytes(data)
    svc, _store, job = make_service(tmp_path, [p], ocr=False)
    a = analyze(svc, job, p)
    assert set(a.info["methods"]) == {"delete_file", "strip_photo_meta"}
    assert a.info["methods"]["strip_photo_meta"]["available"], a.info["methods"]
    assert a.view()["sheets"] == []
    pv = svc.preview(job, str(p), {"method": "strip_photo_meta", "confidences": ["low"]})  # 確度の選びは使わない
    assert pv["can_run"] and "画素は変えません" in pv["summary"]
    assert pv["sample_rows"] == ["EXIF", "XMP"]
    assert any("撮影日時" in w for w in pv["warnings"])
    res = run(svc, job, p, method="strip_photo_meta")
    assert res["state"] == "done", res
    new = p.read_bytes()
    assert_no_needles(new)
    assert pixels(new) == pixels(data)
    with Image.open(io.BytesIO(new)) as im:
        assert dict(im.getexif()) == {0x0112: 6}
    assert res["remaining"]["total"] == 0, res["remaining"]
    assert res["changed"]["meta_blocks"] >= 3
    assert len(trash.files()) == 1 and trash.files()[0].read_bytes() == data
    # 消したあとの写真は、GPS の補足も出ない
    item = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path), ocr=False)).items[0]
    assert not dict(item.finding_counts) and not any("GPS" in n or "位置" in n for n in item.notes), item.notes


def test_other_methods_are_not_offered_for_photo(tmp_path):
    p = tmp_path / "src" / "photo.jpg"
    p.parent.mkdir()
    p.write_bytes(photo_jpeg())
    svc, _store, job = make_service(tmp_path, [p], ocr=False)
    analyze(svc, job, p)
    with pytest.raises(RemedyError, match="方法が正しくありません"):
        svc.preview(job, str(p), {"method": "delete_rows"})
    assert remediate.unsupported_reason("delete_rows", str(p), {"status": "scanned", "layout": "photo"})


def test_photo_in_zip(tmp_path, trash):
    """zip の中の写真の情報も消せる（ほかの項目は変えない）。"""
    arc = tmp_path / "src" / "photos.zip"
    arc.parent.mkdir()
    data = photo_jpeg()
    with zipfile.ZipFile(arc, "w") as z:
        z.writestr("a/photo.jpg", data)
        z.writestr("readme.txt", "nothing here")
    svc, store, job = make_archive_service(tmp_path, arc)
    item = find_item(store, job, arc, "a/photo.jpg")
    res, pv = run_inner(svc, job, arc, item, method="strip_photo_meta")
    assert res["state"] == "done", res
    with zipfile.ZipFile(arc) as z:
        new = z.read("a/photo.jpg")
        assert z.read("readme.txt") == b"nothing here"
    assert_no_needles(new)
    assert pixels(new) == pixels(data)


def test_photo_with_only_xmp_jpeg_from_existing_helper(tmp_path):
    """XMP だけの JPEG（既存の検体の作り方）でも、XMP の塊が消える。"""
    data = _jpeg_with_xmp(_xmp_packet(), size=(64, 64))
    new, stats = remedy_photo.strip_jpeg(data)
    assert stats["meta_blocks"] >= 1 and b"<x:xmpmeta" not in new
    assert pixels(new) == pixels(data)

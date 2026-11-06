"""写真の情報（EXIF）の検査の試験: 撮影者・説明などの文字を検査し、撮影場所（GPS）は補足に残す。"""

from __future__ import annotations

import io

from PIL import Image

from pii_checker.engine import scan_file
from pii_checker.formats import misc
from pii_checker.models import ScanOptions


def _exif(gps: bool = True, **text) -> Image.Exif:
    exif = Image.Exif()
    if "artist" in text:
        exif[0x013B] = text["artist"]
    if "description" in text:
        exif[0x010E] = text["description"]
    if "xp_author" in text:
        exif[0x9C9D] = text["xp_author"].encode("utf-16-le") + b"\x00\x00"
    if "comment" in text:
        exif.get_ifd(0x8769)[0x9286] = b"UNICODE\x00" + text["comment"].encode("utf-16-le")
    if gps:
        g = exif.get_ifd(0x8825)
        g[1], g[2], g[3], g[4] = "N", (35.0, 40.0, 50.0), "E", (139.0, 46.0, 1.0)
    return exif


def _jpeg(exif: Image.Exif, size=(64, 64)) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", size, "white").save(buf, "JPEG", exif=exif.tobytes())
    return buf.getvalue()


def test_exif_text_is_scanned_and_gps_is_noted(tmp_path):
    """撮影者・Windows の作成者・ユーザーコメントの文字を検査する。小さな画像・OCR を切っても読む。座標は載せない。"""
    p = tmp_path / "photo.jpg"
    p.write_bytes(
        _jpeg(
            _exif(
                artist="Taro Yamada",
                xp_author="氏名 山田太郎",
                comment="連絡先 電話 090-1234-5678",
                description="顧客 taro.yamada@example.jp",
            )
        )
    )
    res = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path), ocr=False))
    item = res.items[0]
    found = dict(item.finding_counts)
    assert found.get("phone") and found.get("email") and found.get("name"), found
    locations = {f.location for f in item.findings}
    assert {"EXIF ユーザーコメント", "EXIF 説明", "EXIF 作成者"} <= locations, locations
    assert any("EXIF" in n and "4 項目" in n for n in item.notes), item.notes
    assert misc.GPS_NOTE in item.notes
    text = " ".join(item.notes) + " ".join(f.masked_value + f.context for f in item.findings)
    assert "139" not in text and "35.6" not in text  # 座標そのものは明細・補足に載せない


def test_gps_alone_is_not_a_finding(tmp_path):
    """撮影場所だけの写真は検出に数えない（携帯電話の写真のほとんどに入っているため）。補足には残す。"""
    p = tmp_path / "IMG_0001.jpg"
    p.write_bytes(_jpeg(_exif()))
    item = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path), ocr=False)).items[0]
    assert dict(item.finding_counts) == {}
    assert misc.GPS_NOTE in item.notes
    p2 = tmp_path / "no_gps.jpg"
    p2.write_bytes(_jpeg(_exif(gps=False)))
    item = scan_file(str(p2), ScanOptions(temp_dir=str(tmp_path), ocr=False)).items[0]
    assert misc.GPS_NOTE not in item.notes and not any("EXIF" in n for n in item.notes)


def test_heic_exif_is_found_without_opening_image(tmp_path):
    """HEIC は箱の作りをたどらず、EXIF の印を探して読む（画像を開けない PC・OCR を切ったときも読む）。"""
    tiff = _exif(xp_author="氏名 山田太郎").tobytes()  # 先頭が "Exif\0\0" の TIFF
    assert tiff.startswith(b"Exif\x00\x00")
    data = b"\x00\x00\x00\x18ftypheic" + b"\x00" * 200 + b"\x00\x00\x00\x06" + tiff + b"\x00" * 100
    p = tmp_path / "IMG_0002.HEIC"
    p.write_bytes(data)
    item = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path), ocr=False)).items[0]
    assert "OCR を無効" in item.reason  # 画像の文字は読んでいない
    assert dict(item.finding_counts).get("name"), item.finding_counts
    assert misc.GPS_NOTE in item.notes
    assert misc.exif_from_raw(b"\x00\x00\x00\x18ftypheic" + b"\x00" * 64) is None


def test_broken_exif_does_not_stop_scan(tmp_path):
    """壊れた EXIF の塊・おかしな型の値でも落ちない。"""
    broken = misc.exif_from_raw(b"Exif\x00\x00MM\x00*" + b"\xff" * 30)  # 落ちない（読めた分だけ返すか None）
    misc.scan_exif(broken, type("I", (), {"notes": []})(), type("C", (), {"add_text": lambda *a, **k: None})())
    exif = Image.Exif()
    exif[0x013B] = 12345  # 文字でない値
    exif[0x9C9C] = (0x41, 0x00, 0x42, 0x00)  # XP の値が数の並びで来る
    item = type("I", (), {"notes": []})()

    class Col:
        def __init__(self):
            self.texts = []

        def add_text(self, text, location, **kw):
            self.texts.append((location, text))

    col = Col()
    misc.scan_exif(exif, item, col)
    assert col.texts == [("EXIF コメント", "AB")]
    misc.scan_exif(None, item, col)  # EXIF の無い画像


def test_japanese_exif_text_is_decoded():
    """日本語の撮影者（UTF-8・Shift_JIS）を読み直す（PIL は ASCII の型の値を latin-1 で返すため化けていた）。"""
    assert misc._exif_text(0x013B, "山田太郎".encode("utf-8").decode("latin-1")) == "山田太郎"
    assert misc._exif_text(0x013B, "山田太郎".encode("cp932").decode("latin-1")) == "山田太郎"
    assert misc._exif_text(0x013B, "Café Tokyo") == "Café Tokyo"  # 本物の latin-1 はそのまま
    assert misc._exif_text(0x9286, b"ASCII\x00\x00\x00" + "山田".encode("cp932")) == "山田"
    assert misc._exif_text(0x9286, b"JIS\x00\x00\x00\x00\x00" + "山田".encode("cp932")) == "山田"
    assert misc._exif_text(0x9286, b"\x00" * 8 + "山田".encode("utf-8")) == "山田"


def test_japanese_artist_in_jpeg_is_found(tmp_path):
    """撮影者に UTF-8 で書いた「氏名 山田太郎」を、JPEG に入れて読んでも拾う。小さな画像の説明も EXIF を読んだと書く。"""
    exif = Image.Exif()
    exif[0x013B] = "氏名 山田太郎".encode("utf-8")  # PIL は str の日本語を「?」にして書くので、道具と同じくバイト列で書く
    p = tmp_path / "small.jpg"
    p.write_bytes(_jpeg(exif, size=(16, 16)))
    item = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path))).items[0]
    assert dict(item.finding_counts).get("name"), (item.finding_counts, item.method)
    assert item.method.startswith("写真の情報（EXIF）") and "検査不要" in item.method


def test_gps_photos_are_counted_in_summary(tmp_path):
    """撮影場所のある写真の枚数を集計と判定の文に出す（検出には数えないので、判定は「検出なし」のまま）。"""
    from pii_checker import runner, verdict
    from pii_checker.models import GPS_NOTE_MARK
    from pii_checker.store import Store

    assert misc.GPS_NOTE.startswith(GPS_NOTE_MARK)
    folder = tmp_path / "photos"
    folder.mkdir()
    (folder / "a.jpg").write_bytes(_jpeg(_exif()))
    (folder / "b.jpg").write_bytes(_jpeg(_exif()))
    (folder / "c.jpg").write_bytes(_jpeg(_exif(gps=False)))
    store = Store(str(tmp_path / "jobs.sqlite3"))
    job = store.create_job([str(folder)], ScanOptions(temp_dir=str(tmp_path), ocr=False))
    r = runner.JobRunner(store, job, workers=1)
    r.start()
    r.wait(180)
    summary = store.summary(job)
    assert summary["gps_photos"] == 2
    v = verdict.decide(summary, store.job(job)["state"])
    assert any("撮影場所（GPS）が記録された写真 2 件" in line for line in v.detail), v.detail
    assert summary["files_with_findings"] == 0

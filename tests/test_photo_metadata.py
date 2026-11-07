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
    p2 = tmp_path / "IMG_0003.HEIC"  # XMP（iPhone の編集・Lightroom が書く）も同じく印で探す
    p2.write_bytes(b"\x00\x00\x00\x18ftypheic" + b"\x00" * 200 + _xmp_packet() + b"\x00" * 100)
    item = scan_file(str(p2), ScanOptions(temp_dir=str(tmp_path), ocr=False)).items[0]
    assert dict(item.finding_counts).get("phone"), item.finding_counts
    assert any("XMP" in n for n in item.notes), item.notes


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
    exif[0x013B] = "氏名 山田太郎".encode(
        "utf-8"
    )  # PIL は str の日本語を「?」にして書くので、道具と同じくバイト列で書く
    p = tmp_path / "small.jpg"
    p.write_bytes(_jpeg(exif, size=(16, 16)))
    item = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path))).items[0]
    assert dict(item.finding_counts).get("name"), (item.finding_counts, item.method)
    assert item.method.startswith("写真の情報（EXIF）") and "検査不要" in item.method


_XMP = """<?xpacket begin="﻿" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
 <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description rdf:about=""
    xmlns:dc="http://purl.org/dc/elements/1.1/"
    xmlns:photoshop="http://ns.adobe.com/photoshop/1.0/"
    xmlns:xmp="http://ns.adobe.com/xap/1.0/"
    xmlns:Iptc4xmpCore="http://iptc.org/std/Iptc4xmpCore/1.0/xmlns/"
    xmlns:Iptc4xmpExt="http://iptc.org/std/Iptc4xmpExt/2008-02-29/"
    photoshop:AuthorsPosition="営業部 主任"
    xmp:CreatorTool="Example 1.0">
   <dc:creator><rdf:Seq><rdf:li>{creator}</rdf:li></rdf:Seq></dc:creator>
   <Iptc4xmpCore:CreatorContactInfo
     Iptc4xmpCore:CiAdrExtadr="東京都千代田区丸の内9-9-9"
     Iptc4xmpCore:CiEmailWork="taro.yamada@example.jp">
    <Iptc4xmpCore:CiTelWork>090-1234-5678</Iptc4xmpCore:CiTelWork>
   </Iptc4xmpCore:CreatorContactInfo>
   <Iptc4xmpExt:PersonInImage><rdf:Bag><rdf:li>&undefined; 佐藤花子</rdf:li></rdf:Bag></Iptc4xmpExt:PersonInImage>
  </rdf:Description>
 </rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>"""


def _xmp_packet(creator: str = "氏名 山田太郎") -> bytes:
    return _XMP.replace("{creator}", creator).encode("utf-8")


def _jpeg_with_xmp(packet: bytes, exif: Image.Exif | None = None, size=(64, 64)) -> bytes:
    """JPEG の先頭（SOI の直後）に XMP の APP1 を入れる（Adobe の道具と同じ形）。"""
    data = _jpeg(exif or Image.Exif(), size)
    body = b"http://ns.adobe.com/xap/1.0/\x00" + packet
    app1 = b"\xff\xe1" + (len(body) + 2).to_bytes(2, "big") + body
    return data[:2] + app1 + data[2:]


def test_xmp_text_is_scanned(tmp_path):
    """XMP の作成者・作成者の連絡先（属性で書く形・要素で書く形）・写っている人を検査する。道具の名前などは読まない。"""
    p = tmp_path / "edited.jpg"
    p.write_bytes(_jpeg_with_xmp(_xmp_packet(), size=(16, 16)))
    item = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path))).items[0]
    found = dict(item.finding_counts)
    assert found.get("phone") and found.get("email") and found.get("name"), found
    locations = {f.location for f in item.findings}
    assert {"XMP 作成者", "XMP 作成者の連絡先"} <= locations, locations
    assert any("XMP" in n and "4 項目" in n for n in item.notes), item.notes
    assert item.method.startswith("写真の情報（XMP）") and "検査不要" in item.method
    fields = dict(misc.xmp_fields(_xmp_packet()))
    assert fields["作成者の連絡先"].splitlines() == [
        "住所：東京都千代田区丸の内9-9-9",
        "メール：taro.yamada@example.jp",
        "電話：090-1234-5678",
    ]
    assert "佐藤花子" in fields["写っている人"]  # 定義の無い実体の参照があっても読める（展開はしない）
    assert "Example" not in " ".join(fields.values())


def test_xmp_and_exif_with_same_value_are_counted_once(tmp_path):
    """EXIF と XMP の両方に同じ撮影者を書く道具が多い。同じ値は EXIF の1件だけと数える。"""
    exif = Image.Exif()
    exif[0x9C9D] = "氏名 山田太郎".encode("utf-16-le") + b"\x00\x00"
    p = tmp_path / "both.jpg"
    p.write_bytes(_jpeg_with_xmp(_xmp_packet("氏名 山田太郎"), exif, size=(16, 16)))
    item = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path))).items[0]
    names = [f.location for f in item.findings if f.pii_type == "name"]
    assert names == ["EXIF 作成者", "XMP 写っている人"], (names, item.finding_counts)  # 山田太郎は EXIF の1件だけ
    assert item.method.startswith("写真の情報（EXIF・XMP）"), item.method


def test_xmp_in_png_and_broken_packets(tmp_path):
    """PNG（iTXt）の XMP も読む。壊れた塊・閉じていない塊・XMP でない XML で落ちない。"""
    from PIL.PngImagePlugin import PngInfo

    info = PngInfo()
    info.add_itxt("XML:com.adobe.xmp", _xmp_packet().decode("utf-8"))
    buf = io.BytesIO()
    Image.new("RGB", (64, 64), "white").save(buf, "PNG", pnginfo=info)
    p = tmp_path / "edited.png"
    p.write_bytes(buf.getvalue())
    item = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path), ocr=False)).items[0]
    assert dict(item.finding_counts).get("phone"), item.finding_counts
    assert misc.xmp_fields(b"<x:xmpmeta><<<>>") == []
    assert misc._xmp_packets(b"..<x:xmpmeta xmlns:x='adobe:ns:meta/'>") == []  # 閉じていない
    assert misc.xmp_fields(b"<x:xmpmeta xmlns:x='adobe:ns:meta/'><a>090-1234-5678</a></x:xmpmeta>") == []


_FACES = """<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
 <rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/"
   xmlns:MP="http://ns.microsoft.com/photo/1.2/" xmlns:MPRI="http://ns.microsoft.com/photo/1.2/t/RegionInfo#"
   xmlns:MPReg="http://ns.microsoft.com/photo/1.2/t/Region#"
   xmlns:mwg-rs="http://www.metadataworkinggroup.com/schemas/regions/">
  <dc:creator><rdf:Seq><rdf:li>Canon Inc.</rdf:li></rdf:Seq></dc:creator>
  <dc:rights><rdf:Alt><rdf:li xml:lang="x-default">株式会社サンプル</rdf:li></rdf:Alt></dc:rights>
  <MP:RegionInfo rdf:parseType="Resource"><MPRI:Regions><rdf:Bag>
   <rdf:li MPReg:PersonDisplayName="山田太郎" MPReg:Rectangle="0.1, 0.1, 0.2, 0.2"/>
  </rdf:Bag></MPRI:Regions></MP:RegionInfo>
  <mwg-rs:Regions rdf:parseType="Resource"><mwg-rs:RegionList><rdf:Bag>
   <rdf:li><rdf:Description mwg-rs:Name="佐藤花子" mwg-rs:Type="Face"/></rdf:li>
   <rdf:li><rdf:Description mwg-rs:Name="ポチ" mwg-rs:Type="Pet"/></rdf:li>
   <rdf:li rdf:parseType="Resource"><mwg-rs:Name>タマ</mwg-rs:Name><mwg-rs:Type>Pet</mwg-rs:Type></rdf:li>
  </rdf:Bag></mwg-rs:RegionList></mwg-rs:Regions>
 </rdf:Description></rdf:RDF></x:xmpmeta>""".encode("utf-8")


def test_xmp_face_tags_are_names_but_creators_are_not(tmp_path):
    """顔のタグ（Windows のフォト・Lightroom）の姓名だけの値は名前として拾う。動物の領域は読まない。
    作成者・著作権の会社名は名前にしない（氏名の列とみなすと会社名まで名前になる）。"""
    fields = misc.xmp_fields(_FACES)
    assert ("写っている人", "山田太郎") in fields and ("写っている人", "佐藤花子") in fields, fields
    assert not any(v in ("ポチ", "タマ") for _, v in fields), fields
    p = tmp_path / "faces.jpg"
    p.write_bytes(_jpeg_with_xmp(_FACES, size=(16, 16)))
    item = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path))).items[0]
    names = sorted(f.location for f in item.findings if f.pii_type == "name")
    assert names == ["XMP 写っている人", "XMP 写っている人"], (names, item.finding_counts)
    assert any("（作成者・著作権・写っている人）" in n for n in item.notes), item.notes


def test_xmp_face_tag_placeholders_are_not_names():
    """顔のタグの定型（Unknown・Person 1・不明）・文のような値は氏名の列とみなさない。顔でない領域（Focus）は読まない。"""
    for v in (
        "Unknown",
        "Person 1",
        "face 2",
        "人物1",
        "不明",
        "匿名",
        "運動会で撮った写真です。",
        "家族旅行の集合写真の右から二番目",
    ):
        assert not misc._person_name_like(v), v
    for v in ("山田太郎", "山田 太郎", "Taro Yamada"):
        assert misc._person_name_like(v), v
    focus = _FACES.replace(
        b'mwg-rs:Name="\xe4\xbd\x90\xe8\x97\xa4\xe8\x8a\xb1\xe5\xad\x90" mwg-rs:Type="Face"',
        b'mwg-rs:Name="X" mwg-rs:Type="Focus"',
    )
    assert ("写っている人", "X") not in misc.xmp_fields(focus)


def test_xmp_in_other_containers(tmp_path):
    """圧縮した PNG の iTXt（PIL が解いたもの）・TIFF（700 番）・WebP の XMP も読む。"""
    from PIL.PngImagePlugin import PngInfo

    packet = _xmp_packet()
    info = PngInfo()
    info.add_itxt("XML:com.adobe.xmp", packet.decode("utf-8"), zip=True)
    buf = io.BytesIO()
    Image.new("RGB", (16, 16), "white").save(buf, "PNG", pnginfo=info)
    assert b"<x:xmpmeta" not in buf.getvalue()  # バイト列のままでは探せない
    (tmp_path / "zipped.png").write_bytes(buf.getvalue())
    buf = io.BytesIO()
    Image.new("RGB", (16, 16), "white").save(buf, "TIFF", tiffinfo={700: packet})
    (tmp_path / "photo.tif").write_bytes(buf.getvalue())
    buf = io.BytesIO()
    Image.new("RGB", (16, 16), "white").save(buf, "WEBP", xmp=packet)
    (tmp_path / "photo.webp").write_bytes(buf.getvalue())
    for name in ("zipped.png", "photo.tif", "photo.webp"):
        item = scan_file(str(tmp_path / name), ScanOptions(temp_dir=str(tmp_path))).items[0]
        assert dict(item.finding_counts).get("phone"), (name, item.finding_counts, item.reason)


def test_xmp_packets_skip_oversized_and_dedupe():
    """大きすぎる塊は飛ばして後ろの塊を読む。属性と要素に同じ値を書いても1項目と数える。"""
    big = b"<x:xmpmeta>" + b" " * (misc._XMP_MAX + 1) + b"</x:xmpmeta>"
    packet = _xmp_packet()
    inner = packet[packet.index(b"<x:xmpmeta") : packet.index(b"</x:xmpmeta>") + len(b"</x:xmpmeta>")]
    assert misc._xmp_packets(big + packet) == [inner]
    twice = (
        b'<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
        b'<rdf:Description xmlns:photoshop="http://ns.adobe.com/photoshop/1.0/" photoshop:Credit="ABC">'
        b"<photoshop:Credit>ABC</photoshop:Credit></rdf:Description></rdf:RDF></x:xmpmeta>"
    )
    assert misc.xmp_fields(twice) == [("クレジット", "ABC")]


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
    from pii_checker import report

    rows = dict(report.overview_rows(store.job(job), summary))
    assert rows["撮影場所（GPS）が記録された写真（検出には数えない）"] == 2
    # 0 枚なら判定の文には出さない（集計の行は 0 で出る）。判定の段階は GPS の有無で変えない
    v0 = verdict.decide({**summary, "gps_photos": 0}, store.job(job)["state"])
    assert not any("撮影場所" in line for line in v0.detail), v0.detail
    assert v.level == v0.level and v.level != "found", (v.level, v0.level)

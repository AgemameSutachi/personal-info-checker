"""pii_checker.ocr（Windows 標準 OCR）の試験。

Windows の日本語 OCR が使えない環境では、実際に認識する試験は飛ばす。
"""

from __future__ import annotations

import io
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from PIL import Image, ImageDraw, ImageFont

from pii_checker import ocr

needs_ocr = pytest.mark.skipif(not ocr.is_available(), reason=f"OCR が使えない: {ocr.unavailable_reason()}")

FONT_CANDIDATES = [
    Path("C:/Windows/Fonts/meiryo.ttc"),
    Path("C:/Windows/Fonts/msgothic.ttc"),
]

SAMPLE_LINES = [
    "氏名 山田太郎 電話 090-1234-5678",
    "東京都千代田区丸の内1-2-3",
    "メール taro.yamada@example.jp",
]


def _font(size: int) -> ImageFont.FreeTypeFont:
    """試験用の日本語フォントを返す（無ければ試験を飛ばす）。"""
    for path in FONT_CANDIDATES:
        if path.exists():
            return ImageFont.truetype(str(path), size)
    pytest.skip("日本語フォント（meiryo / msgothic）が見つからない")


def _render(lines: list[str], size: int, mode: str = "RGB") -> Image.Image:
    """文字列を白地に黒で描いた画像を作る。size はフォントの大きさ（px）。"""
    font = _font(size)
    width = int(size * 26)
    height = int(size * (1.0 + 1.7 * len(lines)))
    img = Image.new(mode, (width, height), "white")
    draw = ImageDraw.Draw(img)
    for i, text in enumerate(lines):
        draw.text((size, size * 0.5 + i * size * 1.7), text, font=font, fill="black")
    return img


def _to_bytes(img: Image.Image, fmt: str, **kwargs) -> bytes:
    """PIL 画像を指定形式のバイト列にする。"""
    buf = io.BytesIO()
    img.save(buf, format=fmt, **kwargs)
    return buf.getvalue()


# メールアドレスとして検出できる形で残っていること。メイリオの小さい文字では
# "taro" の "o" を "0" と読むことがある（"tar0.yamada@example.jp"）ため、ローカル部の先頭は問わない
EMAIL_SHAPE = re.compile(r"[A-Za-z0-9._%+-]*\.yamada@example\.jp")


def _assert_main_values(text: str, exact_email: bool = False) -> None:
    """主要な値（電話番号・氏名・メールアドレス）が含まれることを確かめる。

    exact_email が真なら、メールアドレスが一字一句そのまま読めていることまで確かめる。
    """
    assert "090-1234-5678" in text, text
    assert "山田太郎" in text, text
    assert EMAIL_SHAPE.search(text), text
    if exact_email:
        assert "taro.yamada@example.jp" in text, text


# ---------------------------------------------------------------------------
# 利用可否
# ---------------------------------------------------------------------------


def test_is_available_returns_bool_and_reason_consistent():
    available = ocr.is_available()
    assert isinstance(available, bool)
    reason = ocr.unavailable_reason()
    if available:
        assert reason is None
    else:
        assert isinstance(reason, str) and reason


def test_unavailable_raises_ocr_unavailable(monkeypatch):
    # 使えない状態を作り、認識関数が OcrUnavailable（日本語の理由つき）を出すことを確かめる
    monkeypatch.setattr(ocr, "_checked", True)
    monkeypatch.setattr(ocr, "_reason", "日本語の OCR 認識器が入っていません（試験）")
    assert ocr.is_available() is False
    with pytest.raises(ocr.OcrUnavailable, match="日本語の OCR"):
        ocr.ocr_image_bytes(b"dummy")
    with pytest.raises(ocr.OcrUnavailable):
        ocr.ocr_pil_image(Image.new("L", (10, 10), 255))


# ---------------------------------------------------------------------------
# 行の整形（OCR を使わない単体試験）
# ---------------------------------------------------------------------------


def _words(*items: tuple[str, float, float]) -> list[tuple[str, float, float, float]]:
    """(文字列, 左端, 右端) の並びに高さ 50 を足して語の一覧にする。"""
    return [(text, left, right, 50.0) for text, left, right in items]


def test_join_removes_spaces_between_japanese():
    words = _words(("山", 0, 50), ("田", 55, 105), ("太", 110, 160), ("郎", 200, 250))
    assert ocr._join_words(words) == "山田太郎"


def test_join_removes_spaces_around_phone_symbols():
    words = _words(
        ("090", 0, 90), ("-", 120, 130), ("1234", 160, 280), ("-", 310, 320),
        ("5678", 350, 470),
    )  # fmt: skip
    assert ocr._join_words(words) == "090-1234-5678"


def test_join_keeps_space_between_alnum_words():
    words = _words(("Taro", 0, 120), ("Yamada", 160, 340))
    assert ocr._join_words(words) == "Taro Yamada"


def test_join_digits_groups_keep_space():
    words = _words(("1234", 0, 140), ("5678", 165, 305), ("9012", 330, 470))
    assert ocr._join_words(words) == "1234 5678 9012"


def test_join_long_vowel_between_digits_becomes_hyphen():
    words = _words(("090ー1234ー5678", 0, 400))
    assert ocr._join_words(words) == "090-1234-5678"


def test_join_japanese_and_digits_by_gap():
    # 狭い隙間（「4月」の中）はつなぎ、広い隙間（本物の空白）は残す
    words = _words(
        ("電", 0, 50), ("話", 52, 102), ("090-1234-5678", 135, 500),
        ("4", 520, 545), ("月", 547, 597),
    )  # fmt: skip
    assert ocr._join_words(words) == "電話 090-1234-5678 4月"


def test_join_fixes_common_misreads_in_ascii():
    # "r" を「「」、"." を「・」と読む誤りを英字の中でだけ直す
    words = _words(("ta「o.yamada@example・jp", 0, 600))
    assert ocr._join_words(words) == "taro.yamada@example.jp"
    # 日本語の中の鉤括弧はそのまま
    words = _words(("「", 0, 50), ("山", 55, 105), ("」", 110, 160))
    assert ocr._join_words(words) == "「山」"


def test_join_email_split_by_ocr_is_rejoined():
    words = _words(("sato@ma", 0, 200), ("i", 213, 220), ("l.example", 240, 480))
    assert ocr._join_words(words) == "sato@mail.example"


# ---------------------------------------------------------------------------
# 実際の認識
# ---------------------------------------------------------------------------


@needs_ocr
@pytest.mark.parametrize("size", [16, 20, 28, 48])
def test_recognize_png_various_sizes(size):
    data = _to_bytes(_render(SAMPLE_LINES, size), "PNG")
    _assert_main_values(ocr.ocr_image_bytes(data), exact_email=size >= 28)


@needs_ocr
def test_recognize_jpeg_and_bmp_and_gif():
    img = _render(SAMPLE_LINES, 28)
    for fmt, kwargs in [("JPEG", {"quality": 85}), ("BMP", {}), ("GIF", {})]:
        _assert_main_values(ocr.ocr_image_bytes(_to_bytes(img, fmt, **kwargs)))


@needs_ocr
def test_recognize_pil_image_rgba_transparent_background():
    # 透明な背景に黒文字（白背景に合成してから読めていること）
    img = Image.new("RGBA", (800, 200), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    font = _font(32)
    draw.text((20, 20), "電話 090-1234-5678", font=font, fill=(0, 0, 0, 255))
    draw.text((20, 100), "氏名 山田太郎", font=font, fill=(0, 0, 0, 255))
    text = ocr.ocr_pil_image(img)
    assert "090-1234-5678" in text
    assert "山田太郎" in text


@needs_ocr
def test_recognize_multipage_tiff_reads_all_pages():
    page1 = _render(["1ページ目 氏名 山田太郎"], 32)
    page2 = _render(["2ページ目 電話 090-1234-5678"], 32)
    page3 = _render(["3ページ目 taro.yamada@example.jp"], 32)
    buf = io.BytesIO()
    page1.save(buf, format="TIFF", save_all=True, append_images=[page2, page3])
    text = ocr.ocr_image_bytes(buf.getvalue())
    _assert_main_values(text)
    # ページの順に並び、改行で区切られていること
    assert text.index("山田太郎") < text.index("090-1234-5678")
    assert text.index("090-1234-5678") < EMAIL_SHAPE.search(text).start()
    assert len(text.splitlines()) >= 3


@needs_ocr
def test_recognize_large_image_over_max_dimension(tmp_path):
    # 縦が MaxImageDimension を超える画像（帯に分けて読み、二重取りしないこと）
    limit = ocr._max_dimension()
    img = Image.new("L", (2400, limit + 3000), 255)
    draw = ImageDraw.Draw(img)
    font = _font(48)
    draw.text((100, 200), "氏名 山田太郎", font=font, fill=0)
    # 帯の境目付近（重なりの中）に置いた行
    draw.text((100, limit - 500), "電話 090-1234-5678", font=font, fill=0)
    draw.text((100, limit + 2500), "メール taro.yamada@example.jp", font=font, fill=0)
    path = tmp_path / "tall.png"
    img.save(path)
    text = ocr.ocr_image_bytes(path.read_bytes())
    _assert_main_values(text)
    assert text.count("090-1234-5678") == 1, text


@needs_ocr
def test_recognize_wide_image_over_max_dimension():
    limit = ocr._max_dimension()
    img = Image.new("L", (limit + 2000, 400), 255)
    draw = ImageDraw.Draw(img)
    draw.text((200, 100), "電話 090-1234-5678", font=_font(96), fill=0)
    assert "090-1234-5678" in ocr.ocr_pil_image(img)


@needs_ocr
def test_blank_and_tiny_images_return_empty_string():
    assert ocr.ocr_pil_image(Image.new("L", (1, 1), 255)) == ""
    assert ocr.ocr_pil_image(Image.new("RGB", (300, 200), "white")) == ""


@needs_ocr
def test_broken_image_raises_value_error():
    with pytest.raises(ValueError, match="画像"):
        ocr.ocr_image_bytes(b"this is not an image")
    with pytest.raises(ValueError, match="空"):
        ocr.ocr_image_bytes(b"")
    data = _to_bytes(_render(SAMPLE_LINES, 28), "PNG")
    with pytest.raises(ValueError, match="壊れている"):
        ocr.ocr_image_bytes(data[: len(data) // 3])
    with pytest.raises(ValueError):
        ocr.ocr_pil_image("not an image")


@needs_ocr
def test_thread_safety_parallel_calls():
    data = _to_bytes(_render(SAMPLE_LINES, 28), "PNG")
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: ocr.ocr_image_bytes(data), range(8)))
    for text in results:
        _assert_main_values(text)


@needs_ocr
def test_call_from_sta_thread():
    # GUI のメインスレッドのような STA からも同期関数として呼べること
    import winrt.runtime as winrt_runtime

    data = _to_bytes(_render(SAMPLE_LINES, 28), "PNG")
    outcome: dict = {}

    def run_in_sta():
        try:
            winrt_runtime.init_apartment(winrt_runtime.STA)
            outcome["text"] = ocr.ocr_image_bytes(data)
        except BaseException as exc:  # 試験の結果としてメインスレッドへ渡す
            outcome["error"] = exc

    thread = threading.Thread(target=run_in_sta)
    thread.start()
    thread.join(timeout=60)
    assert "error" not in outcome, outcome.get("error")
    _assert_main_values(outcome["text"])


@needs_ocr
def test_speed_is_reasonable():
    # A4 300dpi 相当（2480x3508）・本文 44px の画像を 1 枚 5 秒以内で読めること
    lines = SAMPLE_LINES * 12
    img = Image.new("L", (2480, 3508), 255)
    draw = ImageDraw.Draw(img)
    font = _font(44)
    for i, text in enumerate(lines):
        draw.text((150, 150 + i * 80), text, font=font, fill=0)
    started = time.perf_counter()
    text = ocr.ocr_pil_image(img)
    elapsed = time.perf_counter() - started
    _assert_main_values(text)
    assert elapsed < 5.0, f"{elapsed:.2f} 秒かかった"


# ---------------------------------------------------------------------------
# JPEG XR（PowerPoint・Word で画像に効果をかけたときに残る .wdp）
# ---------------------------------------------------------------------------


def _to_jpeg_xr(img: Image.Image) -> bytes:
    """PIL 画像を WinRT の符号器で JPEG XR にする（PIL は JPEG XR を書けないため）。"""
    import uuid

    import winrt.windows.graphics.imaging as wimaging
    import winrt.windows.storage.streams as wstreams

    rgba = img.convert("RGBA")
    stream = wstreams.InMemoryRandomAccessStream()
    jpeg_xr_encoder = uuid.UUID("AC4CE3CB-E1C1-44CD-8215-5A1665509EC2")
    enc = wimaging.BitmapEncoder.create_async(jpeg_xr_encoder, stream).get()
    enc.set_pixel_data(
        wimaging.BitmapPixelFormat.RGBA8,
        wimaging.BitmapAlphaMode.IGNORE,
        rgba.width,
        rgba.height,
        96,
        96,
        rgba.tobytes(),
    )
    enc.flush_async().get()
    reader = wstreams.DataReader(stream.get_input_stream_at(0))
    n = reader.load_async(stream.size).get()
    return bytes(memoryview(reader.read_buffer(n)))


def test_jpeg_xr_is_sniffed_as_image(tmp_path):
    """JPEG XR の目印の画像を「形式不明（圧縮または暗号化）」にせず、画像として扱う（不具合の修正）。"""
    from pii_checker import sniff
    from pii_checker.engine import scan_file
    from pii_checker.models import ScanOptions, Status

    p = tmp_path / "hdphoto1.wdp"
    p.write_bytes(b"II\xbc\x01" + bytes(range(256)) * 64)  # 目印だけ本物で中身は壊れたもの
    res = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path), ocr=False))
    item = res.items[0]
    assert item.kind == sniff.KIND_LABELS["image"]
    assert item.status == Status.UNCHECKABLE and "JPEG XR" in item.reason, item.reason


@needs_ocr
def test_jpeg_xr_is_read_by_ocr(tmp_path):
    """JPEG XR の画像の文字を OCR で読んで検査する（PowerPoint の中の hdphoto1.wdp が「検査できなかった」になっていた）。"""
    import zipfile

    from pii_checker.engine import scan_file
    from pii_checker.models import ScanOptions, Status

    data = _to_jpeg_xr(_render(SAMPLE_LINES, 32))
    assert ocr.is_jpeg_xr(data)
    text = ocr.ocr_pil_image(ocr.open_with_wic(data))
    # JPEG XR は非可逆なので、メールの「.」のような細かい字は読み落としうる（電話・氏名で確かめる）
    assert "090-1234-5678" in text and "山田太郎" in text, text
    # zip の中（pptx の ppt/media と同じ置き方）でも、検査できなかった項目にならず中身を読む
    z = tmp_path / "slides.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("ppt/media/hdphoto1.wdp", data)
    res = scan_file(str(z), ScanOptions(temp_dir=str(tmp_path)))
    bad = [(it.path, it.status, it.reason) for it in res.items if it.status != Status.SCANNED]
    assert bad == []
    found = {k for it in res.items for k in it.finding_counts}
    assert "phone" in found, found


@needs_ocr
def test_broken_jpeg_xr_is_uncheckable_with_reason(tmp_path):
    from pii_checker.engine import scan_file
    from pii_checker.models import ScanOptions, Status

    p = tmp_path / "broken.wdp"
    p.write_bytes(b"II\xbc\x01" + b"\x00" * 100)
    res = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path)))
    item = res.items[0]
    assert item.status == Status.UNCHECKABLE and "JPEG XR" in item.reason, item.reason


# ---------------------------------------------------------------------------
# HEIC・AVIF（iPhone の写真など）
# ---------------------------------------------------------------------------


def _to_heic(img: Image.Image) -> bytes:
    """PIL 画像を WinRT の HEIF の符号器で HEIC にする。Windows の HEIF・HEVC の拡張が無ければ試験を飛ばす。"""
    import winrt.windows.graphics.imaging as wimaging
    import winrt.windows.storage.streams as wstreams

    rgba = img.convert("RGBA")
    stream = wstreams.InMemoryRandomAccessStream()
    try:
        enc = wimaging.BitmapEncoder.create_async(wimaging.BitmapEncoder.heif_encoder_id, stream).get()
        enc.set_pixel_data(
            wimaging.BitmapPixelFormat.RGBA8,
            wimaging.BitmapAlphaMode.IGNORE,
            rgba.width,
            rgba.height,
            96,
            96,
            rgba.tobytes(),
        )
        enc.flush_async().get()
    except OSError as e:
        pytest.skip(f"この PC では HEIC を作れない（Windows の HEIF・HEVC の拡張が無い）: {e}")
    reader = wstreams.DataReader(stream.get_input_stream_at(0))
    n = reader.load_async(stream.size).get()
    return bytes(memoryview(reader.read_buffer(n)))


@needs_ocr
def test_heic_is_read_by_ocr(tmp_path):
    """HEIC の写真の文字を OCR で読んで検査する（今までは「検査できなかった項目」だった）。zip の中でも同じ。"""
    import zipfile

    from pii_checker import sniff
    from pii_checker.engine import scan_file
    from pii_checker.models import ScanOptions, Status

    data = _to_heic(_render(SAMPLE_LINES, 32))
    assert data[4:12] in (b"ftypheic", b"ftypmif1"), data[:16]
    p = tmp_path / "IMG_0001.HEIC"
    p.write_bytes(data)
    res = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path)))
    item = res.items[0]
    assert item.kind == sniff.KIND_LABELS["image_unsupported"]
    assert item.status == Status.SCANNED, item.reason
    assert "HEIC/AVIF" in item.method and "Windows の部品" in item.method, item.method
    assert "phone" in item.finding_counts, item.finding_counts
    z = tmp_path / "photos.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("DCIM/IMG_0001.HEIC", data)
    res = scan_file(str(z), ScanOptions(temp_dir=str(tmp_path)))
    bad = [(it.path, it.status, it.reason) for it in res.items if it.status != Status.SCANNED]
    assert bad == []
    assert "phone" in {k for it in res.items for k in it.finding_counts}


@needs_ocr
def test_wic_respects_exif_orientation():
    """Windows の部品で開くときは EXIF の向きを守る（横向きに撮った写真の文字を読めるように）。"""
    img = Image.new("RGB", (300, 100), "white")
    exif = Image.Exif()
    exif[0x0112] = 6  # 右へ90度回して見る
    data = _to_bytes(img, "JPEG", exif=exif.tobytes())
    assert ocr.open_with_wic(data).size == (100, 300)


def test_heic_uncheckable_reasons(tmp_path, monkeypatch):
    """開けない HEIC は、理由と入れ方つきで「検査できなかった項目」にする（拡張が無い・壊れている・OCR を切った）。"""
    from pii_checker.engine import scan_file
    from pii_checker.formats import misc
    from pii_checker.models import ScanOptions, Status

    p = tmp_path / "photo.heic"
    p.write_bytes(b"\x00\x00\x00\x18ftypheic" + b"\x00" * 64)
    res = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path), ocr=False))
    assert res.items[0].status == Status.UNCHECKABLE and "OCR を無効" in res.items[0].reason

    monkeypatch.setattr(ocr, "is_available", lambda: True)
    monkeypatch.setattr(misc, "_open_heif_with_pillow", lambda data: None)  # pillow-heif が入っていない

    def missing(data):
        raise ValueError(
            "画像を読み込めませんでした（壊れている可能性があります）: [WinError -2003292336] 見つかりません"
        )

    monkeypatch.setattr(ocr, "open_with_wic", missing)
    reason = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path))).items[0].reason
    assert "この PC の Windows では" in reason and "Microsoft Store" in reason, reason
    assert "HEIF 画像表示オプション" in reason and "HEVC ビデオ拡張機能" in reason and "AV1 ビデオ拡張機能" in reason

    def broken(data):
        raise ValueError(
            "画像を読み込めませんでした（壊れている可能性があります）: [WinError -1072875842] 準拠していません"
        )

    monkeypatch.setattr(ocr, "open_with_wic", broken)
    reason = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path))).items[0].reason
    assert "壊れているか" in reason and "（詳細: [WinError -1072875842] 準拠していません）" in reason, reason
    assert "壊れている可能性" not in reason  # 中の誤りの「（壊れている可能性があります）」は重ねない

    def pillow_fails(data):
        raise OSError("Invalid input: Unspecified: Bitstream not supported by this decoder")

    monkeypatch.setattr(misc, "_open_heif_with_pillow", pillow_fails)
    item = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path))).items[0]
    assert item.status == Status.UNCHECKABLE and "壊れている可能性" in item.reason and "Bitstream" in item.reason
    assert "Microsoft Store" not in item.reason  # WIC の部品はあった（壊れている見込み）ので入れ方は出さない
    monkeypatch.setattr(ocr, "open_with_wic", missing)
    item = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path))).items[0]
    assert "壊れている可能性" in item.reason and "Microsoft Store" in item.reason  # 部品も無かったので入れ方も出す


def test_heic_too_many_pixels_is_not_blamed_on_codec(tmp_path, monkeypatch):
    """画素数が大きすぎて開かなかったものは、拡張の入れ方ではなく大きすぎたことを理由に出す。"""
    from PIL import Image as PILImage

    from pii_checker.engine import scan_file
    from pii_checker.formats import misc
    from pii_checker.models import ScanOptions, Status

    p = tmp_path / "huge.heic"
    p.write_bytes(b"\x00\x00\x00\x18ftypheic" + b"\x00" * 64)
    monkeypatch.setattr(ocr, "is_available", lambda: True)

    def huge(data):
        raise ValueError("画像の画素数が大きすぎるため読み込みを中止しました（20000×20000）")

    monkeypatch.setattr(ocr, "open_with_wic", huge)
    item = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path))).items[0]
    assert item.status == Status.UNCHECKABLE and "画素数が大きすぎる" in item.reason
    assert "Microsoft Store" not in item.reason

    def missing(data):
        raise ValueError("[WinError -2003292336]")

    def bomb(data):
        raise PILImage.DecompressionBombError("Image size (400000000 pixels) exceeds limit")

    monkeypatch.setattr(ocr, "open_with_wic", missing)
    monkeypatch.setattr(misc, "_open_heif_with_pillow", bomb)
    item = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path))).items[0]
    assert "画素数が大きすぎる" in item.reason and "Microsoft Store" not in item.reason


def test_heic_falls_back_to_pillow_heif(tmp_path, monkeypatch):
    """Windows の部品で開けなくても、pillow-heif（任意の追加）が入っていればそれで開いて読む。"""
    from pii_checker.engine import scan_file
    from pii_checker.formats import misc
    from pii_checker.models import ScanOptions, Status

    p = tmp_path / "photo.heic"
    p.write_bytes(b"\x00\x00\x00\x18ftypheic" + b"\x00" * 64)
    monkeypatch.setattr(ocr, "is_available", lambda: True)

    def missing(data):
        raise ValueError("[WinError -2003292336]")

    monkeypatch.setattr(ocr, "open_with_wic", missing)
    monkeypatch.setattr(misc, "_open_heif_with_pillow", lambda data: Image.new("L", (800, 600), "white"))
    monkeypatch.setattr(ocr, "ocr_pil_image", lambda img: "電話 090-1234-5678")
    item = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path))).items[0]
    assert item.status == Status.SCANNED, item.reason
    assert "pillow-heif" in item.method and "phone" in item.finding_counts


def test_pillow_heif_is_not_bundled():
    """pillow-heif は任意の追加。組み立ての環境に入っていても配布版（exe）には入れない（wheel が GPLv2 の x265 を含む）。"""
    import build

    excludes = re.search(r"excludes=\[([^\]]*)\]", build.SPEC)
    assert excludes and "'pillow_heif'" in excludes.group(1)

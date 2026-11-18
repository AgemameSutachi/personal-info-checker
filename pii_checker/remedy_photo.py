"""写真（JPEG・PNG）の情報（EXIF・XMP・IPTC・コメント・PNG の文字の塊）を消す対処。画素は書き換えない。

検査では、写真に人が書き込む文字（撮影者・説明・作成者の連絡先・写っている人など）を検出する（formats.misc の scan_exif・scan_xmp）。
その対処として、ファイルの作りの中の「情報の塊」だけを取り除き、画像のデータ（JPEG の圧縮したデータ・PNG の IDAT）は
バイト列のまま写す。消えた後に元と同じ画素に戻るかは、両方を PIL で開いて画素を比べて確かめる（違えば書き換えない）。

残すもの: 向き（EXIF の Orientation。向きを失うと横倒しで表示される）・色の情報（ICC・sRGB・ガンマなど）・
JFIF と Adobe の印（色の変換の決まりで、無くすと色が変わる）・APNG の動きの情報。
消すもの: EXIF（GPS・撮影日時・機種・サムネイルを含む）・XMP（拡張 XMP を含む）・IPTC（Photoshop の情報）・コメント・
そのほかの道具の独自の塊（JPEG の APP3〜APP13・APP15、PNG の tEXt・zTXt・iTXt・eXIf・知らない塊）・画像の終わりの後ろに付いたデータ
（JPEG の連写・深度・HDR の明るさの別の画像など。そこにも写真の情報が入るため）。
"""

from __future__ import annotations

import hashlib
import io
import os
import struct
import zlib

from .remedy_write import RemedyError, Selection

MAX_PHOTO_BYTES = 512 * 1024 * 1024  # 読み込む写真の大きさの上限（丸ごとメモリに載せるため）
ORIENTATION_TAG = 0x0112
PNG_SIG = b"\x89PNG\r\n\x1a\n"
# 残す PNG の塊（画像そのもの・色・透明・画素の大きさ・APNG の動き）。これ以外（文字・EXIF・時刻・知らない塊）は消す
PNG_KEEP = {
    b"IHDR",
    b"PLTE",
    b"IDAT",
    b"IEND",
    b"tRNS",
    b"cHRM",
    b"gAMA",
    b"iCCP",
    b"sBIT",
    b"sRGB",
    b"cICP",
    b"mDCV",
    b"cLLI",
    b"bKGD",
    b"hIST",
    b"pHYs",
    b"sPLT",
    b"acTL",
    b"fcTL",
    b"fdAT",
}
# 長さを持たない JPEG の印（TEM・RSTn）
_JPEG_STANDALONE = {0x01, *range(0xD0, 0xD8)}


def minimal_exif_tiff(orientation: int) -> bytes:
    """向き（Orientation）だけを持つ EXIF の TIFF の形（リトルエンディアン・項目1つ）。"""
    return (
        b"II*\x00"
        + struct.pack("<I", 8)
        + struct.pack("<H", 1)
        + struct.pack("<HHIHH", ORIENTATION_TAG, 3, 1, orientation, 0)
        + struct.pack("<I", 0)
    )


def _jpeg_keep_segment(marker: int, body: bytes, jfif_kept: bool = False) -> bool:
    """JPEG の区切り（長さを持つもの）を残すか。画像を解くのに要るもの・色の情報だけを残す。

    APP0 は、縮小版の画像を持たない（0×0 の）最初の JFIF だけ残す。JFXX（縮小版の画像）・縮小版を持つ JFIF・
    2つ目からの JFIF・ほかの APP0 は消す（縮小版は別の画像で、顔などが写りうるため）。
    jfif_kept は、すでに JFIF を1つ残したか。
    """
    if marker == 0xE0:
        return not jfif_kept and body.startswith(b"JFIF\x00") and len(body) >= 14 and body[12] == 0 and body[13] == 0
    if marker == 0xE2:  # APP2 は ICC（色）だけ残す。MPF（別の画像の目録）・FlashPix は消す
        return body.startswith(b"ICC_PROFILE\x00")
    if marker == 0xEE:  # APP14 は Adobe（色の変換の決まり）だけ残す
        return body.startswith(b"Adobe")
    if 0xE0 <= marker <= 0xEF or marker == 0xFE:  # そのほかの APPn（EXIF・XMP・IPTC・道具の独自の塊）とコメント
        return False
    return True  # 量子化表・ハフマン表・フレーム・リスタートの間隔など、画像を解くのに要るもの


def _segment_length(data: bytes, pos: int) -> int:
    """pos（0xFF の位置）から始まる区切りの、印を含む全体の長さ。壊れていれば RemedyError。"""
    if pos + 4 > len(data):
        raise RemedyError("JPEG の作りが途中で切れています（元のファイルは変えていません）")
    length = int.from_bytes(data[pos + 2 : pos + 4], "big")
    if length < 2 or pos + 2 + length > len(data):
        raise RemedyError("JPEG の区切りの長さが正しくありません（元のファイルは変えていません）")
    return 2 + length


def strip_jpeg(data: bytes, orientation: int = 1) -> tuple[bytes, dict]:
    """JPEG から写真の情報を取り除いたバイト列と、取り除いたものの数を返す。画像の圧縮したデータはそのまま写す。

    向きが 1（そのまま）以外なら、向きだけの EXIF を JFIF の後ろに置き直す。
    """
    if not data.startswith(b"\xff\xd8"):
        raise RemedyError("JPEG の始まりの印がありません（元のファイルは変えていません）")
    out = bytearray(b"\xff\xd8")
    removed = 0
    exif_at = None  # 向きだけの EXIF を差し込む位置（先頭の APP0 の後ろ）
    jfif_kept = False
    pos = 2
    while True:
        if pos + 2 > len(data) or data[pos] != 0xFF:
            raise RemedyError(
                "JPEG の作りを読めませんでした（画像のデータの前で切れている。元のファイルは変えていません）"
            )
        marker = data[pos + 1]
        if marker == 0xFF:  # 詰め物
            pos += 1
            continue
        if marker in _JPEG_STANDALONE:
            out += data[pos : pos + 2]
            pos += 2
            continue
        if marker == 0xD9:
            raise RemedyError("JPEG に画像のデータがありません（元のファイルは変えていません）")
        size = _segment_length(data, pos)
        if marker != 0xE0 and exif_at is None:
            exif_at = len(out)
        if marker == 0xDA:  # 画像のデータの始まり。ここから終わりの印までを、間に入った情報の塊を除いて写す
            end, drops = _jpeg_image_end(data, pos)
            start = pos
            for d_start, d_end in drops:
                out += data[start:d_start]
                start = d_end
            out += data[start:end]
            removed += len(drops)
            trailer = len(data) - end
            break
        if _jpeg_keep_segment(marker, data[pos + 4 : pos + size], jfif_kept):
            out += data[pos : pos + size]
            jfif_kept = jfif_kept or marker == 0xE0
        else:
            removed += 1
        pos += size
    if exif_at is None:
        exif_at = 2
    if orientation != 1:
        tiff = b"Exif\x00\x00" + minimal_exif_tiff(orientation)
        seg = b"\xff\xe1" + struct.pack(">H", len(tiff) + 2) + tiff
        out[exif_at:exif_at] = seg
    return bytes(out), {"meta_blocks": removed, "trailer_bytes": trailer}


def _jpeg_image_end(data: bytes, pos: int) -> tuple[int, list[tuple[int, int]]]:
    """最初の SOS（pos）から、画像の終わりの印（EOI）の直後までの位置と、間に入った消す区切りの範囲の並び。

    圧縮したデータの中の 0xFF は 0x00 かリスタートの印が続く。プログレッシブの JPEG では、走査の間に表（DHT）や
    次の SOS が入るので、長さを持つ区切りは長さで飛ばす（その中の 0xFFD9 を終わりと読み違えない）。
    間に入ったコメント・APPn（決まりの上では置けるが、まず見ない）は、ほかの所と同じく消す範囲として返す。
    """
    drops: list[tuple[int, int]] = []
    pos += _segment_length(data, pos)
    while True:
        ff = data.find(b"\xff", pos)
        if ff < 0 or ff + 1 >= len(data):
            raise RemedyError(
                "JPEG の終わりの印が見つかりません（途中で切れている可能性。元のファイルは変えていません）"
            )
        nxt = data[ff + 1]
        if nxt == 0x00 or nxt in _JPEG_STANDALONE or nxt == 0xFF:
            pos = ff + 1 if nxt == 0xFF else ff + 2
            continue
        if nxt == 0xD9:
            return ff + 2, drops
        size = _segment_length(data, ff)
        if (0xE0 <= nxt <= 0xEF or nxt == 0xFE) and not _jpeg_keep_segment(nxt, data[ff + 4 : ff + size], True):
            drops.append((ff, ff + size))
        pos = ff + size


def strip_png(data: bytes, orientation: int = 1) -> tuple[bytes, dict]:
    """PNG から写真の情報の塊を取り除いたバイト列と、取り除いた塊の数を返す。IDAT（画像のデータ）はそのまま写す。

    向きが 1 以外なら、向きだけの eXIf を最初の IDAT の前に置き直す。
    """
    if not data.startswith(PNG_SIG):
        raise RemedyError("PNG の始まりの印がありません（元のファイルは変えていません）")
    out = bytearray(PNG_SIG)
    removed = 0
    pos = len(PNG_SIG)
    placed = orientation == 1
    while True:
        if pos + 12 > len(data):
            raise RemedyError(
                "PNG の終わりの塊（IEND）が見つかりません（途中で切れている可能性。元のファイルは変えていません）"
            )
        length = int.from_bytes(data[pos : pos + 4], "big")
        ctype = bytes(data[pos + 4 : pos + 8])
        end = pos + 12 + length
        if end > len(data):
            raise RemedyError("PNG の塊の長さが正しくありません（元のファイルは変えていません）")
        if ctype == b"IDAT" and not placed:
            tiff = minimal_exif_tiff(orientation)
            body = b"eXIf" + tiff
            out += struct.pack(">I", len(tiff)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)
            placed = True
        if ctype in PNG_KEEP:
            out += data[pos:end]
        else:
            removed += 1
        pos = end
        if ctype == b"IEND":
            break
    return bytes(out), {"meta_blocks": removed, "trailer_bytes": len(data) - pos}


def _pixel_digest(data: bytes) -> tuple:
    """画像を解いて（最初のフレームの）画素の形・大きさ・ハッシュとフレームの数を返す。解けなければ RemedyError。"""
    from PIL import Image

    try:
        with Image.open(io.BytesIO(data)) as im:
            frames = getattr(im, "n_frames", 1)
            im.load()
            return im.mode, im.size, hashlib.sha256(im.tobytes()).hexdigest(), frames
    except RemedyError:
        raise
    except Exception as e:  # noqa: BLE001  PIL の失敗は形がさまざま（壊れた画像・大きすぎる画像）
        raise RemedyError(
            f"画像を開いて画素を確かめられませんでした（{type(e).__name__}）。元のファイルは変えていません"
        ) from None


def _orientation(data: bytes) -> int:
    """EXIF の向き（1〜8）。無い・読めなければ 1。"""
    from PIL import Image

    try:
        with Image.open(io.BytesIO(data)) as im:
            value = im.getexif().get(ORIENTATION_TAG)
    except Exception:  # noqa: BLE001  向きが読めなければ、そのままの向きとする
        return 1
    return value if isinstance(value, int) and 1 <= value <= 8 else 1


def rewrite_photo_file(src: str, dst: str, method: str, sel: Selection) -> dict:
    """写真の情報を取り除いた新しいファイルを dst に書く（元の src には書かない）。画素が元と同じことを確かめる。"""
    from .engine import long_path

    if method != "strip_photo_meta":
        raise RemedyError("この形式では選べない方法です")
    if not sel.detections:
        raise RemedyError("対象の位置がありません")
    size = os.path.getsize(long_path(src))
    if size > MAX_PHOTO_BYTES:
        raise RemedyError(
            f"写真が大きすぎる（{MAX_PHOTO_BYTES // 1024 // 1024}MB 超）ため、写真の情報を消せません。ファイルの削除はできます"
        )
    with open(long_path(src), "rb") as f:
        data = f.read()
    orientation = _orientation(data)
    if data.startswith(b"\xff\xd8"):
        new, stats = strip_jpeg(data, orientation)
        others = "動画（モーションフォト）・連写・深度・HDR の明るさなどの別のデータ"
    elif data.startswith(PNG_SIG):
        new, stats = strip_png(data, orientation)
        others = "道具が付けたデータ"
    else:
        raise RemedyError("写真の情報を消せるのは JPEG と PNG だけです。ファイルの削除はできます")
    before = _pixel_digest(data)
    after = _pixel_digest(new)
    # JPEG の連写などの別の画像（MPO）は消すので、フレームの数は比べない。最初のフレームの画素が同じことを確かめる
    if before[:3] != after[:3] or (data.startswith(PNG_SIG) and before[3] != after[3]):
        raise RemedyError("写真の情報を消すと画像が変わってしまうため、書き換えません（元のファイルは変えていません）")
    with open(long_path(dst), "wb") as f:
        f.write(new)
        f.flush()
        os.fsync(f.fileno())
    notes = []
    if stats["trailer_bytes"]:
        notes.append(
            f"画像の終わりの後ろに付いていた{others}（{max(1, stats['trailer_bytes'] // 1024):,} KB）も取り除きました"
        )
    if orientation != 1:
        notes.append("写真の向きの情報だけは残しました（消すと横倒しで表示されるため）")
    return {"meta_blocks": stats["meta_blocks"], "bytes_removed": len(data) - len(new), "notes": notes}

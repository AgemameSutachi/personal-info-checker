"""テキスト・HTML/XML・RTF・メール・画像・対象外・形式不明の処理。"""

from __future__ import annotations

import email
import email.policy
import html
import io
import re

from ..engine import Blob, Collector, ItemResult, OutOfScope, PartialScan, ScanContext, Uncheckable
from ..textdecode import decode_text, entropy, iter_strings_chunked

TEXT_MAX_BYTES = 2 * 1024**3  # これより大きいテキストは少しずつ読む


def handle_empty(ctx: ScanContext, blob: Blob, item: ItemResult, col: Collector, depth: int) -> None:
    item.method = "空（0バイト）"


# これより大きいテキストは丸ごと読まずに少しずつ読む。丸ごと読むと元のバイト列・文字列・行の一覧が同時に載り、
# 大きさの数倍のメモリを使う（SQL のダンプは、ここを超えても列名つきの読み方のまま少しずつ読む）
TEXT_READ_ALL_LIMIT = 64 * 1024 * 1024
SQL_EXTS = (".sql", ".dump", ".pgsql", ".psql", ".ddl")


def handle_text(ctx: ScanContext, blob: Blob, item: ItemResult, col: Collector, depth: int) -> None:
    size = blob.size
    if size > TEXT_READ_ALL_LIMIT:
        return _handle_huge_text(ctx, blob, item, col)
    text, enc = decode_text(blob.read_all())
    item.method = f"テキスト（{enc}）"
    from .dbdump import looks_like_sql, scan_copy_rows, scan_sql_text

    base = (blob.name_hint or blob.display).replace("\\", "/").rsplit("/", 1)[-1].rsplit("!", 1)[-1]
    if base in ctx.pg_columns:
        table, columns = ctx.pg_columns[base]
        scan_copy_rows(text, table, columns, col, item)
        return

    if blob.ext in SQL_EXTS or looks_like_sql(text):
        col.pos_layout = "sqldump"  # 対処のために、表・行・列で位置を集める（COPY の行・INSERT の組）
        scan_sql_text(text, col, item)
    elif blob.ext in (".csv", ".tsv", ".tab") or _looks_tabular(text):
        _scan_delimited(text, col, item)
    else:
        col.pos_layout = "lines"  # 対処のために、行番号で位置を集める（空のままなら集めない）
        col.add_lines(text, method="本文")
    scan_embedded_base64(ctx, blob, item, text, depth)


MAGICS = (
    b"PK\x03\x04",
    b"%PDF",
    b"\xd0\xcf\x11\xe0",
    b"\xff\xd8\xff",
    b"\x89PNG",
    b"7z\xbc\xaf",
    b"Rar!",
    b"\x1f\x8b",
    b"{\\rtf",
    b"GIF8",
)


RE_B64_LINE = re.compile(r"[A-Za-z0-9+/_\-]{16,}={0,2}")  # 行まるごとが base64 の行（MIME の 76 文字ごとの改行など）
RE_B64_INLINE = re.compile(
    r"(?<![A-Za-z0-9+/_\-])[A-Za-z0-9+/_\-]{80,}={0,2}(?![A-Za-z0-9+/_\-])"
)  # 行の中の長い base64
B64_LIMIT = 500


def _b64_candidates(text: str):
    """base64 らしい塊を返す。連続する「base64 だけの行」は1つにつなぎ、行の中の長い並び（data=… や JSON の値）も拾う。"""
    block: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        if RE_B64_LINE.fullmatch(s):
            block.append(s)
            continue
        if block and re.fullmatch(r"[A-Za-z0-9+/_\-]{1,15}={0,2}", s):
            block.append(s)  # MIME の最後の短い行
            yield "".join(block)
            block = []
            continue
        if block:
            yield "".join(block)
            block = []
        for m in RE_B64_INLINE.finditer(line):
            yield m.group(0)
    if block:
        yield "".join(block)


def _b64_decode(s: str) -> bytes | None:
    import base64
    import binascii

    if len(s) < 64 or not re.search(r"[A-Z]", s) or not re.search(r"[a-z]", s):
        return None  # 16進の羅列・数字だけ・大文字だけの並びは base64 ではない
    s = s.rstrip("=")
    s += "=" * (-len(s) % 4)
    try:
        if "-" in s or "_" in s:
            return base64.urlsafe_b64decode(s)
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None


def scan_embedded_base64(ctx: ScanContext, blob: Blob, item: ItemResult, text: str, depth: int) -> None:
    """テキスト・JSON・XML・メールの中に base64 で埋め込まれた中身（添付ファイル・画像・文書）を取り出して検査する。"""
    n = 0
    for cand in _b64_candidates(text):
        data = _b64_decode(cand)
        if not data or len(data) < 32:
            continue
        looks_file = any(data.startswith(mg) for mg in MAGICS)
        if not looks_file:
            # ファイルの目印が無いものは、UTF-8 の文字として素直に読めるときだけ埋め込みとみなす
            # （cp932 で読むと乱数でも仮名に見えてしまい、長いハイフン入りの名前・パスを埋め込みと取り違える）
            head = data[:4096]
            decoded = None
            for cut in range(4):
                try:
                    decoded = head[: len(head) - cut].decode("utf-8")
                    break
                except UnicodeDecodeError:
                    continue
            if decoded is None or not decoded:
                continue
            good = sum(1 for c in decoded if c.isprintable() or c in "\r\n\t")
            if good / max(1, len(decoded)) < 0.9:
                continue  # 中身がファイルでも文字でもない（ハッシュ・鍵など）
        if n >= B64_LIMIT:
            from ..engine import PartialScan

            raise PartialScan(
                f"base64 の埋め込みが {B64_LIMIT} 件を超えたため、{B64_LIMIT + 1} 件目以降は検査していない"
            )
        n += 1
        ctx.scan_nested(
            f"{blob.display}!（base64 の埋め込み {n}）", data=data, depth=depth + 1, name_hint=f"embedded{n}.bin"
        )
    if n:
        item.notes.append(f"base64 で埋め込まれた中身 {n} 件を取り出して検査した")


def _handle_huge_text(ctx: ScanContext, blob: Blob, item: ItemResult, col: Collector) -> None:
    """巨大なテキストを、文字コードを先頭で判定してから少しずつ読む（表なら列見出しつきで）。

    丸ごと読む経路と違い、埋め込まれた base64（添付など）は見ない（README の「できないこと」に書いてある）。
    """
    import csv
    import io

    _, enc = decode_text(blob.head(4 * 1024 * 1024))
    enc = enc.split("(")[0].replace("utf-8-sig", "utf-8-sig")
    with blob.open() as raw:
        stream = io.TextIOWrapper(raw, encoding=enc, errors="replace", newline="")
        sample = stream.read(1024 * 1024)
        if sample and not sample.endswith(("\n", "\r")):
            sample += stream.readline(
                4 * 1024 * 1024
            )  # 見本の終わりで行を2つに割らない（改行の無い巨大な1行は打ち切る）
        rest = stream
        from .dbdump import looks_like_sql, scan_copy_rows, scan_sql_lines

        base = (blob.name_hint or blob.display).replace("\\", "/").rsplit("/", 1)[-1].rsplit("!", 1)[-1]
        if base in ctx.pg_columns:
            # pg_dump のディレクトリ形式のデータファイル（toc.dat で列名が分かっている）
            table, columns = ctx.pg_columns[base]
            item.method = f"巨大なテキスト（{enc}）を少しずつ読み取り"

            def copy_lines():
                for ln in io.StringIO(sample, newline=""):
                    yield ln.rstrip("\r\n")
                for ln in rest:
                    yield ln.rstrip("\r\n")

            scan_copy_rows(copy_lines(), table, columns, col, item)
            return
        if blob.ext in SQL_EXTS or looks_like_sql(sample):
            item.method = f"巨大な SQL（{enc}）を少しずつ読み取り"
            col.pos_layout = "sqldump"

            def sql_lines():
                for ln in io.StringIO(sample, newline=""):
                    yield ln.rstrip("\r\n")
                for ln in rest:
                    yield ln.rstrip("\r\n")

            scan_sql_lines(sql_lines(), col, item)
            return
        if blob.ext in (".csv", ".tsv", ".tab") or _looks_tabular(sample):
            delim = "\t" if sample.count("\t") > sample.count(",") else ","
            csv.field_size_limit(2**31 - 1)

            def lines():
                yield from io.StringIO(sample)
                yield from rest

            from openpyxl.utils import get_column_letter

            col.pos_layout = "csv" + delim
            col.add_table(
                csv.reader(lines(), delimiter=delim),
                lambda r, c: f"{r}行目 {get_column_letter(c + 1)}列",
                method="区切り文字の表",
            )
            item.method = f"巨大な表（{enc}）を少しずつ読み取り"
            return
        line_no = 0
        buf: list[str] = []

        col.pos_layout = "lines"

        def flush():
            nonlocal buf
            if buf:
                col.add_lines(
                    "".join(buf),
                    location_prefix=f"{line_no - len(buf) + 1}行目から ",
                    method="本文",
                    line_offset=line_no - len(buf),
                )
                buf = []

        for ln in io.StringIO(sample):
            line_no += 1
            buf.append(ln)
        for ln in rest:
            line_no += 1
            buf.append(ln)
            if len(buf) >= 5000:
                flush()
        flush()
        item.method = f"巨大なテキスト（{enc}）を少しずつ読み取り（{line_no:,}行）"


def _looks_tabular(text: str) -> bool:
    from collections import Counter

    lines = [ln for ln in text[:50000].splitlines()[:30] if ln.strip()]
    if len(lines) < 2:
        return False
    for sep in (",", "\t"):
        counts = [ln.count(sep) for ln in lines]
        common, freq = Counter(c for c in counts if c >= 1).most_common(1)[0] if any(counts) else (0, 0)
        if common >= 1 and freq >= max(2, len(lines) * 0.6):
            return True
    return False


def _scan_delimited(text: str, col: Collector, item: ItemResult) -> None:
    import csv
    import io

    sample = text[:20000]
    delim = "\t" if sample.count("\t") > sample.count(",") else ","
    csv.field_size_limit(2**31 - 1)  # 巨大なセルでも止まらないように
    reader = csv.reader(io.StringIO(text), delimiter=delim)
    from openpyxl.utils import get_column_letter

    col.pos_layout = "csv" + delim  # 対処のために、行・列で位置を集める
    col.add_table(reader, lambda r, c: f"{r}行目 {get_column_letter(c + 1)}列", method="区切り文字の表")
    item.method += f"・表として読み取り（区切り「{'タブ' if delim == chr(9) else 'カンマ'}」）"


BLOCK_TAGS = re.compile(
    r"</(?:p|div|li|tr|td|th|h[1-6]|br|table|section|article|w:p|a:p|text:p|text:h|si|row|c)\s*>|<br\s*/?>",
    re.I,
)
RE_TAG = re.compile(r"<[^>]{0,2000}>", re.S)
RE_SCRIPT = re.compile(r"<(script|style)\b.*?</\1\s*>", re.I | re.S)
RE_ATTR = re.compile(r'="([^"]{6,500})"')


def markup_to_text(src: str) -> str:
    """HTML/XML から本文の文字を取り出す（段落の区切りは改行にする）。"""
    s = RE_SCRIPT.sub(" ", src)
    s = BLOCK_TAGS.sub("\n", s)
    s = RE_TAG.sub("", s)
    return html.unescape(s)


def attribute_texts(src: str) -> list[str]:
    """属性値のうち個人情報を含みうるもの（mailto: や長い数字・日本語）を拾う。"""
    out = []
    for m in RE_ATTR.finditer(src):
        v = m.group(1)
        if "@" in v or re.search(r"[0-9]{7,}|[\u3040-\u30ff\u4e00-\u9fff]", v):
            out.append(html.unescape(v))
    return out


def handle_markup(ctx: ScanContext, blob: Blob, item: ItemResult, col: Collector, depth: int) -> None:
    src, enc = decode_text(blob.read_all())
    item.method = f"タグを除いた本文と属性値（{enc}）"
    col.add_lines(markup_to_text(src), method="本文")
    scan_embedded_base64(ctx, blob, item, src, depth)  # Word 2003 XML の w:binData など
    for v in attribute_texts(src):
        col.add_text(v, "属性値", method="属性値")


def rtf_to_text(src: bytes) -> str:
    """RTF から本文を取り出す。\\'xx は文書の文字コード（既定 cp932）、\\uN は Unicode として読む。"""
    s = src.decode("latin-1")
    m = re.search(r"\\ansicpg(\d+)", s)
    codepage = f"cp{m.group(1)}" if m else "cp932"
    try:
        "".encode(codepage)
    except LookupError:
        codepage = "cp932"
    out: list[str] = []
    pending = bytearray()
    i = 0
    n = len(s)
    skip_groups = ("\\fonttbl", "\\colortbl", "\\stylesheet", "\\info", "\\*", "\\pict", "\\themedata", "\\datastore")
    depth_skip: list[int] = []
    level = 0
    uc_skip = 1

    def flush() -> None:
        if pending:
            out.append(pending.decode(codepage, errors="replace"))
            pending.clear()

    while i < n:
        ch = s[i]
        if ch == "{":
            level += 1
            rest = s[i + 1 : i + 20]
            if any(rest.startswith(g) for g in skip_groups) and not rest.startswith("\\*\\shppict"):
                depth_skip.append(level)
            i += 1
            continue
        if ch == "}":
            if depth_skip and depth_skip[-1] == level:
                depth_skip.pop()
            level -= 1
            i += 1
            continue
        if depth_skip:
            i += 1
            continue
        if ch == "\\":
            if i + 1 < n and s[i + 1] == "'":
                try:
                    pending.append(int(s[i + 2 : i + 4], 16))
                except ValueError:
                    pass
                i += 4
                continue
            m2 = re.match(r"\\([a-zA-Z]+)(-?\d+)? ?", s[i:])
            if m2:
                word, arg = m2.group(1), m2.group(2)
                i += len(m2.group(0))
                if word == "u" and arg is not None:
                    flush()
                    code = int(arg)
                    out.append(chr(code + 65536 if code < 0 else code))
                    # 後続の代替文字を読み飛ばす
                    j = 0
                    while j < uc_skip and i < n:
                        if s[i] == "\\" and i + 1 < n and s[i + 1] == "'":
                            i += 4
                        else:
                            i += 1
                        j += 1
                elif word == "uc" and arg is not None:
                    uc_skip = int(arg)
                elif word in ("par", "line", "row", "cell", "sect", "page"):
                    flush()
                    out.append("\n")
                elif word == "tab":
                    flush()
                    out.append("\t")
                continue
            if i + 1 < n:
                flush()
                if s[i + 1] in "\\{}":
                    out.append(s[i + 1])
                i += 2
                continue
        if ch in "\r\n":
            i += 1
            continue
        flush()
        out.append(ch)
        i += 1
    flush()
    return "".join(out)


def handle_rtf(ctx: ScanContext, blob: Blob, item: ItemResult, col: Collector, depth: int) -> None:
    data = blob.read_all()
    text = rtf_to_text(data)
    item.method = "RTF の本文を復号"
    col.add_lines(text, method="本文")
    # 埋め込みオブジェクト（\objdata の16進）は生データとしても走査する
    for m in re.finditer(rb"\\objdata\s*([0-9a-fA-F\s]{200,})", data):
        try:
            raw = bytes.fromhex(m.group(1).decode("ascii"))
        except ValueError:
            continue
        idx = min(
            [p for p in (raw.find(b"\xd0\xcf\x11\xe0"), raw.find(b"PK\x03\x04"), raw.find(b"%PDF")) if p >= 0],
            default=-1,
        )
        if idx >= 0:
            ctx.scan_nested(f"{blob.display}!埋め込みオブジェクト{m.start()}", data=raw[idx:], depth=depth + 1)


def handle_eml(ctx: ScanContext, blob: Blob, item: ItemResult, col: Collector, depth: int) -> None:
    msg = email.message_from_bytes(blob.read_all(), policy=email.policy.default)
    item.method = "メールのヘッダー・本文・添付"
    for key in ("From", "To", "Cc", "Bcc", "Reply-To", "Subject", "Sender"):
        for v in msg.get_all(key, []) or []:
            col.add_text(str(v), f"ヘッダー {key}", method="ヘッダー")
    n_att = 0
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        disp = part.get_content_disposition()
        filename = part.get_filename()
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception as e:
            from ..models import ItemResult as _IR, Status as _St

            ctx.items.append(
                _IR(
                    path=f"{blob.display}!{filename or ctype}",
                    kind="メールの部品",
                    status=_St.UNCHECKABLE,
                    reason=f"メールの部品を復号できなかった（{type(e).__name__}: {e}）",
                    depth=depth + 1,
                )
            )
            continue
        if disp == "attachment" or filename or not ctype.startswith("text/"):
            if ctype == "message/rfc822":
                inner = part.get_payload()
                payload = inner[0].as_bytes() if isinstance(inner, list) and inner else payload
            if not payload:
                continue
            n_att += 1
            name = filename or f"添付{n_att}"
            ctx.scan_nested(f"{blob.display}!{name}", data=payload, depth=depth + 1, name_hint=name)
            continue
        charset = part.get_content_charset() or "utf-8"
        try:
            text = payload.decode(charset, errors="replace")
        except LookupError:
            text, _ = decode_text(payload)
        if ctype == "text/html":
            text = markup_to_text(text)
        col.add_lines(text, location_prefix="本文 ", method="本文")


def handle_image(ctx: ScanContext, blob: Blob, item: ItemResult, col: Collector, depth: int) -> None:
    from PIL import Image

    data = blob.read_all()
    import io

    from .. import ocr

    if ocr.is_jpeg_xr(data):
        _handle_jpeg_xr(ctx, data, item, col)
        return
    try:
        with Image.open(io.BytesIO(data)) as im:
            w, h = im.size
            frames = getattr(im, "n_frames", 1)
    except Exception as e:
        raise Uncheckable(f"画像を開けなかった（壊れているか未対応の形式）: {e}")
    if max(w, h) < ctx.options.min_image_px:
        item.method = f"{w}×{h}px の小さな画像（文字を読み取れる大きさでないため検査不要）"
        return
    if not ctx.options.ocr:
        raise Uncheckable("OCR を無効にして実行したため画像の中の文字を検査していない（要目視）")
    if not ocr.is_available():
        raise Uncheckable(f"OCR が使えないため画像の中の文字を検査できない（要目視）: {ocr.unavailable_reason()}")
    text = ocr.ocr_image_bytes(data)
    item.method = f"OCR（{w}×{h}px・{frames}ページ）"
    item.notes.append("画像の文字は OCR で読み取った（手書き・かすれ・小さい文字は読み落としうる）")
    col.add_lines(text, location_prefix="OCR ", method="OCR", ocr=True)


def _handle_jpeg_xr(ctx: ScanContext, data: bytes, item: ItemResult, col: Collector) -> None:
    """JPEG XR（HD Photo。PowerPoint・Word で画像に効果をかけたときに残る元の画像 .wdp など）を OCR で検査する。

    PIL では開けないので、Windows の画像の部品（WIC）で開く。WIC は OCR と同じ WinRT で呼ぶので、OCR が使えないときは
    大きさも分からず、検査できない理由を OCR が使えないことにする。
    """
    from .. import ocr

    if not ctx.options.ocr:
        raise Uncheckable("OCR を無効にして実行したため画像（JPEG XR）の中の文字を検査していない（要目視）")
    if not ocr.is_available():
        raise Uncheckable(
            "OCR が使えないため画像（JPEG XR）の中の文字を検査できない（要目視。JPEG XR は Windows の部品で開くため、"
            f"OCR が使えないと開けない）: {ocr.unavailable_reason()}"
        )
    try:
        img = ocr.open_with_wic(data)
    except ValueError as e:
        raise Uncheckable(f"画像（JPEG XR）を開けなかった: {e}")
    w, h = img.size
    if max(w, h) < ctx.options.min_image_px:
        item.method = f"{w}×{h}px の小さな画像（文字を読み取れる大きさでないため検査不要）"
        return
    text = ocr.ocr_pil_image(img)
    item.method = f"OCR（JPEG XR・{w}×{h}px）"
    item.notes.append("画像の文字は OCR で読み取った（手書き・かすれ・小さい文字は読み落としうる）")
    col.add_lines(text, location_prefix="OCR ", method="OCR", ocr=True)


# 名前は Microsoft Store の日本語の表示（2026-11 に確かめた）。HEVC は有料のことがある
HEIF_HELP = (
    "Microsoft Store から「HEIF 画像表示オプション」を入れるか、JPEG に変換すれば検査できる。"
    "HEIC は「HEVC ビデオ拡張機能」（有料のことがある）、AVIF は「AV1 ビデオ拡張機能」も要る"
)
# WIC が「その形式を開く部品が無い」ときの値（WINCODEC_ERR_COMPONENTNOTFOUND = 0x88982F50 を符号つきで表したもの）
_WIC_COMPONENT_NOT_FOUND = "-2003292336"
_WIN_ERROR = re.compile(r"\[WinError -?\d+\][^\n]*")


def _open_heif_with_pillow(data: bytes):
    """pillow-heif（任意の追加。入れると Windows の拡張が無い PC でも HEIC を読める）で開く。入っていなければ None。"""
    try:
        import pillow_heif
    except (ImportError, OSError):  # 入っていない・中の DLL を読み込めない
        return None
    from PIL import Image

    pillow_heif.register_heif_opener()
    img = Image.open(io.BytesIO(data))
    img.load()
    return img


def handle_image_unsupported(ctx: ScanContext, blob: Blob, item: ItemResult, col: Collector, depth: int) -> None:
    """HEIC・AVIF（iPhone の写真など）を OCR で検査する。

    PIL では開けないので、まず Windows の画像の部品（WIC・Windows の HEIF の拡張）で開き、開けなければ
    pillow-heif（入っていれば）で開く。どちらも開けなければ、入れ方を添えて検査できない項目にする。
    pillow-heif は必須の依存にしない（配布の wheel が GPLv2 の x265 を含むため、配布版の exe には入れていない）。
    連写・深度などの補助の画像は読まず、主の画像だけを検査する。
    """
    from PIL import Image

    from .. import ocr

    if not ctx.options.ocr:
        raise Uncheckable("OCR を無効にして実行したため画像（HEIC/AVIF）の中の文字を検査していない（要目視）")
    if not ocr.is_available():
        raise Uncheckable(
            f"OCR が使えないため画像（HEIC/AVIF）の中の文字を検査できない（要目視）: {ocr.unavailable_reason()}"
        )
    data = blob.read_all()
    how = "Windows の部品"
    try:
        img = ocr.open_with_wic(data)
    except ValueError as e:
        wic_error = str(e)
        if "画素数が大きすぎる" in wic_error:  # 拡張を入れても直らないので、入れ方を案内しない
            raise Uncheckable(f"画像（HEIC/AVIF）の画素数が大きすぎるため検査していない（要目視）: {wic_error}")
        no_codec = _WIC_COMPONENT_NOT_FOUND in wic_error
        detail = _WIN_ERROR.search(wic_error)
        detail = f"（詳細: {detail.group(0)}）" if detail else ""
        try:
            img = _open_heif_with_pillow(data)
        except Image.DecompressionBombError as pe:
            raise Uncheckable(f"画像（HEIC/AVIF）の画素数が大きすぎるため検査していない（要目視）: {pe}")
        except Exception as pe:  # pillow-heif の中の失敗（壊れている・未対応の符号化）
            help_text = f"。{HEIF_HELP}" if no_codec else ""
            raise Uncheckable(f"画像（HEIC/AVIF）を開けなかった（壊れている可能性。要目視）{help_text}: {pe}")
        how = "pillow-heif"
        if img is None:
            if no_codec:
                raise Uncheckable(
                    f"この PC の Windows では画像（HEIC/AVIF）を開けないため検査できない（要目視）。{HEIF_HELP}"
                )
            raise Uncheckable(
                "画像（HEIC/AVIF）を開けなかった（壊れているか、この PC の Windows では開けない符号化。要目視）。"
                f"壊れていなければ、{HEIF_HELP}{detail}"
            )
    w, h = img.size
    if max(w, h) < ctx.options.min_image_px:
        item.method = f"{w}×{h}px の小さな画像（文字を読み取れる大きさでないため検査不要）"
        return
    text = ocr.ocr_pil_image(img)
    item.method = f"OCR（HEIC/AVIF・{w}×{h}px・{how}で開いた）"
    item.notes.append("画像の文字は OCR で読み取った（手書き・かすれ・小さい文字は読み落としうる）")
    col.add_lines(text, location_prefix="OCR ", method="OCR", ocr=True)


def handle_out_of_scope(ctx: ScanContext, blob: Blob, item: ItemResult, col: Collector, depth: int) -> None:
    if item.kind == "実行ファイル":
        # 自己解凍形式・インストーラーは、実行ファイルの後ろに書庫を持つ。7-Zip で開けるなら中身を検査する
        from .archive import _decode_7z, _run_7z, find_7z, handle_with_7z_exe

        exe = find_7z(ctx.options.sevenzip)
        if exe:
            r = _run_7z(
                exe, ["l", "-slt", "-sccUTF-8", "-pPII_CHECKER_NO_PASSWORD", ctx.blob_as_path(blob)], timeout=600
            )
            out = _decode_7z(r.stdout)
            head = out.split("----------", 1)[0]
            types = re.findall(r"^Type = (.+)$", head, re.M)
            archive_types = [t.strip() for t in types if t.strip() not in ("PE", "ELF", "MachO", "TE", "COFF", "Mub")]
            if archive_types:
                item.kind = f"自己解凍形式・インストーラー（{archive_types[-1]}）"
                return handle_with_7z_exe(ctx, blob, item, col, depth, kind="sfx")
        else:
            raise Uncheckable("実行ファイルの中に圧縮ファイル（自己解凍形式）が無いかを確かめるには 7-Zip が要る")
    raise OutOfScope(f"{item.kind}は文字情報を持たない形式として対象外（中の映像・音声・プログラムは検査していない）")


# numpy の型の文字のうち、数を表すもの（利用者に見せる呼び名）
NPY_NUMERIC_KINDS = {
    "b": "真偽",
    "?": "真偽",
    "i": "整数",
    "u": "整数",
    "f": "小数",
    "c": "複素数",
    "m": "時間の長さ",
    "M": "日時",
}
NPY_CHUNK_BYTES = 4 * 1024 * 1024
NPY_MAX_WIDTH = 64 * 1024 * 1024  # 文字の配列の1要素の幅の上限（これを超える頭は壊れているとみなす）


def handle_npy(ctx: ScanContext, blob: Blob, item: ItemResult, col: Collector, depth: int) -> None:
    """numpy の .npy（.npz の中身も）。数の配列は文字を含まないので対象外、文字の配列は要素ごとに検査する。

    以前は形式不明として扱い、中身の数がばらけていると「圧縮または暗号化されている」で検査不能になっていた
    （実物の F の検査で 628 件）。型の分からないもの（object の pickle・構造体の型）・頭が壊れているもの・
    頭に書いた大きさと本体の大きさが合わないもの（後ろに別の中身を足したもの）は、今までどおり形式不明の読み方。
    """
    import ast
    import re
    import struct

    head = blob.head(65536)
    try:
        major = head[6]
        if major == 1:
            (hlen,) = struct.unpack("<H", head[8:10])
            start = 10
        else:
            (hlen,) = struct.unpack("<I", head[8:12])
            start = 12
        raw = head[start : start + hlen].decode("utf-8" if major >= 3 else "latin1")
        meta = ast.literal_eval(raw.strip())
        descr, shape = meta["descr"], tuple(int(n) for n in meta["shape"])
    except Exception:  # noqa: BLE001  頭が壊れている・読めない形は、形式不明と同じ読み方へ
        return handle_unknown(ctx, blob, item, col, depth)
    m = re.fullmatch(r"([<>|=])([a-zA-Z?])(\d+)(\[\w+\])?", descr) if isinstance(descr, str) else None
    if not m:
        return handle_unknown(ctx, blob, item, col, depth)  # 構造体の型（列の並び）・object（pickle）など
    order, kind, size = m.group(1), m.group(2), int(m.group(3))
    count = 1
    for n in shape:
        count *= n
    shape_text = "×".join(str(n) for n in shape) if shape else "1"
    body = start + hlen
    if kind in NPY_NUMERIC_KINDS:
        if blob.size != body + count * size:
            return handle_unknown(ctx, blob, item, col, depth)  # 頭の記述と合わない（壊れている・別の中身がある）
        if kind in "iu" and size == 1:
            # 1バイトの整数の配列には文字のバイト列をそのまま詰められる（評価の指摘）。言い切らずに文字として読む
            return handle_unknown(ctx, blob, item, col, depth)
        item.method = f"numpy の配列の頭を読んだ（型 {descr}・形 {shape}）"
        raise OutOfScope(f"数だけの配列（numpy の .npy・{NPY_NUMERIC_KINDS[kind]}・{shape_text} 個）で、文字を含まない")
    if kind not in "SU":
        return handle_unknown(ctx, blob, item, col, depth)
    width = size * (4 if kind == "U" else 1)
    if width > NPY_MAX_WIDTH or blob.size > body + count * width:
        return handle_unknown(ctx, blob, item, col, depth)
    if width <= 0 or count == 0:
        item.method = f"numpy の文字の配列（型 {descr}・形 {shape}・要素なし）"
        return
    enc = ("utf-32-be" if order == ">" else "utf-32-le") if kind == "U" else None
    per = max(1, NPY_CHUNK_BYTES // width)
    index = 0
    rest = b""
    with blob.open() as f:
        f.seek(body)
        while index < count:
            data = f.read(width * min(per, count - index))
            if not data:
                break
            usable = len(data) - len(data) % width
            rest = data[usable:]
            for off in range(0, usable, width):
                text = _npy_cell_text(data[off : off + width], enc)
                if text:
                    col.add_text(text, f"要素 {index + 1}", method="numpy の文字の配列")
                index += 1
            if rest:
                break
    if rest:
        text = _npy_cell_text(rest, enc)  # 途中で切れた最後の要素も、読める分は検査する
        if text:
            col.add_text(text, f"要素 {index + 1}", method="numpy の文字の配列")
    item.method = f"numpy の文字の配列（型 {descr}・形 {shape}・{index}件）"
    if index < count:
        raise PartialScan(f"ファイルが途中で切れていた（{count} 件のうち {index} 件まで読めた。読めた分は検査した）")


def _npy_cell_text(cell: bytes, enc: str | None) -> str:
    if enc:
        cell = cell[: len(cell) - len(cell) % 4]
        return cell.decode(enc, "replace").rstrip("\x00")
    cell = cell.rstrip(b"\x00")
    try:
        return cell.decode("utf-8")
    except UnicodeDecodeError:
        return cell.decode("cp932", "replace")


def handle_unknown(ctx: ScanContext, blob: Blob, item: ItemResult, col: Collector, depth: int) -> None:
    head = blob.head(1024 * 1024)
    e = entropy(head)
    if e > 7.2 and len(head) > 4096:
        if head.startswith(b"PAR1"):
            # 頭は parquet なのに尾の定義が無い（書き出しの途中で止まった .part・途中で切れたコピー）
            raise Uncheckable(
                "Parquet の表の書きかけか途中で切れたもの（末尾にある表の定義が無い）で、中身が圧縮されているため"
                "文字を取り出せない（元の完全なファイルを検査する）"
            )
        raise Uncheckable(
            f"形式不明で、中身が圧縮または暗号化されている（エントロピー {e:.2f}/8）ため文字を取り出せない"
        )
    with blob.open() as f:
        for s in iter_strings_chunked(f.read):
            col.add_text(s, "生データ", method="生データ走査")
    item.method = f"生データ走査（UTF-16/cp932/UTF-8 の文字列を抽出・エントロピー {e:.2f}）"
    raise PartialScan(
        "形式が分からないため、文字として読める部分だけを検査した（独自形式の中の数値や圧縮された部分は読めない）"
    )


DER_OID_ENVELOPED = bytes.fromhex("06092a864886f70d010703")  # PKCS#7 の EnvelopedData（暗号化したデータ）
DER_OID_ENCRYPTED = bytes.fromhex("06092a864886f70d010706")  # PKCS#7 の EncryptedData


def handle_der(ctx: ScanContext, blob: Blob, item: ItemResult, col: Collector, depth: int) -> None:
    """証明書・電子署名（DER）。名前・メールなどの文字は圧縮されずに入っているので、文字の部分を全部読む。

    鍵と署名の値が乱数に近いので、形式不明の読み方ではエントロピーで「圧縮または暗号化」とみなされて検査不能になっていた
    （実物の F の検査で MSI の DigitalSignature・証明書 約 30 件）。
    鍵と証明書をパスワードで包んだもの（PKCS#12・.pfx/.p12）と、暗号化したデータ（S/MIME の .p7m など）は、
    文字の部分を読んでも中身が読めないので、検査したことにせず検査不能にする。
    """
    head = blob.head(256)
    inner = head[4:] if head[1] == 0x82 else head[5:]
    if inner.startswith(b"\x02\x01\x03"):  # PFX の版 3
        raise Uncheckable(
            "パスワードで守られた鍵と証明書のファイル（.pfx・.p12）で、中身が暗号化されているため検査できない"
        )
    if DER_OID_ENVELOPED in head or DER_OID_ENCRYPTED in head:
        raise Uncheckable("暗号化されたデータ（暗号化メールの .p7m など）で、中身が暗号化されているため検査できない")
    with blob.open() as f:
        for s in iter_strings_chunked(f.read):
            col.add_text(s, "証明書・署名の文字", method="DER の文字の部分")
    item.method = "証明書・電子署名（DER）の文字の部分（名前・メール・組織名など）を読んだ"
    item.notes.append("鍵と署名の値（数のデータ）は検査していない")


def handle_stl(ctx: ScanContext, blob: Blob, item: ItemResult, col: Collector, depth: int) -> None:
    """バイナリの STL（3D プリンタ・CAD の形）。文字を持てるのは先頭 80 バイトの見出しだけなので、そこを読む。

    残りは三角形の頂点の小数の並びで、形式不明の読み方ではエントロピーで「圧縮または暗号化」とみなされて
    検査不能になっていた（実物の F の検査で 102 件。3D プリンタのプロジェクト（.3mf・.cxprj）の中の .stl も同じ）。
    """
    from ..sniff import STL_HEADER

    head = blob.head(STL_HEADER + 4)
    text = head[:STL_HEADER].rstrip(b"\x00 ")
    if text:
        try:
            col.add_text(text.decode("utf-8"), "見出し", method="STL の見出し")
        except UnicodeDecodeError:
            col.add_text(text.decode("cp932", "replace"), "見出し", method="STL の見出し")
    count = int.from_bytes(head[STL_HEADER:], "little")
    item.method = f"3D モデル（STL・三角形 {count:,} 個）の見出しを読んだ"
    item.notes.append("形の数値（三角形の頂点・色の値）は文字を含まないので検査していない")


REGION_MAX_CHUNK = 16 * 1024 * 1024  # 塊1つの展開後の上限（ふつうは数 MB 以下。細工した圧縮で膨らみ続けないように）
NBT_MAX_DEPTH = 512  # Minecraft 自身の入れ子の上限
NBT_FIXED = {1: 1, 2: 2, 3: 4, 4: 8, 5: 4, 6: 8}  # 数の型の大きさ（byte・short・int・long・float・double）
NBT_ARRAYS = {7: 1, 11: 4, 12: 8}  # 数の配列の型の1要素の大きさ（byte・int・long の配列）
# 1つずつ歩く要素の数の上限。実物の塊は展開後でも最大 約 170KB（要素は多くて数万）なので、十分に余裕がある。
# 細工した塊（空の複合・空の文字が何百万も並ぶもの）で1ファイルの検査が何時間も止まらないようにする
NBT_MAX_STEPS_CHUNK = 1_000_000
NBT_MAX_STEPS_FILE = 20_000_000
# 検査に回す文字の数の上限（1つずつ検出の処理を通すので、要素よりずっと重い）。実物は1ファイル最大 約2.7万・1塊 最大 117
NBT_MAX_TEXTS_CHUNK = 20_000
NBT_MAX_TEXTS_FILE = 500_000


class NbtTooLarge(ValueError):
    """NBT の要素が多すぎて、決めた手間の内に読み終えられない。"""


def nbt_strings(data: bytes, budget: list[int] | None = None):
    """NBT（Minecraft のデータの形・大きい順の数）の中の文字の値（TAG_String）だけを順に返す。

    ブロックの並びなどの数の配列を文字として読むと「333333333333」のような並びがマイナンバーの形に当たるので、
    数の部分は読み飛ばす。項目の名前（キー）は決まった英語なので返さない。形が壊れていれば ValueError。
    budget（[残り]）を渡すと、ファイル全体で歩ける要素の数をそこから引き、尽きたら NbtTooLarge。
    """
    pos = 0
    end = len(data)
    steps = NBT_MAX_STEPS_CHUNK

    def take(n: int) -> bytes:
        nonlocal pos
        if n < 0 or pos + n > end:
            raise ValueError("NBT が途中で切れている")
        chunk = data[pos : pos + n]
        pos += n
        return chunk

    def text() -> str:
        raw = take(int.from_bytes(take(2), "big"))
        return raw.decode("utf-8", "replace")  # Java の修正 UTF-8 も、ふつうの文字なら UTF-8 と同じ

    # (型, 残りの数) の積み上げで歩く。複合（10）は名前つきの項目が End（0）まで、一覧（9）は同じ型が数だけ並ぶ
    tag = take(1)[0]
    if tag != 10:
        raise ValueError("NBT の先頭が複合の型ではない")
    text()  # 根の名前
    stack: list[list[int]] = [[10, -1]]
    while stack:
        if len(stack) > NBT_MAX_DEPTH:
            raise ValueError("NBT の入れ子が深すぎる")
        steps -= 1
        if budget is not None:
            budget[0] -= 1
            if budget[0] < 0:
                raise NbtTooLarge("ファイル全体の要素が多すぎる")
        if steps < 0:
            raise NbtTooLarge("塊の要素が多すぎる")
        frame = stack[-1]
        if frame[0] == 10:
            tag = take(1)[0]
            if tag == 0:
                stack.pop()
                continue
            text()  # 項目の名前
        else:
            if frame[1] == 0:
                stack.pop()
                continue
            frame[1] -= 1
            tag = frame[0] - 100  # 一覧は要素の型に 100 を足して積んでいる
        if tag in NBT_FIXED:
            take(NBT_FIXED[tag])
        elif tag in NBT_ARRAYS:
            take(int.from_bytes(take(4), "big", signed=True) * NBT_ARRAYS[tag])
        elif tag == 8:
            s = text()
            if s:
                yield s
        elif tag == 9:
            inner = take(1)[0]
            count = int.from_bytes(take(4), "big", signed=True)
            if count > 0:
                if inner == 0 or inner > 12:
                    raise ValueError("NBT の一覧の型が不正")
                if inner in NBT_FIXED:
                    take(
                        count * NBT_FIXED[inner]
                    )  # 数の一覧は1要素ずつ歩かず、まとめて読み飛ばす（細工で遅くさせない）
                else:
                    stack.append([inner + 100, count])
        elif tag == 10:
            stack.append([10, -1])
        else:
            raise ValueError(f"NBT の型が不正（{tag}）")


def handle_region(ctx: ScanContext, blob: Blob, item: ItemResult, col: Collector, depth: int) -> None:
    """Minecraft のワールドの region（.mca・.mcr）。塊ごとに展開し、中の文字（看板・本・名前など）を検査する。

    塊は gzip・zlib で圧縮されているので、形式不明の読み方ではエントロピーで検査不能になっていた
    （実物の F の検査で 96 件・git の履歴の中にも同じものがある）。LZ4・独自の圧縮と、別ファイル（.mcc）に
    置いた大きな塊は読めないので、残ったら一部だけ検査したことにする。
    """
    import zlib

    from ..sniff import REGION_SECTOR, region_chunks

    used = region_chunks(blob, blob.head(2 * REGION_SECTOR))
    if not used:
        return handle_unknown(ctx, blob, item, col, depth)
    done = 0
    skipped: dict[str, int] = {}
    budget = [NBT_MAX_STEPS_FILE]
    texts_left = [NBT_MAX_TEXTS_FILE]
    too_many = "要素が多すぎて読み切れなかった塊"
    with blob.open() as f:
        for index, offset, count in used:
            if budget[0] <= 0:
                skipped[too_many] = skipped.get(too_many, 0) + 1
                continue
            f.seek(offset * REGION_SECTOR)
            top = f.read(5)
            length = int.from_bytes(top[:4], "big") if len(top) == 5 else 0
            kind = top[4] if len(top) == 5 else 0
            if not 1 <= length <= count * REGION_SECTOR:
                skipped["壊れた塊"] = skipped.get("壊れた塊", 0) + 1
                continue
            if kind & 0x80:
                skipped["別ファイル（.mcc）に置いた大きな塊"] = skipped.get("別ファイル（.mcc）に置いた大きな塊", 0) + 1
                continue
            data = f.read(length - 1)
            try:
                if kind in (1, 2):
                    # 1 は gzip（wbits 31）・2 は zlib。どちらも上限までしか展開しない
                    raw = zlib.decompressobj(31 if kind == 1 else 15).decompress(data, REGION_MAX_CHUNK)
                elif kind == 3:
                    raw = data
                else:
                    skipped["LZ4・独自の圧縮の塊"] = skipped.get("LZ4・独自の圧縮の塊", 0) + 1
                    continue
            except (OSError, EOFError, zlib.error):
                skipped["壊れた塊"] = skipped.get("壊れた塊", 0) + 1
                continue
            # 同じ文字は塊ごとに1回だけ検査する（別の塊にあれば、その塊の場所でも出す）
            where = f"塊（チャンク） ({index % 32}, {index // 32})"
            seen: set[str] = set()
            try:
                for s in nbt_strings(raw, budget):
                    if s not in seen:
                        if len(seen) >= NBT_MAX_TEXTS_CHUNK or texts_left[0] <= 0:
                            raise NbtTooLarge("文字の値が多すぎる")
                        seen.add(s)
                        texts_left[0] -= 1
                        col.add_text(s, where, method="region の塊の文字")
            except NbtTooLarge:
                if texts_left[0] <= 0:
                    budget[0] = 0  # 文字の残りが尽きたら、後の塊は読まずに数える
                skipped[too_many] = skipped.get(too_many, 0) + 1
                continue
            except ValueError:
                # 途中で壊れていても、そこまでに読めた文字は検査した（読めた塊には数えない）
                skipped["壊れた塊"] = skipped.get("壊れた塊", 0) + 1
                continue
            done += 1
    item.method = f"Minecraft の region の塊（チャンク）を展開して中の文字を読んだ（{done}/{len(used)} 個）"
    item.notes.append("ブロック・座標などの数値は文字を含まないので検査していない")
    if skipped:
        detail = "・".join(f"{k} {n} 個" for k, n in skipped.items())
        remedy = "ワールドをゲームで開いて保存し直すか、看板・本などを目で確かめる"
        if done == 0:
            raise Uncheckable(f"region の塊（チャンク）を1つも最後まで読めなかった（{detail}）。{remedy}")
        raise PartialScan(
            f"region の塊（チャンク）のうち読めないものがあった（{detail}）。読めた塊は検査した。{remedy}"
        )


def handle_bitlocker(ctx: ScanContext, blob: Blob, item: ItemResult, col: Collector, depth: int) -> None:
    raise Uncheckable("BitLocker で暗号化されたボリュームのため中身を検査できない（回復キーで解除してから再検査）")


def handle_split_volume(ctx: ScanContext, blob: Blob, item: ItemResult, col: Collector, depth: int) -> None:
    if depth > 0 or not blob.path:
        # アーカイブ等の中の続きは、1つ目の有無も中身も確かめられない（中身同士をつないで展開しない）
        raise Uncheckable(
            "アーカイブ等の中にある分割アーカイブの続き。中身を検査できないため、1つ目と一緒に取り出してから検査する"
        )
    if blob.path and depth == 0:
        import glob as _glob
        import os as _os

        base = blob.display  # 写しではなく元のパスで、1つ目が同じフォルダにあるかを見る
        m = (
            re.search(r"\.(\d{3})$", base)
            or re.search(r"\.[zZ](\d{2})$", base)
            or re.search(r"\.part(\d+)\.rar$", base, re.I)
            or re.search(r"\.[rR](\d{2})$", base)  # 古い形式の RAR 分割（1つ目は .rar）
        )
        stem = base[: m.start()] if m else base
        firsts = [
            stem + ".001",
            stem + ".zip",
            stem + ".part1.rar",
            stem + ".part01.rar",
            stem + ".rar",
            stem + ".7z.001",
        ]
        firsts += _glob.glob(_glob.escape(stem) + ".part*1.rar")
        if not any(_os.path.exists(p) for p in firsts if p != base):
            raise Uncheckable("分割アーカイブの続きだが、1つ目のファイルが同じフォルダに無いため中身を検査できない")
    raise OutOfScope(
        "分割アーカイブの2つ目以降。中身は1つ目（.001・.zip・.part1.rar 等）を展開するときに一緒に検査する"
    )

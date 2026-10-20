"""テキスト・HTML/XML・RTF・メール・画像・対象外・形式不明の処理。"""

from __future__ import annotations

import email
import email.policy
import html
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
    from .. import ocr

    if not ocr.is_available():
        raise Uncheckable(f"OCR が使えないため画像の中の文字を検査できない（要目視）: {ocr.unavailable_reason()}")
    text = ocr.ocr_image_bytes(data)
    item.method = f"OCR（{w}×{h}px・{frames}ページ）"
    item.notes.append("画像の文字は OCR で読み取った（手書き・かすれ・小さい文字は読み落としうる）")
    col.add_lines(text, location_prefix="OCR ", method="OCR", ocr=True)


def handle_image_unsupported(ctx: ScanContext, blob: Blob, item: ItemResult, col: Collector, depth: int) -> None:
    raise Uncheckable("HEIC/AVIF 画像は OCR に未対応のため検査できない（要目視。JPEG に変換すれば検査できる）")


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
            raise Uncheckable("実行ファイルの中に書庫（自己解凍形式）が無いかを確かめるには 7-Zip が要る")
    raise OutOfScope(f"{item.kind}は文字情報を持たない形式として対象外（中の映像・音声・プログラムは検査していない）")


def handle_unknown(ctx: ScanContext, blob: Blob, item: ItemResult, col: Collector, depth: int) -> None:
    head = blob.head(1024 * 1024)
    e = entropy(head)
    if e > 7.2 and len(head) > 4096:
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

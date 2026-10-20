"""PDF の対処（黒塗り・ページの削除）。PyMuPDF を使う。

決まり:
- 黒塗りは、見た目だけ隠す注釈では済ませない。検出した値の文字の矩形に塗りつぶしの注釈（redact）を付け、apply_redactions で
  ページの内容そのものから文字を取り除く（画像の中の文字を OCR で拾った分は、画像のその部分の画素を塗りつぶす）。
- 位置は検査のときに集めたもの（formats/pdf.py）: シートは「Nページ」（OCR は「Nページ（OCR）」）、行はそのページの文字の行番号、
  開始・終了はその行の（NFKC で正規化した）文字の範囲。生の値は持たないので、書き換えるときにページの文字を読み直して矩形を求める。
- 黒塗りのあと、文書情報（作成者・題など）・XMP・注釈・フォーム欄・しおり・リンク・埋め込みファイルに残った値も取り除く（remedy_common.Residue）。
- 保存は増分保存にしない（garbage=4・deflate。消した文字が古い版として残らない）。暗号化された PDF は、検査で入れたパスワードで
  開き、同じパスワードで暗号化し直して保存する（パスワードが無ければ断る）。
- 元のファイルには書かない。結果は別のファイル（一時の名前）へ書き、呼び出し側が確定する。
"""

from __future__ import annotations

import re

from . import detectors
from .remedy_common import Residue
from .remedy_write import RemedyError, Selection, _orig_bounds

RE_PAGE_SHEET = re.compile(r"^(\d+)ページ(（OCR）)?$")
BLACK = (0, 0, 0)


def parse_targets(sel: Selection) -> dict[int, dict[str, list]]:
    """選んだ位置を {ページ番号: {"text": [(行, 開始, 終了, 種類)], "ocr": [...]}} にする。"""
    out: dict[int, dict[str, list]] = {}
    for (sheet, pii_type, _rank), arr in sel.groups.items():
        m = RE_PAGE_SHEET.match(sheet)
        if not m:
            raise RemedyError("PDF の位置の形式が正しくありません（検査し直してください）")
        page = out.setdefault(int(m.group(1)), {"text": [], "ocr": []})
        lst = page["ocr" if m.group(2) else "text"]
        for i in range(0, len(arr), 4):
            lst.append((arr[i], arr[i + 2], arr[i + 3], pii_type))
    return out


def line_ranges(text: str) -> list[tuple[int, int]]:
    """str.splitlines と同じ分け方での、各行の（開始, 終了）（行末の改行は含めない。検査の行番号と同じ数え方）。"""
    out = []
    pos = 0
    for ln in text.splitlines(keepends=True):
        parts = ln.splitlines()
        out.append((pos, pos + len(parts[0] if parts else "")))
        pos += len(ln)
    return out


def page_chars(page) -> tuple[str, list | None]:
    """ページの文字列（get_text("text")）と、1文字ずつ対応する箱（改行は None）の並び。対応が取れなければ箱は None。"""
    text = page.get_text("text") or ""
    chars: list[str] = []
    boxes: list = []
    for block in page.get_text("rawdict").get("blocks", []):
        if block.get("type") != 0:
            continue
        for line in block.get("lines", []):
            for span in line.get("spans", []):
                for ch in span.get("chars", []):
                    for c in ch["c"]:
                        chars.append(c)
                        boxes.append(tuple(ch["bbox"]))
            chars.append("\n")
            boxes.append(None)
    return (text, boxes) if "".join(chars) == text else (text, None)


def orig_range(line_text: str, start: int, end: int) -> tuple[int, int] | None:
    """行の（正規化後の）文字の範囲を、元の行の文字の範囲にする。直せないときは行全体（安全側）。範囲が空なら None。"""
    norm = detectors.normalize(line_text)
    end = min(end, len(norm))
    if not 0 <= start < end:
        return None
    bounds = _orig_bounds(line_text, norm)
    if bounds is None:
        return 0, len(line_text)
    return bounds(start, end)


def shrunk(fitz, rect, n_chars: int):
    """隣の文字を巻き込まないよう、矩形を少し内側に縮める（行が詰まっていて文字の箱が上下に重なることがある）。"""
    avg = rect.width / max(1, n_chars)
    dx = min(1.2, max(0.3, avg * 0.12))
    dy = rect.height * 0.25
    if rect.width <= 2 * dx + 0.2:
        dx = 0.0
    return fitz.Rect(rect.x0 + dx, rect.y0 + dy, rect.x1 - dx, rect.y1 - dy)


class PageTargets:
    """1ページの黒塗りの対象（矩形と、消す値）。"""

    def __init__(self) -> None:
        self.rects: list = []
        self.values: dict[str, int] = {}  # 正規化した値 → 文字の層で消す件数（消えたかの確かめに使う）
        self.ocr = False  # 画像の画素も塗りつぶすか


def text_values(page, targets: list) -> tuple[list[tuple[int, int, str, str]], str, list | None]:
    """文字の層の対象を、（ページの文字列での開始, 終了, 正規化した値, 種類）にする。（対象の並び, ページの文字列, 箱）を返す。"""
    text, boxes = page_chars(page)
    lines = line_ranges(text)
    out = []
    for line_no, start, end, pii_type in targets:
        if not 1 <= line_no <= len(lines):
            raise RemedyError("PDF の行の位置が検査と食い違います（ファイルが変わった可能性。検査し直してください）")
        ls, le = lines[line_no - 1]
        rng = orig_range(text[ls:le], start, end)
        if rng is None:
            continue
        a, b = ls + rng[0], ls + rng[1]
        out.append((a, b, detectors.normalize(text[a:b]), pii_type))
    return out, text, boxes


def redact_text_layer(fitz, page, targets: list, page_targets: PageTargets) -> int:
    """文字の層の対象に塗りつぶしの注釈を付ける。付けた矩形の数を返す。"""
    spans, text, boxes = text_values(page, targets)
    n = 0
    for a, b, value, _t in spans:
        page_targets.values[value] = page_targets.values.get(value, 0) + 1
        rects = []
        if boxes is not None:
            valid = [fitz.Rect(bx) for bx in boxes[a:b] if bx is not None]
            if valid:
                rect = valid[0]
                for r in valid[1:]:
                    rect |= r
                rects = [shrunk(fitz, rect, len(valid))]
        if not rects:
            # 文字の箱を取れないときは、ページの検索で場所を探す（同じ文字は全部塗る）
            found = page.search_for(text[a:b]) or page.search_for(value)
            rects = [shrunk(fitz, r, max(1, b - a)) for r in found]
        if not rects:
            raise RemedyError("黒塗りする場所を特定できませんでした（元のファイルは変えていません）")
        for r in rects:
            page.add_redact_annot(r, fill=BLACK)
            page_targets.rects.append(r)
            n += 1
    return n


def redact_ocr_lines(fitz, page, targets: list, page_targets: PageTargets) -> int:
    """画像の文字を OCR で拾った対象の、画像のその部分に塗りつぶしの注釈を付ける。付けた矩形の数を返す。"""
    from PIL import Image

    from . import ocr
    from .formats.pdf import OCR_DPI

    if not ocr.is_available():
        raise RemedyError(
            "画像の中の検出を塗りつぶすには OCR が必要ですが、使えません: " + (ocr.unavailable_reason() or "")
        )
    pix = page.get_pixmap(dpi=OCR_DPI)
    img = (
        Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
        if pix.n < 4
        else Image.frombytes("RGBA", (pix.width, pix.height), pix.samples)
    )
    lines = ocr.ocr_pil_image_lines(img)
    to_page = 72.0 / OCR_DPI
    n = 0
    for line_no, start, end, _t in targets:
        if not 1 <= line_no <= len(lines):
            raise RemedyError(
                "OCR の行の位置が検査と食い違います（読み取りの結果が変わりました。検査し直してください）"
            )
        line = lines[line_no - 1]
        rng = orig_range(line["text"], start, end)
        if rng is None:
            continue
        chars = line["chars"][rng[0] : rng[1]]
        if not chars:
            continue
        height = max(1.0, line["bottom"] - line["top"])
        pad = height * 0.25  # OCR の文字の幅は語の幅を等分した近似なので、横へ少し余裕を取る
        rect = fitz.Rect(
            (min(c[0] for c in chars) - pad) * to_page,
            (line["top"] - height * 0.05) * to_page,
            (max(c[1] for c in chars) + pad) * to_page,
            (line["bottom"] + height * 0.05) * to_page,
        )
        page.add_redact_annot(rect, fill=BLACK)
        page_targets.rects.append(rect)
        page_targets.ocr = True
        n += 1
    return n


def open_pdf(fitz, path: str, passwords):
    """PDF を開く。暗号化されていれば、検査で入れたパスワードで開く（無ければ断る）。（文書, 使ったパスワード）を返す。"""
    try:
        doc = fitz.open(path, filetype="pdf")
    except Exception as e:
        raise RemedyError(f"PDF を開けませんでした（{type(e).__name__}）。元のファイルは変えていません") from None
    used = ""
    if doc.needs_pass:
        for pw in ["", *(passwords or [])]:
            if doc.authenticate(pw):
                used = pw
                break
        else:
            doc.close()
            raise RemedyError(
                "パスワードで暗号化された PDF ですが、検査のときに入れたパスワードが手元に無いため書き換えられません"
                "（検査のときにパスワードを入れて検査し直してください）"
            )
    return doc, used


def encryption_method(fitz, doc) -> int:
    """元の暗号化の方式に合わせた PyMuPDF の指定（読み取れなければ AES-256）。"""
    text = str((doc.metadata or {}).get("encryption") or "")
    if "AES" in text:
        return fitz.PDF_ENCRYPT_AES_128 if "128" in text else fitz.PDF_ENCRYPT_AES_256
    if "RC4" in text:
        return fitz.PDF_ENCRYPT_RC4_40 if "40" in text else fitz.PDF_ENCRYPT_RC4_128
    return fitz.PDF_ENCRYPT_AES_256


def clean_residue(fitz, doc, residue: Residue) -> dict:
    """本文の外（文書情報・XMP・注釈・フォーム欄・しおり・リンク・埋め込みファイル）に残った値を取り除き、ページの縮小画像（/Thumb）も外す。件数を種類別に返す。"""
    done = {
        "metadata": 0,
        "annotations": 0,
        "widgets": 0,
        "bookmarks": 0,
        "links": 0,
        "attachments": 0,
        "thumbnails": 0,
    }
    # 文書情報（標準の項目）
    meta = dict(doc.metadata or {})
    changed = False
    for key in ("author", "title", "subject", "keywords", "creator", "producer"):
        if meta.get(key) and residue.hit(meta[key]):
            meta[key] = ""
            done["metadata"] += 1
            changed = True
    if changed:
        doc.set_metadata({k: v for k, v in meta.items() if k not in ("format", "encryption")})
    # 文書情報の独自の項目（/Company など）と XMP
    done["metadata"] += _clean_custom_info(doc, residue)
    xmp = doc.get_xml_metadata() or ""
    if xmp and residue.hit_markup(xmp):
        doc.del_xml_metadata()
        done["metadata"] += 1
    # 注釈・リンク・フォーム欄
    for page in doc:
        for annot in list(page.annots() or []):
            info = annot.info or {}
            hit = any(residue.hit(info.get(k) or "") for k in ("content", "title", "subject"))
            if not hit and annot.type[1] == "FileAttachment":
                try:
                    hit = residue.embedded_has_pii(annot.get_file(), (annot.file_info or {}).get("filename") or "")
                except Exception:  # noqa: BLE001  取り出せない添付は、判定できないので触らない
                    hit = False
            if hit:
                page.delete_annot(annot)
                done["annotations"] += 1
        for link in page.get_links():
            uri = link.get("uri") or ""
            if uri and residue.hit(_unquote(uri)):
                page.delete_link(link)
                done["links"] += 1
        for w in page.widgets() or []:
            value = w.field_value
            if isinstance(value, str) and value and residue.hit(value):
                try:
                    w.field_value = ""
                    w.update()
                    done["widgets"] += 1
                except Exception:  # noqa: BLE001  書き換えられない欄は、検査し直しの残りに出る
                    pass
    # ページの縮小画像（/Thumb。変える前のページが写っている）
    for page in doc:
        try:
            if doc.xref_get_key(page.xref, "Thumb")[0] == "xref":
                doc.xref_set_key(page.xref, "Thumb", "null")
                done["thumbnails"] += 1
        except Exception:  # noqa: BLE001  縮小画像を外せなくても、ほかの掃除は続ける
            pass
    # しおり
    try:
        toc = doc.get_toc()
    except Exception:  # noqa: BLE001
        toc = []
    if any(residue.hit(str(t[1])) for t in toc):
        done["bookmarks"] = sum(1 for t in toc if residue.hit(str(t[1])))
        new = [[t[0], "－" if residue.hit(str(t[1])) else t[1], t[2]] for t in toc]
        try:
            doc.set_toc(new)
        except Exception:  # noqa: BLE001  付け替えられないときは、しおりを全部外す（値を残さない側に倒す）
            doc.set_toc([])
            done["bookmarks"] = len(toc)
    # 埋め込みファイル
    for name in list(doc.embfile_names() or []):
        try:
            data = doc.embfile_get(name)
        except Exception:  # noqa: BLE001
            continue
        if residue.embedded_has_pii(data, name):
            doc.embfile_del(name)
            done["attachments"] += 1
    return done


def _unquote(uri: str) -> str:
    from urllib.parse import unquote

    return unquote(uri)


def _clean_custom_info(doc, residue: Residue) -> int:
    """文書情報（/Info）の、標準以外の項目（/Company など）に値が残っていれば、その項目を外す。"""
    try:
        kind, ref = doc.xref_get_key(-1, "Info")
        if kind != "xref":
            return 0
        xref = int(ref.split()[0])
        n = 0
        for key in doc.xref_get_keys(xref):
            if key in ("Author", "Title", "Subject", "Keywords", "Creator", "Producer", "CreationDate", "ModDate"):
                continue
            kind, raw = doc.xref_get_key(xref, key)
            if kind in ("string", "name") and residue.hit(_pdf_string(raw)):
                doc.xref_set_key(xref, key, "null")
                n += 1
        return n
    except Exception:  # noqa: BLE001  独自の項目を読めなくても、標準の項目の掃除は済んでいる
        return 0


def _pdf_string(raw: str) -> str:
    """PDF の文字列の表記（(…) か <16進>）を文字列にする（読み取れる範囲で）。"""
    raw = raw.strip()
    if raw.startswith("<") and raw.endswith(">"):
        try:
            data = bytes.fromhex(raw[1:-1])
            return data.decode("utf-16-be") if data[:2] == b"\xfe\xff" else data.decode("latin-1")
        except ValueError:
            return raw
    if raw.startswith("(") and raw.endswith(")"):
        return raw[1:-1]
    return raw


def rewrite_pdf_file(src: str, dst: str, method: str, sel: Selection, maker, passwords=None) -> dict:
    """PDF の黒塗り（redact）・ページの削除（delete_pages）。結果を dst へ書く。元の src には書かない。"""
    import pymupdf as fitz

    targets = parse_targets(sel)
    if not targets:
        raise RemedyError("対象の位置がありません")
    doc, password = open_pdf(fitz, src, passwords)
    try:
        stats = {"pages": 0, "regions": 0, "detections": sel.detections, "pages_removed": 0}
        notes: list[str] = []
        if (doc.metadata or {}).get(
            "encryption"
        ) and not password:  # is_encrypted は、空のパスワードで開けたときは False になる
            notes.append(
                "元の PDF には、編集・印刷などの制限（所有者のパスワード）がありました。書き直した PDF には、その制限は引き継がれません"
            )
        values: set[str] = set()
        for no in targets:
            if not 1 <= no <= doc.page_count:
                raise RemedyError(
                    "PDF のページの位置が検査と食い違います（ファイルが変わった可能性。検査し直してください）"
                )
        if method == "delete_pages":
            if len(targets) >= doc.page_count:
                raise RemedyError(
                    "PDF のすべてのページは削除できません（ページが1つも残らなくなります）。"
                    "ファイル全体を消すなら「ファイルを削除」を選んでください"
                )
            for no in sorted(targets):
                spans, _text, _boxes = text_values(doc[no - 1], targets[no]["text"])
                values.update(v for _a, _b, v, _t in spans)
            doc.delete_pages([no - 1 for no in sorted(targets)])
            stats["pages_removed"] = len(targets)
        elif method == "redact":
            image_mode = getattr(fitz, "PDF_REDACT_IMAGE_PIXELS", 2)
            no_image = getattr(fitz, "PDF_REDACT_IMAGE_NONE", 0)
            no_graphics = getattr(fitz, "PDF_REDACT_LINE_ART_NONE", 0)
            for no in sorted(targets):
                page = doc[no - 1]
                pt = PageTargets()
                n = redact_text_layer(fitz, page, targets[no]["text"], pt)
                n += redact_ocr_lines(fitz, page, targets[no]["ocr"], pt) if targets[no]["ocr"] else 0
                before = detectors.normalize(page.get_text("text") or "")
                counts_before = {v: before.count(v) for v in pt.values}
                page.apply_redactions(images=image_mode if pt.ocr else no_image, graphics=no_graphics)
                after = detectors.normalize(page.get_text("text") or "")
                for v in pt.values:
                    if counts_before[v] and after.count(v) >= counts_before[v]:
                        raise RemedyError(
                            f"{no} ページの黒塗りで、文字が消えませんでした（文字の層の作りが特殊な PDF の可能性）。"
                            "元のファイルは変えていません"
                        )
                values.update(pt.values)
                stats["pages"] += 1
                stats["regions"] += n
        else:
            raise RemedyError("この方法は PDF に使えません")
        residue = Residue.from_selection(sel, values)
        cleaned = clean_residue(fitz, doc, residue)
        stats["cleaned"] = sum(cleaned.values())
        if notes:
            stats["notes"] = notes
        stats.update({f"cleaned_{k}": v for k, v in cleaned.items() if v})
        kw: dict = {"garbage": 4, "deflate": True}  # 増分保存にしない（消した文字を古い版として残さない）
        if password:
            kw.update(
                encryption=encryption_method(fitz, doc),
                user_pw=password,
                owner_pw=password,
                permissions=doc.permissions,
            )
        try:
            doc.save(dst, **kw)
        except Exception as e:
            raise RemedyError(
                f"PDF を保存できませんでした（{type(e).__name__}）。元のファイルは変えていません"
            ) from None
    finally:
        doc.close()
    return stats

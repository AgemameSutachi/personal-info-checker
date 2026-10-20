"""PDF の処理（PyMuPDF）。

本文・注釈・フォーム欄・しおり・文書情報・添付ファイルを読む。
文字の層が無いページ（スキャンした画像だけのページ）は OCR で読む。
"""

from __future__ import annotations

from ..engine import Blob, Collector, ItemResult, NeedPassword, ScanContext, Uncheckable
from ..models import Status

OCR_DPI = 200


def page_sheet(no: int, ocr: bool) -> str:
    """対処のための位置の「シート」の名前（1 始まりのページ番号。OCR で読んだ分は別）。"""
    return f"{no}ページ（OCR）" if ocr else f"{no}ページ"


def _page_image_coverage(page) -> float:
    """ページの面積のうち画像が占める割合（0〜1）。"""
    try:
        area = abs(page.rect)
        if not area:
            return 0.0
        covered = 0.0
        for info in page.get_image_info():
            x0, y0, x1, y1 = info.get("bbox", (0, 0, 0, 0))
            covered += max(0.0, (x1 - x0)) * max(0.0, (y1 - y0))
        return min(1.0, covered / area)
    except Exception:
        return 0.0


def handle_pdf(ctx: ScanContext, blob: Blob, item: ItemResult, col: Collector, depth: int) -> None:
    import pymupdf as fitz

    try:
        if blob.data is not None:
            doc = fitz.open(stream=blob.data, filetype="pdf")
        else:
            doc = fitz.open(ctx.blob_as_path(blob), filetype="pdf")
    except Exception as e:
        raise Uncheckable(f"PDF を開けなかった（壊れている可能性）: {e}")
    with doc:
        if doc.needs_pass:
            opened = False
            for pw in [""] + ctx.password_candidates():
                if doc.authenticate(pw):
                    opened = True
                    if pw:
                        item.notes.append("パスワードで開いた")
                    break
            if not opened:
                n = len(ctx.password_candidates())
                raise NeedPassword(
                    "pdf",
                    (
                        f"PDF に開くためのパスワードが掛かっている（受け取ったパスワード {n} 個を試したが開けなかった）"
                        if n
                        else "PDF に開くためのパスワードが掛かっている（パスワードを入力すると再検査できる）"
                    ),
                )

        if col.collect_positions:
            col.pos_layout = "pdf"  # 対処のために、ページ・行・文字の範囲で位置を集める（remedy_pdf.py が黒塗りに使う）
        meta = doc.metadata or {}
        for key in ("author", "title", "subject", "keywords", "creator"):
            if meta.get(key):
                col.add_text(meta[key], f"文書情報 {key}", method="文書情報")
        try:
            for level, title, page_no in doc.get_toc():
                col.add_text(title, f"しおり（{page_no}ページ）", method="しおり")
        except Exception:
            pass

        ocr_pages: list[int] = []
        ocr_missing: list[int] = []
        ocr_reason = ""
        for page in doc:
            no = page.number + 1
            text = page.get_text("text") or ""
            if text.strip():
                col.pos_sheet = page_sheet(no, False)
                try:
                    col.add_lines(text, location_prefix=f"{no}ページ ", method="本文")
                finally:
                    col.pos_sheet = ""
            reason_ocr = _needs_ocr(page, text)
            if reason_ocr:
                done, reason = _ocr_page(ctx, page, col, no)
                if done:
                    ocr_pages.append(no)
                else:
                    ocr_missing.append(no)
                    ocr_reason = reason
            for annot in page.annots() or []:
                info = annot.info or {}
                for key in ("content", "title", "subject"):
                    if info.get(key):
                        col.add_text(info[key], f"{no}ページ 注釈", method="注釈")
                if annot.type[1] == "FileAttachment":
                    try:
                        data = annot.get_file()
                        name = annot.file_info.get("filename") or f"注釈の添付{no}"
                        ctx.scan_nested(f"{blob.display}!{name}", data=data, depth=depth + 1, name_hint=name)
                    except Exception as e:
                        item.notes.append(f"{no}ページの注釈の添付を取り出せなかった: {e}")
            for w in page.widgets() or []:
                value = w.field_value
                if value not in (None, "", "Off"):
                    col.add_text(
                        str(value), f"{no}ページ フォーム欄「{w.field_name}」", header=w.field_name, method="フォーム欄"
                    )

        n_emb = 0
        for name in doc.embfile_names():
            try:
                data = doc.embfile_get(name)
            except Exception as e:
                ctx.items.append(
                    ItemResult(
                        path=f"{blob.display}!{name}",
                        kind="PDF の添付",
                        status=Status.UNCHECKABLE,
                        reason=f"添付を取り出せなかった: {e}",
                        depth=depth + 1,
                    )
                )
                continue
            n_emb += 1
            ctx.scan_nested(f"{blob.display}!{name}", data=data, depth=depth + 1, name_hint=name)

        parts = [f"{doc.page_count}ページの本文"]
        if ocr_pages:
            parts.append(f"OCR {len(ocr_pages)}ページ")
        if n_emb:
            parts.append(f"添付 {n_emb}件")
        item.method = "・".join(parts) + "・注釈・フォーム欄・しおり・文書情報"
        if ocr_pages:
            item.notes.append("文字の層が無いページを OCR で読んだ: " + _pages_str(ocr_pages))
        if ocr_missing:
            raise Uncheckable(
                f"画像だけのページ（{_pages_str(ocr_missing)}）を OCR できず検査できていない（要目視）: {ocr_reason}"
            )


def _garbled_ratio(text: str) -> float:
    """取り出した文字のうち化けているもの（私用領域・置換文字・制御文字）の割合。"""
    chars = [c for c in text if not c.isspace()]
    if not chars:
        return 0.0
    bad = sum(1 for c in chars if c == "\ufffd" or "\ue000" <= c <= "\uf8ff" or ord(c) < 0x20)
    return bad / len(chars)


def _needs_ocr(page, text: str) -> str:
    """このページを OCR すべきか。すべきなら理由を返す。

    - 文字の層が無く画像がある（スキャン原稿）
    - 一定の大きさ以上の画像が貼ってある（文字のあるページに身分証の写し等を貼った申込書）
    - 取り出した文字が化けている（ToUnicode の無いフォントの古い PDF）
    - 文字も画像も無いが図形が多い（文字をアウトライン化した PDF）
    """
    stripped = text.strip()
    if _garbled_ratio(stripped) > 0.1:
        return "文字化け"
    area = abs(page.rect) or 1.0
    try:
        infos = page.get_image_info()
    except Exception:
        infos = []
    if not stripped and (infos or page.get_images()):
        return "画像のみ"
    for info in infos:
        x0, y0, x1, y1 = info.get("bbox", (0, 0, 0, 0))
        w, h = abs(x1 - x0), abs(y1 - y0)
        if min(w, h) >= 60 and w * h >= area * 0.03:
            return "画像あり"
    if len(stripped) < 50 and not infos:
        # 表題だけが本物の文字で、残りの文字をアウトライン化した（図形にした）ページも OCR する
        try:
            if len(page.get_drawings()) > 50:
                return "アウトライン化"
        except Exception:
            pass
    return ""


def _ocr_page(ctx: ScanContext, page, col: Collector, no: int) -> tuple[bool, str]:
    if not ctx.options.ocr:
        return False, "OCR を無効にして実行した"
    from .. import ocr

    if not ocr.is_available():
        return False, ocr.unavailable_reason() or "OCR が使えない"
    from PIL import Image

    pix = page.get_pixmap(dpi=OCR_DPI)
    img = (
        Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
        if pix.n < 4
        else Image.frombytes("RGBA", (pix.width, pix.height), pix.samples)
    )
    text = ocr.ocr_pil_image(img)
    col.pos_sheet = page_sheet(no, True)
    try:
        col.add_lines(text, location_prefix=f"{no}ページ（OCR） ", method="OCR", ocr=True)
    finally:
        col.pos_sheet = ""
    return True, ""


def _pages_str(pages: list[int]) -> str:
    if len(pages) > 15:
        return "、".join(map(str, pages[:15])) + f" ほか計{len(pages)}ページ"
    return "、".join(map(str, pages))

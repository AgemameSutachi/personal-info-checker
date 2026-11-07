"""PDF の処理（PyMuPDF）。

本文・注釈・フォーム欄・しおり・文書情報・添付ファイルを読む。
文字の層が無いページ（スキャンした画像だけのページ）は OCR で読む。
"""

from __future__ import annotations

import re

from ..engine import OCR_OFF_HINT, Blob, Collector, ItemResult, NeedPassword, ScanContext, Uncheckable
from ..models import Status

OCR_DPI = 200

# 中身を読めなかったことを示す MuPDF の警告（壊れた圧縮・読めない内容のストリーム・壊れた辞書）。
# 実物の PDF 1,500 件ではどれも出ず、出たのは文字の位置の警告（ActualText…）1件だけだった。
# 警告は MuPDF のプロセス全体で1つの溜まりなので、1つのプロセスで PDF を同時に2つ読むと混ざる
# （検査は1ファイルずつ別のプロセスで読むので混ざらない）
DAMAGE_WARNINGS = ("zlib error", "cannot load content stream", "syntax error", "cannot find object", "aes padding")
# 暗号化の辞書を指す印（trailer の「/Encrypt <<…」「/Encrypt 5 0 R」と、辞書そのものの「/Filter/Standard」）。
# 本文や文書情報に「/Encrypt」という字が書いてあるだけでは当たらないように、後ろに続く形まで見る
ENCRYPT_MARK = re.compile(rb"/Encrypt\s*(?:<<|\d+\s+\d+\s+R)|/Filter\s*/Standard\b")
ENCRYPT_MARK_TAIL = 64  # 読む塊の境目をまたぐ印を拾うため、前の塊の末尾をこれだけ残す
ACTION = "元のファイルを取り直すか、元のアプリで開いて目で確かめる"


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

    fitz.TOOLS.reset_mupdf_warnings()
    try:
        if blob.data is not None:
            doc = fitz.open(stream=blob.data, filetype="pdf")
        else:
            doc = fitz.open(ctx.blob_as_path(blob), filetype="pdf")
    except Exception as e:
        raise Uncheckable(
            "PDF を開けなかった（壊れている可能性）。PDF の閲覧ソフトで開けるなら、"
            f"別名で保存した写しを検査してください。開けなければ元のファイルを取り直してください（詳細: {e}）"
        )
    with doc:
        repaired = doc.is_repaired
        if repaired and not doc.is_encrypted and _has_encrypt_mark(blob):
            # 途中で切れた等で暗号化の情報（末尾の trailer）が失われ、MuPDF が暗号化されていない PDF として組み直した。
            # 中身は暗号のままなので、読んでも文字は出ない（「検査済み・0件」と黙らないようにする）
            raise Uncheckable(
                f"暗号化された PDF が壊れていて（途中で切れている等）、復号できないため中身を検査できていない。{ACTION}"
            )
        if doc.needs_pass:
            opened = False
            for pw in [""] + ctx.password_candidates():
                if doc.authenticate(pw):
                    opened = True
                    if pw:
                        item.notes.append("パスワードで開いた")
                    break
            if not opened:
                raise NeedPassword("pdf", ctx.password_reason("PDF に開くためのパスワードが掛かっている"))

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

        warnings: list[str] = []

        def keep_warnings() -> None:
            # 添付を読む（入れ子の PDF が警告を消す）前に、ここまでの警告を取っておく
            warnings.append(fitz.TOOLS.mupdf_warnings())
            fitz.TOOLS.reset_mupdf_warnings()

        ocr_pages: list[int] = []
        ocr_missing: list[int] = []
        ocr_reason = ""
        n_chars = 0
        for page in doc:
            no = page.number + 1
            text = page.get_text("text") or ""
            n_chars += len(text.strip())
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
                        keep_warnings()
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
                        reason=(
                            "添付を取り出せなかった（壊れている可能性）。PDF の閲覧ソフトで添付を保存できるなら、"
                            "保存したファイルを検査してください。保存できなければ元のファイルを取り直してください"
                            f"（詳細: {type(e).__name__}: {e}）"
                        ),
                        depth=depth + 1,
                    )
                )
                continue
            n_emb += 1
            keep_warnings()
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
                f"画像だけのページ（{_pages_str(ocr_missing)}）を OCR できず検査できていない（要目視）。{ocr_reason}"
            )
        keep_warnings()
        damage = _damage_warning("\n".join(warnings))
        if damage:
            item.notes.append(f"PDF の読み込みの警告（MuPDF）: {damage}")
        repaired = repaired or doc.is_repaired  # パスワードで開いた後に修復が要ると分かることもある
        if repaired and damage and not n_chars and not ocr_pages:
            # 修復しても中身のストリームを1つも読めなかった（半分で切れて暗号化の辞書ごと消えた暗号化 PDF 等）
            raise Uncheckable(
                f"PDF が壊れていて（途中で切れている・暗号化の情報が消えた等）、中身を読めなかった。{ACTION}"
            )
        if repaired:
            item.status = Status.PARTIAL
            item.reason = (
                "PDF が壊れていて（途中で切れている等）、読める部分だけを修復して検査した。"
                f"失われた部分は検査していないので、{ACTION}"
            )
        elif damage:
            item.status = Status.PARTIAL
            item.reason = (
                "PDF の一部（中身の圧縮・ページの内容など）が壊れていて、読めなかった部分があるかもしれない。"
                f"読めた部分だけを検査したので、{ACTION}"
            )


def _has_encrypt_mark(blob: Blob) -> bool:
    """ファイルの中に暗号化の辞書の印（ENCRYPT_MARK）があるか。修復した PDF だけで呼ぶ（全体を少しずつ読む）。"""
    if blob.data is not None:
        return ENCRYPT_MARK.search(blob.data) is not None
    tail = b""
    with blob.open() as f:
        while chunk := f.read(1 << 20):
            if ENCRYPT_MARK.search(tail + chunk):
                return True
            tail = chunk[-ENCRYPT_MARK_TAIL:]
    return False


def _damage_warning(warnings: str) -> str:
    """MuPDF の警告から、中身を読めなかったことを示す行を1つ返す（無ければ空）。"""
    for line in (warnings or "").splitlines():
        if any(k in line for k in DAMAGE_WARNINGS):
            return line.strip()[:120]
    return ""


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
        return False, f"OCR を無効にして実行した。{OCR_OFF_HINT}"
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

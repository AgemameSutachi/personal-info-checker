"""OCR を使わずに要目視にした画像の「文字のありそうな度合い」と、要対応の並び（Excel・画面）の試験。"""

from __future__ import annotations

import io

from openpyxl import load_workbook
from PIL import Image, ImageDraw

from pii_checker import cli
from pii_checker.formats.misc import text_hint, text_hint_label
from pii_checker.models import TEXT_HINT_HIGH, TEXT_HINT_MID
from pii_checker.store import Store


def _png(im: Image.Image, fmt: str = "PNG") -> bytes:
    buf = io.BytesIO()
    im.save(buf, fmt)
    return buf.getvalue()


def _document() -> Image.Image:
    """白地に黒い細い字画を行に並べた、文書を写したような画像（字の形はフォントに頼らず四角で描く）。"""
    im = Image.new("RGB", (1200, 900), "white")
    d = ImageDraw.Draw(im)
    for y in range(30, 870, 34):
        for x in range(30, 1170, 14):
            d.rectangle((x, y, x + 2, y + 16), fill="black")
            d.rectangle((x, y + 7, x + 9, y + 9), fill="black")
    return im


def _photo() -> Image.Image:
    """なだらかな明るさの写真のような画像（くっきりした縁も一色の背景も無い）。"""
    im = Image.linear_gradient("L").resize((1200, 900)).convert("RGB")
    return Image.blend(im, Image.effect_noise((1200, 900), 20).convert("RGB"), 0.3)


def test_text_hint_separates_documents_from_photos():
    """文書のような画像は高、写真のような画像・無地は低（無地の外周を縁と数えない）。JPEG でも同じに分かれる。"""
    for fmt in ("PNG", "JPEG"):
        doc = text_hint(_png(_document(), fmt))
        photo = text_hint(_png(_photo(), fmt))
        blank = text_hint(_png(Image.new("RGB", (800, 600), "white"), fmt))
        assert doc is not None and doc >= TEXT_HINT_HIGH, (fmt, doc)
        assert photo is not None and photo < TEXT_HINT_MID, (fmt, photo)
        assert blank == 0.0, (fmt, blank)


def test_text_hint_gives_none_when_unmeasurable():
    """開けない中身・小さすぎる画像は度合いを付けない（None）。"""
    assert text_hint(b"not an image") is None
    assert text_hint(_png(Image.new("RGB", (2, 2), "white"))) is None


def test_text_hint_label():
    """度合いを 高・中・低 の一言にする。計れなかったときは何も足さない。"""
    assert text_hint_label(None) == ""
    assert text_hint_label(TEXT_HINT_HIGH) == "（文字のありそうな度合い: 高）"
    assert text_hint_label(TEXT_HINT_MID) == "（文字のありそうな度合い: 中）"
    assert text_hint_label(TEXT_HINT_MID / 2) == "（文字のありそうな度合い: 低）"


def _scan(tmp_path):
    """OCR を切った既定の検査で、写真・文書の画像とパスワードの要る書庫を検査する。"""
    root = tmp_path / "root"
    root.mkdir()
    # パスの順では写真（a_）が文書（z_）より前になるように名前を付ける
    (root / "a_photo.png").write_bytes(_png(_photo()))
    (root / "z_document.png").write_bytes(_png(_document()))
    (root / "m_memo.txt").write_text("会議の議題\n", encoding="utf-8")
    db = tmp_path / "jobs.sqlite3"
    out = tmp_path / "out" / "r.xlsx"
    out.parent.mkdir()
    cli.main(["--db", str(db), "scan", str(root), "--no-ask", "-o", str(out)])
    store = Store(str(db))
    return store, store.jobs()[0]["id"], root, out


def test_ocr_off_images_get_hint_and_come_first(tmp_path):
    """OCR を切ると画像は要目視のまま（外さない）で、度合いが理由に付いて保存され、文書の画像が要対応の先頭に来る。"""
    from pii_checker.web.server import create_app

    store, job_id, root, out = _scan(tmp_path)
    rows = {
        r["path"]: r
        for r in store.query("SELECT path, status, reason, text_hint FROM items WHERE job_id=? AND depth=0", (job_id,))
    }
    doc = rows[str(root / "z_document.png")]
    photo = rows[str(root / "a_photo.png")]
    assert doc["status"] == photo["status"] == "uncheckable"  # 度合いが低くても要目視から外さない
    assert doc["text_hint"] >= TEXT_HINT_HIGH and photo["text_hint"] < TEXT_HINT_MID
    assert doc["reason"].endswith("（文字のありそうな度合い: 高）")
    assert photo["reason"].endswith("（文字のありそうな度合い: 低）")
    assert rows[str(root / "m_memo.txt")]["text_hint"] is None  # 画像でないものは計らない

    # Excel の要対応: 度合いが中以上の文書が先頭、低い写真は従来どおりパスの順で後ろ
    ws = load_workbook(out)["要対応"]
    paths = [r[1] for r in ws.iter_rows(min_row=2, values_only=True)]
    assert paths.index(str(root / "z_document.png")) == 0
    assert str(root / "a_photo.png") in paths

    # 画面の要対応: 同じ区分（検査できなかった）の中で文書が先。区分での絞り込みでも同じ
    app = create_app(db=str(tmp_path / "jobs.sqlite3"), token="t")
    attention = next(r.endpoint for r in app.routes if getattr(r, "path", "") == "/api/jobs/{job_id}/attention")
    for status in ("", "uncheckable"):
        res = attention(job_id=job_id, offset=0, limit=100, q="", status=status)
        got = [r["path"] for r in res["rows"] if r["status"] == "uncheckable"]
        assert got[:2] == [str(root / "z_document.png"), str(root / "a_photo.png")], (status, got)
        assert res["total"] == len(res["rows"])


def test_old_db_gets_text_hint_column(tmp_path):
    """列の無い古い版の DB を開くと列を足す（値は NULL＝計っていない）。"""
    db = tmp_path / "old.sqlite3"
    old = Store(str(db))
    old._conn.execute("ALTER TABLE items DROP COLUMN text_hint")
    old._conn.commit()
    assert "text_hint" not in {r[1] for r in old.query("PRAGMA table_info(items)")}  # 古い版の形になった
    store = Store(str(db))
    cols = {r[1] for r in store.query("PRAGMA table_info(items)")}
    assert "text_hint" in cols

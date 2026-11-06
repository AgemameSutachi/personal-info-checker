"""陽性対照の総当たり: 同じ架空の個人情報を、Python だけで作れる形式すべてに入れ、どの形式でも拾うことを確かめる。

形式ごとに別々の試験はあるが、入れる値も確かめる種類もばらばらで、ある形式だけ特定の種類を取りこぼしても
気づけない。ここでは同じ本文（make_corpus.pii_text・table_rows）を全部の形式に入れ、拾った種類を突き合わせる。
外の道具（Office・7-Zip・Java）が要る形式は make_corpus.py と corpus_check.py の検体で確かめる。
"""

from __future__ import annotations

import bz2
import csv
import gzip
import io
import json
import lzma
import sqlite3
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import make_corpus as mc  # noqa: E402

from pii_checker.engine import scan_file  # noqa: E402
from pii_checker.models import ScanOptions, Status  # noqa: E402

TEXT = mc.pii_text()
ROWS = mc.table_rows()
# 本文の形（文章）で必ず拾うべき種類。PEOPLE[0] の値を全部含む
TEXT_TYPES = {
    "name",
    "address",
    "postal_code",
    "phone",
    "email",
    "birthdate",
    "my_number",
    "bank_account",
    "credit_card",
}
# 表の形（見出し＋行）で必ず拾うべき種類
TABLE_TYPES = set(TEXT_TYPES)


def _csv(rows, delimiter=",") -> str:
    buf = io.StringIO()
    csv.writer(buf, delimiter=delimiter, lineterminator="\n").writerows(rows)
    return buf.getvalue()


def _zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return buf.getvalue()


def _tar(entries: dict[str, bytes], mode: str = "w") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as t:
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _docx() -> bytes:
    import docx

    d = docx.Document()
    for line in TEXT.splitlines():
        d.add_paragraph(line)
    buf = io.BytesIO()
    d.save(buf)
    return buf.getvalue()


def _xlsx() -> bytes:
    import openpyxl

    wb = openpyxl.Workbook()
    for row in ROWS:
        wb.active.append(row)
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def _pptx() -> bytes:
    import pptx
    from pptx.util import Inches

    prs = pptx.Presentation()
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    box = slide.shapes.add_textbox(Inches(0.5), Inches(0.5), Inches(9), Inches(6))
    box.text_frame.text = TEXT
    buf = io.BytesIO()
    prs.save(buf)
    return buf.getvalue()


def _pdf() -> bytes:
    import pymupdf

    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((50, 72), TEXT, fontname="japan", fontsize=10)
    return doc.tobytes()


def _odf(mimetype: str, body: str) -> bytes:
    content = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
        'xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" '
        'xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" '
        'xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" '
        'xmlns:presentation="urn:oasis:names:tc:opendocument:xmlns:presentation:1.0" office:version="1.2">'
        f"<office:body>{body}</office:body></office:document-content>"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(zipfile.ZipInfo("mimetype"), mimetype)  # 先頭・無圧縮
        z.writestr("content.xml", content, zipfile.ZIP_DEFLATED)
        z.writestr(
            "META-INF/manifest.xml",
            '<?xml version="1.0" encoding="UTF-8"?><manifest:manifest '
            'xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0">'
            f'<manifest:file-entry manifest:full-path="/" manifest:media-type="{mimetype}"/>'
            '<manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>'
            "</manifest:manifest>",
        )
    return buf.getvalue()


def _paragraphs() -> str:
    from xml.sax.saxutils import escape

    return "".join(f"<text:p>{escape(line)}</text:p>" for line in TEXT.splitlines())


def _odt() -> bytes:
    return _odf("application/vnd.oasis.opendocument.text", f"<office:text>{_paragraphs()}</office:text>")


def _ods() -> bytes:
    from xml.sax.saxutils import escape

    rows = "".join(
        "<table:table-row>"
        + "".join(
            f'<table:table-cell office:value-type="string"><text:p>{escape(v)}</text:p></table:table-cell>' for v in row
        )
        + "</table:table-row>"
        for row in ROWS
    )
    return _odf(
        "application/vnd.oasis.opendocument.spreadsheet",
        f'<office:spreadsheet><table:table table:name="顧客">{rows}</table:table></office:spreadsheet>',
    )


def _odp() -> bytes:
    return _odf(
        "application/vnd.oasis.opendocument.presentation",
        "<office:presentation><draw:page><draw:frame><draw:text-box>"
        f"{_paragraphs()}</draw:text-box></draw:frame></draw:page></office:presentation>",
    )


def _sqlite(tmp_path: Path) -> bytes:
    path = tmp_path / "build.sqlite3"
    con = sqlite3.connect(path)
    cols = ", ".join(f'"{h}" TEXT' for h in ROWS[0])
    con.execute(f"CREATE TABLE 顧客 ({cols})")
    con.executemany(f"INSERT INTO 顧客 VALUES ({', '.join('?' * len(ROWS[0]))})", ROWS[1:])
    con.commit()
    con.close()
    data = path.read_bytes()
    path.unlink()
    return data


def _parquet() -> bytes:
    import pyarrow as pa
    import pyarrow.parquet as pq

    table = pa.table({h: [row[i] for row in ROWS[1:]] for i, h in enumerate(ROWS[0])})
    buf = io.BytesIO()
    pq.write_table(table, buf)
    return buf.getvalue()


def _html() -> bytes:
    from xml.sax.saxutils import escape

    body = "".join(f"<p>{escape(line)}</p>" for line in TEXT.splitlines())
    return f'<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8"><title>顧客</title></head><body>{body}</body></html>'.encode()


def _xml() -> bytes:
    from xml.sax.saxutils import escape

    people = "".join(
        "<顧客>" + "".join(f"<{h}>{escape(v)}</{h}>" for h, v in zip(ROWS[0], row)) + "</顧客>" for row in ROWS[1:]
    )
    return f'<?xml version="1.0" encoding="UTF-8"?><顧客一覧>{people}</顧客一覧>'.encode()


def _json() -> bytes:
    return json.dumps([dict(zip(ROWS[0], row)) for row in ROWS[1:]], ensure_ascii=False, indent=1).encode()


def _rtf() -> bytes:
    def esc(ch: str) -> str:
        n = ord(ch)
        if n < 128:
            return {"\\": "\\\\", "{": "\\{", "}": "\\}", "\n": "\\par\n"}.get(ch, ch)
        return f"\\u{n if n < 32768 else n - 65536}?"

    return ("{\\rtf1\\ansi\\ansicpg932\\deff0 " + "".join(esc(c) for c in TEXT) + "}").encode("ascii")


def _eml() -> bytes:
    from email.mime.text import MIMEText

    msg = MIMEText(TEXT, "plain", "utf-8")
    msg["Subject"] = "顧客情報"
    msg["From"] = "sender@example.jp"
    msg["To"] = "receiver@example.jp"
    return msg.as_bytes()


def _sql_dump() -> bytes:
    cols = ", ".join(f"`{h}`" for h in ROWS[0])
    lines = [f"CREATE TABLE `顧客` ({', '.join(f'`{h}` varchar(100)' for h in ROWS[0])});"]
    for row in ROWS[1:]:
        values = ", ".join("'" + v.replace("'", "''") + "'" for v in row)
        lines.append(f"INSERT INTO `顧客` ({cols}) VALUES ({values});")
    return ("\n".join(lines) + "\n").encode()


def _dbf() -> bytes:
    """dBASE III（Shift_JIS・文字の列だけ）。"""
    import struct

    # 列名は10バイトまで（Shift_JIS の全角で5文字）。日本の業務の DBF はこのように縮めた日本語の列名を持つ
    names = [
        "氏名",
        "フリガナ",
        "郵便番号",
        "住所",
        "電話番号",
        "携帯電話",
        "メール",
        "生年月日",
        "マイナンバ",
        "口座番号",
        "カード番号",
    ]
    records = [[v.encode("cp932") for v in row] for row in ROWS[1:]]
    widths = [max(len(r[i]) for r in records) for i in range(len(names))]
    header_len = 32 + 32 * len(names) + 1
    record_len = 1 + sum(widths)
    out = bytearray(struct.pack("<BBBBIHH20x", 0x03, 126, 11, 6, len(records), header_len, record_len))
    out[29] = 0x13  # 言語の印（Shift_JIS）
    for name, width in zip(names, widths):
        out += struct.pack("<11sc4xB15x", name.encode("cp932"), b"C", width)
    out += b"\r"
    for rec in records:
        out += b" " + b"".join(v.ljust(w, b" ") for v, w in zip(rec, widths))
    out += b"\x1a"
    return bytes(out)


TEXT_U8 = TEXT.encode("utf-8")
CSV_U8 = _csv(ROWS).encode("utf-8")


def _builders(tmp_path: Path) -> dict[str, tuple[bytes, set[str]]]:
    """ファイル名 → (中身, 必ず拾うべき種類)。"""
    # どれも requirements.txt の依存。黙って飛ばすと全部の形式の試験が消えるので、無ければ落とす
    import lz4.frame as lz4f
    import zstandard as zstd

    samples = {
        "本文_utf8.txt": (TEXT_U8, TEXT_TYPES),
        "本文_utf8bom.txt": (b"\xef\xbb\xbf" + TEXT_U8, TEXT_TYPES),
        "本文_sjis.txt": (TEXT.encode("cp932"), TEXT_TYPES),
        "本文_eucjp.txt": (TEXT.encode("euc_jp"), TEXT_TYPES),
        "本文_utf16.txt": (TEXT.encode("utf-16"), TEXT_TYPES),
        "本文_jis.txt": (TEXT.encode("iso2022_jp"), TEXT_TYPES),
        "本文.md": (("# 顧客\n\n" + TEXT).encode(), TEXT_TYPES),
        "本文.log": (
            ("\n".join(f"2026-11-06 10:00:0{i} INFO {line}" for i, line in enumerate(TEXT.splitlines()))).encode(),
            TEXT_TYPES,
        ),
        "表_utf8.csv": (CSV_U8, TABLE_TYPES),
        "表_sjis.csv": (_csv(ROWS).encode("cp932"), TABLE_TYPES),
        "表.tsv": (_csv(ROWS, "\t").encode(), TABLE_TYPES),
        "表.json": (_json(), TABLE_TYPES),
        "表.xml": (_xml(), TABLE_TYPES),
        "本文.html": (_html(), TEXT_TYPES),
        "本文.rtf": (_rtf(), TEXT_TYPES),
        "メール.eml": (_eml(), TEXT_TYPES),
        "表.sql": (_sql_dump(), TABLE_TYPES),
        "本文.docx": (_docx(), TEXT_TYPES),
        "表.xlsx": (_xlsx(), TABLE_TYPES),
        "本文.pptx": (_pptx(), TEXT_TYPES),
        "本文.odt": (_odt(), TEXT_TYPES),
        "表.ods": (_ods(), TABLE_TYPES),
        "本文.odp": (_odp(), TEXT_TYPES),
        "本文.pdf": (_pdf(), TEXT_TYPES),
        "表.sqlite3": (_sqlite(tmp_path), TABLE_TYPES),
        "表.parquet": (_parquet(), TABLE_TYPES),
        "表.dbf": (_dbf(), TABLE_TYPES),
        "本文.txt.gz": (gzip.compress(TEXT_U8), TEXT_TYPES),
        "本文.txt.bz2": (bz2.compress(TEXT_U8), TEXT_TYPES),
        "本文.txt.xz": (lzma.compress(TEXT_U8), TEXT_TYPES),
        "本文.txt.zst": (zstd.ZstdCompressor().compress(TEXT_U8), TEXT_TYPES),
        "本文.txt.lz4": (lz4f.compress(TEXT_U8), TEXT_TYPES),
        "書庫.zip": (_zip({"中/本文.txt": TEXT_U8}), TEXT_TYPES),
        "書庫_表.zip": (_zip({"表.csv": CSV_U8}), TABLE_TYPES),
        "書庫.tar": (_tar({"本文.txt": TEXT_U8}), TEXT_TYPES),
        "書庫.tar.gz": (_tar({"本文.txt": TEXT_U8}, "w:gz"), TEXT_TYPES),
        "入れ子.zip": (_zip({"内.zip": _zip({"本文.docx": _docx()})}), TEXT_TYPES),
    }
    import py7zr

    buf = io.BytesIO()
    with py7zr.SevenZipFile(buf, "w") as z:
        z.writestr(TEXT_U8, "本文.txt")
    samples["書庫.7z"] = (buf.getvalue(), TEXT_TYPES)
    return samples


@pytest.fixture(scope="module")
def matrix(tmp_path_factory):
    """全部の検体を作って1回ずつ検査し、ファイル名 → (拾った種類, 期待, 状態) を返す。"""
    tmp = tmp_path_factory.mktemp("matrix")
    out = {}
    for name, (data, expect) in _builders(tmp).items():
        p = tmp / name
        p.write_bytes(data)
        # 画像の検体は無い。python-docx・python-pptx の雛形が付けるサムネイル（docProps/thumbnail.jpeg）は、
        # 日本語の OCR がある所では「検査済み」、無い所（CI の Windows）では「検査不能」になり、環境で結果が変わる。
        # OCR を切って結果を揃え、サムネイルは判定から外す（画像の中の文字は test_ocr.py が受け持つ）
        res = scan_file(str(p), ScanOptions(temp_dir=str(tmp), ocr=False))
        found = {k for it in res.items for k, n in it.finding_counts.items() if n}
        bad = [
            (it.path.rsplit("\\", 1)[-1], it.status, it.reason)
            for it in res.items
            if it.status != Status.SCANNED and not it.path.endswith("!docProps/thumbnail.jpeg")
        ]
        out[name] = (found, expect, bad)
    return out


def test_every_format_finds_every_type(matrix):
    """どの形式でも、入れた種類を全部拾う。拾えなかった種類を形式ごとに一覧で出す（1つの形式で止まらない）。"""
    missing = {name: sorted(expect - found) for name, (found, expect, _) in matrix.items() if expect - found}
    assert missing == {}, "\n" + "\n".join(f"{n}: {m}" for n, m in sorted(missing.items()))


def test_every_format_is_fully_scanned(matrix):
    """どの検体も「検査済み」になる（一部だけ・検査できなかった項目が混ざらない）。"""
    bad = {name: b for name, (_, _, b) in matrix.items() if b}
    assert bad == {}, "\n" + "\n".join(f"{n}: {b}" for n, b in sorted(bad.items()))


def test_document_xml_keeps_split_runs_together(tmp_path):
    """Word 2003 の XML のように1つの文が小さな要素に分かれる文書は、要素ごとに区切らない（氏名が途中で切れない）。"""
    from pii_checker.formats import misc

    word = (
        '<?xml version="1.0"?><w:wordDocument xmlns:w="http://schemas.microsoft.com/office/word/2003/wordml">'
        "<w:body><w:p><w:r><w:t>氏名：山田</w:t></w:r><w:r><w:t> 太郎 電話 090-</w:t></w:r>"
        "<w:r><w:t>1234-5678</w:t></w:r></w:p></w:body></w:wordDocument>"
    )
    assert misc.is_document_xml(word)
    p = tmp_path / "doc.xml"
    p.write_text(word, encoding="utf-8")
    item = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path))).items[0]
    assert {"name", "phone"} <= set(item.finding_counts), item.finding_counts
    assert "タグを除いた" in item.method
    assert "項目名" not in item.method, item.method  # 文書の XML には要素名を項目名にした読み方を足さない


def test_data_xml_uses_element_names_as_headers():
    """データの XML は、葉の要素を「項目名：値」の1行にする。名前空間の接頭辞は外し、文字の参照は戻す。"""
    from pii_checker.formats import misc

    src = '<?xml version="1.0"?><r xmlns:c="urn:x"><c:電話番号 type="m">090-1234-5678</c:電話番号><備考>A&amp;B</備考><空/></r>'
    assert not misc.is_document_xml(src)
    lines = [s for s in misc.data_xml_to_text(src).splitlines() if s.strip()]
    assert lines == ["電話番号：090-1234-5678", "備考：A&B"]


@pytest.mark.parametrize(
    "src, kinds",
    [
        # 値の途中に要素が入る文（DocBook・SVG の tspan・データの中の強調）: 今までの読み方で拾う（評価の指摘）
        ("<article><para>電話は090-<phrase>1234</phrase>-5678です</para></article>", {"phone"}),
        ("<svg><text><tspan>電話 090-</tspan><tspan>1234-5678</tspan></text></svg>", {"phone"}),
        ("<r><電話番号>090-<b>1234</b>-5678</電話番号></r>", {"phone"}),
        ("<TEI><p>氏名 <persName>山田太郎</persName> 電話 090-1234-5678</p></TEI>", {"name", "phone"}),
        # CDATA の中・名前空間の接頭辞つきの要素名（文書の部品ではない）
        (
            "<r><電話番号><![CDATA[090-1234-5678]]></電話番号><生年月日><![CDATA[1985年4月1日]]></生年月日></r>",
            {"phone", "birthdate"},
        ),
        (
            '<a:r xmlns:a="urn:x"><a:電話番号>090-1234-5678</a:電話番号><a:生年月日>1985年4月1日</a:生年月日></a:r>',
            {"phone", "birthdate"},
        ),
    ],
)
def test_xml_shapes(tmp_path, src, kinds):
    p = tmp_path / "x.xml"
    p.write_text('<?xml version="1.0" encoding="UTF-8"?>' + src, encoding="utf-8")
    item = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path))).items[0]
    assert set(dict(item.finding_counts)) == kinds, (src, item.finding_counts)


@pytest.mark.parametrize(
    "src, counts",
    [
        # 今までの読み方と項目名の読み方の両方で同じ値が出ても1件（skip_seen）
        ("<r><電話番号>090-1234-5678</電話番号></r>", {"phone": 1}),
        ("<r><電話番号><![CDATA[090-1234-5678]]></電話番号><携帯>090-1234-5678</携帯></r>", {"phone": 1}),
        # 要素名が手がかりの語にならない数字だけの 12 桁は拾わない（誤検出を増やさない）。
        # 検査数字の合う 12 桁（345678901234 など）は単独の値と同じく今までも拾う＝本文の語の無い 12 桁の扱いは別の課題
        ("<r><ID>123456789012</ID><ID>234567890123</ID></r>", {}),
    ],
)
def test_data_xml_counts(tmp_path, src, counts):
    p = tmp_path / "x.xml"
    p.write_text('<?xml version="1.0" encoding="UTF-8"?>' + src, encoding="utf-8")
    item = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path))).items[0]
    assert dict(item.finding_counts) == counts, (src, item.finding_counts)


def test_unclosed_cdata_is_linear():
    """閉じていない CDATA の開始が多くても二乗の時間にならない（壊れた XML・XML と名の付いたバイナリ）。"""
    import time

    from pii_checker.formats import misc

    t = time.perf_counter()
    # 3 万個なら線形で 0.3 秒ほど。正規表現の (.*?) では 8000 個で 3 秒以上かかった（二乗なら 3 万個で数十秒）
    misc.data_xml_to_text("<![CDATA[" * 30000)
    assert time.perf_counter() - t < 2.0
    src = "<r><a><![CDATA[x<y]]></a><b><![CDATA[open"
    assert [s for s in misc.data_xml_to_text(src).splitlines() if s.strip()] == ["a：x<y", "<![CDATA[open"]


def test_document_xml_marks():
    from pii_checker.formats import misc

    assert misc.is_document_xml(
        '<w:document xmlns:w="x"><w:body><w:p><w:r><w:t>a</w:t></w:r></w:p></w:body></w:document>'
    )
    assert not misc.is_document_xml('<a:Customer xmlns:a="urn:x"><a:Phone>090-1234-5678</a:Phone></a:Customer>')
    # a: の部品の名前（a:r・a:p・a:t）でも、DrawingML の名前空間でなければデータの XML
    assert not misc.is_document_xml('<a:r xmlns:a="urn:x"><a:t>090-1234-5678</a:t></a:r>')
    drawing = 'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"'
    assert misc.is_document_xml(f"<a:graphic {drawing}><a:p><a:r><a:t>a</a:t></a:r></a:p></a:graphic>")

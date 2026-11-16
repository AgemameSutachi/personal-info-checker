"""Office の文書のプロパティ（docProps）・ユーザー定義の XML（customXml）の値を、隣の値とつなげずに読む試験。

プロパティの XML は値を区切りなく並べるので、タグを外すだけでは「携帯 090-1234-5678」の後ろに版の番号「1」と
日時が続き、番号の形でなくなっていた（2026-11-16 に、隠れた場所 24 通りに1つずつ置いた検体で見つけた）。
値はすべて架空。
"""

from __future__ import annotations

import io
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pii_checker.engine import scan_file  # noqa: E402
from pii_checker.models import ScanOptions  # noqa: E402

SECRET = "携帯 090-1234-5678"


def _docx(fill=None) -> bytes:
    import docx

    d = docx.Document()
    d.add_paragraph("会議の議事録です。")
    if fill:
        fill(d)
    buf = io.BytesIO()
    d.save(buf)
    return buf.getvalue()


def _add_part(data: bytes, name: str, body: bytes) -> bytes:
    src = zipfile.ZipFile(io.BytesIO(data))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for info in src.infolist():
            z.writestr(info.filename, src.read(info.filename))
        z.writestr(name, body)
    return buf.getvalue()


def _found(tmp_path, name: str, data: bytes) -> dict[str, int]:
    p = tmp_path / name
    p.write_bytes(data)
    res = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path), ocr=False))
    out: dict[str, int] = {}
    for it in res.items:
        for k, n in it.finding_counts.items():
            if n:
                out[k] = out.get(k, 0) + n
    return out


def test_docx_core_property_comment(tmp_path):
    data = _docx(lambda d: setattr(d.core_properties, "comments", SECRET))
    assert _found(tmp_path, "a.docx", data) == {"phone": 1}


def test_docx_custom_xml_values_next_to_each_other(tmp_path):
    item = '<?xml version="1.0" encoding="UTF-8"?><r><a>1</a><b>' + SECRET + "</b><c>2</c></r>"
    data = _add_part(_docx(), "customXml/item99.xml", item.encode())
    assert _found(tmp_path, "b.docx", data) == {"phone": 1}


def test_property_value_found_in_body_is_counted_once(tmp_path):
    # 本文とプロパティに同じ値があっても、読み直しの分は数え直さない
    def fill(d):
        d.add_paragraph(SECRET)
        d.core_properties.comments = SECRET

    assert _found(tmp_path, "c.docx", _docx(fill)) == {"phone": 1}

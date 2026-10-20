"""巨大なシートの xlsx: 表として読み終えたシートの拾い直しが大きすぎても、「途中まで」にしない試験。"""

from __future__ import annotations

import zipfile

from openpyxl import Workbook

from pii_checker import engine
from pii_checker.formats import office
from pii_checker.models import ScanOptions, Status


def test_huge_sheet_part_is_not_partial(tmp_path, monkeypatch):
    """シートの XML が丸ごと読む上限を超えても、セルは表として読めているので検査済みのまま（注記だけ残す）。"""
    p = tmp_path / "meibo.xlsx"
    wb = Workbook()
    ws = wb.active
    ws.append(["氏名", "電話番号"])
    for i in range(500):
        ws.append([f"山田 太郎{i}", f"090-1234-{i:04d}"])
    wb.save(p)
    with zipfile.ZipFile(p) as z:
        sizes = {i.filename: i.file_size for i in z.infolist()}
    sheet = sizes.pop("xl/worksheets/sheet1.xml")
    sizes.pop("xl/sharedStrings.xml", None)
    limit = max(sizes.values()) + 1
    assert sheet > limit
    monkeypatch.setattr(office, "READ_ALL_LIMIT", limit)  # シートの部品だけが上限を超える
    res = engine.scan_file(str(p), ScanOptions(temp_dir=str(tmp_path)))
    item = res.items[0]
    assert item.status == Status.SCANNED
    assert item.finding_counts.get("phone", 0) >= 500
    assert any("残留の確かめは文字として読める部分だけ" in n for n in item.notes)

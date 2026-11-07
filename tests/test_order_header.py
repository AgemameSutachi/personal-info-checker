"""個人情報の見出し語が無い「伝票番号,品番,数量」の見出し行を、列の手がかりに使う（engine._order_header_row）の試験。

16桁の数はすべて試験のために作った値で、実在のカード番号ではない。
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pii_checker.detectors import luhn_is_valid  # noqa: E402
from pii_checker.engine import Collector, _order_header_row  # noqa: E402
from pii_checker.models import ItemResult, Status  # noqa: E402


def _card_like(n: int, seed: int) -> list[str]:
    """Luhn 検査が合い、カードの番号体系の先頭（4）を持つ16桁を n 個（品番が偶然合った形の代わり）。"""
    rnd = random.Random(seed)
    out: list[str] = []
    while len(out) < n:
        body = "4" + f"{rnd.randrange(10**13, 10**14):014d}"
        for d in "0123456789":
            if luhn_is_valid(body + d):
                out.append(body + d)
                break
    return out


def _counts(rows) -> dict[str, int]:
    item = ItemResult(path="t", kind="", status=Status.PENDING)
    col = Collector(item, 20)
    col.add_table(rows, lambda r, c: f"R{r}C{c + 1}")
    return item.conf_counts


def _data(n: int = 5) -> list[list[str]]:
    return [[f"10{i:04d}", v, "3", "1200"] for i, v in enumerate(_card_like(n, 7))]


def test_product_code_column_under_order_header_is_low():
    """品番の列の値は、カード番号の形に合っても 低（見出しの「品番」を手がかりに使う）。"""
    counts = _counts([["伝票番号", "品番", "数量", "単価"]] + _data())
    assert counts.get("credit_card:low", 0) == 5
    assert counts.get("credit_card:medium", 0) == 0


def test_same_values_without_header_stay_medium():
    """陽性対照: 見出し行が無ければ、同じ値は手がかりなしの 中 のまま。"""
    counts = _counts(_data())
    assert counts.get("credit_card:medium", 0) == 5


def test_single_title_cell_is_not_used_as_header():
    """1つだけのセルの行（表題の「注文一覧」）は列の意味に使わない（A列の値を取り違えないため）。"""
    rows = [["注文一覧"]] + [[v] for v in _card_like(3, 8)]
    assert _counts(rows).get("credit_card:medium", 0) == 3


def test_header_with_digits_is_not_used():
    """数字を含むセルがある行は見出しとみなさない（データ行の取り違えを避ける）。"""
    assert not _order_header_row(["2024年度", "品番"])
    assert not _order_header_row(["品番", "a@example.com"])
    assert _order_header_row(["伝票番号", "品番", "数量"])
    assert _order_header_row(["Item Code", "Name"])
    assert not _order_header_row(["数量", "単価"])  # 番号の見出しが無い


def test_person_or_name_cells_are_not_order_headers():
    """「注文者」「受注先」は人や会社の列。英語の名前（Jane・Border）も番号の見出しにしない（部分一致にしない）。"""
    for row in (["注文者", "数量"], ["受注先", "数量"], ["注文", "数量"], ["Order", "Qty"]):
        assert not _order_header_row(row), row
    for row in (["Jane", "Doe"], ["Border", "Color"], ["Janet", "Lee"]):
        assert not _order_header_row(row), row
    assert _order_header_row(["Order No", "Qty"])
    assert _order_header_row(["SKU", "商品名"])


def test_mobile_under_orderer_header_is_still_found():
    """注文者の列の区切りの無い携帯の11桁は、今までどおり拾う（番号の見出しにしないので 低 で残る）。"""
    counts = _counts([["注文者", "数量"], ["09012345678", "1"]])
    assert counts.get("phone:low", 0) == 1


def test_grouped_card_under_name_like_header_stays_high():
    """見出しにならない行（英語の名前）の下の、4桁ずつ区切ったカード番号は 高 のまま。"""
    counts = _counts([["Janet", "Lee"], ["4111 1111 1111 1111", "x"]])
    assert counts.get("credit_card:high", 0) == 1


def test_order_header_is_not_carried_over_blank_line():
    """空行の後の別の表へ、番号の見出しを持ち越さない。"""
    rows = [["伝票番号", "数量"], ["A-1", "1"], [], ["お客様", "備考"], ["09012345678", "x"]]
    assert _counts(rows).get("phone:low", 0) == 1
    # 同じ表の中（空行なし）では、伝票番号の列の11桁は番号とみなして拾わない
    rows = [["伝票番号", "数量"], ["09012345678", "1"]]
    assert _counts(rows).get("phone:low", 0) == 0


def test_pii_header_after_order_header_still_switches():
    """番号の見出しの後に個人情報の見出し語のある行が来れば、その行を見出しに切り替える（今までどおり）。"""
    rows = [["伝票番号", "品番"], ["100001", "A-1"], ["氏名", "電話番号"], ["山田 太郎", "0312345678"]]
    counts = _counts(rows)
    assert any(k.startswith("name:") and v for k, v in counts.items()), counts
    assert any(k.startswith("phone:") and v for k, v in counts.items()), counts


def _reread_counts(read_table: bool) -> dict[str, int]:
    """表として読んだ後に、見出しの分からない読み直し（xlsx のシートの XML と同じ skip_seen）で同じ値を読む。"""
    item = ItemResult(path="t", kind="", status=Status.PENDING)
    col = Collector(item, 20)
    data = _data()
    if read_table:
        col.add_table([["伝票番号", "品番", "数量", "単価"]] + data, lambda r, c: f"R{r}C{c + 1}")
    col.add_lines("\n".join(row[1] for row in data), location_prefix="sheet1.xml ", skip_seen=True)
    return item.conf_counts


def test_reread_does_not_raise_product_code():
    """表で型番とみなした値は、見出しの分からない読み直しで 中 に引き上げない。"""
    counts = _reread_counts(read_table=True)
    assert counts.get("credit_card:low", 0) == 5
    assert counts.get("credit_card:medium", 0) == 0


def test_reread_alone_still_finds_medium():
    """陽性対照: 表で読んでいなければ、読み直しの側だけでも 中 で拾う。"""
    assert _reread_counts(read_table=False).get("credit_card:medium", 0) == 5


def test_xlsx_product_code_column_is_low(tmp_path):
    """xlsx の「伝票番号,品番,数量」のシートの品番は、シートの XML の読み直しを含めても 低。"""
    import openpyxl

    from pii_checker.engine import scan_file
    from pii_checker.models import ScanOptions

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "集計"
    ws.append(["伝票番号", "品番", "数量"])
    for i, v in enumerate(_card_like(5, 9)):
        ws.append([f"10{i:04d}", v, 3])
    path = tmp_path / "order.xlsx"
    wb.save(path)
    counts: dict[str, int] = {}
    for it in scan_file(str(path), ScanOptions()).items:
        for k, v in it.conf_counts.items():
            counts[k] = counts.get(k, 0) + v
    assert counts.get("credit_card:low", 0) == 5
    assert counts.get("credit_card:medium", 0) == 0

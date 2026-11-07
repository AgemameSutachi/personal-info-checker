"""氏名の列が会社名の列（銘柄の一覧など）なら、見出し頼みの氏名を 低 に下げる（engine._ColumnOrgs）の試験。

社名・人の名前はすべて試験のために作ったもので、実在の会社・人ではない。
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pii_checker import engine  # noqa: E402
from pii_checker.engine import Collector  # noqa: E402
from pii_checker.models import ItemResult, Status  # noqa: E402

# 法人格の無い社名（1つずつでは人の名前と見分けられない）
PLAIN_COMPANIES = [
    "あおば電機",
    "みどり食品",
    "テスト建設",
    "ひかり物産",
    "サンプル工業",
    "見本製作所",
    "例示化学",
    "仮名精機",
    "架空運輸",
    "試験薬品",
]
# 会社の印のある社名
MARKED_COMPANIES = ["サンプル商事株式会社", "見本ホールディングス", "例示銀行", "テスト証券"]
PERSONS = [
    f"{s}{g}" for s in ("山田", "佐藤", "鈴木", "高橋", "田中") for g in ("太郎", "花子", "一郎", "次郎", "幸子")
]


def _names(rows, records: bool = False) -> dict[str, int]:
    item = ItemResult(path="t", kind="", status=Status.PENDING)
    col = Collector(item, 20)
    if records:
        col.add_records(rows[0], rows[1:], lambda r, c: f"R{r}C{c + 1}")
    else:
        col.add_table(rows, lambda r, c: f"R{r}C{c + 1}")
    return {k: n for k, n in item.conf_counts.items() if k.startswith("name:")}


def _rows(header: str, values: list[str]) -> list[list[str]]:
    return [["code", header]] + [[f"{1000 + i}", v] for i, v in enumerate(values)]


def test_company_column_lowers_plain_company_names():
    """会社の印が3つそろった後の、法人格の無い社名は 低（それまでの分は 中 のまま）。"""
    values = PLAIN_COMPANIES[:2] + MARKED_COMPANIES[:3] + PLAIN_COMPANIES[2:]
    got = _names(_rows("name", values))
    assert got.get("name:medium", 0) == 2, got
    assert got.get("name:low", 0) == len(PLAIN_COMPANIES) - 2, got


def test_company_column_by_records():
    """列名の分かっている表（データベース・parquet の経路）でも同じ。"""
    values = MARKED_COMPANIES[:3] + PLAIN_COMPANIES
    got = _names(_rows("name", values), records=True)
    assert got.get("name:medium", 0) == 0, got
    assert got.get("name:low", 0) == len(PLAIN_COMPANIES), got


def test_person_column_stays_medium():
    """人の名前だけの列は今までどおり 中。"""
    got = _names(_rows("氏名", PERSONS))
    assert got == {"name:medium": len(PERSONS)}, got


def test_few_companies_among_many_persons_do_not_lower():
    """人の名前の列に会社が少し混じるだけ（異なる値の5%未満）なら下げない。"""
    persons = PERSONS * 1  # 25人
    persons += [p + "子" for p in PERSONS] + [p + "朗" for p in PERSONS]  # 75人
    values = persons + MARKED_COMPANIES[:3]
    got = _names(_rows("氏名", values))
    assert got.get("name:low", 0) == 0, got


def test_honorific_value_in_company_column_stays_medium():
    """会社名の列でも、敬称つきの宛名は人として 中 のまま。"""
    values = MARKED_COMPANIES[:3] + ["山田太郎様"] + PLAIN_COMPANIES[:3]
    got = _names(_rows("宛名", values))
    assert got.get("name:medium", 0) == 1, got
    assert got.get("name:low", 0) == 3, got


def test_honorific_company_values_are_not_counted_as_companies():
    """「株式会社サンプル 山田様」のような敬称つきは会社の印として数えない（人宛ての宛名の列を下げない）。"""
    values = [f"株式会社サンプル{i} {p}様" for i, p in enumerate(("山田", "佐藤", "鈴木"))] + PERSONS
    got = _names(_rows("宛名", values))
    assert got.get("name:low", 0) == 0, got


def test_new_header_resets_the_judgement():
    """見出しが変わったら（同じシートの2つ目の表）数え直す。"""
    rows = _rows("name", MARKED_COMPANIES[:3] + PLAIN_COMPANIES[:2])
    rows += [[], ["code", "氏名", "電話"]] + [[f"{2000 + i}", p, ""] for i, p in enumerate(PERSONS[:5])]
    got = _names(rows)
    assert got.get("name:low", 0) == 2, got
    assert got.get("name:medium", 0) == 5, got


def test_judgement_is_fixed_after_track_limit():
    """異なる値が上限に届いたら判定を固め、値の覚えを捨てる（メモリを食わない）。"""
    orgs = engine._ColumnOrgs()
    for i in range(10):  # 上限の 200 個の5%
        orgs.cell(1, "name", f"見本{i}株式会社")
    for i in range(engine.COLUMN_ID_TRACK):
        orgs.cell(1, "name", f"見本{i}")
    assert 1 in orgs._decided and 1 not in orgs._values
    assert orgs.cell(1, "name", "新しい社名") is True
    assert orgs.cell(0, "code", "株式会社サンプル") is False  # 氏名の列でなければ数えない

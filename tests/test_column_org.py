"""氏名の列が会社名の列（銘柄の一覧など）なら、見出し頼みの氏名を 低 に下げる（engine._ColumnOrgs）の試験。

社名・人の名前はすべて試験のために作ったもので、実在の会社・人ではない。
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pii_checker import engine  # noqa: E402
from pii_checker.engine import COLUMN_ORG_MIN_DISTINCT, Collector  # noqa: E402
from pii_checker.models import ItemResult, Status  # noqa: E402

# 法人格の無い社名（1つずつでは人の名前と見分けられない）
PLAIN_COMPANIES = [
    f"{a}{b}"
    for a in ("あおば", "みどり", "ひかり", "さくら", "かえで")
    for b in ("電機", "食品", "建設", "物産", "工業", "精機", "運輸", "薬品", "化学", "商会", "製作所", "通商")
]
# 会社の印のある社名
MARKED_COMPANIES = [f"見本{i}株式会社" for i in range(20)]
PERSONS = [
    f"{s}{g}"
    for s in ("山田", "佐藤", "鈴木", "高橋", "田中", "伊藤", "渡辺", "中村")
    for g in ("太郎", "花子", "一郎", "次郎", "幸子", "健", "愛", "誠", "優子", "直樹")
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
    """異なる値が 50 個そろって会社の印が5%以上なら、それ以降の法人格の無い社名は 低（それまでの分は 中）。"""
    values = MARKED_COMPANIES[:5] + PLAIN_COMPANIES[:55]
    got = _names(_rows("name", values))
    medium_before = COLUMN_ORG_MIN_DISTINCT - 1 - 5  # 50 個目の値で判定が付く
    assert got.get("name:medium", 0) == medium_before, got
    assert got.get("name:low", 0) == 55 - medium_before, got


def test_company_column_by_records():
    """列名の分かっている表（データベース・parquet の経路）でも同じ。"""
    values = MARKED_COMPANIES[:5] + PLAIN_COMPANIES[:55]
    got = _names(_rows("name", values), records=True)
    assert got.get("name:low", 0) == 55 - (COLUMN_ORG_MIN_DISTINCT - 1 - 5), got


def test_small_table_is_not_judged():
    """異なる値が 50 個に満たない表は判定しない（会社の印が多くても 中 のまま）。"""
    values = MARKED_COMPANIES[:5] + PLAIN_COMPANIES[:40]
    got = _names(_rows("name", values))
    assert got == {"name:medium": 40}, got


def test_person_column_stays_medium():
    """人の名前だけの列は今までどおり 中。"""
    got = _names(_rows("氏名", PERSONS))
    assert got == {"name:medium": len(PERSONS)}, got


def test_few_companies_at_head_of_person_list_do_not_lower():
    """名簿の先頭に法人の顧客が数件（50 個の中で5%未満）あるだけなら、後ろの人の名前を下げない。"""
    values = MARKED_COMPANIES[:2] + PERSONS
    got = _names(_rows("氏名", values))
    assert got.get("name:low", 0) == 0, got


def test_ratio_boundary():
    """会社の印が、50 個の時点でちょうど5%（3個は 5% 以上・2個は未満）。"""
    lowered = _names(_rows("name", MARKED_COMPANIES[:3] + PLAIN_COMPANIES[:57]))
    kept = _names(_rows("name", MARKED_COMPANIES[:2] + PLAIN_COMPANIES[:58]))
    assert lowered.get("name:low", 0) > 0, lowered
    assert kept.get("name:low", 0) == 0, kept


def test_repeated_company_counts_once():
    """同じ社名が何行も続いても、会社の印は異なる値で数える。"""
    values = MARKED_COMPANIES[:1] * 30 + PLAIN_COMPANIES[:59]
    got = _names(_rows("name", values))
    assert got.get("name:low", 0) == 0, got


def test_verdict_returns_to_medium_when_ratio_drops():
    """判定の後も上限までは見直す: 人の名前が続いて割合が5%を切れば 中 に戻る。"""
    orgs = engine._ColumnOrgs()
    for v in MARKED_COMPANIES[:3] + PLAIN_COMPANIES[:47]:
        orgs.cell(1, "name", v)
    assert orgs.cell(1, "name", PERSONS[0]) is True  # 3/51
    for p in PERSONS[1:15]:
        orgs.cell(1, "name", p)
    assert orgs.cell(1, "name", PERSONS[15]) is False  # 3/66


def test_honorific_value_in_company_column_stays_medium():
    """会社名の列でも、敬称つきの宛名は人として 中 のまま。"""
    values = MARKED_COMPANIES[:5] + PLAIN_COMPANIES[:45] + ["山田太郎様"] + PLAIN_COMPANIES[45:48]
    got = _names(_rows("宛名", values))
    # 50 個目の社名から 低（その社名と後ろの3つ）。敬称つきが下がれば 低 は5になる
    assert got.get("name:low", 0) == 4, got
    assert got.get("name:medium", 0) == 45, got


def test_honorific_company_values_are_not_counted_as_companies():
    """「株式会社サンプル 山田様」のような敬称つきは会社の印として数えない（人宛ての宛名の列を下げない）。"""
    values = [f"株式会社サンプル{i} {p}様" for i, p in enumerate(PERSONS[:10])] + PERSONS[10:]
    got = _names(_rows("宛名", values))
    assert got.get("name:low", 0) == 0, got


def test_new_header_resets_the_judgement():
    """見出しが変わったら（同じシートの2つ目の表）数え直す。"""
    rows = _rows("name", MARKED_COMPANIES[:5] + PLAIN_COMPANIES[:47])
    rows += [[], ["code", "氏名", "電話"]] + [[f"{2000 + i}", p, ""] for i, p in enumerate(PERSONS[:5])]
    got = _names(rows)
    assert got.get("name:low", 0) == 3, got
    assert got.get("name:medium", 0) == 44 + 5, got


def test_judgement_is_fixed_after_track_limit():
    """異なる値が上限に届いたら判定を固め、値の覚えを捨てる（メモリを食わない）。"""
    orgs = engine._ColumnOrgs()
    for v in MARKED_COMPANIES[:10]:  # 上限の 200 個の5%
        orgs.cell(1, "name", v)
    for i in range(engine.COLUMN_ID_TRACK):
        orgs.cell(1, "name", f"見本{i}")
    assert 1 in orgs._decided and 1 not in orgs._values
    assert orgs.cell(1, "name", "新しい社名") is True
    assert orgs.cell(0, "code", "株式会社サンプル") is False  # 氏名の列でなければ数えない


def _helper32_names(tmp_path, monkeypatch, tables: dict[str, list[list[str]]]) -> dict[str, int]:
    """Access を32ビットの補助で読んだときの氏名の件数（補助の出力は決めた JSON Lines で代える）。"""
    from test_column_id import _helper32_messages, _run_fake_helper32

    msgs = _helper32_messages({name: (rows[0], rows[1:]) for name, rows in tables.items()})
    item = _run_fake_helper32(tmp_path, monkeypatch, msgs)
    return {k: n for k, n in item.conf_counts.items() if k.startswith("name:")}


def test_helper32_path_also_lowers(tmp_path, monkeypatch):
    """Access を32ビットの補助で読んだ表でも、会社名の列の法人格の無い社名を 低 にする（ほかの読み方と同じ）。"""
    values = MARKED_COMPANIES[:5] + PLAIN_COMPANIES[:55]
    got = _helper32_names(tmp_path, monkeypatch, {"brands": _rows("name", values)})
    assert got.get("name:low", 0) == 55 - (COLUMN_ORG_MIN_DISTINCT - 1 - 5), got


def test_helper32_judges_each_table_separately(tmp_path, monkeypatch):
    """32ビットの補助の経路でも表ごとに判定する（前の表の会社名の列の判定を、同じ列番号の次の表へ持ち越さない）。"""
    companies = _rows("name", MARKED_COMPANIES[:5] + PLAIN_COMPANIES[:55])
    members = _rows("氏名", PERSONS[:10])
    got = _helper32_names(tmp_path, monkeypatch, {"brands": companies, "members": members})
    assert got.get("name:low", 0) == 55 - (COLUMN_ORG_MIN_DISTINCT - 1 - 5), got
    assert got.get("name:medium", 0) == (COLUMN_ORG_MIN_DISTINCT - 1 - 5) + 10, got

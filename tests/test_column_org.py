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
    """列名の分かっている表（データベース・parquet の経路）では先頭の行を先読みして判定するので、判定の前の社名も 低。"""
    values = MARKED_COMPANIES[:5] + PLAIN_COMPANIES[:55]
    got = _names(_rows("name", values), records=True)
    assert got == {"name:low": 55}, got


def test_records_prefetch_waits_until_decided():
    """50 個の時点では会社の印が5%未満でも、後で5%を超える列は、先読みで固まった判定を先頭の行から使う（全部 低）。"""
    # 異なる値 50 個で 2/50（未満）・51 個目で 3/51・終わりの 60 個で 3/60（ちょうど5%）
    values = MARKED_COMPANIES[:2] + PLAIN_COMPANIES[:48] + MARKED_COMPANIES[2:3] + PLAIN_COMPANIES[48:57]
    assert _names(_rows("name", values), records=True) == {"name:low": 57}
    # 流しながら読む表（add_table）は今までどおり、判定が変わるまでの 48 行は 中
    assert _names(_rows("name", values)) == {"name:medium": 48, "name:low": 9}


def test_records_prefetch_uses_final_verdict_when_ratio_drops():
    """50 個の時点で5%以上でも、後ろに人の名前が続いて割合が下がる列は、先頭の行から 中（下げすぎない）。"""
    values = MARKED_COMPANIES[:3] + PLAIN_COMPANIES[:47] + PERSONS
    assert _names(_rows("氏名", values), records=True) == {"name:medium": 47 + len(PERSONS)}


def test_records_person_column_stays_medium():
    """先読みしても、人の名前だけの列は 中 のまま（名簿の先頭に法人が数件あっても下げない）。"""
    got = _names(_rows("氏名", MARKED_COMPANIES[:2] + PERSONS), records=True)
    assert got == {"name:medium": len(PERSONS)}, got


def test_records_small_table_is_not_judged():
    """先読みで表の終わりまで読んでも、異なる値が 50 個に満たなければ判定しない。"""
    got = _names(_rows("name", MARKED_COMPANIES[:5] + PLAIN_COMPANIES[:40]), records=True)
    assert got == {"name:medium": 40}, got


def test_records_prefetch_keeps_row_keys():
    """先読みで行の反復子の「今の行」が進んでも、対処のための位置の鍵は行ごとに正しい（DB・ダンプの経路）。"""
    item = ItemResult(path="t", kind="", status=Status.PENDING)
    col = Collector(item, 100)
    col.collect_positions, col.pos_layout, col.pos_sheet = True, "sqlite", "t"
    cur = [0]
    col.row_key = lambda r: cur[0]

    def rows():
        for i, p in enumerate(PERSONS):
            cur[0] = 1000 + i  # 呼び出し側が持つ「今の行」（データベースの rowid など）
            yield [p, f"user{i}@example.com"]

    col.add_records(["氏名", "mail"], rows(), lambda r, c: f"R{r}C{c + 1}")
    got = sorted(arr[i] for (_, t, _), arr in col.positions.items() if t == "email" for i in range(0, len(arr), 4))
    assert got == [1000 + i for i in range(len(PERSONS))], got
    assert col.row_key(5) == cur[0]  # 先読みの間だけの差し替えを元に戻している


def test_records_prefetch_error_scans_read_rows():
    """先読みの途中で読み取りが失敗しても、読めた行を検査してから同じ例外を出す（今までどおり）。"""
    item = ItemResult(path="t", kind="", status=Status.PENDING)
    col = Collector(item, 100)

    def rows():
        for p in PERSONS[:10]:
            yield [p]
        raise OSError("壊れた行")

    try:
        col.add_records(["氏名"], rows(), lambda r, c: f"R{r}C{c + 1}")
    except OSError as e:
        assert str(e) == "壊れた行"
    else:
        raise AssertionError("例外が出なかった")
    assert item.conf_counts.get("name:medium", 0) == 10, item.conf_counts


def test_records_prefetch_is_bounded():
    """氏名の列が判定に届かなくても、先読みは上限の行数で止める（残りは流しながら検査する）。"""
    orgs_rows = [[f"{i}", "山田太郎"] for i in range(engine.COLUMN_ORG_PREFETCH_ROWS + 500)]
    item = ItemResult(path="t", kind="", status=Status.PENDING)
    col = Collector(item, 20)
    col._col_orgs = engine._ColumnOrgs()
    head, _, _, rest = col._prefetch_org_columns(["code", "氏名"], iter(orgs_rows))
    assert len(head) == engine.COLUMN_ORG_PREFETCH_ROWS
    assert len(list(rest)) == 500


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


def test_lowered_company_name_notes_why_low():
    """会社名の列のせいで 低 にした明細には、検出規則の末尾にそのわけを足す（判定の前の 中 には足さない）。"""
    item = ItemResult(path="t", kind="", status=Status.PENDING)
    col = Collector(item, 100)
    col.add_table(_rows("name", MARKED_COMPANIES[:5] + PLAIN_COMPANIES[:55]), lambda r, c: f"R{r}C{c + 1}")
    low = [f.rule for f in item.findings if f.pii_type == "name" and f.confidence.value == "low"]
    medium = [f.rule for f in item.findings if f.pii_type == "name" and f.confidence.value == "medium"]
    assert low and all(r == engine.HEADER_NAME_RULE + engine.ORG_COLUMN_NOTE for r in low), low
    assert medium and all(r == engine.HEADER_NAME_RULE for r in medium), medium

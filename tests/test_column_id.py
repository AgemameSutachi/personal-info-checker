"""手がかり語の無い12桁のマイナンバーを、表の列の文脈で落とす（engine._ColumnDigits）の試験。

12桁の数はすべて試験のために作った値で、実在の番号ではない。
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pii_checker import engine  # noqa: E402
from pii_checker.detectors import my_number_is_valid  # noqa: E402
from pii_checker.engine import Collector  # noqa: E402
from pii_checker.models import ItemResult, Status  # noqa: E402


def _valid_numbers(n: int, seed: int) -> list[str]:
    """検査数字が合う12桁を n 個（試験用に作る）。"""
    rnd = random.Random(seed)
    out: list[str] = []
    while len(out) < n:
        body = f"{rnd.randrange(10**10, 10**11):011d}"
        for d in "0123456789":
            if my_number_is_valid(body + d):
                out.append(body + d)
                break
    return out


def _invalid_numbers(n: int, seed: int) -> list[str]:
    rnd = random.Random(seed)
    out: list[str] = []
    while len(out) < n:
        v = f"{rnd.randrange(10**11, 10**12):012d}"
        if not my_number_is_valid(v):
            out.append(v)
    return out


def _low_my_number(rows, records: bool = False) -> int:
    item = ItemResult(path="t", kind="", status=Status.PENDING)
    col = Collector(item, 20)
    if records:
        col.add_records(rows[0], rows[1:], lambda r, c: f"R{r}C{c + 1}")
    else:
        col.add_table(rows, lambda r, c: f"R{r}C{c + 1}")
    return item.conf_counts.get("my_number:low", 0)


def _id_column(n: int, valid_every: int, repeat: int = 1) -> list[str]:
    """番号の列: valid_every 個に1個だけ検査数字が合う（でたらめな番号の偶然の一致の代わり）。"""
    valid = iter(_valid_numbers(n, 1))
    invalid = iter(_invalid_numbers(n, 2))
    col = []
    for i in range(n):
        v = next(valid) if i % valid_every == 0 else next(invalid)
        col += [v] * repeat
    return col


def test_id_column_drops_bare_my_number_after_enough_values():
    """検査数字の合う値が1割の番号の列: 判定が付くまでの分だけ残り、その後は拾わない。"""
    ids = _id_column(300, 10)
    rows = [["race_id", "rank"]] + [[v, "1"] for v in ids]
    got = _low_my_number(rows)
    # 判定が付くのは異なる値が 20 個そろった時点（そこまでに合うのは 2 個）
    assert got == 2, got


def test_repeated_values_are_counted_as_distinct():
    """同じ番号が何行も続く列（レースごとの行）でも、異なる値で数える（最初の番号が合っても番号の列と分かる）。"""
    ids = _id_column(100, 10, repeat=16)  # 最初の値は検査数字が合う
    rows = [["race_id", "horse"]] + [[v, "テスト号"] for v in ids]
    got = _low_my_number(rows)
    assert got == 2 * 16, got  # 判定までの合う値 2 個 × 16 行


def test_real_my_number_column_is_kept():
    """全部の値の検査数字が合う列（見出しが「番号」でも）は今までどおり拾う。"""
    nums = _valid_numbers(250, 3)
    rows = [["番号", "備考"]] + [[v, ""] for v in nums]
    assert _low_my_number(rows) == 250


def test_mixed_column_majority_valid_is_kept():
    """合う値が半分以上なら番号の列とはみなさない。"""
    valid = _valid_numbers(60, 4)
    invalid = _invalid_numbers(40, 5)
    col = []
    for i in range(100):
        col.append(valid.pop() if i % 5 != 0 and valid else invalid.pop())
    col += valid + invalid
    rows = [["code", "x"]] + [[v, "a"] for v in col]
    assert _low_my_number(rows) == 60


def test_other_columns_are_not_affected():
    """番号の列と判定されても、ほかの列の12桁は今までどおり拾う。"""
    ids = _id_column(100, 10)
    nums = _valid_numbers(100, 6)
    rows = [["race_id", "num"]] + [[a, b] for a, b in zip(ids, nums)]
    assert _low_my_number(rows) == 2 + 100


def test_header_my_number_column_is_not_dropped():
    """見出しがマイナンバーの列は、検査数字の合わない値が多くても見出しの規則で拾う（この判定で落とさない）。"""
    ids = _id_column(100, 10)
    rows = [["マイナンバー", "氏名"]] + [[v, "架空 太郎"] for v in ids]
    item = ItemResult(path="t", kind="", status=Status.PENDING)
    col = Collector(item, 20)
    col.add_table(rows, lambda r, c: f"R{r}C{c + 1}")
    assert item.conf_counts.get("my_number:high", 0) == 10, item.conf_counts


def test_records_path_also_drops():
    """データベースの表（add_records）でも同じ。"""
    ids = _id_column(300, 10)
    rows = [["race_id", "rank"]] + [[v, 1] for v in ids]
    assert _low_my_number(rows, records=True) == 2


def _run_fake_helper32(tmp_path, monkeypatch, messages: list[dict]) -> ItemResult:
    """32bit の補助（access32_helper）の代わりに、決めた JSON Lines を出すだけの台本で _read_access_helper32 を通す。"""
    import json
    from types import SimpleNamespace

    from pii_checker.formats import database

    data = tmp_path / "lines.jsonl"
    data.write_text("\n".join(json.dumps(m, ensure_ascii=False) for m in messages) + "\n", encoding="utf-8")
    script = tmp_path / "fake_helper.py"
    script.write_text(
        "import sys\nsys.stdin.read()\nsys.stdout.buffer.write(open(sys.argv[1], 'rb').read())\n", encoding="utf-8"
    )
    monkeypatch.setattr(database, "find_helper32", lambda configured: [sys.executable, str(script), str(data)])
    ctx = SimpleNamespace(
        options=SimpleNamespace(access_helper32=None, max_rows_per_table=0), password_candidates=lambda: []
    )
    item = ItemResult(path="t", kind="", status=Status.PENDING)
    col = Collector(item, 20)
    database._read_access_helper32(ctx, "dummy.mdb", col, item, 0, "t")
    return item


def _helper32_messages(tables: dict[str, tuple[list[str], list[list]]]) -> list[dict]:
    msgs: list[dict] = [{"type": "open", "driver": "試験", "method": "試験"}]
    for name, (columns, rows) in tables.items():
        msgs.append({"type": "table", "name": name, "columns": columns})
        msgs += [{"type": "row", "table": name, "row": i, "values": v} for i, v in enumerate(rows, start=1)]
    msgs.append({"type": "done"})
    return msgs


def test_helper32_path_also_drops(tmp_path, monkeypatch):
    """Access を32ビットの補助で読んだ表でも、番号の列の手がかり語の無い12桁を落とす（ほかの読み方と同じ）。"""
    ids = _id_column(300, 10)
    item = _run_fake_helper32(
        tmp_path, monkeypatch, _helper32_messages({"races": (["race_id", "rank"], [[v, 1] for v in ids])})
    )
    assert item.conf_counts.get("my_number:low", 0) == 2, item.conf_counts


def test_helper32_judges_each_table_separately(tmp_path, monkeypatch):
    """32ビットの補助の経路でも、表ごとに判定する（前の表の番号の列の判定を、同じ列番号の次の表へ持ち越さない）。"""
    ids = _id_column(300, 10)
    nums = _valid_numbers(30, 7)
    msgs = _helper32_messages({"races": (["race_id"], [[v] for v in ids]), "members": (["x"], [[v] for v in nums])})
    item = _run_fake_helper32(tmp_path, monkeypatch, msgs)
    assert item.conf_counts.get("my_number:low", 0) == 2 + 30, item.conf_counts


def test_new_table_resets_the_judgement():
    """表が変われば判定をやり直す（前の表の番号の列の判定を持ち越さない）。"""
    item = ItemResult(path="t", kind="", status=Status.PENDING)
    col = Collector(item, 20)
    col.add_records(["race_id"], [[v] for v in _id_column(300, 10)], lambda r, c: f"R{r}C{c + 1}")
    before = item.conf_counts.get("my_number:low", 0)
    nums = _valid_numbers(30, 7)
    col.add_records(["x"], [[v] for v in nums], lambda r, c: f"R{r}C{c + 1}")
    assert item.conf_counts.get("my_number:low", 0) - before == 30


def test_track_limit_freezes_decision_until_valid_streak():
    """異なる値が上限に届いたら判定を固めて覚えた値を手放す。検査数字の合う値が続いたら判定を解いて数え直す。"""
    cd = engine._ColumnDigits()
    for v in _id_column(engine.COLUMN_ID_TRACK + 50, 10):
        cd.observe(0, v)
    assert cd._decided == {0} and cd.verdict == {0: True}
    assert 0 not in cd._values
    nums = _valid_numbers(300, 8)
    got = [cd.observe(0, v) for v in nums]
    k = engine.COLUMN_ID_RELEASE_STREAK
    assert got[: k - 1] == [True] * (k - 1)  # 解くまでの数個は捨てる
    assert not any(got[k - 1 :])  # 合う値の続く列は、その後ずっと拾う
    assert cd.verdict[0] is False  # 数え直して、番号の列ではないと固まる


def test_id_values_repeated_do_not_build_streak():
    """番号の列で、検査数字の合う同じ番号が何行続いても（レースごとの行）判定は解かない。"""
    cd = engine._ColumnDigits()
    for v in _id_column(engine.COLUMN_ID_TRACK + 50, 10, repeat=16):
        cd.observe(0, v)
    assert cd.verdict == {0: True}
    assert all(cd.observe(0, v) for v in _id_column(100, 10, repeat=16))


def test_column_switching_to_real_numbers_keeps_most():
    """列の途中から本物のマイナンバーに変わる表: 番号の列の判定が固まった後でも、切り替わりの数個しか捨てない。"""
    ids = _invalid_numbers(150, 9)
    nums = _valid_numbers(3000, 10)
    alone = _low_my_number([["code", "x"]] + [[v, "a"] for v in nums])  # ほかの規則で落ちる分を除いた数
    got = _low_my_number([["code", "x"]] + [[v, "a"] for v in ids + nums])
    assert alone - got == engine.COLUMN_ID_RELEASE_STREAK - 1, (alone, got)


def test_judgement_boundaries():
    """判定は異なる値が 20 個そろってから。合う値がちょうど半分なら番号の列とはみなさない。"""
    cd = engine._ColumnDigits()
    bad = _invalid_numbers(engine.COLUMN_ID_MIN_DISTINCT, 11)
    for v in bad[:-1]:
        assert cd.observe(0, v) is False  # 19 個までは判定しない
    assert cd.observe(0, bad[-1]) is True  # 20 個目で番号の列
    # 合う値と合わない値を交互に 10 個ずつ（続けては合わないので判定を解く仕組みは働かない）
    good = _valid_numbers(10, 12)
    bad = _invalid_numbers(10, 13)
    cd = engine._ColumnDigits()
    for g, b in zip(good, bad):
        cd.observe(1, g)
        last = cd.observe(1, b)
    assert last is False  # 10/20 はちょうど半分: 番号の列とはみなさない
    cd.observe(1, _invalid_numbers(1, 14)[0])
    assert cd.verdict[1] is True  # 10/21 は半分未満


def test_fullwidth_digits_are_counted():
    """全角の12桁も同じく数える。"""
    table = str.maketrans("0123456789", "０１２３４５６７８９")
    cd = engine._ColumnDigits()
    for v in _invalid_numbers(engine.COLUMN_ID_MIN_DISTINCT, 15):
        last = cd.observe(0, v.translate(table))
    assert last is True


def test_space_padded_cells_are_counted():
    """データベースの固定長の文字の列（後ろを空白で詰めた「000000008370␣␣␣…」）も、空白を外して番号の列と分かる。"""
    ids = _id_column(300, 10)
    rows = [["TXT_LABEL", "rank"]] + [[v + " " * 24, "1"] for v in ids]
    assert _low_my_number(rows) == 2


def _scan_xlsx(tmp_path, rows) -> ItemResult:
    import openpyxl

    from pii_checker.engine import scan_file
    from pii_checker.models import ScanOptions

    path = tmp_path / "ids.xlsx"
    wb = openpyxl.Workbook()
    for r in rows:
        wb.active.append(r)
    wb.save(path)
    return scan_file(str(path), ScanOptions(temp_dir=str(tmp_path))).items[0]


def test_xlsx_sheet_xml_reread_keeps_column_verdict(tmp_path):
    """xlsx はセルを表で読んだ後にシートの XML も読み直す。表の番号の列で外した値を、XML の読み直しで拾い直さない。"""
    ids = _id_column(300, 10)
    item = _scan_xlsx(tmp_path, [["CD", "rank"]] + [[v, "1"] for v in ids])
    assert item.finding_counts.get("my_number", 0) == 2, item.finding_counts


def test_xlsx_values_are_not_counted_twice(tmp_path):
    """表で数えた値を、シートの XML の読み直しでもう一度数えない（1つの電話番号が2件になっていた）。"""
    item = _scan_xlsx(tmp_path, [["名前", "電話"], ["架空太郎", "090-1234-5678"]])
    assert item.finding_counts.get("phone", 0) == 1, item.finding_counts


def test_docx_values_are_not_counted_twice(tmp_path):
    """docx も、本文として読んだ値を document.xml の読み直しでもう一度数えない。"""
    import docx

    from pii_checker.engine import scan_file
    from pii_checker.models import ScanOptions

    path = tmp_path / "one.docx"
    d = docx.Document()
    d.add_paragraph("連絡先 電話 090-1234-5678")
    d.save(path)
    item = scan_file(str(path), ScanOptions(temp_dir=str(tmp_path))).items[0]
    assert item.finding_counts.get("phone", 0) == 1, item.finding_counts

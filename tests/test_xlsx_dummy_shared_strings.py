"""xlsx のダミー置換を、Excel が普通に保存する形（共有文字列 t="s"）のブックで試す。

いまの openpyxl は文字のセルを inlineStr で書くため、openpyxl で作ったブックだけでは
共有文字列を読み替える経路と「参照されなくなった共有文字列を空にする」経路が通らない。
ここでは openpyxl で作ったブックの inlineStr を共有文字列へ組み替えてから試す。
"""

import html
import re
import zipfile
from array import array
from pathlib import Path

import openpyxl
import pytest

from pii_checker.remedy_write import DummyMaker, RemedyError, Selection, rewrite_xlsx_dummy

RE_INLINE = re.compile(r'<c r="([A-Z]+\d+)"([^>]*?) t="inlineStr"([^>]*)><is><t>(.*?)</t></is></c>', re.S)


def to_shared_strings(path: Path, rich: dict[str, list[str]] | None = None) -> None:
    """ブックの inlineStr のセルを共有文字列（t="s"）に組み替える。同じ文字は1つの項目を共有する。

    rich は「文字 → run に分けた断片」。指定した文字の項目はリッチテキスト（複数の r）で書く。
    """
    rich = rich or {}
    with zipfile.ZipFile(path) as z:
        parts = {n: z.read(n) for n in z.namelist()}
    strings: list[str] = []

    def sub(m: re.Match) -> str:
        text = html.unescape(m.group(4))
        if text not in strings:
            strings.append(text)
        return f'<c r="{m.group(1)}"{m.group(2)} t="s"{m.group(3)}><v>{strings.index(text)}</v></c>'

    for name in [n for n in parts if n.startswith("xl/worksheets/sheet")]:
        parts[name] = RE_INLINE.sub(sub, parts[name].decode("utf-8")).encode("utf-8")
    items = []
    for s in strings:
        if s in rich:
            runs = "".join(f"<r><t>{html.escape(p, quote=False)}</t></r>" for p in rich[s])
            items.append(f"<si>{runs}</si>")
        else:
            items.append(f"<si><t>{html.escape(s, quote=False)}</t></si>")
    parts["xl/sharedStrings.xml"] = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
        f' count="{len(strings)}" uniqueCount="{len(strings)}">' + "".join(items) + "</sst>"
    ).encode("utf-8")
    rels = parts["xl/_rels/workbook.xml.rels"].decode("utf-8")
    rels = rels.replace(
        "</Relationships>",
        '<Relationship Id="rIdSst" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/'
        'sharedStrings" Target="sharedStrings.xml"/></Relationships>',
    )
    parts["xl/_rels/workbook.xml.rels"] = rels.encode("utf-8")
    ct = parts["[Content_Types].xml"].decode("utf-8")
    ct = ct.replace(
        "</Types>",
        '<Override PartName="/xl/sharedStrings.xml" ContentType="application/'
        'vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/></Types>',
    )
    parts["[Content_Types].xml"] = ct.encode("utf-8")
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in parts.items():
            z.writestr(name, data)


def build_book(path: Path, rows: list[list[str]], rich: dict[str, list[str]] | None = None) -> None:
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "顧客"
    for r in rows:
        ws.append(r)
    wb.save(path)
    to_shared_strings(path, rich)


def select(*cells: tuple[int, int, int, int]) -> Selection:
    """(行（1 始まり）, 列（0 始まり）, 開始, 終了) の並びから、シート「顧客」の選択を作る。"""
    arr = array("q")
    for c in cells:
        arr.extend(c)
    return Selection(groups={("顧客", "メールアドレス", 0): arr})


def read_rows(path: Path) -> list[list]:
    wb = openpyxl.load_workbook(path)
    try:
        return [[c.value for c in row] for row in wb["顧客"].iter_rows()]
    finally:
        wb.close()


def all_bytes(path: Path) -> bytes:
    with zipfile.ZipFile(path) as z:
        return b"".join(z.read(n) for n in z.namelist())


def sst_items(path: Path) -> list[str]:
    with zipfile.ZipFile(path) as z:
        xml = z.read("xl/sharedStrings.xml").decode("utf-8")
    return re.findall(r"<si\b[^>]*?(?:/>|>.*?</si>)", xml, re.S)


def test_shared_string_released_when_no_longer_referenced(tmp_path):
    src, dst = tmp_path / "a.xlsx", tmp_path / "b.xlsx"
    build_book(src, [["氏名", "メール"], ["山田", "taro@example.com"], ["佐藤", "hanako@example.com"]])
    assert b't="s"' in all_bytes(src) and b"taro@example.com" in all_bytes(src)  # 組み替えの確認
    before = sst_items(src)
    stats = rewrite_xlsx_dummy(str(src), str(dst), select((2, 1, 0, 16)), DummyMaker("fixed"))
    assert stats["cells"] == 1 and stats["detections"] == 1
    rows = read_rows(dst)
    assert rows[1] == ["山田", "＊＊＊"]
    assert rows[2] == ["佐藤", "hanako@example.com"]  # 選んでいないセルは共有文字列のまま読める
    assert b"taro@example.com" not in all_bytes(dst)  # 共有文字列の中にも元の値が残らない
    after = sst_items(dst)
    assert len(after) == len(before)  # 番号がずれないよう、項目は消さずに空にする
    assert after[before.index("<si><t>taro@example.com</t></si>")] == "<si><t></t></si>"


def test_shared_string_kept_while_another_cell_uses_it(tmp_path):
    src, dst = tmp_path / "a.xlsx", tmp_path / "b.xlsx"
    build_book(src, [["氏名", "メール"], ["山田", "same@example.com"], ["山田", "same@example.com"]])
    stats = rewrite_xlsx_dummy(str(src), str(dst), select((2, 1, 0, 16)), DummyMaker("fixed"))
    assert stats["cells"] == 1
    rows = read_rows(dst)
    assert rows[1][1] == "＊＊＊"
    assert rows[2][1] == "same@example.com"  # 同じ項目を指す別のセルが壊れない
    assert sst_items(dst) == sst_items(src)


def test_rich_text_shared_string(tmp_path):
    src, dst = tmp_path / "a.xlsx", tmp_path / "b.xlsx"
    value = "連絡先 rich@example.com"
    build_book(src, [["氏名", "メール"], ["山田", value]], rich={value: ["連絡先 ", "rich@", "example.com"]})
    assert b"rich@example.com" not in all_bytes(src)  # run に分かれていて、そのままの並びでは見えない
    start = value.index("rich")
    stats = rewrite_xlsx_dummy(str(src), str(dst), select((2, 1, start, len(value))), DummyMaker("fixed"))
    assert stats["cells"] == 1
    assert read_rows(dst)[1][1] == "連絡先 ＊＊＊"
    blob = all_bytes(dst)
    assert b"rich@" not in blob and b"example.com" not in blob  # 断片も残らない


def test_no_cell_to_rewrite_is_refused(tmp_path):
    src, dst = tmp_path / "a.xlsx", tmp_path / "b.xlsx"
    build_book(src, [["氏名", "メール"], ["山田", "taro@example.com"]])
    with pytest.raises(RemedyError, match="書き換えるセルが見つかりませんでした"):
        rewrite_xlsx_dummy(str(src), str(dst), select((5, 1, 0, 16)), DummyMaker("fixed"))  # 値の無い行
    assert not dst.exists()


def test_unreadable_book_is_refused(tmp_path):
    src, dst = tmp_path / "broken.xlsx", tmp_path / "b.xlsx"
    src.write_bytes(b"PK\x03\x04 this is not a workbook")
    with pytest.raises(RemedyError, match="ブックを読み取れませんでした"):
        rewrite_xlsx_dummy(str(src), str(dst), select((2, 1, 0, 16)), DummyMaker("fixed"))
    assert not dst.exists()

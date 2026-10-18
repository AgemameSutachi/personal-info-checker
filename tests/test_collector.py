"""表の見出し推定・件数・埋め込み・保護文書の回帰試験（見落としやすかった例）。"""

# 試験の住所は施設の公開所在地（例 東京都千代田区丸の内1-1-1）で、個人の住所ではない。人名・電話・メールはすべて架空

from __future__ import annotations

import base64
import io
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pii_checker.engine import Collector, scan_file  # noqa: E402
from pii_checker.models import ItemResult, ScanOptions, Status  # noqa: E402


def table_counts(rows) -> dict[str, int]:
    item = ItemResult(path="t", kind="", status=Status.PENDING)
    col = Collector(item, 20)
    col.add_table(rows, lambda r, c: f"R{r}C{c + 1}")
    return item.finding_counts


@pytest.mark.parametrize(
    "rows, expect",
    [
        # 見出し語が1つだけの名簿（以前の回帰: 見出し語2つ以上でないと見出しにしなかった）
        ([["No", "氏名"], ["1", "鬼瓦権左衛門"], ["2", "勅使河原二郎"]], {"name": 2}),
        (
            [["社員番号", "氏名", "入社日"], ["A01", "鬼瓦権左衛門", "2020/4/1"], ["A02", "勅使河原二郎", "2021/4/1"]],
            {"name": 2},
        ),
        # 括弧書きの見出し（必須・任意）
        (
            [["氏名（必須）", "電話番号（任意）"], ["鬼瓦権左衛門", "0312345678"], ["勅使河原二郎", "0612345678"]],
            {"name": 2, "phone": 2},
        ),
        # 縦に2つ並んだ表（2つ目の方が見出し語が多い）
        (
            [
                ["氏名", "電話"],
                ["鬼瓦権左衛門", "0312345678"],
                [],
                ["氏名", "電話", "生年月日"],
                ["勅使河原二郎", "0612345678", "1980/1/1"],
            ],
            {"name": 2, "phone": 2, "birthdate": 1},
        ),
        # データ行に「住所」「電話」の語が並んでも見出しを切り替えない
        (
            [
                ["氏名", "電話", "変更項目"],
                ["鬼瓦権左衛門", "0312345678", "住所"],
                ["勅使河原二郎", "0612345678", "電話"],
            ],
            {"name": 2, "phone": 2},
        ),
        # 横持ちの申込書
        (
            [["氏名", "鬼瓦権左衛門"], ["住所", "東京都港区六本木6-10-1"], ["電話", "0312345678"]],
            {"name": 1, "address": 1, "phone": 1},
        ),
        # 項目名（入社日・所属）を氏名として拾わない
        ([["氏名", "所属", "入社日"], ["鬼瓦権左衛門", "営業部", "2020/4/1"]], {"name": 1}),
        # 見出しが11行目以降
        ([["表題"]] * 10 + [["氏名", "電話番号"], ["鬼瓦権左衛門", "090-1234-5678"]], {"name": 1, "phone": 1}),
    ],
)
def test_table_headers(rows, expect):
    got = table_counts(rows)
    for k, n in expect.items():
        assert got.get(k, 0) == n, (got, expect)
    assert "name" not in got or got["name"] == expect.get("name", 0), got


def test_low_samples_do_not_hide_high(tmp_path):
    """確度 低 が明細の上限を埋めても、後の確度 高 が件数に数えられる。"""
    item = ItemResult(path="t", kind="", status=Status.PENDING)
    col = Collector(item, 20)
    for i in range(25):
        col.add_text(f"伝票 {100000000000 + i * 7919:012d}", "x")  # 検査数字が合うものは低
    col.add_text("個人番号 1234 5678 9018", "y")
    assert item.conf_counts.get("my_number:high", 0) == 1, item.conf_counts


def test_base64_embedded_zip_in_json(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("meibo.csv", "氏名,電話番号\n鬼瓦権左衛門,090-1234-5678\n勅使河原二郎,080-9876-5432\n")
    p = tmp_path / "export.json"
    p.write_text('{"attachment": "' + base64.b64encode(buf.getvalue()).decode() + '"}', encoding="utf-8")
    r = scan_file(str(p), ScanOptions(ocr=False))
    found = set()
    for it in r.items:
        found |= set(it.finding_counts)
    assert {"name", "phone"} <= found, [(i.path, i.finding_counts) for i in r.items]


def test_truncated_gzip_scans_what_was_read(tmp_path):
    import gzip

    # 行ごとに値を変える（同じ行の繰り返しは極端に圧縮され、半分で切ると数バイトしか戻らない）
    lines = "".join(f"利用者{i},090-{i % 10000:04d}-{(i * 7919) % 10000:04d}\n" for i in range(2000))
    data = gzip.compress(("氏名,電話番号\n" + lines).encode())
    p = tmp_path / "meibo.csv.gz"
    p.write_bytes(data[: len(data) // 2])
    r = scan_file(str(p), ScanOptions(ocr=False))
    assert r.items[0].status == Status.PARTIAL, r.items[0]
    assert any("phone" in i.finding_counts for i in r.items)


def _row_findings(row):
    item = ItemResult(path="t", kind="DB の表", status=Status.PENDING)
    col = Collector(item, 20)
    col.add_records(["c0", "c1"], iter([row]), lambda r, c: str(c))
    col.finish()  # 本物の検査（engine.scan_blob）と同じく、読み終えたら住所・固定電話の確度を決める
    return sorted(f"{f.pii_type}/{f.confidence.value}@{f.location}" for f in item.findings)


@pytest.mark.parametrize(
    "row, expect",
    [
        # 左隣が「見出し語＋値」のセル: 見出しのおかげで拾えた分は低（座標をマイナンバーと取り違えた実機の誤検出）
        (["マイナンバー 123456789018", "POINT (139.76 35.68)"], ["my_number/high@0", "my_number/low@1"]),
        (["生年月日 2024/04/01時点", "1980/04/01"], ["birthdate/high@0", "birthdate/low@1"]),  # 見落とさない
        (
            ["電話 03-1234-5678", "090-1111-2222"],
            ["phone/medium@0", "phone/medium@1"],
        ),  # 見出しなしでも拾える値はそのまま
        # 数字・@ を含むだけの見出しは見出しのまま
        (["2024/04/01時点の氏名", "佐藤花子"], ["name/medium@1"]),
        (["申込者氏名 No.10001", "佐藤花子"], ["name/medium@1"]),
        (["@氏名", "佐藤花子"], ["name/medium@1"]),
        (["病名 2024/04/01", "糖尿病"], ["sensitive/medium@1"]),
        (["マイナンバー", "123456789018"], ["my_number/high@1"]),
    ],
)
def test_horizontal_header_with_value_or_digits(row, expect):
    assert _row_findings(row) == expect


def test_header_cache_does_not_keep_long_cells():
    # 長い本文のセルを覚えるとメモリを食い潰す（40KB×3000行で 115MB 残った）。覚えるのは20字以下だけ
    from pii_checker import engine

    engine._short_header_strength.cache_clear()
    for i in range(50):
        engine._header_strength(f"氏名 {i} " + "あ" * 40_000)
    assert engine._short_header_strength.cache_info().currsize == 0
    assert engine._header_strength("氏名") == engine.HEADER_SURE
    assert engine._short_header_strength.cache_info().currsize == 1

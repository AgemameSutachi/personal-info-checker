"""確度を下げる経路の試験（残留データの1段下げ・横持ちの弱い見出し）。

どちらも件数は変わらず確度だけが変わるので、件数を見る試験では壊れても気づかない。
"""

# 番号・電話はすべて架空（マイナンバー・カード番号は検査数字だけ合わせた試験用の値）

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pii_checker.engine import WEAK_HEADER_NOTE, Collector  # noqa: E402
from pii_checker.models import ItemResult, Status  # noqa: E402


def _conf_counts(fill) -> dict[str, int]:
    item = ItemResult(path="t", kind="", status=Status.PENDING)
    col = Collector(item, 20)
    fill(col)
    return dict(item.conf_counts)


@pytest.mark.parametrize(
    "text, plain, raw",
    [
        # 高は、区切りの失われた残留データでは取り違えうるので中へ
        ("個人番号 1234 5678 9018", "my_number:high", "my_number:medium"),
        ("カード番号 4111 1111 1111 1111", "credit_card:high", "credit_card:medium"),
        # 中の電話は、残留データでは低へ（数字の並びを番号と取り違えやすい種類）
        ("電話 090-1234-5678", "phone:medium", "phone:low"),
    ],
)
def test_raw_lowers_confidence_one_step(text, plain, raw):
    assert _conf_counts(lambda c: c.add_text(text, "x")) == {plain: 1}
    assert _conf_counts(lambda c: c.add_text(text, "x", raw=True)) == {raw: 1}


@pytest.mark.parametrize(
    "text, want",
    [
        ("メール taro.yamada@example.co.jp", {"email:medium": 1}),
        ("氏名 鬼瓦権左衛門 住所 東京都千代田区丸の内9-9-9", {"name:medium": 1, "address:medium": 1}),
    ],
)
def test_raw_keeps_medium_of_other_kinds(text, want):
    """中を低へ下げるのはカード・マイナンバー・電話だけ。ほかの種類の中は残留データでも中のまま。"""
    assert _conf_counts(lambda c: c.add_text(text, "x")) == want
    assert _conf_counts(lambda c: c.add_text(text, "x", raw=True)) == want


@pytest.mark.parametrize(
    "label, value, want",
    [
        # 左隣が見出し語だけのセルなら、見出しとして確度を上げる
        ("マイナンバー", "123456789018", {"my_number:high": 1}),
        # 左隣が「見出し語＋値」のセル（それ自体で検出される）なら弱い見出し。右隣は見出しなしで読んだときの確度に留める
        # （語の無い12桁は見出しなしでは拾えないので低）
        ("マイナンバー 123456789018", "123456789018", {"my_number:high": 1, "my_number:low": 1}),
        # 見出しなしでも中で拾える値は、弱い見出しの右隣でも中（見出しなしの確度を引いていて、一律に低ではない）
        ("電話 090-1111-2222", "090-1234-5678", {"phone:medium": 2}),
    ],
)
def test_weak_side_header_keeps_plain_confidence(label, value, want):
    got = _conf_counts(lambda c: c.add_table([[label, value]], lambda r, k: f"R{r}C{k + 1}"))
    assert got == want, got


def test_weak_side_header_notes_why_low():
    """弱い見出しのせいで 低 にした明細には、検出規則の末尾にそのわけを足す（中 のままの値には足さない）。"""
    item = ItemResult(path="t", kind="", status=Status.PENDING)
    col = Collector(item, 20)
    col.add_table([["氏名 佐藤", "鈴木", "電話 090-1111-2222", "090-1234-5678"]], lambda r, k: f"R{r}C{k + 1}")
    rules = {(f.pii_type, f.confidence.value): f.rule for f in item.findings}
    assert rules[("name", "low")].endswith(WEAK_HEADER_NOTE), rules
    assert not any(r.endswith(WEAK_HEADER_NOTE) for k, r in rules.items() if k[1] != "low"), rules

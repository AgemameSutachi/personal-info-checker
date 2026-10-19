"""人の手がかり待ちの住所を値ごとに覚える数に上限があり、超えても件数と確度の引き上げが変わらないことの試験。"""

from __future__ import annotations

from pii_checker import engine
from pii_checker.models import ItemResult, Status


def _collect(monkeypatch, n_addr: int, with_cue: bool):
    monkeypatch.setattr(engine, "DEFER_LIMIT", 3)
    item = ItemResult(path="list.txt", kind="テキスト", status=Status.PENDING)
    col = engine.Collector(item, 20)
    for i in range(n_addr):
        col.add_text(f"東京都千代田区丸の内{i + 1}丁目{i + 2}番{i + 3}号", f"{i + 1} 行目")
    sizes = (len(col.deferred), dict(col.deferred_overflow))
    if with_cue:
        col.add_text("氏名 山田太郎 生年月日 1980年1月2日", "末尾")
    col.finish()
    return item, sizes


def test_defer_is_capped_and_overflow_counted(monkeypatch):
    """上限を超えた住所は本文を抱えずに件数だけ数え、手がかりが後から見つかれば全件を 中 へ移す。"""
    item, (n_deferred, overflow) = _collect(monkeypatch, 10, with_cue=True)
    assert n_deferred == 3 and overflow == {"address": 7}
    assert item.conf_counts.get("address:medium") == 10
    assert not item.conf_counts.get("address:low")


def test_defer_overflow_stays_low_without_cue(monkeypatch):
    """手がかりが無ければ、上限を超えた分も含めて全件 低 のまま。"""
    item, _ = _collect(monkeypatch, 10, with_cue=False)
    assert item.conf_counts.get("address:low") == 10
    assert not item.conf_counts.get("address:medium")

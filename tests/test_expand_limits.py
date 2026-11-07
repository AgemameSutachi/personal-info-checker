"""書庫の展開の上限（項目数・展開した合計）で打ち切ったときの試験（zip 爆弾対策・網羅の測り直しで通っていなかった所）。

打ち切ったファイルは理由つきの「検査不能」になり、打ち切るまでに見つけた検出は残る。
理由の文言は、上限を人が読む大きさで示し、変えられない設定を「変えられる」と案内しない。
"""

import zipfile

import pytest

from pii_checker import engine
from pii_checker.engine import ScanContext, Uncheckable, size_text
from pii_checker.formats.archive import _check_bomb
from pii_checker.models import ScanOptions, Status


def _zip(tmp_path, count=5):
    z = tmp_path / "a.zip"
    with zipfile.ZipFile(z, "w") as zf:
        for i in range(count):
            zf.writestr(f"f{i}.txt", f"電話 090-1234-567{i}\n" + "あ" * 2000)
    return z


def _scan(tmp_path, **opts):
    z = _zip(tmp_path)
    return engine.scan_file(str(z), ScanOptions(temp_dir=str(tmp_path), **opts))


def test_too_many_entries_is_uncheckable_and_keeps_earlier_hits(tmp_path):
    """内側のファイル数が上限を超えたら打ち切って「検査不能」。上限までに見つけた電話番号は残す。"""
    res = _scan(tmp_path, max_entries=3)
    top = res.items[0]
    assert top.status == Status.UNCHECKABLE
    assert "内側のファイル数が上限（3件）を超えたため打ち切り" in top.reason
    inner = [it for it in res.items if it.depth == 1]
    assert len(inner) == 3 and all(it.finding_counts.get("phone") == 1 for it in inner)


def test_too_much_expansion_is_uncheckable_with_readable_limit(tmp_path):
    """展開した合計が上限を超えたら「検査不能」。上限は人が読む大きさで示し、「0GB」や設定の案内を出さない。"""
    top = _scan(tmp_path, max_expand_bytes=5000).items[0]
    assert top.status == Status.UNCHECKABLE
    assert "上限（4.9KB）" in top.reason, top.reason
    assert "0GB" not in top.reason and "設定で変えられる" not in top.reason
    assert "展開してからそのフォルダを検査" in top.reason


def test_within_limits_scans_everything(tmp_path):
    """陽性対照: 既定の上限なら打ち切らず、5つとも検査する。"""
    res = _scan(tmp_path)
    assert res.items[0].status == Status.SCANNED
    assert sum(1 for it in res.items if it.depth == 1 and it.status == Status.SCANNED) == 5


def test_check_bomb_names_total_and_limit(tmp_path):
    """目次の大きさで先に打ち切るとき、展開後の合計と上限の両方を示す。"""
    ctx = ScanContext(str(tmp_path / "a.zip"), ScanOptions(max_expand_bytes=1024**3), [])
    with pytest.raises(Uncheckable) as e:
        _check_bomb(ctx, total=1536 * 1024**2, archive_size=1536 * 1024**2)
    msg = str(e.value)
    assert "展開後の合計（1.5GB）が上限（1GB）を超える" in msg, msg
    assert "設定で変えられる" not in msg
    _check_bomb(ctx, total=1024**3, archive_size=1024**3)  # ちょうど上限は通す


def test_check_bomb_counts_earlier_expansion_in_text(tmp_path):
    """入れ子の書庫で、それまでに展開した分と合わせて超えたときは、合わせた合計とこの書庫の分の両方を示す。

    今回の分（上限より小さい）だけを書くと「上限より小さい合計が上限を超えた」と読めてしまう。
    """
    ctx = ScanContext(str(tmp_path / "a.zip"), ScanOptions(max_expand_bytes=1024**3), [])
    ctx.expanded_bytes = 800 * 1024**2
    with pytest.raises(Uncheckable) as e:
        _check_bomb(ctx, total=300 * 1024**2, archive_size=300 * 1024**2)
    msg = str(e.value)
    assert "これまでに展開した分（800MB）と合わせた展開後の合計（1.1GB。この書庫の分は 300MB）" in msg, msg
    assert "が上限（1GB）を超える" in msg, msg
    ctx.expanded_bytes = 700 * 1024**2
    _check_bomb(ctx, total=300 * 1024**2, archive_size=300 * 1024**2)  # 合わせて上限以内なら通す


def test_single_compression_over_limit_names_total(tmp_path):
    """gz などの1ファイルの圧縮で上限を超えたときも、展開した合計と上限を示す（入れ子なら合わせた数）。"""
    import gzip

    gz = tmp_path / "big.txt.gz"
    gz.write_bytes(gzip.compress(b"a" * (3 * 1024**2)))
    top = engine.scan_file(str(gz), ScanOptions(temp_dir=str(tmp_path), max_expand_bytes=2 * 1024**2)).items[0]
    assert top.status == Status.UNCHECKABLE
    assert "展開後の合計（" in top.reason and "が上限（2MB）を超えたため打ち切り" in top.reason, top.reason


@pytest.mark.parametrize(
    "nbytes, text",
    [
        (4 * 1024**4, "4TB"),
        (1536 * 1024**2, "1.5GB"),
        (300 * 1024**2, "300MB"),
        (5000, "4.9KB"),
        (1024**2 - 1, "1MB"),  # 丸めで 1024 に届いたら上の単位（「1024KB」にしない）
        (1024**4 - 1, "1TB"),
        (5000 * 1024**4, "5000TB"),
        (512, "512B"),
        (0, "0B"),
    ],
)
def test_size_text(nbytes, text):
    assert size_text(nbytes) == text

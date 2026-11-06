"""zip の目次と項目の頭で名前が食い違うときの試験（実物の F の検査で、Office の cab の中の zip 546 件が検査不能だった）。"""

from __future__ import annotations

import zipfile

from pii_checker import engine
from pii_checker.models import ScanOptions, Status

BODY = "氏名 山田太郎 電話 090-1234-5678\n".encode("utf-8")


def _zip_with_names(path, header_name: str, directory_name: str) -> None:
    """項目の頭に header_name、目次に directory_name と書いた zip を作る（Windows の道具の作り方の再現）。"""
    assert len(header_name) == len(directory_name)
    # zipfile は書くときに \\ を / へ直すので、同じ長さの仮の名前で書いて後で差し替える
    neutral = "n" * len(header_name)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(neutral, BODY)
    raw = bytearray(path.read_bytes())
    old = neutral.encode("ascii")
    head = raw.index(old)  # 項目の頭の名前
    raw[head : head + len(old)] = header_name.encode("ascii")
    cd = raw.index(old, raw.rfind(b"PK\x01\x02"))  # 目次の名前
    raw[cd : cd + len(old)] = directory_name.encode("ascii")
    path.write_bytes(bytes(raw))


def _scan(tmp_path, p):
    return engine.scan_file(str(p), ScanOptions(temp_dir=str(tmp_path)))


def test_backslash_in_directory_slash_in_header(tmp_path):
    """目次が「ar\\x.txt」・頭が「ar/x.txt」の zip も中を検査する（以前は BadZipFile で検査不能）。"""
    p = tmp_path / "win.zip"
    _zip_with_names(p, "ar/x.txt", "ar\\x.txt")
    with zipfile.ZipFile(p) as z:  # 前提: Python の zipfile のままでは開けない
        try:
            z.open(z.infolist()[0]).read()
            raise AssertionError("前提が崩れた: そのままで開けた")
        except zipfile.BadZipFile as e:
            assert "differ" in str(e)
    res = _scan(tmp_path, p)
    inner = [it for it in res.items if it.path.endswith("x.txt")]
    assert inner and inner[0].status != Status.UNCHECKABLE, [(it.path, it.status, it.reason) for it in res.items]
    assert "phone" in {k for it in res.items for k in it.finding_counts}


def test_slash_in_directory_backslash_in_header(tmp_path):
    """逆向き（目次が「/」・頭が「\\」）も開く。"""
    p = tmp_path / "rev.zip"
    _zip_with_names(p, "ar\\x.txt", "ar/x.txt")
    res = _scan(tmp_path, p)
    assert all(it.status != Status.UNCHECKABLE for it in res.items), [(it.path, it.reason) for it in res.items]
    assert "phone" in {k for it in res.items for k in it.finding_counts}


def test_other_name_mismatch_stays_uncheckable(tmp_path):
    """区切り以外の食い違い（別の名前）は開き直さず、理由つきの検査不能のまま。"""
    p = tmp_path / "bad.zip"
    _zip_with_names(p, "ar/x.txt", "zz/y.txt")
    res = _scan(tmp_path, p)
    bad = [it for it in res.items if it.status == Status.UNCHECKABLE]
    assert bad and "differ" in bad[0].reason

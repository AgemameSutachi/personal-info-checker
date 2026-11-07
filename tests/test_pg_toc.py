"""pg_dump の directory 形式（-Fd）のデータファイルを、隣の toc.dat の列名つきで読む試験（engine._load_pg_toc）。

toc.dat は本物の pg_dump が書く二進の形の代わりに、読む側が見る並び（頭の PGDMP・「COPY 表 (列…) FROM stdin;」・
その後ろの「NNNN.dat」）だけを持つ作り物。番号・名前はすべて架空。
"""

from pii_checker import engine
from pii_checker.models import ScanOptions

DAT = "1\t山田 太郎\t090-1234-5678\n2\t佐藤 花子\t\\N\n\\.\n"


def _toc(head: bytes = b"PGDMP") -> bytes:
    return (
        head
        + b"\x01\x0e\x00"
        + b"\x00" * 40
        + b"COPY public.members (id, name, phone) FROM stdin;\x00\x00\x083001.dat\x00"
    )


def _scan(tmp_path, toc: bytes | None):
    folder = tmp_path / "dump"
    folder.mkdir(parents=True)
    (tmp_path / "tmp").mkdir()
    if toc is not None:
        (folder / "toc.dat").write_bytes(toc)
    p = folder / "3001.dat"
    p.write_bytes(DAT.encode("utf-8"))
    res = engine.scan_file(str(p), ScanOptions(temp_dir=str(tmp_path / "tmp")))
    return res.items[0]


def test_data_file_uses_column_names_from_toc(tmp_path):
    """実ファイルは一時フォルダの写しを検査するが、toc.dat は元のフォルダから読み、列名で場所を示す。"""
    item = _scan(tmp_path, _toc())
    assert "toc.dat" in item.method
    locations = {f.location for f in item.findings}
    assert "表「public.members」1行目 列「phone」" in locations, locations


def test_without_toc_still_scanned(tmp_path):
    """toc.dat が無い・PGDMP で始まらないときも、ふつうの文字として検査する（列名が付かないだけ）。"""
    for toc in (None, _toc(b"XXXXX")):
        item = _scan(tmp_path / ("none" if toc is None else "bad"), toc)
        assert "phone" in item.finding_counts
        assert "toc.dat" not in item.method
        assert not any("public.members" in f.location for f in item.findings)

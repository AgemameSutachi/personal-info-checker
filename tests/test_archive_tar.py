"""tar と単体圧縮（zstd・lz4）の展開の試験: pg_dump の tar 形式の列名・リンク・特別な項目・大きな項目・空きの不足・部品の無いとき。

tar は handle_tar、zstd・lz4 は handle_single_compressed を通る。名前・番号はすべて架空。
"""

from __future__ import annotations

import io
import sys
import tarfile

import pytest

from pii_checker import engine
from pii_checker.engine import Uncheckable, scan_file
from pii_checker.formats import archive
from pii_checker.models import ScanOptions, Status

CSV = "".join(f"{i},山田 太郎,090-1234-{i:04d}\n" for i in range(20)).encode()
DAT = "1\t山田 太郎\t090-1234-5678\n2\t佐藤 花子\t\\N\n\\.\n".encode()


def _toc(head: bytes = b"PGDMP") -> bytes:
    """pg_dump の toc.dat の代わり（読む側が見る並びだけ・tests/test_pg_toc.py と同じ形）。"""
    return (
        head
        + b"\x01\x0e\x00"
        + b"\x00" * 40
        + b"COPY public.members (id, name, phone) FROM stdin;\x00\x00\x083001.dat\x00"
    )


def _tar(members: list[tarfile.TarInfo | tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for m in members:
            if isinstance(m, tarfile.TarInfo):
                t.addfile(m)
                continue
            name, data = m
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _special(name: str, kind: bytes, linkname: str = "") -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = kind
    info.linkname = linkname
    return info


def _scan(tmp_path, name: str, data: bytes):
    p = tmp_path / name
    p.write_bytes(data)
    return scan_file(str(p), ScanOptions(temp_dir=str(tmp_path), reuse=False)).items


def _by_suffix(items, suffix: str):
    found = [it for it in items if it.path.endswith(suffix)]
    assert len(found) == 1, [it.path for it in items]
    return found[0]


def _phones(items) -> int:
    return sum(it.finding_counts.get("phone", 0) for it in items)


# ------------------------------------------------------------------ tar


def test_tar_pg_dump_uses_column_names_from_toc(tmp_path):
    """pg_dump の tar 形式（-Ft）: 先に toc.dat を読み、データファイルの場所を表と列の名前で示す。"""
    items = _scan(tmp_path, "dump.tar", _tar([("3001.dat", DAT), ("toc.dat", _toc())]))
    data = _by_suffix(items, "!3001.dat")
    locations = {f.location for f in data.findings}
    assert "表「public.members」1行目 列「phone」" in locations, locations


def test_tar_toc_without_pgdmp_head_is_ignored(tmp_path):
    """PGDMP で始まらない toc.dat は pg_dump のものとみなさない（列名を付けずにふつうの文字として検査する）。"""
    items = _scan(tmp_path, "dump.tar", _tar([("toc.dat", _toc(b"XXXXX")), ("3001.dat", DAT)]))
    data = _by_suffix(items, "!3001.dat")
    assert data.finding_counts.get("phone") == 1
    assert not any("public.members" in f.location for f in data.findings)


def test_tar_unreadable_toc_does_not_stop_the_scan(tmp_path, monkeypatch):
    """toc.dat の読み取りでつまずいても、書庫の検査は止めない（列名が付かないだけ）。"""
    from pii_checker.formats import dbdump

    def broken(_toc):
        raise ValueError("壊れた toc")

    monkeypatch.setattr(dbdump, "pg_toc_mapping", broken)
    items = _scan(tmp_path, "dump.tar", _tar([("toc.dat", _toc()), ("3001.dat", DAT)]))
    assert items[0].status == Status.SCANNED, items[0].reason
    data = _by_suffix(items, "!3001.dat")
    assert data.finding_counts.get("phone") == 1
    assert not any("public.members" in f.location for f in data.findings)


def test_tar_links_are_listed_as_out_of_scope(tmp_path):
    """記号リンク・ハードリンクは中身を持たないので、指す先を添えて対象外として残す（黙って捨てない）。"""
    data = _tar(
        [
            ("real.csv", CSV),
            _special("soft.csv", tarfile.SYMTYPE, "real.csv"),
            _special("hard.csv", tarfile.LNKTYPE, "real.csv"),
        ]
    )
    items = _scan(tmp_path, "links.tar", data)
    assert items[0].method == "tar を展開（1件）"
    for name in ("soft.csv", "hard.csv"):
        link = _by_suffix(items, f"!{name}")
        assert link.status == Status.OUT_OF_SCOPE
        assert link.reason == "リンク（real.csv を指す）のため中身なし"
        assert link.depth == 1
    assert _phones(items) == 20  # 本物の1件だけを数える（リンクの先を二重に数えない）


def test_tar_directories_and_device_entries_are_skipped(tmp_path):
    """フォルダ・名前付きパイプ・装置の項目は中身が無いので、結果に出さず件数にも入れない。"""
    data = _tar(
        [
            _special("dir", tarfile.DIRTYPE),
            _special("dir/pipe", tarfile.FIFOTYPE),
            _special("dir/tty", tarfile.CHRTYPE),
            _special("dir/disk", tarfile.BLKTYPE),
            ("dir/a.csv", CSV),
        ]
    )
    items = _scan(tmp_path, "special.tar", data)
    assert items[0].status == Status.SCANNED, items[0].reason
    assert items[0].method == "tar を展開（1件）"
    assert [it.path.rsplit("!", 1)[-1] for it in items[1:]] == ["dir/a.csv"]
    assert _phones(items) == 20


def test_tar_large_member_is_written_to_a_temp_file(tmp_path, monkeypatch):
    """大きな項目はメモリに読まず一時ファイルへ書き出して検査する（中身と更新日時は小さいときと同じに扱う）。"""
    monkeypatch.setattr(archive, "IN_MEMORY_LIMIT", 100)
    seen = []
    original = engine.ScanContext.scan_nested

    def spy(self, display, *a, **kw):
        seen.append((display, "path" in kw and kw["path"] is not None, kw.get("mtime")))
        return original(self, display, *a, **kw)

    monkeypatch.setattr(engine.ScanContext, "scan_nested", spy)
    info = tarfile.TarInfo("big.csv")
    info.size = len(CSV)
    info.mtime = 1_700_000_000
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        t.addfile(info, io.BytesIO(CSV))
        small = tarfile.TarInfo("small.txt")
        small.size = 5
        small.mtime = 1_600_000_000
        t.addfile(small, io.BytesIO(b"hello"))
    items = _scan(tmp_path, "big.tar", buf.getvalue())
    assert _phones(items) == 20
    assert [s[:2] for s in seen] == [
        (f"{tmp_path / 'big.tar'}!big.csv", True),
        (f"{tmp_path / 'big.tar'}!small.txt", False),
    ]
    assert [s[2] for s in seen] == [1_700_000_000, 1_600_000_000]


def test_tar_large_member_without_temp_space_is_left_with_reason(tmp_path, monkeypatch):
    """一時フォルダの空きが足りない大きな項目は、理由つきで検査不能として残し、残りの項目は検査を続ける。"""
    monkeypatch.setattr(archive, "IN_MEMORY_LIMIT", 100)

    def short(self, nbytes, what=""):
        raise Uncheckable(f"一時フォルダの空きが足りない（{nbytes} バイト）")

    monkeypatch.setattr(engine.ScanContext, "ensure_space", short)
    items = _scan(tmp_path, "big.tar", _tar([("big.csv", CSV), ("small.csv", b"1,090-1234-5678\n")]))
    big = _by_suffix(items, "!big.csv")
    assert big.status == Status.UNCHECKABLE
    assert big.reason == f"一時フォルダの空きが足りない（{len(CSV)} バイト）"
    assert big.size == len(CSV)
    assert _by_suffix(items, "!small.csv").finding_counts.get("phone") == 1
    assert items[0].method == "tar を展開（2件）"


# ------------------------------------------------------------------ zstd・lz4


def test_zstd_and_lz4_are_expanded_with_inner_name(tmp_path):
    zstandard = pytest.importorskip("zstandard")
    lz4_frame = pytest.importorskip("lz4.frame")
    for name, data in (
        ("list.csv.zst", zstandard.ZstdCompressor().compress(CSV)),
        ("list.csv.lz4", lz4_frame.compress(CSV)),
    ):
        items = _scan(tmp_path, name, data)
        assert items[0].status == Status.SCANNED, (name, items[0].reason)
        assert items[0].method == f"展開（{len(CSV):,}バイト）"
        assert items[1].path.endswith(f"{name}!list.csv")
        assert _phones(items) == 20


def test_zstd_frames_are_read_across(tmp_path):
    """続けて書かれた zstd のフレームも2つ目以降まで読む（read_across_frames）。"""
    zstandard = pytest.importorskip("zstandard")
    c = zstandard.ZstdCompressor()
    items = _scan(tmp_path, "two.csv.zst", c.compress(CSV) + c.compress(CSV))
    assert items[0].method == f"展開（{2 * len(CSV):,}バイト）"
    assert _phones(items) == 40


@pytest.mark.parametrize(
    "name,hidden,pip_name",
    [
        ("list.csv.zst", ("zstandard",), "zstandard"),
        ("list.csv.lz4", ("lz4", "lz4.frame"), "lz4"),
    ],
)
def test_missing_module_falls_back_to_7zip(tmp_path, monkeypatch, name, hidden, pip_name):
    """部品（zstandard・lz4）が入っていないときは 7-Zip で開き、それも駄目なら何を入れればよいかを示す。"""
    head = b"\x28\xb5\x2f\xfd" if name.endswith(".zst") else b"\x04\x22\x4d\x18"
    calls = []

    def fake_7z(ctx, blob, item, col, depth, kind=""):
        calls.append(kind)
        raise Uncheckable("7-Zip が見つからない")

    for mod in hidden:
        monkeypatch.setitem(sys.modules, mod, None)  # import すると ImportError になる
    monkeypatch.setattr(archive, "handle_with_7z_exe", fake_7z)
    items = _scan(tmp_path, name, head + b"\x00" * 60)
    assert calls == [name.rsplit(".", 1)[-1].replace("zst", "zstd")]
    assert items[0].status == Status.UNCHECKABLE
    assert f"pip install {pip_name}" in items[0].reason
    assert items[0].reason.endswith("7-Zip でも開けなかった: 7-Zip が見つからない")


def test_missing_module_uses_7zip_result_when_it_opens(tmp_path, monkeypatch):
    """7-Zip で開けたなら、部品が無いことは理由に出さない（7-Zip の結果をそのまま使う）。"""

    def fake_7z(ctx, blob, item, col, depth, kind=""):
        item.method = f"7-Zip で展開（{kind}）"

    monkeypatch.setitem(sys.modules, "zstandard", None)
    monkeypatch.setattr(archive, "handle_with_7z_exe", fake_7z)
    items = _scan(tmp_path, "list.csv.zst", b"\x28\xb5\x2f\xfd" + b"\x00" * 60)
    assert items[0].status == Status.SCANNED, items[0].reason
    assert items[0].method == "7-Zip で展開（zstd）"

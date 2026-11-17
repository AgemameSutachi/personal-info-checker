"""zip を Python で展開する道（handle_zip・scan_zip_entries・_zip_python_encrypted）の細かい分かれ道の試験。

名前の読み直しに失敗したとき・大きな項目・一時フォルダの空きの不足・PyTorch の判定で読めないとき・
項目の頭が壊れているとき・日付が壊れているとき・7-Zip が無い道で取り出せないとき、
あわせて 7-Zip が無いときの 7z（py7zr）と、配布物の中の 7z.exe を探す道を確かめる。名前・番号はすべて架空。
"""

from __future__ import annotations

import io
import sys
import zipfile
from types import SimpleNamespace

import pytest

from pii_checker import engine
from pii_checker.engine import Uncheckable, scan_file
from pii_checker.formats import archive
from pii_checker.models import ScanOptions, Status

CSV = "".join(f"{i},山田 太郎,090-1234-{i:04d}\n" for i in range(20)).encode()


def _zip(members: list[tuple[str | zipfile.ZipInfo, bytes]], method=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", method) as z:
        for name, data in members:
            z.writestr(name, data)
    return buf.getvalue()


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


@pytest.fixture
def no_7z(monkeypatch):
    """7-Zip が無い環境の代わり（手元に 7-Zip があっても Python の道を通す）。"""
    monkeypatch.setattr(archive, "find_7z", lambda configured: None)


def test_fix_zip_name_keeps_name_that_is_not_cp932():
    """UTF-8 の印が無い名前でも、cp932 として読めなければ元の名前のまま使う（文字化けした名前に変えない）。"""
    info = zipfile.ZipInfo("aü")  # cp437 で 61 81 → cp932 では 81 の後ろが欠けて読めない
    assert archive._fix_zip_name(info) == "aü"
    info = zipfile.ZipInfo("名簿")  # cp437 に無い文字（書き手は UTF-8 の印を立てるが、ここでは印を外して試す）
    info.flag_bits = 0
    assert archive._fix_zip_name(info) == "名簿"


def test_large_member_is_written_to_a_temp_file(tmp_path, monkeypatch):
    """大きな項目はメモリに読まず一時ファイルへ書き出して検査する（見つかるものは小さいときと同じ）。"""
    monkeypatch.setattr(archive, "IN_MEMORY_LIMIT", 100)
    seen = []
    original = engine.ScanContext.scan_nested

    def spy(self, display, **kw):
        seen.append((display, "path" in kw and kw["path"] is not None))
        return original(self, display, **kw)

    monkeypatch.setattr(engine.ScanContext, "scan_nested", spy)
    items = _scan(tmp_path, "big.zip", _zip([("big.csv", CSV), ("small.csv", b"1,090-1234-5678\n")]))
    assert any(d.endswith("!big.csv") and by_path for d, by_path in seen), seen
    assert any(d.endswith("!small.csv") and not by_path for d, by_path in seen), seen
    assert _by_suffix(items, "!big.csv").finding_counts.get("phone") == 20
    assert _phones(items) == 21


def test_large_member_without_temp_space_stops_the_zip(tmp_path, monkeypatch):
    """一時フォルダの空きが足りないときは、項目の失敗にせず zip ごと検査不能にする（空きを作って再検査する話なので）。"""
    monkeypatch.setattr(archive, "IN_MEMORY_LIMIT", 100)

    def short(self, nbytes, what=""):
        raise Uncheckable(f"一時フォルダの空きが足りない（{nbytes} バイト）")

    monkeypatch.setattr(engine.ScanContext, "ensure_space", short)
    items = _scan(tmp_path, "big.zip", _zip([("big.csv", CSV)]))
    top = items[0]
    assert top.status == Status.UNCHECKABLE
    assert "一時フォルダの空きが足りない" in top.reason
    assert not [it for it in items if it.path.endswith("!big.csv")]


def _torch_zip() -> bytes:
    return _zip(
        [
            ("model/data.pkl", b"\x80\x02}q\x00."),
            ("model/version", b"3\n"),
            ("model/data/0", CSV),
        ],
        method=zipfile.ZIP_STORED,
    )


def test_torch_tensors_are_out_of_scope(tmp_path):
    """陽性対照: torch.save の zip の数の本体は対象外になる（下の読めないときの試験と見比べる）。"""
    items = _scan(tmp_path, "model.pt", _torch_zip())
    assert _by_suffix(items, "!model/data/0").status == Status.OUT_OF_SCOPE


def test_torch_check_unreadable_pickle_scans_normally(tmp_path, monkeypatch):
    """torch の印の data.pkl が読めなければ torch とみなさず、data/0 もふつうに検査する（見落としの側に倒さない）。"""
    original = archive._open_zip_member

    def flaky(z, info, pwd):
        if info.filename.endswith("data.pkl"):
            raise OSError("読めない")
        return original(z, info, pwd)

    monkeypatch.setattr(archive, "_open_zip_member", flaky)
    items = _scan(tmp_path, "model.pt", _torch_zip())
    tensor = _by_suffix(items, "!model/data/0")
    assert tensor.status != Status.OUT_OF_SCOPE
    assert tensor.finding_counts.get("phone") == 20


def _break_local_header(data: bytes, nth: int) -> bytes:
    """nth 番目（0から）の項目の頭の印（PK\\x03\\x04）を壊す。目次はそのまま。"""
    pos = -1
    for _ in range(nth + 1):
        pos = data.index(b"PK\x03\x04", pos + 1)
    return data[:pos] + b"XX\x03\x04" + data[pos + 4 :]


def test_broken_member_header_is_left_with_reason(tmp_path):
    """項目の頭が壊れていれば（名前の区切り違いとは別の壊れ）、その項目だけ理由つきで残し、ほかは検査する。"""
    data = _break_local_header(_zip([("a.csv", b"1,090-1234-5678\n"), ("b.csv", CSV)]), 1)
    items = _scan(tmp_path, "x.zip", data)
    broken = _by_suffix(items, "!b.csv")
    assert broken.status == Status.UNCHECKABLE
    assert "zip から取り出せなかった" in broken.reason and "BadZipFile" in broken.reason
    assert _by_suffix(items, "!a.csv").finding_counts.get("phone") == 1


def test_open_member_reraises_other_error_after_separator_retry():
    """区切りを入れ替えて開き直したときに別の壊れが出たら、それをそのまま上げる（区切り違いとして飲み込まない）。"""
    calls = []

    def open_(info, pwd=None):
        calls.append(info.orig_filename)
        if len(calls) == 1:
            raise zipfile.BadZipFile("File name in directory 'a\\\\b' and header b'a/b' differ.")
        raise zipfile.BadZipFile("Bad magic number for file header")

    info = zipfile.ZipInfo("a\\b")
    with pytest.raises(zipfile.BadZipFile, match="Bad magic"):
        archive._open_zip_member(SimpleNamespace(open=open_), info, None)
    assert calls == ["a\\b", "a/b"]


def test_open_member_reraises_non_separator_error_at_once():
    def open_(info, pwd=None):
        raise zipfile.BadZipFile("Bad magic number for file header")

    with pytest.raises(zipfile.BadZipFile, match="Bad magic"):
        archive._open_zip_member(SimpleNamespace(open=open_), zipfile.ZipInfo("a/b"), None)


def test_broken_member_date_is_ignored(tmp_path):
    """項目の日付が暦に無い値（月 0 など）でも、日付を付けないだけで中身は検査する。"""
    info = zipfile.ZipInfo("a.csv", date_time=(1980, 0, 0, 0, 0, 0))
    items = _scan(tmp_path, "x.zip", _zip([(info, CSV)]))
    assert _by_suffix(items, "!a.csv").finding_counts.get("phone") == 20


def test_without_7z_broken_plain_member_is_left_with_reason(tmp_path, monkeypatch, no_7z):
    """7-Zip が無い道（暗号化・未対応の方式を含む zip）でも、壊れた平文の項目は理由つきで残し、ほかへ進む。"""
    monkeypatch.setattr(archive, "SUPPORTED_ZIP_METHODS", {zipfile.ZIP_STORED})
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("ok.csv", b"1,090-1234-5678\n", compress_type=zipfile.ZIP_STORED)
        z.writestr("broken.csv", CSV, compress_type=zipfile.ZIP_STORED)
        z.writestr("deflated.csv", CSV, compress_type=zipfile.ZIP_DEFLATED)
    items = _scan(tmp_path, "x.zip", _break_local_header(buf.getvalue(), 1))
    assert "7-Zip なし" in items[0].method
    broken = _by_suffix(items, "!broken.csv")
    assert broken.status == Status.UNCHECKABLE and "zip から取り出せなかった" in broken.reason
    unsupported = _by_suffix(items, "!deflated.csv")
    assert unsupported.status == Status.UNCHECKABLE and "7-Zip が無いと展開できない" in unsupported.reason
    assert _by_suffix(items, "!ok.csv").finding_counts.get("phone") == 1


def test_7z_without_7zip_uses_py7zr(tmp_path, no_7z):
    py7zr = pytest.importorskip("py7zr")
    p = tmp_path / "a.7z"
    with py7zr.SevenZipFile(p, "w") as z:
        z.writestr(CSV, "list.csv")
    items = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path), reuse=False)).items
    assert "py7zr で展開" in items[0].method
    assert _by_suffix(items, "!list.csv").finding_counts.get("phone") == 20


def test_find_7z_looks_inside_the_bundle(tmp_path, monkeypatch):
    """配布物（PyInstaller の展開先 _MEIPASS）の中の 7z.exe を、Program Files より先に見つける。"""
    bundle = tmp_path / "bundle"
    (bundle / "7z").mkdir(parents=True)
    (bundle / "7z" / "7z.exe").write_bytes(b"")
    exe_dir = tmp_path / "exe"
    exe_dir.mkdir()
    monkeypatch.setattr(sys, "executable", str(exe_dir / "python.exe"))
    monkeypatch.setattr(sys, "_MEIPASS", str(bundle), raising=False)
    assert archive.find_7z(None) == str(bundle / "7z" / "7z.exe")

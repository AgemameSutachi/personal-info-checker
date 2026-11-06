"""数の配列（numpy の .npy・PyTorch のモデル）の試験。

実物の F の検査で、.npy 628 件と PyTorch の zip の中の data/N 334 件が「形式不明で、圧縮または暗号化されている」の
検査不能になっていた。数の配列は対象外、文字の配列は中を検査する。
"""

from __future__ import annotations

import os
import struct
import zipfile

from pii_checker import engine
from pii_checker.models import ScanOptions, Status


def _npy(descr: str, shape: tuple, data: bytes, major: int = 1) -> bytes:
    """numpy を使わずに .npy を組む（頭は 64 バイト境界にそろえる・numpy と同じ形）。"""
    header = repr({"descr": descr, "fortran_order": False, "shape": shape}).encode("latin1")
    pre = 10 if major == 1 else 12
    pad = (-(pre + len(header) + 1)) % 64
    header = header + b" " * pad + b"\n"
    size = struct.pack("<H", len(header)) if major == 1 else struct.pack("<I", len(header))
    return b"\x93NUMPY" + bytes([major, 0]) + size + header + data


def _scan(tmp_path, p):
    return engine.scan_file(str(p), ScanOptions(temp_dir=str(tmp_path)))


def _types(res):
    return {k for it in res.items for k in it.finding_counts}


def test_float_array_is_out_of_scope(tmp_path):
    p = tmp_path / "w.npy"
    p.write_bytes(_npy("<f4", (256, 64), os.urandom(256 * 64 * 4)))
    res = _scan(tmp_path, p)
    top = res.items[0]
    assert top.status == Status.OUT_OF_SCOPE, (top.status, top.reason)
    assert "<f4" in top.reason and "(256, 64)" in top.reason


def test_unicode_array_is_scanned(tmp_path):
    words = ["山田太郎", "090-1234-5678", "taro@example.com"]
    data = b"".join(w.ljust(16, "\x00").encode("utf-32-le") for w in words)
    p = tmp_path / "names.npy"
    p.write_bytes(_npy("<U16", (3,), data, major=2))
    res = _scan(tmp_path, p)
    top = res.items[0]
    assert top.status == Status.SCANNED, (top.status, top.reason)
    assert {"phone", "email"} <= _types(res)
    assert "3件" in top.method


def test_bytes_array_is_scanned(tmp_path):
    words = ["090-1234-5678".encode("utf-8"), "東京都千代田区丸の内9-9-9".encode("cp932")]
    data = b"".join(w.ljust(40, b"\x00") for w in words)
    p = tmp_path / "b.npy"
    p.write_bytes(_npy("|S40", (2,), data))
    res = _scan(tmp_path, p)
    assert res.items[0].status == Status.SCANNED
    assert "phone" in _types(res)


def test_npz_members_are_handled(tmp_path):
    """.npz（.npy を入れた zip）も中の .npy ごとに同じ扱い。"""
    p = tmp_path / "a.npz"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("w.npy", _npy("<i8", (100,), os.urandom(800)))
        z.writestr("s.npy", _npy("<U16", (1,), "090-1234-5678".ljust(16, "\x00").encode("utf-32-le")))
    res = _scan(tmp_path, p)
    by = {it.path.rsplit("!", 1)[-1]: it for it in res.items}
    assert by["w.npy"].status == Status.OUT_OF_SCOPE
    assert by["s.npy"].status == Status.SCANNED and "phone" in by["s.npy"].finding_counts


def test_object_array_falls_back_to_raw_sweep(tmp_path):
    """object（pickle）の配列は型が分からないので、今までどおり生データ走査（簡易検査）。"""
    p = tmp_path / "o.npy"
    p.write_bytes(_npy("|O", (1,), b"\x80\x04\x95X\x00\x00\x00 090-1234-5678 \x00" * 4))
    res = _scan(tmp_path, p)
    assert res.items[0].status == Status.PARTIAL, (res.items[0].status, res.items[0].reason)
    assert "phone" in _types(res)


def test_broken_header_falls_back(tmp_path):
    p = tmp_path / "x.npy"
    p.write_bytes(b"\x93NUMPY\x01\x00\x20\x00{'descr': <<broken" + b"a" * 100)
    res = _scan(tmp_path, p)
    assert res.items[0].status in (Status.PARTIAL, Status.UNCHECKABLE)


def test_torch_zip_tensors_are_out_of_scope(tmp_path):
    """torch.save の zip の data/<番号>（テンソルの数）は対象外。data.pkl などほかの項目は検査する。"""
    p = tmp_path / "adapter_model.bin"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("adapter_model/data.pkl", b"\x80\x02 layer.weight 090-1234-5678 " * 3)
        z.writestr("adapter_model/version", b"3\n")
        for i in range(3):
            z.writestr(f"adapter_model/data/{i}", os.urandom(64 * 1024))
    res = _scan(tmp_path, p)
    by = {it.path.rsplit("!", 1)[-1]: it for it in res.items}
    for i in range(3):
        assert by[f"adapter_model/data/{i}"].status == Status.OUT_OF_SCOPE
        assert "PyTorch" in by[f"adapter_model/data/{i}"].reason
    assert by["adapter_model/data.pkl"].status != Status.OUT_OF_SCOPE
    assert "phone" in by["adapter_model/data.pkl"].finding_counts


def test_plain_zip_named_data_is_not_torch(tmp_path):
    """data.pkl の無い zip の data/1 は、ふつうに検査する（名前だけで対象外にしない）。"""
    p = tmp_path / "plain.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("data/1", "電話 090-1234-5678\n".encode("utf-8"))
    res = _scan(tmp_path, p)
    by = {it.path.rsplit("!", 1)[-1]: it for it in res.items}
    assert by["data/1"].status != Status.OUT_OF_SCOPE
    assert "phone" in by["data/1"].finding_counts

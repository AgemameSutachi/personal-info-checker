"""ar 形式（リンク用のライブラリ .lib・.a と deb）の扱い。"""

from __future__ import annotations

import struct

from pii_checker import engine
from pii_checker.formats import archive
from pii_checker.models import ScanOptions, Status


def _member(name: str, body: bytes, date: str = "1700000000") -> bytes:
    """ar の項目1つ（60 バイトの頭＋中身・奇数の長さは1バイト詰める）。"""
    hdr = f"{name:<16}{date:<12}{'':<6}{'':<6}{'0':<8}{len(body):<10}".encode("ascii") + b"`\n"
    assert len(hdr) == 60
    return hdr + body + (b"\n" if len(body) % 2 else b"")


def _import_stub(symbol: str, dll: str) -> bytes:
    """Windows のインポートの欠片（Sig1=0・Sig2=0xFFFF の頭＋記号の名前＋DLL の名前）。"""
    names = symbol.encode("ascii") + b"\x00" + dll.encode("ascii") + b"\x00"
    return struct.pack("<HHHHIIHH", 0, 0xFFFF, 0, 0x8664, 0, len(names), 0, 0) + names


def _coff(text: bytes) -> bytes:
    """x64 の COFF のオブジェクト（頭の 20 バイトの後ろに文字を置いただけのもの）。"""
    return struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0, 0) + text


def _write_lib(path, members: list[bytes]) -> None:
    path.write_bytes(b"!<arch>\n" + b"".join(members))


def test_import_library_is_read_once_without_7zip(tmp_path, monkeypatch):
    # 関数ごとに同じ名前（jvm.dll）の項目が並ぶインポートライブラリ。7-Zip で開くと 1.jvm.dll〜 の欠片を1件ずつ検査していた
    lib = tmp_path / "jvm.lib"
    members = [_member("/", b"\x00\x00\x00\x00")]
    members += [_member("jvm.dll/", _import_stub(f"JVM_Func{i}", "jvm.dll")) for i in range(50)]
    members.append(_member("note.obj/", _coff(b"\x00contact taro.yamada@example.com\x00")))
    _write_lib(lib, members)
    calls = []
    monkeypatch.setattr(archive, "handle_with_7z_exe", lambda *a, **k: calls.append(a))
    res = engine.scan_file(str(lib), ScanOptions(temp_dir=str(tmp_path), reuse=False))
    assert calls == []
    assert len(res.items) == 1  # 欠片を項目として数えない
    item = res.items[0]
    assert item.kind == archive.AR_LIBRARY_KIND
    assert item.status == Status.PARTIAL
    assert [f for f in item.findings if f.pii_type == "email"]


def test_library_member_headers_are_not_read(tmp_path):
    # 項目の頭（名前・日時・大きさの欄）は今まで読んでいなかった。頭を読むと、そこの数字を電話番号などと拾いうる
    lib = tmp_path / "x.lib"
    _write_lib(lib, [_member("090-1234-5678/", _coff(b"\x00hello\x00"))])
    res = engine.scan_file(str(lib), ScanOptions(temp_dir=str(tmp_path), reuse=False))
    item = res.items[0]
    assert item.kind == archive.AR_LIBRARY_KIND
    assert item.findings == []
    # 陽性対照: 同じ数字を中身に置けば拾う（頭を読まないことで消えたのであって、数字が拾われない形だからではない）
    _write_lib(lib, [_member("a.obj/", _coff(b"\x00TEL 090-1234-5678\x00"))])
    res = engine.scan_file(str(lib), ScanOptions(temp_dir=str(tmp_path), reuse=False))
    assert [f for f in res.items[0].findings if f.pii_type == "phone"]


def test_ar_with_other_members_still_uses_7zip(tmp_path, monkeypatch):
    # deb は ar の中に debian-binary（文字）と圧縮した tar を持つ。中を開かないと読めないので、今までどおり 7-Zip へ
    deb = tmp_path / "pkg.deb"
    _write_lib(deb, [_member("debian-binary", b"2.0\n"), _member("control.tar.xz", b"\xfd7zXZ\x00" + b"\x00" * 20)])
    calls = []
    monkeypatch.setattr(archive, "handle_with_7z_exe", lambda *a, **k: calls.append(a))
    engine.scan_file(str(deb), ScanOptions(temp_dir=str(tmp_path), reuse=False))
    assert len(calls) == 1


def test_ar_mixing_objects_and_other_members_uses_7zip(tmp_path, monkeypatch):
    # 部品の後ろに部品でない項目が1つでもあれば、中を開かないと読めないので 7-Zip へ
    lib = tmp_path / "mixed.a"
    _write_lib(lib, [_member("a.o/", _coff(b"abc")), _member("readme.txt/", b"hello world\n")])
    calls = []
    monkeypatch.setattr(archive, "handle_with_7z_exe", lambda *a, **k: calls.append(a))
    engine.scan_file(str(lib), ScanOptions(temp_dir=str(tmp_path), reuse=False))
    assert len(calls) == 1


def test_elf_members_are_not_read_like_executables(tmp_path):
    # ELF の部品は単体なら「実行ファイル」として対象外。ライブラリの中でも今までどおり中身を読まない
    elf = b"\x7fELF\x02\x01\x01" + b"\x00" * 13 + b"\x00TEL 090-1234-5678\x00"
    lib = tmp_path / "libx.a"
    _write_lib(lib, [_member("/", b"\x00\x00\x00\x00"), _member("x.o/", elf)])
    res = engine.scan_file(str(lib), ScanOptions(temp_dir=str(tmp_path), reuse=False))
    item = res.items[0]
    assert item.kind == archive.AR_LIBRARY_KIND
    assert not [f for f in item.findings if f.pii_type == "phone"]
    assert any("ELF の部品 1 個" in n for n in item.notes)
    # 陽性対照: 同じ文字を COFF の部品に置けば拾う
    _write_lib(lib, [_member("/", b"\x00\x00\x00\x00"), _member("x.obj/", _coff(b"\x00TEL 090-1234-5678\x00"))])
    res = engine.scan_file(str(lib), ScanOptions(temp_dir=str(tmp_path), reuse=False))
    assert [f for f in res.items[0].findings if f.pii_type == "phone"]


def test_ar_object_spans_reads_bsd_long_names_and_padding():
    import io

    # BSD の長い名前（#1/長さ）は中身の頭にあり、名前の部分も読まない範囲に入る。奇数長の項目は1バイト詰める
    name = b"a_long_object_name.o".ljust(24, b"\x00")
    body = name + _coff(b"x")  # 合計の長さは奇数
    data = b"!<arch>\n" + _member(f"#1/{len(name)}", body) + _member("b.o/", _coff(b"yz"))
    spans, elf = archive.ar_object_spans(io.BytesIO(data))
    assert elf == 0
    assert spans[1] == (8, 8 + 60 + len(name))
    second = 8 + 60 + len(body) + 1
    assert spans[2] == (second, second + 60)


def test_ar_object_spans_rejects_broken_headers():
    import io

    good = b"!<arch>\n" + _member("a.obj/", _coff(b"abc"))
    assert archive.ar_object_spans(io.BytesIO(good)) is not None
    broken = good[:8] + good[8:66].replace(b"`\n", b"xx") + good[68:]
    assert archive.ar_object_spans(io.BytesIO(broken)) is None
    assert archive.ar_object_spans(io.BytesIO(b"!<arch>\n")) is None  # 項目が無い
    assert archive.ar_object_spans(io.BytesIO(b"!<arch>\n" + _member("/", b"\x00\x00"))) is None  # 目次だけ
    # 大きさの欄が負の目次は、前へ戻って同じ所を読み続けていた（終わらない）
    neg = f"{'/':<16}{'0':<12}{'':<6}{'':<6}{'0':<8}{'-60':<10}".encode("ascii") + b"`\n"
    assert archive.ar_object_spans(io.BytesIO(b"!<arch>\n" + neg + good[8:])) is None
    # BSD の名前の長さが負・中身より長い
    assert archive.ar_object_spans(io.BytesIO(b"!<arch>\n" + _member("#1/-5", _coff(b"abc")))) is None
    assert archive.ar_object_spans(io.BytesIO(b"!<arch>\n" + _member("#1/999", _coff(b"abc")))) is None


def test_masked_reader_blanks_only_given_spans():
    import io

    data = bytes(range(32))
    r = archive.MaskedReader(io.BytesIO(data), [(2, 5), (10, 20)])
    got = r.read(7) + r.read(100)
    assert got[:2] == data[:2]
    assert got[2:5] == b"\x00" * 3
    assert got[5:10] == data[5:10]
    assert got[10:20] == b"\x00" * 10
    assert got[20:] == data[20:]
    # 小刻みに読んで範囲が読みの境目をまたいでも同じになる
    for step in (1, 3, 4):
        r = archive.MaskedReader(io.BytesIO(data), [(2, 5), (10, 20)])
        parts = []
        while chunk := r.read(step):
            parts.append(chunk)
        assert b"".join(parts) == got

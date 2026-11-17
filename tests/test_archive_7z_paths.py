"""7-Zip（7z.exe）で一覧を取って展開する経路（handle_with_7z_exe）の分かれ道の試験。

本物の 7-Zip は CI に有る保証が無く、壊れ方や暗号化の組み合わせもファイルでは作りにくいので、
_run_7z を差し替えて 7-Zip の出力を手で与える。ScanContext も要る分だけの代わりを使う。
あわせて、ディスクイメージを 7-Zip で開けないときの生データ走査への逃げ道と、7-Zip が無いときの py7zr の道も確かめる。
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pii_checker.engine import NeedPassword, PartialScan, Uncheckable  # noqa: E402
from pii_checker.formats import archive  # noqa: E402
from pii_checker.models import Status  # noqa: E402

LIST_HEAD = "7-Zip 24.08\n\nListing archive: a.7z\n\n--\nPath = a.7z\nType = 7z\n\n----------\n"


def _listing(*entries: dict) -> str:
    """7z l -slt の出力の形（区切りの下に項目を空行で並べる）。"""
    body = "\n\n".join("\n".join(f"{k} = {v}" for k, v in e.items()) for e in entries)
    return LIST_HEAD + body + "\n"


class _Fake7z:
    """_run_7z の代わり。一覧（l）と展開（x）のそれぞれの応答を、渡されたパスワードで選ぶ。

    list_replies: パスワード → (終了コード, 出力)。無いパスワードは「パスワードが違う」。
    extract: パスワード → {名前: 中身}。書き出す名前と、出力に足す行（errors）を返す。
    """

    def __init__(self, list_replies: dict, extract: dict | None = None, extract_errors: dict | None = None):
        self.list_replies = list_replies
        self.extract = extract or {}
        self.extract_errors = extract_errors or {}
        self.calls: list[tuple[str, str]] = []

    def __call__(self, exe, args, timeout=3600):
        pw = next(a[2:] for a in args if a.startswith("-p"))
        self.calls.append((args[0], pw))
        if args[0] == "l":
            code, out = self.list_replies.get(pw, (2, "ERROR: Wrong password : a.7z"))
            return subprocess.CompletedProcess(args, code, out.encode("utf-8"), b"")
        outdir = next(a[2:] for a in args if a.startswith("-o"))
        listfile = next(a[1:] for a in args if a.startswith("@"))
        wanted = Path(listfile).read_text(encoding="utf-8").splitlines()
        for name, body in self.extract.get(pw, {}).items():
            if name in wanted:
                Path(outdir, name).parent.mkdir(parents=True, exist_ok=True)
                Path(outdir, name).write_bytes(body)
        err = self.extract_errors.get(pw, "")
        return subprocess.CompletedProcess(args, 2 if err else 0, b"", err.encode("utf-8"))


def _ctx(tmp_path, *, passwords=(), batch_bytes=1 << 30, archive_bytes=b"x" * 600):
    """handle_with_7z_exe が使う分だけの ScanContext の代わり。scanned に検査へ回した名前が入る。"""
    arc = tmp_path / "a.7z"
    arc.write_bytes(archive_bytes)
    counter = iter(range(1000))

    def new_tmp_subdir():
        d = tmp_path / f"out{next(counter)}"
        d.mkdir()
        return str(d)

    scanned: list[str] = []
    ctx = SimpleNamespace(
        options=SimpleNamespace(
            sevenzip=None, extract_batch_bytes=batch_bytes, max_expand_bytes=1 << 40, max_expand_ratio=1000
        ),
        expanded_bytes=0,
        tmpdir=str(tmp_path),
        items=[],
        blob_as_path=lambda blob: str(arc),
        password_candidates=lambda: list(passwords),
        password_reason=lambda what: f"{what}（パスワードの試し）",
        new_tmp_subdir=new_tmp_subdir,
        scan_nested=lambda display, **kw: scanned.append(display),
    )
    ctx.scanned = scanned
    return ctx


def _run(ctx, monkeypatch, fake, kind="7z"):
    monkeypatch.setattr(archive, "find_7z", lambda configured: "7z.exe")
    monkeypatch.setattr(archive, "_run_7z", fake)
    item = SimpleNamespace(method="", notes=[], kind="7z")
    blob = SimpleNamespace(display="a.7z", head=lambda n: b"")
    archive.handle_with_7z_exe(ctx, blob, item, None, 0, kind=kind)
    return item


NO_PW = archive.NO_PASSWORD


def test_plain_entries_are_extracted_and_scanned(tmp_path, monkeypatch):
    """暗号化の無い書庫は一覧の名前を全部展開し、フォルダの項目は除いて検査へ回す。"""
    out = _listing(
        {"Path": "docs", "Folder": "+", "Size": "0"},
        {"Path": "docs\\a.txt", "Size": "4"},
        {"Path": "b.txt", "Size": "4"},
    )
    fake = _Fake7z({NO_PW: (0, out)}, extract={NO_PW: {"docs\\a.txt": b"aaaa", "b.txt": b"bbbb"}})
    ctx = _ctx(tmp_path)
    item = _run(ctx, monkeypatch, fake)
    assert sorted(ctx.scanned) == ["a.7z!b.txt", "a.7z!docs\\a.txt"], ctx.scanned
    assert item.method == "7-Zip で展開（2件・暗号化 0件）", item.method
    assert ctx.items == []


def test_zip_kind_passes_codepage(tmp_path, monkeypatch):
    """zip のときは名前を cp932 で読むよう -mcp=932 を渡す（7z のときは渡さない）。"""
    seen: list[list[str]] = []
    out = _listing({"Path": "a.txt", "Size": "1"})
    fake = _Fake7z({NO_PW: (0, out)}, extract={NO_PW: {"a.txt": b"a"}})

    def spy(exe, args, timeout=3600):
        seen.append(args)
        return fake(exe, args, timeout)

    (tmp_path / "zip").mkdir()
    (tmp_path / "7z").mkdir()
    _run(_ctx(tmp_path / "zip"), monkeypatch, spy, kind="zip")
    assert seen and all("-mcp=932" in a for a in seen), seen
    seen.clear()
    _run(_ctx(tmp_path / "7z"), monkeypatch, spy, kind="7z")
    assert seen and not any("-mcp=932" in a for a in seen), seen


def test_header_encrypted_listing_opens_with_candidate(tmp_path, monkeypatch):
    """一覧自体が暗号化されていれば候補で一覧を取り、そのパスワードで展開を始める。"""
    out = _listing({"Path": "a.txt", "Size": "3", "Encrypted": "+"})
    fake = _Fake7z({"secret": (0, out)}, extract={"secret": {"a.txt": b"abc"}})
    ctx = _ctx(tmp_path, passwords=["wrong", "secret"])
    _run(ctx, monkeypatch, fake)
    assert ctx.scanned == ["a.7z!a.txt"], ctx.scanned
    # 一覧は なし → wrong → secret の順に試し、展開は最初から secret で打つ（ほかのパスワードで無駄に展開しない）
    assert fake.calls == [("l", NO_PW), ("l", "wrong"), ("l", "secret"), ("x", "secret")], fake.calls


def test_header_encrypted_listing_without_password(tmp_path, monkeypatch):
    """一覧が暗号化されていて候補のどれでも開けなければ、要パスワードにする。"""
    fake = _Fake7z({})
    ctx = _ctx(tmp_path, passwords=["wrong"])
    with pytest.raises(NeedPassword) as e:
        _run(ctx, monkeypatch, fake)
    assert e.value.kind == "archive"
    assert str(e.value).startswith("アーカイブの一覧自体が暗号化されている"), str(e.value)


def test_unopenable_listing_is_broken_archive(tmp_path, monkeypatch):
    """パスワードの問題でなく一覧を取れなければ、壊れた書庫として理由を出し、パスは技術情報から除く。"""
    arc = str(tmp_path / "a.7z")
    fake = _Fake7z({NO_PW: (2, f"ERROR: {arc}\nCan not open the file as archive\nIs not archive")})
    ctx = _ctx(tmp_path, passwords=["p"])
    item = SimpleNamespace(method="", notes=[], kind="7z")
    monkeypatch.setattr(archive, "find_7z", lambda configured: "7z.exe")
    monkeypatch.setattr(archive, "_run_7z", fake)
    with pytest.raises(Uncheckable) as e:
        archive.handle_with_7z_exe(ctx, SimpleNamespace(display="a.7z"), item, None, 0)
    assert "7-Zip でも開けなかった" in str(e.value), str(e.value)
    assert fake.calls == [("l", NO_PW)], fake.calls  # 壊れていればパスワードを変えて試さない
    assert item.notes and arc not in item.notes[0], item.notes


def test_truncated_listing_scans_what_was_read(tmp_path, monkeypatch):
    """一覧は取れたが途中で切れている書庫は、読めた分を検査してから簡易検査にする。"""
    out = _listing({"Path": "a.txt", "Size": "1"}) + "\nERRORS:\nUnexpected end of archive\n"
    fake = _Fake7z({NO_PW: (2, out)}, extract={NO_PW: {"a.txt": b"a"}})
    ctx = _ctx(tmp_path)
    item = SimpleNamespace(method="", notes=[], kind="7z")
    monkeypatch.setattr(archive, "find_7z", lambda configured: "7z.exe")
    monkeypatch.setattr(archive, "_run_7z", fake)
    with pytest.raises(PartialScan) as e:
        archive.handle_with_7z_exe(ctx, SimpleNamespace(display="a.7z"), item, None, 0)
    assert ctx.scanned == ["a.7z!a.txt"], ctx.scanned
    assert str(e.value).startswith("アーカイブが途中で切れているか壊れている（読めた分だけ検査した。"), str(e.value)
    assert any(n.startswith("7-Zip の出力（技術情報）: ") and "Unexpected end" in n for n in item.notes), item.notes


def test_empty_listing_small_file_is_empty_archive(tmp_path, monkeypatch):
    """中身の無い小さな書庫は「空のアーカイブ」として通す。"""
    fake = _Fake7z({NO_PW: (0, _listing({"Path": "d", "Folder": "+"}))})
    ctx = _ctx(tmp_path, archive_bytes=b"7z" + b"\x00" * 30)
    item = _run(ctx, monkeypatch, fake)
    assert item.method == "空のアーカイブ"


def test_empty_listing_large_file_is_uncheckable(tmp_path, monkeypatch):
    """大きな書庫なのに一覧が空なら、取り出せていないので検査不能にする（空と言い切らない）。"""
    fake = _Fake7z({NO_PW: (0, LIST_HEAD)})
    ctx = _ctx(tmp_path, archive_bytes=b"x" * 513)
    with pytest.raises(Uncheckable) as e:
        _run(ctx, monkeypatch, fake)
    assert "中身が1件も無い" in str(e.value), str(e.value)


def test_nameless_entry_extracts_everything(tmp_path, monkeypatch):
    """名前の無い項目がある形式は、丸ごと展開する道（_extract_all_and_scan）へ回す。"""
    calls = []
    monkeypatch.setattr(archive, "_extract_all_and_scan", lambda *a: calls.append(a[-1]))
    fake = _Fake7z({"pw": (0, _listing({"Size": "10"}))})
    _run(_ctx(tmp_path, passwords=["pw"]), monkeypatch, fake)
    assert calls == ["pw"], calls  # 一覧を開いたパスワードを渡す


def test_encrypted_entry_tries_candidates_until_extracted(tmp_path, monkeypatch):
    """暗号化された項目は候補を順に試し、開けたものを検査する。暗号化の無い項目は最初の1回で取り出す。"""
    out = _listing({"Path": "plain.txt", "Size": "1"}, {"Path": "enc.txt", "Size": "1", "Encrypted": "+"})
    fake = _Fake7z(
        {NO_PW: (0, out)},
        extract={NO_PW: {"plain.txt": b"p"}, "right": {"enc.txt": b"e"}},
        extract_errors={NO_PW: "ERROR: Wrong password : enc.txt", "wrong": "ERROR: Wrong password : enc.txt"},
    )
    ctx = _ctx(tmp_path, passwords=["wrong", "right"])
    item = _run(ctx, monkeypatch, fake)
    assert sorted(ctx.scanned) == ["a.7z!enc.txt", "a.7z!plain.txt"], ctx.scanned
    assert [c for c in fake.calls if c[0] == "x"] == [("x", NO_PW), ("x", "wrong"), ("x", "right")], fake.calls
    assert item.method == "7-Zip で展開（2件・暗号化 1件）"
    assert ctx.items == []


def test_encrypted_entry_without_matching_password(tmp_path, monkeypatch):
    """どの候補でも開けない暗号化の項目は、要パスワードとして結果に残す（黙って捨てない）。"""
    out = _listing({"Path": "enc.txt", "Size": "7", "Encrypted": "+"})
    err = "ERROR: Wrong password : enc.txt"
    fake = _Fake7z({NO_PW: (0, out)}, extract_errors={NO_PW: err, "a": err})
    ctx = _ctx(tmp_path, passwords=["a"])
    _run(ctx, monkeypatch, fake)
    assert ctx.scanned == []
    [failed] = ctx.items
    assert failed.path == "a.7z!enc.txt" and failed.status == Status.NEEDS_PASSWORD
    assert failed.password_kind == "archive" and failed.size == 7
    assert failed.reason == "暗号化されている（パスワードの試し）"


def test_broken_plain_entry_is_not_retried_with_passwords(tmp_path, monkeypatch):
    """暗号化でないのに取り出せない項目は、パスワードを変えても無駄なので1回で諦め、7-Zip の理由を残す。"""
    out = _listing({"Path": "bad.txt", "Size": "5"})
    fake = _Fake7z({NO_PW: (0, out)}, extract_errors={NO_PW: "ERROR: CRC Failed : bad.txt"})
    ctx = _ctx(tmp_path, passwords=["a", "b"])
    _run(ctx, monkeypatch, fake)
    assert [c for c in fake.calls if c[0] == "x"] == [("x", NO_PW)], fake.calls
    [failed] = ctx.items
    assert failed.status == Status.UNCHECKABLE
    assert failed.reason == "展開できなかった（ERROR: CRC Failed : bad.txt）", failed.reason


def test_missing_output_without_error_line(tmp_path, monkeypatch):
    """7-Zip が何も言わずにファイルを出さなかった項目は「壊れている可能性」として残す。"""
    out = _listing({"Path": "gone.txt", "Size": "5"})
    fake = _Fake7z({NO_PW: (0, out)})
    ctx = _ctx(tmp_path)
    _run(ctx, monkeypatch, fake)
    [failed] = ctx.items
    assert failed.reason == "展開できなかった（壊れている可能性）", failed.reason


def test_failed_entry_partial_file_is_removed(tmp_path, monkeypatch):
    """CRC の合わない項目は、7-Zip が書きかけたファイルを検査に回さず消す（壊れた中身を検査済みにしない）。"""
    out = _listing({"Path": "bad.txt", "Size": "5"})
    fake = _Fake7z(
        {NO_PW: (0, out)}, extract={NO_PW: {"bad.txt": b"ha"}}, extract_errors={NO_PW: "ERROR: CRC Failed : bad.txt"}
    )
    ctx = _ctx(tmp_path)
    _run(ctx, monkeypatch, fake)
    assert ctx.scanned == []
    assert ctx.items[0].status == Status.UNCHECKABLE


def test_low_temp_space_skips_batch_with_reason(tmp_path, monkeypatch):
    """一時領域の空きが塊に足りなければ、その塊は展開せず、必要と空きの量と置き場の案内を添えて残す。"""
    out = _listing({"Path": "big.bin", "Size": str(3 * 1024**3)}, {"Path": "small.txt", "Size": "1"})
    fake = _Fake7z({NO_PW: (0, out)}, extract={NO_PW: {"small.txt": b"s"}})
    monkeypatch.setattr(archive.safeio, "free_bytes", lambda d: 2 * 1024**3)
    monkeypatch.setattr(archive.safeio, "reserve_bytes", lambda d: 0)
    ctx = _ctx(tmp_path, batch_bytes=1024**3)
    _run(ctx, monkeypatch, fake)
    assert ctx.scanned == ["a.7z!small.txt"], ctx.scanned  # 次の塊は空きに収まるので展開する
    [failed] = ctx.items
    assert failed.path == "a.7z!big.bin" and failed.size == 3 * 1024**3
    assert failed.reason.startswith("一時領域の空きが足りず展開できない（必要 3.0GB・空き 2.0GB）。"), failed.reason
    assert failed.reason.endswith(archive.TEMP_DIR_HINT)


def test_extract_dirs_are_cleaned_up(tmp_path, monkeypatch):
    """パスワードを試した回ごとの展開先は、検査の後で全部片付ける。"""
    out = _listing({"Path": "enc.txt", "Size": "1", "Encrypted": "+"})
    fake = _Fake7z(
        {NO_PW: (0, out)}, extract={"b": {"enc.txt": b"e"}}, extract_errors={NO_PW: "ERROR: Wrong password : enc.txt"}
    )
    ctx = _ctx(tmp_path, passwords=["b"])
    _run(ctx, monkeypatch, fake)
    assert not list(tmp_path.glob("out*")), list(tmp_path.glob("out*"))


def test_no_7z_falls_back_to_py7zr_only_for_7z_signature(tmp_path, monkeypatch):
    """7-Zip が無いとき、7z の頭なら py7zr の道へ、ほかの形式なら 7-Zip の入れ方を添えて検査不能にする。"""
    monkeypatch.setattr(archive, "find_7z", lambda configured: None)
    calls = []
    monkeypatch.setattr(archive, "_handle_7z_python", lambda *a: calls.append(a[1].display))
    ctx = _ctx(tmp_path)
    archive.handle_with_7z_exe(
        ctx, SimpleNamespace(display="a.7z", head=lambda n: b"7z\xbc\xaf\x27\x1c"), SimpleNamespace(kind=""), None, 0
    )
    assert calls == ["a.7z"]
    with pytest.raises(Uncheckable) as e:
        archive.handle_with_7z_exe(
            ctx, SimpleNamespace(display="a.rar", head=lambda n: b"Rar!\x1a\x07"), SimpleNamespace(kind="RAR"), None, 0
        )
    assert str(e.value).startswith("RARの展開には 7-Zip（7z.exe）が要るが見つからない（"), str(e.value)
    assert archive.SEVENZIP_HINT in str(e.value)


def test_failed_names_matches_suffix_and_colon_forms():
    """7-Zip の失敗の行は「… : 名前」と行末の名前の両方の形で拾い、パスワード違いは日本語の理由にする。"""
    output = "\n".join(
        [
            "ERROR: Wrong password : enc.txt",
            "ERROR: Data Error in encrypted file. Wrong password? : enc2.txt",
            "CRC Failed : dir\\bad.txt",
            "Everything is Ok",
            "ERROR: unrelated.txt",
        ]
    )
    got = archive._failed_names(output, {"enc.txt", "enc2.txt", "dir\\bad.txt", "fine.txt"})
    assert got == {
        "enc.txt": "パスワードが違う",
        "enc2.txt": "パスワードが違う",
        "dir\\bad.txt": "CRC Failed : dir\\bad.txt",
    }, got


def test_batches_groups_by_size_and_keeps_big_entry_alone():
    """塊はおよそ上限の大きさで切り、上限より大きな1件は単独の塊にする。"""
    entries = [{"Size": "4"}, {"Size": "4"}, {"Size": "20"}, {"Size": "1"}, {"Size": ""}]
    sizes = [[e["Size"] for e in b] for b in archive._batches(entries, 10)]
    assert sizes == [["4", "4"], ["20"], ["1", ""]], sizes
    assert list(archive._batches([], 10)) == []


def test_parse_7z_list_handles_empty_values_and_no_separator():
    """値が空の行（「Comment =」）も読み、区切りの無い出力は空の一覧にする。"""
    out = LIST_HEAD + "Path = a.txt\nSize = 1\nComment =\n\nPath = b.txt\r\nSize = 2\r\n"
    entries = archive._parse_7z_list(out)
    assert entries == [{"Path": "a.txt", "Size": "1", "Comment": ""}, {"Path": "b.txt", "Size": "2"}], entries
    assert archive._parse_7z_list("Open ERROR: Can not open the file as archive") == []


def test_decode_7z_falls_back_to_cp932():
    """7-Zip の出力が UTF-8 でなければ cp932 として読む。"""
    assert archive._decode_7z("名簿.txt".encode("utf-8")) == "名簿.txt"
    assert archive._decode_7z("名簿.txt".encode("cp932")) == "名簿.txt"


# ------------------------------------------------------------------ ディスクイメージ（7-Zip で開けないときの逃げ道）

VMDK = b"KDMV" + bytes(1024) + "氏名 山田太郎 電話 090-1234-5678\n".encode("utf-16-le") + bytes(512)


def _scan_image(tmp_path, monkeypatch, handler, exe="7z.exe", **opts):
    from pii_checker.engine import scan_file
    from pii_checker.models import ScanOptions

    monkeypatch.setattr(archive, "find_7z", lambda configured: exe)
    monkeypatch.setattr(archive, "handle_with_7z_exe", handler)
    p = tmp_path / "disk.vmdk"
    p.write_bytes(VMDK)
    return scan_file(str(p), ScanOptions(temp_dir=str(tmp_path), **opts)).items[0]


def test_disk_image_falls_back_to_raw_strings(tmp_path, monkeypatch):
    """7-Zip でも中のファイルを取り出せないイメージは、文字として読める部分だけ検査して簡易検査にする。"""

    def broken(*a, **k):
        raise Uncheckable("7-Zip で一覧を取れたが中身が1件も無い")

    item = _scan_image(tmp_path, monkeypatch, broken)
    assert item.status == Status.PARTIAL, (item.status, item.reason)
    assert item.method == "イメージ全体の生データ走査"
    assert item.reason.startswith(
        "7-Zip でイメージの中のファイルを取り出せなかったため、文字列だけを検査した（"
    ), item.reason
    assert "中身が1件も無い" in item.reason
    assert item.finding_counts.get("phone"), item.finding_counts  # 生データの中の電話番号を拾う


def test_disk_image_without_7z_is_uncheckable(tmp_path, monkeypatch):
    """7-Zip が無ければ生データ走査に逃げず、7-Zip の入れ方を添えて検査不能にする。"""
    item = _scan_image(tmp_path, monkeypatch, lambda *a, **k: None, exe=None)
    assert item.status == Status.UNCHECKABLE, (item.status, item.reason)
    assert "ディスクイメージの展開には 7-Zip（7z.exe）が要るが見つからない" in item.reason, item.reason


def test_disk_image_password_is_not_swallowed(tmp_path, monkeypatch):
    """暗号化されたイメージは生データ走査で済ませず、要パスワードのまま返す。"""

    def locked(*a, **k):
        raise NeedPassword("archive", "アーカイブの一覧自体が暗号化されている")

    item = _scan_image(tmp_path, monkeypatch, locked)
    assert item.status == Status.NEEDS_PASSWORD, (item.status, item.reason)


def test_disk_image_deep_sweep_adds_raw_scan(tmp_path, monkeypatch):
    """削除されたファイルの走査をオンにすると、中のファイルの検査に加えてイメージ全体の生データも見る。"""

    def ok(ctx, blob, item, col, depth, kind=""):
        item.method = "7-Zip で展開（0件・暗号化 0件）"

    item = _scan_image(tmp_path, monkeypatch, ok, deep_image_sweep=True)
    assert item.method == "7-Zip で展開（0件・暗号化 0件）＋イメージ全体の生データ走査", item.method
    assert item.finding_counts.get("phone"), item.finding_counts


# ------------------------------------------------------------------ py7zr（7-Zip が無いときの 7z）


def _py7z(tmp_path, files: dict[str, bytes], password: str | None = None) -> Path:
    py7zr = pytest.importorskip("py7zr")
    p = tmp_path / "a.7z"
    with py7zr.SevenZipFile(p, "w", password=password) as z:
        if password:
            z.set_encrypted_header(True)
        for name, body in files.items():
            z.writestr(body, name)
    return p


def _py7z_ctx(tmp_path, arc: Path, passwords=(), max_expand=1 << 40):
    ctx = _ctx(tmp_path, passwords=passwords)
    ctx.options.max_expand_bytes = max_expand
    blob = SimpleNamespace(display="a.7z", open=lambda: open(arc, "rb"))
    return ctx, blob, SimpleNamespace(method="")


def test_py7zr_extracts_with_password_candidate(tmp_path, monkeypatch):
    """7-Zip が無いときは py7zr で展開し、暗号化されていれば候補を順に試す。"""
    arc = _py7z(tmp_path, {"list.csv": b"a,b\n", "sub/b.txt": b"b"}, password="right")
    (tmp_path / "w").mkdir()
    ctx, blob, item = _py7z_ctx(tmp_path / "w", arc, passwords=["wrong", "right"])
    archive._handle_7z_python(ctx, blob, item, None, 0)
    assert sorted(ctx.scanned) == ["a.7z!list.csv", "a.7z!sub/b.txt"], ctx.scanned
    assert item.method == "py7zr で展開（2件）"


def test_py7zr_without_matching_password(tmp_path):
    """どの候補でも開けない 7z は要パスワードにする。

    一覧まで暗号化された 7z を違うパスワードで開くと、py7zr は復号した一覧を読んで TypeError（Unknown field）・
    Bad7zFile などを投げる（どれになるかは暗号の乱数しだい。手元の実測では TypeError が多い）。最後の例外の型で決めていたときは「壊れている」になっていた。
    """
    arc = _py7z(tmp_path, {"a.txt": b"a"}, password="right")
    (tmp_path / "w").mkdir()
    ctx, blob, item = _py7z_ctx(tmp_path / "w", arc, passwords=["wrong", "x", "abc123", "pass", "0000"])
    with pytest.raises(NeedPassword) as e:
        archive._handle_7z_python(ctx, blob, item, None, 0)
    assert str(e.value) == "7z アーカイブが暗号化されている（パスワードの試し）"


def test_py7zr_expand_limit(tmp_path):
    """展開後の合計が上限を超える 7z は、展開せずに打ち切る（パスワードを変えて試し直さない）。"""
    arc = _py7z(tmp_path, {"a.txt": b"a" * 5000})
    (tmp_path / "w").mkdir()
    ctx, blob, item = _py7z_ctx(tmp_path / "w", arc, passwords=["p"], max_expand=1000)
    with pytest.raises(Uncheckable) as e:
        archive._handle_7z_python(ctx, blob, item, None, 0)
    assert "を超えるため打ち切り（zip 爆弾の疑い。" in str(e.value), str(e.value)
    assert ctx.scanned == []


def _utf8_locked_zip_ctx(tmp_path, password: str | bytes, candidates):
    """ZipCrypto で暗号化した本物の zip を置き、7-Zip はどのパスワードでも開けない形にする。"""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from zipcrypto import zipcrypto_zip

    blob = zipcrypto_zip("secret.txt", "顧客 携帯 090-5555-6000\n".encode(), password)
    ctx = _ctx(tmp_path, passwords=candidates, archive_bytes=blob)
    out = _listing({"Path": "secret.txt", "Size": "30", "Encrypted": "+"})
    fake = _Fake7z({NO_PW: (0, out)}, extract_errors={pw: "ERROR: Wrong password : secret.txt" for pw in candidates})
    return ctx, fake


def test_zip_utf8_password_opens_without_7z(tmp_path, monkeypatch):
    """7-Zip は ZipCrypto のパスワードを cp932 で当てるので、UTF-8 の日本語パスワードの zip は Python で開く。"""
    ctx, fake = _utf8_locked_zip_ctx(tmp_path, "合言葉42", ["違う", "合言葉42"])
    _run(ctx, monkeypatch, fake, kind="zip")
    assert ctx.scanned == ["a.7z!secret.txt"], ctx.scanned
    assert ctx.items == []


def _utf8_locked_zip_with_plain(tmp_path, monkeypatch, ensure_space):
    """暗号化の項目を大きな項目の道（一時ファイルへ書く）で開き、7-Zip で開けた平文の項目を同じまとまりに置く。"""
    ctx, _ = _utf8_locked_zip_ctx(tmp_path, "合言葉42", ["違う", "合言葉42"])
    ctx.ensure_space = ensure_space
    monkeypatch.setattr(archive, "IN_MEMORY_LIMIT", 0)
    out = _listing({"Path": "plain.txt", "Size": "4"}, {"Path": "secret.txt", "Size": "30", "Encrypted": "+"})
    fake = _Fake7z(
        {NO_PW: (0, out)},
        extract={NO_PW: {"plain.txt": b"aaaa"}},
        extract_errors={pw: "ERROR: Wrong password : secret.txt" for pw in [NO_PW, "違う", "合言葉42"]},
    )
    _run(ctx, monkeypatch, fake, kind="zip")
    return ctx


def test_zip_utf8_password_large_member_goes_through_temp_file(tmp_path, monkeypatch):
    """大きな項目は一時ファイルへ書いて検査する。空きの確認は合うパスワードの1回だけ（違う候補ではしない）。"""
    sizes: list[int] = []
    ctx = _utf8_locked_zip_with_plain(tmp_path, monkeypatch, lambda n, what="": sizes.append(n))
    assert sorted(ctx.scanned) == ["a.7z!plain.txt", "a.7z!secret.txt"], ctx.scanned
    assert ctx.items == []
    assert len(sizes) == 1, sizes


def test_zip_utf8_password_space_short_marks_only_that_item(tmp_path, monkeypatch):
    """パスワードが合っても空きが足りなければ、その項目だけ検査不能にし、同じまとまりの項目の検査は続ける。"""

    def short(n, what=""):
        raise Uncheckable("一時領域の空きが足りない")

    ctx = _utf8_locked_zip_with_plain(tmp_path, monkeypatch, short)
    assert ctx.scanned == ["a.7z!plain.txt"], ctx.scanned
    assert [(i.path, i.status, i.reason) for i in ctx.items] == [
        ("a.7z!secret.txt", Status.UNCHECKABLE, "一時領域の空きが足りない")
    ], ctx.items


def test_zip_utf8_password_wrong_stays_locked(tmp_path, monkeypatch):
    """日本語の候補が合わなければ要パスワードのまま（英数字の候補は 7-Zip と同じなので Python では試さない）。"""
    ctx, fake = _utf8_locked_zip_ctx(tmp_path, "合言葉42", ["abc", "違う"])
    _run(ctx, monkeypatch, fake, kind="zip")
    assert ctx.scanned == []
    assert [i.status for i in ctx.items] == [Status.NEEDS_PASSWORD], ctx.items


def test_zip_utf8_retry_only_for_zip(tmp_path, monkeypatch):
    """zip でない書庫（7z など）には Python の zip の試しをしない。"""
    ctx, fake = _utf8_locked_zip_ctx(tmp_path, "合言葉42", ["合言葉42"])
    _run(ctx, monkeypatch, fake, kind="7z")
    assert ctx.scanned == []
    assert [i.status for i in ctx.items] == [Status.NEEDS_PASSWORD], ctx.items


def test_zip_utf8_retry_skips_non_zip_bytes(tmp_path, monkeypatch):
    """zip として開けない中身なら、Python の試しは何もせずに要パスワードのまま残す。"""
    ctx = _ctx(tmp_path, passwords=["合言葉42"], archive_bytes=b"x" * 600)
    out = _listing({"Path": "secret.txt", "Size": "30", "Encrypted": "+"})
    fake = _Fake7z({NO_PW: (0, out)}, extract_errors={"合言葉42": "ERROR: Wrong password : secret.txt"})
    _run(ctx, monkeypatch, fake, kind="zip")
    assert [i.status for i in ctx.items] == [Status.NEEDS_PASSWORD], ctx.items


@pytest.mark.skipif(not archive.find_7z(None), reason="本物の 7-Zip が無い")
def test_real_7z_rejects_utf8_zipcrypto_password(tmp_path):
    """前提の確認: 本物の 7-Zip は UTF-8 のパスワードの ZipCrypto を開けず、cp932 のものは開く。"""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from zipcrypto import zipcrypto_zip

    exe = archive.find_7z(None)
    codes = {}
    for label, raw in (("utf8", "合言葉42".encode("utf-8")), ("cp932", "合言葉42".encode("cp932"))):
        p = tmp_path / f"{label}.zip"
        p.write_bytes(zipcrypto_zip("a.txt", b"hello\n", raw))
        r = archive._run_7z(exe, ["t", "-p合言葉42", "-sccUTF-8", "-scsUTF-8", "-mcp=932", str(p)])
        codes[label] = r.returncode
    assert codes["cp932"] == 0 and codes["utf8"] != 0, codes

"""git リポジトリ（作業フォルダの .git と bare）の履歴にだけ残った個人情報を見つける試験。"""

import os
import shutil
import stat
import subprocess

import pytest

from pii_checker.engine import scan_file
from pii_checker.formats.git import apply_delta
from pii_checker.models import ScanOptions, Status

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git が無い")


def _git(*args, cwd):
    subprocess.run(["git", "-c", "core.longpaths=true", *args], cwd=cwd, check=True, capture_output=True)


@pytest.fixture(scope="module")
def repo(tmp_path_factory):
    base = tmp_path_factory.mktemp("git")
    work = base / "work"
    work.mkdir()
    _git("init", "-q", cwd=work)
    _git("config", "user.name", "Tester", cwd=work)
    _git("config", "user.email", "tester@example.invalid", cwd=work)
    (work / "README.txt").write_text("説明\n", encoding="utf-8")
    (work / "顧客.csv").write_text(
        "氏名,電話,マイナンバー\n山田太郎,090-1234-5678,123456789018\n" + "行,0000\n" * 200, encoding="utf-8"
    )
    _git("add", ".", cwd=work)
    _git("commit", "-q", "-m", "初版", cwd=work)
    # 少し変えた版を入れてから消す（pack では差分で持つ）
    with open(work / "顧客.csv", "a", encoding="utf-8") as f:
        f.write("佐藤花子,080-2222-3333,\n")
    _git("commit", "-q", "-am", "追記", cwd=work)
    os.remove(work / "顧客.csv")
    _git("commit", "-q", "-am", "個人情報を消した", cwd=work)
    _git("repack", "-a", "-d", "-q", cwd=work)
    (work / "memo.txt").write_text("連絡先 080-9999-8888\n", encoding="utf-8")
    _git("add", "memo.txt", cwd=work)
    _git("commit", "-q", "-m", "メモ", cwd=work)
    os.remove(work / "memo.txt")
    _git("commit", "-q", "-am", "メモを消した", cwd=work)
    subprocess.run(
        ["git", "-c", "core.longpaths=true", "clone", "-q", "--bare", str(work), str(base / "bare.git")], check=True
    )
    yield base

    def writable(func, path, _):
        os.chmod(path, stat.S_IWRITE)
        func(path)

    shutil.rmtree(base, onerror=writable)


def _all_files(root):
    for dirpath, _, files in os.walk(root):
        if os.sep + "hooks" in dirpath:
            continue
        for f in files:
            yield os.path.join(dirpath, f)


def _scan_tree(root, tmp_path):
    results = [scan_file(p, ScanOptions(temp_dir=str(tmp_path))) for p in _all_files(root)]
    items = [it for r in results for it in r.items]
    return items


@pytest.mark.parametrize("which", [os.path.join("work", ".git"), "bare.git"])
def test_history_only_pii_is_found(repo, tmp_path, which):
    items = _scan_tree(repo / which, tmp_path)
    found = {}
    for it in items:
        for k, v in it.finding_counts.items():
            found.setdefault(k, set()).add(it.path.rsplit("!", 1)[-1])
    # 消したファイルの中身（pack の中・差分で持つ版も）と、消したメモ（緩いオブジェクト）
    assert any("顧客.csv" in p for p in found.get("my_number", ()))
    assert "phone" in found
    phones = sum(it.finding_counts.get("phone", 0) for it in items)
    assert phones >= 3  # 090-…（2版）・080-2222-…・080-9999-…
    # 言い切りを妨げる状態や簡易検査が残らない（git の中身を構造ごと読めている）
    bad = [(it.path, it.status, it.reason) for it in items if it.status not in (Status.SCANNED,)]
    assert bad == []


def test_without_git_support_would_miss(repo, tmp_path, monkeypatch):
    """陽性対照: git の処理を外すと、履歴の中の個人情報は見つからない（この試験が守っていることの確かめ）。"""
    from pii_checker import sniff

    real = sniff.sniff

    def no_git(blob):
        kind = real(blob)
        return "unknown" if kind.startswith("git_") else kind

    monkeypatch.setattr(sniff, "sniff", no_git)
    items = _scan_tree(repo / "bare.git", tmp_path)
    assert sum(it.finding_counts.get("my_number", 0) for it in items) == 0


@pytest.mark.parametrize("head", ["BITMAP_ID", "MTMEMBER", "MIDX", "CGPH", "RIDX", "DIRC", "PACK"])
def test_text_starting_with_git_magic_is_read_as_text(tmp_path, head):
    """git の補助ファイルの目印と同じ英字で始まる CSV を、中身を読まずに「検査済み」にしない（不具合の修正）。"""
    p = tmp_path / "list.csv"
    p.write_text(f"{head},氏名,電話,マイナンバー\n1,山田太郎,090-1234-5678,123456789018\n", encoding="utf-8")
    res = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path)))
    found = {k for it in res.items for k in it.finding_counts}
    assert {"phone", "my_number"} <= found, (res.items[0].kind, found)


def test_meta_and_broken_pack(tmp_path):
    (tmp_path / "pack-1.mtimes").write_bytes(b"MTME" + b"\x00\x00\x00\x01" + b"\x00" * 40)
    res = scan_file(str(tmp_path / "pack-1.mtimes"), ScanOptions(temp_dir=str(tmp_path)))
    assert res.items[0].status == Status.SCANNED and "mtimes" in res.items[0].kind
    # 件数を偽った pack（中身が足りない）は、読めた分だけで言い切らず検査不能
    (tmp_path / "pack-2.pack").write_bytes(b"PACK\x00\x00\x00\x02\x00\x00\x00\x05" + b"\x30\x78\x9c\x03\x00")
    res = scan_file(str(tmp_path / "pack-2.pack"), ScanOptions(temp_dir=str(tmp_path)))
    assert res.items[0].status == Status.UNCHECKABLE


def test_long_delta_chain_is_not_recursive():
    """差分の鎖が長くても再帰の深さで落ちない（2000 段の鎖を偽の pack で戻す）。"""
    import zlib

    from pii_checker.formats.git import PackReader

    reader = PackReader.__new__(PackReader)
    reader._cache = __import__("collections").OrderedDict()
    reader._cached = 0
    base = b"x" * 10
    blobs = {0: zlib.compress(base)}
    entries = [(0, 3, len(base), 0, None)]
    data = bytearray(zlib.compress(base))
    for k in range(1, 2001):
        delta = bytes([10, 10, 0x80 | 0x10, 10])  # 元の10バイトをそのまま写す
        off = len(data)
        data += zlib.compress(delta)
        entries.append((k, 6, len(delta), off, k - 1))
    reader.entries = entries
    reader.by_offset = {k: k for k in range(len(entries))}
    reader.by_sha = {}
    reader.mm = bytes(data)
    assert blobs
    assert reader.resolve(2000) == (3, base)


def test_apply_delta_copy_and_insert():
    src = b"0123456789abcdef"
    # 元の大きさ 16、結果の大きさ 9: 「abc」を挿入し、元の 4 文字目から 6 文字をコピー
    delta = bytes([16, 9, 3]) + b"abc" + bytes([0x80 | 0x01 | 0x10, 4, 6])
    assert apply_delta(src, delta) == b"abc456789"

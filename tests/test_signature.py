"""検査器の版（signature）の試験: exe で埋め込んだ値を使うこと・部品が無いときの扱い・環境の手がかり。

版が変わらないのに変わったと見ると前回の結果を使い回せず、変わったのに同じと見ると古い検出規則の結果を
使い回してしまう。exe とソースの両方の道を確かめる。
"""

from __future__ import annotations

import json
import sys
import types

import pytest

from pii_checker import signature
from pii_checker.models import ScanOptions


@pytest.fixture
def fresh_caches():
    signature.code_fingerprint.cache_clear()
    signature._environment.cache_clear()
    yield
    signature.code_fingerprint.cache_clear()
    signature._environment.cache_clear()


def _fake_buildsig(monkeypatch, **attrs):
    mod = types.ModuleType("pii_checker._buildsig")
    for k, v in attrs.items():
        setattr(mod, k, v)
    monkeypatch.setitem(sys.modules, "pii_checker._buildsig", mod)


def test_frozen_uses_embedded_signature_and_libraries(monkeypatch, fresh_caches):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    _fake_buildsig(monkeypatch, SIG="abc123", LIBS={"openpyxl": "9.9"})
    assert signature.code_fingerprint() == "abc123"
    assert signature.library_versions() == {"openpyxl": "9.9"}


def test_frozen_without_embedded_values(monkeypatch, fresh_caches):
    """exe に埋め込みが無ければ、版は「分からない」と分かる値にし、部品の版は入っている情報から読む。"""
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setitem(sys.modules, "pii_checker._buildsig", None)  # import が ImportError になる
    assert signature.code_fingerprint() == "frozen-unknown"
    libs = signature.library_versions()
    assert set(libs) == set(signature.LIBRARIES)


def test_source_run_ignores_leftover_buildsig(monkeypatch, fresh_caches):
    """ソースで動くときは、ビルドの後に残った _buildsig の古い値を使わない。"""
    monkeypatch.delattr(sys, "frozen", raising=False)
    _fake_buildsig(monkeypatch, SIG="stale", LIBS={"openpyxl": "0.0"})
    assert signature.code_fingerprint() != "stale"
    assert signature.library_versions().get("openpyxl") != "0.0"


def test_missing_library_has_empty_version(monkeypatch):
    monkeypatch.delattr(sys, "frozen", raising=False)
    monkeypatch.setattr(signature, "LIBRARIES", ("no-such-package-for-pii-test",))
    assert signature.library_versions() == {"no-such-package-for-pii-test": ""}


def test_source_fingerprint_ignores_excluded_files_and_line_endings(tmp_path):
    pkg = tmp_path / "pkg"
    (pkg / "web").mkdir(parents=True)
    (pkg / "detectors.py").write_bytes(b"A = 1\n")
    base = signature.source_fingerprint(str(pkg))
    # 版に含めないもの（画面・保存・web・.py 以外）は変えても同じ
    (pkg / "cli.py").write_bytes(b"x = 1\n")
    (pkg / "web" / "server.py").write_bytes(b"y = 1\n")
    (pkg / "notes.txt").write_bytes(b"z\n")
    assert signature.source_fingerprint(str(pkg)) == base
    # 改行コードだけの違いは同じ（git の設定で CRLF になっても版を変えない）
    (pkg / "detectors.py").write_bytes(b"A = 1\r\n")
    assert signature.source_fingerprint(str(pkg)) == base
    # 陽性対照: 検出に関わるソースが変われば変わる
    (pkg / "detectors.py").write_bytes(b"A = 2\n")
    assert signature.source_fingerprint(str(pkg)) != base


def test_environment_stamps_tools_and_survives_missing_ones_and_odbc_failure(monkeypatch, fresh_caches, tmp_path):
    from pii_checker import ocr
    from pii_checker.formats import archive, database, dbdump

    tool = tmp_path / "7z.exe"
    tool.write_bytes(b"x" * 5)
    monkeypatch.setattr(ocr, "is_available", lambda: False)
    monkeypatch.setattr(archive, "find_7z", lambda hint=None: str(tool))
    monkeypatch.setattr(database, "find_helper32", lambda hint=None: None)
    # 見つかったと返されたのに消えている道具は、名前だけを手がかりにする（版を出せないので落とさない）
    monkeypatch.setattr(dbdump, "find_pg_restore", lambda: str(tmp_path / "gone" / "pg_restore.exe"))

    # ODBC の一覧が取れなくても落とさない（pyodbc の入っていない環境でも試せるよう、偽の部品を差し込む）
    def broken_drivers():
        raise RuntimeError("ODBC の一覧を取れない")

    monkeypatch.setitem(sys.modules, "pyodbc", types.SimpleNamespace(drivers=broken_drivers))
    got = json.loads(signature._environment(None, None))
    assert got["7z"].startswith("7z.exe:5:")
    assert got["pg_restore"] == "pg_restore.exe"
    assert got["access"] == []
    assert got["helper32"] is False and got["ocr"] is False


def test_engine_signature_changes_only_with_result_affecting_options(fresh_caches):
    base = signature.engine_signature(ScanOptions())
    # 場所・道具のパスは結果に効かない
    assert signature.engine_signature(ScanOptions(temp_dir="X:\\tmp", reuse=False)) == base
    # 許可リストは書き順・重複では変わらず、中身が変われば変わる
    a = signature.engine_signature(ScanOptions(allow_values=["090-1234-5678", "info@example.com"]))
    b = signature.engine_signature(ScanOptions(allow_values=["info@example.com", "090-1234-5678", "090-1234-5678"]))
    assert a == b != base
    assert signature.engine_signature(ScanOptions(ocr=True)) != base

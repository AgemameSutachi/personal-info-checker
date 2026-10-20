"""Rust 拡張に組み込む正規表現の表（rust/pii_rs_detect/src/patterns.json）が、detectors.py と食い違っていないことの試験。

Rust が無い環境でも走る。detectors.py の式を変えたのに表を作り直し忘れると、ここで落ちる。
作り直し: python tools/export_rust_patterns.py（そのあと拡張も作り直す: python tools/build_rust_ext.py）
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import export_rust_patterns as export  # noqa: E402

PATTERNS = ROOT / "rust" / "pii_rs_detect" / "src" / "patterns.json"


def test_patterns_json_matches_detectors():
    current = PATTERNS.read_text(encoding="utf-8")
    assert current == export.render(), (
        "patterns.json が detectors.py と食い違っています。"
        "python tools/export_rust_patterns.py で作り直し、python tools/build_rust_ext.py で拡張も作り直してください"
    )


def test_patterns_json_covers_all_rules():
    """detectors.py の主な正規表現が表に入っている（入れ忘れ・名前の取り違えを防ぐ）。"""
    table = json.loads(PATTERNS.read_text(encoding="utf-8"))["rg"]
    for name in (
        "RE_MY_NUMBER",
        "RE_CARD",
        "RE_LANDLINE",
        "RE_ADDRESS",
        "RE_EMAIL",
        "RE_DATE",
        "ORDER_KW",
        "COMPANY_KW",
    ):
        assert name in table, name


def test_installed_extension_uses_same_patterns():
    """入っている拡張が組み込んだ表も、いまの表と同じ（表だけ直して拡張を作り直し忘れた状態を見つける）。拡張が無ければ飛ばす。"""
    import pytest

    ext = pytest.importorskip("pii_rs_detect")
    # Windows で改行が CRLF に変えられて取り出されても同じとみなす
    assert ext.patterns_json().replace("\r\n", "\n") == PATTERNS.read_text(
        encoding="utf-8"
    ), "入っている拡張が古い表で作られています。python tools/build_rust_ext.py で作り直してください"


def test_installed_extension_has_no_build_paths():
    """入っている拡張に、作った環境のパス（利用者名を含むホーム・リポジトリの置き場）が埋め込まれていない。

    rustc は panic の位置としてソースのパスを埋め込む。tools/build_rust_ext.py が --remap-path-prefix で写す。拡張が無ければ飛ばす。
    """
    import os

    import pytest

    ext = pytest.importorskip("pii_rs_detect")
    # maturin は pii_rs_detect/__init__.py と同じフォルダに本体（.pyd／.so）を置く
    binaries = [p for p in Path(ext.__file__).parent.iterdir() if p.suffix in (".pyd", ".so")]
    assert binaries, f"拡張の本体が見つかりません: {Path(ext.__file__).parent}"
    data = b"".join(p.read_bytes() for p in binaries).lower()
    for path in (os.path.expanduser("~"), str(ROOT)):
        for variant in (path, path.replace("\\", "/")):
            needle = variant.lower().encode("utf-8")
            assert needle not in data, (
                f"拡張に作った環境のパスが埋め込まれています（{data.count(needle)} か所）。"
                "python tools/build_rust_ext.py で作り直してください（--remap-path-prefix を付けて組みます）"
            )

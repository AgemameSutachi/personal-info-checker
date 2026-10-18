"""検査器の版（前回の結果を使い回してよいかの判定に使う）。

同じファイルでも、検出規則・形式の読み方・結果に効く設定・使える部品（OCR・7-Zip・Access のドライバ・pg_restore）が
変われば結果が変わりうる。それらをまとめて1つの値にし、値が同じ前回の結果だけを使い回す。
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict
from functools import lru_cache

from .models import ScanOptions

# 1ファイルの検査結果に関わらない部分（画面・保存・集計・実行の制御）は版に含めない
_EXCLUDE = {
    "cli.py",
    "desktop.py",
    "report.py",
    "store.py",
    "verdict.py",
    "runner.py",
    "procguard.py",
    "signature.py",
    "_buildsig.py",
    "__main__.py",
}
# 読み取りに使う部品（requirements.txt の「形式の読み取り」と OCR）。版が変われば前回の結果を使い回さない
LIBRARIES = (
    "openpyxl",
    "xlrd",
    "pyxlsb",
    "python-docx",
    "python-pptx",
    "pymupdf",
    "olefile",
    "extract-msg",
    "msoffcrypto-tool",
    "py7zr",
    "rarfile",
    "zstandard",
    "lz4",
    "pillow",
    "chardet",
    "access-parser",
    "pyodbc",
    "winrt-Windows.Media.Ocr",
)
# 結果に効かない設定（場所・道具のパス・展開の区切り方）。道具の有無は環境として別に数える
# connection（接続方式の接続先）も検出の結果には効かない（同じファイルなら、フォルダで指定しても接続方式でも結果は同じ）
_OPTION_EXCLUDE = {"temp_dir", "sevenzip", "access_helper32", "extract_batch_bytes", "reuse", "connection"}


@lru_cache(maxsize=1)
def code_fingerprint() -> str:
    """検査に関わるソースの指紋。exe では作るときに埋め込んだ値（_buildsig.SIG）を使う。

    ソースで動いているときは毎回ソースから求める（ビルドの後に残った _buildsig.py の古い値で、
    直した検出規則の前の結果を使い回さないため）。
    """
    import sys

    if getattr(sys, "frozen", False):
        try:
            from ._buildsig import SIG  # type: ignore

            return SIG
        except ImportError:
            return "frozen-unknown"
    return source_fingerprint(os.path.dirname(os.path.abspath(__file__)))


def source_fingerprint(package_dir: str) -> str:
    h = hashlib.sha256()
    for dirpath, dirnames, filenames in os.walk(package_dir):
        dirnames[:] = sorted(d for d in dirnames if d not in ("web", "__pycache__"))
        for name in sorted(filenames):
            if not name.endswith(".py") or name in _EXCLUDE:
                continue
            p = os.path.join(dirpath, name)
            h.update(os.path.relpath(p, package_dir).replace(os.sep, "/").encode())
            with open(p, "rb") as f:
                h.update(f.read().replace(b"\r\n", b"\n"))
    return h.hexdigest()


def library_versions() -> dict[str, str]:
    """読み取りに使う部品の版。exe には部品の版の情報（dist-info）が入らないので、作るときに埋め込んだ値を使う。"""
    import sys

    if getattr(sys, "frozen", False):
        try:
            from ._buildsig import LIBS  # type: ignore

            return dict(LIBS)
        except ImportError:
            pass
    from importlib import metadata

    libs = {}
    for name in LIBRARIES:
        try:
            libs[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            libs[name] = ""
    return libs


@lru_cache(maxsize=8)
def _environment(sevenzip: str | None, helper32: str | None) -> str:
    """使える部品の一覧（有無と版の手がかり）。"""
    from . import ocr
    from .formats.archive import find_7z
    from .formats.database import find_helper32
    from .formats.dbdump import find_pg_restore

    def stamp(path: str | None) -> str:
        if not path:
            return ""
        try:
            st = os.stat(path)
            return f"{os.path.basename(path)}:{st.st_size}:{int(st.st_mtime)}"
        except OSError:
            return os.path.basename(path)

    try:
        import pyodbc

        drivers = sorted(d for d in pyodbc.drivers() if "Access" in d)
    except Exception:
        drivers = []
    libs = library_versions()
    env = {
        "libs": libs,  # 読み取りに使う部品の版（上げると読める範囲が変わりうる）
        "ocr": bool(ocr.is_available()),
        "7z": stamp(find_7z(sevenzip)),
        "access": drivers,
        "helper32": bool(find_helper32(helper32)),
        "pg_restore": stamp(find_pg_restore()),
    }
    return json.dumps(env, sort_keys=True, ensure_ascii=False)


def engine_signature(options: ScanOptions) -> str:
    """検査器の版（ソース・結果に効く設定・使える部品）。"""
    opts = {k: v for k, v in asdict(options).items() if k not in _OPTION_EXCLUDE}
    h = hashlib.sha256()
    h.update(code_fingerprint().encode())
    h.update(json.dumps(opts, sort_keys=True, ensure_ascii=False).encode())
    h.update(_environment(options.sevenzip, options.access_helper32).encode())
    return h.hexdigest()[:32]

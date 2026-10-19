"""配布用の exe を作る。

  python build.py [--python32-zip <python-3.12.x-embed-win32.zip>]

dist/PiiChecker/ に次をまとめる:
  PiiChecker.exe       … アプリ版（窓）。引数を付ければ CLI としても動く
  PiiChecker-cmd.exe   … コマンド版（コンソール）
  7z/                  … 7-Zip（LGPL。License.txt を同梱）。この PC の 7-Zip から写す
  python32/            … 32bit の Python 埋め込み版＋ access32_helper.py（Access 97 等を読む補助）
  LICENSE.txt / THIRD-PARTY-LICENSES.txt … このツールと、同梱する依存のライセンス文
  はじめにお読みください.txt … どの exe を開けばよいかの短い説明
作業用のフォルダは build/ と dist/ の下にだけ作る。
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist" / "PiiChecker"
WORK = ROOT / "build"
PY32_URL = "https://www.python.org/ftp/python/3.12.10/python-3.12.10-embed-win32.zip"

SPEC = r"""
# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

datas = [(r'{root}/pii_checker/web/static', 'pii_checker/web/static')]
binaries = []
hiddenimports = ['pii_checker.formats.archive', 'pii_checker.formats.database', 'pii_checker.formats.dbdump',
                 'pii_checker.formats.misc', 'pii_checker.formats.office', 'pii_checker.formats.pdf',
                 'pii_checker.formats.pst', 'pii_checker.desktop', 'pii_checker.web.server',
                 'winrt._winrt_windows_foundation', 'winrt._winrt_windows_foundation_collections',
                 'uvicorn.logging', 'uvicorn.loops.auto', 'uvicorn.protocols.http.auto', 'uvicorn.lifespan.on']
for pkg in ('winrt', 'pymupdf', 'webview', 'extract_msg', 'msoffcrypto', 'py7zr'):
    try:
        d, b, h = collect_all(pkg)
        datas += d; binaries += b; hiddenimports += h
    except Exception:
        pass

def make(script, name, console):
    a = Analysis([script], pathex=[r'{root}'], binaries=binaries, datas=datas, hiddenimports=hiddenimports,
                 excludes=['tkinter'], noarchive=False)
    pyz = PYZ(a.pure)
    exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name=name, console=console, upx=False)
    return a, exe

a1, exe1 = make(r'{root}/entry_app.py', 'PiiChecker', False)
a2, exe2 = make(r'{root}/entry_cli.py', 'PiiChecker-cmd', True)
coll = COLLECT(exe1, a1.binaries, a1.datas, exe2, a2.binaries, a2.datas, upx=False, name='PiiChecker')
"""


def run(cmd: list[str]) -> None:
    print(">", " ".join(cmd))
    subprocess.run(cmd, check=True)


def copy_7zip() -> None:
    src = None
    vendor = ROOT / "vendor" / "7zip"
    if (vendor / "7z.exe").is_file():
        src = vendor
    for env in ("ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"):
        if os.environ.get(env) and (Path(os.environ[env]) / "7-Zip" / "7z.exe").is_file():
            src = src or Path(os.environ[env]) / "7-Zip"
            break
    if not src:
        print("! 7-Zip が見つからないため同梱しない（rar・lzh・ディスクイメージ等は配布先に 7-Zip が要る）")
        return
    dst = DIST / "7z"
    dst.mkdir(parents=True, exist_ok=True)
    for name in ("7z.exe", "7z.dll", "License.txt", "readme.txt"):
        if (src / name).is_file():
            shutil.copy2(src / name, dst / name)
    print(f"7-Zip を同梱: {src}")


LICENSE_WORDS = ("LICENSE", "LICENCE", "COPYING", "NOTICE", "AUTHORS")


def _requirement_closure() -> list:
    """requirements.txt の依存と、その依存をたどった配布物（importlib.metadata.Distribution）を名前順に返す。"""
    import importlib.metadata as md
    import re

    names = []
    for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines():
        line = line.split("#")[0].strip()
        if line:
            names.append(re.split(r"[<>=!~;\[ ]", line)[0])
    seen: dict[str, object] = {}
    while names:
        name = names.pop()
        key = re.sub(r"[-_.]+", "-", name).lower()
        if key in seen:
            continue
        try:
            dist = md.distribution(name)
        except md.PackageNotFoundError:
            continue
        seen[key] = dist
        for req in dist.requires or []:
            if "extra ==" in req:
                continue  # 任意の追加機能の依存は入れない
            names.append(re.split(r"[<>=!~;\[ (]", req.strip())[0])
    return [seen[k] for k in sorted(seen)]


def write_licenses() -> None:
    """配布版に、このツールの LICENSE と、同梱する依存のライセンス文の一覧を置く（MIT・GPL 系とも許諾文の同梱を求めるため）。"""
    DIST.mkdir(parents=True, exist_ok=True)
    shutil.copy2(ROOT / "LICENSE", DIST / "LICENSE.txt")
    parts = [
        "個人情報チェッカーの配布版に含まれる第三者のソフトウェアと、そのライセンス文です。\n"
        "PyMuPDF（AGPL-3.0）・extract-msg（GPL-3.0）を含むため、配布版の全体は AGPL-3.0 の条件に従います。\n"
        "ソース: https://github.com/AgemameSutachi/personal-info-checker\n"
        "7-Zip のライセンスは 7z/License.txt、32bit の Python 埋め込み版のライセンスは python32/LICENSE.txt にあります。\n",
        # PyMuPDF の配布物の COPYING は1行だけで本文を含まないので、AGPL-3.0 の全文はリポジトリの写しから入れる
        "=" * 78
        + "\nGNU Affero General Public License v3.0（PyMuPDF と、それを含む配布版の全体に適用）\n"
        + "=" * 78
        + "\n"
        + (ROOT / "licenses" / "AGPL-3.0.txt").read_text(encoding="utf-8"),
    ]
    py_license = Path(sys.base_prefix) / "LICENSE.txt"
    if py_license.is_file():
        parts.append(
            "=" * 78
            + f"\nPython {sys.version.split()[0]}\n"
            + "=" * 78
            + "\n"
            + py_license.read_text(encoding="utf-8", errors="replace")
        )
    for dist in _requirement_closure():
        meta = dist.metadata
        lic = meta.get("License-Expression") or (meta.get("License") or "").splitlines()[0:1]
        lic = lic if isinstance(lic, str) else "".join(lic)
        header = "=" * 78 + f"\n{meta['Name']} {dist.version}" + (f"（{lic}）" if lic else "") + "\n" + "=" * 78 + "\n"
        texts = []
        for f in dist.files or []:
            if any(w in f.name.upper() for w in LICENSE_WORDS) and not f.name.endswith((".py", ".pyc")):
                try:
                    texts.append(Path(f.locate()).read_text(encoding="utf-8", errors="replace"))
                except OSError:
                    pass
        if not texts:
            texts.append(f"（ライセンス文のファイルが配布物に含まれていない。ライセンス: {lic or '不明'}）\n")
        parts.append(header + "\n".join(texts))
    (DIST / "THIRD-PARTY-LICENSES.txt").write_text("\n\n".join(parts), encoding="utf-8")
    print(f"ライセンス文を同梱: {DIST / 'THIRD-PARTY-LICENSES.txt'}")


FIRST_README = """個人情報チェッカー {version}

■ どれを開けばよいか
  PiiChecker.exe       … ふだんはこれをダブルクリックします（画面で操作するアプリ版）
  PiiChecker-cmd.exe   … コマンドで使う版です。ダブルクリックでは使いません
                          （Web 版の起動・タスクスケジューラでの定期検査などに使う）

■ 中身
  7z\\・python32\\・_internal\\ … 動かすのに要る部品です。消したり動かしたりしないでください
  LICENSE.txt・THIRD-PARTY-LICENSES.txt … ライセンス文

使い方の詳細: https://github.com/AgemameSutachi/personal-info-checker#readme
"""


def write_first_readme() -> None:
    """配布フォルダに、どの exe を開けばよいかを書いた短い説明を置く（exe が2つあって迷わないように）。"""
    from pii_checker import __version__

    DIST.mkdir(parents=True, exist_ok=True)
    # メモ帳で文字化けしないよう BOM 付きの UTF-8・CRLF で書く
    with open(DIST / "はじめにお読みください.txt", "w", encoding="utf-8-sig", newline="\r\n") as f:
        f.write(FIRST_README.format(version=__version__))


def add_python32(zip_path: str | None) -> None:
    dst = DIST / "python32"
    dst.mkdir(parents=True, exist_ok=True)
    if not zip_path:
        zip_path = str(WORK / "python32-embed.zip")
        if not Path(zip_path).is_file():
            print(f"32bit 埋め込み Python を取得: {PY32_URL}")
            WORK.mkdir(exist_ok=True)
            urllib.request.urlretrieve(PY32_URL, zip_path)
    with zipfile.ZipFile(zip_path) as z:
        z.extractall(dst)
    shutil.copy2(ROOT / "pii_checker" / "access32_helper.py", dst / "access32_helper.py")
    print("32bit の Access 補助を同梱")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--python32-zip", help="python-3.12.x-embed-win32.zip（無ければ python.org から取得）")
    ap.add_argument("--skip-python32", action="store_true")
    args = ap.parse_args()
    WORK.mkdir(exist_ok=True)
    spec = WORK / "PiiChecker.spec"
    spec.write_text(SPEC.replace("{root}", ROOT.as_posix()), encoding="utf-8")
    # exe の中にはソースが無いので、検査器の版（前回の結果を使い回してよいかの判定）を作るときに埋め込む
    sys.path.insert(0, str(ROOT))
    from pii_checker.signature import library_versions, source_fingerprint

    sig_file = ROOT / "pii_checker" / "_buildsig.py"
    sig_file.write_text(
        '"""build.py が作る（検査に関わるソースの指紋と、読み取りに使う部品の版）。リポジトリには入れない。"""\n\n'
        f'SIG = "{source_fingerprint(str(ROOT / "pii_checker"))}"\n'
        f"LIBS = {library_versions()!r}\n",
        encoding="utf-8",
    )
    run(
        [
            sys.executable,
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--clean",
            "--distpath",
            str(ROOT / "dist"),
            "--workpath",
            str(WORK / "pyi"),
            str(spec),
        ]
    )
    copy_7zip()
    write_licenses()
    write_first_readme()
    if not args.skip_python32:
        add_python32(args.python32_zip)
    print(f"\n完成: {DIST}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

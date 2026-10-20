"""配布用の exe を作る。

  python build.py [--python32-zip <python-3.12.x-embed-win32.zip>] [--jdk-dir <Temurin の JDK 21 のフォルダ>] [--skip-java]
  python build.py --fetch-jackcess      … 開発・試験用に、Jackcess の jar を vendor/jackcess へ取り込んで終わる

ダウンロードしたもの（Java 実行環境の元の JDK・Jackcess の jar）は、ビルド用のキャッシュ（build/cache。環境変数
PIICHK_BUILD_CACHE で変えられる）へ置く。チェックサムを確かめてから使う。

dist/PiiChecker/ に次をまとめる（一番上でダブルクリックできる exe はアプリ版の1つだけにする）:
  PiiChecker.exe               … アプリ版（窓）。引数にパスがあれば、それを対象に入れて窓を開く
  cmd/PiiChecker-cmd.exe       … コマンド版（コンソール）。親の _internal を使う
  _internal/                   … PyInstaller の部品と、次の同梱物
  _internal/7z/                … 7-Zip（LGPL。License.txt を同梱）。この PC の 7-Zip から写す
  _internal/python32/          … 32bit の Python 埋め込み版＋ access32_helper.py（Access 97 等を読む補助）・
                                 access32_rewrite.py（Access の中身の対処で、Windows 標準の Jet 4.0 を動かす補助）
  _internal/java/              … Java 実行環境（Eclipse Temurin の OpenJDK 21 を jlink で必要なモジュールだけにしたもの。
                                 GPLv2 + Classpath Exception。Access の対処で ACE の無い .accdb を Jackcess で書き換えるために使う）
  _internal/jackcess/          … Jackcess（Apache 2.0）とその依存の jar・補助（tools/jackcess の Java のソースをビルドした jar）・ライセンス文
  LICENSE.txt / THIRD-PARTY-LICENSES.txt … このツールと、同梱する依存のライセンス文
  はじめにお読みください.txt   … 画面の版とコマンド版の使い方（配布の zip に README は入れない）
作業用のフォルダは build/ と dist/ の下にだけ作る。
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import locale
import os
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist" / "PiiChecker"
INTERNAL = DIST / "_internal"
CMD_DIR = DIST / "cmd"
CMD_EXE = "PiiChecker-cmd.exe"
WORK = ROOT / "build"
PY32_URL = "https://www.python.org/ftp/python/3.12.10/python-3.12.10-embed-win32.zip"
# Java 実行環境の元（Eclipse Temurin の OpenJDK。jlink と javac が要るので JDK を取る）と、Jackcess（Access の中身の対処で使う）
CACHE = Path(os.environ.get("PIICHK_BUILD_CACHE") or (WORK / "cache"))
JDK_TAG = "jdk-21.0.10+7"
JDK_FILE = "OpenJDK21U-jdk_x64_windows_hotspot_21.0.10_7.zip"
JDK_URL = f"https://github.com/adoptium/temurin21-binaries/releases/download/{JDK_TAG.replace('+', '%2B')}/{JDK_FILE}"
MAVEN = "https://repo1.maven.org/maven2"
JACKCESS_JARS = {
    "jackcess-4.0.8.jar": "com/healthmarketscience/jackcess/jackcess/4.0.8/jackcess-4.0.8.jar",
    "commons-lang3-3.10.jar": "org/apache/commons/commons-lang3/3.10/commons-lang3-3.10.jar",
    "commons-logging-1.2.jar": "commons-logging/commons-logging/1.2/commons-logging-1.2.jar",
}
JAVA_SOURCE = ROOT / "tools" / "jackcess" / "AccessRewrite.java"
HELPER_JAR = "piichk-access.jar"
# jdeps で調べられなかったときの、実行環境に入れるモジュール（Jackcess が使う java.sql などを含む）
FALLBACK_JAVA_MODULES = "java.base,java.logging,java.sql,java.xml,java.naming"

SPEC = r"""
# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

datas = [(r'{root}/pii_checker/web/static', 'pii_checker/web/static')]
binaries = []
hiddenimports = ['pii_checker.formats.archive', 'pii_checker.formats.database', 'pii_checker.formats.dbdump',
                 'pii_checker.formats.misc', 'pii_checker.formats.office', 'pii_checker.formats.pdf',
                 'pii_checker.formats.pst', 'pii_checker.desktop', 'pii_checker.web.server',
                 'winrt._winrt_windows_foundation', 'winrt._winrt_windows_foundation_collections',
                 'pii_rs_detect',
                 'uvicorn.logging', 'uvicorn.loops.auto', 'uvicorn.protocols.http.auto', 'uvicorn.lifespan.on']
for pkg in ('winrt', 'pymupdf', 'webview', 'extract_msg', 'msoffcrypto', 'py7zr'):
    try:
        d, b, h = collect_all(pkg)
        datas += d; binaries += b; hiddenimports += h
    except Exception:
        pass

def make(script, name, console, options=(), **kw):
    a = Analysis([script], pathex=[r'{root}'], binaries=binaries, datas=datas, hiddenimports=hiddenimports,
                 excludes=['tkinter'], noarchive=False)
    pyz = PYZ(a.pure)
    exe = EXE(pyz, a.scripts, list(options), exclude_binaries=True, name=name, console=console, upx=False, **kw)
    return a, exe

a1, exe1 = make(r'{root}/entry_app.py', 'PiiChecker', False)
# コマンド版は build.py が cmd/ へ移すので、部品は親の _internal から読ませる。PyInstaller の
# contents_directory は1階層の名前しか受け付けないため、"." で既定の設定を止め、起動部が読む設定を直接埋める
a2, exe2 = make(r'{root}/entry_cli.py', 'PiiChecker-cmd', True,
                options=[('pyi-contents-directory ..\\_internal', '', 'OPTION')], contents_directory='.')
# COLLECT は最初の EXE（アプリ版）の contents_directory（_internal）でフォルダを組む
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
    dst = INTERNAL / "7z"
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
        "7-Zip のライセンスは _internal/7z/License.txt、32bit の Python 埋め込み版のライセンスは "
        "_internal/python32/LICENSE.txt にあります。Access の対処で使う Java 実行環境（OpenJDK）・Jackcess の"
        "ライセンス文は、このファイルの末尾にあります。\n",
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
    java_section = java_license_section()
    if java_section:
        parts.append(java_section)
    (DIST / "THIRD-PARTY-LICENSES.txt").write_text("\n\n".join(parts), encoding="utf-8")
    print(f"ライセンス文を同梱: {DIST / 'THIRD-PARTY-LICENSES.txt'}")


FIRST_README = """個人情報チェッカー {version}

■ 画面で使う
  PiiChecker.exe をダブルクリックします。調べたいフォルダを PiiChecker.exe に重ねて離しても開けます。
  警告（Windows によって PC が保護されました）が出たら「詳細情報」→「実行」を押します。

■ 見つけた個人情報への対処（画面の版・Web 版。コマンド版ではできません）
  ファイルの詳細の「対処する…」から、行の削除・ダミー化・黒塗り・ファイルの削除などができます。
  元の写しは作りません。元はごみ箱へ送りますが、ごみ箱の無い場所（NAS・外付けなど）では元は残りません。
  「下見」を読んでから実行してください。

■ コマンドで使う（定期検査・Web 版）
  cmd\\PiiChecker-cmd.exe を、コマンドプロンプトや PowerShell から使います。例:
    cmd\\PiiChecker-cmd.exe scan \\\\nas01\\総務 -o 結果.xlsx
    cmd\\PiiChecker-cmd.exe serve
  引数の一覧は cmd\\PiiChecker-cmd.exe --help で出ます。

■ そのほか
  _internal と cmd は動かすのに要る部品です（Python・Java・7-Zip も中に入っているので、別に入れる必要はありません）。
  中身を消したり、PiiChecker フォルダの外へ動かしたりしないでください。
  ライセンス: LICENSE.txt（このツール）・THIRD-PARTY-LICENSES.txt（同梱した部品）
  使い方の詳細: https://github.com/AgemameSutachi/personal-info-checker#readme
"""


def write_first_readme() -> None:
    """配布フォルダに、画面の版とコマンド版の使い方を書いた短い説明を置く（配布の zip に README は入れないため）。"""
    from pii_checker import __version__

    DIST.mkdir(parents=True, exist_ok=True)
    # メモ帳で文字化けしないよう BOM 付きの UTF-8・CRLF で書く
    with open(DIST / "はじめにお読みください.txt", "w", encoding="utf-8-sig", newline="\r\n") as f:
        f.write(FIRST_README.format(version=__version__))


def add_python32(zip_path: str | None) -> None:
    dst = INTERNAL / "python32"
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
    shutil.copy2(ROOT / "pii_checker" / "access32_rewrite.py", dst / "access32_rewrite.py")
    print("32bit の Access 補助（読み取り用・書き換え用）を同梱")


# ---------------------------------------------------------------- Java 実行環境と Jackcess（Access の中身の対処）


def _download(url: str, dest: Path) -> None:
    """url を dest へ取得する（途中で止まったファイルを残さないよう、一時の名前へ書いてから置く）。"""
    print(f"取得: {url}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".part")
    urllib.request.urlretrieve(url, tmp)
    os.replace(tmp, dest)


def _digest(path: Path, algo: str) -> str:
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _remote_text(url: str) -> str:
    with urllib.request.urlopen(url, timeout=60) as r:
        return r.read().decode("ascii", errors="replace")


def fetch_jackcess_jars(dest: Path) -> dict[str, Path]:
    """Jackcess と、その依存の jar を dest へ取り込む（Maven Central。SHA-1 を公開値と照合する）。{名前: パス} を返す。"""
    out: dict[str, Path] = {}
    for name, rel in JACKCESS_JARS.items():
        target = dest / name
        if not target.is_file():
            cached = CACHE / "jackcess" / name
            if not cached.is_file():
                _download(f"{MAVEN}/{rel}", cached)
            expected = _remote_text(f"{MAVEN}/{rel}.sha1").split()[0].strip().lower()
            if _digest(cached, "sha1") != expected:
                cached.unlink()
                raise SystemExit(f"! {name} のチェックサムが Maven Central の公開値と合いません。取り直してください")
            dest.mkdir(parents=True, exist_ok=True)
            shutil.copy2(cached, target)
        out[name] = target
    return out


def _jdk_home_of(path: Path) -> Path | None:
    """path 自身か、その直下の1段のフォルダ（zip の展開直下の作り）のうち、jlink.exe を持つもの。"""
    if (path / "bin" / "jlink.exe").is_file():
        return path
    if path.is_dir():
        for p in sorted(path.iterdir()):
            if p.is_dir() and (p / "bin" / "jlink.exe").is_file():
                return p
    return None


def find_jdk(jdk_dir: str | None) -> Path:
    """jlink と javac のある JDK のフォルダを返す。指定（--jdk-dir・環境変数 PIICHK_JDK）が無ければ、キャッシュへ取得して展開する。"""
    given = jdk_dir or os.environ.get("PIICHK_JDK")
    if given:
        home = _jdk_home_of(Path(given))
    else:
        cache_home = CACHE / "jdk" / JDK_TAG.replace("+", "_")
        home = _jdk_home_of(cache_home)
        if home is None:
            archive = CACHE / JDK_FILE
            if not archive.is_file():
                _download(JDK_URL, archive)
            expected = _remote_text(JDK_URL + ".sha256.txt").split()[0].strip().lower()
            if _digest(archive, "sha256") != expected:
                archive.unlink()
                raise SystemExit("! JDK のチェックサムが公開値と合いません。取り直してください")
            cache_home.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(archive) as z:
                z.extractall(cache_home)
            home = _jdk_home_of(cache_home)
    if home is None:
        raise SystemExit(f"! JDK が見つかりません（jlink.exe のあるフォルダ）: {given or CACHE}")
    for tool in ("javac.exe", "jar.exe", "jlink.exe", "jdeps.exe"):
        if not (home / "bin" / tool).is_file():
            raise SystemExit(f"! JDK に {tool} がありません（JRE ではなく JDK が要ります）: {home}")
    return home


def build_helper_jar(jdk: Path, jars: dict[str, Path], out_jar: Path) -> None:
    """tools/jackcess の Java のソースを、Java 11 向けにコンパイルして jar にする。"""
    classes = WORK / "jackcess-classes"
    if classes.exists():
        shutil.rmtree(classes)
    classes.mkdir(parents=True)
    cp = os.pathsep.join(str(p) for p in jars.values())
    run(
        [str(jdk / "bin" / "javac.exe"), "-encoding", "UTF-8", "--release", "11", "-cp", cp, "-d", str(classes)]
        + [str(JAVA_SOURCE)]
    )
    out_jar.parent.mkdir(parents=True, exist_ok=True)
    run([str(jdk / "bin" / "jar.exe"), "cf", str(out_jar), "-C", str(classes), "."])


def make_java_runtime(jdk: Path, class_path: list[Path], out_dir: Path) -> None:
    """jdeps で必要なモジュールを調べ、jlink で小さな Java 実行環境を作る（OpenJDK の legal/ も入る）。"""
    if out_dir.exists():
        shutil.rmtree(out_dir)  # jlink は既にある出力先へは作れない
    modules = FALLBACK_JAVA_MODULES
    probe = subprocess.run(
        [
            str(jdk / "bin" / "jdeps.exe"),
            "--print-module-deps",
            "--ignore-missing-deps",
            "--multi-release",
            "11",
            "-cp",
            os.pathsep.join(str(p) for p in class_path),
            *[str(p) for p in class_path],
        ],
        capture_output=True,
        text=True,
    )
    found = probe.stdout.strip().splitlines()[-1].strip() if probe.returncode == 0 and probe.stdout.strip() else ""
    if found:
        modules = ",".join(sorted(set(found.split(",")) | {"java.base", "java.logging"}))
    print(f"Java 実行環境のモジュール: {modules}")
    run(
        [
            str(jdk / "bin" / "jlink.exe"),
            "--add-modules",
            modules,
            "--strip-debug",
            "--no-header-files",
            "--no-man-pages",
            "--compress",
            "zip-6",
            "--output",
            str(out_dir),
        ]
    )


def jar_license_texts(jar: Path) -> str:
    """jar の中の META-INF/LICENSE.txt・NOTICE.txt（Apache 2.0 の許諾文と著作権表示）を取り出して1つの文字列にする。"""
    parts = []
    with zipfile.ZipFile(jar) as z:
        for name in z.namelist():
            if name.upper() in ("META-INF/LICENSE.TXT", "META-INF/NOTICE.TXT", "META-INF/LICENSE", "META-INF/NOTICE"):
                parts.append(f"--- {jar.name}: {name} ---\n" + z.read(name).decode("utf-8", errors="replace"))
    return "\n".join(parts)


def add_java(jdk_dir: str | None) -> None:
    """配布フォルダへ、Java 実行環境（_internal/java）と Jackcess の jar・補助の jar・ライセンス文（_internal/jackcess）を入れる。"""
    jdk = find_jdk(jdk_dir)
    jar_dir = INTERNAL / "jackcess"
    jar_dir.mkdir(parents=True, exist_ok=True)
    jars = fetch_jackcess_jars(jar_dir)
    helper = jar_dir / HELPER_JAR
    build_helper_jar(jdk, jars, helper)
    lic = jar_dir / "licenses"
    lic.mkdir(exist_ok=True)
    texts = {jar: jar_license_texts(jar) for jar in jars.values()}
    if not any("Apache License" in t for t in texts.values()):
        raise SystemExit("! Jackcess・Apache Commons の jar から Apache License 2.0 の許諾文を取り出せません")
    for jar, text in texts.items():
        if not text.strip():
            # jackcess の jar には META-INF/LICENSE・NOTICE が無い。著作権表示を補い、全文は commons の許諾文を指す
            text = (
                f"--- {jar.name} ---\n"
                "Jackcess: Copyright (c) Health Market Science, Inc. and the Jackcess contributors.\n"
                "Licensed under the Apache License, Version 2.0 (the full text is included in this file with Apache Commons).\n"
                "https://jackcess.sourceforge.io/\n"
            )
        (lic / (jar.stem + "-LICENSE.txt")).write_text(text, encoding="utf-8")
    make_java_runtime(jdk, [*jars.values(), helper], INTERNAL / "java")
    print(f"Java 実行環境と Jackcess を同梱: {INTERNAL / 'java'}・{jar_dir}")


def java_license_section() -> str:
    """THIRD-PARTY-LICENSES.txt に足す、Jackcess・Apache Commons・OpenJDK の許諾文（同梱していれば）。"""
    parts = []
    lic = INTERNAL / "jackcess" / "licenses"
    if lic.is_dir():
        parts.append(
            "=" * 78
            + "\nJackcess 4.0（Apache License 2.0）・Apache Commons Lang 3・Apache Commons Logging（Apache License 2.0）\n"
            + "Access の中身の対処で、ACE の無い .accdb を書き換えるために使う（別プロセスの Java として動かす）。\n"
            + "ソース: https://jackcess.sourceforge.io/ ・ https://commons.apache.org/\n"
            + "=" * 78
            + "\n"
            + "\n".join(p.read_text(encoding="utf-8") for p in sorted(lic.glob("*-LICENSE.txt")))
        )
    legal = INTERNAL / "java" / "legal"
    if (INTERNAL / "java").is_dir() and not (legal / "java.base" / "LICENSE").is_file():
        raise SystemExit(
            "! 同梱の Java 実行環境に許諾文（legal/java.base/LICENSE）がありません（GPL の許諾文を落とせません）"
        )
    if legal.is_dir():
        texts = []
        for name in ("LICENSE", "ASSEMBLY_EXCEPTION", "ADDITIONAL_LICENSE_INFO"):
            f = legal / "java.base" / name
            if f.is_file():
                texts.append(f"--- java.base/{name} ---\n" + f.read_text(encoding="utf-8", errors="replace"))
        parts.append(
            "=" * 78
            + "\nOpenJDK（Eclipse Temurin 21。GNU General Public License v2 + Classpath Exception）\n"
            + "同梱の Java 実行環境（_internal/java）。Jackcess の補助を動かす別プロセスとして使い、このツールとは結合しない。\n"
            + "ソース: https://github.com/adoptium/temurin21-binaries ・ https://github.com/openjdk/jdk21u\n"
            + "各モジュールの許諾文は _internal/java/legal にあります。\n"
            + "=" * 78
            + "\n"
            + "\n".join(texts)
        )
    return "\n\n".join(parts)


def check_java() -> None:
    """同梱した Java 実行環境と補助の jar が動くことを、実物で確かめる（空の入力で起動して「ok」が返るか）。"""
    java = INTERNAL / "java" / "bin" / "java.exe"
    jar_dir = INTERNAL / "jackcess"
    if not java.is_file():
        return
    cp = os.pathsep.join(str(p) for p in sorted(jar_dir.glob("*.jar")))
    # 空の .accdb を作って表の一覧を読むところまで動かす（jlink で削ったモジュールが足りないと、ここで落ちる）
    probe = DIST.parent / "check-java.accdb"
    probe.unlink(missing_ok=True)
    b64 = base64.b64encode(str(probe).encode("utf-8")).decode("ascii")
    out = subprocess.run(
        [str(java), "-cp", cp, "AccessRewrite"],
        input=f"create\t{b64}\ntables\nclose\n",
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    probe.unlink(missing_ok=True)
    if out.returncode != 0 or out.stdout.split() != ["ok", "end", "ok"]:
        raise SystemExit(f"! 同梱の Java 補助が起動しない（終了コード {out.returncode}）: {out.stdout}{out.stderr}")
    print("同梱の Java 補助の起動を確認")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--python32-zip", help="python-3.12.x-embed-win32.zip（無ければ python.org から取得）")
    ap.add_argument("--skip-python32", action="store_true")
    ap.add_argument("--jdk-dir", help="Temurin の JDK 21 のフォルダ（無ければ GitHub から取得してキャッシュへ置く）")
    ap.add_argument(
        "--skip-java",
        action="store_true",
        help="Java 実行環境と Jackcess を同梱しない（ACE の無い .accdb は書き換えられない）",
    )
    ap.add_argument(
        "--fetch-jackcess",
        action="store_true",
        help="開発・試験用に、Jackcess の jar を vendor/jackcess へ取り込んで終わる",
    )
    args = ap.parse_args()
    if args.fetch_jackcess:
        for name, path in fetch_jackcess_jars(ROOT / "vendor" / "jackcess").items():
            print(f"取り込み済み: {path}")
        return 0
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
    build_rust_extension()
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
    move_cmd_exe()
    copy_7zip()
    if not args.skip_java:
        add_java(args.jdk_dir)
    write_licenses()
    write_first_readme()
    if not args.skip_python32:
        add_python32(args.python32_zip)
    check_layout()
    check_rust_extension()
    check_java()
    print(f"\n完成: {DIST}")
    return 0


def build_rust_extension() -> None:
    """検出の中心の Rust 拡張を作って、この Python の環境へ入れる（PyInstaller がそれを exe に取り込む）。

    cargo・maturin が無い、またはビルドに失敗したときは警告だけ出して続ける（その exe は Python の経路で検出する）。
    入れ直す前の古い拡張が残っていて、それが exe に入ってしまわないよう、失敗したときは入っている拡張を外す。
    """
    sys.path.insert(0, str(ROOT / "tools"))
    import build_rust_ext

    if build_rust_ext.build_and_install():
        return
    subprocess.run([sys.executable, "-m", "pip", "uninstall", "-y", "pii_rs_detect"], capture_output=True)
    print("! Rust 拡張なしの exe を作ります（検出は Python の経路で動きます）")


def check_rust_extension() -> None:
    """Rust 拡張を入れて作ったときは、できた配布フォルダの中に拡張の本体（.pyd）が入っていることを確かめる。"""
    probe = subprocess.run([sys.executable, "-c", "import pii_rs_detect"], capture_output=True)
    found = sorted(str(p.relative_to(INTERNAL)) for p in INTERNAL.glob("**/pii_rs_detect*.pyd"))
    if probe.returncode == 0 and not found:
        raise SystemExit("! Rust 拡張を入れて作ったのに、配布フォルダに pii_rs_detect の .pyd がありません")
    print(f"Rust 拡張の同梱: {', '.join(found) if found else 'なし（Python の経路で動く exe）'}")


def move_cmd_exe() -> None:
    """コマンド版を cmd/ へ移し、一番上でダブルクリックできる exe をアプリ版の1つだけにする。"""
    CMD_DIR.mkdir(parents=True, exist_ok=True)
    shutil.move(str(DIST / CMD_EXE), str(CMD_DIR / CMD_EXE))


def check_layout() -> None:
    """できた配布フォルダの置き方を確かめる（親の _internal を読む設定は PyInstaller の文書に無い使い方なので、毎回実物で起動する）。"""
    top_exes = sorted(p.name for p in DIST.glob("*.exe"))
    if top_exes != ["PiiChecker.exe"]:
        raise SystemExit(f"! 一番上の exe がアプリ版の1つだけになっていない: {top_exes}")
    from pii_checker import __version__

    # 配布版の exe はパイプへの出力に PC の既定の文字コード（日本語の Windows なら cp932）を使う
    out = subprocess.run(
        [str(CMD_DIR / CMD_EXE), "--version"],
        capture_output=True,
        text=True,
        encoding=locale.getpreferredencoding(False),
        errors="replace",
    )
    if out.returncode != 0 or __version__ not in out.stdout:
        raise SystemExit(f"! cmd/{CMD_EXE} が起動しない（終了コード {out.returncode}）: {out.stdout}{out.stderr}")
    print(f"cmd/{CMD_EXE} の起動を確認: {out.stdout.strip()}")


if __name__ == "__main__":
    sys.exit(main())

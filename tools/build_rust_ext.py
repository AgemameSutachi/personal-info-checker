"""Rust 拡張 pii_rs_detect（本文の検出の中心）を作って、いま動かしている Python の環境へ入れる。

  python tools/build_rust_ext.py           … cargo と maturin があれば作って入れる（無ければ警告だけで終了コード 0）
  python tools/build_rust_ext.py --strict  … 作れなかったら終了コード 1（CI 用）

作れなくても本体は動く（detectors.py が Python の経路で検出する）。build.py が exe を作る前にも呼ぶ。
"""

from __future__ import annotations

import glob
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CRATE = os.path.join(ROOT, "rust", "pii_rs_detect")
WHEELS = os.path.join(CRATE, "target", "wheels")


def _warn(message: str) -> None:
    print(f"! Rust 拡張: {message}（Python の経路で動きます。検出の速さが下がります）")


def _find_maturin() -> list[str] | None:
    """maturin の起動コマンド。この Python の Scripts にあればそれ、無ければ python -m maturin、PATH にあればそれ。"""
    scripts = os.path.dirname(sys.executable)
    for name in ("maturin.exe", "maturin"):
        path = os.path.join(scripts, name)
        if os.path.isfile(path):
            return [path]
    probe = subprocess.run([sys.executable, "-m", "maturin", "--version"], capture_output=True, text=True)
    if probe.returncode == 0:
        return [sys.executable, "-m", "maturin"]
    found = shutil.which("maturin")
    return [found] if found else None


def build_and_install() -> bool:
    """wheel を作って入れる。入れられたら True。"""
    if not shutil.which("cargo"):
        _warn("cargo（Rust の道具）が見つかりません。https://rustup.rs/ から入れると使えます")
        return False
    maturin = _find_maturin()
    if maturin is None:
        _warn("maturin が見つかりません（python -m pip install -r requirements-dev.txt で入ります）")
        return False
    for old in glob.glob(os.path.join(WHEELS, "pii_rs_detect-*.whl")):
        os.remove(old)  # 古い版を拾わないように、作る前に空にする
    cmd = maturin + ["build", "--release", "-m", os.path.join(CRATE, "Cargo.toml"), "-i", sys.executable]
    print(">", " ".join(cmd))
    if subprocess.run(cmd).returncode != 0:
        _warn("maturin build が失敗しました")
        return False
    wheels = sorted(glob.glob(os.path.join(WHEELS, "pii_rs_detect-*.whl")), key=os.path.getmtime)
    if not wheels:
        _warn("wheel が見つかりません")
        return False
    # 同じ版の入れ直しは pip が黙って飛ばすので、先に外す（入っていなければ何も起きない）
    subprocess.run([sys.executable, "-m", "pip", "uninstall", "-y", "pii_rs_detect"], capture_output=True)
    cmd = [sys.executable, "-m", "pip", "install", "--no-deps", wheels[-1]]
    print(">", " ".join(cmd))
    if subprocess.run(cmd).returncode != 0:
        _warn("wheel を入れられませんでした")
        return False
    check = subprocess.run([sys.executable, "-c", "import pii_rs_detect"], capture_output=True)
    if check.returncode != 0:
        _warn("入れた拡張を読み込めません")
        return False
    # 食い違う文字の範囲を、ここで求めて同梱する（起動のたびに求めると約 0.15 秒かかる）
    if subprocess.run([sys.executable, os.path.abspath(__file__), "--write-guard"]).returncode != 0:
        _warn("食い違う文字の範囲の表を作れませんでした（起動時にその場で求めます）")
    print("Rust 拡張 pii_rs_detect を入れました")
    return True


GUARD_FILE = os.path.join(ROOT, "pii_checker", "_rust_guard.py")


def write_guard() -> None:
    """Python と Rust で語の文字・空白の判定が食い違う文字の範囲を求め、pii_checker/_rust_guard.py に書く。

    鍵（Python の Unicode データの版・拡張の Unicode の表の版）が実行時の環境と一致するときだけ使われる。
    """
    sys.path.insert(0, ROOT)
    import pii_rs_detect as ext
    from pii_checker import detectors

    ranges = detectors._rust_guard_ranges(ext)
    key = detectors._guard_key(ext)
    lines = [
        '"""tools/build_rust_ext.py が作る（Python と Rust で語の文字・空白の判定が食い違う文字の範囲）。リポジトリには入れない。"""',
        "",
        f"KEY = {tuple(key)!r}",
        "RANGES = (",
    ]
    lines += [f"    {tuple(r)!r}," for r in ranges]
    lines += [")", ""]
    with open(GUARD_FILE, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines))
    print(f"食い違う文字の範囲 {len(ranges)} 件を {GUARD_FILE} に書きました（鍵 {key}）")


if __name__ == "__main__":
    if "--write-guard" in sys.argv:
        write_guard()
        sys.exit(0)
    ok = build_and_install()
    sys.exit(0 if ok or "--strict" not in sys.argv else 1)

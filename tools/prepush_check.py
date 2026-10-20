"""push の前に、CI（.github/workflows/test.yml）と同じ確かめを手元で流す。

  python tools/prepush_check.py          # 全部（約8分）
  python tools/prepush_check.py --quick  # 依存の版と書式だけ（数秒）

git の pre-push フックから呼ぶと、落ちたときに push を止める（docs/開発者向け.md の「試験」の節）。
CI が落ちると持ち主へメールが届くので、手元で落ちるものは手元で止める。
確かめること:
  1. 試すのが push する中身と同じか（追跡しているファイルに、コミットしていない変更が無いか）
  2. 入っている依存の版が constraints.txt（CI が入れる版）と同じか
  3. 書式（black --check。CI と同じ対象）
  4. 試験（pytest。CI と同じく tests 全部）
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import time
from importlib import metadata
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# CI と同じ対象（.github/workflows/test.yml の「書式（black）」と同じにしておくこと）
BLACK_TARGETS = ["pii_checker", "tests", "tools", "build.py", "entry_app.py", "entry_cli.py"]


def _say(msg: str) -> None:
    print(f"[push 前の確かめ] {msg}", flush=True)


def check_clean_tree() -> list[str]:
    """コミットしていない変更があれば、その一覧を返す（試すものと push するものがずれるため）。

    追跡しているファイルの変更に加え、試験やコードの置き場（pii_checker・tests・tools）の追跡していない .py も数える
    （add し忘れた試験は手元では流れても CI には無い）。ほかの追跡していないもの（メモ・作業の残り）は見ない。
    """
    out = subprocess.run(
        ["git", "-C", str(ROOT), "status", "--porcelain", "--untracked-files=all", "--", "."],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    ).stdout
    found = []
    for ln in out.splitlines():
        if not ln.strip():
            continue
        if ln.startswith("??"):
            path = ln[3:].strip().strip('"')
            if not (path.endswith(".py") and path.split("/", 1)[0] in ("pii_checker", "tests", "tools")):
                continue
        found.append(ln)
    return found


def check_versions() -> list[str]:
    """constraints.txt の版と、いま入っている版の食い違いを返す。"""
    problems = []
    for line in (ROOT / "constraints.txt").read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        m = re.fullmatch(r"([A-Za-z0-9_.\-]+)==(\S+)", line)
        if not m:
            continue
        name, want = m.groups()
        try:
            have = metadata.version(name)
        except metadata.PackageNotFoundError:
            problems.append(f"{name}: 入っていない（CI は {want} を入れる）")
            continue
        if have != want:
            problems.append(f"{name}: 手元は {have}、CI は {want}")
    return problems


def run(cmd: list[str], label: str) -> bool:
    _say(f"{label} …")
    started = time.monotonic()
    code = subprocess.run(cmd, cwd=ROOT).returncode
    _say(f"{label}: {'通った' if code == 0 else '落ちた'}（{time.monotonic() - started:.0f} 秒）")
    return code == 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--quick", action="store_true", help="依存の版と書式だけ確かめる（試験は流さない）")
    args = ap.parse_args()

    dirty = check_clean_tree()
    if dirty:
        _say(
            "コミットしていない変更があります。試す中身と push する中身がずれるので、コミットするか退避してから push してください:"
        )
        for ln in dirty:
            print("    " + ln)
        return 1

    problems = check_versions()
    if problems:
        _say("入っている依存の版が CI と違います（手元で通っても CI で落ちることがあります）:")
        for p in problems:
            print("    " + p)
        _say(
            "手元を constraints.txt の版にそろえるか、上げた版で全部の試験を通してから constraints.txt を書き直してください"
        )
        return 1
    _say("依存の版: CI と同じ")

    if not run([sys.executable, "-m", "black", "--check", "-q", *BLACK_TARGETS], "書式（black）"):
        _say(f"直すには: {Path(sys.executable).name} -m black {' '.join(BLACK_TARGETS)}")
        return 1
    if args.quick:
        return 0
    if not run([sys.executable, "-m", "pytest", "tests", "-q", "-x", "-p", "no:cacheprovider"], "試験（pytest）"):
        return 1
    _say("すべて通りました。push します")
    return 0


if __name__ == "__main__":
    sys.exit(main())

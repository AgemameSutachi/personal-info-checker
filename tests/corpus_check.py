"""検体（make_corpus.py の出力）を検査エンジンに掛け、manifest の期待と突き合わせる。

使い方: python tests/corpus_check.py <検体フォルダ> [--password secret123] [--only 部分文字列]
期待との食い違い（見逃し・誤検出・状態の違い）を一覧にし、食い違いがあれば終了コード 1。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pii_checker.engine import scan_file  # noqa: E402
from pii_checker.models import PasswordBook, ScanOptions, Status  # noqa: E402

# 期待の種類のうち、この種類が見つかれば「その値を見つけた」とみなす（言い換えの許容）
ALIASES = {"postal_code": {"postal_code", "address"}}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus")
    ap.add_argument("--password", action="append", default=[])
    ap.add_argument("--only", default="")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    root = Path(args.corpus)
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    entries = [e for e in manifest["entries"] if args.only in e["path"]]
    by_top: dict[str, list[dict]] = {}
    for e in entries:
        if e.get("skipped"):
            continue
        top = e["path"].split("!", 1)[0]
        by_top.setdefault(top, []).append(e)
    opts = ScanOptions()
    book = PasswordBook(common=args.password)
    problems = 0
    for top, exps in sorted(by_top.items()):
        path = str(root / top)
        if (root / top).is_dir():
            # フォルダ単位の期待（pg_dump の directory 形式など）は、中の全ファイルの結果をまとめて見る
            from pii_checker.models import FileResult

            merged = []
            for p in sorted((root / top).rglob("*")):
                if p.is_file():
                    merged += scan_file(str(p), opts, book).items
            res = FileResult(path, merged)
        else:
            res = scan_file(path, opts, book)
        items = {i.path: i for i in res.items}
        for e in exps:
            disp = str(root / e["path"].split("!", 1)[0])
            if "!" in e["path"]:
                inner = e["path"].split("!", 1)[1]
                cands = [
                    i for p, i in items.items() if p.startswith(disp + "!") and p.replace("\\", "/").endswith(inner)
                ]
                group = cands
            else:
                group = res.items
            found = set()
            for it in group:
                found |= set(it.finding_counts)
            statuses = {i.status for i in group}
            expect = e["expect"]
            msg = ""
            if expect == "detect":
                missing = [k for k in e.get("kinds", []) if not (ALIASES.get(k, {k}) & found)]
                residue = "削除済み" in e.get("note", "")
                if not group:
                    msg = "項目が見つからない"
                elif residue and found:
                    # 削除済みレコードは値が区切りなしで連結して残り、日付型はバイナリなので全種類は拾えない。
                    # ファイルが「個人情報あり」と旗を立てられれば目的は果たせる
                    msg = ""
                elif missing:
                    msg = f"見逃し {missing}"
            elif expect == "clean":
                if found:
                    msg = f"誤検出 {sorted(found)}"
            elif expect == "uncheckable":
                if not (statuses & {Status.NEEDS_PASSWORD, Status.UNCHECKABLE}) and not args.password:
                    msg = f"検査不能になるべきが {sorted(s.value for s in statuses)}"
            elif expect == "partial":
                # 内部形式の分からないもの（Oracle ダンプ等）は「簡易検査」か「検査不能」と正直に出ること。
                # 「検査済み」と出たら、言い切れないものを言い切ったことになるので食い違いとする
                if not (statuses & {Status.PARTIAL, Status.UNCHECKABLE}):
                    msg = f"簡易検査・検査不能になるべきが {sorted(s.value for s in statuses)}"
                elif Status.PARTIAL in statuses and not found:
                    msg = "簡易検査で文字列型の値も見つけられなかった"
            bad = bool(msg)
            problems += bad
            if bad or args.verbose:
                print(f"{'NG' if bad else 'OK'} {e['path']} [{expect}] {msg}")
                for it in group:
                    print(
                        f"     - {it.status.value:14} {it.kind} | {it.path[len(str(root)) + 1:]} | {it.reason[:150]} | {dict(it.finding_counts)}"
                    )
        if args.verbose:
            print(f"   ({res.elapsed:.1f}s)")
    print(f"\n食い違い {problems} 件 / 期待 {sum(len(v) for v in by_top.values())} 件")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())

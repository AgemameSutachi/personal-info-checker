"""結果 DB の files の時間の内訳（elapsed・save_elapsed・wall_elapsed）を集計して、検査の遅さの原因を確かめる。

大きな検査の後に「時間が検査そのものか・保存か・配る側の待ちか」を見るための道具（docs/開発者向け.md の「検査の速さ」）。
DB は読み取り専用で開くので、検査の途中の DB にも当ててよい（WAL なので書き手を止めない）。

使い方: python tools/scan_timing.py <jobs.sqlite3> <ジョブID> [--workers 8] [--top 10] [--after 20]
  --workers  検査に使ったワーカーの数（稼働の割合＝検査の時間の合計÷（かかった時間×本数）を出す）
  --top      保存の長いファイルを何件並べるか
  --after    保存の長いファイルの直後の何件で「配ってから受け取るまでの待ち」を見るか
  --gap      受け取りの間がこの秒数を超えて空いた区間を、止めていた時間として除く（既定 300）
"""

import argparse
import sqlite3
import statistics
import sys
from contextlib import closing
from pathlib import Path

# 保存が長いとみなす秒（store.SAVE_RECHECK_SECONDS と同じ。これ以上のときだけ確定の書き込みを含めて書き直される）
LONG_SAVE_SECONDS = 0.5


def open_readonly(path: str) -> sqlite3.Connection:
    """DB を読み取り専用で開く。無いファイルを新しく作らない。"""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"結果 DB が見つかりません: {path}")
    con = sqlite3.connect(p.resolve().as_uri() + "?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    return con


def load_rows(con: sqlite3.Connection, job_id: str) -> list[sqlite3.Row]:
    """実際に中身を検査した行（使い回し・古い版の行＝時間の内訳が NULL のものを除く）を、受け取った順に返す。"""
    cols = {r["name"] for r in con.execute("PRAGMA table_info(files)")}
    if "wall_elapsed" not in cols:
        raise ValueError("この DB は時間の内訳（save_elapsed・wall_elapsed）を記録する前の版です")
    return con.execute(
        "SELECT top_path, size, elapsed, save_elapsed, wall_elapsed, scanned_at, n_findings FROM files"
        " WHERE job_id=? AND state='done' AND wall_elapsed IS NOT NULL AND scanned_at IS NOT NULL"
        " ORDER BY scanned_at",
        (job_id,),
    ).fetchall()


def summarize(rows: list, workers: int | None = None, top: int = 10, after: int = 20, gap: float = 300.0) -> dict:
    """時間の内訳をまとめる。rows は scanned_at の順（load_rows の形）。

    受け取りの間が gap 秒を超えて空いた区間は、止めていた時間（中断して続きから再開したジョブ）とみなして
    かかった時間から除く（稼働の割合がその分低く出ないように）。
    """
    if not rows:
        return {"files": 0}
    whole = rows[-1]["scanned_at"] - rows[0]["scanned_at"]
    steps = [b["scanned_at"] - a["scanned_at"] for a, b in zip(rows, rows[1:])]
    paused = [d for d in steps if d > gap]
    span = whole - sum(paused)
    work = sum(r["elapsed"] or 0.0 for r in rows)
    save = sum(r["save_elapsed"] or 0.0 for r in rows)
    # 配ってから受け取るまでの秒のうち、ワーカーの中の検査の時間でない分（待ち行列・起動・保存による受け取り待ち）
    waits = [max(0.0, (r["wall_elapsed"] or 0.0) - (r["elapsed"] or 0.0)) for r in rows]
    out = {
        "files": len(rows),
        "whole": whole,
        "paused": sum(paused),
        "pauses": len(paused),
        "span": span,
        "work": work,
        "save": save,
        "wait": sum(waits),
        "wait_median": statistics.median(waits),
        "busy": work / (span * workers) if workers and span > 0 else None,
        "save_share": save / span if span > 0 else None,
    }
    longest = sorted(range(len(rows)), key=lambda i: rows[i]["save_elapsed"] or 0.0, reverse=True)[:top]
    out["long_saves"] = [
        {
            "path": rows[i]["top_path"],
            "save": rows[i]["save_elapsed"] or 0.0,
            "findings": rows[i]["n_findings"],
            "size": rows[i]["size"],
        }
        for i in longest
        if (rows[i]["save_elapsed"] or 0.0) > 0
    ]
    # 保存の長いファイルの直後に、待ちが伸びているか（保存の間は新しく配れないので、ワーカーが空く見立て）
    marks = [i for i, r in enumerate(rows) if (r["save_elapsed"] or 0.0) >= LONG_SAVE_SECONDS]
    following = [w for i in marks for w in waits[i + 1 : i + 1 + after]]
    out["long_save_count"] = len(marks)
    out["wait_after_long_save"] = statistics.median(following) if following else None
    return out


def _fmt(sec: float | None) -> str:
    return "-" if sec is None else f"{sec:,.1f} 秒"


def report(s: dict, after: int) -> str:
    """summarize の結果を人が読む文にする。"""
    if not s["files"]:
        return "時間の内訳が記録された行がありません（使い回しだけのジョブ・古い版の検査・ジョブ ID の誤り）"
    lines = [
        f"検査した行 {s['files']:,} 件・最初から最後の受け取りまで {_fmt(s['whole'])}"
        + (
            f"（受け取りが長く空いた {s['pauses']} 区間 {_fmt(s['paused'])} を除いて {_fmt(s['span'])}）"
            if s["pauses"]
            else ""
        ),
        f"ワーカーの中の検査の時間の合計 {_fmt(s['work'])}"
        + (f"（稼働 {s['busy']:.0%}）" if s["busy"] is not None else "（--workers を付けると稼働の割合を出す）"),
        f"保存の時間の合計 {_fmt(s['save'])}"
        + (f"（本体のスレッドの {s['save_share']:.0%}）" if s["save_share"] is not None else ""),
        # 待ちには、配ってある workers×4 件の順番待ちも入る（合計はかかった時間より大きくなる）
        f"配ってから受け取るまでの待ち（順番待ちを含む）の合計 {_fmt(s['wait'])}・1件の中央値 {_fmt(s['wait_median'])}",
        f"保存が {LONG_SAVE_SECONDS} 秒以上の行 {s['long_save_count']:,} 件・その直後 {after} 件の待ちの中央値"
        f" {_fmt(s['wait_after_long_save'])}（全体の中央値と比べる）",
    ]
    if s["long_saves"]:
        lines.append("保存の長いファイル:")
        for r in s["long_saves"]:
            lines.append(f"  {r['save']:8.1f} 秒  検出 {r['findings'] or 0:>9,}  {r['path']}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="結果 DB の時間の内訳を集計する")
    ap.add_argument("db")
    ap.add_argument("job_id")
    ap.add_argument("--workers", type=int)
    ap.add_argument("--top", type=int, default=10)
    ap.add_argument("--after", type=int, default=20)
    ap.add_argument("--gap", type=float, default=300.0)
    a = ap.parse_args(argv)
    try:
        with closing(open_readonly(a.db)) as con:
            rows = load_rows(con, a.job_id)
    except (OSError, ValueError, sqlite3.Error) as e:
        print(f"読めませんでした: {e}", file=sys.stderr)
        return 1
    print(report(summarize(rows, a.workers, a.top, a.after, a.gap), a.after))
    return 0


if __name__ == "__main__":
    sys.exit(main())

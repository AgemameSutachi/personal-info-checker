"""結果 DB の files の時間の内訳（elapsed・save_elapsed・wall_elapsed）を集計して、検査の遅さの原因を確かめる。

大きな検査の後に「時間が検査そのものか・保存か・配る側の待ちか」を見るための道具（docs/開発者向け.md の「検査の速さ」）。
DB は読み取り専用で開くので、検査の途中の DB にも当ててよい（WAL なので書き手を止めない）。

使い方: python tools/scan_timing.py <jobs.sqlite3> <ジョブID> [--workers 8] [--top 10] [--after 20]
  --workers  検査に使ったワーカーの数（稼働の割合＝検査の時間の合計÷（動いていた時間×本数）を出す）
  --top      保存の長いファイルを何件並べるか
  --after    保存の長いファイルの直後の何件で「配ってから受け取るまでの待ち」を見るか

動いていた時間は、各ファイルが手元を離れていた区間（受け取った時刻 − 配ってから受け取るまでの秒 〜 受け取った時刻）を
重ねた長さ。どのファイルも配られていない区間（中断して続きから再開したジョブの止めていた間）は入らず、
大きなファイルだけが長く走っていた区間は入る。
"""

import argparse
import sqlite3
import statistics
import sys
from contextlib import closing
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pii_checker.store import SAVE_RECHECK_SECONDS  # noqa: E402

# 止めていた間として数えて出す、どのファイルも配られていない区間の長さ（秒）
HOLE_SECONDS = 60.0


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


def active_time(rows: list) -> tuple[float, float, int, float]:
    """(最初に配ってから最後に受け取るまで, 動いていた時間, 止めていた区間の数, その合計) を返す。"""
    spans = sorted((r["scanned_at"] - (r["wall_elapsed"] or 0.0), r["scanned_at"]) for r in rows)
    first, end = spans[0]
    active = 0.0
    holes = []
    for a, b in spans[1:]:
        if a > end:
            active += end - first
            holes.append(a - end)
            first, end = a, b
        else:
            end = max(end, b)
    active += end - first
    whole = max(b for _, b in spans) - spans[0][0]
    long_holes = [h for h in holes if h >= HOLE_SECONDS]
    return whole, active, len(long_holes), sum(long_holes)


def summarize(rows: list, workers: int | None = None, top: int = 10, after: int = 20) -> dict:
    """時間の内訳をまとめる。rows は scanned_at の順（load_rows の形）。"""
    if not rows:
        return {"files": 0}
    whole, span, pauses, paused = active_time(rows)
    work = sum(r["elapsed"] or 0.0 for r in rows)
    save = sum(r["save_elapsed"] or 0.0 for r in rows)
    # 配ってから受け取るまでの秒のうち、ワーカーの中の検査の時間でない分（順番待ち・起動・保存による受け取り待ち）
    waits = [max(0.0, (r["wall_elapsed"] or 0.0) - (r["elapsed"] or 0.0)) for r in rows]
    out = {
        "files": len(rows),
        "whole": whole,
        "paused": paused,
        "pauses": pauses,
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
    # 保存の長いファイルの直後に、待ちが伸びているか（保存の間は新しく配れないので、ワーカーが空く見立て）。
    # 近くに保存の長い行が続いても、直後の行は1回だけ数える
    marks = [i for i, r in enumerate(rows) if (r["save_elapsed"] or 0.0) >= SAVE_RECHECK_SECONDS]
    following = sorted({j for i in marks for j in range(i + 1, min(i + 1 + after, len(rows)))})
    out["long_save_count"] = len(marks)
    out["wait_after_long_save"] = statistics.median(waits[j] for j in following) if following else None
    return out


def _fmt(sec: float | None) -> str:
    return "-" if sec is None else f"{sec:,.1f} 秒"


def report(s: dict, after: int) -> str:
    """summarize の結果を人が読む文にする。"""
    if not s["files"]:
        return "時間の内訳が記録された行がありません（使い回しだけのジョブ・古い版の検査・ジョブ ID の誤り）"
    lines = [
        f"検査した行 {s['files']:,} 件・最初に配ってから最後に受け取るまで {_fmt(s['whole'])}"
        + (
            f"（どのファイルも配られていない {s['pauses']} 区間 {_fmt(s['paused'])} を除くと {_fmt(s['span'])}）"
            if s["pauses"]
            else f"（動いていた時間 {_fmt(s['span'])}）"
        ),
        f"ワーカーの中の検査の時間の合計 {_fmt(s['work'])}"
        + (f"（稼働 {s['busy']:.0%}）" if s["busy"] is not None else "（--workers を付けると稼働の割合を出す）"),
        f"保存の時間の合計 {_fmt(s['save'])}"
        + (
            f"（動いていた時間の {s['save_share']:.0%}。本体のスレッドのうち保存だけの割合）"
            if s["save_share"] is not None
            else ""
        ),
        # 待ちには、配ってある workers×4 件の順番待ちも入る（合計は動いていた時間より大きくなる）
        f"配ってから受け取るまでの待ち（順番待ちを含む）の合計 {_fmt(s['wait'])}",
        f"1件の待ちの中央値: 全体 {_fmt(s['wait_median'])}・保存が {SAVE_RECHECK_SECONDS} 秒以上の行"
        f"（{s['long_save_count']:,} 件）の直後 {after} 件 {_fmt(s['wait_after_long_save'])}",
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
    a = ap.parse_args(argv)
    try:
        with closing(open_readonly(a.db)) as con:
            rows = load_rows(con, a.job_id)
    except (OSError, ValueError, sqlite3.Error) as e:
        print(f"読めませんでした: {e}", file=sys.stderr)
        return 1
    print(report(summarize(rows, a.workers, a.top, a.after), a.after))
    return 0


if __name__ == "__main__":
    sys.exit(main())

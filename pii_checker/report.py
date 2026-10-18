"""レポートの出力（Excel・CSV）。

Excel のシート:
  1. 判定 … 総合判定・言い切れない理由・数字・設定・読み方
  2. 要対応 … 要パスワード・検査不能・簡易検査・読めなかったフォルダ（言い切るために潰すべきもの）
  3. ファイル別 … 実ファイル1件ずつの最終状態・危険度・報告の目安・異なる値・誰が読めるか・種類ごとの件数（監査の証跡）
  4. 前回との違い … 同じ検査先の前回の検査と比べて、新しく見つかった・無くなった・件数が増えた／減ったファイル
  5. 検出明細 … 検出1件ずつ（値はマスク済み）
  6. 全項目 … アーカイブの中身・埋め込みまで含めた全項目の状態と読み方
"""

from __future__ import annotations

import csv
import json
import os
import time
from contextlib import contextmanager
from pathlib import Path

from openpyxl import Workbook
from openpyxl.cell import WriteOnlyCell
from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
from openpyxl.styles import Alignment, Font, PatternFill

from . import __version__, folderacl, jobdiff, reportflags
from .detectors import PII_TYPES
from .models import STATUS_LABELS, Confidence, Status
from .store import Store
from .userrules import rule_names
from .verdict import decide

CONF_LABELS = {c.value: c.label for c in Confidence}
STATUS_JA = {s.value: label for s, label in STATUS_LABELS.items()}
HEADER_FILL = PatternFill("solid", fgColor="1F4E78")
HEADER_FONT = Font(color="FFFFFF", bold=True)
LEVEL_FILL = {
    "found": "F8CBAD",
    "undetermined": "FFE699",
    "low_only": "FFF2CC",
    "clean_partial": "DDEBF7",
    "clean": "C6EFCE",
    "running": "EDEDED",
    "empty": "E4DFEC",
}
STATE_JA = {
    "running": "実行中",
    "done": "完了",
    "cancelled": "中止",
    "interrupted": "中断",
    "error": "エラー",
    "created": "準備中",
}


def _size(b):
    """大きさを KB の数値にする（並べ替え・絞り込みができるよう文字にしない）。"""
    if b is None or b == "":
        return ""
    return round(float(b) / 1024, 1)


def _display_width(text: str) -> int:
    """Excel の列幅の目安（全角は2文字分）。"""
    return sum(2 if ord(c) > 0x2E7F else 1 for c in str(text))


def _sheet(wb, name: str, widths: list[int]):
    """表のシート: 列幅・見出し行の固定を先に決める（書き込み専用モードでは行を足す前に設定する）。"""
    from openpyxl.utils import get_column_letter

    ws = wb.create_sheet(name)
    ws._piichk_widths = {}
    for i, w in enumerate(widths, start=1):
        ws.column_dimensions[get_column_letter(i)].width = w
        ws._piichk_widths[i] = w
    ws.freeze_panes = "A2"
    ws._piichk_rows = 0
    ws._piichk_cols = len(widths)
    return ws


def _finish(ws) -> None:
    """表のシートにフィルターを付ける。"""
    from openpyxl.utils import get_column_letter

    ws.auto_filter.ref = f"A1:{get_column_letter(ws._piichk_cols)}{max(1, ws._piichk_rows)}"


def _safe(v):
    """Excel に書ける形にする（制御文字を除き、= で始まる文字列を数式として扱わせない）。"""
    if v is None:
        return ""
    if isinstance(v, str):
        v = ILLEGAL_CHARACTERS_RE.sub("", v)
        if v[:1] in ("=", "+", "-", "@") and len(v) > 1:
            v = "'" + v
        return v[:32000]
    return v


def _row(ws, values, bold=False, fill=None):
    if bold and hasattr(ws, "_piichk_widths"):
        # 見出しが切れないよう、見出しの長さ（＋フィルターのボタン分）より列幅を狭くしない
        from openpyxl.utils import get_column_letter

        for i, v in enumerate(values, start=1):
            need = _display_width(v) + 4
            if need > ws._piichk_widths.get(i, 0):
                ws.column_dimensions[get_column_letter(i)].width = need
    cells = []
    for v in values:
        c = WriteOnlyCell(ws, value=_safe(v))
        if bold:
            c.font = HEADER_FONT
            c.fill = HEADER_FILL
        elif fill:
            c.fill = PatternFill("solid", fgColor=fill)
        cells.append(c)
    ws.append(cells)
    if hasattr(ws, "_piichk_rows"):
        ws._piichk_rows += 1


def _ts(t):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t)) if t else ""


DIFF_WHERE = "「前回との違い」（Excel はシート、画面は結果の表のタブ・レポートの頁は下の節）"


def overview_rows(job: dict, summary: dict, diff: dict | None = None) -> list[tuple[str, object]]:
    """「判定」の概要の表（Excel の判定シートと Web のレポートで同じものを出す）。

    diff は jobdiff.compute の結果（渡せば「前回との違い」の要約を、一覧へのたどり方つきで載せる）。
    """
    rows: list[tuple[str, object]] = [
        ("ジョブ", job["id"]),
        ("検査対象", "\n".join(job["roots"])),
        ("開始", _ts(job["started"])),
        ("終了", _ts(job["finished"])),
        ("状態", STATE_JA.get(job["state"], job["state"])),
        ("列挙したファイル数", summary["files_total"]),
        ("結果のあるファイル数", summary["files_done"]),
        (
            "列挙と結果の一致",
            (
                "一致"
                if summary["files_total"] == summary["files_done"]
                else f"不一致（未検査 {summary['files_total'] - summary['files_done']} 件）"
            ),
        ),
        ("前回の結果を使ったファイル", summary.get("reused", 0)),
    ]
    for s in Status:
        rows.append((f"項目の状態: {s.label}", summary["item_status"].get(s.value, 0)))
    rows += [
        ("読めなかったフォルダ", summary["folder_errors"]),
        ("辿らなかったリンク", summary["links"]),
        ("個人情報の可能性があるファイル", summary["files_with_findings"]),
    ]
    for k, label in PII_TYPES.items():
        if summary["types"].get(k):
            rows.append((f"検出件数: {label}", summary["types"][k]))
    # 漏えい時の報告の目安（印ごとのファイル数。目安であり法的な判断ではない＝読み方に出典と一緒に書く）
    flags = summary.get("flags") or {}
    for f in reportflags.FLAG_ORDER:
        rows.append((f"報告の目安: {reportflags.FLAG_LABELS[f]}", f"{flags.get(f, 0):,} ファイル"))
    access = summary.get("access") or {}
    rows.append(("広く読めるフォルダにある、個人情報の可能性があるファイル", access.get(folderacl.BROAD, 0)))
    if access.get(folderacl.UNKNOWN) or access.get(folderacl.FTP):
        rows.append(
            (
                "誰が読めるかを取れなかった、個人情報の可能性があるファイル",
                access.get(folderacl.UNKNOWN, 0) + access.get(folderacl.FTP, 0),
            )
        )
    if diff is not None:
        rows.append(("前回との違い", jobdiff.summary_text(diff, DIFF_WHERE)))
    opts = job["options"]
    rows += [
        ("設定: OCR", "する" if opts.get("ocr") else "しない"),
        ("設定: 生データ走査", "する" if opts.get("raw_sweep") else "しない"),
        ("設定: イメージの未使用領域", "走査する" if opts.get("deep_image_sweep") else "走査しない"),
        ("設定: 前回の結果の使い回し", "する" if opts.get("reuse", True) else "しない（全部読み直す）"),
    ]
    # 許可リストの値そのものは出さない（自社の電話番号などを、レポートの渡し先へ広めないため）。件数だけ
    n_allow = len(opts.get("allow_values") or [])
    names = rule_names(opts.get("custom_rules"))
    rows.append(("設定: 許可リスト", f"{n_allow:,} 件" if n_allow else "なし"))
    if n_allow or summary.get("allowed"):
        rows.append(("許可リストで外した検出", summary.get("allowed", 0)))
    rows.append(("設定: 利用者の規則", f"{len(names)} 件（{'、'.join(names)}）" if names else "なし"))
    rows += [
        ("ツール", f"個人情報チェッカー {__version__}"),
        ("出力日時", _ts(time.time())),
    ]
    return rows


def reading_notes(job: dict) -> list[str]:
    """レポートの読み方の注意（Excel と Web で同じ）。"""
    n = job["options"].get("max_samples_per_type", 20)
    return [
        "検出値はマスクしてある（元の値はこのレポートにも DB にも残していない）。場所の欄で元ファイルの位置を示す。"
        "ファイルのパスと名前は伏せていない。",
        "「簡易検査」は形式を解釈できず文字として読める部分だけを見たもの。「対象外」は文字情報を持たない形式。",
        f"検出明細は、1つの項目につき種類と確度ごとに最大 {n} 件の見本。件数（検出件数）は全数を数えて判定している。",
        "このレポート自体もファイルの場所や検出の有無という機密を含むため、取り扱いに注意すること。",
        "「報告の目安」は" + reportflags.NOTE + "。根拠: " + "／".join(reportflags.SOURCES) + "。",
        "「異なる値」は、同じ値（全角半角・空白・ハイフンの違い、氏名の敬称は無視）を1つと数えた数（確度 中以上）。"
        "値そのものは残していない。" + reportflags.PEOPLE_NOTE + "。",
        "「誰が読めるか」は、検出のあったファイルの親フォルダのアクセス権で、Everyone・Authenticated Users・"
        "BUILTIN\\Users・Domain Users などに読み取りが許されていれば「広く読める」とした（目安。共有のアクセス許可・"
        "ファイル個別の設定・グループの入れ子までは見ていない）。危険度は変えていない。",
    ]


def file_mark_cells(r) -> list:
    """ファイル別の表の「報告の目安・異なる値・誰が読めるか」の列（files の行から）。検出が無いファイルは空。"""
    if not r["n_findings"]:
        return ["", "", "", "", "", "", "", ""]
    distinct_json = r["distinct_counts"]
    mine = ""
    if distinct_json is not None:
        mine = reportflags.distinct_medium(json.loads(distinct_json or "{}")).get("my_number", 0)
    access = r["access"]
    return [
        "・".join(reportflags.labels(r["flags"])),
        r["people_n"] if r["people_n"] is not None and r["people_type"] else "",
        reportflags.type_label(r["people_type"]) if r["people_type"] else "",
        mine,
        reportflags.distinct_text(distinct_json),
        folderacl.LABELS.get(access, "") if access else "",
        r["access_who"] or "",
        r["access_owner"] or "",
    ]


def write_xlsx(store: Store, job_id: str, out_path: str) -> str:
    job = store.job(job_id)
    if not job:
        raise ValueError(f"ジョブ {job_id} が見つからない")
    summary = store.summary(job_id)
    v = decide(summary, job["state"], target="excel")
    wb = Workbook(write_only=True)

    # 1. 判定
    ws = wb.create_sheet("判定")
    ws.column_dimensions["A"].width = 26
    ws.column_dimensions["B"].width = 110
    title = WriteOnlyCell(ws, value=f"総合判定: {v.title}")
    title.font = Font(bold=True, size=16)
    title.fill = PatternFill("solid", fgColor=LEVEL_FILL.get(v.level, "FFFFFF"))
    ws.append([title])
    ws.append([])
    for line in v.detail:
        ws.append(["", _safe(line)])
    ws.append([])
    if v.next_step:
        nxt = WriteOnlyCell(ws, value=_safe("次にすること: " + v.next_step))
        nxt.font = Font(bold=True)
        ws.append(["", nxt])
    ws.append([])
    _row(ws, ["項目", "値"], bold=True)
    diff = jobdiff.compute(store, job_id)
    for k, val in overview_rows(job, summary, diff):
        ws.append([_safe(k), _safe(val)])
    ws.append([])
    for i, note in enumerate(reading_notes(job)):
        ws.append(["読み方" if i == 0 else "", note])

    # 2. 要対応
    ws = _sheet(wb, "要対応", [16, 80, 26, 70, 11])
    _row(ws, ["区分", "パス", "形式", "理由・対処", "大きさ(KB)"], bold=True)
    order = {"needs_password": 0, "uncheckable": 1, "pending": 2, "partial": 3}
    for r in store.query(
        "SELECT status, path, kind, reason, size FROM items WHERE job_id=? AND status IN ('needs_password','uncheckable','pending','partial') ORDER BY path",
        (job_id,),
    ):
        _row(
            ws,
            [STATUS_JA.get(r["status"], r["status"]), r["path"], r["kind"], r["reason"], _size(r["size"])],
            fill={"needs_password": "FFE699", "uncheckable": "F8CBAD", "partial": "DDEBF7"}.get(r["status"]),
        )
    for r in store.query("SELECT top_path FROM files WHERE job_id=? AND state='pending'", (job_id,)):
        _row(ws, ["未検査", r["top_path"], "", "まだ検査していない（中断した等）。再開すると検査する", ""])
    for r in store.query("SELECT path, kind, reason FROM folder_errors WHERE job_id=? ORDER BY path", (job_id,)):
        _row(
            ws,
            ["読めなかったフォルダ" if r["kind"] == "error" else "リンク", r["path"], "", r["reason"], ""],
            fill="F8CBAD" if r["kind"] == "error" else None,
        )
    _finish(ws)

    # 3. ファイル別
    type_keys = list(PII_TYPES)
    ws = _sheet(wb, "ファイル別", [80, 12, 8, 10, 40, 12, 14, 12, 40, 22, 30, 24] + [9] * len(type_keys) + [11, 19, 10])
    _row(
        ws,
        ["パス", "最終状態", "危険度", "検出件数"]
        + [
            "報告の目安（目安・法的な判断ではない）",
            "人数の目安",
            "人数の目安の種類",
            "異なるマイナンバー",
            "異なる値（確度 中以上）",
            "誰が読めるか",
            "読める人・読めなかった理由",
            "フォルダの所有者",
        ]
        + [PII_TYPES[k] for k in type_keys]
        + ["大きさ(KB)", "更新日時", "検査時間(秒)"],
        bold=True,
    )
    counts_by_top: dict[str, dict[str, int]] = {}
    for r in store.query("SELECT top_path, counts FROM items WHERE job_id=? AND counts != '{}'", (job_id,)):
        d = counts_by_top.setdefault(r["top_path"], {})
        for k, n in json.loads(r["counts"]).items():
            d[k] = d.get(k, 0) + n
    for r in store.query("SELECT * FROM files WHERE job_id=? ORDER BY top_path", (job_id,)):
        c = counts_by_top.get(r["top_path"], {})
        fill = {"高": "F8CBAD", "中": "FCE4D6", "低": "FFF2CC"}.get(r["risk"] or "")
        _row(
            ws,
            [r["top_path"], STATUS_JA.get(r["worst_status"] or "pending", "未検査"), r["risk"] or "", r["n_findings"]]
            + file_mark_cells(r)
            + [c.get(k, "") for k in type_keys]
            + [_size(r["size"]), _ts(r["mtime"]), round(r["elapsed"] or 0, 2)],
            fill=fill,
        )
    _finish(ws)

    # 4. 前回との違い（同じ検査先を最後まで終えた前回の検査と比べる）
    ws = _sheet(wb, "前回との違い", [16, 80, 12, 12, 10, 10, 50])
    _row(
        ws,
        ["違い", "パス", "今回の検出件数", "前回の検出件数", "今回の危険度", "前回の危険度", "理由・補足"],
        bold=True,
    )
    head_note = jobdiff.summary_text(diff)
    if job["state"] != "done":
        head_note += "（この検査は最後まで終わっていないため、違いは途中までの結果によるもの）"
    _row(ws, ["要約", head_note, "", "", "", "", ""], fill="EDEDED")
    for d in diff["rows"]:
        _row(
            ws,
            [d["kind_label"], d["top_path"], d["n_now"], d["n_prev"], d["risk_now"], d["risk_prev"], d["note"]],
            fill={"new": "F8CBAD", "increased": "FCE4D6", "gone": "C6EFCE", "decreased": "E2EFDA"}.get(d["kind"]),
        )
    _finish(ws)

    # 5. 検出明細
    ws = _sheet(wb, "検出明細", [70, 16, 6, 24, 30, 50, 30, 24])
    _row(
        ws,
        ["パス（項目）", "種類", "確度", "値（マスク済み）", "場所", "前後の文脈（マスク済み）", "検出規則", "読み方"],
        bold=True,
    )
    for r in store.query(
        """SELECT i.path, f.pii_type, f.confidence, f.masked_value, f.location, f.context, f.rule, f.method
           FROM findings f JOIN items i ON i.job_id=f.job_id AND i.top_path=f.top_path AND i.seq=f.item_seq
           WHERE f.job_id=? ORDER BY i.path""",
        (job_id,),
    ):
        _row(ws, [r[0], PII_TYPES.get(r[1], r[1]), CONF_LABELS.get(r[2], r[2]), r[3], r[4], r[5], r[6], r[7]])
    _finish(ws)

    # 6. 全項目
    ws = _sheet(wb, "全項目", [80, 24, 10, 50, 40, 40, 11, 19, 8, 9])
    _row(
        ws,
        ["パス", "形式", "状態", "理由", "読み方", "補足", "大きさ(KB)", "更新日時", "入れ子の深さ", "検出件数"],
        bold=True,
    )
    for r in store.query("SELECT * FROM items WHERE job_id=? ORDER BY top_path, seq", (job_id,)):
        counts = json.loads(r["counts"])
        notes = "／".join(json.loads(r["notes"]))
        _row(
            ws,
            [
                r["path"],
                r["kind"],
                STATUS_JA.get(r["status"], r["status"]),
                r["reason"],
                r["method"],
                notes,
                _size(r["size"]),
                _ts(r["mtime"]),
                r["depth"],
                sum(counts.values()),
            ],
        )
    _finish(ws)

    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    # 途中で落ちても（電源断・満杯）壊れたレポートが残らないよう、隣の一時ファイルに書いてから差し替える
    tmp = f"{out_path}.{os.getpid()}.tmp"
    try:
        wb.save(tmp)
        os.replace(tmp, out_path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    return out_path


@contextmanager
def _atomic_text(path: Path):
    """書き終えてから差し替えるテキストファイル（UTF-8 BOM 付き・Excel で開ける）。"""
    tmp = Path(f"{path}.{os.getpid()}.tmp")
    try:
        with open(tmp, "w", encoding="utf-8-sig", newline="") as f:
            yield f
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


def write_csv(store: Store, job_id: str, out_dir: str) -> list[str]:
    """検出明細と全項目を CSV（UTF-8 BOM 付き・Excel で開ける）で書く。"""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    p1 = out / f"検出明細_{job_id}.csv"
    with _atomic_text(p1) as f:
        w = csv.writer(f)
        w.writerow(["パス", "種類", "確度", "値（マスク済み）", "場所", "文脈", "検出規則", "読み方"])
        for r in store.query(
            """SELECT i.path, f.pii_type, f.confidence, f.masked_value, f.location, f.context, f.rule, f.method
               FROM findings f JOIN items i ON i.job_id=f.job_id AND i.top_path=f.top_path AND i.seq=f.item_seq
               WHERE f.job_id=? ORDER BY i.path""",
            (job_id,),
        ):
            w.writerow([r[0], PII_TYPES.get(r[1], r[1]), CONF_LABELS.get(r[2], r[2]), r[3], r[4], r[5], r[6], r[7]])
    p2 = out / f"全項目_{job_id}.csv"
    with _atomic_text(p2) as f:
        w = csv.writer(f)
        w.writerow(["パス", "形式", "状態", "理由", "読み方", "大きさ(KB)", "検出件数"])
        for r in store.query("SELECT * FROM items WHERE job_id=? ORDER BY top_path, seq", (job_id,)):
            w.writerow(
                [
                    r["path"],
                    r["kind"],
                    STATUS_JA.get(r["status"], r["status"]),
                    r["reason"],
                    r["method"],
                    r["size"],
                    sum(json.loads(r["counts"]).values()),
                ]
            )
    return [str(p1), str(p2)]

"""前回の検査との違い。

同じ検査先（フォルダの指定なら同じフォルダの組、接続方式なら同じ方式・サーバー・ポート・共有・フォルダ）を、
最後まで終えた前回の検査と比べ、次の4つを出す。比べるのは DB にある（伏せた）件数と状態だけで、生の値は使わない。

- 新しく見つかった … 今回は検出があり、前回は無かった（前回は検出なし・前回は無かったファイル）
- 無くなった … 前回は検出があり、今回は無い（消えた・直った・今回は調べられなかった を理由で分ける）
- 件数が増えた／減った … 両方で検出があり、検出の件数が違う
"""

from __future__ import annotations

import json
import os
import time

from .models import STATUS_LABELS, Status

KIND_LABELS = {
    "new": "新しく見つかった",
    "gone": "無くなった",
    "increased": "件数が増えた",
    "decreased": "件数が減った",
}
KIND_ORDER = tuple(KIND_LABELS)
NO_PREVIOUS = "比べる前回の検査がありません（同じ場所を最後まで検査した記録が無い）"
_BLOCKING = {s.value for s in Status if s.blocks_clean_verdict}
_STATUS_JA = {s.value: label for s, label in STATUS_LABELS.items()}


def target_key(roots: list[str], options: dict | None) -> tuple:
    """検査先の同一性の鍵。接続方式はユーザー名・文字コード等を除いた接続先、フォルダは大小文字を寄せたパスの組。"""
    conn = (options or {}).get("connection")
    if conn:
        return ("connection",) + tuple(
            str(conn.get(k) or "").strip().lower() for k in ("kind", "host", "port", "share", "path")
        )
    return ("roots",) + tuple(sorted(os.path.normcase(os.path.normpath(r)) for r in roots or []))


def previous_job(store, job_id: str) -> dict | None:
    """同じ検査先を最後まで終えた、この検査より前の検査（最新のもの）。無ければ None。"""
    job = store.job(job_id)
    if not job:
        return None
    key = target_key(job["roots"], job["options"])
    for r in store.query(
        "SELECT id, created, name, roots, options, finished FROM jobs WHERE state='done' AND id<>? AND created<?"
        " ORDER BY created DESC",
        (job_id, job["created"]),
    ):
        try:
            roots, opts = json.loads(r["roots"]), json.loads(r["options"])
        except (TypeError, ValueError):
            continue
        if target_key(roots, opts) == key:
            return {"id": r["id"], "created": r["created"], "name": r["name"], "finished": r["finished"]}
    return None


def _with_findings(store, job_id: str) -> dict[str, dict]:
    return {
        r["top_path"]: dict(r)
        for r in store.query(
            "SELECT top_path, n_findings, risk, worst_status, state FROM files"
            " WHERE job_id=? AND state='done' AND n_findings > 0",
            (job_id,),
        )
    }


def _rows_for(store, job_id: str, paths: list[str]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for i in range(0, len(paths), 400):
        part = paths[i : i + 400]
        marks = ",".join("?" * len(part))
        for r in store.query(
            f"SELECT top_path, n_findings, risk, worst_status, state FROM files WHERE job_id=? AND top_path IN ({marks})",
            (job_id, *part),
        ):
            out[r["top_path"]] = dict(r)
    return out


def _gone_note(now: dict | None) -> str:
    if now is None:
        return "今回は見つからない（消した・移した・名前を変えた）"
    if now["state"] != "done":
        return "今回はまだ調べていない"
    if (now["worst_status"] or "") in _BLOCKING:
        return f"今回は調べられなかった（{_STATUS_JA.get(now['worst_status'], now['worst_status'])}）"
    return "検出が無くなった（直した・中身が変わった）"


def _new_note(before: dict | None) -> str:
    if before is None:
        return "前回は無かったファイル"
    if before["state"] != "done":
        return "前回は調べ終えていない"
    if (before["worst_status"] or "") in _BLOCKING:
        return f"前回は調べられなかった（{_STATUS_JA.get(before['worst_status'], before['worst_status'])}）"
    return "前回は検出なし"


def compute(store, job_id: str) -> dict:
    """前回との違い。{"previous": 前回のジョブか None, "counts": 種類→件数, "rows": [行…]}。

    行は {kind, top_path, n_now, n_prev, risk_now, risk_prev, note}（パスの順）。
    """
    prev = previous_job(store, job_id)
    if not prev:
        return {"previous": None, "counts": {k: 0 for k in KIND_ORDER}, "rows": []}
    cur, old = _with_findings(store, job_id), _with_findings(store, prev["id"])
    new_paths = [p for p in cur if p not in old]
    gone_paths = [p for p in old if p not in cur]
    before = _rows_for(store, prev["id"], new_paths)
    now = _rows_for(store, job_id, gone_paths)
    rows = []
    for p in new_paths:
        b = before.get(p)
        rows.append(_row("new", p, cur[p], b, _new_note(b)))
    for p in gone_paths:
        n = now.get(p)
        rows.append(_row("gone", p, n, old[p], _gone_note(n)))
    for p, c in cur.items():
        o = old.get(p)
        if o and o["n_findings"] != c["n_findings"]:
            kind = "increased" if c["n_findings"] > o["n_findings"] else "decreased"
            rows.append(_row(kind, p, c, o, f"{o['n_findings']:,} 件 → {c['n_findings']:,} 件"))
    rows.sort(key=lambda r: (KIND_ORDER.index(r["kind"]), r["top_path"]))
    counts = {k: 0 for k in KIND_ORDER}
    for r in rows:
        counts[r["kind"]] += 1
    return {"previous": prev, "counts": counts, "rows": rows}


def _row(kind: str, path: str, now: dict | None, before: dict | None, note: str) -> dict:
    return {
        "kind": kind,
        "kind_label": KIND_LABELS[kind],
        "top_path": path,
        "n_now": (now or {}).get("n_findings") or 0,
        "n_prev": (before or {}).get("n_findings") or 0,
        "risk_now": (now or {}).get("risk") or "",
        "risk_prev": (before or {}).get("risk") or "",
        "note": note,
    }


def previous_text(prev: dict | None) -> str:
    """「前回の検査（2026-10-18 09:00・ジョブ …）」の形。"""
    if not prev:
        return ""
    when = time.strftime("%Y-%m-%d %H:%M", time.localtime(prev["finished"] or prev["created"]))
    return f"前回の検査（{when} に終了・ジョブ {prev['id']}）"


def summary_text(d: dict, where: str = "") -> str:
    """要約の1文。where は一覧へのたどり方（「「前回との違い」シート」など）。"""
    if not d["previous"]:
        return NO_PREVIOUS
    c = d["counts"]
    body = "・".join(f"{KIND_LABELS[k]} {c[k]:,} 件" for k in KIND_ORDER)
    if not any(c.values()):
        return f"{previous_text(d['previous'])}と比べて、検出のあったファイルに違いはありません"
    tail = f"。一覧は{where}" if where else ""
    return f"{previous_text(d['previous'])}と比べて: {body}{tail}"

"""前回の検査との違い。

同じ検査先（フォルダの指定なら同じフォルダの組、接続方式なら同じ方式・サーバー・ポート・共有・フォルダ）を、
最後まで終えた前回の検査と比べ、次の4つを出す。比べるのは DB にある（伏せた）件数と状態だけで、生の値は使わない。

- 新しく見つかった … 今回は検出があり、前回は無かった（前回は検出なし・前回は無かったファイル）
- 無くなった … 前回は検出があり、今回は無い（直った・今回は見つからない・今回は調べられなかった を理由で分ける）
- 件数が増えた／減った … 両方で検出があり、検出の件数が違う

ファイルは、FTP 以外は大小文字と区切りを寄せたパス（os.path.normcase）で突き合わせる（Windows・SMB のパスは
大小文字を区別しないので、大小文字だけの違いで「無くなった＋新しく見つかった」にしない）。
前回と今回で結果に効く設定（拾わない値・自分で足す規則・OCR など）や検査器の版が違うときも比べるが、
違いにはファイルの変化でないものが混ざるので、要約にその旨と何が違うかを添える。
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
# 「無くなった」の理由の区分（画面の札の色・Excel の塗りを分ける）
GONE_FIXED = "fixed"  # 今回は検出が無い（直した・中身が変わった）
GONE_MISSING = "missing"  # 今回は見つからない（消した・移した・名前を変えた、または見えなかった）
GONE_UNCHECKED = "unchecked"  # 今回は調べられなかった・まだ調べていない（言い切れない）
GONE_UNCHECKED_LABEL = "無くなった（調べられなかった）"
NO_PREVIOUS = "比べる前回の検査がありません（同じ場所を最後まで検査した記録が無い）"
_BLOCKING = {s.value for s in Status if s.blocks_clean_verdict}
_STATUS_JA = {s.value: label for s, label in STATUS_LABELS.items()}

# 結果に効く設定の名前（違いの説明に出す）。ほかの結果に効く設定は「その他の設定」にまとめる
_SETTING_NAMES = {
    "allow_values": "拾わない値（許可リスト）",
    "custom_rules": "自分で足す規則",
    "ocr": "OCR",
    "raw_sweep": "生データ走査",
    "deep_image_sweep": "イメージの空き領域の走査",
}
# 結果に効かない設定（場所・道具のパス・展開の区切り方・使い回し・接続先・明細の見本の数）
_SETTING_IGNORE = {
    "temp_dir",
    "sevenzip",
    "access_helper32",
    "extract_batch_bytes",
    "reuse",
    "connection",
    "max_samples_per_type",
}
VERSION_NAME = "検査器の版（またはこの PC の部品）"


def target_key(roots: list[str], options: dict | None) -> tuple:
    """検査先の同一性の鍵。接続方式はユーザー名・文字コード等を除いた接続先、フォルダは大小文字を寄せたパスの組。"""
    conn = (options or {}).get("connection")
    if conn:
        return ("connection",) + tuple(
            str(conn.get(k) or "").strip().lower() for k in ("kind", "host", "port", "share", "path")
        )
    return ("roots",) + tuple(sorted(os.path.normcase(os.path.normpath(r)) for r in roots or []))


def path_key(path: str) -> str:
    """ファイルを突き合わせる鍵。FTP のパスはそのまま、ほかは大小文字と区切りを寄せる（os.path.normcase）。"""
    from .remote import is_ftp_path

    return path if is_ftp_path(path) else os.path.normcase(path)


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
    """検出のあるファイル（鍵 → 行）。"""
    return {
        path_key(r["top_path"]): dict(r)
        for r in store.query(
            "SELECT top_path, n_findings, risk, worst_status, state FROM files"
            " WHERE job_id=? AND state='done' AND n_findings > 0",
            (job_id,),
        )
    }


def _rows_for(store, job_id: str, paths: list[str]) -> dict[str, dict]:
    """パスの一覧の、そのジョブでの行（鍵 → 行）。大小文字だけ違うパスも拾う。"""
    out: dict[str, dict] = {}
    cols = "top_path, n_findings, risk, worst_status, state"
    for i in range(0, len(paths), 400):
        part = paths[i : i + 400]
        marks = ",".join("?" * len(part))
        for r in store.query(f"SELECT {cols} FROM files WHERE job_id=? AND top_path IN ({marks})", (job_id, *part)):
            out[path_key(r["top_path"])] = dict(r)
        # 大小文字だけ違うもの（SQLite の lower は英字だけを寄せるので、最後は Python の鍵で確かめる）
        missing = [p for p in part if path_key(p) not in out]
        if missing:
            lowered = [p.lower() for p in missing]
            marks = ",".join("?" * len(lowered))
            wanted = {path_key(p) for p in missing}
            for r in store.query(
                f"SELECT {cols} FROM files WHERE job_id=? AND lower(top_path) IN ({marks})", (job_id, *lowered)
            ):
                k = path_key(r["top_path"])
                if k in wanted:
                    out[k] = dict(r)
    return out


def _unreached_folders(store, job_id: str) -> list[tuple[str, str]]:
    """今回の検査で開けなかったフォルダ・辿らなかったリンク（鍵, 種類）。"""
    return [
        (path_key(r["path"]), r["kind"])
        for r in store.query("SELECT path, kind FROM folder_errors WHERE job_id=?", (job_id,))
    ]


def _under(key: str, folder_key: str) -> bool:
    """パスの鍵が、フォルダの鍵の下にあるか。"""
    folder = folder_key.rstrip("\\/")
    return key.startswith(folder + "\\") or key.startswith(folder + "/")


def _gone_note(now: dict | None, key: str, unreached: list[tuple[str, str]]) -> tuple[str, str]:
    """(理由の文, 理由の区分)。"""
    if now is None:
        for folder, kind in unreached:
            if _under(key, folder):
                what = "フォルダを開けなかった" if kind == "error" else "リンクを辿らなかった"
                return f"今回は調べられなかった（{what}）", GONE_UNCHECKED
        # 今回は列挙されなかった。消した・移したとは言い切らない（権限・接続で見えなかったこともある）
        return "今回は見つからない（消した・移した・名前を変えた、または今回は見えなかった）", GONE_MISSING
    if now["state"] != "done":
        return "今回はまだ調べていない", GONE_UNCHECKED
    if (now["worst_status"] or "") in _BLOCKING:
        return (
            f"今回は調べられなかった（{_STATUS_JA.get(now['worst_status'], now['worst_status'])}）",
            GONE_UNCHECKED,
        )
    return "検出が無くなった（直した・中身が変わった）", GONE_FIXED


def _new_note(before: dict | None) -> str:
    if before is None:
        return "前回は無かったファイル"
    if before["state"] != "done":
        return "前回は調べ終えていない"
    if (before["worst_status"] or "") in _BLOCKING:
        return f"前回は調べられなかった（{_STATUS_JA.get(before['worst_status'], before['worst_status'])}）"
    return "前回は検出なし"


def _result_settings(options: dict) -> dict:
    """結果に効く設定（比べる形）。拾わない値は照合と同じ形に寄せて並べ、書き順・重複では変えない。"""
    from dataclasses import asdict

    from .models import ScanOptions
    from .userrules import allow_signature

    # 古い版で保存した設定に無い項目は、既定の値とみなす（項目が増えただけで「設定が違う」としない）
    merged = {**asdict(ScanOptions()), **(options or {})}
    opts = {k: v for k, v in merged.items() if k not in _SETTING_IGNORE}
    opts["allow_values"] = allow_signature(opts.get("allow_values"))
    opts["custom_rules"] = opts.get("custom_rules") or []
    return opts


def _engine_sigs(store, job_id: str) -> set[str]:
    return {
        r[0]
        for r in store.query(
            "SELECT DISTINCT engine_sig FROM files WHERE job_id=? AND state='done' AND engine_sig IS NOT NULL",
            (job_id,),
        )
    }


def settings_changes(store, job_id: str, prev_id: str) -> list[str]:
    """前回と今回で違う、結果に効く設定・検査器の版の名前の一覧（同じなら空）。"""
    cur_job, prev_job = store.job(job_id), store.job(prev_id)
    if not cur_job or not prev_job:
        return []
    a, b = _result_settings(cur_job["options"]), _result_settings(prev_job["options"])
    names: list[str] = []
    other = False
    for k in sorted(set(a) | set(b)):
        if a.get(k) == b.get(k):
            continue
        if k in _SETTING_NAMES:
            names.append(_SETTING_NAMES[k])
        else:
            other = True
    names.sort(key=lambda n: list(_SETTING_NAMES.values()).index(n))
    if other:
        names.append("その他の設定")
    if not names:
        # 設定が同じでも、検査器の版（ソース・読み取りの部品・OCR などこの PC で使える部品）が違えば結果が変わりうる
        cur_sigs, prev_sigs = _engine_sigs(store, job_id), _engine_sigs(store, prev_id)
        if cur_sigs and prev_sigs and cur_sigs != prev_sigs:
            names.append(VERSION_NAME)
    return names


def compute(store, job_id: str) -> dict:
    """前回との違い。

    {"previous": 前回のジョブか None, "counts": 種類→件数, "gone_unchecked": 調べられなかった「無くなった」の数,
     "settings_changed": 違う設定の名前の一覧, "rows": [行…]}。
    行は {kind, kind_label, top_path, n_now, n_prev, risk_now, risk_prev, note, gone_reason}（種類・パスの順）。
    """
    prev = previous_job(store, job_id)
    if not prev:
        return {
            "previous": None,
            "counts": {k: 0 for k in KIND_ORDER},
            "gone_unchecked": 0,
            "settings_changed": [],
            "rows": [],
        }
    cur, old = _with_findings(store, job_id), _with_findings(store, prev["id"])
    new_keys = [k for k in cur if k not in old]
    gone_keys = [k for k in old if k not in cur]
    before = _rows_for(store, prev["id"], [cur[k]["top_path"] for k in new_keys])
    now = _rows_for(store, job_id, [old[k]["top_path"] for k in gone_keys])
    unreached = _unreached_folders(store, job_id) if gone_keys else []
    rows = []
    for k in new_keys:
        b = before.get(k)
        rows.append(_row("new", cur[k]["top_path"], cur[k], b, _new_note(b)))
    for k in gone_keys:
        n = now.get(k)
        note, reason = _gone_note(n, k, unreached)
        rows.append(_row("gone", (n or old[k])["top_path"], n, old[k], note, reason))
    for k, c in cur.items():
        o = old.get(k)
        if o and o["n_findings"] != c["n_findings"]:
            kind = "increased" if c["n_findings"] > o["n_findings"] else "decreased"
            rows.append(_row(kind, c["top_path"], c, o, f"{o['n_findings']:,} 件 → {c['n_findings']:,} 件"))
    rows.sort(key=lambda r: (KIND_ORDER.index(r["kind"]), r["top_path"]))
    counts = {k: 0 for k in KIND_ORDER}
    for r in rows:
        counts[r["kind"]] += 1
    return {
        "previous": prev,
        "counts": counts,
        "gone_unchecked": sum(1 for r in rows if r["gone_reason"] == GONE_UNCHECKED),
        "settings_changed": settings_changes(store, job_id, prev["id"]),
        "rows": rows,
    }


def _row(kind: str, path: str, now: dict | None, before: dict | None, note: str, gone_reason: str = "") -> dict:
    return {
        "kind": kind,
        "kind_label": GONE_UNCHECKED_LABEL if gone_reason == GONE_UNCHECKED else KIND_LABELS[kind],
        "top_path": path,
        "n_now": (now or {}).get("n_findings") or 0,
        "n_prev": (before or {}).get("n_findings") or 0,
        "risk_now": (now or {}).get("risk") or "",
        "risk_prev": (before or {}).get("risk") or "",
        "note": note,
        "gone_reason": gone_reason,
    }


def previous_text(prev: dict | None) -> str:
    """「前回の検査（2026-10-18 09:00 に終了）」の形（ジョブ ID ではなく日時で示す）。"""
    if not prev:
        return ""
    when = time.strftime("%Y-%m-%d %H:%M", time.localtime(prev["finished"] or prev["created"]))
    return f"前回の検査（{when} に終了）"


def settings_note(d: dict) -> str:
    """設定・検査器の版が違うときの添え書き（同じなら空）。"""
    names = d.get("settings_changed") or []
    if not names:
        return ""
    return (
        "前回と設定（または検査器の版）が違うため、違いにはファイルの変化でないものを含みます"
        f"（違うもの: {'・'.join(names)}）"
    )


def counts_text(d: dict) -> str:
    """「新しく見つかった N 件・無くなった N 件（うち調べられなかった N 件）・…」の形。"""
    c = d["counts"]
    parts = []
    for k in KIND_ORDER:
        part = f"{KIND_LABELS[k]} {c[k]:,} 件"
        if k == "gone" and d.get("gone_unchecked"):
            part += f"（うち調べられなかった {d['gone_unchecked']:,} 件）"
        parts.append(part)
    return "・".join(parts)


CLI_KIND_LABELS = {"new": "新しく見つかった", "gone": "無くなった", "increased": "増えた", "decreased": "減った"}


def cli_line(d: dict) -> str:
    """コマンドの最後に出す1行（「前回との違い: 新しく見つかった N 件・無くなった N 件・増えた N 件・減った N 件」）。"""
    if not d["previous"]:
        return f"前回との違い: {NO_PREVIOUS}"
    c = d["counts"]
    body = "・".join(f"{CLI_KIND_LABELS[k]} {c[k]:,} 件" for k in KIND_ORDER)
    if d.get("gone_unchecked"):
        body += f"（無くなったうち調べられなかった {d['gone_unchecked']:,} 件）"
    note = settings_note(d)
    return f"前回との違い: {body}（{previous_text(d['previous'])}と比べて）" + (f"。{note}" if note else "")


def summary_text(d: dict, where: str = "") -> str:
    """要約の1文。where は一覧へのたどり方（「「前回との違い」シート」など）。"""
    if not d["previous"]:
        return NO_PREVIOUS
    note = settings_note(d)
    tail_note = f"。{note}" if note else ""
    if not any(d["counts"].values()):
        return f"{previous_text(d['previous'])}と比べて、検出のあったファイルに違いはありません{tail_note}"
    tail = f"。一覧は{where}" if where else ""
    return f"{previous_text(d['previous'])}と比べて: {counts_text(d)}{tail}{tail_note}"

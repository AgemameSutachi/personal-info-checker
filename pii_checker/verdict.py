"""総合判定。「このフォルダに個人情報は無い」と言い切れるかを、根拠の数字つきで決める。"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Verdict:
    level: str  # found / undetermined / empty / low_only / clean_partial / clean / running
    title: str
    detail: list[str] = field(default_factory=list)
    can_declare_clean: bool = False
    next_step: str = ""  # 次にすること（画面とレポートで同じ文を使う）


PLACES = {
    # 「次にすること」で指す場所の名前を、出す先（画面・Excel・コマンド）ごとに変える
    "screen": {"HITS": "「個人情報の可能性があるファイル」タブ", "ATTN": "「要対応」タブ", "FIND": "「検出明細」タブ"},
    "excel": {
        "HITS": "「ファイル別」シート（危険度の列で絞り込み）",
        "ATTN": "「要対応」シート",
        "FIND": "「検出明細」シート",
    },
    "cli": {
        "HITS": "Excel レポートの「ファイル別」シート",
        "ATTN": "Excel レポートの「要対応」シート",
        "FIND": "Excel レポートの「検出明細」シート",
    },
}


def decide(summary: dict, job_state: str, target: str = "screen") -> Verdict:
    """store.summary() の結果から判定する。target は「次にすること」を出す先（screen / excel / cli）。"""
    v = _decide(summary, job_state)
    for key, name in PLACES.get(target, PLACES["screen"]).items():
        v.next_step = v.next_step.replace("{" + key + "}", name)
    return v


def _decide(summary: dict, job_state: str) -> Verdict:
    st = summary["item_status"]
    conf = summary["confidence"]
    n_files = summary["files_total"]
    n_done = summary["files_done"]
    n_items = sum(st.values())
    blocking = {
        "パスワードが必要": st.get("needs_password", 0),
        "検査できなかった": st.get("uncheckable", 0),
        "まだ調べていない": n_files - n_done,
        "開けなかったフォルダ": summary["folder_errors"],
        "辿らなかったリンク": summary["links"],
    }
    blocking = {k: v for k, v in blocking.items() if v}
    partial = st.get("partial", 0)
    out_of_scope = st.get("out_of_scope", 0)
    high_mid = conf.get("high", 0) + conf.get("medium", 0)
    low = conf.get("low", 0)

    detail = [f"見つけたファイル {n_files:,} 件のうち {n_done:,} 件を調べ終えた（zip などの中身を含め {n_items:,} 件）"]
    if blocking:
        detail.append("言い切れない理由: " + "、".join(f"{k} {v:,} 件" for k, v in blocking.items()))
    if partial:
        detail.append(f"簡易検査 {partial:,} 件（中身の形式を解釈できず、文字として読める部分だけを調べた）")
    if summary.get("reused"):
        detail.append(
            f"うち {summary['reused']:,} 件は前回から変わっていない（大きさ・更新日時・変更日時・ファイル ID が一致）ため、"
            "前回の検査結果を使った"
        )
    if out_of_scope:
        detail.append(f"対象外 {out_of_scope:,} 件（動画・音声・実行ファイル・フォントなど、文字の情報を持たない形式）")

    if job_state in ("running", "created"):
        return Verdict("running", "検査中", detail)
    if high_mid:
        detail.insert(
            0,
            f"個人情報の可能性があるファイル {summary['files_with_findings']:,} 件（確度 高・中の検出 {high_mid:,} 件）",
        )
        step = "{HITS}を確かめ、不要なものを削除・移動してから再検査してください。"
        if blocking:
            step += " あわせて、{ATTN}の項目（パスワード・権限など）も解消してください。"
        return Verdict("found", "個人情報の可能性あり", detail, next_step=step)
    if job_state in ("interrupted", "cancelled") and n_files == 0:
        # 列挙の途中で止めた（NAS への接続が切れた等）。0 件を「見つからない」と言うと、アクセス権を探しに行かせてしまう
        detail.insert(0, "ファイルを探している途中で検査を止めた")
        return Verdict(
            "undetermined",
            "言い切れない（検査を途中で止めた）",
            detail,
            next_step="止めた理由（NAS への接続など）を解消してから、同じジョブを再開してください。",
        )
    if n_files == 0 and n_items == 0:
        # 0 件で「無い」と言い切ると、場所の指定違い・権限で見えないフォルダを見落とす
        detail.insert(0, "ファイルが1件も見つからなかった")
        return Verdict(
            "empty",
            "ファイルが見つからない（言い切れない）",
            detail,
            next_step="指定した場所が正しいか、その場所のファイルが自分のアカウントで見えるか（アクセス権）を確かめてください。",
        )
    if blocking:
        return Verdict(
            "undetermined",
            "言い切れない（調べられなかったものがある）",
            detail,
            next_step="{ATTN}の項目（パスワード入力・権限の付与・目視）を解消して再検査すると、言い切れるようになります。",
        )
    if low:
        detail.insert(0, f"確度の低い候補 {low:,} 件だけが見つかった")
        return Verdict(
            "low_only",
            "要確認（確度の低い候補のみ）",
            detail,
            next_step="{FIND}で確度 低 の候補を目視で確かめてください。個人情報でなければ、そのまま言い切れます。",
        )
    if partial:
        return Verdict(
            "clean_partial",
            "検出なし（一部は簡易検査）",
            detail,
            next_step="{ATTN}の簡易検査の項目を確かめてください（中身の形式を解釈できず、文字として読める部分だけを調べたものです）。",
        )
    return Verdict(
        "clean",
        "検出なし（全ファイルを中身まで検査した）",
        detail,
        can_declare_clean=True,
        next_step="検査した範囲（指定したフォルダ）については「個人情報は無い」と報告できます（zip などの中身を含む全ファイルを中身まで検査済み）。",
    )

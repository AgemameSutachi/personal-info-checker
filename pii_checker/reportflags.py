"""漏えい時の報告の目安（ファイルごとの印）。

見つけたものを上へ報告するときの手がかりとして、ファイルごとに次の印を付ける。どれも**目安**で、法的な判断ではない
（「高度な暗号化その他の措置」の有無・実際に漏えいしたか・本人の数の数え方などは、このツールには分からない）。

- 特定個人情報（マイナンバー）を含む … マイナンバーの検出が確度 中以上
- 要配慮個人情報を含む … 要配慮個人情報の検出が確度 中以上
- 財産的被害のおそれ … クレジットカード番号・銀行口座番号の検出が確度 中以上
- 異なるマイナンバーが 100 を超える … 番号法の報告の規則（本人の数が百人を超える事態）に寄せた目安
- 異なる個人の値が 1,000 を超える … 個人情報保護法施行規則第7条第4号（本人の数が千人を超える事態）に寄せた目安。
  人の数は数えられないので、氏名・マイナンバー・メール・電話などのうち、異なる値が最も多い種類の数で代える

異なる値の数は、確度 中以上の値だけを数える（判定の「個人情報の可能性あり」と同じ線）。
"""

from __future__ import annotations

import json

FLAG_LABELS = {
    "my_number": "特定個人情報（マイナンバー）を含む",
    "sensitive": "要配慮個人情報を含む",
    "financial": "財産的被害のおそれ（カード番号・口座番号）",
    "many_my_number": "異なるマイナンバーが 100 を超える",
    "many_people": "異なる個人の値が 1,000 を超える",
}
# 表の列に並べる短い名前
FLAG_SHORT = {
    "my_number": "マイナンバー",
    "sensitive": "要配慮",
    "financial": "財産的被害",
    "many_my_number": "マイナンバー100超",
    "many_people": "1,000人超",
}
FLAG_ORDER = tuple(FLAG_LABELS)

MY_NUMBER_LIMIT = 100  # 番号法の報告の規則: 本人の数が百人を超える
PEOPLE_LIMIT = 1000  # 個人情報保護法施行規則第7条第4号: 本人の数が千人を超える

# 1人に1つずつ付く見込みの強い種類（人の数の目安に使う）。生年月日・性別・年齢は同じ値の人が多いので使わない
PEOPLE_TYPES = (
    "name",
    "my_number",
    "email",
    "phone",
    "address",
    "drivers_license",
    "passport",
    "pension",
    "health_insurance",
    "residence_card",
    "resident_code",
    "employment_insurance",
    "bank_account",
    "credit_card",
)

NOTE = (
    "漏えい時の報告の目安（個人情報保護委員会の規則・番号法の規則の基準に寄せたもの）。法的な判断ではありません。"
    "報告が要るかの判断は、専門家・所管部署へ相談してください"
)
SOURCES = [
    "個人情報の保護に関する法律施行規則 第7条（第1号 要配慮個人情報・第2号 財産的被害のおそれ・第4号 本人の数が千人を超える）",
    "行政手続における特定の個人を識別するための番号の利用等に関する法律第二十九条の四第一項及び第二項に基づく特定個人情報の"
    "漏えい等に関する報告等に関する規則 第2条第4号（本人の数が百人を超える）",
]
PEOPLE_NOTE = "人の数は数えられないため、氏名・マイナンバー・メール・電話などのうち、異なる値（確度 中以上）が最も多い種類の数で代えた"


def _at_least_medium(counts: dict, pii_type: str) -> int:
    return int(counts.get(f"{pii_type}:high", 0) or 0) + int(counts.get(f"{pii_type}:medium", 0) or 0)


def distinct_medium(distinct: dict | None) -> dict[str, int]:
    """種類→異なる値の数（確度 中以上）。0 の種類は入れない。"""
    out: dict[str, int] = {}
    for k in distinct or {}:
        t = k.split(":", 1)[0]
        if t not in out:
            n = _at_least_medium(distinct, t)
            if n:
                out[t] = n
    return out


def people_estimate(distinct: dict | None) -> tuple[int | None, str]:
    """(人の数の目安, どの種類で判断したか)。異なる値を数えていない（古い版の検査）なら (None, "")。"""
    if distinct is None:
        return None, ""
    best_n, best_t = 0, ""
    for t in PEOPLE_TYPES:
        n = _at_least_medium(distinct, t)
        if n > best_n:
            best_n, best_t = n, t
    return best_n, best_t


def compute(conf_counts: dict, distinct: dict | None) -> dict:
    """ファイルの検出（「種類:確度」→件数）と異なる値の数から印を決める。

    distinct が None（異なる値を数えていない古い版の検査）のときは、数に頼る印（100 超・1,000 超）は付けない。
    """
    flags: list[str] = []
    if _at_least_medium(conf_counts, "my_number"):
        flags.append("my_number")
    if _at_least_medium(conf_counts, "sensitive"):
        flags.append("sensitive")
    if _at_least_medium(conf_counts, "credit_card") or _at_least_medium(conf_counts, "bank_account"):
        flags.append("financial")
    people_n, people_type = people_estimate(distinct)
    if distinct is not None and _at_least_medium(distinct, "my_number") > MY_NUMBER_LIMIT:
        flags.append("many_my_number")
    if people_n is not None and people_n > PEOPLE_LIMIT:
        flags.append("many_people")
    return {"flags": flags, "people_n": people_n, "people_type": people_type}


def encode(flags: list[str]) -> str:
    """DB に置く形（「,my_number,sensitive,」。LIKE '%,x,%' で数えられる）。印が無ければ空文字。"""
    return "," + ",".join(flags) + "," if flags else ""


def decode(text: str | None) -> list[str]:
    return [f for f in (text or "").split(",") if f in FLAG_LABELS]


def labels(text: str | None, short: bool = False) -> list[str]:
    names = FLAG_SHORT if short else FLAG_LABELS
    return [names[f] for f in decode(text)]


def verdict_lines(summary: dict) -> list[str]:
    """総合判定の文に添える行（印ごとのファイル数・広く読めるフォルダにあるファイル数）。当たるものが無ければ空。"""
    flags = summary.get("flags") or {}
    parts = [f"{FLAG_LABELS[f]} {flags[f]:,} 件" for f in FLAG_ORDER if flags.get(f)]
    lines = []
    if parts:
        lines.append(
            "漏えい時の報告の目安に当たるファイル: "
            + "、".join(parts)
            + "（目安。法的な判断ではない。判断は専門家・所管部署へ）"
        )
    broad = (summary.get("access") or {}).get("broad", 0)
    if broad:
        lines.append(f"広く読めるフォルダ（Everyone など）にある、個人情報の可能性があるファイル {broad:,} 件")
    return lines


def type_label(pii_type: str) -> str:
    from .detectors import PII_TYPES

    return PII_TYPES.get(pii_type, pii_type)


def distinct_text(distinct_json: str | None) -> str:
    """表に出す「種類 数」の並び（確度 中以上・多い順）。数えていない古い版の検査は「（数えていない）」。"""
    if distinct_json is None:
        return "（数えていない・古い版の検査）"
    d = distinct_medium(json.loads(distinct_json or "{}"))
    return "・".join(f"{type_label(t)} {n:,}" for t, n in sorted(d.items(), key=lambda x: -x[1]))


def people_text(people_n: int | None, people_type: str | None) -> str:
    """人の数の目安の表示（「1,200（メールアドレスで判断）」）。数えていなければ空。"""
    if people_n is None or not people_type:
        return ""
    return f"{people_n:,}（{type_label(people_type)}で判断）"

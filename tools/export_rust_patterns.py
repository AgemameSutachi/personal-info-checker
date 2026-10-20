"""今の本体 detectors.py から正規表現を取り出し、Rust 用の書き換え式を src/patterns.json に書く。

- "py": Python の元の式（Rust でそのまま動くもの＝ \\b を使う語だけ使う）。
- "rg": 先読み・後読みの無い Rust regex 向けの書き換え。
    * 後読み (?<!X) は、呼び出し側（Rust）が開始位置の直前の文字で確かめる。
    * 末尾の否定先読み (?!X) は、末尾に「X でない文字 か 文字列の終わり」を (?P<t>...) として消費させ、
      本来の終わりを t の開始位置とする（後戻りの優先順位を保つため）。
- Python の \\s は \\x1c-\\x1f（情報区切り文字）も空白とみなすが、Rust の \\s は含まない。
  そのため \\s は全部 [\\s\\x1c-\\x1f] に書き換える（fix_space）。
- 先読み・後読みの無い式の組み替えは、detectors.py の式を変えたら必ずやり直す。tests/test_rust_equivalence.py が、
  この道具が作る内容と rust/pii_rs_detect/src/patterns.json が食い違っていないかを確かめる（食い違えば試験が落ちる）。
- 語の境目（\\b）・\\w・\\s の Unicode の範囲の違いは、式の書き換えでは直せない。実行時に Python と Rust の判定が食い違う
  文字の範囲を求め、その文字を含む本文は Rust を使わず Python の経路で検出する（pii_checker/detectors.py の _rust_guard_ranges）。

使い方: python tools/export_rust_patterns.py          … patterns.json を書き直す
        python tools/export_rust_patterns.py --check  … 今の patterns.json と食い違っていれば終了コード 1
"""

import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from pii_checker import detectors as d  # noqa: E402

OUT = os.path.join(ROOT, "rust", "pii_rs_detect", "src", "patterns.json")

H, HC, SEP, LAND_SEP = d.H, d.H[1:-1], d.SEP, d.LAND_SEP
PREF = d.PREFECTURES
SUR = d.SURNAMES
NUM = d.NUM
ADDR_TAIL = d.ADDR_TAIL
PEND = r"[^\s、。,，「」()（）]"
# 「第」だけを除いた町名の文字（Rust には集合の差が使いにくいので範囲で書く）
dai = ord("第")
X_NO_DAI = f"[一-{chr(dai - 1)}{chr(dai + 1)}-龥々ぁ-んァ-ヶー]"
assert "第" not in "".join(chr(c) for c in range(0x4E00, 0x9FA6) if re.match(X_NO_DAI, chr(c)))
assert re.match("[一-龥]", "第")

T_NOT_DIGIT = r"(?P<t>[^0-9]|\z)"

rg = {
    "RE_LICENSE": r"(?:免許証番号|免許番号|免許証|運転免許)[^0-9\n]{0,12}?([0-9]{12})" + T_NOT_DIGIT,
    "RE_MY_NUMBER": rf"([0-9]{{4}}){SEP}([0-9]{{4}}){SEP}([0-9]{{4}})(?P<t>\z|[^0-9 \-]|[ \-]\z|[ \-][^0-9])",
    "RE_CARD": r"(?:[0-9][ \-]?){12,18}[0-9]" + T_NOT_DIGIT,
    "RE_MOBILE": rf"0[5789]0{SEP}[0-9]{{4}}{SEP}[0-9]{{4}}" + T_NOT_DIGIT,
    "RE_MOBILE_INTL": r"\+81[\s\-]?\(?0?\)?[5789]0[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}" + T_NOT_DIGIT,
    # (?![5789]0) は p の直後で呼び出し側が確かめる
    "RE_LANDLINE_INTL": r"(?P<p>\+81[\s\-.]?\(?0?\)?)\(?[1-9][0-9]{0,3}\)?[\s\-.]?[0-9]{1,4}[\s\-.]?[0-9]{4}"
    + T_NOT_DIGIT,
    "RE_LANDLINE": rf"(?:\(0[0-9]{{1,4}}\)\s?[0-9]{{1,4}}{LAND_SEP}"
    rf"|0[1-9][0-9]{{0,3}}(?:{LAND_SEP}|\s?\(\s?)[0-9]{{1,4}}(?:{LAND_SEP}|\s?\)\s?))"
    rf"[0-9]{{4}}(?P<t>[^0-9{HC}]|\z)",
    "RE_LANDLINE_SPACE": r"0[1-9][0-9]{0,3} [0-9]{1,4} [0-9]{4}" + T_NOT_DIGIT,
    "RE_PHONE_BARE": r"0[1-9][0-9]{8,9}" + T_NOT_DIGIT,
    "RE_POSTAL_MARK": rf"〒\s?[0-9]{{3}}{H}?[0-9]{{4}}" + T_NOT_DIGIT,
    "RE_POSTAL_BEFORE_PREF": rf"[0-9]{{3}}{H}[0-9]{{4}}(?P<t>\s{{0,3}}(?:{PREF}))",
    "RE_BANK": r"(?:口座番号|口座no\.?|口座|普通預金|当座預金|普通|当座)[^0-9\n]{0,12}?([0-9]{7})" + T_NOT_DIGIT,
    "RE_BANK_FULL": rf"(?:口座番号|口座no\.?|口座|普通預金|当座預金|普通|当座|振込先)[^0-9\n]{{0,12}}?"
    rf"([0-9]{{4}}{H}[0-9]{{3}}{H}[0-9]{{7}})" + T_NOT_DIGIT,
    "RE_PENSION": rf"(?:基礎年金番号|年金番号)[^0-9\n]{{0,12}}?([0-9]{{4}}{H}?[0-9]{{6}})" + T_NOT_DIGIT,
    "RE_PASSPORT": r"(?:旅券番号|旅券|パスポート番号|パスポート|passport\s?no\.?)[^A-Za-z0-9\n]{0,12}?([A-Z]{2}[0-9]{7})"
    + T_NOT_DIGIT,
    "RE_RESIDENCE_CARD": r"(?:在留カード番号|在留カード)[^A-Za-z0-9\n]{0,12}?([A-Z]{2}[0-9]{8}[A-Z]{2})(?P<t>[^A-Za-z0-9]|\z)",
    "RE_RESIDENT_CODE": r"住民票コード[^0-9\n]{0,12}?([0-9]{11})" + T_NOT_DIGIT,
    "RE_EMPLOYMENT": rf"{d.EMPLOYMENT_KW.pattern}[^0-9\n]{{0,12}}?([0-9]{{4}}{H}[0-9]{{6}}{H}[0-9]|[0-9]{{11}})"
    + T_NOT_DIGIT,
    # 正の先読み（値に数字を含む）は呼び出し側で確かめる。末尾の否定先読みは t
    "RE_MEMBER_ID": rf"(?:{d.MEMBER_ID_WORDS})[\s:：]{{0,3}}([0-9A-Za-z][0-9A-Za-z\-]{{3,19}})"
    r"(?P<t>\z|[^0-9A-Za-z\-\s年月日円件名人個回桁台]|\s(?:[^年月日円件名人個回桁台]|\z))",
    # 市区町村の後の空白1つ: 直後が町名の文字（「第」以外）のときだけ。先読みを使わずに場合分けで書く
    "RE_ADDRESS": rf"(?:{PREF})\s?{PEND}{{1,20}}?[市区町村郡]"
    rf"(?:\s(?:[一二三四五六七八九十][一二三四五六七八九十〇]*(?:丁目|番地|番|号|{H}[0-9]+)"
    rf"|{X_NO_DAI}{PEND}{{0,24}}?{ADDR_TAIL})|{PEND}{{0,25}}?{ADDR_TAIL})(?:{H}?[0-9]+)*",
    "RE_ADDRESS_NO_PREF": rf"[一-龥]{{1,5}}[市区][一-龥ぁ-んァ-ヶー]{{1,10}}(?:[0-9]+{H}[0-9]+(?:{H}[0-9]+)?|{NUM}丁目(?:{NUM}番地?)?(?:{NUM}号)?[0-9\-]*|{NUM}番地)",
    "RE_EMAIL": r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63})*\.[A-Za-z]{2,24}(?P<t>[^A-Za-z]|\z)",
    "RE_NAME_LABEL_TIGHT": rf"(?:氏名|お名前|名前|患者名|顧客名|契約者名)((?:{SUR})[ 　]?[一-龥々]{{1,3}})(?P<t>[^一-龥々]|\z)",
    "RE_NAME_HONORIFIC": rf"(?:{SUR})[ 　]?[一-龥々]{{0,3}}(?:様|殿|さん|君|くん|ちゃん)",
    "RE_NAME_HONORIFIC_ANY": r"([一-龥々]{3,5})(?:様|殿)(?P<t>[^方]|\z)",
    "RE_NAME_SPACED": rf"(?:{SUR})[ 　][一-龥々]{{1,3}}(?P<t>[^一-龥々]|\z)",
}

# 先読み・後読みの無いものは元の式をそのまま使う
for name in ("RE_DATE", "RE_DATE_ERA", "RE_INSURANCE", "RE_NAME_LABEL", "RE_SENSITIVE"):
    rg[name] = getattr(d, name).pattern
# RE_LANDLINE_INTL の途中の先読み (?![5789]0) の探知用: 「+81」の後ろ（区切り・括弧・0 のあと）に [5789]0 が続く形。
# Python は前の部分（括弧・0）を取り直して先読みを通る場合があるが、Rust の regex は先読みが無く同じ結果にできない。
# この形を含む本文は Rust で扱わず Python に回す（lib.rs の detect_py）
rg["LANDLINE_INTL_GUARD"] = r"\+81[\s\-.]?\(?0?\)?[5789]0"
# 全体一致用（Python の fullmatch 相当）
rg["RE_DATE_ERA_FULL"] = r"\A(?:" + d.RE_DATE_ERA.pattern + r")\z"

ctx_plain = [
    "MY_NUMBER_KW",
    "CARD_KW",
    "PHONE_KW",
    "BIRTH_KW",
    "LICENSE_KW",
    "PERSONAL_PHONE_KW",
    "CARD_NUMBER_KW",
    "MONEY_AFTER",
    "MONEY_BEFORE",
    "ROLE_EMAIL",
    "PERSONAL_ADDRESS_KW",
    "RE_MOBILE_PREFIX",
    "HONORIFIC_STOP",
]
for name in ctx_plain:
    rg[name] = getattr(d, name).pattern
# 語の途中で当たらないように前後を確かめる語。ORDER_KW・COMPANY_KW は \b だけなので元の式のまま（Rust の \b は Unicode）
rg["ORDER_KW"] = d.ORDER_KW.pattern
rg["COMPANY_KW"] = d.COMPANY_KW.pattern
# MODEL_KW・FACILITY_KW は先読み・後読みを外した芯だけ。呼び出し側で前後を確かめる
model = d.MODEL_KW.pattern
core_model = model.replace("(?<![a-z])isbn(?![a-z])", "isbn").replace("(?<![a-z])jan(?![a-z])", "jan")
assert "(?" not in core_model.replace("(?:", ""), core_model
rg["MODEL_KW"] = core_model
fac = d.FACILITY_KW.pattern
core = fac.replace("小学校(?!生)", "小学校").replace("中学校(?!生)", "中学校").replace("高等学校(?!生)", "高等学校")
core = core.replace("高校(?!生)", "高校").replace("大学(?!生|院生)", "大学").replace("学校(?!生)", "学校")
core = core.replace(r"(?<!最寄)(?<!最寄り)駅(?!前|から|まで|徒歩)", "駅")
assert "(?" not in core.replace("(?:", ""), core
rg["FACILITY_KW"] = core

# 元の式の flags（re.I）
orig_flags = {}
for name in dir(d):
    v = getattr(d, name)
    if isinstance(v, re.Pattern):
        orig_flags[name] = "i" if v.flags & re.I else ""
orig_flags["RE_DATE_ERA_FULL"] = ""


def fix_space(src: str) -> str:
    """\\s を Python と同じ範囲（\\x1c-\\x1f を含む）にする。文字クラスの中と外で書き方を変える。"""
    out = []
    i = 0
    in_class = False
    n = len(src)
    while i < n:
        c = src[i]
        if c == "\\" and i + 1 < n:
            nxt = src[i + 1]
            if nxt == "s":
                out.append(r"\s\x1c-\x1f" if in_class else r"[\s\x1c-\x1f]")
            else:
                out.append(c + nxt)
            i += 2
            continue
        if not in_class and c == "[":
            in_class = True
            out.append(c)
            i += 1
            # [^ と、先頭の ] はクラスの中身
            if i < n and src[i] == "^":
                out.append("^")
                i += 1
            continue
        if in_class and c == "]":
            in_class = False
        out.append(c)
        i += 1
    return "".join(out)


def fix_turkic_i(src: str) -> str:
    """re.I のとき、Python は ı（U+0131）・İ（U+0130）を i/I と同じ文字とみなすが、Rust の簡易な大文字小文字の畳み込みはしない。
    リテラルの i/I は [iIıİ] に、i を含みうる文字クラス（A-Z・a-z・i・I を含むもの）には ıİ を足す。"""
    out = []
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        if c == "\\" and i + 1 < n:
            out.append(c + src[i + 1])
            i += 2
            continue
        if c == "[":
            j = i + 1
            if j < n and src[j] == "^":
                j += 1
            body_start = j
            while j < n and src[j] != "]":
                j += 2 if src[j] == "\\" else 1
            body = src[body_start:j]
            if "A-Z" in body or "a-z" in body or "i" in body or "I" in body:
                out.append(src[i:j] + "ıİ" + "]")
            else:
                out.append(src[i : j + 1])
            i = j + 1
            continue
        if c in "iI":
            out.append("[iIıİ]")
        elif c == "(" and src.startswith("(?P<", i):
            k = src.index(">", i)
            out.append(src[i : k + 1])  # グループ名は触らない
            i = k + 1
            continue
        else:
            out.append(c)
        i += 1
    return "".join(out)


rg_out = {}
for k, v in rg.items():
    fl = orig_flags.get(k, "")
    if k in ("RE_DATE_ERA_FULL",):
        fl = ""
    if fl == "i":
        v = fix_turkic_i(v)
    rg_out[k] = [fix_space(v), fl]

# 検証: 書き換え式が Python でも compile できる（\z は \Z に、(?P<t>) は Python 構文でも通る）
for k, (src, fl) in rg_out.items():
    re.compile(src.replace(r"\z", r"\Z").replace(r"\A", r"\A"), re.I if fl else 0)


def render() -> str:
    """patterns.json に書く内容（文字列）。"""
    return json.dumps({"rg": rg_out}, ensure_ascii=False, indent=0)


def main() -> int:
    text = render()
    if "--check" in sys.argv:
        with open(OUT, encoding="utf-8", newline="") as f:
            current = f.read()
        if current != text:
            print(
                "patterns.json が detectors.py と食い違っています。python tools/export_rust_patterns.py で作り直してください"
            )
            return 1
        print("patterns.json は detectors.py と一致しています")
        return 0
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    print("rg", len(rg_out), "->", OUT)
    return 0


if __name__ == "__main__":
    # 日本語でない Windows では標準出力が cp1252 で、日本語の表示で落ちる。化けても続ける
    for stream in (sys.stdout, sys.stderr):
        if stream is not None and hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    sys.exit(main())

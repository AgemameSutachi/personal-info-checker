"""許可リスト（拾わない値）と利用者の規則（自前の語・正規表現）。

- 許可リスト: 1行に1つの値。検出した値（伏せる前）を正規化し、許可リストの値（同じく正規化）と完全に一致したら、
  その検出は数えない（部分一致はしない）。外した件数は項目ごとに数えて残す（黙って消さない）。
- 利用者の規則: 1行に1つ「名前 | 正規表現 | 確度」。当たった値を種類 custom（利用者の規則）として検出する。
  書式・正規表現の誤りは、検査を始める前に「何行目の何が悪いか」を日本語で返して断る。

極端に遅くなる正規表現への備え（規則は利用者が書くので、検査が終わらなくなる書き方を先に断る）:
- 長さは MAX_PATTERN_LEN 文字まで。後方参照と、量指定子の入れ子（(\\d+)+ の形）は断る
- 長さ0の文字列に当たりうる書き方（a* だけ等）は断る（どこにでも当たり、件数が意味を持たない）
- 受け付ける前に、繰り返しの文字列へ実際に当てて時間を測り、長くなるものは断る（_check_speed）
- 検査では、1回に当てる文字数を WINDOW 文字までに区切る（長い本文でも1回の当て方の手間に上限を置く）
"""

from __future__ import annotations

import re
import time
import unicodedata
from dataclasses import dataclass
from functools import lru_cache

from .models import Confidence

try:  # Python 3.11 以降の正規表現の構文解析（形を調べるだけに使う）
    import re._constants as _sre_c
    import re._parser as _sre_p
except ImportError:  # pragma: no cover  古い版の Python
    import sre_constants as _sre_c  # type: ignore
    import sre_parse as _sre_p  # type: ignore

MAX_PATTERN_LEN = 200  # 1つの正規表現の長さの上限
MAX_NAME_LEN = 50  # 規則の名前の長さの上限（明細の「検出規則」の欄に出す）
MAX_RULES = 100  # 規則の数の上限
MAX_ALLOW_VALUES = 10_000  # 許可リストの値の数の上限
MAX_ALLOW_VALUE_LEN = 300  # 許可リストの1つの値の長さの上限
WINDOW = 1024  # 検査で1回に当てる文字数の上限
STEP = 768  # 区切りをずらす幅（WINDOW - STEP = 256 文字までの当たりは、区切りの境目でも欠けない）
MAX_ERRORS_SHOWN = 5  # 断るときに並べる誤りの数

CUSTOM_TYPE = "custom"
CONFIDENCE_WORDS = {
    "高": Confidence.HIGH,
    "中": Confidence.MEDIUM,
    "低": Confidence.LOW,
    "high": Confidence.HIGH,
    "medium": Confidence.MEDIUM,
    "low": Confidence.LOW,
}
DEFAULT_CONFIDENCE = Confidence.MEDIUM

# 許可リストの照合で除く文字（空白・ハイフンの仲間・括弧）。電話番号の「03-1234-5678」「(03)1234-5678」を同じに扱う
_RE_ALLOW_STRIP = re.compile(r"[\s\-‐‑‒–—―ー−()]")
# 氏名の検出値に付く敬称（「山田太郎様」を許可リストの「山田太郎」と同じに扱う）
_RE_HONORIFIC_TAIL = re.compile(r"(様|殿|さん|君|くん|ちゃん)$")

# 速さを確かめるときの、繰り返しの文字列の長さ（短いものから順に当て、遅くなった時点で断る）
_SPEED_LENGTHS = (8, 12, 16, 20, 24, 32, 64, 128, 256, 512, WINDOW)
_SPEED_BUDGET = 0.2  # 1つの長さで、すべての試し文字列に当てる合計時間の上限（秒）
_SPEED_DEFAULT_CHARS = ("a", "1", "あ", " ", "-", "A", "漢")


class RuleError(ValueError):
    """許可リスト・利用者の規則の書き方の誤り。文面はそのまま人に見せる。"""


@dataclass(frozen=True)
class UserRule:
    """利用者の規則1つ（受け付けた後の形）。"""

    name: str
    pattern: str
    confidence: str  # Confidence の値（high / medium / low）

    def to_dict(self) -> dict:
        return {"name": self.name, "pattern": self.pattern, "confidence": self.confidence}


# ---------------------------------------------------------------- 許可リスト


def normalize_allow(value: str) -> str:
    """許可リストの照合に使う形（全角→半角・空白とハイフンと括弧を除く・英字は小文字）。"""
    v = unicodedata.normalize("NFKC", str(value))
    return _RE_ALLOW_STRIP.sub("", v).lower()


def _content_lines(text: str | None):
    """(行番号, 中身) を返す。空行と「#」で始まる行（説明書き）は飛ばす。"""
    for no, line in enumerate((text or "").splitlines(), start=1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        yield no, s


def parse_allow_list(text: str | None) -> list[str]:
    """許可リストの文字列（1行に1つ）を値の一覧にする。重複は除き、入れた順を保つ。誤りは RuleError。"""
    values: list[str] = []
    seen: set[str] = set()
    errors: list[str] = []
    for no, s in _content_lines(text):
        if len(s) > MAX_ALLOW_VALUE_LEN:
            errors.append(f"{no}行目: 長すぎます（{MAX_ALLOW_VALUE_LEN} 文字まで。1行に1つの値を書きます）")
            continue
        key = normalize_allow(s)
        if not key:
            errors.append(f"{no}行目: 空白・ハイフンだけの値は使えません")
            continue
        if key in seen:
            continue
        seen.add(key)
        values.append(s)
    if len(values) > MAX_ALLOW_VALUES:
        errors.append(f"値が多すぎます（{len(values):,} 件。{MAX_ALLOW_VALUES:,} 件まで）")
    if errors:
        raise RuleError(_join_errors("拾わない値（許可リスト）", errors))
    return values


# ---------------------------------------------------------------- 利用者の規則


def _split_fields(line: str) -> list[str]:
    """行を「|」で区切る。ただし正規表現の中の「|」（括弧・文字クラスの中、「\\|」）では区切らない。"""
    fields: list[str] = []
    cur: list[str] = []
    depth = 0
    in_class = False
    i = 0
    while i < len(line):
        c = line[i]
        if c == "\\" and i + 1 < len(line):
            cur.append(line[i : i + 2])
            i += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
        elif c == "[":
            in_class = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth = max(0, depth - 1)
        elif c == "|" and depth == 0:
            fields.append("".join(cur))
            cur = []
            i += 1
            continue
        cur.append(c)
        i += 1
    fields.append("".join(cur))
    return fields


def parse_rules(text: str | None, check_speed: bool = True) -> list[UserRule]:
    """利用者の規則の文字列（1行に1つ「名前 | 正規表現 | 確度」）を規則の一覧にする。誤りは RuleError。

    確度は 高・中・低（省けば 中）。「|」を含まない行は、その語（正規表現）がそのまま名前になる。
    check_speed=False は、受け付け済みの規則を読み直すとき（速さは受け付けたときに確かめてある）。
    """
    rules: list[UserRule] = []
    errors: list[str] = []
    for no, s in _content_lines(text):
        fields = [f.strip() for f in _split_fields(s)]
        if len(fields) > 3:
            errors.append(
                f"{no}行目: 区切りの「|」が多すぎます（「名前 | 正規表現 | 確度」の3つまで）。"
                "正規表現の中で「|」（または）を使うときは (?:A|B) のように括弧で囲んでください"
            )
            continue
        if len(fields) == 1:
            name = pattern = fields[0]
            conf_word = ""
        else:
            name, pattern = fields[0], fields[1]
            conf_word = fields[2] if len(fields) == 3 else ""
        if not name:
            errors.append(f"{no}行目: 名前が空です（「社員番号 | EMP-\\d{{6}} | 中」のように先頭に名前を書きます）")
            continue
        if len(name) > MAX_NAME_LEN:
            errors.append(f"{no}行目: 名前が長すぎます（{MAX_NAME_LEN} 文字まで）")
            continue
        if not pattern:
            errors.append(f"{no}行目: 正規表現が空です（名前の後の「|」に続けて、探す語か正規表現を書きます）")
            continue
        if len(fields) == 3 and not conf_word:
            errors.append(f"{no}行目: 確度が空です（高・中・低のどれかを書くか、最後の「|」ごと省きます）")
            continue
        conf = DEFAULT_CONFIDENCE
        if conf_word:
            conf = CONFIDENCE_WORDS.get(unicodedata.normalize("NFKC", conf_word).lower())
            if conf is None:
                errors.append(
                    f"{no}行目: 確度は「高」「中」「低」のどれかにしてください（「{conf_word}」と書かれています）"
                )
                continue
        problem = check_pattern(pattern, check_speed=check_speed)
        if problem:
            errors.append(f"{no}行目（{name}）: {problem}")
            continue
        rules.append(UserRule(name=name, pattern=_normalize_pattern(pattern), confidence=conf.value))
    if len(rules) > MAX_RULES:
        errors.append(f"規則が多すぎます（{len(rules)} 件。{MAX_RULES} 件まで）")
    if errors:
        raise RuleError(_join_errors("自分で足す規則", errors))
    return rules


def rules_from_dicts(items: list[dict] | None) -> list[UserRule]:
    """ジョブの設定に保存した規則（to_dict の形）を読み直す。"""
    out = []
    for d in items or []:
        out.append(UserRule(name=str(d["name"]), pattern=str(d["pattern"]), confidence=str(d["confidence"])))
    return out


def _normalize_pattern(pattern: str) -> str:
    """正規表現を、検査する本文と同じ形（NFKC。全角の英数字・記号は半角）に寄せる。

    本文は検出の前に NFKC で寄せてあるので、全角で書いた「ＥＭＰ－」も「EMP-」として当たるようにする。
    """
    return unicodedata.normalize("NFKC", pattern)


def check_pattern(pattern: str, check_speed: bool = True) -> str | None:
    """正規表現として受け付けられるかを調べる。だめなら理由（日本語）、よければ None。"""
    if len(pattern) > MAX_PATTERN_LEN:
        return f"正規表現が長すぎます（{len(pattern)} 文字。{MAX_PATTERN_LEN} 文字まで）"
    p = _normalize_pattern(pattern)
    try:
        tree = _sre_p.parse(p)
        compiled = re.compile(p)
    except re.error as e:
        return f"正規表現の書き方に誤りがあります（{_describe_re_error(e)}）"
    except (RecursionError, OverflowError, ValueError) as e:
        return f"正規表現の書き方に誤りがあります（{type(e).__name__}）"
    if tree.getwidth()[0] == 0:
        return (
            "長さ0の文字列にも当たる書き方です（例: 「\\d*」だけ）。どこにでも当たってしまうので、"
            "「\\d+」のように少なくとも1文字に当たる形にしてください"
        )
    shape = _risky_shape(tree)
    if shape:
        return shape
    if check_speed:
        slow = _check_speed(compiled, tree)
        if slow:
            return slow
    return None


def _describe_re_error(e: re.error) -> str:
    """re.error を日本語にする（よくあるものだけ。ほかは位置を添えて英語の文のまま）。"""
    msg = str(e.msg) if hasattr(e, "msg") else str(e)
    table = {
        "missing ), unterminated subpattern": "「(」に対応する「)」がありません",
        "unbalanced parenthesis": "「)」に対応する「(」がありません",
        "unterminated character set": "「[」に対応する「]」がありません",
        "nothing to repeat": "「*」「+」「?」「{」の前に繰り返す文字がありません",
        "multiple repeat": "繰り返しの記号が続いています（「++」「*?+」など）",
        "bad escape (end of pattern)": "最後が「\\」で終わっています",
    }
    for k, v in table.items():
        if msg.startswith(k):
            msg = v
            break
    pos = getattr(e, "pos", None)
    return f"{msg}・{pos + 1} 文字目" if isinstance(pos, int) else msg


_REPEATS = {_sre_c.MAX_REPEAT, _sre_c.MIN_REPEAT}
if hasattr(_sre_c, "POSSESSIVE_REPEAT"):
    _REPEATS.add(_sre_c.POSSESSIVE_REPEAT)


def _children(op, av) -> list:
    """構文木の1つの節の、子の部分木の一覧。"""
    if op in _REPEATS:
        return [av[2]]
    if op is _sre_c.SUBPATTERN:
        return [av[3]]
    if op is _sre_c.BRANCH:
        return list(av[1])
    if op in (_sre_c.ASSERT, _sre_c.ASSERT_NOT):
        return [av[1]]
    if hasattr(_sre_c, "ATOMIC_GROUP") and op is _sre_c.ATOMIC_GROUP:
        return [av]
    if op is _sre_c.GROUPREF_EXISTS:
        return [x for x in av[1:] if x is not None]
    return []


def _has_variable_repeat(sub) -> bool:
    """部分木の中に、回数の決まっていない繰り返し（+・*・?・{1,3} 等）があるか。"""
    for op, av in sub:
        if op in _REPEATS and av[0] != av[1]:
            return True
        if any(_has_variable_repeat(c) for c in _children(op, av)):
            return True
    return False


def _risky_shape(sub) -> str | None:
    """極端に遅くなりうる形（後方参照・量指定子の入れ子）なら理由を返す。"""
    for op, av in sub:
        if op in (_sre_c.GROUPREF, _sre_c.GROUPREF_EXISTS):
            return "後方参照（\\1 など）は使えません（検査が極端に遅くなることがあるため）"
        if op in _REPEATS and av[1] > 1 and _has_variable_repeat(av[2]):
            return (
                "繰り返しの中に、回数の決まっていない繰り返しを入れる書き方（例: (\\d+)+ や (a*)*）は使えません"
                "（検査が極端に遅くなることがあるため）。「\\d+」のように1段の繰り返しに書き直してください"
            )
        for c in _children(op, av):
            found = _risky_shape(c)
            if found:
                return found
    return None


def _sample_chars(sub, out: list[str]) -> None:
    """速さを確かめる試し文字列に使う文字（正規表現が当てにいく文字）を集める。"""
    for op, av in sub:
        if len(out) >= 8:
            return
        if op is _sre_c.LITERAL:
            out.append(chr(av))
        elif op is _sre_c.IN:
            for iop, iav in av:
                if iop is _sre_c.LITERAL:
                    out.append(chr(iav))
                elif iop is _sre_c.RANGE:
                    out.append(chr(iav[0]))
                elif iop is _sre_c.CATEGORY:
                    out.append({"CATEGORY_DIGIT": "1", "CATEGORY_SPACE": " "}.get(str(iav), "a"))
                break
        for c in _children(op, av):
            _sample_chars(c, out)


def _check_speed(compiled: re.Pattern, tree) -> str | None:
    """繰り返しの文字列に実際に当てて時間を測り、長くかかるなら理由を返す。

    短い文字列から順に当て、1つの長さで合計 _SPEED_BUDGET 秒を超えた時点で断る（長い文字列で固まる前に止める）。
    最後の長さは検査で1回に当てる文字数（WINDOW）と同じにしてある。
    """
    chars: list[str] = []
    _sample_chars(tree, chars)
    pool = list(dict.fromkeys([c for c in chars if c.isprintable()] + list(_SPEED_DEFAULT_CHARS)))[:12]
    mixed = "".join(pool[:4])
    for n in _SPEED_LENGTHS:
        probes = [c * n + "\x00" for c in pool]
        probes.append((mixed * (n // max(1, len(mixed)) + 1))[:n] + "\x00")
        started = time.perf_counter()
        for text in probes:
            for _ in compiled.finditer(text):
                pass
            if time.perf_counter() - started > _SPEED_BUDGET:
                return (
                    "当てるのに時間がかかりすぎる書き方です（同じ文字が続く所で、当て方を何通りも試してしまう形）。"
                    "「.*」「\\s*」などの繰り返しを減らすか、「\\d{6}」のように回数を決めた形に書き直してください"
                )
    return None


def _join_errors(what: str, errors: list[str]) -> str:
    shown = errors[:MAX_ERRORS_SHOWN]
    more = f"（ほか {len(errors) - len(shown)} 件）" if len(errors) > len(shown) else ""
    return f"「{what}」の書き方に誤りがあります: " + " ／ ".join(shown) + more


# ---------------------------------------------------------------- 検査で使う形


@dataclass
class _Compiled:
    rule: UserRule
    regex: re.Pattern
    confidence: Confidence


class Matcher:
    """検査中に使う、許可リストと利用者の規則（ワーカーの中で作る）。"""

    def __init__(self, allow_values: list[str], rules: list[UserRule]):
        self.allow = frozenset(k for k in (normalize_allow(v) for v in allow_values) if k)
        self.rules = [_Compiled(r, re.compile(r.pattern), Confidence(r.confidence)) for r in rules]

    def is_allowed(self, pii_type: str, value: str) -> bool:
        """検出した値が許可リストの値と一致するか（正規化して完全一致。部分一致はしない）。"""
        if not self.allow:
            return False
        key = normalize_allow(value)
        if key in self.allow:
            return True
        if pii_type == "name":
            bare = _RE_HONORIFIC_TAIL.sub("", key)
            return bool(bare) and bare in self.allow
        return False

    def find(self, text: str) -> list:
        """本文（normalize 済み）から利用者の規則に当たるものを探す。1回に当てる文字数は WINDOW まで。"""
        from .detectors import Hit

        if not self.rules or not text:
            return []
        hits = []
        n = len(text)
        for c in self.rules:
            start = 0
            while True:
                end = min(start + WINDOW, n)
                last = end >= n
                limit = n if last else start + STEP  # 次の区切りが拾う範囲（境目の当たりを二重に数えない）
                for m in c.regex.finditer(text, start, end):
                    if m.start() >= limit:
                        break
                    if not last and m.end() == end:
                        # 区切りの終わりまで届いた当たりは、区切りで切られた（「$」が区切りの終わりに当たった）かもしれない。
                        # 当たりの頭から WINDOW 文字の範囲で当て直す
                        m = c.regex.match(text, m.start(), min(n, m.start() + WINDOW))
                        if m is None:
                            continue
                    if m.end() > m.start():
                        hits.append(
                            Hit(
                                CUSTOM_TYPE,
                                c.confidence,
                                m.group(0),
                                m.start(),
                                m.end(),
                                f"利用者の規則「{c.rule.name}」",
                            )
                        )
                if last:
                    break
                start += STEP
        return hits


@lru_cache(maxsize=16)
def _matcher_cached(allow: tuple[str, ...], rules: tuple[tuple[str, str, str], ...]) -> Matcher:
    return Matcher(list(allow), [UserRule(*r) for r in rules])


def matcher_for(options) -> Matcher | None:
    """検査の設定（ScanOptions）から Matcher を作る。許可リストも規則も無ければ None。"""
    allow = tuple(getattr(options, "allow_values", None) or ())
    rules = tuple(
        (r.name, r.pattern, r.confidence) for r in rules_from_dicts(getattr(options, "custom_rules", None) or [])
    )
    if not allow and not rules:
        return None
    return _matcher_cached(allow, rules)


def allow_signature(values: list[str] | None) -> list[str]:
    """前回の結果を使い回してよいかの判定に使う許可リストの形（正規化して並べ替え。書き順・重複では変えない）。"""
    return sorted({k for k in (normalize_allow(v) for v in values or []) if k})


def rule_names(rules: list[dict] | None) -> list[str]:
    """ジョブの設定に保存した規則の名前の一覧。"""
    return [str(d.get("name", "")) for d in rules or []]

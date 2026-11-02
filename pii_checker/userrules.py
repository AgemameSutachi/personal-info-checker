"""拾わない値（許可リスト）と自分で足す規則（利用者の規則。自前の語・正規表現）。

- 拾わない値: 1行に1つの値。検出した値（伏せる前）を正規化し、拾わない値（同じく正規化）と完全に一致したら、
  その検出は数えない（部分一致はしない）。外した件数は項目ごとに数えて残す（黙って消さない）。
- 自分で足す規則: 1行に1つ「名前 | 正規表現 | 確度」。当たった値を種類 custom（利用者の規則）として検出する。
  書式・正規表現の誤りは、検査を始める前に「何行目の何が悪いか」を日本語で返して断る。
  正規表現は複数行モード（re.MULTILINE。「^」「$」が行の頭・終わりに当たる）で当てる。

極端に遅くなる正規表現への備え（規則は利用者が書くので、検査が終わらなくなる書き方を先に断る）:
- 長さは MAX_PATTERN_LEN 文字まで。後方参照と、量指定子の入れ子（(\\d+)+ の形）は断る
- 長さ0の文字列に当たりうる書き方（a* だけ等）は断る（どこにでも当たり、件数が意味を持たない）
- 同じ文字に当たる長い繰り返しを続けた形（.*.*x・[a-z]{1,200}[a-z]{1,200}! など）と、繰り返しの中の選択肢が
  同じ文字で始まりうる形（(?:a|b|ab)*c など）は断る。回数の上限が LONG_REPEAT を超える繰り返しは、上限の無い
  繰り返しと同じに扱う
- 受け付ける前に、繰り返しの文字列へ実際に当てて時間を測り、長くかかるものは断る（_check_speed）
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
    import re._compiler as _sre_compile
    import re._constants as _sre_c
    import re._parser as _sre_p
except ImportError:  # pragma: no cover  古い版の Python
    import sre_compile as _sre_compile  # type: ignore
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
LONG_REPEAT = 16  # 回数の上限がこれを超える繰り返し（{1,200} など）は、上限の無い繰り返し（+・*）と同じに扱う
RULE_FLAGS = re.MULTILINE  # 規則を当てるときの指定（「^」「$」を行の頭・終わりに当てる）

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
_SPEED_LENGTHS = (8, 12, 16, 20, 24, 32, 64, 256, WINDOW)
_SPEED_ABORT = 0.05  # 試し文字列1本でこれ（秒）を超えたら、長さに関わらずすぐ断る（急に遅くなる形）
# WINDOW 文字の試し文字列1本の時間が、基準の正規表現（_SPEED_REFERENCE）の何倍までなら受け付けるか。
# 基準は同じ時にこの PC で測るので、PC の速さ・混み具合に左右されない。文字数の2乗で遅くなる普通の形（\w+\d+ など）は
# 1本あたり基準の数倍に収まり、区切って当てるので検査を止めない。それより桁違いに遅い形（\w+\w?\d+x は数百倍）だけを断る
_SPEED_RATIO = 10.0
_SPEED_FLOOR = 0.002  # これ（秒）より速ければ比べない（測り方の揺れで断らない）
# 明らかに遅く見えた1本を、もう1回だけ測り直す上限（秒）。これより長くかかった1本は測り直さずに断る
# （PC が一瞬止まった揺れは測り直せば消える。本当に遅い規則を何秒も測り直して待たせない）
_SPEED_RECHECK_LIMIT = 1.0
_SPEED_REFERENCE = r"\w+@"  # 「名前@」のように、普通に書かれる程度の手間の正規表現
_SPEED_DEFAULT_CHARS = ("a", "1", "あ", " ", "-", "A", "漢")
# 2つの繰り返しが同じ文字に当たりうるかを確かめる文字（本文は NFKC で寄せてあるので半角の記号・英数字と仮名・漢字）
_OVERLAP_SAMPLE = "".join(chr(i) for i in range(32, 127)) + "\t\nあアー漢〒・々"


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
    class_start = -1  # 文字クラスの中身の始まり（ここに来た「]」は閉じではなく文字そのもの: []|] や [^]|]）
    i = 0
    while i < len(line):
        c = line[i]
        if c == "\\" and i + 1 < len(line):
            cur.append(line[i : i + 2])
            i += 2
            continue
        if in_class:
            if c == "^" and i == class_start:
                class_start += 1
            elif c == "]" and i != class_start:
                in_class = False
        elif c == "[":
            in_class = True
            class_start = i + 1
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
    """正規表現を、検査する本文（NFKC で寄せてある）に当たる形にする。

    全角の英数字だけは半角に寄せる（「ＥＭＰ\\ｄ」を「EMP\\d」として扱う）。全角の記号など、寄せると形が変わる
    ほかの文字は、正規表現の記号にせず、その文字そのもの（本文と同じく NFKC で寄せた文字）として当てる。
    全体を NFKC で寄せると「（本社）」が「(本社)」というグループに、「＊」が繰り返しの記号に化けるため。
    """
    out: list[str] = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern) and _is_fullwidth_symbol(pattern[i + 1]):
            # 「\（」のように全角の記号を逃がしてあっても、同じくその文字そのものとして当てる
            out.append(re.escape(unicodedata.normalize("NFKC", pattern[i + 1])))
            i += 2
            continue
        if c == "\\" and i + 1 < len(pattern):
            out.append(c + _fold_alnum(pattern[i + 1]))
            i += 2
            continue
        if _is_fullwidth_symbol(c):
            out.append(re.escape(unicodedata.normalize("NFKC", c)))
        else:
            out.append(_fold_alnum(c))
        i += 1
    return "".join(out)


def _fold_alnum(c: str) -> str:
    """全角の英数字（０-９・Ａ-Ｚ・ａ-ｚ）を半角にする。ほかの文字はそのまま。"""
    o = ord(c)
    if 0xFF10 <= o <= 0xFF19 or 0xFF21 <= o <= 0xFF3A or 0xFF41 <= o <= 0xFF5A:
        return chr(o - 0xFEE0)
    return c


def _is_fullwidth_symbol(c: str) -> bool:
    """NFKC で形が変わる、全角の英数字以外の文字（全角の記号・半角の仮名・㈱ など）か。"""
    return _fold_alnum(c) == c and unicodedata.normalize("NFKC", c) != c


def check_pattern(pattern: str, check_speed: bool = True) -> str | None:
    """正規表現として受け付けられるかを調べる。だめなら理由（日本語）、よければ None。"""
    if len(pattern) > MAX_PATTERN_LEN:
        return f"正規表現が長すぎます（{len(pattern)} 文字。{MAX_PATTERN_LEN} 文字まで）"
    p = _normalize_pattern(pattern)
    try:
        tree = _sre_p.parse(p, RULE_FLAGS)
        compiled = re.compile(p, RULE_FLAGS)
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


def _is_long_repeat(op, av) -> bool:
    """回数の決まっていない繰り返しで、上限が無いか LONG_REPEAT を超えるもの（+・*・{1,200} など）か。"""
    return op in _REPEATS and av[0] != av[1] and av[1] > LONG_REPEAT


_SINGLE_CHAR_OPS = {_sre_c.LITERAL, _sre_c.NOT_LITERAL, _sre_c.IN, _sre_c.ANY}


def _first_items(seq, state) -> list | None:
    """並び（部分木）の1文字目に当たりうる1文字の部品の一覧。分からなければ None。"""
    out: list = []
    for op, av in seq:
        if op in _SINGLE_CHAR_OPS:
            out.append((op, av))
            return out
        if op is _sre_c.AT or op in (_sre_c.ASSERT, _sre_c.ASSERT_NOT):
            continue  # 位置の指定・先読みは文字を食べない
        if op in _REPEATS:
            inner = _first_items(av[2], state)
            if inner is None:
                return None
            out += inner
            if av[0] > 0:
                return out
            continue
        if op is _sre_c.SUBPATTERN:
            inner = _first_items(av[3], state)
            if inner is None:
                return None
            out += inner
            if _sre_p.SubPattern(state, list(av[3])).getwidth()[0] > 0:
                return out
            continue
        if op is _sre_c.BRANCH:
            for alt in av[1]:
                inner = _first_items(alt, state)
                if inner is None:
                    return None
                out += inner
            return out
        return None
    return out


def _chars_matched(items: list, state) -> set[str] | None:
    """1文字の部品の一覧が当たる、試しの文字の集まり。作れなければ None。"""
    got: set[str] = set()
    for item in items:
        try:
            single = _sre_compile.compile(_sre_p.SubPattern(state, [item]), RULE_FLAGS)
        except Exception:  # noqa: BLE001  内部の部品で作れない形は「分からない」として扱う
            return None
        got.update(ch for ch in _OVERLAP_SAMPLE if single.fullmatch(ch))
    return got


def _overlap(a_items: list | None, b_items: list | None, state) -> bool:
    """2つの1文字目の候補が、同じ文字に当たりうるか（分からなければ False）。"""
    if a_items is None or b_items is None:
        return False
    a, b = _chars_matched(a_items, state), _chars_matched(b_items, state)
    return bool(a and b and a & b)


_MSG_NESTED = (
    "繰り返しの中に、回数の決まっていない繰り返しを入れる書き方（例: (\\d+)+ や (a*)*）は使えません"
    "（検査が極端に遅くなることがあるため）。「\\d+」のように1段の繰り返しに書き直してください"
)
_MSG_ADJACENT = (
    "同じ文字に当たる長い繰り返しを続けた書き方（例: .*.*x・\\d*\\d*・[a-z]{1,200}[a-z]{1,200}!）は使えません"
    "（当たらない所で当て方を何通りも試し、検査が極端に遅くなるため）。繰り返しを1つにまとめるか、"
    f"「\\d{{6}}」のように回数を決めた形（上限 {LONG_REPEAT} 回まで）に書き直してください"
)
_MSG_BRANCH = (
    "繰り返しの中の選択肢が同じ文字で始まりうる書き方（例: (?:a|b|ab)*c・(\\w|\\d)+x）は使えません"
    "（当て方を何通りも試し、検査が遅くなるため）。「[ab]+c」「\\w+x」のように1つの文字の集まりに書き直してください"
)


def _risky_shape(sub, state=None, top: bool = True) -> str | None:
    """極端に遅くなりうる形（後方参照・量指定子の入れ子・重なる長い繰り返しの連続・重なる選択肢の繰り返し）なら理由を返す。

    top は正規表現の一番外の並びか。一番外の並びの最後の2つ（「\\w+\\d+」で終わる形）は、両方が当たれば
    そこで当たりが決まり、後ろで失敗して当て直すことが無いので、続いた繰り返しでも断らない。
    """
    state = state if state is not None else getattr(sub, "state", None)
    items = list(sub)
    for idx, (op, av) in enumerate(items):
        if op in (_sre_c.GROUPREF, _sre_c.GROUPREF_EXISTS):
            return "後方参照（\\1 など）は使えません（検査が極端に遅くなることがあるため）"
        if op in _REPEATS and av[1] > 1 and _has_variable_repeat(av[2]):
            return _MSG_NESTED
        if state is not None and op in _REPEATS and av[1] > 1:
            if _ambiguous_branch(av[2], state) or _repeat_body_overlaps(av[2], state):
                return _MSG_BRANCH
        at_end = top and idx + 2 == len(items)
        if state is not None and not at_end and _is_long_repeat(op, av) and idx + 1 < len(items):
            nop, nav = items[idx + 1]
            if _is_long_repeat(nop, nav) and _overlap(_first_items(av[2], state), _first_items(nav[2], state), state):
                return _MSG_ADJACENT
        for c in _children(op, av):
            found = _risky_shape(c, state, top=False)
            if found:
                return found
    return None


def _ambiguous_branch(sub, state) -> bool:
    """部分木の中に、繰り返すと当て方が何通りにもなる選択肢（|）があるか。

    次のどれかに当たる選択肢を数える（繰り返しの中に置くと、同じ文字の並びを何通りにも分けて試すため）:
    - 長さの違う選択肢がある（(?:a|b|ab)・(a|aa) は「aa」を a+a とも aa とも取れる）
    - 長さ0の選択肢が2つ以上ある（(a|a) は構文解析で a(?:|) にくくられる）
    - 1文字目に同じ文字が当たりうる選択肢の組がある
    """
    for op, av in sub:
        if op is _sre_c.BRANCH:
            alts = [list(a) for a in av[1]]
            widths = [_sre_p.SubPattern(state, a).getwidth() for a in alts]
            if len(set(widths)) > 1:
                return True
            if sum(1 for w in widths if w[0] == 0) > 1:
                return True
            firsts = [_first_items(a, state) for a in alts]
            for i in range(len(firsts)):
                for j in range(i + 1, len(firsts)):
                    if _overlap(firsts[i], firsts[j], state):
                        return True
        for c in _children(op, av):
            if _ambiguous_branch(c, state):
                return True
    return False


def _repeat_body_overlaps(body, state) -> bool:
    """繰り返す中身が、同じ文字で始まりうる選択肢を持つグループか（(?:a|b|ab)・(\\w|\\d) の形）。

    1文字の部品をそのまま繰り返す形（\\w+・[ab]+）は速いので数えない。グループの中の選択肢（|）か、
    グループの中の文字の集まりで、同じ文字に当たりうるもの同士があるときだけ真。
    """
    seq = list(body)
    if len(seq) != 1 or seq[0][0] is not _sre_c.SUBPATTERN:
        return False
    inner = list(seq[0][1][3])
    if len(inner) == 1 and inner[0][0] is _sre_c.BRANCH:
        alts = [_first_items(alt, state) for alt in inner[0][1][1]]
        for i in range(len(alts)):
            for j in range(i + 1, len(alts)):
                if _overlap(alts[i], alts[j], state):
                    return True
        return False
    if len(inner) == 1 and inner[0][0] is _sre_c.IN:
        # (\w|\d) は構文解析で1つの文字の集まり（IN）にまとめられる。まとめた中身同士が重なるかを見る
        members = [m for m in inner[0][1] if m[0] is not _sre_c.NEGATE]
        if len(members) == len(inner[0][1]):
            for i in range(len(members)):
                for j in range(i + 1, len(members)):
                    if _overlap([(_sre_c.IN, [members[i]])], [(_sre_c.IN, [members[j]])], state):
                        return True
    return False


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


_MSG_SLOW = (
    "当てるのに時間がかかりすぎる書き方です（同じ文字が続く所で、当て方を何通りも試してしまう形）。"
    "「.*」「\\s*」などの繰り返しを減らすか、「\\d{6}」のように回数を決めた形に書き直してください"
)


def _time_once(compiled: re.Pattern, text: str) -> float:
    started = time.perf_counter()
    for _ in compiled.finditer(text):
        pass
    return time.perf_counter() - started


@lru_cache(maxsize=1)
def _reference_pattern() -> re.Pattern:
    return re.compile(_SPEED_REFERENCE, RULE_FLAGS)


def _reference_time_now(length: int) -> float:
    """同じ長さの試し文字列に基準の正規表現を当てる時間（今測る。3回のうち最も速い値。数ミリ秒で終わる）。"""
    ref = _reference_pattern()
    ref_text = "a" * max(1, length - 1) + "\x00"
    return max(_SPEED_FLOOR / _SPEED_RATIO, min(_time_once(ref, ref_text) for _ in range(3)))


def _slower_than_reference(compiled: re.Pattern, text: str) -> bool:
    """規則が基準の正規表現の _SPEED_RATIO 倍より遅いか。

    基準と規則を同じ時に交互に3回ずつ測り、それぞれ最も速い値で比べる。基準を一度だけ測って使い回すと、
    PC が混んでいた時の基準で遅い規則を通したり、空いていた時の基準で普通の規則を断ったりするため。
    """
    ref = _reference_pattern()
    ref_text = "a" * max(1, len(text) - 1) + "\x00"  # 同じ長さで比べる
    ref_best = cand_best = float("inf")
    for _ in range(3):
        ref_best = min(ref_best, _time_once(ref, ref_text))
        cand_best = min(cand_best, _time_once(compiled, text))
    return cand_best > max(_SPEED_FLOOR, _SPEED_RATIO * ref_best)


def _check_speed(compiled: re.Pattern, tree) -> str | None:
    """繰り返しの文字列に実際に当てて時間を測り、長くかかるなら理由を返す。

    短い文字列から順に当て、試し文字列1本で _SPEED_ABORT 秒を超えたらすぐ断る（急に遅くなる形で固まる前に止める）。
    最後の長さ（検査で1回に当てる文字数 WINDOW）では、基準の正規表現の _SPEED_RATIO 倍を超えるものを断る。
    超えたときは測り直して、最も速い値で決める（ほかの処理と重なった揺れで断らない）。
    普通の規則は全部で数ミリ秒で終わるので、受け付けるときに待たせない。
    """
    chars: list[str] = []
    _sample_chars(tree, chars)
    pool = list(dict.fromkeys([c for c in chars if c.isprintable()] + list(_SPEED_DEFAULT_CHARS)))[:12]
    mixed = "".join(pool[:4])
    for n in _SPEED_LENGTHS:
        probes = [c * n + "\x00" for c in pool]
        probes.append((mixed * (n // max(1, len(mixed)) + 1))[:n] + "\x00")
        for text in probes:
            took = _time_once(compiled, text)
            # 1本で _SPEED_ABORT を超えたら、長い文字列へ進まずにここで決める（急に遅くなる形で固まらないため）。
            # PC が混んでいると普通の規則でも超えうるので、同じ長さの基準と交互に測り直して、桁違いのときだけ断る
            if took > _SPEED_ABORT:
                # (a) 明らかに遅い（_SPEED_ABORT の10倍超）とき: 規則をもう1回だけ測り直し、2回とも基準の _SPEED_RATIO 倍を
                #     超えたら断る（1回だけで決めると、PC が一瞬止まっただけの普通の規則まで断る）。1本が
                #     _SPEED_RECHECK_LIMIT を超えたものは測り直さずに断る（遅い規則ほど測り直しも遅く、待たせるため）。
                # (b) 境目のとき: PC の混み具合の揺れかもしれないので、同じ長さの基準と交互に3回ずつ測って決める。
                # どちらも「遅くない」と分かったら、ここでは受け付けない。残りの試し文字列（本当に遅い文字の並び）と
                # 長い文字列を調べ終えてから受け付ける（混んでいて速い並びが一瞬遅く見えただけのことがあるため）
                if took > 10 * _SPEED_ABORT:
                    limit = _SPEED_RATIO * _reference_time_now(len(text))
                    if took > limit and (took > _SPEED_RECHECK_LIMIT or _time_once(compiled, text) > limit):
                        return _MSG_SLOW
                    continue
                if _slower_than_reference(compiled, text):
                    return _MSG_SLOW
                continue
            if n == WINDOW and took > _SPEED_FLOOR and _slower_than_reference(compiled, text):
                return _MSG_SLOW
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
        self.rules = [_Compiled(r, re.compile(r.pattern, RULE_FLAGS), Confidence(r.confidence)) for r in rules]

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
        """本文（normalize 済み）から利用者の規則に当たるものを探す。1回に当てる文字数は WINDOW まで。

        当てる前に改行（CR LF・CR）を LF に寄せる（re の「$」「^」は LF でしか行の境目にならず、Excel のセル内改行・
        メールの本文などの CR LF で行末の規則が当たらないため）。返す位置は元の本文での位置に戻す。
        """
        from .detectors import Hit

        if not self.rules or not text:
            return []
        text, to_original = _fold_newlines(text)
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
                                to_original(m.start()),
                                to_original(m.end()),
                                rule_text(c.rule.name),
                            )
                        )
                if last:
                    break
                start += STEP
        return hits


def _fold_newlines(text: str):
    """(CR LF・CR を LF に寄せた本文, 寄せた本文の位置→元の本文の位置)。CR が無ければ本文をそのまま返す。

    CR だけの改行は1文字のまま LF にするので位置は変わらない。CR LF は1文字に縮むので、縮めた改行より後ろの位置は
    その数だけ元へずらす。
    """
    if "\r" not in text:
        return text, _same_position
    import bisect

    merged: list[int] = []  # 寄せた本文での、CR LF を縮めた改行の位置
    removed = 0
    for m in re.finditer("\r\n", text):
        merged.append(m.start() - removed)
        removed += 1
    folded = text.replace("\r\n", "\n").replace("\r", "\n")
    if not merged:
        return folded, _same_position
    return folded, lambda pos: pos + bisect.bisect_left(merged, pos)


def _same_position(pos: int) -> int:
    return pos


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


RULE_KEY_PREFIX = CUSTOM_TYPE + "/"  # 異なる値・内訳を規則ごとに分けて数える鍵（「custom/社員番号」）
_RULE_TEXT_HEAD = "利用者の規則「"  # 明細の検出規則の欄の形（「利用者の規則「社員番号」」）


def rule_text(name: str) -> str:
    """明細の「検出規則」の欄に出す文（「利用者の規則「社員番号」」）。"""
    return f"{_RULE_TEXT_HEAD}{name}」"


def rule_name_of_text(rule: str | None) -> str | None:
    """「検出規則」の欄の文から規則の名前を取り出す。利用者の規則の文でなければ None。"""
    if rule and rule.startswith(_RULE_TEXT_HEAD) and rule.endswith("」"):
        return rule[len(_RULE_TEXT_HEAD) : -1]
    return None


def rule_key(name: str) -> str:
    """規則ごとに分けて数えるときの種類の鍵（「custom/社員番号」）。"""
    return RULE_KEY_PREFIX + name


def rule_name_of_key(key: str | None) -> str | None:
    """規則ごとの種類の鍵から規則の名前を取り出す。規則ごとの鍵でなければ None。"""
    if key and key.startswith(RULE_KEY_PREFIX):
        return key[len(RULE_KEY_PREFIX) :]
    return None


def rule_names(rules: list[dict] | None) -> list[str]:
    """ジョブの設定に保存した規則の名前の一覧。"""
    return [str(d.get("name", "")) for d in rules or []]

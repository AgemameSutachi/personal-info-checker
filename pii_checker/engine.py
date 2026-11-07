"""1つの実ファイルを検査するエンジン。

方針（「このフォルダに個人情報は無い」と言い切るための不変条件）:
- 拡張子ではなく中身（先頭のバイト列）で形式を判定する。改名・拡張子なしでも見逃さない。
- アーカイブ・埋め込みファイルは再帰的に展開し、内側の1つ1つにも結果を残す。
- 読めなかったものは黙って飛ばさず、必ず「検査不能」「要パスワード」として理由つきで残す。
- 例外はすべて項目の結果に変換する（1ファイルの失敗で全体を止めない）。
"""

from __future__ import annotations

import datetime as _dt
import os
import re
import shutil
import tempfile
import time
import traceback
from array import array
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Callable

from . import detectors
from .models import (
    Confidence,
    FileResult,
    Finding,
    ItemResult,
    PasswordBook,
    ScanOptions,
    Status,
)
from .userrules import CUSTOM_TYPE, normalize_allow, rule_key, rule_name_of_text

IN_MEMORY_LIMIT = 64 * 1024 * 1024  # これより大きい内側ファイルは一時ファイルに書き出して扱う
# これより大きいものはメモリへ丸ごと読まない（形式の読み方をあきらめ、文字として読める部分だけを少しずつ検査する）。
# 1プロセスのメモリ上限（procguard、1.5〜4GB）の中で、読み直しや文字列化で数倍に膨らんでも収まる大きさ
READ_ALL_LIMIT = 256 * 1024 * 1024
TEMP_PREFIX = "piichk_"  # 一時フォルダの名前の頭（片付けの目印）
OWNER_MARK = "_owner.lock"  # 一時フォルダの持ち主が開いたままにする目印のファイル
# OCR を切って検査したときの次の手（画面の項目名と、コマンドの版の引数）
OCR_OFF_HINT = (
    "「画像とスキャンした PDF の文字を OCR で読む」をオンにして再検査してください。コマンドの版は --no-ocr を外します"
)
# 一時フォルダの空きが足りないときの次の手
TEMP_DIR_HINT = (
    "「展開に使う一時フォルダ」を空きの多いドライブにして再検査してください。コマンドの版は --temp-dir で指定します"
)
# ディスクイメージの削除されたファイルも見るときの手
DEEP_SWEEP_HINT = (
    "削除されたファイルも見るなら「ディスクイメージの空き領域（削除されたファイル）も調べる」を"
    "オンにして再検査してください。コマンドの版は --deep-image-sweep を付けます"
)
# 画素数が大きすぎる画像の次の手
IMAGE_TOO_LARGE_HINT = "画像を縮小した写しを検査するか、目視で確かめてください"
# 想定外の失敗の次の手（中身が壊れているかを作ったアプリで確かめ、それでも分からなければ報告してもらう）
UNEXPECTED_HINT = (
    "作ったアプリで開けるなら、別名で保存し直した写しを検査してください。開けなければ壊れている可能性があるので"
    "元のファイルを取り直してください。開けるのに写しでも同じなら、この文のまま報告してください"
)
# 権限がなくて開けなかったときの次の手
ACCESS_DENIED_HINT = "読む権限のあるアカウントで再検査するか、そのファイルの権限を持つ人に頼んでください"
# 検査の途中で見えなくなったときの次の手
NOT_FOUND_HINT = "置き場所を確かめ、ファイルがあれば再検査してください"
# 検査の途中経過（それまでの検出）を書き出す最短の間隔。時間切れで打ち切られても、ここまでの分は残る。
# 書き出しに時間がかかる（内側の項目が多い書庫など）ときは、検査の時間の 2% 以下に収まるよう間隔を広げる
CHECKPOINT_SECONDS = 10
CHECKPOINT_EVERY = 500  # 何回の add_text ごとに時計を見るか（毎回見ると遅い）
# 住所・固定電話を「人の手がかり待ち」で値ごとに覚えておく上限（1件ごとに本文を抱える。超えた分は種類ごとの件数だけ数える）
DEFER_LIMIT = 200_000
# 見た値を覚えておく上限（Collector.seen と、ファイル全体の異なる値の集計。超えた値は件数だけ数え、異なる値には数えない）
SEEN_LIMIT = 3_000_000
# 対処のために集める検出の位置の上限（超えたら「多すぎる」として、位置を使う対処はしない。1件 32 バイトで 64MB）
POSITIONS_LIMIT = 2_000_000
# 手がかり語の無い12桁のマイナンバー（確度 低）を、表の列の文脈で落とす。列のセルに12桁の数だけが並び、その異なる値のうち
# 検査数字が合うものが半分に満たなければ、レースの ID のような番号の列とみなす（でたらめな12桁は約1割が偶然合う。
# 本物のマイナンバーの列はほぼ全部合う）。異なる値が COLUMN_ID_MIN_DISTINCT 個そろうまでは判定しない（それまでの分は今までどおり）
BARE_MY_NUMBER_RULE = "12桁・検査数字一致（手がかり語なし"
COLUMN_ID_MIN_DISTINCT = 20
COLUMN_ID_MAX_VALID_RATIO = 0.5
COLUMN_ID_TRACK = 200  # 1列で数える異なる値の上限（ここで判定を固める。メモリを食わないため）
# 番号の列と決めた後でも、検査数字の合う値（直前と違う値）がこの数だけ続いたら判定を解いて数え直す（列の途中から本物に
# 変わる表のため）。番号の列で偶然続く見込みは約 0.1 の8乗（1億分の1）
COLUMN_ID_RELEASE_STREAK = 8
RE_TWELVE_DIGITS = re.compile(r"\d{12}")
# 氏名の列が会社名の列か（株の表の英語の見出し「name」の銘柄名・2026-11-07）。列の異なる値のうち会社の印（法人格など）を
# 含むものが COLUMN_ORG_MIN_RATIO 以上なら、その列で見出しのおかげで拾えた氏名を 低 に下げる
# （人の名前の列に会社の印はまず入らない。法人格の無い社名「トヨタ自動車」は1つずつでは人の名前と見分けられない）。
# 異なる値が COLUMN_ORG_MIN_DISTINCT 個そろうまでは判定しない（名簿の先頭に法人の顧客が数件並んだだけで、後ろの人の名前を
# 下げないため）。銘柄の一覧の会社の印の割合は、異なる値 200 個の時点で 6〜74%（2026-11-07・株のデータの28ファイル。
# 松井の分売 6%・優待 9%・JPX の銘柄 10% があるので 10% にはしない）
COLUMN_ORG_MIN_DISTINCT = 50
COLUMN_ORG_MIN_RATIO = 0.05
# 列名の分かっている表（add_records）では、判定が付く前の行の社名も 中 で拾わないよう、検査の前に先頭の行を先読みして
# 判定を付ける（株の parquet の列「name」で、判定の前の 49 行ずつの社名が 中 に残っていた・2026-11-07）。
# 先読みは判定が固まる（異なる値が COLUMN_ID_TRACK 個）まで続け、固まった判定を先頭の行から使う。
# 先読みは行数とセルの文字数の合計で抑える（幅の広い表・長い文の列でメモリを食わないため）
COLUMN_ORG_PREFETCH_ROWS = 2000
COLUMN_ORG_PREFETCH_CHARS = 4_000_000
HEADER_NAME_RULE = "列見出しが「氏名」の列の値"
# 表の形で確度を 低 に下げたときに、明細の「検出規則」の末尾へ足す注（なぜ 低 なのかを使い手が引けるように）
ORG_COLUMN_NOTE = "（会社名の列とみなしたため 低）"
WEAK_HEADER_NOTE = "（左隣の「見出し語＋値」のセルを見出しにしたため 低）"


def checkpoint_path(options: ScanOptions, top_path: str) -> str:
    """1ファイルの途中経過を書き出す場所（ワーカーと実行器が同じ名前を求める）。"""
    import hashlib

    digest = hashlib.sha1(top_path.encode("utf-8", "surrogatepass")).hexdigest()[:20]
    return os.path.join(options.temp_dir or tempfile.gettempdir(), f"{TEMP_PREFIX}ckpt_{digest}.pkl")


def read_checkpoint(path: str) -> list | None:
    """途中経過（項目の一覧）を読む。無い・壊れているときは None。読んだら消す。"""
    import pickle

    try:
        with open(path, "rb") as f:
            items = pickle.load(f)
    except Exception:  # 壊れた・古い版の途中経過で、打ち切りの記録そのものを落とさない
        items = None
    try:
        os.remove(path)
    except OSError:
        pass
    return items if isinstance(items, list) else None


class NeedPassword(Exception):
    """パスワードが要る（候補を全部試しても開けなかった）。"""

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind


class Uncheckable(Exception):
    """検査できない（理由を日本語で持つ）。"""


class OutOfScope(Exception):
    """対象外として扱う形式（動画・音声・実行ファイル等）。"""


class PartialScan(Exception):
    """構造を解釈できず、文字として読める部分だけ検査した（検出は残したまま簡易検査にする）。"""


class TooLargeForMemory(Exception):
    """メモリへ丸ごと読むには大きすぎる（scan_blob が文字列の少しずつの走査に切り替える）。"""

    def __init__(self, size: int):
        super().__init__(f"{size:,} バイト")
        self.size = size


def long_path(path: str) -> str:
    """Windows の 260 文字制限を越えるパスでも開けるよう、拡張パス形式にする。"""
    if os.name != "nt" or path.startswith("\\\\?\\"):
        return path
    p = os.path.abspath(path)
    if len(p) < 240:
        return p
    if p.startswith("\\\\"):
        return "\\\\?\\UNC\\" + p[2:]
    return "\\\\?\\" + p


@dataclass
class Blob:
    """検査する中身。実ファイル（path）か、メモリ上のバイト列（data）のどちらか。"""

    display: str  # レポートに出すパス
    path: str | None = None
    data: bytes | None = None
    mtime: float | None = None
    name_hint: str = ""  # 拡張子の手がかり用（アーカイブ内のファイル名など）

    @property
    def size(self) -> int:
        if self.data is not None:
            return len(self.data)
        return os.path.getsize(long_path(self.path))

    def head(self, n: int = 8192) -> bytes:
        if self.data is not None:
            return self.data[:n]
        with open(long_path(self.path), "rb") as f:
            return f.read(n)

    def read_all(self) -> bytes:
        if self.data is not None:
            return self.data
        size = self.size
        if size > READ_ALL_LIMIT:
            raise TooLargeForMemory(size)
        with open(long_path(self.path), "rb") as f:
            return f.read()

    def open(self):
        import io

        if self.data is not None:
            return io.BytesIO(self.data)
        return open(long_path(self.path), "rb")

    @property
    def ext(self) -> str:
        name = self.name_hint or self.display.rsplit("!", 1)[-1]
        return Path(name).suffix.lower()


# 人の手がかりがあって確度 中にした住所・固定電話の明細に添える注記（手がかりが氏名などの値か、書類の題か）
PERSON_CUE_NOTE = "（同じファイルに氏名などの人の手がかりあり）"
TITLE_CUE_NOTE = "（ファイル名・本文の先頭に「{}」の書類の題があり、人の手がかりとみなした）"
RANK_CONF = {c.rank: c for c in Confidence}
_RE_HONORIFIC_TAIL = re.compile(r"(様|殿|さん|君|くん|ちゃん)$")


def _distinct_type(hit) -> str:
    """異なる値を数えるときの種類。利用者の規則は規則の名前ごとに分ける（「custom/社員番号」）。"""
    if hit.pii_type == CUSTOM_TYPE:
        name = rule_name_of_text(hit.rule)
        if name is not None:
            return rule_key(name)
    return hit.pii_type


def distinct_key(pii_type: str, value: str) -> str:
    """異なる値を数えるときの、値の同一性の形（全角→半角・空白とハイフンと括弧を除く・英字は小文字・氏名は敬称を外す）。

    「090-1234-5678」と「09012345678」、「山田 太郎様」と「山田太郎」を同じ1つと数える。許可リストの照合と同じ寄せ方。
    """
    key = normalize_allow(value)
    if pii_type == "name":
        key = _RE_HONORIFIC_TAIL.sub("", key) or key
    return key


def _count_by_rank(best: dict[str, dict[int, int]]) -> dict[str, int]:
    """種類 → {値の hash → 確度の順位} から「種類:確度」→異なる値の数を作る。"""
    counts: dict[str, int] = {}
    for pii_type, per_type in best.items():
        for rank in per_type.values():
            k = f"{pii_type}:{RANK_CONF[rank].value}"
            counts[k] = counts.get(k, 0) + 1
    return counts


def size_text(nbytes: int) -> str:
    """バイト数を人が読む大きさにする（4TB・1.5GB・300MB）。上限の文言で 1GB 未満が「0GB」にならないように。"""
    units = (("TB", 1024**4), ("GB", 1024**3), ("MB", 1024**2), ("KB", 1024))
    for i, (unit, scale) in enumerate(units):
        if nbytes >= scale:
            value = round(nbytes / scale, 1)
            if value >= 1024 and i > 0:  # 丸めで 1024 に届いたら1つ上の単位で（「1024KB」と出さない）
                unit, value = units[i - 1][0], round(nbytes / units[i - 1][1], 1)
            return f"{value:.1f}".removesuffix(".0") + unit
    return f"{nbytes}B"


@dataclass
class Collector:
    """1項目分の検出を集める。件数は「種類×確度」で全数、明細は種類×確度ごとに上限まで。"""

    item: ItemResult
    max_samples: int
    # (種類, 値) の hash → (明細の位置か -1, 見た確度, 異なる値を数える種類, 正規化した値の hash)。
    # 後ろの2つは異なる値の数を数えるためだけに持つ（メモリの中だけ。保存しない）。上限の外で後から足した値は
    # (位置, 確度) の2つだけで、異なる値には数えない。別の辞書に分けると上限の 300万件で約 275MB 余計に食う
    seen: dict[int, tuple] = field(default_factory=dict)
    # 住所は、同じ項目に人の手がかり（氏名・生年月日・マイナンバー等）があるときだけ確度 中にする（施設の一覧・
    # 番地の一覧を「個人情報の可能性あり」にしない）。手がかりを待つ住所は 低 で数えておき、finish() で決める
    person_cue: bool = False
    deferred: dict[int, list] = field(
        default_factory=dict
    )  # (種類, 値) の hash → [低で数えた件数, Hit, 明細を持つか, 引数]
    # deferred が DEFER_LIMIT 件に達した後に待たせた分（値ごとには覚えず、種類ごとの件数だけ。本文を抱えないのでメモリが増えない）
    deferred_overflow: dict[str, int] = field(default_factory=dict)
    head_chars: int = 0  # 書類の題を探すために見た本文の先頭の文字数（ファイル名は数えない）
    cue_title: str = ""  # 人の手がかりにした書類の題（「名簿」など。明細の注記を出し分ける）
    # 許可リストと利用者の規則（userrules.Matcher。どちらも無ければ None）
    matcher: object | None = None
    allowed_seen: set = field(default_factory=set)  # 許可リストで外した (種類, 値) の hash（読み直しで二重に数えない）
    # 番号の列（_ColumnDigits）で外した、手がかり語の無い12桁の値の hash。同じ本文の読み直し（xlsx のシートの XML・
    # 生データ走査）では列が分からないので、表で外した値をここで見て拾い直さない
    id_column_seen: set = field(default_factory=set)
    # ファイル全体の異なる値を集める先（種類 → {正規化した値の hash → 見た最も高い確度の順位}）。ScanContext が渡す
    distinct_sink: dict | None = None
    # CHECKPOINT_EVERY 回の add_text ごとに呼ぶ（ScanContext が途中経過を書き出す。巨大なファイルの時間切れで検出を失わない）
    on_tick: Callable[[], None] | None = None
    ticks: int = 0
    # 画面の詳細のための読み直し: 明細に検出した値そのものと伏せていない文脈も入れる（メモリの中だけ。保存しない）
    reveal: bool = False
    # 対処のための位置集め（ScanOptions.collect_positions）: 検出の構造の位置を、上限（POSITIONS_LIMIT）まで全部集める。
    # 生の値は持たない（値の開始・終了の位置だけ。ダミー化のとき書き換える側が、その場で読み直した文字から値を取る）
    collect_positions: bool = False
    positions: dict = field(
        default_factory=dict
    )  # (シート名, 種類, 確度の順位) → array('q')（行, 列, 開始, 終了 の繰り返し）
    pos_total: int = 0
    pos_overflow: bool = False
    pos_layout: str = ""  # 取り込み側（形式ごとの処理）が決める。空のあいだは位置を集めない
    pos_sheet: str = ""
    cell_pos: tuple | None = None  # 表のセルを検査している間だけ（行, 列。どちらも 1 始まり・0 始まり）
    # 表の行を、検査での通し番号（r_idx）ではなく別の鍵で位置に残すための関数（SQLite の rowid・SQL ダンプの行番号など）。
    # 表を読んでいる間だけ形式ごとの処理が入れる。None のときは通し番号をそのまま使う
    row_key: Callable[[int], int] | None = None
    pos_off: bool = False  # True の間は位置を集めない（書き換えられない表を読んでいるとき）
    # 形式ごとの処理が足す構造の情報（Oracle ダンプの {"tables": {表名: {"columns": [列名...]}}} など）。位置の集め直しのときだけ使う
    pos_info: dict = field(default_factory=dict)
    # 集めた位置（行, 列, 開始, 終了）を、別の鍵の位置の並び [(シート, 行, 列, 開始, 終了), ...] に置き換える関数。
    # docx の表のセルの文字の範囲を、その中の段落ごとの範囲にするために、表を読んでいる間だけ入れる
    pos_map: Callable[[int, int, int, int], list[tuple]] | None = None
    line_base: int | None = None  # 行の塊を検査している間だけ（塊の先頭の行番号）
    # 明細の数（(種類, 確度) → 件数）と、数え終えた明細の数（-1 は数え直し）。_has_room だけが使う
    _room: dict = field(default_factory=dict)
    _room_len: int = -1

    def add_text(
        self,
        text: str,
        location: str,
        header: str | None = None,
        method: str = "",
        raw: bool = False,
        location_fn: Callable[[int], str] | None = None,
        skip_seen: bool = False,
        weak_header: bool = False,
        id_column: bool = False,
        org_column: bool = False,
    ) -> None:
        """文字列を検査して結果に加える。

        raw=True は生データ走査（既に見つけた値は数えず、見つけた分は「残留の可能性」と記す）。
        skip_seen=True は既に見つけた値を数えないだけ（同じ本文を別の読み方でもう一度読むとき）。
        どちらでも、既に見た値をより高い確度で見直したときは明細の確度を引き上げる。
        weak_header=True は見出しが確かでない（左隣が「見出し語＋値」のセル）とき。見出しのおかげで拾えた分は確度を低にする。
        id_column=True は番号の列のセル（_ColumnDigits）。手がかり語の無い12桁のマイナンバーを拾わない
        （外した値は覚えておき、raw・skip_seen の読み直しでも拾わない）。
        org_column=True は会社名の列のセル（_ColumnOrgs）。見出しのおかげで拾えた氏名を 低 にする（敬称つきは下げない）。
        """
        if text is None:
            return
        self.ticks += 1
        if self.on_tick is not None and self.ticks % CHECKPOINT_EVERY == 0:
            self.on_tick()
        if not isinstance(text, str):
            text = str(text)
        if not text.strip() and not header:
            return
        norm = detectors.normalize(text)
        if not self.person_cue:
            # ファイル名と本文の先頭300文字に書類の題（履歴書・名簿・連絡網など）があれば、人と結びつく書類とみなす
            if location == "ファイル名":
                look = norm
            elif self.head_chars < 300:
                look = norm[: 300 - self.head_chars]
                self.head_chars += len(look)
            else:
                look = ""
            title = detectors.PERSON_DOC_TITLE.search(look) if look else None
            if title:
                self.person_cue = True
                self.cue_title = title.group(0)
        hits = detectors.detect(norm, header)
        if id_column:
            kept = []
            for h in hits:
                if h.pii_type == "my_number" and h.rule.startswith(BARE_MY_NUMBER_RULE):
                    if len(self.id_column_seen) < SEEN_LIMIT:
                        self.id_column_seen.add(hash(h.value))
                else:
                    kept.append(h)
            hits = kept
        elif (raw or skip_seen) and self.id_column_seen:
            hits = [
                h
                for h in hits
                if not (
                    h.pii_type == "my_number"
                    and h.rule.startswith(BARE_MY_NUMBER_RULE)
                    and hash(h.value) in self.id_column_seen
                )
            ]
        if self.matcher is not None:
            hits += self.matcher.find(norm)  # 利用者の規則（見出しに関係なく本文に当てる）
        # 見出しが確かでないときは、見出しなしで読んだときの確度に留める（見出しなしでは拾えない分は低）
        plain = (
            {(h.pii_type, h.value): h.confidence for h in detectors.detect(norm, None)}
            if weak_header and header
            else None
        )
        for hit in hits:
            if self.matcher is not None and self.matcher.is_allowed(hit.pii_type, hit.value):
                # 許可リストの値: 数えず、人の手がかりにもしない。外した件数だけ残す
                self._count_allowed(hit, raw or skip_seen)
                continue
            confidence = hit.confidence
            if plain is not None and hit.pii_type != "custom":
                confidence = plain.get((hit.pii_type, hit.value), Confidence.LOW)
                if confidence == Confidence.LOW and hit.confidence.rank > Confidence.LOW.rank:
                    hit.rule += WEAK_HEADER_NOTE
            elif org_column and hit.rule == HEADER_NAME_RULE and not detectors.name_value_has_honorific(hit.value):
                confidence = Confidence.LOW  # 銘柄名の列の、法人格の無い社名
                hit.rule += ORG_COLUMN_NOTE
            if raw and confidence == Confidence.HIGH:
                confidence = Confidence.MEDIUM  # 残留データは値の区切りが失われていて取り違えうるので1段下げる
            elif raw and confidence == Confidence.MEDIUM and hit.pii_type in ("credit_card", "my_number", "phone"):
                confidence = Confidence.LOW
            # 人の手がかりは確度 中以上だけ（語の無い和暦の日付＝生年月日の 低 や「中村 公園」のような 低 の名前で、
            # 番地の一覧を引き上げない）
            if confidence.rank >= Confidence.MEDIUM.rank and (
                hit.pii_type in detectors.PERSON_CUE_TYPES
                # 携帯・「自宅」などの語つきの電話は個人に結びつく（施設の一覧にはまず載らない）。固定電話は手がかりにしない
                or (hit.pii_type == "phone" and not hit.needs_person)
            ):
                self.person_cue = True
            key = hash((hit.pii_type, hit.value))
            prev = self.seen.get(key)
            seen_conf = prev[1] if prev is not None else Confidence.LOW
            defer = (
                hit.needs_person
                and confidence == Confidence.MEDIUM
                and not self.person_cue
                and seen_conf.rank < Confidence.MEDIUM.rank  # 同じ住所を既に手がかりつきで見ていれば待たない
            )
            if self.collect_positions and not raw:
                self._record_position(hit, 0 if defer else confidence.rank, norm)
            if defer:
                confidence = Confidence.LOW
                counted = prev is None or not (raw or skip_seen)  # 数えない重複は待ちの件数にも足さない
                d = self.deferred.get(key)
                if d is None and len(self.deferred) >= DEFER_LIMIT:
                    # 人の手がかりの無い巨大な住所の一覧: 値ごとに本文を抱えると件数に比例してメモリが増えるので、件数だけ数える
                    if counted:
                        self.deferred_overflow[hit.pii_type] = self.deferred_overflow.get(hit.pii_type, 0) + 1
                else:
                    if d is None:
                        # 明細がまだ無い（この呼び出しで載せる）か、施設の 低 などで既に載っているか
                        d = self.deferred[key] = [0, hit, prev is None, (norm, location, location_fn, method, raw)]
                    if counted:
                        d[0] += 1
            elif key in self.deferred and confidence.rank > Confidence.LOW.rank:
                self._resolve_deferred(key)  # 同じ住所を、手がかりつきで見直した
                prev = self.seen.get(key)
            elif hit.needs_person and confidence == Confidence.MEDIUM and self.person_cue:
                # 手がかりが先に見つかっていた（待たずに 中 にした）ときも、なぜ 中 なのかを明細に残す
                hit.rule += self._cue_note()
            if prev is not None:
                self._maybe_upgrade(prev, hit, confidence, norm, location, location_fn, method, raw, key)
                if raw or skip_seen:
                    continue
                self._count(hit.pii_type, confidence, hit)
                continue
            self._count(hit.pii_type, confidence, hit)
            idx = self._add_sample(hit, confidence, norm, location, location_fn, method, raw, hits)
            if len(self.seen) < SEEN_LIMIT:
                self.seen[key] = (idx, confidence, _distinct_type(hit), hash(distinct_key(hit.pii_type, hit.value)))

    def finish(self) -> None:
        """項目を読み終えたときに呼ぶ。人の手がかりがあれば、待たせていた住所を確度 中に引き上げる。

        最後に、種類ごとの異なる値の数を数えて項目に残す（値・hash は捨てる。seen もここで空にするので、後から add_text しない）。
        """
        self._finish_cues()
        self._count_distinct()
        if self.collect_positions:
            self._finish_positions()

    def _record_position(self, hit, rank: int, norm: str) -> None:
        """検出1件の構造の位置（行・列・値の開始と終了）を集める。rank 0 は「人の手がかり待ち」（finish で決める）。"""
        if self.pos_layout.startswith("csv") or self.pos_layout in (
            "xlsx",
            "sqlite",
            "sqldump",
            "docx",
            "pptx",
            "oracle_exp",
            "oracle_expdp",
            "access",  # シートは表の名前、行は SELECT * の通し番号（1 始まり）、列は列の番号（0 始まり）
        ):
            # oracle_exp・oracle_expdp: シートは表の名前、行は表の中の行の通し番号（1 始まり）、列は列の番号（0 始まり）
            # docx・pptx: シートは部品名（表のセルは「部品名#tblN」）、行は段落の通し番号（表のセルは表の行）、列は図形・表の列
            if self.cell_pos is None or self.pos_off:
                return
            row, col = self.cell_pos
            if self.row_key is not None:
                row = self.row_key(row)
            start, end = hit.start, hit.end
        elif self.pos_layout in ("lines", "pdf") and self.line_base is not None:
            # pdf: シートは「Nページ」（OCR は「Nページ（OCR）」）、行はそのページの文字（または OCR の行）の行番号
            row = self.line_base + norm.count("\n", 0, hit.start)
            col = 0
            line_start = norm.rfind("\n", 0, hit.start) + 1
            line_end = norm.find("\n", hit.start)
            line_end = len(norm) if line_end < 0 else line_end
            start, end = hit.start - line_start, min(hit.end, line_end) - line_start
        else:
            return
        pieces = [(self.pos_sheet, row, col, start, end)]
        if self.pos_map is not None:
            pieces = self.pos_map(row, col, start, end)
        for sheet, row, col, start, end in pieces:
            if self.pos_total >= POSITIONS_LIMIT:
                self.pos_overflow = True
                return
            arr = self.positions.get((sheet, hit.pii_type, rank))
            if arr is None:
                arr = self.positions[(sheet, hit.pii_type, rank)] = array("q")
            arr.extend((row, col, start, end))
            self.pos_total += 1

    def _finish_positions(self) -> None:
        """待たせていた住所・固定電話の位置を、人の手がかりがあれば確度 中、無ければ 低 の位置へ移し、項目に渡す。"""
        for key in [k for k in self.positions if k[2] == 0]:
            moved = self.positions.pop(key)
            target = (key[0], key[1], Confidence.MEDIUM.rank if self.person_cue else Confidence.LOW.rank)
            if target in self.positions:
                self.positions[target].extend(moved)
            else:
                self.positions[target] = moved
        self.item.positions = self.positions
        self.item.pos_layout = self.pos_layout
        self.item.pos_overflow = self.pos_overflow
        self.item.pos_info = self.pos_info

    def _count_distinct(self) -> None:
        """種類×確度ごとの異なる値の数を item.distinct_counts に入れ、ファイル全体の集計先にも足す。

        確度は、同じ値（正規化して同じもの）を見たうちで最も高いもの。住所の引き上げ（_finish_cues）の後に数える。
        """
        # 種類 → {値の hash → 順位} の2段にする（(種類, hash) の組を値ごとに作ると、300万件で約 170MB 余計に食う）
        # seen は finish の後には使わない。中身を小さな配列（値の hash と「種類の番号×4＋確度の順位」）へ写して
        # seen を丸ごと手放してから best を作る（seen と best の表を同時に抱えないので、最後の跳ねが小さい。
        # 260万件で +80MB → +29MB）
        types: list[str] = []
        type_no: dict[str, int] = {}
        hashes = array("q")
        codes = array("L")
        for entry in self.seen.values():
            if len(entry) < 4:
                continue  # 上限の外で後から足した値（異なる値には数えない）
            no = type_no.get(entry[2])
            if no is None:
                no = type_no[entry[2]] = len(types)
                types.append(entry[2])
            hashes.append(entry[3])
            codes.append(no * 4 + entry[1].rank)
        self.seen = {}
        best: dict[str, dict[int, int]] = {t: {} for t in types}
        per = [best[t] for t in types]
        for dhash, code in zip(hashes, codes):
            per_type = per[code >> 2]
            rank = code & 3
            if per_type.get(dhash, 0) < rank:
                per_type[dhash] = rank
        del hashes, codes
        self.item.distinct_counts = _count_by_rank(best)
        if self.distinct_sink is not None:
            sink = self.distinct_sink
            size = sum(len(v) for v in sink.values())
            for pii_type, per_type in best.items():
                if pii_type not in sink and size + len(per_type) <= SEEN_LIMIT:
                    # その種類を初めて集める（大きなファイル1つのときはこれ）: 写さずにそのまま渡す（best はここで捨てる）
                    sink[pii_type] = per_type
                    size += len(per_type)
                    continue
                dest = sink.setdefault(pii_type, {})
                for dhash, rank in per_type.items():
                    old = dest.get(dhash)
                    if old is None:
                        if rank > 0 and size < SEEN_LIMIT:
                            dest[dhash] = rank
                            size += 1
                    elif old < rank:
                        dest[dhash] = rank

    def _finish_cues(self) -> None:
        """人の手がかりがあれば、待たせていた住所・固定電話を確度 中に引き上げる（無ければ明細に理由を添える）。"""
        if self.person_cue:
            for key in list(self.deferred):
                self._resolve_deferred(key)
            # 上限を超えて件数だけ数えた分も 中 へ移す（明細は上限の内の分で足りている）
            cc = self.item.conf_counts
            for pii_type, n in self.deferred_overflow.items():
                low_key, mid_key = f"{pii_type}:{Confidence.LOW.value}", f"{pii_type}:{Confidence.MEDIUM.value}"
                moved = min(n, cc.get(low_key, 0))
                if moved:
                    cc[low_key] -= moved
                    cc[mid_key] = cc.get(mid_key, 0) + moved
            self.deferred_overflow.clear()
            return
        for _, hit, own_sample, _args in self.deferred.values():
            pos = self.seen.get(hash((hit.pii_type, hit.value)), (-1, None))[0]
            if (
                own_sample
                and 0 <= pos < len(self.item.findings)
                and self.item.findings[pos].confidence == Confidence.LOW
            ):
                f = self.item.findings[pos]
                if "人の手がかり" not in f.rule:
                    f.rule += "（同じファイルに氏名などの人の手がかりが無いため 低）"
        self.deferred.clear()
        self.deferred_overflow.clear()

    def _resolve_deferred(self, key: int) -> None:
        """待たせていた住所を、低で数えた分すべて確度 中へ移し、明細も引き上げる。"""
        n, hit, own_sample, args = self.deferred.pop(key)
        cc = self.item.conf_counts
        low_key, mid_key = f"{hit.pii_type}:{Confidence.LOW.value}", f"{hit.pii_type}:{Confidence.MEDIUM.value}"
        moved = min(n, cc.get(low_key, 0))
        if moved:
            cc[low_key] -= moved
            cc[mid_key] = cc.get(mid_key, 0) + moved
        if not moved:
            return
        entry = self.seen.get(key, (-1, Confidence.LOW))
        pos, conf = entry[0], entry[1]
        if conf != Confidence.LOW:
            return
        hit.rule = hit.rule + self._cue_note()
        if own_sample and 0 <= pos < len(self.item.findings) and not self._has_room(hit.pii_type, Confidence.MEDIUM):
            # 中 の明細が上限まで埋まっている。件数は 中 へ移したので、低 の明細は残したまま 中 では載せない。
            # 「低 0 件なのに 低 の明細がある」と読まれないよう、明細に件数の扱いを添える
            f = self.item.findings[pos]
            f.rule = hit.rule + "（中 の明細が上限のため 低 の欄に載せた。件数は 中 に数えた）"
            self._set_seen(key, -1, Confidence.MEDIUM)
            return
        if own_sample and 0 <= pos < len(self.item.findings):
            f = self.item.findings[pos]
            f.confidence = Confidence.MEDIUM
            self._room_len = -1  # 明細の確度を書き換えたので、枠の数を数え直させる
            f.rule = hit.rule
        else:
            # 低の明細の枠が埋まっていて載らなかった（pos=-1）ときも、引き上げた分は 中 の明細に載せる
            # 施設の 低 などで先に載った明細は書き換えず、引き上げた分を別に載せる
            norm, location, location_fn, method, raw = args
            pos = self._add_sample(hit, Confidence.MEDIUM, norm, location, location_fn, method, raw, [])
        self._set_seen(key, pos, Confidence.MEDIUM)

    def _set_seen(self, key: int, pos: int, confidence: Confidence) -> None:
        """見た値の明細の位置と確度を書き換える（異なる値を数えるための後ろの2つは残す）。"""
        prev = self.seen.get(key)
        self.seen[key] = (pos, confidence) + (prev[2:] if prev is not None else ())

    def _count_allowed(self, hit, reread: bool) -> None:
        """許可リストで外した検出を数える。読み直し（生データ走査等）で既に外した値は数えない（検出の数え方と同じ）。"""
        key = hash((hit.pii_type, hit.value))
        if reread and key in self.allowed_seen:
            return
        if len(self.allowed_seen) < 3_000_000:
            self.allowed_seen.add(key)
        self.item.allowed += 1

    def _count(self, pii_type: str, confidence: Confidence, hit=None) -> None:
        counts = self.item.finding_counts
        counts[pii_type] = counts.get(pii_type, 0) + 1
        ck = f"{pii_type}:{confidence.value}"
        self.item.conf_counts[ck] = self.item.conf_counts.get(ck, 0) + 1
        if hit is not None and pii_type == CUSTOM_TYPE:
            # 利用者の規則は、どの規則に当たったかを内訳に出すため、規則の名前ごとにも数える（種類の件数とは別に持つ）
            name = rule_name_of_text(hit.rule)
            if name is not None:
                self.item.rule_counts[name] = self.item.rule_counts.get(name, 0) + 1

    def _cue_note(self) -> str:
        """引き上げた理由の注記。書類の題で手がかりにしたときは、ありもしない氏名を探させないよう題と書く。"""
        return TITLE_CUE_NOTE.format(self.cue_title) if self.cue_title else PERSON_CUE_NOTE

    def _has_room(self, pii_type: str, confidence: Confidence) -> bool:
        """その種類×確度の明細に、まだ載せる枠があるか。

        明細の数は種類×確度ごとに数えて持つ（新しい値のたびに明細を全部数え直すと、明細が多い項目で遅い）。
        明細が足されたら差分だけ数え足し、明細の確度を書き換えたとき（_room_len を -1 にする）は数え直す。
        """
        findings = self.item.findings
        if self._room_len < 0 or self._room_len > len(findings):
            self._room = {}
            self._room_len = 0
        if self._room_len < len(findings):
            room = self._room
            for f in findings[self._room_len :]:
                k = (f.pii_type, f.confidence)
                room[k] = room.get(k, 0) + 1
            self._room_len = len(findings)
        return self._room.get((pii_type, confidence), 0) < self.max_samples

    def _add_sample(self, hit, confidence, norm, location, location_fn, method, raw, hits) -> int:
        if not self._has_room(hit.pii_type, confidence):
            return -1
        masked = detectors.mask_value(hit.pii_type, hit.value)
        loc = location_fn(hit.start) if location_fn else location
        raw_value = raw_context = ""
        if self.reveal:
            raw_value = hit.value
            raw_context = re.sub(
                r"\s+",
                " ",
                f"{norm[max(0, hit.start - 20) : hit.start]}【{hit.value}】{norm[hit.end : hit.end + 20]}",
            ).strip()
        self.item.findings.append(
            Finding(
                pii_type=hit.pii_type,
                confidence=confidence,
                masked_value=masked,
                location=loc,
                context=detectors.masked_context(norm, hit.start, hit.end, masked),
                rule=hit.rule,
                method=method + ("（削除済み・非表示領域の残留の可能性）" if raw else ""),
                raw_value=raw_value,
                raw_context=raw_context,
            )
        )
        return len(self.item.findings) - 1

    def _maybe_upgrade(self, prev, hit, confidence, norm, location, location_fn, method, raw, key) -> None:
        """既に見た値を、より高い確度で見直したら明細と件数を引き上げる。"""
        pos, prev_conf = prev[0], prev[1]
        if confidence.rank <= prev_conf.rank:
            return
        self._move_count(hit.pii_type, prev_conf, confidence)
        if pos < 0 or pos >= len(self.item.findings):
            # 明細の上限で載っていなかった値でも、高い確度で見直したなら新しく明細に載せる
            idx = self._add_sample(hit, confidence, norm, location, location_fn, method, raw, [])
            self._set_seen(key, idx, confidence)
            return
        self._set_seen(key, pos, confidence)
        old = self.item.findings[pos]
        old.confidence = confidence
        self._room_len = -1  # 明細の確度を書き換えたので、枠の数を数え直させる
        old.rule = hit.rule
        old.location = location_fn(hit.start) if location_fn else location
        old.method = method

    def _move_count(self, pii_type: str, old: Confidence, new: Confidence) -> None:
        cc = self.item.conf_counts
        ok = f"{pii_type}:{old.value}"
        if cc.get(ok, 0) > 0:
            cc[ok] -= 1
            nk = f"{pii_type}:{new.value}"
            cc[nk] = cc.get(nk, 0) + 1

    def add_id_documents(self, text: str, location: str, method: str = "OCR") -> None:
        """OCR で読んだ1項目分（画像1枚・PDF の1ページ）の文字から、本人確認書類の写しを見分けて加える。

        同じ書類でもページごとに1件として数える（値が書類の名前なので、値の重複では1件にまとめない）。
        """
        if not text:
            return
        norm = detectors.normalize(text)
        for hit in detectors.detect_id_documents(norm, from_ocr=True):
            self.person_cue = True  # 本人確認書類の写しは、それだけで人と結びつく
            self._count(hit.pii_type, hit.confidence)
            self._add_sample(hit, hit.confidence, norm, location, None, method, False, [])

    def add_lines(
        self,
        text: str,
        location_prefix: str = "",
        method: str = "",
        ocr: bool = False,
        line_offset: int = 0,
        skip_seen: bool = False,
    ) -> None:
        """長い本文を行の塊に分けて検査する（位置は「N行目」で示す）。

        ocr=True は OCR で読んだ1項目分の文字（本人確認書類の写しの判別もする）。
        line_offset は、text がファイルの途中から始まるときの、それまでの行数（位置を集めるときの行番号に使う）。
        skip_seen=True は既に見つけた値を数えない（同じ本文を別の読み方でもう一度読むとき。add_text と同じ）。
        """
        if ocr:
            self.add_id_documents(text, location_prefix.strip() or "OCR", method or "OCR")
        lines = text.splitlines()
        block = 200
        for i in range(0, len(lines), block):
            chunk = "\n".join(lines[i : i + block])
            base = i + 1

            def loc(pos: int, chunk=chunk, base=base) -> str:
                return f"{location_prefix}{base + chunk.count(chr(10), 0, pos)}行目"

            self.line_base = base + line_offset
            try:
                self.add_text(chunk, "", method=method, location_fn=loc, skip_seen=skip_seen)
            finally:
                self.line_base = None

    def add_table(
        self,
        rows,
        location_fn: Callable[[int, int], str],
        method: str = "",
        header_rows: int | None = None,
        skip_seen: bool = False,
    ) -> int:
        """表（行の反復子。各行は値のリスト）を検査する。見出し行を推定して列の意味に使う。

        - 見出しらしい行（数字を含まない短いセルだけで、個人情報の見出し語が1つ以上）を見出しにする
        - 見出しを切り替えるのは、まだ見出しが無いとき・空行の直後・今の見出しより見出し語が多い行だけ
          （データ行の中の「住所」「電話」などの語で切り替えない）
        - 左隣のセルが見出し語なら、その値の見出しとして使う（横持ちの申込書）
        戻り値は処理した行数。
        """
        self._skip_seen = skip_seen
        self._col_digits = _ColumnDigits()
        self._col_orgs = _ColumnOrgs()
        headers: list[str | None] = []
        cur_score = 0
        cur_cells = 0
        prev_blank = True
        n = 0
        for r_idx, row in enumerate(rows, start=1):
            n += 1
            values = ["" if v is None else _cell_to_str(v) for v in row]
            if not any(values):
                prev_blank = True
                continue
            score, headerish = _header_row_score(values)
            cells = sum(1 for v in values if v)
            majority = headerish * 2 > cells  # 行の過半数が見出しらしいセル（データ行の「住所変更済」等で切り替えない）
            switch = score and (
                not headers
                or (cur_cells == 1 and cells >= 2)  # 表題だけの行（「顧客名簿」）の後の本当の見出し
                or (majority and (prev_blank or score >= max(2, cur_score + 1)))
            )
            if switch:
                headers = [v or None for v in values]
                self._col_digits = _ColumnDigits()  # 見出しが変われば列の中身も変わる
                self._col_orgs = _ColumnOrgs()
                cur_score = score
                cur_cells = cells
                # 見出し行自体も検査（見出しなしで）
                self._table_row(values, r_idx, [], location_fn, method, header_row=True)
            else:
                self._table_row(values, r_idx, headers, location_fn, method)
            prev_blank = False
        return n

    def add_records(self, columns: list[str], rows, location_fn: Callable[[int, int], str], method: str = "") -> int:
        """列名が分かっている表（データベース）を検査する。戻り値は行数。"""
        self._skip_seen = False
        self._col_digits = _ColumnDigits()
        self._col_orgs = _ColumnOrgs()
        headers = list(columns)
        # 列名は表の中で変わらないので、見出しとして使えるかは表ごとに1回だけ決める
        sure = [bool(h and detectors.header_category(h)) for h in headers]
        head, keys, error, rest = self._prefetch_org_columns(headers, rows)
        n = 0
        row_key = self.row_key
        if keys:
            # 先読みで行の反復子の「今の行」が進んだので、先読みした行の位置の鍵は控えた値を返す
            self.row_key = lambda r: keys[r - 1]
        try:
            for row in head:
                n += 1
                values = ["" if v is None else _cell_to_str(v) for v in row]
                self._table_row(values, n, headers, location_fn, method, sure)
        finally:
            if keys:
                self.row_key = row_key
        if error is not None:
            raise error  # 先読みの途中で読み取りが失敗した（読めた行は上で検査した）
        for row in rest:
            n += 1
            values = ["" if v is None else _cell_to_str(v) for v in row]
            self._table_row(values, n, headers, location_fn, method, sure)
        return n

    def _prefetch_org_columns(self, headers: list[str], rows):
        """氏名の列があれば先頭の行を先読みし、会社名の列かの判定（_ColumnOrgs）を付けておく。

        戻り値は（先読みした行・その行ごとの位置の鍵・先読みの途中の例外・残りの行の反復子）。
        先読みは COLUMN_ORG_PREFETCH_ROWS 行・セルの文字数の合計 COLUMN_ORG_PREFETCH_CHARS までで、
        どの氏名の列も判定が固まったら（異なる値が COLUMN_ID_TRACK 個に届いたら）止める。判定が付いた
        COLUMN_ORG_MIN_DISTINCT 個で止めると、そこでは会社の印が5%を切っていて後で会社名の列に変わる表（株の分売・優待の
        銘柄の一覧）で、変わる前の行の社名が 中 に残る（2026-11-08）。
        位置の鍵（row_key）は行の反復子が進める「今の行」を読むので、1行読むたびに控える。
        読み取りの例外はここで止め、読めた行を検査してから呼び出し側で出し直す（今までどおり読めた行は検査する）。
        """
        rest = iter(rows)
        name_cols = [i for i, h in enumerate(headers) if h and detectors.header_category(h) == "name"]
        if not name_cols:
            return [], [], None, rest
        orgs = self._col_orgs
        row_key = self.row_key
        head: list = []
        keys: list[int] = []
        chars = 0
        error: Exception | None = None
        while len(head) < COLUMN_ORG_PREFETCH_ROWS and chars < COLUMN_ORG_PREFETCH_CHARS:
            try:
                row = next(rest)
            except StopIteration:
                break
            except Exception as e:  # noqa: BLE001 - 読めた行を検査してから出し直す
                error = e
                break
            head.append(row)
            if row_key is not None:
                keys.append(row_key(len(head)))
            chars += sum(len(v) for v in row if isinstance(v, (str, bytes)))
            decided = True
            for c in name_cols:
                v = row[c] if c < len(row) else None
                if v is not None:
                    s = _cell_to_str(v)
                    if s:
                        orgs.cell(c, headers[c], s)
                decided = decided and orgs.decided(c)
            if decided:
                break
        return head, keys, error, rest

    def _table_row(
        self, values, r_idx, headers, location_fn, method, sure: list[bool] | None = None, header_row: bool = False
    ) -> None:
        """表の1行を検査する。sure は列ごとの「見出しが個人情報の見出し語か」（無ければここで判定する）。

        header_row は見出しと決めた行。その行の英語の項目名（Remarks・Department）は、左隣の見出しの値として読まない。

        場所の文字列は明細に載せるときだけ要るので、セルごとには作らず location_fn に任せる（明細はセルの数より
        ずっと少ない）。呼び出し側の location_fn は行・列だけで場所が決まること（後から呼んでも同じ文字列になること）。
        """
        skip_seen = getattr(self, "_skip_seen", False)
        col_digits = getattr(self, "_col_digits", None)
        col_orgs = getattr(self, "_col_orgs", None)
        n_headers = len(headers)
        for c_idx, v in enumerate(values):
            if not v:
                continue
            id_column = False if col_digits is None else col_digits.cell(c_idx, v)
            if c_idx < n_headers:
                header = headers[c_idx]
                has_category = sure[c_idx] if sure is not None else bool(header and detectors.header_category(header))
            else:
                header = None
                has_category = False
            # 会社名の列かは、列の見出しで決まる氏名の列だけで数える（横持ちの左隣の見出しは列の意味ではない）
            org_column = has_category and col_orgs is not None and col_orgs.cell(c_idx, header, v)
            weak = False
            if not has_category and not (header_row and _is_en_label_cell(v)):
                # 横持ち: 左隣（空白を挟んでもよい）のセルが見出し語なら、それを見出しにする。
                # 左隣が「見出し語＋値」のセルなら、見出しのおかげで拾えた分は確度を低にする（座標を番号と取り違えないため）
                for j in range(c_idx - 1, max(-1, c_idx - 3), -1):
                    if values[j]:
                        strength = _header_strength(values[j])
                        if strength != HEADER_NONE:
                            header, weak = values[j], strength == HEADER_WEAK
                        break
            self.cell_pos = (r_idx, c_idx)
            try:
                self.add_text(
                    v,
                    "",
                    header=header,
                    method=method,
                    location_fn=lambda _start, r=r_idx, c=c_idx: location_fn(r, c),
                    skip_seen=skip_seen,
                    weak_header=weak,
                    id_column=id_column,
                    org_column=org_column,
                )
            finally:
                self.cell_pos = None


class _ColumnOrgs:
    """表の氏名の列ごとに、異なる値と、そのうち会社の印を含む数を数え、会社名の列（銘柄の一覧など）かを決める。

    _ColumnDigits と同じく表ごとに作り直す。1列で数えるのは異なる値 COLUMN_ID_TRACK 個まで（そこで判定を固める）。
    判定が付く前（異なる値が COLUMN_ORG_MIN_DISTINCT 個未満）に読んだ値は今までどおり（中）。小さな表は判定しない。
    """

    __slots__ = ("_values", "_orgs", "_decided", "_is_name", "verdict")

    def __init__(self) -> None:
        self._values: dict[int, set[str]] = {}
        self._orgs: dict[int, int] = {}
        self._decided: set[int] = set()  # 判定を固めた列（異なる値が上限に届いた）
        self._is_name: dict[int, bool] = {}  # 列の見出しが氏名か（見出しは表の中で変わらないので1回だけ調べる）
        self.verdict: dict[int, bool] = {}  # 列ごとの今の判定（会社名の列なら True）

    def cell(self, c_idx: int, header: str | None, v: str) -> bool:
        """表のセルを1つ見て、この列が今のところ会社名の列か（org_column に渡す値）を返す。header は列の見出し。"""
        is_name = self._is_name.get(c_idx)
        if is_name is None:
            is_name = self._is_name[c_idx] = bool(header) and detectors.header_category(header) == "name"
        if not is_name or c_idx in self._decided:
            return self.verdict.get(c_idx, False)
        v = v.strip()
        values = self._values.get(c_idx)
        if values is None:
            values = self._values[c_idx] = set()
        if v and v not in values:
            values.add(v)
            orgs = self._orgs[c_idx] = self._orgs.get(c_idx, 0) + detectors.org_name_marked(v)
            if len(values) >= COLUMN_ORG_MIN_DISTINCT:
                # 判定の後も、上限までは値が増えるたびに割合を見直す（割合が下がれば 中 に戻る）
                self.verdict[c_idx] = orgs >= len(values) * COLUMN_ORG_MIN_RATIO
            if len(values) >= COLUMN_ID_TRACK:
                self._decided.add(c_idx)
                del self._values[c_idx]
        return self.verdict.get(c_idx, False)

    def decided(self, c_idx: int) -> bool:
        """この列の判定が固まったか（異なる値が COLUMN_ID_TRACK 個に届いたか・氏名の列でなければ常に固まっている）。

        まだ値を1つも見ていない列は固まっていない（見出しが氏名かを調べる前なので）。
        """
        return self._is_name.get(c_idx) is False or c_idx in self._decided


class _ColumnDigits:
    """表の列ごとに、12桁の数だけのセルの異なる値と、そのうち検査数字が合う数を数え、番号の列かを決める。

    表（add_table・add_records の1回の呼び出し。Access の32ビットの補助の経路では表の名前）ごとに作り直す。1列で数えるのは異なる値 COLUMN_ID_TRACK 個まで。
    番号の列と決めた後も、検査数字の合う値が COLUMN_ID_RELEASE_STREAK 個続いたら判定を解いて数え直す
    （それまでに捨てた分は戻らない。列の途中から本物に変わっても、捨てるのは切り替わりの数個で済む）。
    """

    __slots__ = ("_values", "_valid", "_decided", "_last", "_streak", "verdict")

    def __init__(self) -> None:
        self._values: dict[int, set[str]] = {}
        self._valid: dict[int, int] = {}
        self._decided: set[int] = set()  # 判定を固めた列（異なる値が上限に届いた）
        self._last: dict[int, str] = {}  # 列ごとの直前の12桁の値
        self._streak: dict[int, int] = {}  # 列ごとの、検査数字の合う値（直前と違う値）が続いた数
        self.verdict: dict[int, bool] = {}  # 列ごとの今の判定（番号の列なら True）。12桁でないセルはこれを引くだけ

    def cell(self, c_idx: int, v: str) -> bool:
        """表のセルを1つ見て、番号の列か（id_column に渡す値）を返す。

        12桁でないセル（表の大半）は今の判定を引くだけにする（1セルごとに observe を呼ぶと重い）。
        前後の空白は外して見る（データベースの固定長の文字の列「000000008370␣␣␣…」を書き出した表で、
        長さが12にならず番号の列と決められなかった）。
        """
        if len(v) > 12 and (v[-1] == " " or v[0] == " "):
            v = v.strip(" ")
        if len(v) == 12:
            return self.observe(c_idx, v)
        return self.verdict.get(c_idx, False)

    def observe(self, c_idx: int, v: str) -> bool:
        """セルを1つ見て、この列が今のところ番号の列か（手がかり語の無い12桁のマイナンバーを落とすか）を返す。"""
        if not (len(v) == 12 and RE_TWELVE_DIGITS.fullmatch(v)):
            return self.verdict.get(c_idx, False)
        if c_idx in self._decided and not self.verdict[c_idx]:
            # 本物の列と固まった: 解く判定は番号の列にしか効かないので、検査数字の計算を省く
            return False
        valid = None
        if self._last.get(c_idx) != v:
            self._last[c_idx] = v
            valid = detectors.my_number_is_valid(v)
            streak = self._streak[c_idx] = self._streak.get(c_idx, 0) + 1 if valid else 0
            if streak >= COLUMN_ID_RELEASE_STREAK and self.verdict.get(c_idx):
                # 本物のマイナンバーが続いている: 番号の列の判定を解き、ここから数え直す
                self._decided.discard(c_idx)
                self.verdict[c_idx] = False
                self._values[c_idx] = set()
                self._valid[c_idx] = 0
        if c_idx in self._decided:
            return self.verdict[c_idx]
        values = self._values.get(c_idx)
        if values is None:
            values = self._values[c_idx] = set()
        if v not in values:
            values.add(v)
            if valid is None:
                valid = detectors.my_number_is_valid(v)
            if valid:
                self._valid[c_idx] = self._valid.get(c_idx, 0) + 1
            if len(values) >= COLUMN_ID_MIN_DISTINCT:
                self.verdict[c_idx] = self._valid.get(c_idx, 0) < len(values) * COLUMN_ID_MAX_VALID_RATIO
                if len(values) >= COLUMN_ID_TRACK:
                    self._decided.add(c_idx)
                    del self._values[c_idx]
        return self.verdict.get(c_idx, False)


RE_ANNOTATION = re.compile(r"[（(【\[〔<＜][^）)】\]〕>＞]{0,20}[）)】\]〕>＞]")
RE_LABEL_WITH_INDEX = re.compile(r"\D{1,15}\d{1,2}")


HEADER_NONE, HEADER_WEAK, HEADER_SURE = 0, 1, 2


def _header_strength(v: str) -> int:
    """見出しのセルらしさ（短く、文ではなく、個人情報の見出し語を含む）。「氏名（必須）」の括弧書きは除いて判定する。

    「マイナンバー 123456789018」のように値まで入ったセル（それ自体で検出される）は HEADER_WEAK。
    「2024/04/01時点の氏名」のように数字を含むだけの見出しは HEADER_SURE のまま。
    """
    if not v or detectors.cannot_be_header(v):
        return HEADER_NONE  # 番号・日付のセル（表の大半）は見出しではない。正規表現にも覚え込みにも回さない
    core = RE_ANNOTATION.sub("", v).strip()
    if not core or len(core) > 20:
        return HEADER_NONE  # 長いセルは見出しではない（覚える前に弾く。長い本文を覚えるとメモリを食い潰す）
    return _short_header_strength(core)


@lru_cache(maxsize=65536)
def _short_header_strength(core: str) -> int:
    """20字以下の文字列の見出しらしさ。同じ見出しが行ごとに繰り返し出るので覚えておく（検出まで回すため重い）。"""
    if core.startswith(("※", "*", "注")):
        return HEADER_NONE
    if any(w in core for w in ("。", "ください", "下さい", "してい", "します")):
        return HEADER_NONE  # 説明文は見出しではない
    if detectors.header_category(core) is None:
        return HEADER_NONE
    if not detectors.en_header_word_backed(core):
        return HEADER_NONE  # 英語の名前（Patel・Ismail）が tel・mail を含むだけでは見出しにしない
    return HEADER_WEAK if detectors.detect(detectors.normalize(core), None) else HEADER_SURE


RE_VALUE_SHAPE = re.compile(r"\d{2,4}[-/.]\d{1,4}[-/.]\d{1,4}|\d{5,}|@")
RE_GENERIC_HEADER = re.compile(
    r"^(No\.?|NO|№|ID|番号|連番|通番|部署|部門|所属|役職|備考|区分|種別|日付|会社名?|社名|内容|メモ|状態|コード|"
    r"[一-龥]{1,4}日|第?\d{1,2}希望|.{1,6}番号)$"
)


# 見出しの行に並ぶ、個人情報でない英語の項目名の語。「Name | Remarks | Department」の Remarks・Department を
# 左隣の Name の値（氏名）と読まないために使う。姓にもある語（Price・Branch・Rank・Grade・Class）は入れない
_EN_LABEL_WORDS = frozenset(
    "remarks remark notes note memo comment comments status department dept division section title position role "
    "company organization organisation date id no number code type category team description item joined start end "
    "created updated employee staff member job salary amount qty quantity total nationality country region "
    "reference ref account join hire manager location order occupation hobby birthplace blood".split()
)


def _is_en_label_cell(v: str) -> bool:
    """英字のセルが、項目名の語（_EN_LABEL_WORDS）を1つ以上含み、項目名の語と英語の見出しの語だけでできているか。

    見出しの語だけのセル（Roman・Kana は名前にもある）はここでは外さない（見出しの語そのものは値の側で判定する）。
    """
    if not v.isascii():
        return False
    words = [w.lower() for w in detectors._RE_EN_WORD.findall(v)]
    return any(w in _EN_LABEL_WORDS for w in words) and all(
        w in _EN_LABEL_WORDS or w in detectors._EN_HEADER_WORDS for w in words
    )


def _header_row_score(values: list[str]) -> tuple[int, int]:
    """（個人情報の見出し語の数, 見出しらしいセルの数）を返す。見出し行でなければ (0, 0)。

    見出し行は、どのセルも短く、電話番号・日付・長い数字・メールのような「値の形」のセルを含まない。
    「郵便番号(7桁)」「2024年度所属」のように数字を含む見出しは構わない（括弧書きは除いて見る）。
    """
    count = 0
    headerish = 0
    for v in values:
        if not v:
            continue
        core = RE_ANNOTATION.sub("", v).strip() or v
        if len(core) > 30 or RE_VALUE_SHAPE.search(core):
            return 0, 0
        if _header_strength(v) != HEADER_NONE:
            count += 1
            headerish += 1
        elif RE_GENERIC_HEADER.match(core):
            headerish += 1
    return count, headerish


def _cell_to_str(v) -> str:
    if type(v) is str:
        return v  # 表の値の大半。判定を重ねずに返す
    if isinstance(v, float) and v.is_integer() and abs(v) < 1e17:
        return str(int(v))
    if isinstance(v, (_dt.datetime, _dt.date)):
        return v.isoformat()[:10] if isinstance(v, _dt.datetime) and v.time() == _dt.time() else v.isoformat()
    if isinstance(v, bytes):
        return ""
    return str(v)


def _looks_numeric(v: str) -> bool:
    return v.replace(".", "", 1).replace("-", "", 1).isdigit()


class ScanContext:
    """1つの実ファイルの検査中の状態（展開量・項目数・一時フォルダ・パスワード）。"""

    def __init__(self, top_path: str, options: ScanOptions, passwords: list[str]):
        self.top_path = top_path
        self.options = options
        self.passwords = passwords
        self.items: list[ItemResult] = []
        self.checkpoint_file: str | None = None  # 途中経過の書き出し先（scan_file が決める）
        self._last_checkpoint = time.time()
        self._checkpoint_gap = 0.0  # 書き出しの重さから決めた間隔（CHECKPOINT_SECONDS より短くはしない）
        self.expanded_bytes = 0
        self.entries = 0
        self._tmp: str | None = None
        self.deadline: float | None = None
        self.pg_columns: dict[str, tuple[str, list[str]]] = {}  # pg_dump のデータファイル名 → (表, 列名)
        # 元のファイルのフォルダ（検査するのは一時フォルダの写しなので、隣のファイルはここで引く）
        self.source_dir: str | None = None
        self._owner = None  # 一時フォルダの持ち主の目印（開いている間は消せない）
        from .userrules import matcher_for

        self.matcher = matcher_for(options)  # 許可リストと利用者の規則（無ければ None）
        # ファイル全体の異なる値（(種類, 正規化した値の hash) → 確度の順位）。数え終えたら数だけを結果に残す
        self.distinct: dict[str, dict[int, int]] = {}

    def distinct_counts(self) -> dict[str, int]:
        """ファイル全体（内側の項目を含む）での「種類:確度」→異なる値の数。"""
        return _count_by_rank(self.distinct)

    @property
    def tmpdir(self) -> str:
        if self._tmp is None:
            self._tmp = tempfile.mkdtemp(prefix=TEMP_PREFIX, dir=self.options.temp_dir or None)
            # 持ち主の目印を開いたままにする。このプロセスが打ち切られると目印が閉じ、次の片付けで消せるようになる
            self._owner = open(os.path.join(self._tmp, OWNER_MARK), "wb")
        return self._tmp

    def new_tmp_subdir(self) -> str:
        return tempfile.mkdtemp(dir=self.tmpdir)

    def ensure_space(self, nbytes: int, what: str = "") -> None:
        """一時フォルダへ nbytes 書いても最低限の空きが残るかを確かめ、残らなければ検査不能にする。"""
        from . import safeio

        try:
            safeio.ensure_free(self.tmpdir, nbytes)
        except safeio.TempSpaceShort as e:
            raise Uncheckable(f"{what}{e}") from None

    def cleanup(self) -> None:
        if self._owner is not None:
            self._owner.close()
            self._owner = None
        if self._tmp:
            shutil.rmtree(self._tmp, ignore_errors=True)
            self._tmp = None

    def account(self, nbytes: int) -> None:
        """展開した量を数え、上限を越えたら検査不能にする（zip 爆弾対策）。"""
        self.expanded_bytes += max(0, nbytes)
        self.entries += 1
        if self.expanded_bytes > self.options.max_expand_bytes:
            raise Uncheckable(
                f"展開した合計が上限（{size_text(self.options.max_expand_bytes)}）を超えたため打ち切り"
                "（zip 爆弾の疑い。本物の書庫なら、展開してからそのフォルダを検査してください）"
            )
        if self.entries > self.options.max_entries:
            raise Uncheckable(
                f"内側のファイル数が上限（{self.options.max_entries:,}件）を超えたため打ち切り"
                "（本物の書庫なら、展開してからそのフォルダを検査してください）"
            )

    def password_candidates(self) -> list[str]:
        return list(self.passwords)

    def password_reason(self, what: str, also: str = "") -> str:
        """パスワードで開けなかったときの理由の文。試した数と、画面とコマンドの版での次の手を添える。

        also は受け取ったパスワードのほかに試したもの（Office の既定値など）。
        """
        n = len(self.password_candidates())
        if n:
            return (
                f"{what}（受け取ったパスワード {n:,} 個{also}を試したが開けなかった。"
                "別のパスワードを入れると再検査できる。分からなければ持ち主に中身を確かめてもらう）"
            )
        return (
            f"{what}（パスワードが分かれば、結果の「パスワードが必要なファイル」で入れると再検査できる。"
            "コマンドの版は --password-file で渡す）"
        )

    def maybe_checkpoint(self) -> None:
        """前の書き出しから CHECKPOINT_SECONDS 経っていれば、それまでの項目（検出の件数・明細）を書き出す。

        時間切れでワーカーごと打ち切られても、実行器がこれを読んで「途中まで検査」として検出を残す。書きかけで
        壊れた状態を読ませないよう、別名で書いてから置き換える。
        """
        now = time.time()
        if self.options.reveal or self.options.collect_positions:
            return  # 値を持つ読み直し・位置集めでは書かない（生の値・位置が一時フォルダに出てしまう）
        if not self.checkpoint_file or now - self._last_checkpoint < max(CHECKPOINT_SECONDS, self._checkpoint_gap):
            return
        import pickle

        tmp = self.checkpoint_file + ".tmp"
        try:
            with open(tmp, "wb") as f:
                pickle.dump(self.items, f, protocol=pickle.HIGHEST_PROTOCOL)
            os.replace(tmp, self.checkpoint_file)
        except (OSError, pickle.PickleError, TypeError, AttributeError):
            pass  # 書き出せなくても検査は続ける（時間切れのときに途中の検出が残らないだけ）
        self._last_checkpoint = time.time()
        self._checkpoint_gap = (self._last_checkpoint - now) * 50

    # ---------------------------------------------------------- 検査の入口

    def scan_blob(self, blob: Blob, depth: int) -> ItemResult:
        """中身を1件検査して結果を items に加える（内側は再帰）。"""
        from . import sniff

        item = ItemResult(path=blob.display, kind="", status=Status.PENDING, depth=depth)
        item.mtime = blob.mtime
        self.items.append(item)
        collector = Collector(
            item,
            self.options.max_samples_per_type,
            matcher=self.matcher,
            distinct_sink=self.distinct,
            on_tick=self.maybe_checkpoint,
            reveal=self.options.reveal,
            collect_positions=self.options.collect_positions and depth == 0,  # 対処の対象は実ファイルそのものだけ
        )
        try:
            item.size = blob.size
            if depth > self.options.max_depth:
                raise Uncheckable(
                    f"入れ子が深すぎる（{self.options.max_depth}段を超えた）ため、ここから内側は検査していない"
                    "（外側の書庫を展開して、そのフォルダを検査してください。"
                    "文書の埋め込み・メールの添付なら、外側から取り出したファイルを検査してください）"
                )
            self._load_pg_toc(blob)
            leaf = blob.display.replace("\\", "/").rsplit("!", 1)[-1].rsplit("/", 1)[-1]
            collector.add_text(leaf, "ファイル名", method="ファイル名")
            kind = sniff.sniff(blob)
            item.kind = sniff.KIND_LABELS.get(kind, kind)
            handler = sniff.handler_for(kind)
            handler(self, blob, item, collector, depth)
            if item.status == Status.PENDING:
                item.status = Status.SCANNED
        except NeedPassword as e:
            item.status = Status.NEEDS_PASSWORD
            item.password_kind = e.kind
            item.reason = str(e)
        except Uncheckable as e:
            item.status = Status.UNCHECKABLE
            item.reason = str(e)
        except OutOfScope as e:
            item.status = Status.OUT_OF_SCOPE
            item.reason = str(e)
        except PartialScan as e:
            item.status = Status.PARTIAL
            item.reason = str(e)
        except PermissionError as e:
            item.status = Status.UNCHECKABLE
            item.reason = access_denied_reason(e)
        except FileNotFoundError as e:
            item.status = Status.UNCHECKABLE
            item.reason = f"ファイルが見つからない（検査中に移動・削除された可能性）。{NOT_FOUND_HINT}（詳細: {e}）"
        except (TooLargeForMemory, MemoryError) as e:
            self._sweep_instead(blob, item, collector, e)
        except Exception as e:  # 想定外の失敗も「検査不能」として必ず残す
            from .safeio import is_disk_full

            item.status = Status.UNCHECKABLE
            if is_disk_full(e):
                item.reason = "一時フォルダのドライブが満杯になり、展開・書き出しができなかった。" + TEMP_DIR_HINT
                return item
            item.reason = (
                "読み取りの途中で想定外のエラーになり、検査できなかった（要目視）。" + UNEXPECTED_HINT + error_detail(e)
            )
        finally:
            collector.finish()  # 途中で止まっても、それまでに見た住所の確度を決める
        return item

    def _sweep_instead(self, blob: Blob, item: ItemResult, collector: Collector, cause: BaseException) -> None:
        """大きすぎて（メモリ不足で）形式どおりに読めなかったものを、文字列の少しずつの走査で検査する（簡易検査）。"""
        from .textdecode import iter_strings_chunked

        why = "メモリ不足" if isinstance(cause, MemoryError) else f"大きすぎる（{cause}）"
        if item.kind.startswith("画像"):
            # 画像の文字は OCR でしか読めない。圧縮されたバイト列から文字を拾っても検査したことにはならない
            item.status = Status.UNCHECKABLE
            item.reason = f"{why}ため OCR できなかった（画像の中の文字は検査していない）。画像を小さくして再検査するか目視で確かめる"
            return
        try:
            with blob.open() as f:
                for s in iter_strings_chunked(f.read):
                    collector.add_text(s, "文字列走査", method="文字列走査（大きすぎて形式どおりに読めないため）")
        except MemoryError:
            item.status = Status.UNCHECKABLE
            item.reason = (
                f"{why}ため形式どおりに読めず、文字列だけを拾う走査もメモリ不足で失敗した。"
                "作ったアプリで開けるなら、小さく分けた写しを検査するか、中身を目視で確かめてください。"
                "開けなければ壊れている可能性があるので元のファイルを取り直してください"
            )
            return
        except Exception as e:
            item.status = Status.UNCHECKABLE
            item.reason = f"{why}ため形式どおりに読めず、文字列だけを拾う走査も失敗した（要目視）。{UNEXPECTED_HINT}{error_detail(e)}"
            return
        item.status = Status.PARTIAL
        item.reason = f"{why}ため形式どおりには読めず、文字として読める部分だけを少しずつ検査した"

    def _load_pg_toc(self, blob: Blob) -> None:
        """pg_dump の directory 形式のデータファイルなら、隣の toc.dat から列名を読んでおく。"""
        import re as _re

        if not blob.path:
            return
        name = os.path.basename(
            blob.path if not blob.name_hint else blob.name_hint.replace("\\", "/").rsplit("/", 1)[-1]
        )
        if not _re.fullmatch(r"\d+\.dat(\.gz)?", name):
            return
        try:
            if blob.display == self.top_path and self.source_dir:
                # 実ファイルは写しを検査しているので、隣の toc.dat は元のフォルダから共有を許して読む
                from .safeio import read_head_shared

                data = read_head_shared(os.path.join(self.source_dir, "toc.dat"), 64 * 1024 * 1024)
            else:
                with open(long_path(os.path.join(os.path.dirname(blob.path), "toc.dat")), "rb") as f:
                    data = f.read(64 * 1024 * 1024)
        except OSError:
            return
        if data.startswith(b"PGDMP"):
            from .formats.dbdump import pg_toc_mapping

            self.pg_columns.update(pg_toc_mapping(data))

    def scan_nested(
        self,
        display: str,
        data: bytes | None = None,
        path: str | None = None,
        depth: int = 1,
        name_hint: str = "",
        mtime: float | None = None,
    ) -> ItemResult:
        """内側のファイル（アーカイブの中身・埋め込み・添付）を検査する。"""
        size = len(data) if data is not None else os.path.getsize(long_path(path))
        self.account(size)
        if data is not None and len(data) > IN_MEMORY_LIMIT:
            try:
                self.ensure_space(len(data))
            except Uncheckable as e:  # その1件だけ検査不能にして、残りの中身は続ける
                failed = ItemResult(path=display, kind="", status=Status.UNCHECKABLE, reason=str(e), depth=depth)
                failed.size = len(data)
                self.items.append(failed)
                return failed
            fd, tmp = tempfile.mkstemp(dir=self.tmpdir)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            data, path = None, tmp
        blob = Blob(
            display=display, path=path, data=data, name_hint=name_hint or display.rsplit("!", 1)[-1], mtime=mtime
        )
        return self.scan_blob(blob, depth)

    def blob_as_path(self, blob: Blob, suffix: str = "") -> str:
        """外部の道具（ODBC・7z 等）に渡すため、実ファイルのパスを得る（メモリ上なら書き出す）。"""
        if blob.path is not None:
            return long_path(blob.path) if len(blob.path) >= 240 else blob.path
        self.ensure_space(len(blob.data or b""))
        fd, tmp = tempfile.mkstemp(dir=self.tmpdir, suffix=suffix or blob.ext)
        with os.fdopen(fd, "wb") as f:
            f.write(blob.data or b"")
        return tmp


IGNORED_STREAMS = {"Zone.Identifier", "SmartScreen", "com.dropbox.attrs", "encryptable", "AFP_AfpInfo", "AFP_Resource"}


def alternate_streams(path: str) -> list[tuple[str, int]]:
    """NTFS の代替データストリーム（主ストリーム以外）の名前と大きさ。Windows 以外・未対応なら空。"""
    if os.name != "nt":
        return []
    if not _volume_has_streams(path):
        return []  # ストリームを持てないボリューム（FAT・CD・一部の NAS 等）。番号の一覧に頼らずに済ませる
    import ctypes
    from ctypes import wintypes

    class WIN32_FIND_STREAM_DATA(ctypes.Structure):
        _fields_ = [("StreamSize", ctypes.c_longlong), ("cStreamName", ctypes.c_wchar * (260 + 36))]

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.FindFirstStreamW.restype = wintypes.HANDLE
    k32.FindFirstStreamW.argtypes = [wintypes.LPCWSTR, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    k32.FindNextStreamW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    k32.FindClose.argtypes = [wintypes.HANDLE]
    data = WIN32_FIND_STREAM_DATA()
    h = k32.FindFirstStreamW(long_path(path), 0, ctypes.byref(data), 0)
    if h in (None, wintypes.HANDLE(-1).value):
        err = ctypes.get_last_error()
        if err in NO_STREAM_ERRORS:
            return []  # ストリームが無い・ストリームを持てないファイルシステム（FAT 等）
        # 回線断・権限などで一覧を取れなかった。黙って「ストリーム無し」にすると、隠しストリームを調べないまま
        # 「検査済み」と言い切ってしまう（不具合の修正・2026-10-17）
        raise ctypes.WinError(err)
    out = []
    try:
        while True:
            name = data.cStreamName  # 例 ":secret:$DATA"
            parts = name.split(":")
            if len(parts) >= 3 and parts[1] and parts[1] not in IGNORED_STREAMS:
                out.append((parts[1], int(data.StreamSize)))
            if not k32.FindNextStreamW(h, ctypes.byref(data)):
                err = ctypes.get_last_error()
                if err in (18, 38):  # ERROR_NO_MORE_FILES / ERROR_HANDLE_EOF（終わり）
                    break
                raise ctypes.WinError(err)
    finally:
        k32.FindClose(h)
    return out


FILE_NAMED_STREAMS = 0x40000


def _volume_has_streams(path: str) -> bool:
    """そのファイルのあるボリュームが代替データストリームを持てるか。分からなければ True（一覧を取りに行く）。"""
    # ボリュームの根を調べる kernel32.GetVolumePathNameW は 1回 約6ms かかる。同じフォルダのファイルは同じボリュームなので、
    # フォルダ単位で覚える（上限つきの lru_cache なので、フォルダが何万あってもメモリは増え続けない）
    try:
        return _root_has_streams(_volume_root_of_dir(os.path.dirname(path) or path))
    except OSError:
        return True  # 根を調べられなかった（失敗は覚えない。一覧を取りに行く）


@lru_cache(maxsize=512)
def _volume_root_of_dir(folder: str) -> str:
    """フォルダのあるボリュームの根（例 "C:\\"）。調べられなければ OSError（失敗は lru_cache に残らない）。"""
    import ctypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    root = ctypes.create_unicode_buffer(32768)
    if not k32.GetVolumePathNameW(long_path(folder), root, len(root)):
        raise OSError("GetVolumePathNameW failed")
    return root.value


@lru_cache(maxsize=256)
def _root_has_streams(root: str) -> bool:
    import ctypes
    from ctypes import wintypes

    flags = wintypes.DWORD(0)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    if not k32.GetVolumeInformationW(root, None, 0, None, None, ctypes.byref(flags), None, 0):
        return True
    return bool(flags.value & FILE_NAMED_STREAMS)


# FindFirstStreamW が「ストリームが無い・扱えない」ときの番号（ERROR_HANDLE_EOF・ERROR_INVALID_FUNCTION・
# ERROR_NOT_SUPPORTED・ERROR_INVALID_PARAMETER）。これ以外の失敗は一覧を取れなかったものとして扱う
NO_STREAM_ERRORS = {38, 1, 50, 87}


RE_SPLIT_FIRST = re.compile(
    r"(?i)^(?P<stem>.+?)(?:\.(?P<num>0*1)|\.part(?P<rar>0*1)\.rar|(?P<zip>\.zip)|(?P<old>\.rar))$"
)


def split_siblings(path: str) -> list[str]:
    """分割アーカイブの1つ目なら、同じフォルダにある続きのファイル（.002・.z01・.part2.rar・.r00 等）を返す。"""
    folder, name = os.path.split(path)
    m = RE_SPLIT_FIRST.match(name)
    if not m:
        return []
    stem = m.group("stem")
    out: list[str] = []

    def collect(make) -> None:
        for i in range(2 if make(2) is not None else 0, 100000):
            cand = make(i)
            if cand is None or not os.path.exists(long_path(os.path.join(folder, cand))):
                break
            out.append(os.path.join(folder, cand))

    if m.group("num"):
        width = len(m.group("num"))
        collect(lambda i: f"{stem}.{i:0{width}d}")
    elif m.group("rar"):
        width = len(m.group("rar"))
        collect(lambda i: f"{stem}.part{i:0{width}d}.rar")
    elif m.group("zip"):
        collect(lambda i: f"{stem}.z{i - 1:02d}" if i >= 2 else None)
    elif m.group("old"):
        collect(lambda i: f"{stem}.r{i - 2:02d}" if i >= 2 else None)
    return out


def error_detail(e: BaseException) -> str:
    """想定外の例外の詳細（型・文・起きた場所）を、理由の文の末尾に添える形にする。

    使い手が読む次の手を先に出し、直す側が要る詳細は後ろの括弧へ回す（報告から直せるように場所は残す）。
    """
    tb = traceback.extract_tb(e.__traceback__)
    where = f"・{Path(tb[-1].filename).name}:{tb[-1].lineno}" if tb else ""
    return f"（詳細: {type(e).__name__}: {str(e)[:300]}{where}）"


# Python が PermissionError に振る Windows の番号（5・16・19〜36・65・82・83・108・132・158・167）のうちの分け方。
# 権限が無いことを示すもの（ERROR_ACCESS_DENIED・ERROR_NETWORK_ACCESS_DENIED）
_NO_RIGHT_WINERRORS = (5, 65)
# ディスクから読めなかったことを示すもの（未準備・CRC・シーク・セクタが無い・読み書きの失敗・装置の故障）。
# ここに無い番号は、権限か使用中かを言い切らない
_DEVICE_WINERRORS = (21, 23, 25, 26, 27, 29, 30, 31)


def access_denied_reason(e: OSError) -> str:
    """開けなかったときの理由の文。他のプログラムが使用中なのか、権限がないのかで次の手を分ける。

    Windows ではどちらも PermissionError になる。使用中なのに「権限がない」と出すと、権限を直しに行かせてしまう。
    組み込みの open() は使用中でも番号（winerror）を持たない [Errno 13] になるので、番号が無ければ両方を挙げる。
    """
    from . import safeio

    if isinstance(e, safeio.SourceError):  # 使用中（SourceInUse）など、理由の文を持っているもの
        return str(e)
    winerror = getattr(e, "winerror", None)
    if winerror in (safeio.WINERR_SHARING_VIOLATION, safeio.WINERR_LOCK_VIOLATION):
        return f"{safeio.IN_USE_OPEN_MSG}（詳細: {e}）"
    if winerror in _NO_RIGHT_WINERRORS:
        return f"アクセスが拒否された（読む権限がない）。{ACCESS_DENIED_HINT}（詳細: {e}）"
    if winerror == 108:  # ERROR_DRIVE_LOCKED
        return (
            "ドライブがロックされていて読めなかった（BitLocker など）。ドライブのロックを解除してから"
            f"再検査してください（詳細: {e}）"
        )
    if winerror in _DEVICE_WINERRORS:
        return (
            "ディスクから読めなかった（ディスク・記録媒体の不具合の可能性。権限の問題ではない）。"
            "エクスプローラーで手元の別のドライブへ写せるかを確かめ、写せたらその写しを検査してください。"
            f"写せなければ、別の写し（バックアップ等）を検査してください（詳細: {e}）"
        )
    return (
        "アクセスが拒否された（読む権限がないか、他のプログラムが使用中）。そのファイルを開いているアプリを閉じるか、"
        f"{ACCESS_DENIED_HINT}（詳細: {e}）"
    )


def _source_failure(path: str, e: BaseException) -> ItemResult:
    """元のファイルを写せなかったときの項目（理由つきの検査不能）。"""
    from . import safeio

    item = ItemResult(path=path, kind="", status=Status.UNCHECKABLE, depth=0)
    if safeio.is_network_lost(e):
        # FileNotFoundError（WinError 53）より先に見る。「削除された」と出すと、回線断なのに人がファイルを探しに行く
        item.reason = f"{safeio.NETWORK_LOST_MSG}: {e}"
    elif isinstance(e, safeio.SourceError):
        item.reason = str(e)
    elif isinstance(e, PermissionError):
        item.reason = access_denied_reason(e)
    elif isinstance(e, FileNotFoundError):
        item.reason = f"ファイルが見つからない（検査中に移動・削除された可能性）。{NOT_FOUND_HINT}（詳細: {e}）"
    elif safeio.is_disk_full(e):
        item.reason = "一時フォルダのドライブが満杯になった。" + TEMP_DIR_HINT
    else:
        item.reason = (
            "元のファイルを読めなかった。エクスプローラーで開けるかを確かめ、開けるなら手元のドライブへ写して"
            "その写しを検査してください" + error_detail(e)
        )
    return item


def scan_file(path: str, options: ScanOptions, passwords: PasswordBook | None = None) -> FileResult:
    """実ファイル1件を検査する（ワーカープロセスから呼ばれる入口）。

    元のファイルは safeio.snapshot で一時フォルダへ写してから検査する（他の人の保存を妨げない・
    最終アクセス日時を変えない・外部の道具が元のファイルを触らない）。写しの識別情報と SHA-256 を結果に付ける。
    """
    from dataclasses import asdict

    from . import safeio

    started = time.time()
    book = passwords or PasswordBook()
    ctx = ScanContext(path, options, book.candidates_for(path))
    # 値を持つ読み直し（reveal）は途中経過を書かない・消さない（生の値を一時フォルダに出さない。検査の分を壊さない）
    ctx.checkpoint_file = None if options.reveal or options.collect_positions else checkpoint_path(options, path)
    if ctx.checkpoint_file:
        try:
            os.remove(ctx.checkpoint_file)  # 前の検査が残した途中経過を、今回の分として読ませない
        except OSError:
            pass
    temp_root = options.temp_dir or tempfile.gettempdir()
    source: dict | None = None
    network_lost = False
    try:
        local_dir = ctx.new_tmp_subdir()
        from . import remote

        on_ftp = remote.is_ftp_path(path)
        name = (path.rsplit("/", 1)[-1] if on_ftp else os.path.basename(path)) or "file"
        local = os.path.join(local_dir, name)
        try:
            if on_ftp:
                # FTP は1件ずつ手元へ写す（サーバーへは何も書かない）。分割アーカイブの続き・隠しストリーム・隣の toc.dat は
                # 取りに行かない（README の限界）
                if not options.connection:
                    raise safeio.SourceError("FTP の接続先の設定が無い（接続方式で始めたジョブから再開する）")
                info = remote.ftp_snapshot(
                    path, local, temp_root, remote.Connection.from_dict(options.connection), book.connection_password
                )
            else:
                info = safeio.snapshot(path, local, temp_root, allow_recall=options.allow_recall)
                # 分割アーカイブの1つ目は、7-Zip が続きを同じフォルダから読むので一緒に写す
                for sib in split_siblings(path):
                    safeio.snapshot(
                        sib, os.path.join(local_dir, os.path.basename(sib)), temp_root, options.allow_recall
                    )
        except (safeio.SourceError, OSError) as e:
            ctx.items.append(_source_failure(path, e))
            return FileResult(
                top_path=path,
                items=ctx.items,
                elapsed=time.time() - started,
                network_lost=safeio.is_network_lost(e),
            )
        source = asdict(info)
        mtime = info.mtime_ns / 1e9 if info.mtime_ns else None
        ctx.source_dir = None if on_ftp else os.path.dirname(path)
        top = ctx.scan_blob(Blob(display=path, path=local, mtime=mtime, name_hint=name), depth=0)
        if not info.atime_kept and not on_ftp:
            # FTP はサーバー側の日時を保つ手段そのものが無い（画面・README で説明する。1件ずつの注記にはしない）
            if info.atime_lost_reason == "server_updated":
                top.notes.append(
                    "サーバーが最終アクセス日時を保つ指示に対応しておらず、読み取りで更新された（Samba 等）"
                )
            else:
                top.notes.append("最終アクセス日時を保つ権限が無かった（読み取りで更新された可能性がある）")
        try:
            streams = [] if on_ftp else alternate_streams(path)
        except OSError as e:
            # 一覧を取れなかった: 隠しストリームを調べていないので言い切らない（回線断なら、つながってから読み直す）
            failed = _source_failure(f"{path}:（代替データストリーム）", e)
            failed.depth = 1
            if not safeio.is_network_lost(e):
                failed.reason = f"代替データストリーム（隠しストリーム）の一覧を取れなかった: {failed.reason}"
            ctx.items.append(failed)
            network_lost = network_lost or safeio.is_network_lost(e)
            streams = []
        for i, (stream, size) in enumerate(streams):
            # 隠れた別ストリーム（file.txt:secret）にも中身を書けるので、別項目として検査する
            display = f"{path}:{stream}"
            ads_local = os.path.join(local_dir, f"_stream{i}")
            try:
                safeio.snapshot(display, ads_local, temp_root, allow_recall=options.allow_recall)
            except (safeio.SourceError, OSError) as e:
                failed = _source_failure(display, e)
                failed.depth = 1
                ctx.items.append(failed)
                # 隠しストリームだけ回線断で読めなかったときも、ファイルごと読み直しに回す
                network_lost = network_lost or safeio.is_network_lost(e)
                continue
            ctx.scan_blob(Blob(display=display, path=ads_local, mtime=mtime, name_hint=stream), depth=1)
    finally:
        ctx.cleanup()
        # 最後まで（または例外で）終わったら途中経過は要らない。打ち切られたときだけ残り、実行器が読む
        for p in (ctx.checkpoint_file, ctx.checkpoint_file + ".tmp") if ctx.checkpoint_file else ():
            try:
                os.remove(p)
            except OSError:
                pass
    return FileResult(
        top_path=path,
        items=ctx.items,
        elapsed=time.time() - started,
        source=source,
        network_lost=network_lost,
        distinct_counts=ctx.distinct_counts(),
    )


def worst_status(items: list[ItemResult]) -> Status:
    """項目群のうち最も悪い状態（言い切れなさの強い順）。"""
    order = [
        Status.NEEDS_PASSWORD,
        Status.UNCHECKABLE,
        Status.PENDING,
        Status.PARTIAL,
        Status.OUT_OF_SCOPE,
        Status.SCANNED,
    ]
    present = {i.status for i in items}
    for s in order:
        if s in present:
            return s
    return Status.SCANNED


def risk_of(items: list[ItemResult]) -> str:
    """検出の中身から危険度（高・中・低・なし）を決める。"""
    best = 0
    total = 0
    for it in items:
        for key, n in it.conf_counts.items():
            if not n:
                continue
            pii_type, conf = key.split(":", 1)
            rank = Confidence(conf).rank
            if pii_type in detectors.CRITICAL_TYPES and conf != Confidence.LOW.value:
                rank = 3
            best = max(best, rank)
        # 件数の多さで「高」にするのは確度 中以上だけ（番地の一覧の 低 が100件を超えても「高」にしない）
        total += sum(n for k, n in it.conf_counts.items() if not k.endswith(":" + Confidence.LOW.value))
    if best == 0:
        return "なし"
    if best == 3 or total >= 100:
        return "高"
    return "中" if best == 2 else "低"

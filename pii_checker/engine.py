"""1つの実ファイルを検査するエンジン。

方針（「このフォルダに個人情報は無い」と言い切るための不変条件）:
- 拡張子ではなく中身（先頭のバイト列）で形式を判定する。改名・拡張子なしでも見逃さない。
- アーカイブ・埋め込みファイルは再帰的に展開し、内側の1つ1つにも結果を残す。
- 読めなかったものは黙って飛ばさず、必ず「検査不能」「要パスワード」として理由つきで残す。
- 例外はすべて項目の結果に変換する（1ファイルの失敗で全体を止めない）。
"""

from __future__ import annotations

import os
import re
import shutil
import tempfile
import time
import traceback
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


@dataclass
class Collector:
    """1項目分の検出を集める。件数は「種類×確度」で全数、明細は種類×確度ごとに上限まで。"""

    item: ItemResult
    max_samples: int
    seen: dict[int, tuple] = field(default_factory=dict)  # (種類, 値) の hash → (明細の位置か -1, 見た確度)
    # 住所は、同じ項目に人の手がかり（氏名・生年月日・マイナンバー等）があるときだけ確度 中にする（施設の一覧・
    # 番地の一覧を「個人情報の可能性あり」にしない）。手がかりを待つ住所は 低 で数えておき、finish() で決める
    person_cue: bool = False
    deferred: dict[int, list] = field(
        default_factory=dict
    )  # (種類, 値) の hash → [低で数えた件数, Hit, 明細を持つか, 引数]
    head_chars: int = 0  # 書類の題を探すために見た本文の先頭の文字数（ファイル名は数えない）
    cue_title: str = ""  # 人の手がかりにした書類の題（「名簿」など。明細の注記を出し分ける）
    # 許可リストと利用者の規則（userrules.Matcher。どちらも無ければ None）
    matcher: object | None = None
    allowed_seen: set = field(default_factory=set)  # 許可リストで外した (種類, 値) の hash（読み直しで二重に数えない）
    # 異なる値の数を数えるための対応（seen の鍵 → (種類, 正規化した値の hash)）。メモリの中だけで使い、保存しない
    distinct_keys: dict[int, tuple] = field(default_factory=dict)
    # ファイル全体の異なる値を集める先（(種類, 正規化した値の hash) → 見た最も高い確度の順位）。ScanContext が渡す
    distinct_sink: dict | None = None

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
    ) -> None:
        """文字列を検査して結果に加える。

        raw=True は生データ走査（既に見つけた値は数えず、見つけた分は「残留の可能性」と記す）。
        skip_seen=True は既に見つけた値を数えないだけ（同じ本文を別の読み方でもう一度読むとき）。
        どちらでも、既に見た値をより高い確度で見直したときは明細の確度を引き上げる。
        weak_header=True は見出しが確かでない（左隣が「見出し語＋値」のセル）とき。見出しのおかげで拾えた分は確度を低にする。
        """
        if text is None:
            return
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
            if defer:
                confidence = Confidence.LOW
                counted = prev is None or not (raw or skip_seen)  # 数えない重複は待ちの件数にも足さない
                d = self.deferred.get(key)
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
            if len(self.seen) < 3_000_000:
                self.seen[key] = (idx, confidence)
                self.distinct_keys[key] = (_distinct_type(hit), hash(distinct_key(hit.pii_type, hit.value)))

    def finish(self) -> None:
        """項目を読み終えたときに呼ぶ。人の手がかりがあれば、待たせていた住所を確度 中に引き上げる。

        最後に、種類ごとの異なる値の数を数えて項目に残す（値・hash は捨てる）。
        """
        self._finish_cues()
        self._count_distinct()

    def _count_distinct(self) -> None:
        """種類×確度ごとの異なる値の数を item.distinct_counts に入れ、ファイル全体の集計先にも足す。

        確度は、同じ値（正規化して同じもの）を見たうちで最も高いもの。住所の引き上げ（_finish_cues）の後に数える。
        """
        best: dict[tuple, int] = {}
        for key, dk in self.distinct_keys.items():
            conf = self.seen.get(key, (-1, Confidence.LOW))[1]
            if best.get(dk, 0) < conf.rank:
                best[dk] = conf.rank
        counts: dict[str, int] = {}
        for (pii_type, _), rank in best.items():
            k = f"{pii_type}:{RANK_CONF[rank].value}"
            counts[k] = counts.get(k, 0) + 1
        self.item.distinct_counts = counts
        if self.distinct_sink is not None:
            sink = self.distinct_sink
            for dk, rank in best.items():
                if sink.get(dk, 0) < rank and (dk in sink or len(sink) < 3_000_000):
                    sink[dk] = rank

    def _finish_cues(self) -> None:
        """人の手がかりがあれば、待たせていた住所・固定電話を確度 中に引き上げる（無ければ明細に理由を添える）。"""
        if self.person_cue:
            for key in list(self.deferred):
                self._resolve_deferred(key)
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
        pos, conf = self.seen.get(key, (-1, Confidence.LOW))
        if conf != Confidence.LOW:
            return
        hit.rule = hit.rule + self._cue_note()
        if own_sample and 0 <= pos < len(self.item.findings) and not self._has_room(hit.pii_type, Confidence.MEDIUM):
            # 中 の明細が上限まで埋まっている。件数は 中 へ移したので、低 の明細は残したまま 中 では載せない。
            # 「低 0 件なのに 低 の明細がある」と読まれないよう、明細に件数の扱いを添える
            f = self.item.findings[pos]
            f.rule = hit.rule + "（中 の明細が上限のため 低 の欄に載せた。件数は 中 に数えた）"
            self.seen[key] = (-1, Confidence.MEDIUM)
            return
        if own_sample and 0 <= pos < len(self.item.findings):
            f = self.item.findings[pos]
            f.confidence = Confidence.MEDIUM
            f.rule = hit.rule
        else:
            # 低の明細の枠が埋まっていて載らなかった（pos=-1）ときも、引き上げた分は 中 の明細に載せる
            # 施設の 低 などで先に載った明細は書き換えず、引き上げた分を別に載せる
            norm, location, location_fn, method, raw = args
            pos = self._add_sample(hit, Confidence.MEDIUM, norm, location, location_fn, method, raw, [])
        self.seen[key] = (pos, Confidence.MEDIUM)

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
        """その種類×確度の明細に、まだ載せる枠があるか。"""
        n_same = sum(1 for f in self.item.findings if f.pii_type == pii_type and f.confidence == confidence)
        return n_same < self.max_samples

    def _add_sample(self, hit, confidence, norm, location, location_fn, method, raw, hits) -> int:
        if not self._has_room(hit.pii_type, confidence):
            return -1
        masked = detectors.mask_value(hit.pii_type, hit.value)
        loc = location_fn(hit.start) if location_fn else location
        self.item.findings.append(
            Finding(
                pii_type=hit.pii_type,
                confidence=confidence,
                masked_value=masked,
                location=loc,
                context=detectors.masked_context(norm, hit.start, hit.end, masked),
                rule=hit.rule,
                method=method + ("（削除済み・非表示領域の残留の可能性）" if raw else ""),
            )
        )
        return len(self.item.findings) - 1

    def _maybe_upgrade(self, prev, hit, confidence, norm, location, location_fn, method, raw, key) -> None:
        """既に見た値を、より高い確度で見直したら明細と件数を引き上げる。"""
        pos, prev_conf = prev
        if confidence.rank <= prev_conf.rank:
            return
        self._move_count(hit.pii_type, prev_conf, confidence)
        if pos < 0 or pos >= len(self.item.findings):
            # 明細の上限で載っていなかった値でも、高い確度で見直したなら新しく明細に載せる
            idx = self._add_sample(hit, confidence, norm, location, location_fn, method, raw, [])
            self.seen[key] = (idx, confidence)
            return
        self.seen[key] = (pos, confidence)
        old = self.item.findings[pos]
        old.confidence = confidence
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

    def add_lines(self, text: str, location_prefix: str = "", method: str = "", ocr: bool = False) -> None:
        """長い本文を行の塊に分けて検査する（位置は「N行目」で示す）。

        ocr=True は OCR で読んだ1項目分の文字（本人確認書類の写しの判別もする）。
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

            self.add_text(chunk, "", method=method, location_fn=loc)

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
                cur_score = score
                cur_cells = cells
                self._table_row(values, r_idx, [], location_fn, method)  # 見出し行自体も検査（見出しなしで）
            else:
                self._table_row(values, r_idx, headers, location_fn, method)
            prev_blank = False
        return n

    def add_records(self, columns: list[str], rows, location_fn: Callable[[int, int], str], method: str = "") -> int:
        """列名が分かっている表（データベース）を検査する。戻り値は行数。"""
        self._skip_seen = False
        n = 0
        for r_idx, row in enumerate(rows, start=1):
            n += 1
            values = ["" if v is None else _cell_to_str(v) for v in row]
            self._table_row(values, r_idx, list(columns), location_fn, method)
        return n

    def _table_row(self, values, r_idx, headers, location_fn, method) -> None:
        for c_idx, v in enumerate(values):
            if not v:
                continue
            header = headers[c_idx] if c_idx < len(headers) else None
            weak = False
            if not (header and detectors.header_category(header)):
                # 横持ち: 左隣（空白を挟んでもよい）のセルが見出し語なら、それを見出しにする。
                # 左隣が「見出し語＋値」のセルなら、見出しのおかげで拾えた分は確度を低にする（座標を番号と取り違えないため）
                for j in range(c_idx - 1, max(-1, c_idx - 3), -1):
                    if values[j]:
                        strength = _header_strength(values[j])
                        if strength != HEADER_NONE:
                            header, weak = values[j], strength == HEADER_WEAK
                        break
            self.add_text(
                v,
                location_fn(r_idx, c_idx),
                header=header,
                method=method,
                skip_seen=getattr(self, "_skip_seen", False),
                weak_header=weak,
            )


RE_ANNOTATION = re.compile(r"[（(【\[〔<＜][^）)】\]〕>＞]{0,20}[）)】\]〕>＞]")
RE_LABEL_WITH_INDEX = re.compile(r"\D{1,15}\d{1,2}")


HEADER_NONE, HEADER_WEAK, HEADER_SURE = 0, 1, 2


def _header_strength(v: str) -> int:
    """見出しのセルらしさ（短く、文ではなく、個人情報の見出し語を含む）。「氏名（必須）」の括弧書きは除いて判定する。

    「マイナンバー 123456789018」のように値まで入ったセル（それ自体で検出される）は HEADER_WEAK。
    「2024/04/01時点の氏名」のように数字を含むだけの見出しは HEADER_SURE のまま。
    """
    if not v:
        return HEADER_NONE
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
    return HEADER_WEAK if detectors.detect(detectors.normalize(core), None) else HEADER_SURE


RE_VALUE_SHAPE = re.compile(r"\d{2,4}[-/.]\d{1,4}[-/.]\d{1,4}|\d{5,}|@")
RE_GENERIC_HEADER = re.compile(
    r"^(No\.?|NO|№|ID|番号|連番|通番|部署|部門|所属|役職|備考|区分|種別|日付|会社名?|社名|内容|メモ|状態|コード|"
    r"[一-龥]{1,4}日|第?\d{1,2}希望|.{1,6}番号)$"
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
    import datetime as _dt

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
        self.distinct: dict[tuple, int] = {}

    def distinct_counts(self) -> dict[str, int]:
        """ファイル全体（内側の項目を含む）での「種類:確度」→異なる値の数。"""
        counts: dict[str, int] = {}
        for (pii_type, _), rank in self.distinct.items():
            k = f"{pii_type}:{RANK_CONF[rank].value}"
            counts[k] = counts.get(k, 0) + 1
        return counts

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
                f"展開した合計が上限（{self.options.max_expand_bytes // 1024**3}GB）を超えたため打ち切り"
                "（zip 爆弾の疑い。上限は設定で変えられる）"
            )
        if self.entries > self.options.max_entries:
            raise Uncheckable(f"内側のファイル数が上限（{self.options.max_entries}件）を超えたため打ち切り")

    def password_candidates(self) -> list[str]:
        return list(self.passwords)

    # ---------------------------------------------------------- 検査の入口

    def scan_blob(self, blob: Blob, depth: int) -> ItemResult:
        """中身を1件検査して結果を items に加える（内側は再帰）。"""
        from . import sniff

        item = ItemResult(path=blob.display, kind="", status=Status.PENDING, depth=depth)
        item.mtime = blob.mtime
        self.items.append(item)
        collector = Collector(
            item, self.options.max_samples_per_type, matcher=self.matcher, distinct_sink=self.distinct
        )
        try:
            item.size = blob.size
            if depth > self.options.max_depth:
                raise Uncheckable(f"入れ子が深すぎる（{self.options.max_depth}段を超えた）")
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
            item.reason = f"アクセスが拒否された（権限がない・他のプログラムが使用中）: {e}"
        except FileNotFoundError as e:
            item.status = Status.UNCHECKABLE
            item.reason = f"ファイルが見つからない（検査中に移動・削除された可能性）: {e}"
        except (TooLargeForMemory, MemoryError) as e:
            self._sweep_instead(blob, item, collector, e)
        except Exception as e:  # 想定外の失敗も「検査不能」として必ず残す
            from .safeio import is_disk_full

            item.status = Status.UNCHECKABLE
            if is_disk_full(e):
                item.reason = (
                    "一時フォルダのドライブが満杯になり、展開・書き出しができなかった。"
                    "空きの多いドライブを「展開に使う一時フォルダ」に指定して再検査する"
                )
                return item
            tb = traceback.extract_tb(e.__traceback__)
            where = f"{Path(tb[-1].filename).name}:{tb[-1].lineno}" if tb else ""
            item.reason = f"読み取り中にエラー（{type(e).__name__}: {str(e)[:300]}）{where}"
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
            item.reason = f"{why}ため形式どおりに読めず、文字列だけを拾う走査もメモリ不足で失敗した"
            return
        except Exception as e:
            item.status = Status.UNCHECKABLE
            item.reason = f"{why}ため形式どおりに読めず、文字列だけを拾う走査も失敗した（{type(e).__name__}: {e}）"
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
    import ctypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    root = ctypes.create_unicode_buffer(32768)
    if not k32.GetVolumePathNameW(long_path(path), root, len(root)):
        return True
    return _root_has_streams(root.value)


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
        item.reason = f"アクセスが拒否された（権限がない）: {e}"
    elif isinstance(e, FileNotFoundError):
        item.reason = f"ファイルが見つからない（検査中に移動・削除された可能性）: {e}"
    elif safeio.is_disk_full(e):
        item.reason = (
            "一時フォルダのドライブが満杯になった。空きの多いドライブを「展開に使う一時フォルダ」に指定して再検査する"
        )
    else:
        item.reason = f"元のファイルを読めなかった（{type(e).__name__}: {str(e)[:300]}）"
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

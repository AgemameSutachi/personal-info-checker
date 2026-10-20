"""Access（Jet 4・ACE）のファイルの、消した行の跡と空き領域を 0 で塗りつぶす（対処 T2-e の Jackcess 用）。

Jackcess は行を消しても「削除済み」の印を付けるだけで、値のバイト列をデータページに残す。Access の「最適化」（CompactDatabase）
は Jackcess に無いので、書き換えたあとのファイルを、ページの作りを読み解いて自前で塗りつぶす。

読み解いた形式（Jet 4・ACE。ページは 4096 バイト。Jackcess の公開しているファイル形式の文書と実物で確かめた）:
- データページ（先頭バイト 0x01）: 2〜3 バイト目が空き領域の大きさ、12〜13 が行の数、14 から行ごとの 2 バイトの位置。
  位置の下位 13 ビットが行の開始位置、0x8000 が削除済み、0x4000 が別の場所への繰り越しの指し示し。行はページの末尾から前へ詰める
  （行 0 が一番後ろ）ので、行 i の範囲は [開始 i, 開始 i-1)（行 0 は [開始 0, ページの終わり)）。
  長い値（メモ・OLE）の本文も同じ形のページに入っているので、同じ処理で消える。
  行が更新で大きくなって元の場所に収まらないと、元の場所には4バイトの指し示し（行の番号1バイト＋ページ番号3バイト。
  印 0x4000）だけを残し、本体は別の場所へ移る。移った先の行は、ページの走査で拾われないよう削除済みの印（0x8000）が付いたまま
  生きている（実物で確かめた。印だけで消すと、更新した行が丸ごと消える）。そこで、生きている指し示しの行き先は塗りつぶさない。
- 解放された長い値のページ: ACE は、長い値（メモ・OLE）のページを解放するとき、先頭バイトを 0x01 から 0x09 に変えるだけで
  本文を残す（実物で確かめた。印 0x09・2バイト目 0x01・4〜7バイト目 "LVAL" のページ）。見出しの8バイトを残して 0 にする。
- 索引ページ（0x03 の中間・0x04 の葉）: 2〜3 バイト目が空き領域の大きさ。空き領域はページの末尾にあるとして、そこを 0 にする。
塗りつぶすのは、削除済みの行の範囲・データページの行の位置の表と行の間の空き・索引ページの末尾の空きだけ。
生きている行・行の位置の表・ページの見出しは変えない（空き領域の大きさの記録も、そのまま保つ）。
Jet 3（2048 バイトのページ）は扱わない（ScrubUnsupported）。
"""

from __future__ import annotations

import os
import re

PAGE_SIZE = 4096
DATA_PAGE = 0x01
INDEX_INTERMEDIATE = 0x03
INDEX_LEAF = 0x04
FREED_PAGE = 0x09
DELETED_FLAG = 0x8000
OVERFLOW_FLAG = 0x4000
OFFSET_MASK = 0x1FFF
ROW_COUNT_OFFSET = 12
ROW_TABLE_OFFSET = 14
INDEX_ENTRIES_START = 0x1E0  # 索引ページの、見出しとビットマスクのあとから項目が始まる位置


class ScrubUnsupported(Exception):
    """このファイルの形式は塗りつぶせない（Jet 3・暗号化など）。"""


def _u16(buf, pos: int) -> int:
    return buf[pos] | (buf[pos + 1] << 8)


def scrub_data_page(page: bytearray, keep: set[int] | None = None) -> int:
    """データページ1枚の、削除済みの行と空き領域を 0 にする。塗りつぶしたバイト数を返す。

    keep は塗りつぶさない行の番号（生きている繰り越しの指し示しの行き先。削除済みの印が付いていても生きている）。
    """
    n = _u16(page, ROW_COUNT_OFFSET)
    table_end = ROW_TABLE_OFFSET + 2 * n
    if n == 0 or table_end > PAGE_SIZE:
        return 0
    starts = [_u16(page, ROW_TABLE_OFFSET + 2 * i) for i in range(n)]
    cleared = 0
    lowest = PAGE_SIZE
    for i, raw in enumerate(starts):
        start = raw & OFFSET_MASK
        end = PAGE_SIZE if i == 0 else (starts[i - 1] & OFFSET_MASK)
        if not (table_end <= start <= end <= PAGE_SIZE):
            return 0  # 見慣れない作り（壊れている・別の種類のページ）。触らない
        lowest = min(lowest, start)
        if raw & DELETED_FLAG and not (keep and i in keep):
            cleared += sum(1 for b in page[start:end] if b)
            page[start:end] = bytes(end - start)
    if lowest > table_end:
        cleared += sum(1 for b in page[table_end:lowest] if b)
        page[table_end:lowest] = bytes(lowest - table_end)
    return cleared


def scrub_index_page(page: bytearray) -> int:
    """索引ページ1枚の、末尾の空き領域を 0 にする。塗りつぶしたバイト数を返す。"""
    free = _u16(page, 2)
    if free <= 0 or free > PAGE_SIZE - INDEX_ENTRIES_START:
        return 0
    start = PAGE_SIZE - free
    cleared = sum(1 for b in page[start:] if b)
    page[start:] = bytes(free)
    return cleared


def live_overflow_targets(page) -> list[tuple[int, int]]:
    """データページの、生きている繰り越しの指し示し（印 0x4000・削除済みでない）の行き先 [(ページ番号, 行の番号)]。"""
    out = []
    for i, start, end, deleted in _page_records(page):
        raw = _u16(page, ROW_TABLE_OFFSET + 2 * i)
        if raw & OVERFLOW_FLAG and not deleted and end - start >= 4:
            out.append((int.from_bytes(page[start + 1 : start + 4], "little"), page[start]))
    return out


def _page_records(page, base: int = 0) -> list[tuple[int, int, int, bool]]:
    """データページの行の一覧 [(行の番号, 開始, 終了, 削除済みか)]（ページ内の位置）。見慣れない作りなら空。"""
    n = _u16(page, ROW_COUNT_OFFSET)
    table_end = ROW_TABLE_OFFSET + 2 * n
    if n == 0 or table_end > PAGE_SIZE:
        return []
    starts = [_u16(page, ROW_TABLE_OFFSET + 2 * i) for i in range(n)]
    out = []
    for i, raw in enumerate(starts):
        start = raw & OFFSET_MASK
        end = PAGE_SIZE if i == 0 else (starts[i - 1] & OFFSET_MASK)
        if not (table_end <= start <= end <= PAGE_SIZE):
            return []
        out.append((i, start, end, bool(raw & DELETED_FLAG)))
    return out


def _is_data_page(buf, pos: int) -> bool:
    return buf[pos] == DATA_PAGE and buf[pos + 1] == 0x01


def _is_lval_page(buf, pos: int) -> bool:
    """長い値（メモ・OLE）の本文のページか（データページで、4〜7 バイト目が "LVAL"）。"""
    return _is_data_page(buf, pos) and buf[pos + 4 : pos + 8] == b"LVAL"


LV_NEXT_PAGES = 0x00  # 長い値の見出しの印: 繰り越しの鎖（1切れだけのこともある。長さは全体の大きさ）
LV_OTHER_PAGE = 0x40  # 長い値の見出しの印: 1ページに収まる値


def _header_regex(pages: int) -> re.Pattern:
    """表の行の中の、長い値の見出し（長さ 3 バイト・印 1 バイト・位置 4 バイト）の形を探す正規表現。

    先読みで重なりも拾う。群 1 が長さ、群 2 が印、群 3 が行の番号、群 4 がページ番号（3 バイト）。
    長さが 0 のもの・ページ番号がファイルの外のものは拾わない（0 の並びや文字の並びに、むだに当たらないように）。
    """
    last = max(pages - 1, 1)
    if last <= 0xFFFF:
        page = b"." + b"[" + re.escape(b"\x00") + b"-" + re.escape(bytes([last >> 8])) + b"]" + re.escape(b"\x00")
    else:
        page = b".." + b"[" + re.escape(b"\x00") + b"-" + re.escape(bytes([min(last >> 16, 0xFF)])) + b"]"
    nonzero3 = rb"(?:[^\x00]..|.[^\x00].|..[^\x00])"
    flags = b"[" + re.escape(bytes([LV_NEXT_PAGES])) + re.escape(bytes([LV_OTHER_PAGE])) + b"]"
    return re.compile(b"(?s)(?=(" + nonzero3 + b")(" + flags + b")(.)(" + page + b"))")


def _chain_covers(mm, rows: dict[tuple[int, int], tuple[int, int]], key: tuple[int, int], length: int) -> bool:
    """繰り越しの鎖（印 0）をたどった本文の合計（各切れの行の大きさ − 次の位置の 4 バイト）が、見出しの長さに届くか。

    本物の見出しなら、鎖の切れの合計は見出しの長さちょうどになる。届かないものは、見出しの形をした偶然の並びか、
    指し先が使い回された古い見出し（Jackcess の雛形のシステム表 MSysObjects の行に、ファイルのどこにも無い長い値を指す
    ままの見出しがあり、ファイルが大きくなると、その行き先に別の行の本文が入って「指されている」と誤る。実物で確かめた）。
    鎖が途中で切れている・輪になっている場合も届かない扱いにする（そのような値は読めない壊れた値で、守る意味がない）。
    """
    total = 0
    seen: set[tuple[int, int]] = set()
    cur: tuple[int, int] | None = key
    while cur is not None and cur in rows and cur not in seen:
        seen.add(cur)
        start, end = rows[cur]
        if end - start < 4:
            return False
        total += end - start - 4
        if total >= length:
            return True
        at = cur[0] * PAGE_SIZE + start
        cur = (int.from_bytes(mm[at + 1 : at + 4], "little"), mm[at])
    return total >= length


def scrub_orphan_long_values(path: str) -> int:
    """どの行からも指されなくなった長い値（メモ・OLE）の本文を 0 にする。塗りつぶした本文の数を返す。

    Jackcess は行を消しても・メモを書き換えても、元の長い値の本文（LVAL ページの行）を「削除済み」にせず、そのまま残す。
    選んだ値を含まない本文（消した行のほかの列のメモ）や、鎖の切れ目で割れた値もあるので、指されていない本文はすべて消す。

    長い値の本文は、表の行の中の12バイトの見出し（長さ 3 バイト・印 1 バイト・位置 4 バイト・4 バイト）が指している。
    位置は「行の番号 + ページ番号 × 256」の4バイト（リトルエンディアン）。印 0x40 は1ページに収まる値、印 0 は繰り越しの鎖
    （長さは全体の大きさ。1切れだけのこともある）。鎖では、本文の行の先頭4バイトが次の本文の位置（無ければ 0）。
    生きている本文の見分け方（迷ったら「生きている」側に倒す。消し損ねは書き換えのあとの値の確かめが止めるが、
    生きている値を消すとファイルが壊れる）:
    - 表のデータページ（LVAL でないページ）に、印 0x40 の見出し、または本文より短くない長さの印 0 の見出しで指されている
    - 生きている本文から、鎖の「次」でたどれる
    LVAL ページの中は見出しの探索に使わない: ほかの長い値の中身に同じ並びが偶然あると、消すべき本文を「指されている」と誤るため
    （実物の .accdb で起きた）。使われなくなった古いデータページに見出しが残っていると「指されている」と数えるが、
    消し損ねた値は書き換えのあとの確かめが止める。
    呼び出しの前に、削除済みの行は scrub_file で 0 にしておくこと（削除済みの行の中の見出しを、参照とみなさないため）。
    """
    import mmap

    from .engine import long_path

    zeroed = 0
    with open(long_path(path), "r+b") as f:
        if os.fstat(f.fileno()).st_size < 2 * PAGE_SIZE:
            return 0
        with mmap.mmap(f.fileno(), 0) as mm:
            pages = len(mm) // PAGE_SIZE
            rows: dict[tuple[int, int], tuple[int, int]] = {}  # (ページ, 行) → (開始, 終了)。生きている LVAL の本文
            table_pages: list[int] = []
            for pg in range(1, pages):
                pos = pg * PAGE_SIZE
                if not _is_data_page(mm, pos):
                    continue
                if mm[pos + 4 : pos + 8] != b"LVAL":
                    table_pages.append(pg)
                    continue
                for idx, start, end, deleted in _page_records(mm[pos : pos + PAGE_SIZE]):
                    if not deleted and end > start:
                        rows[(pg, idx)] = (start, end)
            if not rows:
                return 0
            header = _header_regex(pages)
            alive: set[tuple[int, int]] = set()
            for pg in table_pages:
                page = mm[pg * PAGE_SIZE : (pg + 1) * PAGE_SIZE]
                for m in header.finditer(page):
                    key = (int.from_bytes(m.group(4), "little"), m.group(3)[0])
                    span = rows.get(key)
                    if span is None or key in alive:
                        continue
                    flag = m.group(2)[0]
                    length = int.from_bytes(m.group(1), "little")
                    if flag == LV_OTHER_PAGE:
                        ok = (
                            length <= span[1] - span[0]
                        )  # 1ページに収まる値: 本文の行は値そのもの（値より短い行は参照ではない）
                    else:
                        ok = length >= span[1] - span[0] - 4 and _chain_covers(mm, rows, key, length)
                    if ok:
                        alive.add(key)
            todo = list(alive)
            while todo:  # 生きている本文から、鎖の「次」をたどる（輪になっていても alive で止まる）
                pg, idx = todo.pop()
                start, end = rows[(pg, idx)]
                if end - start < 4:
                    continue
                at = pg * PAGE_SIZE + start
                nxt = (int.from_bytes(mm[at + 1 : at + 4], "little"), mm[at])
                if nxt in rows and nxt not in alive:
                    alive.add(nxt)
                    todo.append(nxt)
            for key in sorted(rows):
                if key not in alive:
                    start, end = rows[key]
                    lo, hi = key[0] * PAGE_SIZE + start, key[0] * PAGE_SIZE + end
                    mm[lo:hi] = bytes(hi - lo)
                    zeroed += 1
            mm.flush()
        f.flush()
        os.fsync(f.fileno())
    return zeroed


def scrub_freed_long_value_page(page: bytearray) -> int:
    """解放された長い値のページ（先頭 0x09・"LVAL"）の、見出し8バイトより後ろを 0 にする。塗りつぶしたバイト数を返す。"""
    if page[0] != FREED_PAGE or page[1] != 0x01 or bytes(page[4:8]) != b"LVAL":
        return 0
    cleared = sum(1 for b in page[8:] if b)
    page[8:] = bytes(PAGE_SIZE - 8)
    return cleared


def scrub_file(path: str) -> dict:
    """ファイルのデータページ・索引ページを塗りつぶす（その場で書き換える。呼び出し側は写しに対して使う）。

    戻り値: {"data_pages": n, "index_pages": n, "freed_pages": n, "bytes": 塗りつぶしたバイト数}
    """
    from .engine import long_path

    p = long_path(path)
    with open(p, "rb") as f:
        head = f.read(0x80)
    if len(head) < 0x80 or head[4:19] not in (b"Standard Jet DB", b"Standard ACE DB"):
        raise ScrubUnsupported("Access のファイルとして読めません")
    if head[0x14] == 0:
        raise ScrubUnsupported("Access 97（Jet 3）の形式は塗りつぶせません")
    # 暗号化されたファイルは、そもそも Jackcess が（鍵なしでは）開けないので、ここへは来ない。念のため、ページの形が
    # 厳密に合うものだけを塗りつぶす（scrub_data_page・scrub_index_page は見慣れない作りのページには触らない）
    stats = {"data_pages": 0, "index_pages": 0, "freed_pages": 0, "bytes": 0}
    size = os.path.getsize(p)
    keep: dict[int, set[int]] = {}  # ページ番号 → 塗りつぶさない行（生きている指し示しの行き先）
    with open(p, "rb") as f:
        pos = PAGE_SIZE
        while pos + PAGE_SIZE <= size:
            page = f.read(PAGE_SIZE)
            if page[0] == DATA_PAGE and page[1] == 0x01:
                for tp, tr in live_overflow_targets(page):
                    keep.setdefault(tp, set()).add(tr)
            pos += PAGE_SIZE
    with open(p, "r+b") as f:
        pos = PAGE_SIZE  # 0 ページ目はファイルの見出し
        while pos + PAGE_SIZE <= size:
            f.seek(pos)
            page = bytearray(f.read(PAGE_SIZE))
            kind = page[0]
            cleared = 0
            if kind == DATA_PAGE and page[1] == 0x01:
                cleared = scrub_data_page(page, keep.get(pos // PAGE_SIZE))
                key = "data_pages"
            elif kind == FREED_PAGE:
                cleared = scrub_freed_long_value_page(page)
                key = "freed_pages"
            elif kind in (INDEX_INTERMEDIATE, INDEX_LEAF) and page[1] == 0x01:
                cleared = scrub_index_page(page)
                key = "index_pages"
            if cleared:
                f.seek(pos)
                f.write(page)
                stats[key] += 1
                stats["bytes"] += cleared
            pos += PAGE_SIZE
        f.flush()
        os.fsync(f.fileno())
    return stats

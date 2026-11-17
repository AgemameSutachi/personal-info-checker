"""Unicode の PST/OST（版 23・36）の構造（NDB・LTP）を読む部品。

公開仕様 MS-PST に沿って、ヘッダー → ノードとブロックの B 木（NBT・BBT）→ ブロック（XBLOCK・SLBLOCK を含む）
→ ヒープ（HN）→ B 木のヒープ（BTH）→ プロパティの塊（PC）・表（TC）と辿る。
版 36（Outlook 2013 以降の OST）は 4K のページで、ブロックが zlib で圧縮されていることがある。
壊れた値でも果てしなく辿らないよう、深さ・件数・位置を確かめ、おかしければ PstFormatError を投げる。
"""

from __future__ import annotations

import struct
import zlib
from typing import BinaryIO, Iterator

from .pst import _COMPRESSIBLE

# プロパティの型（MS-OXCDATA 2.11.1）
PT_STRING8 = 0x001E
PT_UNICODE = 0x001F
PT_BINARY = 0x0102
PT_OBJECT = 0x000D
PT_MV_STRING8 = 0x101E
PT_MV_UNICODE = 0x101F
# 値が4バイト以下で、PC の中に直に入る型
_INLINE_TYPES = {0x0002, 0x0003, 0x000A, 0x000B, 0x0004}
# 値が固定長で、ヒープに置かれる型（文字にはならないので読まない）
_FIXED_HEAP_TYPES = {0x0005, 0x0006, 0x0007, 0x0014, 0x0040, 0x0048}

_MAX_TREE_LEVEL = 8  # B 木の深さの上限（実物は 2〜4 段）
_MAX_BLOCK_LEVEL = 2  # XXBLOCK まで


class PstFormatError(ValueError):
    """PST の構造が仕様どおりでない（壊れている・未対応の形）。"""


class PstFile:
    """PST の NDB 層（ノードとブロック）を読む。"""

    def __init__(self, f: BinaryIO, version: int, crypt: int):
        if version not in (23, 36):
            raise PstFormatError(f"未対応の版 {version}")
        self.f = f
        self.crypt = crypt
        self.page = 4096 if version == 36 else 512
        self.big = version == 36
        f.seek(0, 2)
        self.size = f.tell()
        f.seek(0)
        head = f.read(0x100)
        nbt_ib = struct.unpack_from("<Q", head, 0xE0)[0]
        bbt_ib = struct.unpack_from("<Q", head, 0xF0)[0]
        # nid → (データの bid, サブノードの bid, 親の nid)
        self.nbt: dict[int, tuple[int, int, int]] = {}
        # bid → (位置, 大きさ, 戻した後の大きさ)
        self.bbt: dict[int, tuple[int, int, int]] = {}
        self._walk(nbt_ib, 0x81, self._nbt_leaf, 0, set())
        self._walk(bbt_ib, 0x80, self._bbt_leaf, 0, set())

    # --- ページと B 木 ---
    def _read_at(self, ib: int, n: int) -> bytes:
        if ib <= 0 or ib + n > self.size:
            raise PstFormatError(f"ファイルの外を指している（位置 {ib:#x}）")
        self.f.seek(ib)
        data = self.f.read(n)
        if len(data) != n:
            raise PstFormatError(f"読み切れなかった（位置 {ib:#x}）")
        return data

    def _walk(self, ib: int, ptype: int, leaf, depth: int, seen: set[int]) -> None:
        if depth > _MAX_TREE_LEVEL or ib in seen:
            raise PstFormatError("B 木が深すぎるか、輪になっている")
        seen.add(ib)
        p = self._read_at(ib, self.page)
        # 項の数などの位置と、後ろの見出し（ページの型）の位置。4K のページは間に詰め物が 8 バイトある
        meta, trailer = (4056, 4072) if self.big else (488, 496)
        if p[trailer] != ptype or p[trailer + 1] != ptype:
            raise PstFormatError(f"B 木のページの印が違う（位置 {ib:#x}）")
        if self.big:
            c_ent, c_max, cb_ent, level = struct.unpack_from("<HHBB", p, meta)
        else:
            c_ent, c_max, cb_ent, level = p[meta], p[meta + 1], p[meta + 2], p[meta + 3]
        if not cb_ent or c_ent > c_max or c_ent * cb_ent > meta:
            raise PstFormatError(f"B 木のページの項の数がおかしい（位置 {ib:#x}）")
        for i in range(c_ent):
            off = i * cb_ent
            if level > 0:
                child_ib = struct.unpack_from("<Q", p, off + 16)[0]
                self._walk(child_ib, ptype, leaf, depth + 1, seen)
            else:
                leaf(p, off)

    def _nbt_leaf(self, p: bytes, off: int) -> None:
        nid, bid_data, bid_sub, parent = struct.unpack_from("<QQQI", p, off)
        self.nbt[nid & 0xFFFFFFFF] = (bid_data, bid_sub, parent)

    def _bbt_leaf(self, p: bytes, off: int) -> None:
        if self.big:
            bid, ib, cb, cb_inflated = struct.unpack_from("<QQHH", p, off)
        else:
            bid, ib, cb = struct.unpack_from("<QQH", p, off)
            cb_inflated = cb
        self.bbt[bid & ~1] = (ib, cb, cb_inflated)

    # --- ブロック ---
    def _raw_block(self, bid: int) -> bytes:
        try:
            ib, cb, cb_inflated = self.bbt[bid & ~1]
        except KeyError:
            raise PstFormatError(f"ブロック {bid:#x} が見つからない") from None
        data = self._read_at(ib, cb)
        if cb_inflated != cb:
            # 戻した大きさは BBT の値（16 ビット）までに抑え、それより大きく膨らむものは壊れているとみなす
            if not cb_inflated:
                raise PstFormatError(f"ブロック {bid:#x} の戻した大きさが 0")  # max_length=0 は上限なしの意味
            d = zlib.decompressobj()
            try:
                data = d.decompress(data, cb_inflated)
            except zlib.error as e:
                raise PstFormatError(f"ブロック {bid:#x} の圧縮を戻せない（{e}）") from None
            if len(data) != cb_inflated or d.unconsumed_tail:
                raise PstFormatError(f"ブロック {bid:#x} の戻した大きさが合わない")
        return data

    def _children(self, bid: int, data: bytes) -> tuple[int, ...]:
        btype, _lvl, c_ent = struct.unpack_from("<BBH", data, 0)
        if btype != 1 or 8 + c_ent * 8 > len(data):
            raise PstFormatError(f"XBLOCK {bid:#x} の形が違う")
        children = struct.unpack_from(f"<{c_ent}Q", data, 8)
        if len(set(children)) != len(children):
            # 実物は同じブロックを2度指さない。重ねて指すものは、膨らませるための壊れた値とみなす
            raise PstFormatError(f"XBLOCK {bid:#x} が同じブロックを重ねて指している")
        return children

    def _walk_data(self, bid: int, level: int, seen: set[int]) -> Iterator[int]:
        """データの bid を、外部ブロックの bid の並びに開く（同じブロックを2度辿らない）。"""
        if level > _MAX_BLOCK_LEVEL:
            raise PstFormatError("XBLOCK の段が深すぎる")
        if bid & ~1 in seen:
            raise PstFormatError(f"ブロック {bid:#x} を重ねて指している")
        seen.add(bid & ~1)
        if bid & 2:  # 内部ブロック（XBLOCK・XXBLOCK）。内部ブロックは暗号化されない
            for child in self._children(bid, self._raw_block(bid)):
                yield from self._walk_data(child, level + 1, seen)
        else:
            yield bid

    def iter_blocks(self, bid: int) -> Iterator[bytes]:
        """データの bid を、外部ブロックの並び（暗号を戻したもの）として順に返す。"""
        for b in self._walk_data(bid, 0, set()):
            data = self._raw_block(b)
            if self.crypt == 1:
                data = data.translate(_COMPRESSIBLE)
            yield data

    def data_size(self, bid: int) -> int:
        """データの bid の全体の大きさ（見出しの自己申告でなく、BBT の外部ブロックの大きさの合計）。"""
        total = 0
        for b in self._walk_data(bid, 0, set()):
            try:
                total += self.bbt[b & ~1][2]
            except KeyError:
                raise PstFormatError(f"ブロック {b:#x} が見つからない") from None
        return total

    def subnodes(self, bid_sub: int, level: int = 0, seen: set[int] | None = None) -> dict[int, tuple[int, int]]:
        """サブノードの B 木（SLBLOCK・SIBLOCK）を nid → (データの bid, サブノードの bid) に開く。"""
        out: dict[int, tuple[int, int]] = {}
        if not bid_sub:
            return out
        if level > _MAX_BLOCK_LEVEL:
            raise PstFormatError("サブノードの段が深すぎる")
        seen = set() if seen is None else seen
        if bid_sub & ~1 in seen:
            raise PstFormatError(f"サブノードのブロック {bid_sub:#x} を重ねて指している")
        seen.add(bid_sub & ~1)
        data = self._raw_block(bid_sub)
        btype, lvl, c_ent = struct.unpack_from("<BBH", data, 0)
        if btype != 2:
            raise PstFormatError(f"サブノードのブロック {bid_sub:#x} の形が違う")
        for i in range(c_ent):
            if lvl == 0:
                nid, bd, bs = struct.unpack_from("<QQQ", data, 8 + i * 24)
                out[nid & 0xFFFFFFFF] = (bd, bs)
            else:
                _nid, child = struct.unpack_from("<QQ", data, 8 + i * 16)
                out.update(self.subnodes(child, level + 1, seen))
        return out


class Heap:
    """ノードのデータを HN（ヒープ）として読む。"""

    def __init__(self, pst: PstFile, bid: int, bid_sub: int):
        self.pst = pst
        self.bid_sub = bid_sub
        self.blocks = list(pst.iter_blocks(bid))
        first = self.blocks[0] if self.blocks else b""
        if len(first) < 12 or first[2] != 0xEC:
            raise PstFormatError("ヒープの印が違う")
        self.client = first[3]
        self.root = struct.unpack_from("<I", first, 4)[0]
        self._subs: dict[int, tuple[int, int]] | None = None

    def item(self, hid: int) -> bytes:
        idx = (hid >> 5) & 0x7FF
        blk_i = hid >> 16
        if hid & 0x1F or not idx or blk_i >= len(self.blocks):
            raise PstFormatError(f"ヒープの番地 {hid:#x} がおかしい")
        blk = self.blocks[blk_i]
        ib_map = struct.unpack_from("<H", blk, 0)[0]
        c_alloc = struct.unpack_from("<H", blk, ib_map)[0]
        if idx > c_alloc:
            raise PstFormatError(f"ヒープの番地 {hid:#x} が範囲の外")
        offs = struct.unpack_from(f"<{c_alloc + 1}H", blk, ib_map + 4)
        return blk[offs[idx - 1] : offs[idx]]

    def subs(self) -> dict[int, tuple[int, int]]:
        if self._subs is None:
            self._subs = self.pst.subnodes(self.bid_sub)
        return self._subs

    def hnid_bytes(self, hnid: int) -> bytes:
        """HNID（ヒープの番地か、サブノードの nid）が指す値を返す。"""
        if hnid == 0:
            return b""
        if hnid & 0x1F == 0:
            return self.item(hnid)
        return b"".join(self.pst.iter_blocks(self.sub_entry(hnid)[0]))

    def sub_entry(self, nid: int) -> tuple[int, int]:
        try:
            return self.subs()[nid]
        except KeyError:
            raise PstFormatError(f"サブノード {nid:#x} が見つからない") from None

    def bth(self, hid: int) -> list[tuple[bytes, bytes]]:
        """BTH（ヒープの上の B 木）の葉の (鍵, 値) を並べて返す。"""
        h = self.item(hid)
        btype, cb_key, cb_ent, levels, hid_root = struct.unpack_from("<BBBBI", h, 0)
        if btype != 0xB5 or not cb_key or levels > _MAX_TREE_LEVEL:
            raise PstFormatError("BTH の印が違う")
        out: list[tuple[bytes, bytes]] = []
        seen: set[int] = set()

        def walk(hid_: int, lvl: int) -> None:
            if not hid_:
                return
            if hid_ in seen:
                raise PstFormatError("BTH が同じ番地を重ねて指している")
            seen.add(hid_)
            rec = self.item(hid_)
            step = cb_key + (cb_ent if lvl == 0 else 4)
            for i in range(0, len(rec) - step + 1, step):
                if lvl == 0:
                    out.append((rec[i : i + cb_key], rec[i + cb_key : i + step]))
                else:
                    walk(struct.unpack_from("<I", rec, i + cb_key)[0], lvl - 1)

        walk(hid_root, levels)
        return out


class Prop:
    """PC・TC の1つの値（大きな値は必要になるまで読まない）。"""

    __slots__ = ("ptype", "heap", "hnid", "inline")

    def __init__(self, ptype: int, heap: Heap, hnid: int = 0, inline: bytes | None = None):
        self.ptype = ptype
        self.heap = heap
        self.hnid = hnid
        self.inline = inline

    def raw(self) -> bytes:
        return self.inline if self.inline is not None else self.heap.hnid_bytes(self.hnid)

    def in_subnode(self) -> bool:
        return self.inline is None and self.hnid & 0x1F != 0

    def size(self) -> int:
        if self.in_subnode():
            return self.heap.pst.data_size(self.heap.sub_entry(self.hnid)[0])
        return len(self.raw())

    def iter_chunks(self) -> Iterator[bytes]:
        if self.in_subnode():
            yield from self.heap.pst.iter_blocks(self.heap.sub_entry(self.hnid)[0])
        else:
            yield self.raw()


def read_pc(pst: PstFile, bid: int, bid_sub: int) -> dict[int, Prop]:
    """PC（プロパティの塊）を pid → Prop に開く。PC でないノードは空を返す。"""
    heap = Heap(pst, bid, bid_sub)
    if heap.client != 0xBC:
        return {}
    props: dict[int, Prop] = {}
    for k, v in heap.bth(heap.root):
        pid = struct.unpack_from("<H", k)[0]
        ptype, hnid = struct.unpack_from("<HI", v)
        if ptype in _INLINE_TYPES:
            props[pid] = Prop(ptype, heap, inline=v[2:6])
        else:
            props[pid] = Prop(ptype, heap, hnid=hnid)
    return props


def read_tc(pst: PstFile, bid: int, bid_sub: int) -> list[dict[int, Prop]]:
    """TC（表）の行を、pid → Prop の並びで返す（値のある欄だけ）。"""
    heap = Heap(pst, bid, bid_sub)
    if heap.client != 0x7C:
        raise PstFormatError("表（TC）の印が違う")
    info = heap.item(heap.root)
    btype, c_cols = info[0], info[1]
    if btype != 0x7C:
        raise PstFormatError("表（TC）の見出しの印が違う")
    rgib = struct.unpack_from("<4H", info, 2)
    hnid_rows = struct.unpack_from("<I", info, 14)[0]
    cols = []
    for i in range(c_cols):
        tag, ib_data, cb_data, i_bit = struct.unpack_from("<IHBB", info, 22 + i * 8)
        cols.append((tag & 0xFFFF, tag >> 16, ib_data, cb_data, i_bit))
    cb_row = rgib[3]
    if not hnid_rows or not cb_row:
        return []
    if hnid_rows & 0x1F == 0:
        row_blocks = [heap.item(hnid_rows)]
    else:
        row_blocks = list(pst.iter_blocks(heap.sub_entry(hnid_rows)[0]))
    rows: list[dict[int, Prop]] = []
    for blk in row_blocks:
        for start in range(0, len(blk) - cb_row + 1, cb_row):
            row = blk[start : start + cb_row]
            cells: dict[int, Prop] = {}
            for ptype, pid, ib_data, cb_data, i_bit in cols:
                if ib_data + cb_data > cb_row or rgib[2] + i_bit // 8 >= cb_row:
                    raise PstFormatError("表の欄の位置がおかしい")
                if not row[rgib[2] + i_bit // 8] & (0x80 >> (i_bit % 8)):
                    continue  # その行には値が無い
                cell = row[ib_data : ib_data + cb_data]
                if ptype in _INLINE_TYPES or ptype in _FIXED_HEAP_TYPES or cb_data != 4:
                    cells[pid] = Prop(ptype, heap, inline=cell)
                else:
                    cells[pid] = Prop(ptype, heap, hnid=struct.unpack_from("<I", cell)[0])
            rows.append(cells)
    return rows


def prop_texts(prop: Prop, codepage: str) -> list[str]:
    """文字列の型の値を文字にする（複数値は1つずつ）。文字列の型でなければ空。"""
    t = prop.ptype
    if t not in (PT_UNICODE, PT_STRING8, PT_MV_UNICODE, PT_MV_STRING8):
        return []
    raw = prop.raw()
    enc = "utf-16-le" if t in (PT_UNICODE, PT_MV_UNICODE) else codepage
    if t in (PT_UNICODE, PT_STRING8):
        return [raw.decode(enc, errors="replace").rstrip("\x00")]
    if len(raw) < 4:
        return []
    n = struct.unpack_from("<I", raw)[0]
    if 4 + n * 4 > len(raw):
        raise PstFormatError("複数値の文字列の数がおかしい")
    offs = list(struct.unpack_from(f"<{n}I", raw, 4)) + [len(raw)]
    return [raw[offs[i] : offs[i + 1]].decode(enc, errors="replace").rstrip("\x00") for i in range(n)]

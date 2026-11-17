"""試験用の最小の PST/OST の書き手（MS-PST の NDB・LTP のうち、読み手が辿る部分だけを作る）。

Outlook では開けない（CRC・割り当て表・名前の対応表などは作らない）。読み手（pii_checker.formats.pst_ndb）が
辿る形だけを仕様どおりに置き、読み手の正しさは公開の実物の PST で別に確かめる。
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field

from pii_checker.formats.pst import _COMPRESSIBLE

# 置換表は「暗号化された値の位置に元の値」なので、その逆が暗号化
_ENCRYPT = bytearray(256)
for _i, _v in enumerate(_COMPRESSIBLE):
    _ENCRYPT[_v] = _i
ENCRYPT = bytes(_ENCRYPT)

PT_LONG = 0x0003
PT_STRING8 = 0x001E
PT_UNICODE = 0x001F
PT_SYSTIME = 0x0040
PT_BINARY = 0x0102
PT_OBJECT = 0x000D
PT_MV_UNICODE = 0x101F

_MAX_EXTERNAL = 8176  # 外部ブロックの中身の上限（これを越えるデータは XBLOCK で分ける）
_MAX_HEAP_ITEM = 3580  # これを越える値はヒープでなくサブノードに置く


@dataclass
class Attachment:
    name: str
    data: bytes | None = None  # ファイルの添付
    message: "Message | None" = None  # 埋め込みメッセージ
    ole: bool = False  # data を OLE の添付（方式 6・PtypObject の先のサブノード）として置く


@dataclass
class Message:
    props: dict[int, tuple[int, object]] = field(default_factory=dict)  # pid → (型, 値)
    recipients: list[dict[int, str]] = field(default_factory=list)  # pid → 文字列
    attachments: list[Attachment] = field(default_factory=list)
    broken: bool = False  # PC のブロックを BBT に載せない（中身はファイルに残る。壊れた PST の試験）


@dataclass
class Folder:
    name: str
    messages: list[Message] = field(default_factory=list)


class _Writer:
    def __init__(self, version: int, crypt: int):
        self.version = version
        self.crypt = crypt
        self.blocks: dict[int, bytes] = {}  # bid → 書く中身
        self.inflated: dict[int, int] = {}  # bid → 戻した後の大きさ（圧縮したブロックだけ）
        self.next_bid = 4
        self.nodes: list[tuple[int, int, int, int]] = []  # (nid, データの bid, サブノードの bid, 親)
        self.next_sub = 1
        self.unlisted: set[int] = set()  # BBT に載せないブロック

    def _bid(self, internal: bool) -> int:
        bid = self.next_bid | (2 if internal else 0)
        self.next_bid += 4
        return bid

    def external(self, data: bytes, compress: bool = False) -> int:
        bid = self._bid(False)
        if self.crypt == 1:
            data = data.translate(ENCRYPT)
        packed = zlib.compress(data) if compress else data
        if len(packed) < len(data):
            # 縮まないときは圧縮しない（大きさが同じだと、読み手は圧縮していないものとして読む）
            self.inflated[bid] = len(data)
            data = packed
        self.blocks[bid] = data
        return bid

    def data(self, data: bytes) -> int:
        """データを外部ブロック（大きければ XBLOCK でまとめたもの）として置き、その bid を返す。"""
        if len(data) <= _MAX_EXTERNAL:
            return self.external(data, compress=self.version == 36)
        parts = [self.external(data[i : i + _MAX_EXTERNAL]) for i in range(0, len(data), _MAX_EXTERNAL)]
        bid = self._bid(True)
        self.blocks[bid] = struct.pack("<BBHI", 1, 1, len(parts), len(data)) + b"".join(
            struct.pack("<Q", b) for b in parts
        )
        return bid

    def subnodes(self, entries: list[tuple[int, int, int]]) -> int:
        if not entries:
            return 0
        bid = self._bid(True)
        body = b"".join(struct.pack("<QQQ", nid, bd, bs) for nid, bd, bs in entries)
        self.blocks[bid] = struct.pack("<BBHI", 2, 0, len(entries), 0) + body
        return bid

    def sub_nid(self, ntype: int) -> int:
        nid = (self.next_sub << 5) | ntype
        self.next_sub += 1
        return nid


def _heap(client: int, items: list[bytes], root_index: int) -> bytes:
    """1ブロックの HN を作る（items の i 番目の hid は (i+1) << 5）。"""
    body = b"".join(items)
    ib_map = 12 + len(body)
    ib_map += ib_map % 2
    offs = [12]
    for it in items:
        offs.append(offs[-1] + len(it))
    hdr = struct.pack("<HBBII", ib_map, 0xEC, client, (root_index + 1) << 5, 0)
    page_map = struct.pack("<HH", len(items), 0) + b"".join(struct.pack("<H", o) for o in offs)
    return (hdr + body).ljust(ib_map, b"\x00") + page_map


def _encode(ptype: int, value) -> bytes:
    if ptype in (PT_UNICODE,):
        return value.encode("utf-16-le")
    if ptype == PT_STRING8:
        return value.encode("cp932")
    if ptype == PT_MV_UNICODE:
        parts = [s.encode("utf-16-le") for s in value]
        head = 4 + 4 * len(parts)
        offs = []
        for p in parts:
            offs.append(head)
            head += len(p)
        return struct.pack(f"<I{len(parts)}I", len(parts), *offs) + b"".join(parts)
    return bytes(value)


def _pc(w: _Writer, props: dict[int, tuple[int, object]], subs: list[tuple[int, int, int]]) -> bytes:
    """PC（プロパティの塊）の HN を作る。大きな値はサブノードに置き、subs へ足す。"""
    items: list[bytes] = [b"", b""]  # 0: BTH の見出し 1: 葉の記録（後で埋める）
    leaf = b""
    for pid in sorted(props):
        ptype, value = props[pid]
        if ptype == PT_LONG:
            leaf += struct.pack("<HHI", pid, ptype, value)
            continue
        raw = _encode(ptype, value)
        if len(raw) > _MAX_HEAP_ITEM:
            nid = w.sub_nid(0x1F)
            subs.append((nid, w.data(raw), 0))
            leaf += struct.pack("<HHI", pid, ptype, nid)
        else:
            items.append(raw)
            leaf += struct.pack("<HHI", pid, ptype, len(items) << 5)
    items[0] = struct.pack("<BBBBI", 0xB5, 2, 6, 0, 2 << 5)
    items[1] = leaf
    return _heap(0xBC, items, 0)


def _tc(rows: list[dict[int, str]]) -> bytes:
    """宛先表（TC）の HN を作る。欄は行の番号・表示名・アドレスの3つ。"""
    cols = [(0x67F2, PT_LONG, 0, 4, 0), (0x3001, PT_UNICODE, 4, 4, 1), (0x3003, PT_UNICODE, 8, 4, 2)]
    items: list[bytes] = [b"", b""]  # 0: TCINFO 1: 行の並び
    matrix = b""
    for i, row in enumerate(rows):
        cells = struct.pack("<I", i)
        ceb = 0x80
        for pid, _t, _ib, _cb, bit in cols[1:]:
            if pid in row:
                items.append(row[pid].encode("utf-16-le"))
                cells += struct.pack("<I", len(items) << 5)
                ceb |= 0x80 >> bit
            else:
                cells += b"\x00\x00\x00\x00"
        matrix += cells + bytes([ceb])
    items[1] = matrix
    info = struct.pack("<BB4HIII", 0x7C, len(cols), 12, 12, 12, 13, 0, 2 << 5, 0)
    info += b"".join(struct.pack("<IHBB", (pid << 16) | t, ib, cb, bit) for pid, t, ib, cb, bit in cols)
    items[0] = info
    return _heap(0x7C, items, 0)


def _message(w: _Writer, m: Message) -> tuple[int, int]:
    """メッセージの PC と、宛先表・添付のサブノードを置き、(データの bid, サブノードの bid) を返す。"""
    subs: list[tuple[int, int, int]] = []
    pc = _pc(w, m.props, subs)
    if m.recipients:
        subs.append((0x692, w.data(_tc(m.recipients)), 0))
    for a in m.attachments:
        asubs: list[tuple[int, int, int]] = []
        aprops: dict[int, tuple[int, object]] = {0x3707: (PT_UNICODE, a.name)}
        if a.message is not None:
            ebd, ebs = _message(w, a.message)
            enid = w.sub_nid(0x04)
            asubs.append((enid, ebd, ebs))
            aprops[0x3701] = (PT_OBJECT, struct.pack("<II", enid, 0))
            aprops[0x3705] = (PT_LONG, 5)
        elif a.ole and a.data is not None:
            onid = w.sub_nid(0x1F)
            asubs.append((onid, w.data(a.data), 0))
            aprops[0x3701] = (PT_OBJECT, struct.pack("<II", onid, len(a.data)))
            aprops[0x3705] = (PT_LONG, 6)
        elif a.data is not None:
            aprops[0x3701] = (PT_BINARY, a.data)
        apc = _pc(w, aprops, asubs)
        subs.append((w.sub_nid(0x05), w.data(apc), w.subnodes(asubs)))
    bid = w.data(pc)
    if m.broken:
        w.unlisted.add(bid)  # 指す先のブロックが BBT に無い（壊れた PST）
    return bid, w.subnodes(subs)


def _btree(w: _Writer, entries: list[bytes], ptype: int, out: bytearray, keys: list[int]) -> int:
    """葉の項を B 木のページにして out の後ろへ置き、根のページの位置を返す。"""
    big = w.version == 36
    page = 4096 if big else 512
    meta, trailer = (4056, 4072) if big else (488, 496)
    cb_ent = len(entries[0]) if entries else 24
    per_page = meta // cb_ent
    level = 0
    while True:
        refs = []
        for i in range(0, max(len(entries), 1), per_page):
            chunk = entries[i : i + per_page]
            p = bytearray(page)
            for j, e in enumerate(chunk):
                p[j * cb_ent : (j + 1) * cb_ent] = e
            if big:
                struct.pack_into("<HHBB", p, meta, len(chunk), per_page, cb_ent, level)
            else:
                p[meta : meta + 4] = bytes([len(chunk), per_page, cb_ent, level])
            p[trailer] = p[trailer + 1] = ptype
            ib = len(out)
            out += p
            refs.append((keys[i] if keys else 0, ib))
        if len(refs) == 1:
            return refs[0][1]
        entries = [struct.pack("<QQQ", k, 0, ib) for k, ib in refs]
        keys = [k for k, _ in refs]
        cb_ent = 24
        per_page = meta // cb_ent
        level += 1


def build_pst(folders: list[Folder], version: int = 23, crypt: int = 0) -> bytes:
    """フォルダとメッセージから PST の中身を作る。"""
    w = _Writer(version, crypt)
    for fi, folder in enumerate(folders):
        fnid = ((0x400 + fi) << 5) | 0x02
        fbd = w.data(_pc(w, {0x3001: (PT_UNICODE, folder.name)}, []))
        w.nodes.append((fnid, fbd, 0, 0))
        for mi, m in enumerate(folder.messages):
            bd, bs = _message(w, m)
            w.nodes.append((((0x8000 + fi * 0x100 + mi) << 5) | 0x04, bd, bs, fnid))
    out = bytearray(1024)
    # ブロックを 64 バイトの境目に並べる
    where: dict[int, tuple[int, int]] = {}
    for bid, data in sorted(w.blocks.items()):
        ib = len(out)
        out += data
        out += b"\x00" * (-len(out) % 64)
        where[bid] = (ib, len(data))
    page = 4096 if version == 36 else 512
    out += b"\x00" * (-len(out) % page)
    nbt_entries = [struct.pack("<QQQII", nid, bd, bs, parent, 0) for nid, bd, bs, parent in sorted(w.nodes)]
    nbt_ib = _btree(w, nbt_entries, 0x81, out, [n[0] for n in sorted(w.nodes)])
    bbt_entries = []
    listed = sorted(b for b in where if b not in w.unlisted)
    for bid in listed:
        ib, cb = where[bid]
        if version == 36:
            bbt_entries.append(struct.pack("<QQHHHH", bid, ib, cb, w.inflated.get(bid, cb), 2, 0))
        else:
            bbt_entries.append(struct.pack("<QQHHI", bid, ib, cb, 2, 0))
    bbt_ib = _btree(w, bbt_entries, 0x80, out, listed)
    out[0:4] = b"!BDN"
    out[10:12] = version.to_bytes(2, "little")
    struct.pack_into("<QQ", out, 0xD8, 0, nbt_ib)
    struct.pack_into("<QQ", out, 0xE8, 0, bbt_ib)
    out[0x201] = crypt
    return bytes(out)

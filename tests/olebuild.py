"""試験用の最小の OLE 複合文書（CFB・版3・512 バイトのセクター）の書き手。

Word・Excel・PowerPoint・Outlook の 97-2003 形式の検体を、Office を使わずに組み立てるためのもの。
4096 バイト未満のストリームは仕様どおりミニストリームへ入れる（olefile・xlrd・extract_msg が読む形）。
兄弟の並びは右の兄弟だけでつなぐ（赤黒木の釣り合いは取らない。読み手は並びを確かめない）。
"""

from __future__ import annotations

import struct

SIGNATURE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
SECTOR = 512
MINI = 64
CUTOFF = 4096
FREESECT = 0xFFFFFFFF
ENDOFCHAIN = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD
NOSTREAM = 0xFFFFFFFF


class _Entry:
    def __init__(self, name: str, kind: int, data: bytes = b"") -> None:
        self.name = name
        self.kind = kind  # 1=ストレージ・2=ストリーム・5=ルート
        self.data = data
        self.children: list[_Entry] = []
        self.sid = 0
        self.start = ENDOFCHAIN
        self.size = 0
        self.left = self.right = self.child = NOSTREAM


def _sort_key(e: _Entry):
    return (len(e.name), e.name.upper())


def build(streams: dict[str, bytes]) -> bytes:
    """ストリームのパス（"/" 区切り）と中身から、CFB のバイト列を作る。途中のストレージは自動で作る。"""
    root = _Entry("Root Entry", 5)
    storages: dict[str, _Entry] = {"": root}
    for path, data in streams.items():
        parts = path.split("/")
        parent = root
        for i in range(len(parts) - 1):
            key = "/".join(parts[: i + 1])
            if key not in storages:
                st = _Entry(parts[i], 1)
                parent.children.append(st)
                storages[key] = st
            parent = storages[key]
        parent.children.append(_Entry(parts[-1], 2, bytes(data)))

    # 通し番号を振る（ルートが 0）
    entries: list[_Entry] = []

    def number(e: _Entry) -> None:
        e.sid = len(entries)
        entries.append(e)
        for ch in sorted(e.children, key=_sort_key):
            number(ch)

    number(root)
    for e in entries:
        kids = sorted(e.children, key=_sort_key)
        if kids:
            e.child = kids[0].sid
            for a, b in zip(kids, kids[1:]):
                a.right = b.sid

    # ミニストリーム
    mini_data = bytearray()
    minifat: list[int] = []
    big: list[_Entry] = []
    for e in entries:
        if e.kind != 2:
            continue
        e.size = len(e.data)
        if e.size == 0:
            e.start = ENDOFCHAIN
        elif e.size < CUTOFF:
            first = len(minifat)
            n = -(-e.size // MINI)
            minifat.extend(range(first + 1, first + n))
            minifat.append(ENDOFCHAIN)
            e.start = first
            mini_data += e.data + b"\x00" * (n * MINI - e.size)
        else:
            big.append(e)

    sectors: list[bytes] = []
    fat: list[int] = []

    def put(data: bytes) -> int:
        n = max(1, -(-len(data) // SECTOR))
        first = len(sectors)
        padded = data + b"\x00" * (n * SECTOR - len(data))
        for i in range(n):
            sectors.append(padded[i * SECTOR : (i + 1) * SECTOR])
        fat.extend(range(first + 1, first + n))
        fat.append(ENDOFCHAIN)
        return first

    for e in big:
        e.start = put(e.data)
    if mini_data:
        root.start, root.size = put(bytes(mini_data)), len(mini_data)
    minifat_start, n_minifat = ENDOFCHAIN, 0
    if minifat:
        raw = struct.pack(f"<{len(minifat)}I", *minifat)
        n_minifat = -(-len(raw) // SECTOR)
        raw += struct.pack("<I", FREESECT) * ((n_minifat * SECTOR - len(raw)) // 4)
        minifat_start = put(raw)

    dir_raw = bytearray()
    for e in entries:
        name = e.name.encode("utf-16-le") + b"\x00\x00"
        if len(name) > 64:
            raise ValueError(f"名前が長すぎる: {e.name}")
        dir_raw += name + b"\x00" * (64 - len(name))
        dir_raw += struct.pack("<HBB", len(name), e.kind, 1)
        dir_raw += struct.pack("<III", e.left, e.right, e.child)
        dir_raw += b"\x00" * 16 + b"\x00" * 4 + b"\x00" * 16
        start = e.start if e.kind != 1 else 0
        dir_raw += struct.pack("<IQ", start, e.size if e.kind != 1 else 0)
    while len(dir_raw) % SECTOR:
        dir_raw += b"\x00" * 64 + struct.pack("<HBB", 0, 0, 0) + struct.pack("<III", NOSTREAM, NOSTREAM, NOSTREAM)
        dir_raw += b"\x00" * 48
    dir_start = put(bytes(dir_raw))

    # FAT 自身のセクターの数を決める（FAT のセクターも FAT に載る）
    n_fat = 1
    while (len(fat) + n_fat) > n_fat * (SECTOR // 4):
        n_fat += 1
    if n_fat > 109:
        raise ValueError("試験の検体としては大きすぎる（DIFAT は作らない）")
    fat_start = len(sectors)
    fat.extend([FATSECT] * n_fat)
    fat.extend([FREESECT] * (n_fat * (SECTOR // 4) - len(fat)))
    fat_raw = struct.pack(f"<{len(fat)}I", *fat)
    for i in range(n_fat):
        sectors.append(fat_raw[i * SECTOR : (i + 1) * SECTOR])

    header = bytearray(SIGNATURE + b"\x00" * 16)
    header += struct.pack("<HHHHH", 0x3E, 3, 0xFFFE, 9, 6)
    header += b"\x00" * 6
    header += struct.pack("<IIIIIIIII", 0, n_fat, dir_start, 0, CUTOFF, minifat_start, n_minifat, ENDOFCHAIN, 0)
    difat = list(range(fat_start, fat_start + n_fat)) + [FREESECT] * (109 - n_fat)
    header += struct.pack("<109I", *difat)
    assert len(header) == SECTOR
    return bytes(header) + b"".join(sectors)


# ------------------------------------------------------------------ 中身の組み立て


def doc_stream(pieces: list[tuple[str, bool]], prc: bytes = b"") -> tuple[bytes, bytes]:
    """Word 97-2003 の WordDocument と 1Table を作る。pieces は（文字, 圧縮か）の並び。

    圧縮した piece は cp1252 の1バイト、そうでなければ UTF-16LE で本文に置く（MS-DOC の piece table）。
    prc を渡すと、piece table の前に書式の塊（Prc）を1つ置く。
    """
    body_at = 0x800
    wd = bytearray(body_at)
    struct.pack_into("<HH", wd, 0, 0xA5EC, 0x00C1)
    struct.pack_into("<H", wd, 0x0A, 0x0200)  # 1Table を使う
    cps = [0]
    pcds = b""
    for text, compressed in pieces:
        at = len(wd)
        if compressed:
            wd += text.encode("cp1252")
            fcv = (at * 2) | 0x40000000
        else:
            wd += text.encode("utf-16-le")
            fcv = at
        cps.append(cps[-1] + len(text))
        pcds += struct.pack("<HIH", 0, fcv, 0)
    plc = struct.pack(f"<{len(cps)}I", *cps) + pcds
    clx = b""
    if prc:
        clx += b"\x01" + struct.pack("<H", len(prc)) + prc
    clx += b"\x02" + struct.pack("<I", len(plc)) + plc
    table = b"\x00" * 16 + clx
    struct.pack_into("<II", wd, 0x01A2, 16, len(clx))
    return bytes(wd), table


def ppt_record(rtype: int, body: bytes, ver: int = 0, inst: int = 0) -> bytes:
    """PowerPoint 97-2003 のレコード1つ（見出し8バイト＋中身）。"""
    return struct.pack("<HHI", (inst << 4) | ver, rtype, len(body)) + body


def ppt_container(rtype: int, *children: bytes) -> bytes:
    return ppt_record(rtype, b"".join(children), ver=0x0F)


def _biff(rtype: int, body: bytes) -> bytes:
    return struct.pack("<HH", rtype, len(body)) + body


def _bof(dt: int) -> bytes:
    return _biff(0x0809, struct.pack("<HHHHII", 0x0600, dt, 0x0DBB, 0x07CC, 0, 0x0206))


def _u16str(s: str, lenlen: int) -> bytes:
    raw = s.encode("utf-16-le")
    return struct.pack("<B" if lenlen == 1 else "<H", len(s)) + b"\x01" + raw


def xls_workbook(sheets: dict[str, list[list[str]]]) -> bytes:
    """Excel 97-2003（BIFF8）の Workbook ストリームを作る。セルはすべて文字（LABEL）で置く。

    数値のセルは書式（XF）の表が要るので作らない（xlrd は XF の無い数値のセルを読めない）。
    """
    globals_head = _bof(0x0005)
    bounds = [(name, _biff(0x0085, b"\x00\x00\x00\x00\x00\x00" + _u16str(name, 1))) for name in sheets]
    eof = _biff(0x000A, b"")
    offset = len(globals_head) + sum(len(b) for _, b in bounds) + len(eof)
    out_bounds = b""
    bodies = b""
    for (name, _), rows in zip(bounds, sheets.values()):
        sheet = _bof(0x0010)
        ncols = max((len(r) for r in rows), default=0)
        sheet += _biff(0x0200, struct.pack("<IIHHH", 0, len(rows), 0, ncols, 0))
        for r, row in enumerate(rows):
            for c, v in enumerate(row):
                sheet += _biff(0x0204, struct.pack("<HHH", r, c, 0) + _u16str(v, 2))
        sheet += eof
        out_bounds += _biff(0x0085, struct.pack("<IBB", offset + len(bodies), 0, 0) + _u16str(name, 1))
        bodies += sheet
    return globals_head + out_bounds + eof + bodies


def msg_streams(subject: str, body: str, attachments: list[tuple[str, bytes]] = ()) -> dict[str, bytes]:
    """Outlook の msg（MS-OXMSG）のストリームを作る。件名・本文・差出人の名前・添付だけ。"""

    def text(tag: int) -> str:
        return f"__substg1.0_{tag:04X}001F"

    def props(header: bytes, entries: list[tuple[int, int, int]]) -> bytes:
        out = header
        for tag, ptype, value in entries:
            out += struct.pack("<HHIQ", ptype, tag, 6, value)
        return out

    streams = {
        text(0x001A): "IPM.Note".encode("utf-16-le"),
        text(0x0037): subject.encode("utf-16-le"),
        text(0x1000): body.encode("utf-16-le"),
    }
    entries = [(0x001A, 0x001F, 0), (0x0037, 0x001F, 0), (0x1000, 0x001F, 0)]
    header = b"\x00" * 8 + struct.pack("<IIII", 0, len(attachments), 0, len(attachments)) + b"\x00" * 8
    streams["__properties_version1.0"] = props(header, entries)
    # 名前つきプロパティの置き場（中身は空でよい）。添付があると extract_msg が読みに行き、無ければ規格違反として断る
    for tag in ("00020102", "00030102", "00040102"):
        streams[f"__nameid_version1.0/__substg1.0_{tag}"] = b""
    for i, (name, data) in enumerate(attachments):
        base = f"__attach_version1.0_#{i:08X}"
        streams[f"{base}/{text(0x3707)}"] = name.encode("utf-16-le")
        streams[f"{base}/__substg1.0_37010102"] = data
        streams[f"{base}/{text(0x3704)}"] = name[:8].encode("utf-16-le")
        streams[f"{base}/__properties_version1.0"] = props(
            b"\x00" * 8,
            [(0x3707, 0x001F, 0), (0x3701, 0x0102, len(data)), (0x3705, 0x0003, 1), (0x0E21, 0x0003, i)],
        )
    return streams

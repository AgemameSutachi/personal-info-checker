"""git リポジトリ（作業フォルダの .git も bare リポジトリも）の中身の処理。

git は履歴の中身を圧縮して持つので、そのままでは文字として読めない。消したつもりのファイルや過去の版に
個人情報が残っていることがあるため、履歴の全オブジェクトを取り出して検査する。

- 緩いオブジェクト（objects/ab/cdef…）: zlib を展開し、blob は中身を、commit・tag は作者・メッセージを、tree はファイル名を検査する
- pack（objects/pack/*.pack）: 全オブジェクトを取り出し、差分（OFS_DELTA・REF_DELTA）を元に戻してから同じように検査する。
  blob には、同じ pack の commit → tree をたどって元のパス名を付ける（たどれないものはハッシュで示す）
- 索引（.git/index）: 追跡しているファイルのパス名を検査する
- commit-graph・multi-pack-index・pack の .idx/.rev/.bitmap: ハッシュと位置だけで文字の中身を持たない

外部の道具（git・dulwich）は使わない（版ごとの違いに左右されないよう、形式を自分で読む）。SHA-1 のリポジトリを前提にし、
SHA-256 のリポジトリで差分の元を引けないときは簡易検査として理由を残す。
"""

from __future__ import annotations

import hashlib
import mmap
import re
import zlib
from collections import OrderedDict

from ..engine import READ_ALL_LIMIT, Blob, Collector, ItemResult, PartialScan, ScanContext, Uncheckable

RE_LOOSE_HEADER = re.compile(rb"^(blob|tree|commit|tag) (\d+)\x00")
# 目印は版のバイトまで含めて照らす（「BITMAP_ID,氏名,…」のような英字で始まるテキストを取り違えないため）
META_MAGIC = {
    b"CGPH\x01": "git のコミットグラフ",
    b"MIDX\x01": "git の複数 pack の索引",
    b"\xfftOc\x00\x00\x00\x02": "git の pack の索引（.idx）",
    b"RIDX\x00\x00\x00\x01": "git の pack の逆引き索引（.rev）",
    b"BITM\x00\x01": "git の pack のビットマップ",
    b"MTME\x00\x00\x00\x01": "git の cruft pack の時刻（.mtimes）",
}


def meta_label(head: bytes) -> str | None:
    """git の補助ファイル（ハッシュと位置だけのもの）なら、その名前を返す。"""
    for magic, label in META_MAGIC.items():
        if head.startswith(magic):
            return label
    return None


TYPE_NAMES = {1: "commit", 2: "tree", 3: "blob", 4: "tag"}
OFS_DELTA, REF_DELTA = 6, 7
CHUNK = 1024 * 1024
CACHE_BYTES = 64 * 1024 * 1024  # 差分の元として覚えておく量


def looks_loose(head: bytes) -> bool:
    """git の緩いオブジェクト（zlib で圧縮した「種類 大きさ\\0中身」）か。"""
    if head[:1] != b"\x78":
        return False
    try:
        out = zlib.decompressobj().decompress(head[:4096], 64)
    except zlib.error:
        return False
    return RE_LOOSE_HEADER.match(out) is not None


def is_pack(head: bytes) -> bool:
    return head.startswith(b"PACK") and head[4:8] in (b"\x00\x00\x00\x02", b"\x00\x00\x00\x03")


# ------------------------------------------------------------------ 中身の種類ごとの検査


def _scan_object(
    ctx: ScanContext, col: Collector, display: str, otype: str, data: bytes, depth: int, name: str = ""
) -> None:
    if otype == "blob":
        leaf = name.rsplit("/", 1)[-1]
        ctx.scan_nested(f"{display}!{name or '（blob）'}", data=data, depth=depth + 1, name_hint=leaf or "blob")
    elif otype in ("commit", "tag"):
        # 作者・コミッターの氏名とメール、メッセージ
        col.add_lines(data.decode("utf-8", errors="replace"), location_prefix=f"{otype} ", method=f"git の {otype}")
    elif otype == "tree":
        for entry_name, _mode, _sha in parse_tree(data):
            col.add_text(entry_name, "tree のファイル名", method="git の tree")


def parse_tree(data: bytes):
    """tree の中身から (名前, モード, 子の SHA-1) を返す。"""
    pos = 0
    n = len(data)
    while pos < n:
        sp = data.index(b" ", pos)
        nul = data.index(b"\x00", sp)
        mode = data[pos:sp].decode("ascii", errors="replace")
        name = data[sp + 1 : nul].decode("utf-8", errors="replace")
        sha = data[nul + 1 : nul + 21]
        yield name, mode, sha
        pos = nul + 21


def handle_git_loose(ctx: ScanContext, blob: Blob, item: ItemResult, col: Collector, depth: int) -> None:
    d = zlib.decompressobj()
    out = bytearray()
    with blob.open() as f:
        while True:
            chunk = f.read(CHUNK)
            if not chunk:
                break
            out += d.decompress(chunk, max(1, READ_ALL_LIMIT + 64 - len(out)))
            if d.unconsumed_tail or len(out) > READ_ALL_LIMIT + 64:
                raise Uncheckable(
                    f"git のオブジェクトが大きすぎる（展開後 {READ_ALL_LIMIT // 1024**2}MB 超）ため、中身を検査していない"
                )
            if d.eof:
                break
    m = RE_LOOSE_HEADER.match(bytes(out[:64]))
    if not m:
        raise Uncheckable("git のオブジェクトとして読めなかった（壊れている可能性）")
    otype = m.group(1).decode()
    data = bytes(out[m.end() :])
    item.kind = f"git のオブジェクト（{otype}）"
    item.method = "zlib を展開して検査"
    _scan_object(ctx, col, blob.display, otype, data, depth)


def handle_git_index(ctx: ScanContext, blob: Blob, item: ItemResult, col: Collector, depth: int) -> None:
    data = blob.read_all()
    version = int.from_bytes(data[4:8], "big")
    count = int.from_bytes(data[8:12], "big")
    item.kind = "git の索引（index）"
    if version not in (2, 3):
        # v4 はパス名を前の名前との差分で持つ。文字列として拾う（簡易検査）
        from ..textdecode import iter_strings

        for s in iter_strings(data):
            col.add_text(s, "索引", method="git の索引の文字列走査")
        raise PartialScan(f"git の索引の形式 v{version} は文字として読める部分だけを検査した")
    pos = 12
    names = 0
    for _ in range(count):
        flags = int.from_bytes(data[pos + 60 : pos + 62], "big")
        start = pos + 62 + (2 if version >= 3 and flags & 0x4000 else 0)
        end = data.index(b"\x00", start)
        col.add_text(data[start:end].decode("utf-8", errors="replace"), "索引のパス", method="git の索引")
        names += 1
        entry_len = end - pos
        pos += (entry_len + 8) // 8 * 8
    item.method = f"追跡しているファイルのパス名 {names} 件"


def handle_git_meta(ctx: ScanContext, blob: Blob, item: ItemResult, col: Collector, depth: int) -> None:
    item.kind = meta_label(blob.head(16)) or "git の索引ファイル"
    item.method = "ハッシュと位置だけで文字の中身を持たない（検査する文字が無い）"


# ------------------------------------------------------------------ pack


class PackReader:
    """pack を読み、差分を元に戻した全オブジェクトを取り出す（.idx は使わない）。"""

    def __init__(self, path: str):
        self._f = open(path, "rb")
        self.mm = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_READ)
        if not is_pack(self.mm[:8]):
            raise Uncheckable("git の pack の見出しが読めない")
        self.count = int.from_bytes(self.mm[8:12], "big")
        # (位置, 種類, 大きさ, 中身の位置, 差分の元)
        self.entries: list[tuple[int, int, int, int, object]] = []
        self.by_offset: dict[int, int] = {}
        self.by_sha: dict[bytes, int] = {}
        self._cache: OrderedDict[int, tuple[int, bytes]] = OrderedDict()
        self._cached = 0
        self._index()

    def close(self) -> None:
        self.mm.close()
        self._f.close()

    def _index(self) -> None:
        mm = self.mm
        pos = 12
        for _ in range(self.count):
            start = pos
            c = mm[pos]
            pos += 1
            otype = (c >> 4) & 7
            size = c & 15
            shift = 4
            while c & 0x80:
                c = mm[pos]
                pos += 1
                size |= (c & 0x7F) << shift
                shift += 7
            base: object = None
            if otype == OFS_DELTA:
                c = mm[pos]
                pos += 1
                off = c & 0x7F
                while c & 0x80:
                    c = mm[pos]
                    pos += 1
                    off = ((off + 1) << 7) | (c & 0x7F)
                base = start - off
            elif otype == REF_DELTA:
                base = bytes(mm[pos : pos + 20])
                pos += 20
            data_pos = pos
            pos = self._skip_zlib(pos)
            self.by_offset[start] = len(self.entries)
            self.entries.append((start, otype, size, data_pos, base))

    def _skip_zlib(self, pos: int) -> int:
        """zlib の流れの終わりの位置（中身はメモリに貯めない）。"""
        d = zlib.decompressobj()
        p = pos
        while not d.eof:
            chunk = self.mm[p : p + CHUNK]
            if not chunk:
                raise Uncheckable("git の pack が途中で切れている")
            d.decompress(chunk, 1)
            while d.unconsumed_tail and not d.eof:
                d.decompress(d.unconsumed_tail, CHUNK)
            p += len(chunk)
        return p - len(d.unused_data)

    def _inflate(self, data_pos: int, size: int) -> bytes:
        if size > READ_ALL_LIMIT:
            raise _TooBig(size)
        d = zlib.decompressobj()
        out = bytearray()
        p = data_pos
        while len(out) < size and not d.eof:
            if d.unconsumed_tail:
                data = d.unconsumed_tail
            else:
                data = self.mm[p : p + CHUNK]
                if not data:
                    raise ValueError("git の pack が途中で切れている")
                p += len(data)
            out += d.decompress(data, size - len(out))
        if len(out) != size:
            raise ValueError("git のオブジェクトの大きさが見出しと合わない")
        return bytes(out)

    def resolve(self, i: int) -> tuple[int, bytes]:
        """i 番目のオブジェクトの (種類, 中身)。差分は元をたどって戻す。

        差分の鎖は数千段になりうるので、再帰ではなく「元までたどってから順に当てる」繰り返しで戻す。
        """
        chain: list[int] = []
        cur = i
        while True:
            hit = self._cache.get(cur)
            if hit is not None:
                self._cache.move_to_end(cur)
                result = hit
                break
            start, otype, size, data_pos, base = self.entries[cur]
            if otype in TYPE_NAMES:
                result = (otype, self._inflate(data_pos, size))
                self._remember(cur, result)
                break
            chain.append(cur)
            if len(chain) > len(self.entries):
                raise ValueError("git の差分の鎖が輪になっている")
            nxt = self.by_offset.get(base) if otype == OFS_DELTA else self.by_sha.get(base)  # type: ignore[arg-type]
            if nxt is None:
                raise _MissingBase()
            cur = nxt
        for j in reversed(chain):
            _, _, size, data_pos, _ = self.entries[j]
            result = (result[0], apply_delta(result[1], self._inflate(data_pos, size)))
            self._remember(j, result)
        return result

    def _remember(self, i: int, result: tuple[int, bytes]) -> None:
        n = len(result[1])
        if n > CACHE_BYTES // 4:
            return
        self._cache[i] = result
        self._cached += n
        while self._cached > CACHE_BYTES and self._cache:
            _, (_, old) = self._cache.popitem(last=False)
            self._cached -= len(old)


class _TooBig(Exception):
    def __init__(self, size: int):
        super().__init__(size)
        self.size = size


class _MissingBase(Exception):
    pass


def apply_delta(src: bytes, delta: bytes) -> bytes:
    """git の差分（コピーと挿入の命令の並び）を元に当てる。"""
    pos = 0

    def varint() -> int:
        nonlocal pos
        result = shift = 0
        while True:
            c = delta[pos]
            pos += 1
            result |= (c & 0x7F) << shift
            shift += 7
            if not c & 0x80:
                return result

    varint()  # 元の大きさ
    dst_size = varint()
    out = bytearray()
    n = len(delta)
    while pos < n:
        op = delta[pos]
        pos += 1
        if op & 0x80:
            off = size = 0
            for k in range(4):
                if op & (1 << k):
                    off |= delta[pos] << (8 * k)
                    pos += 1
            for k in range(3):
                if op & (0x10 << k):
                    size |= delta[pos] << (8 * k)
                    pos += 1
            out += src[off : off + (size or 0x10000)]
        elif op:
            out += delta[pos : pos + op]
            pos += op
        else:
            raise ValueError("git の差分に不正な命令がある")
    if len(out) != dst_size:
        raise ValueError("git の差分を当てた大きさが合わない")
    return bytes(out)


def _object_sha(otype: int, data: bytes) -> bytes:
    return hashlib.sha1(b"%s %d\x00" % (TYPE_NAMES[otype].encode(), len(data)) + data).digest()


def handle_git_pack(ctx: ScanContext, blob: Blob, item: ItemResult, col: Collector, depth: int) -> None:
    item.kind = "git の pack（履歴の中身）"
    path = ctx.blob_as_path(blob, ".pack")
    reader = PackReader(path)
    try:
        _scan_pack(ctx, reader, blob, item, col, depth)
    finally:
        reader.close()


def _scan_pack(ctx: ScanContext, reader: PackReader, blob: Blob, item: ItemResult, col: Collector, depth: int) -> None:
    n = len(reader.entries)
    types: list[int | None] = [None] * n
    shas: list[bytes | None] = [None] * n
    trees: dict[bytes, list[tuple[str, str, bytes]]] = {}
    roots: list[bytes] = []
    problems: list[str] = []
    pending = list(range(n))
    # 1) 全オブジェクトを戻して種類と SHA-1 を求める。REF_DELTA の元が後ろにあるときのため、進まなくなるまで繰り返す
    while pending:
        left = []
        for i in pending:
            try:
                otype, data = reader.resolve(i)
            except _MissingBase:
                left.append(i)
                continue
            except _TooBig as e:
                problems.append(f"{e.size:,} バイトのオブジェクト")
                continue
            except (zlib.error, ValueError, IndexError) as e:
                problems.append(f"壊れたオブジェクト（{e}）")
                continue
            types[i] = otype
            sha = _object_sha(otype, data)
            shas[i] = sha
            reader.by_sha[sha] = i
            if otype == 2:
                try:
                    trees[sha] = list(parse_tree(data))
                except ValueError:
                    problems.append("読めない tree")
            elif otype == 1:
                m = re.match(rb"tree ([0-9a-f]{40})", data)
                if m:
                    roots.append(bytes.fromhex(m.group(1).decode()))
        if len(left) == len(pending):
            problems.append(f"差分の元が pack の中に無いオブジェクト {len(left)} 件")
            break
        pending = left

    # 2) commit → tree をたどって blob のパス名を求める（たどれない tree は名前だけで）
    names: dict[bytes, str] = {}
    seen: set[bytes] = set()

    def walk(tree_sha: bytes, prefix: str) -> None:
        stack = [(tree_sha, prefix)]
        while stack:
            t, pre = stack.pop()
            if t in seen or t not in trees:
                continue
            seen.add(t)
            for name, mode, child in trees[t]:
                p = f"{pre}{name}"
                if mode.startswith("4") or mode == "40000":
                    stack.append((child, p + "/"))
                else:
                    names.setdefault(child, p)

    for r in roots:
        walk(r, "")
    for t in list(trees):
        walk(t, "…/")

    # 3) 中身を検査する（commit・tag は作者とメッセージ、tree はファイル名、blob は中身）
    counts = {"commit": 0, "tree": 0, "blob": 0, "tag": 0}
    for i in range(n):
        if types[i] is None:
            continue
        otype = TYPE_NAMES[types[i]]
        counts[otype] += 1
        try:
            _, data = reader.resolve(i)
        except (_MissingBase, _TooBig, zlib.error, ValueError, IndexError):
            continue
        name = names.get(shas[i], "") if otype == "blob" else ""
        if otype == "blob" and not name:
            name = f"（blob {shas[i].hex()[:12]}）"
        _scan_object(ctx, col, blob.display, otype, data, depth, name)
    item.method = (
        f"全オブジェクト {n} 件を展開（commit {counts['commit']}・tree {counts['tree']}・"
        f"blob {counts['blob']}・tag {counts['tag']}）"
    )
    if problems:
        # 中身を読めずに飛ばしたオブジェクトがある。読めた分の検出は残したまま、言い切りを妨げる「検査不能」にする
        raise Uncheckable("git の pack の一部のオブジェクトを読めず、中身を検査していない: " + "、".join(problems[:5]))

"""大きな zip の中を「区切り」に分けて、複数のワーカーへ並べて検査する（S4）。

背景: ドライブ全体の検査（約50万件・5時間・ワーカー4本）の最後の約1時間は、7.8GB の zip 1件（直下 6.8万項目）だけが
1本のワーカーで動いていた。ファイル単位で配る形を保ったまま、大きな zip だけ中の項目の並びを区切りに分けて別々に配る。

流れ:
1. 配る側（runner）が、大きな zip に一時フォルダ（持ち主の目印つき）と分けてよいという指示（SplitPolicy）を付けて配る。
2. ワーカーの scan_file が写しを作り、zip の目次だけを読む。分けると決めたら、中身は検査せずに計画（SplitPlan）を返す。
   分けないと決めたら、今までどおりそのまま全部を検査する。
3. 配る側が計画を受けて、区切りごとの仕事（PartSpec）を、同時に動かす本数を絞って配る。
4. 区切りの仕事（scan_part）は、写しから自分の範囲の項目だけを検査して PartResult を返す。
5. 全部の区切りが戻ったら、配る側が項目を並びの順に連ねて、親1件の FileResult にして保存する（assemble）。

見落としを出さないための決まり:
- 分けるのは、実ファイルが大きな（runner.BIG_FILE_BYTES 以上の）、Python の zipfile で読める zip だけ。暗号化・7-Zip を通す
  もの・分割アーカイブ・隠しストリームを持つもの・FTP・ネットワークの道は分けない（今の経路のまま）。
- 展開の合計・項目数の上限は、目次の合計で先に確かめて超えれば分けない（今と同じ所で打ち切る）。内側の書庫の分は
  区切りごとに数えて合計し、超えたら今と同じ理由で親を打ち切りにする。
- 区切りが落ちたら、その区切りの項目だけを検査不能（途中経過があれば途中まで）にし、ほかの区切りの結果は残す。
- ファイル全体の異なる値の数は、区切りが返す（種類 → 値の hash → 確度の順位）を、親で合わせて数える。hash は
  プロセスをまたいで同じになる engine.stable_hash。
"""

from __future__ import annotations

import os
import tempfile
import time
import zipfile
from array import array
from collections import deque
from dataclasses import dataclass, field

from . import engine
from .models import FileResult, ItemResult, PasswordBook, ScanOptions, Status


@dataclass
class SplitPolicy:
    """配る側がワーカーへ渡す「分けてよい」という指示（値は runner の ARCHIVE_SPLIT_* から決める）。"""

    min_entries: int  # 項目数がこれ未満なら分けない
    part_bytes: int  # 区切りの展開後の大きさの目安
    part_entries: int  # 区切りの項目数の上限
    parallel: int  # 1ファイルあたり同時に動かす区切りの本数（空きの見込みに使う）


@dataclass
class SplitPlan:
    """ワーカーが返す「分ける」という計画（最上位の項目までは検査済み）。"""

    top_path: str
    entries: list  # [(zip の中の名前, 展開後の大きさ)]（目次のディレクトリを除いた並び）
    parts: list  # [(始まりの番号, 終わりの番号（含まない）, 展開後の大きさの合計)]
    torch_dirs: list  # 目次から求めた PyTorch の保存形式の根（区切りへそのまま渡す）
    space_extra: int  # 同時に動く別の区切りが一時フォルダの空きを取り合う分の見込み
    local_zip: str = ""  # 写しのパス（一時フォルダの中）
    tmp_dir: str = ""
    source: dict | None = None  # 元のファイルの識別情報と SHA-256
    top_item: ItemResult | None = None
    top_distinct: dict = field(default_factory=dict)
    elapsed: float = 0.0


@dataclass
class PartSpec:
    """区切り1つの仕事の指示。"""

    index: int
    top_path: str
    local_zip: str
    start: int
    end: int
    n_entries: int  # 目次の項目数（開き直して食い違っていれば区切りを検査しない）
    torch_dirs: list
    space_extra: int


@dataclass
class PartResult:
    """区切り1つの結果。失敗した区切り（failed）は、項目を検査不能にして親が作る。"""

    index: int
    items: list
    packed: dict  # 種類 → (hash の array('q'), 確度の順位の array('b'))
    expanded_bytes: int = 0
    entries: int = 0
    abort: str = ""  # 展開の上限などで区切りの途中から打ち切った理由（親を検査不能にする）
    elapsed: float = 0.0
    failed: bool = False
    reason: str = ""  # 落ちた区切り（failed）の理由（時間切れ・メモリ・異常終了など）
    where: str = ""  # 落ちた区切りの場所（「区切り 2/4（11〜20件目）」）


# ------------------------------------------------------------------ 分けるかの判断（ワーカー側）


def may_split(path: str, options: ScanOptions) -> bool:
    """このファイルは分けてよい種類か（中身は読まない）。zip の目次の中身の確かめは plan_zip_split がする。"""
    from .remote import is_ftp_path

    if options.reveal or options.collect_positions:
        return False  # 値の読み直し・位置集めは1本の経路のまま
    if not path.lower().endswith(".zip") or is_ftp_path(path):
        return False
    if path.startswith("\\\\") or path.startswith("//"):
        return False  # ネットワークの道は今の経路のまま
    try:
        if engine.depends_on_neighbors(path):
            return False  # 分割アーカイブ（続きのファイルも読む）
        if engine.alternate_streams(path):
            return False  # 隠しストリームは今の経路で別項目として検査する
    except OSError:
        return False
    return True


def make_parts(sizes: list[int], part_bytes: int, part_entries: int) -> list[tuple[int, int, int]]:
    """項目の展開後の大きさの並びを、順を保ったまま区切りに分ける。[(始まり, 終わり（含まない）, 大きさの合計)]。

    約 part_bytes か part_entries 項目のどちらか先に届いた所で切る。1項目だけで part_bytes を超えるものは1区切りにする。
    """
    parts: list[tuple[int, int, int]] = []
    start = 0
    acc = 0
    for i, size in enumerate(sizes):
        if i > start and acc + size > part_bytes:
            parts.append((start, i, acc))
            start, acc = i, 0
        acc += size
        if i + 1 - start >= part_entries or acc >= part_bytes:
            parts.append((start, i + 1, acc))
            start, acc = i + 1, 0
    if start < len(sizes):
        parts.append((start, len(sizes), acc))
    return parts


def plan_zip_split(ctx, infos, torch_dirs: set[str]) -> SplitPlan | None:
    """目次（infos）から区切りの計画を作る。分けない（今の経路で全部を検査する）ときは None。

    分けない条件: 項目数が少ない・目次の合計が展開の上限（max_expand_bytes・max_entries）を超える（今と同じ所で打ち切る）・
    区切りが2つ未満。
    """
    from .formats.archive import _fix_zip_name, _is_torch_tensor

    pol = ctx.split_policy
    opts = ctx.options
    n = len(infos)
    if n < pol.min_entries or n > opts.max_entries:
        return None
    if sum(i.file_size for i in infos) > opts.max_expand_bytes:
        return None
    sizes = [0 if (torch_dirs and _is_torch_tensor(i, torch_dirs)) else i.file_size for i in infos]
    parts = make_parts(sizes, pol.part_bytes, pol.part_entries)
    if len(parts) < 2:
        return None
    # 一時フォルダへ書き出すほど大きな項目（engine.IN_MEMORY_LIMIT 超）は、同時に動く別の区切りも取り合う
    biggest = max((s for s in sizes if s > engine.IN_MEMORY_LIMIT), default=0)
    return SplitPlan(
        top_path=ctx.top_path,
        entries=[(_fix_zip_name(i), i.file_size) for i in infos],
        parts=parts,
        torch_dirs=sorted(torch_dirs),
        space_extra=biggest * max(0, pol.parallel - 1),
    )


def finish_plan(ctx, top: ItemResult, source: dict | None, local: str | None, elapsed: float) -> SplitPlan:
    """handle_zip が決めた計画に、最上位の項目・写しのパス・識別情報を足して返す（scan_file の終わり）。"""
    plan: SplitPlan = ctx.split_plan
    plan.local_zip = local or ""
    plan.tmp_dir = ctx.tmpdir
    plan.source = source
    plan.top_item = top
    plan.top_distinct = pack_distinct(ctx.distinct)
    plan.elapsed = elapsed
    return plan


# ------------------------------------------------------------------ 異なる値の受け渡し・合わせ方


def pack_distinct(distinct: dict[str, dict[int, int]]) -> dict[str, tuple[array, array]]:
    """種類 → {hash → 確度の順位} を、種類ごとの2つの配列にする（辞書のまま返すより小さい: 異なる値 100 万で約 9MB）。"""
    return {t: (array("q", d.keys()), array("b", d.values())) for t, d in distinct.items() if d}


def merge_distinct(sink: dict[str, dict[int, int]], packed: dict[str, tuple[array, array]]) -> None:
    """区切りが返した異なる値を、親の集計 sink へ足す（Collector._count_distinct が項目ごとに sink へ足すのと同じ決まり）。

    上限は engine.SEEN_LIMIT。上限に届いた後は、新しい値は足さず、既にある値の確度だけ上げ続ける。
    """
    size = sum(len(v) for v in sink.values())
    limit = engine.SEEN_LIMIT
    for pii_type, (hashes, ranks) in packed.items():
        dest = sink.setdefault(pii_type, {})
        for dhash, rank in zip(hashes, ranks):
            old = dest.get(dhash)
            if old is None:
                if rank > 0 and size < limit:
                    dest[dhash] = rank
                    size += 1
            elif old < rank:
                dest[dhash] = rank


# ------------------------------------------------------------------ 区切りの仕事（ワーカー側）


def scan_part(spec: PartSpec, options: ScanOptions, passwords: PasswordBook | None = None) -> PartResult:
    """写しから、区切り1つ（項目の番号の範囲）の項目を検査する。ワーカープロセスで動く。

    内側の書庫の再帰・時間制限・途中経過（checkpoint）は区切りごと。途中経過の書き出し先は区切りの番号で分ける。
    """
    from .formats.archive import scan_zip_entries

    started = time.time()
    book = passwords or PasswordBook()
    ctx = engine.ScanContext(spec.top_path, options, book.candidates_for(spec.top_path))
    ctx.checkpoint_file = engine.checkpoint_path(options, spec.top_path, part=spec.index)
    try:
        os.remove(ctx.checkpoint_file)  # 前の検査が残した途中経過を、今回の分として読ませない
    except OSError:
        pass
    ctx.space_extra = spec.space_extra
    abort = ""
    try:
        with open(engine.long_path(spec.local_zip), "rb") as f, zipfile.ZipFile(f) as z:
            infos = [i for i in z.infolist() if not i.is_dir()]
            if len(infos) != spec.n_entries:
                raise ValueError(f"写しの zip の目次が計画と食い違った（{len(infos)}件・計画は {spec.n_entries}件）")
            try:
                scan_zip_entries(ctx, spec.top_path, z, infos[spec.start : spec.end], set(spec.torch_dirs), 0)
            except engine.Uncheckable as e:
                abort = str(e)  # 展開の上限・一時フォルダの空き不足など: 親を打ち切りにする（ここまでの項目は残す）
    finally:
        ctx.cleanup()
        for p in (ctx.checkpoint_file, ctx.checkpoint_file + ".tmp") if ctx.checkpoint_written else ():
            try:
                os.remove(p)
            except OSError:
                pass
    return PartResult(
        index=spec.index,
        items=ctx.items,
        packed=pack_distinct(ctx.distinct),
        expanded_bytes=ctx.expanded_bytes,
        entries=ctx.entries,
        abort=abort,
        elapsed=time.time() - started,
    )


# ------------------------------------------------------------------ 親1件にまとめる（配る側）


def failed_part(plan: SplitPlan, idx: int, reason: str, partial: list | None, elapsed: float = 0.0) -> PartResult:
    """区切りが落ちた（時間切れ・異常終了・想定外のエラー）ときの結果。その区切りの項目だけを検査不能にする。

    partial は区切りが途中まで書き出した項目（あれば検出を残す）。途中経過に無い項目は、理由つきの検査不能で並べる
    （黙って落とさない）。
    """
    start, end, _ = plan.parts[idx]
    where = f"区切り {idx + 1}/{len(plan.parts)}（{start + 1}〜{end}件目）"
    items: list[ItemResult] = []
    covered = 0
    for it in partial or []:
        if it.status == Status.PENDING:
            it.status = Status.UNCHECKABLE
            it.reason = f"{where}の途中で打ち切られたため、途中までしか検査していない"
        if it.depth == 1:
            covered += 1  # 区切りの直下の項目は、1項目につき1件ちょうど（入れ子は depth 2 以上）
        items.append(it)
    for name, size in plan.entries[start + covered : end]:
        items.append(
            ItemResult(
                path=f"{plan.top_path}!{name}",
                kind="",
                status=Status.UNCHECKABLE,
                reason=f"{where}を検査できなかった。{reason}",
                depth=1,
                size=size,
            )
        )
    return PartResult(index=idx, items=items, packed={}, elapsed=elapsed, failed=True, reason=reason, where=where)


def assemble(plan: SplitPlan, outcomes: dict[int, PartResult], options: ScanOptions) -> FileResult:
    """区切りの結果を、分けないときと同じ並びの親1件の FileResult にする。

    項目は最上位 → 区切りの番号の順に連ねる（項目のパスと並びは分けないときと同じ）。ファイル全体の異なる値は、区切りの順に
    合わせてから最後に最上位の分を足す（分けないときは最上位の項目が最後に終わるので、その順にそろえる）。
    内側の書庫を含む展開の合計・項目数が上限を超えたら、分けないときと同じ理由で親を打ち切りにする。
    """
    top = plan.top_item
    items: list[ItemResult] = [top]
    sink: dict[str, dict[int, int]] = {}
    expanded = entries = 0
    abort = ""
    failed: list[PartResult] = []
    elapsed = plan.elapsed
    for idx in sorted(outcomes):
        oc = outcomes[idx]
        items.extend(oc.items)
        merge_distinct(sink, oc.packed)
        expanded += oc.expanded_bytes
        entries += oc.entries
        elapsed += oc.elapsed
        abort = abort or oc.abort
        if oc.failed:
            failed.append(oc)
    merge_distinct(sink, plan.top_distinct)
    if not abort and expanded > options.max_expand_bytes:
        abort = engine.expand_limit_reason(options)
    if not abort and entries > options.max_entries:
        abort = engine.entries_limit_reason(options)
    if failed:
        # 分けない経路の save_failure と同じく、最上位も検査不能にして理由を残す（落ちた区切りの項目は検査不能、
        # それ以外の区切りの結果は残っている）。どの区切りが落ちたかが分かる文にする
        n_lost = sum(plan.parts[oc.index][1] - plan.parts[oc.index][0] for oc in failed)
        shown = "、".join(f"{oc.where}: {oc.reason}" for oc in failed[:3])
        more = f"（ほか {len(failed) - 3} 区切り）" if len(failed) > 3 else ""
        text = (
            f"全 {len(plan.entries):,} 項目のうち {n_lost:,} 項目（{len(failed)} 区切り）を検査できなかった。{shown}{more}。"
            "ほかの区切りは検査できていて、その結果は残してある"
        )
        abort = f"{abort} {text}" if abort else text
    if abort:
        top.status = Status.UNCHECKABLE
        top.reason = abort
    return FileResult(
        top_path=plan.top_path,
        items=items,
        elapsed=elapsed,
        source=plan.source,
        distinct_counts=engine._count_by_rank(sink),
    )


# ------------------------------------------------------------------ 配る側の持ち物


class SharedTemp:
    """配る側が先に作る一時フォルダ（大きな zip の写しと、区切りの仕事が使う場所）。

    持ち主の目印（engine.OWNER_MARK）を配る側が開いたままにするので、後始末の掃除（runner.cleanup_stale_temp）は
    目印を消せず、使用中として消さない。release で閉じて消す（最後の区切りが戻ったとき・停止・失敗のとき）。
    """

    def __init__(self, base: str | None):
        self.path = tempfile.mkdtemp(prefix=engine.TEMP_PREFIX, dir=base or None)
        self._owner = open(os.path.join(self.path, engine.OWNER_MARK), "wb")

    def release(self) -> None:
        from . import safeio

        if self._owner is not None:
            self._owner.close()
            self._owner = None
        safeio.remove_tree(self.path)


class SplitRun:
    """分けると決まった親1件の、区切りの配り方と結果の集まり（配る側のスレッドだけが使う）。"""

    def __init__(self, plan: SplitPlan, path: str, version: int, started: float, tmp: SharedTemp | None, parallel: int):
        self.plan = plan
        self.path = path
        self.version = version  # 配ったときのパスワードの版
        self.started = started
        self.tmp = tmp
        self.parallel = max(1, parallel)
        # 大きな区切りから配る。1項目だけで大きい区切りが最後に回ると、それだけが1本で走る尾になる
        # （7.8GB の zip で 1.5GB の1項目の区切りが最後に配られ、壁の時間の約半分を1本で走っていた）。
        # 結果は番号の順に連ねるので、全部の区切りが戻れば配る順は結果を変えない（展開の上限などで途中から
        # 配るのをやめたときは親は打ち切りのままで、中に残る項目の範囲だけが変わる）
        order = sorted(range(len(plan.parts)), key=lambda i: -plan.parts[i][2])
        self.queue: deque[int] = deque(order)
        self.running: set[int] = set()
        self.outcomes: dict[int, PartResult] = {}
        self._expanded = 0
        self._entries = 0
        self.stopped = False  # 展開の合計が上限を超えたので、残りの区切りを配らない
        self.aborted = False  # 保存先の満杯などで検査そのものを止めた（親は保存せず、再開でやり直す）

    def take(self) -> int | None:
        """次に配る区切りの番号（同時の本数の上限・取りやめを守る）。無ければ None。"""
        if self.stopped or not self.queue or len(self.running) >= self.parallel:
            return None
        idx = self.queue.popleft()
        self.running.add(idx)
        return idx

    def record(self, idx: int, result: PartResult, options: ScanOptions) -> None:
        self.running.discard(idx)
        self.outcomes[idx] = result
        self._expanded += result.expanded_bytes
        self._entries += result.entries
        if result.abort or self._expanded > options.max_expand_bytes or self._entries > options.max_entries:
            self.stopped = True  # 親は打ち切りになる。残りの区切りは配らない

    @property
    def finished(self) -> bool:
        return not self.running and (self.stopped or not self.queue)

    def release(self) -> None:
        if self.tmp is not None:
            try:
                self.tmp.release()
            except Exception:  # noqa: BLE001  消せなかった分は次の後始末の掃除が消す（目印は閉じてある）
                pass
            self.tmp = None

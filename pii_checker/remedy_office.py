"""docx・pptx の対処（ダミー化・段落／表の行・列／スライドの削除）。

決まり:
- zip の中の XML を直接書き換える。書き換えた部品以外（画像・スタイル・埋め込みなど）は、圧縮したままのデータをバイト単位で
  そのまま写す（archive_write の zip の写し方と同じ。日時・圧縮方式・並び順・コメントも保つ）。
- 位置は検査のときに集めたもの（formats/office.py）: シートは部品名（pptx は「スライドN:部品名」）、行は段落の通し番号（root.iter の順）、
  開始・終了はその段落の文字（NFKC で正規化したもの）の範囲。表のセルの検出も段落ごとの範囲になっている。生の値は持たないので、
  書き換えるときに段落の文字を読み直して置き換える。
- ダミー化は、段落の文字を run（w:r・a:r）をまたいで見て、値の部分だけを置き換える。置き換えた文字は、値の最初の文字を持つ run
  （書式はその run）に置き、値が複数の run に割れていれば、残りの run からは値の分を取り除く。
- 変更履歴の削除文字列（w:delText）・フィールドの命令（w:instrText）も、検査と同じく段落の文字として扱う（元の値が履歴に残らない）。
- 書き換えのあと、文書のプロパティ（docProps）・属性値・グラフやスマートアートなど、段落の外に残った値も取り除き、
  文書の縮小画像（サムネイル）は取り除く（元の画面が写っているため）。
- 元のファイルには書かない。結果は別のファイル（一時の名前）へ書き、呼び出し側が確定する。
"""

from __future__ import annotations

import copy
import html
import io
import os
import re
import zipfile
from urllib.parse import quote

from . import detectors
from .ooxml_text import (
    A,
    DOCX_EXTRA_RE,
    DOCX_MAIN,
    P,
    REL,
    W,
    XML_SPACE,
    atom_text,
    docx_atoms,
    pptx_atoms,
    pptx_paragraphs,
    pptx_slide_parts,
    rels_name,
    resolve_target,
    split_pptx_sheet,
)
from .remedy_common import MIN_VALUE_LEN, Residue
from .remedy_write import DummyMaker, RemedyError, Selection, _orig_bounds

PART_LIMIT = 256 * 1024**2  # 木として読んでよい部品の大きさ
RE_XML_BAD = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f]")
THUMBNAIL_REL = "/thumbnail"
RE_SLIDE_LABEL = re.compile(r"^スライド(\d+)")
RE_PPTX_PARAGRAPH_PART = re.compile(r"^ppt/(slides|notesSlides)/[^/]+\.xml$")


# ---------------------------------------------------------------- zip の読み書き


def _long(path: str) -> str:
    from .engine import long_path

    return long_path(path)


def _parser():
    from lxml import etree

    return etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False)


class Package:
    """OOXML の zip。部品を読み、書き換えた部品・取り除いた部品を覚えて、最後にほかの項目をそのまま写して書き出す。"""

    def __init__(self, path: str):
        self.path = path
        try:
            self.zip = zipfile.ZipFile(_long(path))
        except (zipfile.BadZipFile, OSError) as e:
            raise RemedyError(
                f"ファイルを zip として読み取れませんでした（{type(e).__name__}）。元のファイルは変えていません"
            ) from None
        self.infos = {i.filename: i for i in self.zip.infolist()}
        self.names = [n for n, i in self.infos.items() if not i.is_dir()]
        self.trees: dict = {}
        self.standalone: dict[str, bool] = {}
        self.dirty: set[str] = set()
        self.replaced: dict[str, bytes] = {}
        self.removed: set[str] = set()

    def close(self) -> None:
        self.zip.close()

    def has(self, name: str) -> bool:
        return name in self.infos and name not in self.removed

    def read(self, name: str) -> bytes:
        if name in self.removed or name not in self.infos:
            raise KeyError(name)
        if name in self.dirty:
            return self._serialize(name)
        if name in self.replaced:
            return self.replaced[name]
        if self.infos[name].file_size > PART_LIMIT:
            raise RemedyError(f"部品 {name} が大きすぎるため、書き換えられません")
        return self.zip.read(name)

    def tree(self, name: str):
        """部品の XML を木（lxml）として返す（同じ部品は同じ木。touch したものだけ最後に書き戻す）。"""
        if name not in self.trees:
            from lxml import etree

            data = self.read(name)
            try:
                self.trees[name] = etree.fromstring(data, _parser())
            except etree.XMLSyntaxError as e:
                raise RemedyError(
                    f"部品 {name} の XML を読み取れませんでした（{e}）。元のファイルは変えていません"
                ) from None
            self.standalone[name] = b"standalone" in data[:200]
        return self.trees[name]

    def touch(self, name: str) -> None:
        self.dirty.add(name)

    def remove(self, name: str) -> None:
        self.removed.add(name)
        self.trees.pop(name, None)
        self.dirty.discard(name)
        self.replaced.pop(name, None)

    def set_bytes(self, name: str, data: bytes) -> None:
        self.replaced[name] = data
        self.trees.pop(name, None)
        self.dirty.discard(name)

    def _serialize(self, name: str) -> bytes:
        from lxml import etree

        kw = {"standalone": True} if self.standalone.get(name) else {}
        return etree.tostring(self.trees[name], xml_declaration=True, encoding="UTF-8", **kw)

    def flush_trees(self) -> None:
        for name in sorted(self.dirty):
            self.replaced[name] = self._serialize(name)
        self.dirty.clear()

    def write(self, dst: str) -> None:
        self.flush_trees()
        rewrite_zip(self.path, dst, self.replaced, self.removed)


def rewrite_zip(src: str, dst: str, replaced: dict[str, bytes], removed: set[str]) -> None:
    """zip の項目のうち、replaced の部品は新しい中身で入れ直し、removed の部品は除き、ほかは圧縮済みのデータをそのまま写す。"""
    from .archive_write import _central_record, _copy_entry, _had_zip64_end, _write_end

    with zipfile.ZipFile(_long(src)) as z:
        infos = list(z.infolist())
        comment = z.comment
    if infos and min(i.header_offset for i in infos) != 0:
        raise RemedyError("zip の先頭に余分なデータがあるため、書き換えられません")
    force64 = _had_zip64_end(_long(src))
    with open(_long(src), "rb") as s, open(_long(dst), "wb") as out:
        records: list[bytes] = []
        for info in infos:
            if info.filename in removed:
                continue
            offset = out.tell()
            utf8 = bool(info.flag_bits & 0x800)
            name_bytes = info.orig_filename.encode("utf-8" if utf8 else "cp437")
            if info.filename in replaced:
                new_info, buf = _new_entry(info, replaced[info.filename])
                flag = (new_info.flag_bits & ~0x800) | (info.flag_bits & 0x800)
                _copy_entry(out, buf, new_info, name_bytes, utf8)
                hybrid = copy.copy(new_info)
                hybrid.create_system = info.create_system
                hybrid.external_attr = info.external_attr
                hybrid.internal_attr = info.internal_attr
                hybrid.comment = info.comment
                records.append(_central_record(hybrid, name_bytes, flag, offset))
            else:
                _copy_entry(out, s, info)
                records.append(_central_record(info, name_bytes, info.flag_bits, offset))
        cd_start = out.tell()
        for rec in records:
            out.write(rec)
        _write_end(out, len(records), cd_start, out.tell() - cd_start, comment, force64)
        out.flush()
        os.fsync(out.fileno())


def _new_entry(info: zipfile.ZipInfo, data: bytes):
    """新しい中身を、元の項目と同じ日時・圧縮方式（deflate か無圧縮）の zip の項目にして（ZipInfo, 読み出し元）を返す。"""
    zi = zipfile.ZipInfo("x", date_time=info.date_time)
    zi.compress_type = info.compress_type if info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED) else 8
    zi.external_attr = info.external_attr
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as tz:
        tz.writestr(zi, data)
    buf.seek(0)
    with zipfile.ZipFile(buf) as tz:
        made = tz.infolist()[0]
    buf.seek(0)
    return made, buf


# ---------------------------------------------------------------- 段落の書き換え


def orig_spans(text: str, spans: list[tuple[int, int, str]]) -> list[tuple[int, int, str]]:
    """段落の（正規化後の）文字の範囲を、元の文字の範囲にして、重なりをまとめる。直せないときは段落全体（安全側）。"""
    norm = detectors.normalize(text)
    clipped = sorted((s, min(e, len(norm)), t) for s, e, t in spans if 0 <= s < min(e, len(norm)))
    if not clipped:
        return []
    bounds = _orig_bounds(text, norm)
    if bounds is None:
        return [(0, len(text), clipped[0][2])]
    mapped = [(*bounds(s, e), t) for s, e, t in clipped]
    merged: list[list] = []
    for s, e, t in sorted(mapped):
        if merged and s < merged[-1][1]:
            if e - s > merged[-1][1] - merged[-1][0]:
                merged[-1][2] = t
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e, t])
    return [(s, e, t) for s, e, t in merged]


def _xml_text(text: str) -> str:
    return RE_XML_BAD.sub("", text)


def apply_edits(atoms: list, edits: list[tuple[int, int, str]], text_tag: str, wrap_run: str | None) -> None:
    """段落の文字の部品（要素, 種類）に、置き換え（開始, 終了, 新しい文字）を当てる。開始・終了は段落全体の文字の位置。

    値の最初の文字を持つ文字要素に新しい文字を置き、続く文字要素からは値の分を取り除く。tab・br の上から始まる値は、
    その前に新しい文字要素（pptx は run ごと）を置く。
    """
    from lxml import etree

    spans = []
    pos = 0
    for el, kind in atoms:
        n = len(atom_text(el, kind))
        spans.append((pos, pos + n))
        pos += n
    for s, e, new in sorted(edits, reverse=True):
        new = _xml_text(new)
        placed = False
        for (el, kind), (a0, a1) in zip(atoms, spans):
            if a1 <= s or a0 >= e:
                continue
            if kind == "t":
                cur = el.text or ""
                lo, hi = max(s, a0) - a0, min(e, a1) - a0
                el.text = cur[:lo] + (new if not placed else "") + cur[hi:]
                el.set(XML_SPACE, "preserve")
                placed = True
                continue
            parent = el.getparent()
            if not placed:
                t = etree.Element(text_tag)
                t.text = new
                t.set(XML_SPACE, "preserve")
                if wrap_run:
                    run = etree.Element(wrap_run)
                    run.append(t)
                    el.addprevious(run)
                else:
                    el.addprevious(t)
                placed = True
            parent.remove(el)


def empty_paragraph(p, pr_tag: str) -> None:
    """段落の中身（文字・run・リンクなど）を空にする。段落の書式（pPr）は残す。"""
    for ch in list(p):
        if ch.tag != pr_tag:
            p.remove(ch)


class Edited:
    """書き換えの記録（件数と、取り除いた値。値は residue の判定と、段落の外の掃除にだけ使い、保存しない）。"""

    def __init__(self) -> None:
        self.stats: dict[str, int] = {}
        self.known: dict[str, str] = {}  # 消した値（元の文字・正規化した文字）→ 段落の外での置き換え先
        self.values: set[str] = set()

    def count(self, key: str, n: int = 1) -> None:
        self.stats[key] = self.stats.get(key, 0) + n

    def learn(self, value: str, repl: str) -> None:
        for v in {value, detectors.normalize(value)}:
            if len(v) >= MIN_VALUE_LEN:
                self.known.setdefault(v, repl)
                self.values.add(detectors.normalize(v))


def dummy_paragraph(p, atoms_fn, text_tag, wrap_run, pr_tag, spans, maker: DummyMaker, edited: Edited) -> bool:
    """1つの段落の検出した値をダミーに置き換える。変わったら True。"""
    atoms = atoms_fn(p)
    text = "".join(atom_text(el, k) for el, k in atoms)
    merged = orig_spans(text, spans)
    edits = []
    for s, e, t in merged:
        piece = text[s:e]
        repl = maker.make(t, detectors.normalize(piece))
        if repl == piece:
            continue
        edits.append((s, e, repl))
        edited.learn(piece, repl)
    if not edits:
        return False
    apply_edits(atoms, edits, text_tag, wrap_run)
    edited.count("cells")
    edited.count("detections", len(edits))
    return True


def _spans_by_para(sel: Selection) -> dict[str, dict[int, list[tuple[int, int, str]]]]:
    """選んだ位置を {シート: {段落の通し番号: [(開始, 終了, 種類)]}} にする。"""
    out: dict[str, dict[int, list]] = {}
    for (sheet, pii_type, _rank), arr in sel.groups.items():
        paras = out.setdefault(sheet, {})
        for i in range(0, len(arr), 4):
            paras.setdefault(arr[i], []).append((arr[i + 2], arr[i + 3], pii_type))
    return out


# ---------------------------------------------------------------- docx の段落・表


def _ancestor(el, tag: str):
    cur = el.getparent()
    while cur is not None:
        if cur.tag == tag:
            return cur
        cur = cur.getparent()
    return None


KEEP_ONE_PARAGRAPH = (W + "tc", W + "txbxContent", W + "hdr", W + "ftr", W + "footnote", W + "endnote", W + "comment")


def remove_paragraph(p) -> None:
    """段落を取り除く。セル・テキストボックス・脚注など、段落が1つは要る入れ物の最後の段落と、節の区切りを持つ段落は、中身だけ空にする。"""
    parent = p.getparent()
    ppr = p.find(W + "pPr")
    has_section = ppr is not None and ppr.find(W + "sectPr") is not None
    others = [c for c in parent if c.tag == W + "p" and c is not p]
    if has_section or (parent.tag in KEEP_ONE_PARAGRAPH and not others):
        empty_paragraph(p, W + "pPr")
        return
    parent.remove(p)


def fix_cell(cell) -> None:
    """表を取り除いたあと、セルの最後が段落でなければ空の段落を足す（セルは段落で終わる決まり）。"""
    if cell is None or cell.tag != W + "tc":
        return
    last = [c for c in cell if isinstance(c.tag, str) and c.tag != W + "tcPr"]
    if not last or last[-1].tag != W + "p":
        from lxml import etree

        etree.SubElement(cell, W + "p")


def remove_row(tr) -> None:
    tbl = tr.getparent()
    tbl.remove(tr)
    if not any(c.tag == W + "tr" for c in tbl):
        remove_table(tbl)


def remove_table(tbl) -> None:
    parent = tbl.getparent()
    parent.remove(tbl)
    fix_cell(parent)


def _int_val(el, default: int = 1) -> int:
    try:
        return int(el.get(W + "val")) if el is not None else default
    except (TypeError, ValueError):
        return default


def cell_span(tc) -> int:
    pr = tc.find(W + "tcPr")
    return max(1, _int_val(pr.find(W + "gridSpan") if pr is not None else None))


def grid_start(tr, target) -> int:
    """行の中でセルが始まる、表の格子の列（0 始まり。行頭の空きの格子 gridBefore を数える）。"""
    pr = tr.find(W + "trPr")
    before = pr.find(W + "gridBefore") if pr is not None else None
    col = _int_val(before, 0) if before is not None else 0
    for tc in tr:
        if tc.tag != W + "tc":
            continue
        if tc is target:
            return col
        col += cell_span(tc)
    raise RemedyError("表のセルの位置を求められませんでした")


def delete_grid_column(tbl, g: int) -> None:
    """表の格子の列 g を、全部の行から取り除く（結合したセルは幅を1つ減らす）。"""
    for tr in [c for c in tbl if c.tag == W + "tr"]:
        pr = tr.find(W + "trPr")
        before = pr.find(W + "gridBefore") if pr is not None else None
        nb = _int_val(before, 0) if before is not None else 0
        col = nb
        if g < nb:
            before.set(W + "val", str(nb - 1))
        else:
            hit = False
            for tc in [c for c in tr if c.tag == W + "tc"]:
                span = cell_span(tc)
                if col <= g < col + span:
                    if span == 1:
                        tr.remove(tc)
                    else:
                        tc.find(W + "tcPr").find(W + "gridSpan").set(W + "val", str(span - 1))
                    hit = True
                    break
                col += span
            if not hit and pr is not None:
                after = pr.find(W + "gridAfter")
                if after is not None and _int_val(after, 0) > 0:
                    after.set(W + "val", str(_int_val(after, 0) - 1))
        if not any(c.tag == W + "tc" for c in tr):
            tbl.remove(tr)
    grid = tbl.find(W + "tblGrid")
    if grid is not None:
        cols = [c for c in grid if c.tag == W + "gridCol"]
        if g < len(cols):
            grid.remove(cols[g])
    if not any(c.tag == W + "tr" for c in tbl):
        remove_table(tbl)


def rewrite_docx_package(
    pkg: Package, method: str, sel: Selection, maker: DummyMaker | None, edited: Edited
) -> dict[str, set]:
    """段落・表の書き換え。書き換えた部品の名前の集まり {"paragraph_parts": …} を返す。"""
    by_part = _spans_by_para(sel)
    parts = {}
    for part in by_part:
        if not (part == DOCX_MAIN or DOCX_EXTRA_RE.match(part)) or not pkg.has(part):
            raise RemedyError("文書の位置が検査と食い違います（ファイルが変わった可能性。検査し直してください）")
        parts[part] = pkg.tree(part)
    deleted_rows: list = []
    deleted_cols: dict = {}  # 表の要素 → 格子の列の集合
    deleted_paras: list = []
    outside_table = 0
    for part, paras_spans in by_part.items():
        root = parts[part]
        paras = list(root.iter(W + "p"))
        for idx, spans in sorted(paras_spans.items()):
            if not 1 <= idx <= len(paras):
                raise RemedyError(
                    "文書の段落の位置が検査と食い違います（ファイルが変わった可能性。検査し直してください）"
                )
            p = paras[idx - 1]
            if method == "dummy":
                if dummy_paragraph(p, docx_atoms, W + "t", None, W + "pPr", spans, maker, edited):
                    pkg.touch(part)
                continue
            text = "".join(atom_text(el, k) for el, k in docx_atoms(p))
            for s, e, _t in orig_spans(text, spans):
                edited.learn(text[s:e], "")
            if method == "delete_paragraphs":
                deleted_paras.append((part, p))
            else:
                tc = _ancestor(p, W + "tc")
                if tc is None:
                    outside_table += 1
                    continue
                tr, tbl = tc.getparent(), tc.getparent().getparent()
                if tr is None or tr.tag != W + "tr" or tbl is None or tbl.tag != W + "tbl":
                    outside_table += 1
                    continue
                if method == "delete_rows":
                    deleted_rows.append((part, tr))
                else:
                    if cell_span(tc) > 1:
                        raise RemedyError(
                            "結合したセル（複数の列にまたがるセル）の検出は、列を削除できません。ダミー化か行の削除を選んでください"
                        )
                    deleted_cols.setdefault((part, tbl), set()).add(grid_start(tr, tc))
    if method == "delete_paragraphs":
        seen = set()
        for part, p in deleted_paras:
            if id(p) in seen:
                continue
            seen.add(id(p))
            remove_paragraph(p)
            pkg.touch(part)
            edited.count("paragraphs")
    elif method == "delete_rows":
        seen = set()
        for part, tr in deleted_rows:
            if id(tr) in seen:
                continue
            seen.add(id(tr))
            edited.count("rows")
        for part, tr in deleted_rows:
            if tr.getparent() is not None:
                remove_row(tr)
                pkg.touch(part)
    elif method == "delete_columns":
        for (part, tbl), grids in deleted_cols.items():
            for g in sorted(grids, reverse=True):
                if tbl.getparent() is None:
                    break
                delete_grid_column(tbl, g)
                edited.count("cols")
            pkg.touch(part)
    if outside_table:
        edited.count("outside_table", outside_table)
    return {"paragraph_parts": set(by_part)}


# ---------------------------------------------------------------- pptx

PPTX_RUN_TAG = A + "r"


def rewrite_pptx_package(
    pkg: Package, method: str, sel: Selection, maker: DummyMaker | None, edited: Edited
) -> dict[str, set]:
    by_sheet = _spans_by_para(sel)
    slide_parts = pptx_slide_parts(pkg.read)
    by_number = {no: (part, notes) for no, part, notes in slide_parts}
    touched_slides: set[int] = set()
    paragraph_parts: set[str] = set()
    for sheet, paras_spans in by_sheet.items():
        label, part = split_pptx_sheet(sheet)
        m = RE_SLIDE_LABEL.match(label)
        if not m or not pkg.has(part):
            raise RemedyError("スライドの位置が検査と食い違います（ファイルが変わった可能性。検査し直してください）")
        no = int(m.group(1))
        if no not in by_number or part not in by_number[no]:
            raise RemedyError("スライドの位置が検査と食い違います（ファイルが変わった可能性。検査し直してください）")
        touched_slides.add(no)
        root = pkg.tree(part)
        paragraph_parts.add(part)
        paras = pptx_paragraphs(root)
        for idx, spans in sorted(paras_spans.items()):
            if not 1 <= idx <= len(paras):
                raise RemedyError(
                    "スライドの段落の位置が検査と食い違います（ファイルが変わった可能性。検査し直してください）"
                )
            p = paras[idx - 1][2]
            if method == "dummy":
                if dummy_paragraph(p, pptx_atoms, A + "t", PPTX_RUN_TAG, A + "pPr", spans, maker, edited):
                    pkg.touch(part)
            else:
                text = "".join(atom_text(el, k) for el, k in pptx_atoms(p))
                for s, e, _t in orig_spans(text, spans):
                    edited.learn(text[s:e], "")
    if method == "delete_slides":
        if len(touched_slides) >= len(slide_parts):
            raise RemedyError(
                "すべてのスライドは削除できません（スライドが1つも残らなくなります）。ファイル全体を消すなら「ファイルを削除」を選んでください"
            )
        remove_slides(pkg, [by_number[no][0] for no in sorted(touched_slides)])
        edited.count("slides", len(touched_slides))
    return {"paragraph_parts": paragraph_parts}


def _reachable(pkg: Package) -> set[str]:
    """パッケージの根（_rels/.rels）から関係をたどって届く部品の集まり（木に加えた変更も読む）。"""
    from lxml import etree

    def targets(rels_file: str, base: str) -> list[str]:
        if not pkg.has(rels_file):
            return []
        out = []
        for r in etree.fromstring(pkg.read(rels_file), _parser()).iter(REL + "Relationship"):
            if r.get("TargetMode") != "External":
                out.append(resolve_target(base, r.get("Target") or ""))
        return out

    seen: set[str] = set()
    queue = targets("_rels/.rels", "x")
    while queue:
        part = queue.pop()
        if part in seen or not pkg.has(part):
            continue
        seen.add(part)
        queue.extend(targets(rels_name(part), part))
    return seen


def remove_slides(pkg: Package, slides: list[str]) -> None:
    """スライドを取り除く。プレゼンテーションの一覧・関係・区画（セクション）から外し、ほかから届かなくなった部品（ノート・画像・
    グラフ・埋め込みなど）も、中の値が残らないよう取り除く。ほかのスライドからのリンク（スライドへのジャンプ）は外す。"""
    from lxml import etree

    pres = "ppt/presentation.xml"
    rels_file = rels_name(pres)
    pres_root = pkg.tree(pres)
    rels_root = pkg.tree(rels_file)
    slide_set = set(slides)
    before = _reachable(pkg)
    drop_ids = set()
    for r in list(rels_root.iter(REL + "Relationship")):
        if r.get("TargetMode") != "External" and resolve_target(pres, r.get("Target") or "") in slide_set:
            drop_ids.add(r.get("Id"))
            rels_root.remove(r)
    removed_slide_ids = set()
    for sld in list(pres_root.iter(P + "sldId")):
        rid = sld.get("{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id")
        if rid in drop_ids:
            removed_slide_ids.add(sld.get("id"))
            sld.getparent().remove(sld)
    rid_attr = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id"
    for el in list(pres_root.iter()):  # 区画（セクション）・目的別スライドショーの一覧に残った参照も外す
        if not isinstance(el.tag, str) or el.getparent() is None:
            continue
        local = etree.QName(el).localname
        if (local == "sldId" and el.get("id") in removed_slide_ids) or (
            local == "sld" and el.get(rid_attr) in drop_ids
        ):
            el.getparent().remove(el)
    pkg.touch(pres)
    pkg.touch(rels_file)
    # ほかの部品が、取り除くスライドへ張っている関係（スライドへのジャンプなど）を外す
    for name in list(pkg.names):
        if not name.endswith(".rels") or not pkg.has(name) or name == rels_file:
            continue
        owner = _owner_of_rels(name)
        if owner in slide_set or not pkg.has(owner):
            continue
        rroot = pkg.tree(name)
        gone = set()
        for r in list(rroot.iter(REL + "Relationship")):
            if r.get("TargetMode") != "External" and resolve_target(owner, r.get("Target") or "") in slide_set:
                gone.add(r.get("Id"))
                rroot.remove(r)
        if gone:
            pkg.touch(name)
            _strip_links(pkg, owner, gone)
    dropped = before - _reachable(pkg)
    for part in dropped:
        pkg.remove(part)
        pkg.remove(rels_name(part))
    _drop_content_types(pkg, dropped)
    _fix_app_properties(pkg, len(slides))


def _owner_of_rels(rels: str) -> str:
    """関係ファイルの名前から、持ち主の部品の名前を求める（ppt/slides/_rels/slide1.xml.rels → ppt/slides/slide1.xml）。"""
    folder, leaf = os.path.split(rels.replace("\\", "/"))
    base = leaf[: -len(".rels")]
    parent = os.path.dirname(folder)
    return (parent + "/" + base).lstrip("/") if parent else base


def _strip_links(pkg: Package, owner: str, gone: set[str]) -> None:
    """取り除いた関係（Id）を参照しているリンクの指定（a:hlinkClick など）を、持ち主の部品から外す。"""
    if not pkg.has(owner):
        return
    root = pkg.tree(owner)
    rid_attr = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id"
    changed = False
    for el in list(root.iter()):
        if isinstance(el.tag, str) and el.get(rid_attr) in gone and el.getparent() is not None:
            el.getparent().remove(el)
            changed = True
    if changed:
        pkg.touch(owner)


def _drop_content_types(pkg: Package, dropped: set[str]) -> None:
    ct = "[Content_Types].xml"
    if not pkg.has(ct):
        return
    root = pkg.tree(ct)
    changed = False
    for el in list(root):
        if (
            isinstance(el.tag, str)
            and el.tag.endswith("}Override")
            and (el.get("PartName") or "").lstrip("/") in dropped
        ):
            root.remove(el)
            changed = True
    if changed:
        pkg.touch(ct)


def _fix_app_properties(pkg: Package, removed: int) -> None:
    """docProps/app.xml: スライドの題の一覧（取り除いたスライドの題が残る）を外し、スライド数を合わせる。"""
    name = "docProps/app.xml"
    if not pkg.has(name):
        return
    root = pkg.tree(name)
    changed = False
    for el in list(root):
        local = el.tag.rsplit("}", 1)[-1] if isinstance(el.tag, str) else ""
        if local in ("TitlesOfParts", "HeadingPairs"):
            root.remove(el)
            changed = True
        elif local in ("Slides", "Notes") and (el.text or "").strip().isdigit():
            el.text = str(max(0, int(el.text) - removed))
            changed = True
    if changed:
        pkg.touch(name)


# ---------------------------------------------------------------- 段落の外に残った値の掃除（共通）

RE_PLAIN_NUMBER = re.compile(r"^[0-9\-:TZ+. ]+$")
PROPERTY_PARTS = ("docProps/core.xml", "docProps/app.xml", "docProps/custom.xml")


def _is_xml_part(name: str) -> bool:
    return name.lower().endswith((".xml", ".rels", ".vml"))


def scrub_properties(pkg: Package, residue: Residue, stats: dict) -> None:
    """文書のプロパティ（作成者・題・会社など）の文字が、消した値や選んだ種類・確度の検出を含むなら、その文字を消す。"""
    for name in PROPERTY_PARTS:
        if not pkg.has(name):
            continue
        root = pkg.tree(name)
        n = 0
        for el in root.iter():
            if not (isinstance(el.tag, str) and el.text and el.text.strip()):
                continue
            # 日時・ページ数・文字数など、数字と日時の記号だけの項目は、消した値と一致するときだけ消す（検出の判定で消さない）
            plain = RE_PLAIN_NUMBER.match(el.text.strip())
            if residue.known(el.text) or (not plain and residue.detected(el.text)):
                el.text = ""
                n += 1
        if n:
            pkg.touch(name)
            stats["cleaned_properties"] = stats.get("cleaned_properties", 0) + n


def drop_thumbnail(pkg: Package, stats: dict) -> None:
    """文書の縮小画像（サムネイル。元の画面が写っている）を取り除く。"""
    name = "_rels/.rels"
    if not pkg.has(name):
        return
    root = pkg.tree(name)
    gone = []
    for r in list(root.iter(REL + "Relationship")):
        if (r.get("Type") or "").endswith(THUMBNAIL_REL) and r.get("TargetMode") != "External":
            gone.append(resolve_target("x", r.get("Target") or ""))
            root.remove(r)
    if not gone:
        return
    pkg.touch(name)
    for part in gone:
        if pkg.has(part):
            pkg.remove(part)
            pkg.remove(rels_name(part))
    stats["thumbnails"] = len(gone)


def scrub_other_parts(pkg: Package, known: dict[str, str], paragraph_parts: set[str], stats: dict) -> None:
    """段落の外（属性値・グラフやスマートアートの文字・リンク先など）に残った、消した値と同じ文字を置き換える。

    段落を持つ部品は属性値だけ（段落の文字は検出した位置だけを書き換えるため）、ほかの部品は文字も置き換える。
    """
    keys = sorted((k for k in known if len(k) >= MIN_VALUE_LEN), key=len, reverse=True)
    if not keys:
        return
    for name in list(pkg.names):
        if not _is_xml_part(name) or not pkg.has(name) or name in PROPERTY_PARTS:
            continue
        if pkg.infos[name].file_size > PART_LIMIT:
            continue
        try:
            raw = pkg.read(name).decode("utf-8")
        except UnicodeDecodeError:
            continue
        if not any(k in raw or html.escape(k, quote=False) in raw for k in keys):
            continue
        as_uri = name.endswith(".rels")
        text_too = not (
            name in paragraph_parts
            or name == DOCX_MAIN
            or DOCX_EXTRA_RE.match(name)
            or RE_PPTX_PARAGRAPH_PART.match(name)
        )
        try:
            root = pkg.tree(name)
        except RemedyError:
            # XML として読めない部品（古い VML など）は、段落の部品でなければ、文字列のまま置き換える
            if not text_too:
                continue
            fixed = raw
            for k in keys:
                fixed = fixed.replace(k, known[k]).replace(
                    html.escape(k, quote=False), html.escape(known[k], quote=False)
                )
            if fixed != raw:
                pkg.set_bytes(name, fixed.encode("utf-8"))
                stats["cleaned_other"] = stats.get("cleaned_other", 0) + 1
            continue
        n = _replace_in_tree(root, keys, known, text_too, as_uri)
        if n:
            pkg.touch(name)
            stats["cleaned_other"] = stats.get("cleaned_other", 0) + n


def _replace_in_tree(root, keys: list[str], known: dict[str, str], text_too: bool, as_uri: bool) -> int:
    n = 0

    def sub(s: str | None) -> str | None:
        if not s:
            return s
        out = s
        for k in keys:
            if k in out:
                repl = known[k]
                out = out.replace(k, quote(repl, safe="") if as_uri and repl else repl)
        return out

    for el in root.iter():
        if not isinstance(el.tag, str):
            continue
        for an, av in list(el.attrib.items()):
            nv = sub(av)
            if nv != av:
                el.set(an, nv)
                n += 1
        if text_too:
            for attr in ("text", "tail"):
                cur = getattr(el, attr)
                nv = sub(cur)
                if nv != cur:
                    setattr(el, attr, nv)
                    n += 1
    return n


# ---------------------------------------------------------------- 入口


def rewrite_office_file(src: str, dst: str, layout: str, method: str, sel: Selection, maker: DummyMaker | None) -> dict:
    """docx（layout="docx"）・pptx（"pptx"）の書き換え。結果を dst へ書く。元の src には書かない。"""
    pkg = Package(src)
    try:
        edited = Edited()
        if layout == "docx":
            info = rewrite_docx_package(pkg, method, sel, maker, edited)
        else:
            info = rewrite_pptx_package(pkg, method, sel, maker, edited)
        changed = sum(edited.stats.get(k, 0) for k in ("cells", "paragraphs", "rows", "cols", "slides"))
        if not changed:
            raise RemedyError(
                "書き換える箇所が見つかりませんでした（表の外の検出は、行・列の削除では変わりません）。元のファイルは変えていません"
                if method in ("delete_rows", "delete_columns")
                else "書き換える箇所が見つかりませんでした。元のファイルは変えていません"
            )
        stats = dict(edited.stats)
        known = dict(edited.known)
        if method != "dummy":
            known = {k: "" for k in known}
        residue = Residue.from_selection(sel, edited.values)
        scrub_properties(pkg, residue, stats)
        scrub_other_parts(pkg, known, info["paragraph_parts"], stats)
        drop_thumbnail(pkg, stats)
        stats["cleaned"] = (
            stats.get("cleaned_properties", 0) + stats.get("cleaned_other", 0) + stats.get("thumbnails", 0)
        )
        pkg.write(dst)
        return stats
    finally:
        pkg.close()

"""docx・pptx の段落の取り出し方（検査と対処で同じ数え方・同じ文字の並びを使うための共通部分）。

検査（formats/office.py）が検出の位置（段落の通し番号・文字の範囲）を集め、対処（remedy_office.py）が同じ段落を
読み直して書き換える。この2つで段落の数え方・段落の文字の並べ方がずれると、別の場所を書き換えてしまうので、
数え方はここに1つだけ置く。標準の ElementTree と lxml のどちらの要素でも動く（子の並びと tag だけを使う）。
"""

from __future__ import annotations

import posixpath
import re

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
A = "{http://schemas.openxmlformats.org/drawingml/2006/main}"
P = "{http://schemas.openxmlformats.org/presentationml/2006/main}"
R = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"
REL = "{http://schemas.openxmlformats.org/package/2006/relationships}"
XML_SPACE = "{http://www.w3.org/XML/1998/namespace}space"

DOCX_MAIN = "word/document.xml"
# 本文のほかに、段落を持つ部品（ヘッダー・フッター・脚注・文末脚注・コメント）
DOCX_EXTRA_RE = re.compile(r"^word/(header\d*|footer\d*|footnotes|endnotes|comments\w*)\.xml$")
# 段落の位置の「列」（docx）: 表の外は 0。表の中は（いちばん内側の表の番号（部品の中で文書順に 1 始まり）<< 40）|
# （その表の中の行（直下の tr の順・1 始まり）<< 16）|（行の中の列（直下の tc の順）+ 1）
CODE_TBL_SHIFT = 40
CODE_ROW_SHIFT = 16
CODE_ROW_MASK = (1 << 24) - 1
CODE_COL_MASK = (1 << 16) - 1

# 文字を持つ要素（docx）
DOCX_TEXT_TAGS = (W + "t", W + "delText", W + "instrText")
DOCX_BREAK_TAGS = (W + "br", W + "cr")
PPTX_SHAPE_TAGS = (P + "sp", P + "pic", P + "graphicFrame", P + "cxnSp")


# ---------------------------------------------------------------- docx


def docx_atoms(p) -> list[tuple[object, str]]:
    """段落の文字の部品（要素, 種類）を文書順に返す。種類: "t"（文字）・"tab"（\\t）・"br"（\\n）。

    入れ子の段落（テキストボックスの中）は含めない（そちらは別の段落として数える）。変更履歴の削除文字列（w:delText）と
    フィールドの命令（w:instrText）も文字として含める（検査と同じ）。
    """
    out: list[tuple[object, str]] = []

    def walk(el, top: bool) -> None:
        tag = el.tag
        if not isinstance(tag, str):
            return  # コメント・処理命令
        if not top and tag == W + "p":
            return
        if tag in DOCX_TEXT_TAGS and el.text:
            out.append((el, "t"))
        elif tag == W + "tab":
            out.append((el, "tab"))
        elif tag in DOCX_BREAK_TAGS:
            out.append((el, "br"))
        for ch in el:
            walk(ch, False)

    walk(p, True)
    return out


def docx_structure(root) -> dict[int, tuple[int, int]]:
    """部品の中の段落を、id(段落の要素) → （段落の通し番号, 表の中の位置の符号）にする。

    通し番号は root.iter(w:p) の順（1 始まり。テキストボックスの中の段落も数える）。符号の意味は上の CODE_*。
    表の符号は、下見で「何行・何列が消えるか」を数えるためのもの（書き換えでは、要素の親をたどって改めて求める）。
    """
    info: dict[int, tuple[int, int]] = {}
    counters = {"p": 0, "tbl": 0}

    def walk(el, ctx) -> None:
        for ch in el:
            tag = ch.tag
            if not isinstance(tag, str):
                continue
            if tag == W + "p":
                counters["p"] += 1
                code = 0 if ctx is None else (ctx[0] << CODE_TBL_SHIFT) | (ctx[1] << CODE_ROW_SHIFT) | (ctx[2] + 1)
                info[id(ch)] = (counters["p"], code)
                walk(ch, ctx)
            elif tag == W + "tbl":
                counters["tbl"] += 1
                walk_table(ch, counters["tbl"], ctx)
            else:
                walk(ch, ctx)

    def walk_table(tbl, ord_no: int, outer) -> None:
        row = 0
        for ch in tbl:
            tag = ch.tag
            if not isinstance(tag, str):
                continue
            if tag != W + "tr":
                walk(ch, outer)
                continue
            row += 1
            col = 0
            for cell in ch:
                ctag = cell.tag
                if not isinstance(ctag, str):
                    continue
                if ctag == W + "tc":
                    walk(cell, (ord_no, row, col))
                    col += 1
                else:
                    walk(cell, (ord_no, row, -1))

    walk(root, None)
    return info


def atom_text(el, kind: str) -> str:
    if kind == "tab":
        return "\t"
    if kind == "br":
        return "\n"
    return el.text or ""


def docx_para_text(p) -> str:
    """段落の文字（検査の formats.office._para_text と同じ並び）。"""
    return "".join(atom_text(el, k) for el, k in docx_atoms(p))


# ---------------------------------------------------------------- pptx


def pptx_atoms(p) -> list[tuple[object, str]]:
    """DrawingML の段落（a:p）の文字の部品。a:r・a:fld の a:t を文字、a:br を改行とする。"""
    out: list[tuple[object, str]] = []
    for ch in p:
        tag = ch.tag
        if not isinstance(tag, str):
            continue
        if tag in (A + "r", A + "fld"):
            t = ch.find(A + "t")
            if t is not None and t.text:
                out.append((t, "t"))
        elif tag == A + "br":
            out.append((ch, "br"))
    return out


def pptx_para_text(p) -> str:
    return "".join(atom_text(el, k) for el, k in pptx_atoms(p))


def pptx_paragraphs(root) -> list[tuple[int, int, object]]:
    """部品の中の段落（a:p）を文書順に（段落の通し番号（1 始まり）, 図形の番号（0 始まり。図形の外は -1）, a:p）で返す。

    図形は p:sp・p:pic・p:graphicFrame（表を含む）・p:cxnSp（グループの中も文書順に数える）。
    """
    out: list[tuple[int, int, object]] = []
    shape_no = [-1]

    def walk(el, shape: int) -> None:
        for ch in el:
            tag = ch.tag
            if not isinstance(tag, str):
                continue
            if tag in PPTX_SHAPE_TAGS:
                shape_no[0] += 1
                walk(ch, shape_no[0])
            elif tag == A + "p":
                out.append((len(out) + 1, shape, ch))
            else:
                walk(ch, shape)

    walk(root, -1)
    return out


def resolve_target(base_part: str, target: str) -> str:
    """関係（rels）の Target を、パッケージの中の部品名にする。"""
    if target.startswith("/"):
        return posixpath.normpath(target.lstrip("/"))
    return posixpath.normpath(posixpath.join(posixpath.dirname(base_part), target))


def rels_name(part: str) -> str:
    """部品の関係ファイルの名前（ppt/slides/slide1.xml → ppt/slides/_rels/slide1.xml.rels）。"""
    folder, leaf = posixpath.split(part)
    return posixpath.join(folder, "_rels", leaf + ".rels") if folder else f"_rels/{leaf}.rels"


def read_rels(read, part: str) -> list[dict]:
    """部品の関係（Id・Type・Target・TargetMode）。関係ファイルが無ければ空。"""
    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(read(rels_name(part)))
    except KeyError:
        return []
    return [
        {
            "id": r.get("Id") or "",
            "type": r.get("Type") or "",
            "target": r.get("Target") or "",
            "mode": r.get("TargetMode") or "",
        }
        for r in root.iter(REL + "Relationship")
    ]


def pptx_slide_parts(read) -> list[tuple[int, str, str]]:
    """プレゼンテーションの順に（スライド番号（1 始まり）, スライドの部品名, ノートの部品名（無ければ空））を返す。

    read は部品名 → バイト列（無ければ KeyError）。
    """
    import xml.etree.ElementTree as ET

    pres = "ppt/presentation.xml"
    root = ET.fromstring(read(pres))
    targets = {r["id"]: r for r in read_rels(read, pres)}
    out: list[tuple[int, str, str]] = []
    for sld in root.iter(P + "sldId"):
        rel = targets.get(sld.get(R + "id") or "")
        if not rel or rel["mode"] == "External":
            continue
        part = resolve_target(pres, rel["target"])
        notes = ""
        for r in read_rels(read, part):
            if r["type"].endswith("/notesSlide") and r["mode"] != "External":
                notes = resolve_target(part, r["target"])
                break
        out.append((len(out) + 1, part, notes))
    return out


def pptx_sheet(no: int, part: str, notes: bool) -> str:
    """pptx の位置の「シート」の名前（スライド番号と部品名。ノートは別）。"""
    return f"スライド{no}{'（ノート）' if notes else ''}:{part}"


def split_pptx_sheet(sheet: str) -> tuple[str, str]:
    """pptx の位置の「シート」の名前を（見出し, 部品名）に分ける。"""
    label, _, part = sheet.partition(":")
    return label, part

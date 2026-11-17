"""Outlook のデータファイル（PST/OST）の処理。

Unicode の PST/OST（版 23・36）は構造（MS-PST の NDB・LTP）を読み、メール・連絡先・予定ごとに
件名・本文（テキスト・HTML・RTF）・宛先表・添付ファイルの中身（埋め込みメッセージを含む）を検査する（pst_ndb）。
構造を読めない PST（旧い ANSI の版・壊れたもの）は、既定の「圧縮可能暗号化」（公開仕様 MS-PST 5.1 の
1バイト置換）を戻して文字列を走査する（簡易検査）。「強い暗号化」の PST は読めないため、その旨を理由に残す。
置換表は libpff（LGPL）の libpff_encryption_compressible と同じもの。
"""

from __future__ import annotations

import os
import struct
import zlib

from ..engine import IN_MEMORY_LIMIT, Blob, Collector, ItemResult, PartialScan, ScanContext, Uncheckable
from ..textdecode import iter_strings_chunked

# 暗号化された値の位置に元の値が入っている（復号は bytes.translate 1回で済む）
_COMPRESSIBLE = bytes(
    [
        0x47, 0xF1, 0xB4, 0xE6, 0x0B, 0x6A, 0x72, 0x48, 0x85, 0x4E, 0x9E, 0xEB, 0xE2, 0xF8, 0x94, 0x53,
        0xE0, 0xBB, 0xA0, 0x02, 0xE8, 0x5A, 0x09, 0xAB, 0xDB, 0xE3, 0xBA, 0xC6, 0x7C, 0xC3, 0x10, 0xDD,
        0x39, 0x05, 0x96, 0x30, 0xF5, 0x37, 0x60, 0x82, 0x8C, 0xC9, 0x13, 0x4A, 0x6B, 0x1D, 0xF3, 0xFB,
        0x8F, 0x26, 0x97, 0xCA, 0x91, 0x17, 0x01, 0xC4, 0x32, 0x2D, 0x6E, 0x31, 0x95, 0xFF, 0xD9, 0x23,
        0xD1, 0x00, 0x5E, 0x79, 0xDC, 0x44, 0x3B, 0x1A, 0x28, 0xC5, 0x61, 0x57, 0x20, 0x90, 0x3D, 0x83,
        0xB9, 0x43, 0xBE, 0x67, 0xD2, 0x46, 0x42, 0x76, 0xC0, 0x6D, 0x5B, 0x7E, 0xB2, 0x0F, 0x16, 0x29,
        0x3C, 0xA9, 0x03, 0x54, 0x0D, 0xDA, 0x5D, 0xDF, 0xF6, 0xB7, 0xC7, 0x62, 0xCD, 0x8D, 0x06, 0xD3,
        0x69, 0x5C, 0x86, 0xD6, 0x14, 0xF7, 0xA5, 0x66, 0x75, 0xAC, 0xB1, 0xE9, 0x45, 0x21, 0x70, 0x0C,
        0x87, 0x9F, 0x74, 0xA4, 0x22, 0x4C, 0x6F, 0xBF, 0x1F, 0x56, 0xAA, 0x2E, 0xB3, 0x78, 0x33, 0x50,
        0xB0, 0xA3, 0x92, 0xBC, 0xCF, 0x19, 0x1C, 0xA7, 0x63, 0xCB, 0x1E, 0x4D, 0x3E, 0x4B, 0x1B, 0x9B,
        0x4F, 0xE7, 0xF0, 0xEE, 0xAD, 0x3A, 0xB5, 0x59, 0x04, 0xEA, 0x40, 0x55, 0x25, 0x51, 0xE5, 0x7A,
        0x89, 0x38, 0x68, 0x52, 0x7B, 0xFC, 0x27, 0xAE, 0xD7, 0xBD, 0xFA, 0x07, 0xF4, 0xCC, 0x8E, 0x5F,
        0xEF, 0x35, 0x9C, 0x84, 0x2B, 0x15, 0xD5, 0x77, 0x34, 0x49, 0xB6, 0x12, 0x0A, 0x7F, 0x71, 0x88,
        0xFD, 0x9D, 0x18, 0x41, 0x7D, 0x93, 0xD8, 0x58, 0x2C, 0xCE, 0xFE, 0x24, 0xAF, 0xDE, 0xB8, 0x36,
        0xC8, 0xA1, 0x80, 0xA6, 0x99, 0x98, 0xA8, 0x2F, 0x0E, 0x81, 0x65, 0x73, 0xE4, 0xC2, 0xA2, 0x8A,
        0xD4, 0xE1, 0x11, 0xD0, 0x08, 0x8B, 0x2A, 0xF2, 0xED, 0x9A, 0x64, 0x3F, 0xC1, 0x6C, 0xF9, 0xEC,
    ]
)  # fmt: skip


def handle_pst(ctx: ScanContext, blob: Blob, item: ItemResult, col: Collector, depth: int) -> None:
    head = blob.head(1024)
    version = int.from_bytes(head[10:12], "little")
    unicode = version >= 23
    crypt = head[0x201] if unicode else head[0x1CD]
    item.kind = f"Outlook データファイル（{'Unicode' if unicode else 'ANSI'} PST/OST）"
    if crypt == 2:
        raise Uncheckable(
            "「強い暗号化」の PST のため中身を読めない（Outlook で開いてエクスポートするか、暗号化なしの PST に移して再検査）"
        )
    if crypt not in (0, 1):
        raise Uncheckable(
            f"未対応の暗号化方式（{crypt:#x}。Windows 情報保護など）の PST のため中身を読めない。"
            "Outlook で開いてメールを書き出したもの（msg・eml）を検査するか、持ち主に中身を確かめてもらってください"
        )
    broken = ""
    if version in (23, 36):
        try:
            failed = _scan_structured(ctx, blob, col, depth, version, crypt)
        except _PARSE_ERRORS as e:
            from .pst_ndb import PstFormatError

            why = str(e) if isinstance(e, PstFormatError) else "形が仕様と違う。壊れている可能性"
            broken = f"構造として読めなかった（{why}）ため、"
        else:
            item.method = "構造を読んで件名・本文・宛先・添付を検査"
            if not failed:
                return
            # 読めなかったメールの分は、ファイル全体の文字列の走査で補う（既に見つけた値は数えない）
            _scan_strings(blob, col, crypt, skip_seen=True)
            item.method += "＋文字列の走査"
            raise PartialScan(
                f"PST/OST のうち {failed} 件の項目（メール・フォルダ・添付・本文などの欄）を構造として読めず、"
                "その分は文字列だけを検査した（添付ファイルの中身は読めていない）。"
                "言い切るには Outlook でメールと添付を書き出して（msg/eml として）再検査すること"
            )
    # 構造の途中で壊れていたときは、それまでに数えた値を二重に数えない
    _scan_strings(blob, col, crypt, skip_seen=bool(broken))
    item.method = f"{'置換暗号を戻して' if crypt == 1 else ''}件名・本文・宛先などの文字列を走査"
    raise PartialScan(
        f"{broken}PST/OST は件名・本文・宛先などの文字列だけを検査した。添付ファイル（Office 文書・PDF・画像）の中身は読めない。"
        "言い切るには Outlook でメールと添付を書き出して（msg/eml として）再検査すること"
    )


def _scan_strings(blob: Blob, col: Collector, crypt: int, skip_seen: bool = False) -> None:
    """ファイル全体を、置換暗号を戻しながら文字列として走査する（簡易検査）。"""
    table = _COMPRESSIBLE if crypt == 1 else None
    with blob.open() as f:

        def read(n, f=f):
            chunk = f.read(n)
            return chunk.translate(table) if (table and chunk) else chunk

        for s in iter_strings_chunked(read):
            col.add_text(s, "メールデータ", method="PST の文字列走査", skip_seen=skip_seen)


# 構造の読み違い（壊れた PST・未対応の形）として、文字列の走査へ落とす例外
_PARSE_ERRORS = (ValueError, struct.error, IndexError, KeyError, zlib.error)

# 見せ方を決めておくプロパティ（それ以外は「項目 0x…」と出す）
_PROP_LABELS = {
    0x0037: "件名",
    0x0070: "話題",
    0x0042: "差出人の代理",
    0x0044: "受け手の代理",
    0x0065: "差出人の代理のアドレス",
    0x0C1A: "差出人",
    0x0C1F: "差出人のアドレス",
    0x0E02: "BCC",
    0x0E03: "CC",
    0x0E04: "宛先",
    0x3001: "表示名",
    0x3003: "アドレス",
    0x39FE: "SMTP アドレス",
    0x007D: "ヘッダー",
    0x1000: "本文",
    0x3707: "添付の名前",
    0x3704: "添付の名前",
}
_LONG_TEXT = {0x1000, 0x007D}  # 行ごとに位置を出す長い文
_MAX_EMBED = 8  # 埋め込みメッセージ（メールに添付したメール）を辿る深さ
_NID_NORMAL_FOLDER, _NID_SEARCH_FOLDER, _NID_MESSAGE, _NID_ATTACHMENT, _NID_ASSOC = 0x02, 0x03, 0x04, 0x05, 0x08
_NID_MESSAGE_STORE = 0x21
_NID_RECIPIENTS = 0x692


def _codepage(props) -> str:
    """8ビット文字列の文字コード（メッセージの PR_MESSAGE_CODEPAGE・PR_INTERNET_CPID。無ければ cp932）。"""
    import codecs

    for pid in (0x3FFD, 0x3FDE):
        p = props.get(pid)
        if p is not None and p.inline is not None:
            cp = int.from_bytes(p.inline, "little")
            name = "utf-8" if cp == 65001 else f"cp{cp}"
            try:
                codecs.lookup(name)
                return name
            except LookupError:
                continue
    return "cp932"


def _when(props) -> str:
    """メッセージの日時（受信・送信・作成の順に有るもの）を、Outlook で探すための手がかりとして返す。

    件名は個人情報を含みうるので、場所の文字には使わない（値を持たないレポートへ漏らさない）。
    """
    import datetime

    for pid in (0x0E06, 0x0039, 0x3007):
        p = props.get(pid)
        if p is None or p.ptype != 0x0040:
            continue
        try:
            raw = p.raw()
            ft = struct.unpack_from("<Q", raw)[0]
            t = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ft // 10)
            local = t.replace(tzinfo=datetime.timezone.utc).astimezone()
            return local.strftime("%Y-%m-%d %H:%M")
        except (struct.error, OverflowError, ValueError, OSError):
            continue
    return ""


def _scan_props(props, where: str, col: Collector, cp: str, seen: set[str]) -> int:
    """PC・表の行の文字列の値を検査し（同じ値は1回だけ）、読めなかった欄の数を返す。

    1つの欄が読めなくても、残りの欄・宛先表・添付は続けて検査する。
    """
    failed = 0
    for pid, p in props.items():
        try:
            _scan_prop(pid, p, where, col, cp, seen)
        except _PARSE_ERRORS:
            failed += 1
    return failed


def _scan_prop(pid: int, p, where: str, col: Collector, cp: str, seen: set[str]) -> None:
    from .misc import markup_to_text, rtf_to_text
    from .pst_ndb import PT_BINARY, PT_STRING8, PT_UNICODE, prop_texts

    if pid == 0x1013 and p.ptype in (PT_BINARY, PT_STRING8, PT_UNICODE):  # HTML の本文
        raw = p.raw()
        html = raw.decode("utf-16-le", "replace") if p.ptype == PT_UNICODE else raw.decode(cp, "replace")
        col.add_lines(markup_to_text(html), location_prefix=f"{where}HTML本文 ", method="本文", skip_seen=True)
        return
    if pid == 0x1009 and p.ptype == PT_BINARY:  # 圧縮した RTF の本文（MS-OXRTFCP）
        try:
            import compressed_rtf

            rtf = compressed_rtf.decompress(p.raw())
        except Exception:  # 戻せない RTF・部品が無いときは、その本文だけを読めなかった欄に数える
            raise ValueError("RTF の本文を戻せない") from None
        col.add_lines(rtf_to_text(rtf), location_prefix=f"{where}RTF本文 ", method="本文", skip_seen=True)
        return
    for text in prop_texts(p, cp):
        if not text.strip() or text in seen:
            continue
        seen.add(text)
        # 0x8000 以上は名前つきの項目（連絡先の電子メールなど・番号はファイルごとに違う）
        label = _PROP_LABELS.get(pid) or (f"追加の欄（{pid:#06x}）" if pid >= 0x8000 else f"欄 {pid:#06x}")
        if pid in _LONG_TEXT or len(text) > 2000:
            col.add_lines(text, location_prefix=f"{where}{label} ", method="メール")
        else:
            col.add_text(text, f"{where}{label}", method="メール")


def _scan_message(ctx, pst, bid, bid_sub, display: str, col: Collector, depth: int, level: int, label: str) -> int:
    """1通のメッセージ（メール・連絡先・予定）を検査し、構造を読めなかった添付の数を返す。

    label は場所の見せ方（「受信トレイ/3件目」など）。日時が分かれば後ろに足す。
    """
    from .pst_ndb import PT_BINARY, PT_OBJECT, Heap, Prop, prop_texts, read_pc, read_tc

    props = read_pc(pst, bid, bid_sub)
    cp = _codepage(props)
    when = _when(props)
    label = f"{label}（{when}）" if when else label
    where = f"{label}の"
    seen: set[str] = set()
    failed = _scan_props(props, where, col, cp, seen)
    if not bid_sub:
        return failed
    subs = Heap(pst, bid, bid_sub).subs()
    if _NID_RECIPIENTS in subs:
        try:
            rbd, rbs = subs[_NID_RECIPIENTS]
            for row in read_tc(pst, rbd, rbs):
                failed += _scan_props(row, f"{where}宛先表の", col, cp, seen)
        except _PARSE_ERRORS:
            failed += 1  # 宛先表が読めなくても添付は続ける
    for snid, (sbd, sbs) in subs.items():
        if snid & 0x1F != _NID_ATTACHMENT:
            continue
        try:
            att = read_pc(pst, sbd, sbs)
            names = [t for pid in (0x3707, 0x3704, 0x3001) if pid in att for t in prop_texts(att[pid], cp) if t]
            name = names[0] if names else f"添付{snid:#x}"
            failed += _scan_props({pid: p for pid, p in att.items() if pid != 0x3701}, f"{where}添付の", col, cp, seen)
            data = att.get(0x3701)
            inner = f"{display}!{label}/{name}"
            if data is None:
                continue
            if data.ptype == PT_BINARY:
                _scan_attachment(ctx, data, inner, depth, name)
            elif data.ptype == PT_OBJECT:
                # 値の頭の4バイトが、添付のサブノードの中の nid（MS-PST 2.4.6.2）
                enid = struct.unpack_from("<I", data.raw())[0]
                method = att.get(0x3705)
                if method is not None and method.inline is not None and int.from_bytes(method.inline, "little") != 5:
                    # 埋め込みメッセージ（添付の方式 5）でない OLE の添付は、その中身をファイルとして検査する
                    _scan_attachment(ctx, Prop(PT_BINARY, Heap(pst, sbd, sbs), hnid=enid), inner, depth, name)
                elif level >= _MAX_EMBED:
                    failed += 1  # 深すぎる入れ子は辿らず、読めなかった項目として知らせる
                else:
                    ebd, ebs = Heap(pst, sbd, sbs).sub_entry(enid)
                    failed += _scan_message(
                        ctx, pst, ebd, ebs, display, col, depth, level + 1, f"{label}に添付したメール"
                    )
            else:
                failed += 1  # 未知の型の添付の中身
        except _PARSE_ERRORS:
            failed += 1
    return failed


def _scan_attachment(ctx: ScanContext, data, display: str, depth: int, name: str) -> None:
    """添付ファイルの中身を内側のファイルとして検査する（大きなものは一時ファイルへ書き出す）。"""
    size = data.size()
    if size > IN_MEMORY_LIMIT:
        try:
            ctx.ensure_space(size)
        except Uncheckable as e:
            # 空きが足りないときは、その添付だけを検査不能にして PST の残りを続ける
            from ..models import Status
            from .archive import add_failed_item

            add_failed_item(ctx, display, Status.UNCHECKABLE, str(e), depth + 1, size=size)
            return
        out = os.path.join(ctx.new_tmp_subdir(), "attachment")
        with open(out, "wb") as dst:
            for chunk in data.iter_chunks():
                dst.write(chunk)
        ctx.scan_nested(display, path=out, depth=depth + 1, name_hint=name)
    else:
        ctx.scan_nested(display, data=b"".join(data.iter_chunks()), depth=depth + 1, name_hint=name)


def _scan_structured(ctx: ScanContext, blob: Blob, col: Collector, depth: int, version: int, crypt: int) -> int:
    """構造を読んで検査し、読めなかった項目の数を返す（ファイル全体が読めなければ例外）。"""
    from .pst_ndb import PstFile, prop_texts, read_pc

    failed = 0
    with blob.open() as f:
        pst = PstFile(f, version, crypt)
        folders: dict[int, str] = {}
        for nid, (bd, bs, _parent) in pst.nbt.items():
            if nid & 0x1F in (_NID_NORMAL_FOLDER, _NID_SEARCH_FOLDER):
                try:
                    props = read_pc(pst, bd, bs)
                    names = prop_texts(props[0x3001], _codepage(props)) if 0x3001 in props else []
                    folders[nid] = names[0] if names else ""
                    failed += _scan_props(props, f"フォルダ『{folders[nid]}』の", col, _codepage(props), set())
                except _PARSE_ERRORS:
                    failed += 1
        counts: dict[tuple[int, int], int] = {}
        for nid, (bd, bs, parent) in sorted(pst.nbt.items()):
            kind = nid & 0x1F
            try:
                if kind in (_NID_MESSAGE, _NID_ASSOC):
                    n = counts[(parent, kind)] = counts.get((parent, kind), 0) + 1
                    what = f"設定の項目{n}" if kind == _NID_ASSOC else f"{n}件目"
                    label = f"{folders.get(parent) or 'フォルダ外'}/{what}"
                    failed += _scan_message(ctx, pst, bd, bs, blob.display, col, depth, 0, label)
                elif nid == _NID_MESSAGE_STORE:
                    props = read_pc(pst, bd, bs)
                    failed += _scan_props(props, "データファイルの", col, _codepage(props), set())
            except _PARSE_ERRORS:
                failed += 1
    return failed

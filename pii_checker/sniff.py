"""中身（先頭のバイト列）から形式を判定し、担当の処理を選ぶ。"""

from __future__ import annotations

import zipfile

from .engine import Blob

KIND_LABELS = {
    "empty": "空ファイル",
    "xlsx": "Excel（xlsx/xlsm）",
    "xlsb": "Excel バイナリ（xlsb）",
    "docx": "Word（docx）",
    "pptx": "PowerPoint（pptx）",
    "ooxml": "Office Open XML",
    "odf": "OpenDocument",
    "xps": "XPS",
    "zip": "ZIP アーカイブ",
    "ole": "OLE 複合文書（Office97-2003 等）",
    "xls_biff_legacy": "Excel 2.x〜4.0（BIFF2-4）",
    "access": "Access データベース",
    "sqlite": "SQLite データベース",
    "pdf": "PDF",
    "rtf": "リッチテキスト（RTF）",
    "7z": "7z アーカイブ",
    "rar": "RAR アーカイブ",
    "gzip": "gzip 圧縮",
    "bzip2": "bzip2 圧縮",
    "xz": "xz 圧縮",
    "zstd": "zstd 圧縮",
    "lz4": "lz4 圧縮",
    "lzip": "lzip 圧縮",
    "compress_z": "compress 圧縮（.Z）",
    "cpio": "cpio アーカイブ",
    "rpm": "RPM パッケージ",
    "ar": "ar アーカイブ（deb 等）",
    "tar": "tar アーカイブ",
    "cab": "CAB アーカイブ",
    "lzh": "LZH アーカイブ",
    "arj": "ARJ アーカイブ",
    "iso": "ディスクイメージ（ISO）",
    "wim": "WIM イメージ",
    "image": "画像",
    "image_unsupported": "画像（未対応の形式）",
    "media": "動画・音声",
    "executable": "実行ファイル",
    "font": "フォント",
    "eml": "メール（eml/mht）",
    "html": "HTML",
    "xml": "XML",
    "text": "テキスト",
    "dbf": "dBase（dbf）",
    "oracle_dump": "Oracle ダンプ（exp/expdp）",
    "pg_custom": "PostgreSQL ダンプ（custom 形式）",
    "db_binary": "データベースのファイル本体",
    "disk_image": "ディスク・OS イメージ",
    "filesystem": "パーティション（ファイルシステム）イメージ",
    "bitlocker": "BitLocker 暗号化ボリューム",
    "split_volume": "分割アーカイブの続き",
    "pst": "Outlook データファイル（PST/OST）",
    "git_pack": "git の pack（履歴の中身）",
    "git_loose": "git のオブジェクト",
    "git_index": "git の索引（index）",
    "git_meta": "git の索引ファイル",
    "unknown": "形式不明",
}

DB_FILE_EXTS = {
    ".mdf": "SQL Server データファイル",
    ".ndf": "SQL Server データファイル",
    ".ldf": "SQL Server ログファイル",
    ".ibd": "MySQL InnoDB データファイル",
    ".myd": "MySQL MyISAM データファイル",
    ".frm": "MySQL 表定義",
    ".ora": "Oracle ファイル",
    ".dbf": "Oracle データファイル",
    ".ctl": "Oracle 制御ファイル",
    ".arc": "Oracle アーカイブログ",
    ".bak": "データベースのバックアップ",
    ".trn": "SQL Server ログバックアップ",
    ".fdb": "Firebird データベース",
    ".gdb": "InterBase データベース",
    ".nsf": "Lotus Notes データベース",
    ".fmp12": "FileMaker データベース",
    ".fp7": "FileMaker データベース",
    ".4dd": "4D データベース",
}
DISK_IMAGE_EXTS = {
    ".img",
    ".raw",
    ".dd",
    ".bin",
    ".vhd",
    ".vhdx",
    ".vmdk",
    ".vdi",
    ".qcow2",
    ".qcow",
    ".hdd",
    ".dmg",
    ".e01",
}

TEXT_EXTS = {
    ".txt",
    ".csv",
    ".tsv",
    ".log",
    ".md",
    ".json",
    ".ini",
    ".cfg",
    ".conf",
    ".yaml",
    ".yml",
    ".sql",
    ".tab",
    ".dat",
    ".prn",
    ".vcf",
    ".ics",
    ".ldif",
    ".bat",
    ".ps1",
    ".py",
    ".js",
    ".vbs",
    ".bas",
    ".cls",
    ".frm",
    ".properties",
    ".reg",
}
MEDIA_EXTS = {
    ".mp4",
    ".mov",
    ".avi",
    ".wmv",
    ".mkv",
    ".webm",
    ".flv",
    ".m4v",
    ".mpg",
    ".mpeg",
    ".ts",
    ".mp3",
    ".wav",
    ".wma",
    ".m4a",
    ".aac",
    ".flac",
    ".ogg",
    ".mid",
    ".midi",
    ".3gp",
}
EXEC_EXTS = {".exe", ".dll", ".sys", ".ocx", ".com", ".scr", ".cpl", ".drv", ".so", ".pyd"}
FONT_EXTS = {".ttf", ".otf", ".ttc", ".fon", ".woff", ".woff2", ".eot"}
IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".webp", ".jfif"}


def _zip_kind(blob: Blob) -> str:
    try:
        with blob.open() as f, zipfile.ZipFile(f) as z:
            names = set(z.namelist())
    except Exception:
        return "zip"  # 壊れた zip・中央ディレクトリ欠損は zip の処理側（7z 予備）で扱う
    if "[Content_Types].xml" in names:
        if "xl/workbook.bin" in names:
            return "xlsb"
        if "xl/workbook.xml" in names or any(n.startswith("xl/") for n in names):
            return "xlsx"
        if "word/document.xml" in names:
            return "docx"
        if any(n.startswith("ppt/") for n in names):
            return "pptx"
        if any(n.endswith(".fdoc") or n.startswith("Documents/") for n in names):
            return "xps"
        return "ooxml"
    if "mimetype" in names and "content.xml" in names:
        return "odf"
    return "zip"


def _is_split_continuation(blob: Blob) -> bool:
    """分割アーカイブの2つ目以降（.002・.z01・.part2.rar 等）か。"""
    import re

    name = (blob.name_hint or blob.display.rsplit("!", 1)[-1]).lower()
    m = re.search(r"\.(\d{3})$", name)
    if m and int(m.group(1)) > 1:
        return True
    if re.search(r"\.z\d{2}$", name) or re.search(r"\.r\d{2}$", name):
        return True
    m = re.search(r"\.part(\d+)\.rar$", name)
    return bool(m and int(m.group(1)) > 1)


def sniff(blob: Blob) -> str:
    """形式のキーを返す。拡張子は、中身で決めきれないときの補助にだけ使う。"""
    head = blob.head(65536)
    ext = blob.ext
    if not head:
        return "empty"
    if head.startswith(b"!BDN"):
        return "pst"
    # git の履歴（作業フォルダの .git も bare リポジトリも、中身で見分ける）
    from .formats import git as _git

    if _git.is_pack(head):
        return "git_pack"
    if head.startswith(b"DIRC") and head[4:8] in (b"\x00\x00\x00\x02", b"\x00\x00\x00\x03", b"\x00\x00\x00\x04"):
        return "git_index"
    if _git.meta_label(head):
        return "git_meta"
    if _git.looks_loose(head):
        return "git_loose"
    if b"EXPORT:V" in head[:64]:
        return "oracle_dump"
    if head.startswith(b"PGDMP") and head[5:6] == b"\x01":
        return "pg_custom"
    if head.startswith(b"TAPE") and ext in (".bak", ".trn", ""):
        return "db_binary"
    if head[3:11] == b"-FVE-FS-":
        return "bitlocker"
    if (
        head.startswith(b"vhdxfile")
        or head.startswith(b"conectix")
        or head.startswith(b"KDMV")
        or head.startswith(b"QFI\xfb")
    ):
        return "disk_image"
    if head.startswith(b"# Disk DescriptorFile") or (head.startswith(b"<<< ") and b"VirtualBox" in head[:64]):
        return "disk_image"
    if (
        head[3:11] in (b"NTFS    ", b"EXFAT   ")
        or head[82:90] == b"FAT32   "
        or head[54:62] in (b"FAT12   ", b"FAT16   ")
    ):
        return "filesystem"
    if len(head) > 0x43A and head[0x438:0x43A] == b"\x53\xef" and ext in DISK_IMAGE_EXTS | {""}:
        return "filesystem"
    if head.startswith(b"hsqs") or head.startswith(b"sqsh"):
        return "filesystem"
    if len(head) > 520 and (head[512:520] == b"EFI PART" or (head[510:512] == b"\x55\xaa" and ext in DISK_IMAGE_EXTS)):
        return "disk_image"
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06") or head.startswith(b"PK\x07\x08"):
        return _zip_kind(blob)
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if head[4:19] in (b"Standard Jet DB", b"Standard ACE DB"):
        return "access"
    if head.startswith(b"SQLite format 3\x00"):
        return "sqlite"
    pdf_at = head.find(b"%PDF", 0, 1024)
    if pdf_at == 0 or (pdf_at > 0 and b" obj" in head):  # 先頭以外の %PDF は本物らしいときだけ
        return "pdf"
    if head.lstrip().startswith(b"{\\rtf"):
        return "rtf"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if head.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if head.startswith(b"BZh") and len(head) > 4 and head[3:4].isdigit():
        return "bzip2"
    if head.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if head.startswith(b"\x28\xb5\x2f\xfd"):
        return "zstd"
    if head.startswith(b"\x04\x22\x4d\x18"):
        return "lz4"
    if head.startswith(b"LZIP"):
        return "lzip"
    if head.startswith(b"\x1f\x9d"):
        return "compress_z"
    if head[:6] in (b"070701", b"070702", b"070707") or head[:2] in (b"\xc7\x71", b"\x71\xc7"):
        return "cpio"
    if head.startswith(b"\xed\xab\xee\xdb"):
        return "rpm"
    if head.startswith(b"!<arch>\n"):
        return "ar"
    if len(head) > 262 and head[257:262] == b"ustar":
        return "tar"
    if head.startswith(b"MSCF"):
        return "cab"
    if len(head) > 7 and head[2:4] == b"-l" and head[6:7] == b"-":
        return "lzh"
    if head.startswith(b"\x60\xea"):
        return "arj"
    if head.startswith(b"MSWIM\x00"):
        return "wim"
    if len(head) >= 0x8006 and head[0x8001:0x8006] == b"CD001":
        return "iso"
    # Excel 2.x〜4.0 は OLE ではなく BIFF レコードがそのまま並ぶ
    if head[:2] in (b"\x09\x00", b"\x09\x02", b"\x09\x04") and ext in (".xls", ".xlw", ".xlc", ""):
        return "xls_biff_legacy"
    # 画像
    if head.startswith(b"\xff\xd8\xff") or head.startswith(b"\x89PNG") or head[:4] in (b"GIF8",):
        return "image"
    if head[:4] in (b"II*\x00", b"MM\x00*"):
        return "image"
    if head.startswith(b"BM") and ext in (".bmp", ".dib", ""):
        return "image"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image"
    # ここから下の目印は「対象外」に振るものが多い。テキストとして読めるもの（目印の文字で始まる CSV 等）を
    # 中身を読まずに対象外にすると言い切りを誤らせるので、テキストとして読むほうを先にする（本物の動画・音声・
    # 実行ファイルは NUL などの制御文字を含むのでテキストとはみなされない）
    kind = _text_kind(blob, head, ext)
    if kind:
        return kind
    if head[4:8] == b"ftyp":
        brand = head[8:12]
        if brand in (b"heic", b"heix", b"mif1", b"msf1", b"avif", b"heim", b"heis"):
            return "image_unsupported"
        return "media"
    if head[:4] == b"RIFF" and head[8:12] in (b"AVI ", b"WAVE"):
        return "media"
    if (
        head.startswith(b"\x1a\x45\xdf\xa3")
        or head.startswith(b"ID3")
        or head.startswith(b"fLaC")
        or head.startswith(b"OggS")
    ):
        return "media"
    if head.startswith(b"\x30\x26\xb2\x75\x8e\x66\xcf\x11") or head.startswith(b"FLV"):
        return "media"
    if len(head) >= 2 and head[0] == 0xFF and (head[1] & 0xE0) == 0xE0 and ext in MEDIA_EXTS:
        return "media"  # MP3・AAC のフレーム同期
    if len(head) > 376 and head[0] == 0x47 and head[188] == 0x47 and head[376] == 0x47:
        return "media"  # MPEG-TS
    if (
        head.startswith(b"\x00\x00\x01\xba")
        or head.startswith(b"MThd")
        or (head[:4] == b"FORM" and head[8:12] in (b"AIFF", b"AIFC"))
    ):
        return "media"
    if head.startswith(b"MZ") or head.startswith(b"\x7fELF"):
        return "executable"
    if head[:4] in (b"\x00\x01\x00\x00", b"OTTO", b"ttcf", b"wOFF", b"wOF2") and ext in FONT_EXTS:
        return "font"
    if ext == ".dmp" and any(
        k in head
        for k in (b"AL32UTF8", b"JA16SJIS", b"JA16EUC", b"UTF8", b"SYS_EXPORT_", b"WE8MSWIN1252", b"WE8ISO8859P1")
    ):
        return "oracle_dump"
    if ext == ".dbf" and head[:1] in (
        b"\x02",
        b"\x03",
        b"\x30",
        b"\x31",
        b"\x43",
        b"\x63",
        b"\x83",
        b"\x8b",
        b"\xcb",
        b"\xf5",
        b"\xfb",
    ):
        return "dbf"
    if ext in DB_FILE_EXTS:
        return "db_binary"
    if ext in (".dmg",) or (ext in DISK_IMAGE_EXTS and blob.size > 1024 * 1024):
        return "disk_image"
    if _is_split_continuation(blob):
        return "split_volume"
    # 動画・実行ファイル・フォントの拡張子でも、中身の目印が無いものは対象外にしない（形式不明として文字列走査）
    return "unknown"


def _text_kind(blob: Blob, head: bytes, ext: str) -> str | None:
    """メール・HTML・XML・テキストのどれか。どれでもなければ None。"""
    stripped = head.lstrip(b"\xef\xbb\xbf").lstrip()
    lower = stripped[:512].lower()
    if ext in (".eml", ".mht", ".mhtml", ".nws") or _looks_like_mail(stripped):
        return "eml"
    if ext in (".htm", ".html", ".xhtml") or lower.startswith(b"<!doctype html") or lower.startswith(b"<html"):
        return "html"
    if ext in (".xml", ".xaml", ".rdf", ".svg", ".plist", ".xsl") or lower.startswith(b"<?xml"):
        return "xml"
    # 中身がテキストなら、拡張子が何であってもテキストとして読む（.ts・.mp3・.002 という名前の CSV 等）
    if _looks_like_text(head):
        return "text"
    return None


def _looks_like_mail(head: bytes) -> bool:
    first = head[:2048]
    keys = (b"Received:", b"Return-Path:", b"From:", b"MIME-Version:", b"Message-ID:", b"Subject:", b"Date:")
    hits = sum(1 for k in keys if k in first)
    return hits >= 3 and first.split(b"\n", 1)[0].count(b":") >= 1


def _utf16_ok_char(c: str) -> bool:
    if c in "\r\n\t ":
        return True
    if not c.isprintable() or c == "�" or "" <= c <= "":
        return False
    # ラテン文字・記号（罫線 ─・※・…・“”・①）・日本語・ハングル・全角を文字として数える
    return c < "ɐ" or " " <= c <= "⯿" or "　" <= c <= "鿿" or "가" <= c <= "힯" or "＀" <= c <= "￯"


def _utf16_readable(sample: bytes, enc: str) -> bool:
    """UTF-16 として読んだとき、ふつうの文字が大半か（16bit の数値表などのバイナリをテキストと誤らない）。"""
    text = sample[: len(sample) - len(sample) % 2].decode(enc, errors="replace")
    if not text:
        return False
    return sum(1 for c in text if _utf16_ok_char(c)) / len(text) >= 0.9


def _looks_like_text(head: bytes) -> bool:
    if head.startswith((b"\xff\xfe", b"\xfe\xff", b"\xef\xbb\xbf")):
        return True
    sample = head[:8192]
    if not sample:
        return False
    # UTF-16（BOM なし）
    if len(sample) > 16 and sample[1::2].count(0) > len(sample) * 0.15 and sample[0::2].count(0) < len(sample) * 0.02:
        return _utf16_readable(sample, "utf-16-le")
    if len(sample) > 16 and sample[0::2].count(0) > len(sample) * 0.15 and sample[1::2].count(0) < len(sample) * 0.02:
        return _utf16_readable(sample, "utf-16-be")  # UTF-16BE（BOM なし）
    controls = sum(1 for b in sample if b < 0x09 or (0x0E <= b < 0x20 and b != 0x1B))
    return controls / len(sample) < 0.01


def handler_for(kind: str):
    """形式のキーから担当の処理関数を返す。"""
    from .formats import archive, database, dbdump, git, misc, office, pdf, pst

    table = {
        "empty": misc.handle_empty,
        "xlsx": office.handle_xlsx,
        "xlsb": office.handle_xlsb,
        "docx": office.handle_docx,
        "pptx": office.handle_pptx,
        "ooxml": office.handle_ooxml_generic,
        "odf": office.handle_ooxml_generic,
        "xps": office.handle_ooxml_generic,
        "zip": archive.handle_zip,
        "ole": office.handle_ole,
        "xls_biff_legacy": office.handle_xls_legacy,
        "access": database.handle_access,
        "sqlite": database.handle_sqlite,
        "dbf": database.handle_dbf,
        "pdf": pdf.handle_pdf,
        "rtf": misc.handle_rtf,
        "7z": archive.handle_7z,
        "rar": archive.handle_with_7z_exe,
        "cab": archive.handle_with_7z_exe,
        "lzh": archive.handle_with_7z_exe,
        "arj": archive.handle_with_7z_exe,
        "iso": archive.handle_with_7z_exe,
        "wim": archive.handle_with_7z_exe,
        "zstd": archive.handle_single_compressed,
        "lz4": archive.handle_single_compressed,
        "lzip": archive.handle_single_compressed,
        "compress_z": archive.handle_with_7z_exe,
        "cpio": archive.handle_with_7z_exe,
        "rpm": archive.handle_with_7z_exe,
        "ar": archive.handle_with_7z_exe,
        "gzip": archive.handle_single_compressed,
        "bzip2": archive.handle_single_compressed,
        "xz": archive.handle_single_compressed,
        "tar": archive.handle_tar,
        "image": misc.handle_image,
        "image_unsupported": misc.handle_image_unsupported,
        "media": misc.handle_out_of_scope,
        "executable": misc.handle_out_of_scope,
        "font": misc.handle_out_of_scope,
        "eml": misc.handle_eml,
        "html": misc.handle_markup,
        "xml": misc.handle_markup,
        "text": misc.handle_text,
        "oracle_dump": dbdump.handle_oracle_dump,
        "pg_custom": dbdump.handle_pg_custom,
        "db_binary": dbdump.handle_db_binary,
        "disk_image": archive.handle_disk_image,
        "filesystem": archive.handle_disk_image,
        "bitlocker": misc.handle_bitlocker,
        "split_volume": misc.handle_split_volume,
        "pst": pst.handle_pst,
        "git_pack": git.handle_git_pack,
        "git_loose": git.handle_git_loose,
        "git_index": git.handle_git_index,
        "git_meta": git.handle_git_meta,
        "unknown": misc.handle_unknown,
    }
    return table[kind]

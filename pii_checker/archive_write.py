"""書庫の中のファイルへの対処（T2-a2）: 取り出す・書庫を作り直す。

決まり:
- 対象は検査で「外側!内側」のパスになった、書庫の中のファイル（入れ子も）。元の書庫の確定（改名・置き換え・ごみ箱）と記録は
  呼び出し側（remediate.py）が行い、ここでは「対象の項目だけを取り出す」「対象の項目だけを差し替える（または取り除く）形で書庫を作り直す」を担当する。
- 作り直しは元の書庫を書き換えず、別のファイル（呼び出し側が決めた一時の名前）へ書く。置き換えは呼び出し側。
- zip: ほかの項目は圧縮済みのデータをそのまま写す（展開・再圧縮しない）。局所ヘッダー・データ・データ記述子は元のバイト列、
  中央ディレクトリは元の ZipInfo から作り直す（日時・圧縮方式・属性・コメント・フラグ・名前のバイト列・ZIP64・並び順を保つ）。
  対象の項目だけを元と同じ圧縮方式で入れ直す。パスワードつきの項目は、同梱の 7-Zip で同じ暗号方式（ZipCrypto / AES）にして入れ直す。
- 入れ子（zip の中の zip 等）は、内側から順に作り直して外側へ戻す。
- 7z は 7-Zip の更新（d・u）、tar は tarfile、gz・bz2・xz（1ファイルを包む形式）は包み直す。
- rar・cab・iso など書けない形式は、zip に作り直す（形式が変わる）ことだけができる。暗号化された書庫は暗号が外れるので断る。
- 生の値はここでは扱わない（取り出したファイルは作業フォルダの中だけ。呼び出し側が終わったら消す）。
"""

from __future__ import annotations

import bz2
import copy
import gzip
import lzma
import os
import re
import shutil
import struct
import subprocess
import tarfile
import tempfile
import time
import zipfile
import zlib
from dataclasses import dataclass

from .remedy_write import RemedyError

# 書き換えて作り直せる形式（sniff のキー）。それ以外の書庫は、zip に作り直すことだけができる
WRITABLE_KINDS = {"zip", "7z", "tar", "gzip", "bzip2", "xz"}
# 書庫として扱う形式（sniff のキー）。Office 文書・OpenDocument（docx・xlsx・odt など）は書庫として扱わない（形式の対処）
ARCHIVE_KINDS = WRITABLE_KINDS | {
    "rar",
    "cab",
    "lzh",
    "arj",
    "iso",
    "wim",
    "compress_z",
    "cpio",
    "rpm",
    "ar",
    "zstd",
    "lz4",
    "lzip",
}
# 1ファイルを包んだだけの形式（中のファイルだけを取り除くことはできない）
SINGLE_KINDS = {"gzip", "bzip2", "xz", "zstd", "lz4", "lzip", "compress_z"}
SINGLE_SUFFIXES = {
    "gzip": (".gz", ".gzip", ".tgz", ".z"),
    "bzip2": (".bz2", ".tbz", ".tbz2"),
    "xz": (".xz", ".txz", ".lzma"),
}
KIND_NAMES = {
    "zip": "zip",
    "7z": "7z",
    "tar": "tar",
    "gzip": "gzip（gz）",
    "bzip2": "bzip2",
    "xz": "xz",
    "zstd": "zstd",
    "lz4": "lz4",
    "lzip": "lzip",
    "rar": "rar",
    "cab": "cab",
    "lzh": "lzh",
    "arj": "arj",
    "iso": "iso",
    "wim": "wim",
    "cpio": "cpio",
    "rpm": "rpm",
    "ar": "ar",
    "compress_z": "compress（.Z）",
}
ZIP64_LIMIT = 0xFFFFFFFF
RE_SIGNATURE = re.compile(r"^META-INF/[^/]+\.(SF|RSA|DSA|EC)$", re.I)
CHUNK = 1024 * 1024
SEVENZIP_TIMEOUT = 3600
NO_WINDOW = 0x08000000


# ---------------------------------------------------------------- 作業フォルダ・環境


def make_workdir(temp_dir: str | None) -> tuple[str, object]:
    """作業フォルダを作る。名前の頭と「持ち主の目印」は検査の一時フォルダと同じ（打ち切られたあとの片付けの対象になる）。"""
    from .engine import OWNER_MARK, TEMP_PREFIX

    base = temp_dir if temp_dir and os.path.isdir(temp_dir) else None
    path = tempfile.mkdtemp(prefix=TEMP_PREFIX, dir=base)
    owner = open(os.path.join(path, OWNER_MARK), "wb")
    return path, owner


def remove_workdir(path: str, owner) -> None:
    try:
        owner.close()
    except Exception:  # noqa: BLE001
        pass
    shutil.rmtree(path, ignore_errors=True)


@dataclass
class ArchiveEnv:
    """書庫を扱う間の環境（7-Zip の場所・パスワードの候補・作業フォルダ）。"""

    sevenzip: str | None
    passwords: list[str]
    workdir: str

    def new_dir(self) -> str:
        return tempfile.mkdtemp(dir=self.workdir)

    def need_space(self, nbytes: int) -> None:
        """作業フォルダへ nbytes 書いても空きが残るかを確かめる。"""
        from . import safeio

        try:
            safeio.ensure_free(self.workdir, max(0, int(nbytes)), "作業用の一時フォルダ")
        except safeio.TempSpaceShort as e:
            raise RemedyError(f"{e}（元の圧縮ファイルは変えていません）") from None


def _leaf_file_name(entry_name: str) -> str:
    """項目の名前から、作業フォルダに置くファイル名を作る（拡張子は形式の見分けに使うので残す）。"""
    base = entry_name.replace("\\", "/").rsplit("/", 1)[-1] or "item"
    base = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", base).rstrip(" .") or "item"
    stem, ext = os.path.splitext(base)
    if stem.upper() in {"CON", "PRN", "AUX", "NUL"} or re.fullmatch(r"(COM|LPT)\d", stem.upper() or ""):
        base = "_" + base
    if len(base) > 120:
        stem, ext = os.path.splitext(base)
        base = stem[: 120 - len(ext)] + ext
    return base


def norm_name(name: str) -> str:
    """名前の突き合わせ用（区切りは / にそろえる。Windows の 7-Zip は \\ で出す）。"""
    return name.replace("\\", "/")


def sniff_kind(path: str, name_hint: str) -> str:
    """ファイルの形式のキーを、検査と同じ見分け方で得る。"""
    from . import sniff
    from .engine import Blob

    return sniff.sniff(Blob(display=name_hint or os.path.basename(path), path=path, name_hint=name_hint))


def kind_label(kind: str) -> str:
    from . import sniff

    return KIND_NAMES.get(kind) or sniff.KIND_LABELS.get(kind, kind)


# ---------------------------------------------------------------- 7-Zip の呼び出し


def _sevenzip_run(exe: str, args: list[str], cwd: str | None = None) -> tuple[int, str]:
    r = subprocess.run(
        [exe] + args,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=SEVENZIP_TIMEOUT,
        cwd=cwd,
        creationflags=NO_WINDOW if os.name == "nt" else 0,
    )
    from .formats.archive import _decode_7z

    return r.returncode, _decode_7z(r.stdout) + "\n" + _decode_7z(r.stderr)


def _need_sevenzip(env: ArchiveEnv, why: str) -> str:
    if not env.sevenzip:
        raise RemedyError(
            f"{why}には 7-Zip（7z.exe）が要りますが、見つかりません（設定で 7z.exe の場所を指定してください）"
        )
    return env.sevenzip


def _short_output(out: str, *paths: str) -> str:
    """7-Zip の出力から、利用者に見せてよい短い要約を作る（作業フォルダのパスは除く）。"""
    from .formats.archive import tech_summary

    return tech_summary(out, *paths) or out.strip()[-160:].replace("\n", " ")


def _list_7z(path: str, env: ArchiveEnv, kind: str) -> tuple[dict, list[dict], str | None]:
    """7-Zip で一覧を取る。（書庫の性質, 項目の一覧, 一覧に要ったパスワード）。"""
    from .formats.archive import NO_PASSWORD, WRONG_PW_MARKERS, _parse_7z_list

    exe = _need_sevenzip(env, "この形式の圧縮ファイルを読む")
    common = ["-sccUTF-8", "-scsUTF-8"] + (["-mcp=932"] if kind == "zip" else [])
    for pw in [NO_PASSWORD] + env.passwords:
        code, out = _sevenzip_run(exe, ["l", "-slt", f"-p{pw}"] + common + [path])
        if code == 0 or ("----------" in out and not any(m in out for m in WRONG_PW_MARKERS)):
            head, _, _ = out.partition("----------")
            props: dict[str, str] = {}
            for line in head.splitlines():
                if " = " in line:
                    k, v = line.split(" = ", 1)
                    props.setdefault(k.strip(), v.strip())
            entries = [
                e
                for e in _parse_7z_list(out)
                if e.get("Folder", "-") != "+" and not e.get("Attributes", "").startswith("D")
            ]
            if code != 0 and any(m in out for m in ("ERRORS:", "Unexpected end", "Headers Error", "Data Error")):
                raise RemedyError("圧縮ファイルが途中で切れているか壊れているため、作り直せません")
            return props, entries, (None if pw == NO_PASSWORD else pw)
        if not any(m in out for m in WRONG_PW_MARKERS):
            raise RemedyError(f"圧縮ファイルを開けませんでした（{_short_output(out, path, os.path.dirname(path))}）")
    raise RemedyError(
        "圧縮ファイルの一覧が暗号化されていて、手元のパスワードでは開けません（検査の画面でパスワードを入れ直してください）"
    )


def _extract_with_7z(path: str, native: str, dest_dir: str, env: ArchiveEnv, kind: str) -> tuple[str, str | None]:
    """7-Zip で項目を1つだけ取り出す。（取り出したファイル, 使えたパスワード）。開けなければ RemedyError。"""
    from .formats.archive import NO_PASSWORD

    exe = _need_sevenzip(env, "この項目を取り出す")
    common = ["-sccUTF-8", "-scsUTF-8"] + (["-mcp=932"] if kind == "zip" else [])
    listdir = env.new_dir()
    listfile = os.path.join(listdir, "_list.txt")
    with open(listfile, "w", encoding="utf-8") as f:
        f.write(native)
    dest = os.path.join(dest_dir, _leaf_file_name(native))
    for pw in [NO_PASSWORD] + env.passwords:
        outdir = env.new_dir()
        code, out = _sevenzip_run(exe, ["x", "-y", f"-o{outdir}", f"-p{pw}", "-spd"] + common + [path, f"@{listfile}"])
        target = os.path.join(outdir, native.replace("/", os.sep))
        if code == 0 and os.path.isfile(target):
            shutil.move(target, dest)
            return dest, (None if pw == NO_PASSWORD else pw)
    raise RemedyError(
        "圧縮ファイルの中のファイルを取り出せませんでした（パスワードが手元に無い・違う、または壊れている可能性）。"
        "検査の画面でパスワードを入れ直してから、もう一度お試しください"
    )


# ---------------------------------------------------------------- 項目・形式ごとの扱い


@dataclass
class Entry:
    """書庫の中の項目1つ。"""

    name: str  # 検査のパス（外!内）に出る名前
    native: str  # その書庫の中での名前そのもの
    index: int = 0  # 書庫の中の並びの番号（同じ名前が重なっても選べる）
    encrypted: bool = False
    size: int = 0


class Handler:
    """書庫の形式ごとの扱いの共通部分。"""

    kind = ""
    writable = False
    single = False
    password: str | None = None  # 取り出しに使えたパスワード（暗号化されているとき）

    def entries(self) -> list[Entry]:  # pragma: no cover
        raise NotImplementedError

    def extract(self, entry: Entry, dest_dir: str) -> str:  # pragma: no cover
        raise NotImplementedError

    def rebuild(self, dst: str, entry: Entry, new_file: str | None) -> list[str]:
        raise RemedyError(f"{kind_label(self.kind)} の圧縮ファイルは書き換えられません")

    def signed(self) -> bool:
        return False

    def encryption_text(self) -> str:
        return ""


# ---- zip


def _zip_extra_ids(extra: bytes) -> dict[int, bytes]:
    out: dict[int, bytes] = {}
    i = 0
    while i + 4 <= len(extra):
        tid, ln = struct.unpack_from("<HH", extra, i)
        out.setdefault(tid, extra[i + 4 : i + 4 + ln])
        i += 4 + ln
    return out


def _strip_extra(extra: bytes, drop: set[int]) -> bytes:
    """追加フィールドから、指定の番号のものを除く（壊れた末尾はそのまま残す）。"""
    out = b""
    i = 0
    while i + 4 <= len(extra):
        tid, ln = struct.unpack_from("<HH", extra, i)
        if i + 4 + ln > len(extra):
            out += extra[i:]
            return out
        if tid not in drop:
            out += extra[i : i + 4 + ln]
        i += 4 + ln
    return out + extra[i:]


def _aes_info(extra: bytes) -> tuple[int, int] | None:
    """AES 暗号化の追加フィールド（0x9901）から（強度 1〜3, 実際の圧縮方式）。"""
    data = _zip_extra_ids(extra).get(0x9901)
    if data is None or len(data) < 7:
        return None
    return data[4], struct.unpack_from("<H", data, 5)[0]


class ZipHandler(Handler):
    kind = "zip"
    writable = True

    def __init__(self, path: str, env: ArchiveEnv):
        self.path, self.env = path, env
        try:
            with zipfile.ZipFile(path) as z:
                self._infos = list(z.infolist())
                self._comment = z.comment
        except (zipfile.BadZipFile, OSError) as e:
            raise RemedyError(f"zip として読み取れませんでした（{e}）。壊れた zip は作り直せません") from None
        self._entries: list[Entry] | None = None

    def entries(self) -> list[Entry]:
        if self._entries is None:
            from .formats.archive import _fix_zip_name

            self._entries = [
                Entry(
                    name=_fix_zip_name(i),
                    native=i.filename,
                    index=n,
                    encrypted=bool(i.flag_bits & 0x1),
                    size=i.file_size,
                )
                for n, i in enumerate(self._infos)
                if not i.is_dir()
            ]
        return self._entries

    def signed(self) -> bool:
        return any(RE_SIGNATURE.match(norm_name(e.name)) for e in self.entries())

    def extract(self, entry: Entry, dest_dir: str) -> str:
        from .formats.archive import SUPPORTED_ZIP_METHODS

        info = self._infos[entry.index]
        self.env.need_space(info.file_size)
        dest = os.path.join(dest_dir, _leaf_file_name(entry.name))
        encrypted = bool(info.flag_bits & 0x1)
        if info.compress_type in SUPPORTED_ZIP_METHODS:
            if not encrypted:
                with zipfile.ZipFile(self.path) as z, z.open(info) as src, open(dest, "wb") as dst:
                    shutil.copyfileobj(src, dst, CHUNK)
                return dest
            for pw in self.env.passwords:  # ZipCrypto は Python で試す（AES は 7-Zip）
                for enc in ("utf-8", "cp932"):
                    try:
                        with (
                            zipfile.ZipFile(self.path) as z,
                            z.open(info, pwd=pw.encode(enc)) as src,
                            open(dest, "wb") as dst,
                        ):
                            shutil.copyfileobj(src, dst, CHUNK)
                        self.password = pw
                        return dest
                    except (RuntimeError, zipfile.BadZipFile, ValueError, UnicodeEncodeError):
                        continue
        path, pw = _extract_with_7z(self.path, info.filename, dest_dir, self.env, "zip")
        if encrypted:
            self.password = pw
        return path

    def encryption_text(self) -> str:
        return ""

    # -- 作り直し

    def rebuild(self, dst: str, entry: Entry, new_file: str | None) -> list[str]:
        notes: list[str] = []
        infos = self._infos
        target = infos[entry.index]
        replacement = self._make_replacement(target, new_file, notes) if new_file is not None else None
        if infos and min(i.header_offset for i in infos) != 0:
            raise RemedyError("zip の先頭に余分なデータ（自己解凍の部分など）があるため、作り直せません")
        force64 = _had_zip64_end(self.path)
        with open(self.path, "rb") as src, open(dst, "wb") as out:
            records: list[bytes] = []
            for n, info in enumerate(infos):
                offset = out.tell()
                name_bytes = info.orig_filename.encode("utf-8" if info.flag_bits & 0x800 else "cp437")
                if n == entry.index:
                    if replacement is None:
                        continue
                    tmp_path, tmp_info = replacement
                    flag = (tmp_info.flag_bits & ~0x800) | (info.flag_bits & 0x800)
                    with open(tmp_path, "rb") as tsrc:
                        _copy_entry(out, tsrc, tmp_info, name_bytes, bool(info.flag_bits & 0x800))
                    hybrid = copy.copy(tmp_info)
                    hybrid.create_system = info.create_system
                    hybrid.external_attr = info.external_attr
                    hybrid.internal_attr = info.internal_attr
                    hybrid.comment = info.comment
                    records.append(_central_record(hybrid, name_bytes, flag, offset))
                else:
                    _copy_entry(out, src, info)
                    records.append(_central_record(info, name_bytes, info.flag_bits, offset))
            cd_start = out.tell()
            for rec in records:
                out.write(rec)
            _write_end(out, len(records), cd_start, out.tell() - cd_start, self._comment, force64)
            out.flush()
            os.fsync(out.fileno())
        return notes

    def _make_replacement(self, target: zipfile.ZipInfo, new_file: str, notes: list[str]):
        """対象の項目の新しい中身を、元と同じ圧縮方式（暗号化も同じ方式）の zip の項目にして返す（作業用の zip と ZipInfo）。"""
        from .formats.archive import SUPPORTED_ZIP_METHODS

        work = self.env.new_dir()
        out = os.path.join(work, "r.zip")
        if target.flag_bits & 0x1:
            return self._encrypted_replacement(target, new_file, out, notes)
        method = target.compress_type
        if method not in SUPPORTED_ZIP_METHODS:
            notes.append(f"元の圧縮方式（コード {method}）では書けないため、この項目は deflate にしました")
            method = zipfile.ZIP_DEFLATED
        zi = zipfile.ZipInfo("x", date_time=target.date_time)
        zi.compress_type = method
        zi.external_attr = target.external_attr
        size = os.path.getsize(new_file)
        with (
            zipfile.ZipFile(out, "w") as tz,
            open(new_file, "rb") as s,
            tz.open(zi, "w", force_zip64=size >= ZIP64_LIMIT) as w,
        ):
            shutil.copyfileobj(s, w, CHUNK)
        with zipfile.ZipFile(out) as tz:
            info = tz.infolist()[0]
        return out, info

    def _encrypted_replacement(self, target: zipfile.ZipInfo, new_file: str, out: str, notes: list[str]):
        exe = _need_sevenzip(self.env, "パスワードつきの zip の項目を入れ直す")
        pw = self.password
        if not pw:
            raise RemedyError("この項目のパスワードが手元に無いため、暗号化し直せません")
        aes = target.compress_type == 99
        if not pw.isascii():
            raise RemedyError(
                "パスワードつきの zip は、7-Zip の制限で、パスワードに英数字・記号以外の文字があると暗号化し直せません"
                "（元の圧縮ファイルは変えていません）"
            )
        aes_info = _aes_info(target.extra) if aes else None
        actual = (aes_info[1] if aes_info else 8) if aes else target.compress_type
        mm = {0: "Copy", 8: "Deflate", 12: "BZip2", 14: "LZMA"}.get(actual, "Deflate")
        if mm == "Deflate" and actual != 8:
            notes.append("元の圧縮方式では書けないため、この項目は deflate にしました")
        if aes and aes_info and aes_info[0] != 3:
            notes.append("元の暗号の強さは AES-256 ではありませんでしたが、この項目は AES-256 で暗号化しました")
        stage = self.env.new_dir()
        member = os.path.join(stage, "member.bin")
        shutil.copyfile(new_file, member)
        try:
            t = time.mktime(tuple(target.date_time) + (0, 0, -1))
            os.utime(
                member, (t, t)
            )  # 日時を元に合わせる（ZipCrypto の確認の 1 バイトが時刻に依存するため、7-Zip の書いた値を使う）
        except (OverflowError, ValueError, OSError):
            pass
        code, text = _sevenzip_run(
            exe,
            ["a", "-tzip", "-y", f"-p{pw}", f"-mem={'AES256' if aes else 'ZipCrypto'}", f"-mm={mm}", out, "member.bin"],
            cwd=stage,
        )
        if code != 0 or not os.path.isfile(out):
            raise RemedyError(f"7-Zip で項目を暗号化し直せませんでした（{_short_output(text, stage)}）")
        with zipfile.ZipFile(out) as tz:
            infos = tz.infolist()
        if len(infos) != 1 or not (infos[0].flag_bits & 0x1):
            raise RemedyError("7-Zip が作った項目が暗号化されていませんでした")
        return out, infos[0]


def _had_zip64_end(path: str) -> bool:
    """元の zip が ZIP64 の終端レコードを持っていたか（持っていたなら、作り直しても持たせる）。"""
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            f.seek(max(0, size - 70000))
            tail = f.read()
    except OSError:
        return False
    i = tail.rfind(b"PK\x05\x06")
    return i >= 20 and tail[i - 20 : i - 16] == b"PK\x06\x07"


def _read_descriptor(src, info: zipfile.ZipInfo, local_extra: bytes) -> bytes:
    """データのあとのデータ記述子（署名つき・なし、4 バイト幅・8 バイト幅）を、そのまま読み取る。"""
    pos = src.tell()
    buf = src.read(24)
    crc_le = struct.pack("<L", info.CRC)
    prefer = 8 if 1 in _zip_extra_ids(local_extra) else 4
    for w in (prefer, 12 - prefer):
        if buf[:4] == b"PK\x07\x08" and buf[4:8] == crc_le:
            n = 4 + 4 + 2 * w
        elif buf[:4] == crc_le:
            n = 4 + 2 * w
        else:
            continue
        src.seek(pos + n)
        nxt = src.read(2)
        if nxt == b"PK" or len(buf) == n:
            src.seek(pos + n)
            return buf[:n]
    raise RemedyError("zip のデータ記述子を読み取れませんでした（壊れた zip の可能性）。作り直しません")


def _copy_entry(out, src, info: zipfile.ZipInfo, name_bytes: bytes | None = None, utf8: bool = False) -> None:
    """zip の項目1つ（局所ヘッダー・圧縮済みデータ・データ記述子）を、そのまま out へ写す。

    name_bytes を渡したときだけ、局所ヘッダーの名前（と UTF-8 の印）をその値に差し替える（対象の項目を入れ直すとき）。
    """
    src.seek(info.header_offset)
    hdr = src.read(30)
    if len(hdr) < 30 or hdr[:4] != b"PK\x03\x04":
        raise RemedyError("zip の項目の見出しを読み取れませんでした（壊れた zip の可能性）。作り直しません")
    sig, ver, flag, method, t, d, crc, cs32, us32, fnlen, elen = struct.unpack("<4sHHHHHLLLHH", hdr)
    name = src.read(fnlen)
    extra = src.read(elen)
    if name_bytes is not None:
        flag = (flag | 0x800) if utf8 else (flag & ~0x800)
        hdr = struct.pack("<4sHHHHHLLLHH", sig, ver, flag, method, t, d, crc, cs32, us32, len(name_bytes), elen)
        name = name_bytes
    out.write(hdr)
    out.write(name)
    out.write(extra)
    remaining = info.compress_size
    while remaining > 0:
        chunk = src.read(min(CHUNK, remaining))
        if not chunk:
            raise RemedyError("zip のデータが途中で切れています（壊れた zip の可能性）。作り直しません")
        out.write(chunk)
        remaining -= len(chunk)
    if flag & 0x8:
        out.write(_read_descriptor(src, info, extra))


def _central_record(info: zipfile.ZipInfo, name_bytes: bytes, flag: int, offset: int) -> bytes:
    """中央ディレクトリの1項目を、ZipInfo の値から作る（ZIP64 の追加フィールドは必要なときだけ作り直す）。"""
    usize, csize = info.file_size, info.compress_size
    z64: list[int] = []
    us, cs, off = usize, csize, offset
    if usize >= ZIP64_LIMIT:
        z64.append(usize)
        us = 0xFFFFFFFF
    if csize >= ZIP64_LIMIT:
        z64.append(csize)
        cs = 0xFFFFFFFF
    if offset >= ZIP64_LIMIT:
        z64.append(offset)
        off = 0xFFFFFFFF
    extra = _strip_extra(info.extra, {1})
    if z64:
        extra = struct.pack("<HH", 1, 8 * len(z64)) + struct.pack("<" + "Q" * len(z64), *z64) + extra
    need = max(info.extract_version, 45) if z64 else info.extract_version
    dt = info.date_time
    dos_date = ((dt[0] - 1980) << 9) | (dt[1] << 5) | dt[2]
    dos_time = getattr(info, "_raw_time", None)
    if dos_time is None:
        dos_time = (dt[3] << 11) | (dt[4] << 5) | (dt[5] // 2)
    head = struct.pack(
        "<4s4B4HL2L5H2L",
        b"PK\x01\x02",
        info.create_version,
        info.create_system,
        need,
        info.reserved,
        flag,
        info.compress_type,
        dos_time,
        dos_date,
        info.CRC,
        cs,
        us,
        len(name_bytes),
        len(extra),
        len(info.comment),
        0,
        info.internal_attr,
        info.external_attr,
        off,
    )
    return head + name_bytes + extra + info.comment


def _write_end(out, count: int, cd_offset: int, cd_size: int, comment: bytes, force64: bool) -> None:
    """中央ディレクトリの終わり（必要なとき、または元がそうだったときは ZIP64 の終端レコードも）を書く。"""
    n16, size32, off32 = min(count, 0xFFFF), min(cd_size, 0xFFFFFFFF), min(cd_offset, 0xFFFFFFFF)
    if force64 or count >= 0xFFFF or cd_size >= 0xFFFFFFFF or cd_offset >= 0xFFFFFFFF:
        pos = out.tell()
        out.write(struct.pack("<4sQ2H2L4Q", b"PK\x06\x06", 44, 45, 45, 0, 0, count, count, cd_size, cd_offset))
        out.write(struct.pack("<4sLQL", b"PK\x06\x07", 0, pos, 1))
    out.write(struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, n16, n16, size32, off32, len(comment)))
    out.write(comment)


# ---- 7z と、書けない形式（rar・cab・iso など。7-Zip で読む）


class SevenZipHandler(Handler):
    """7z（7-Zip の更新で作り直せる）と、書けない形式（rar・cab・iso など。zip に作り直すことだけができる）。"""

    def __init__(self, path: str, env: ArchiveEnv, kind: str):
        self.path, self.env, self.kind = path, env, kind
        self.writable = kind == "7z"
        self.single = kind in SINGLE_KINDS
        self.props, raw, self.header_pw = _list_7z(path, env, kind)
        if any(not e.get("Path") for e in raw):
            raise RemedyError("名前の無い項目のある形式のため、中のファイルを選べません")
        if not raw:
            raise RemedyError("圧縮ファイルの中にファイルが見つかりません")
        self._entries = [
            Entry(
                name=norm_name(e["Path"]),
                native=e["Path"],
                index=n,
                encrypted=e.get("Encrypted") == "+",
                size=int(e.get("Size") or 0),
            )
            for n, e in enumerate(raw)
        ]
        self._raw = raw
        self.password = self.header_pw

    def entries(self) -> list[Entry]:
        return self._entries

    def encrypted(self) -> bool:
        return bool(self.header_pw) or any(e.encrypted for e in self._entries)

    def extract(self, entry: Entry, dest_dir: str) -> str:
        self.env.need_space(entry.size)
        path, pw = _extract_with_7z(self.path, entry.native, dest_dir, self.env, self.kind)
        if pw:
            self.password = pw
        return path

    def extract_all(self, out_dir: str) -> None:
        """全部の項目を out_dir へ取り出す（zip に作り直すとき）。"""
        from .formats.archive import NO_PASSWORD

        exe = _need_sevenzip(self.env, "この形式の圧縮ファイルを読む")
        self.env.need_space(sum(e.size for e in self._entries))
        code, out = _sevenzip_run(
            exe,
            ["x", "-y", f"-o{out_dir}", f"-p{NO_PASSWORD}", "-sccUTF-8", "-scsUTF-8"] + [self.path],
        )
        if code != 0:
            raise RemedyError(f"圧縮ファイルを取り出せませんでした（{_short_output(out, self.path, out_dir)}）")

    def _method_switches(self) -> list[str]:
        """元の書庫の圧縮方式・まとめ圧縮（solid）の設定を、更新のときの指定にする。"""
        sw: list[str] = []
        method = self.props.get("Method", "")
        for tok in method.split():
            name, _, rest = tok.partition(":")
            low = name.lower()
            if "aes" in low:
                continue
            canon = {
                "lzma2": "LZMA2",
                "lzma": "LZMA",
                "ppmd": "PPMd",
                "bzip2": "BZip2",
                "deflate": "Deflate",
                "copy": "Copy",
            }
            if low in canon:
                spec = f"-m0={canon[low]}"
                if low in ("lzma2", "lzma") and rest.isdigit() and 12 <= int(rest) <= 30:
                    spec += f":d={1 << int(rest)}b"
                sw.append(spec)
                break
        solid = self.props.get("Solid")
        if solid in ("+", "-"):
            sw.append("-ms=on" if solid == "+" else "-ms=off")
        return sw

    def rebuild(self, dst: str, entry: Entry, new_file: str | None) -> list[str]:
        if not self.writable:
            return super().rebuild(dst, entry, new_file)
        from .formats.archive import NO_PASSWORD

        exe = _need_sevenzip(self.env, "7z 圧縮ファイルを作り直す")
        notes: list[str] = []
        work = self.env.new_dir()
        arch = os.path.join(work, "w.7z")
        shutil.copyfile(self.path, arch)
        common = ["-y", "-spd", "-sccUTF-8", "-scsUTF-8"]
        if entry.native.startswith(("-", "@")):
            raise RemedyError("名前が「-」「@」で始まる項目は、7-Zip で更新できません")
        pw = self.password
        mhe = ["-mhe=on"] if self.header_pw else []
        if new_file is None:
            listfile = os.path.join(work, "_del.txt")
            with open(listfile, "w", encoding="utf-8") as f:
                f.write(entry.native)
            code, text = _sevenzip_run(exe, ["d"] + common + [f"-p{pw or NO_PASSWORD}"] + mhe + [arch, f"@{listfile}"])
        else:
            stage = self.env.new_dir()
            member = os.path.join(stage, entry.native.replace("/", os.sep))
            if os.path.isabs(entry.native) or ":" in entry.native or ".." in norm_name(entry.native).split("/"):
                raise RemedyError("名前に「..」やドライブ名を含む項目は、7-Zip で更新できません")
            os.makedirs(os.path.dirname(member), exist_ok=True)
            shutil.copyfile(new_file, member)
            now = time.time()
            os.utime(member, (now, now))  # 書庫の中の項目より新しい日時にして、7-Zip に更新させる
            pw_args = [f"-p{pw}"] if pw else []
            code, text = _sevenzip_run(
                exe,
                ["u"] + common + pw_args + mhe + self._method_switches() + [arch, entry.native.replace("/", os.sep)],
                cwd=stage,
            )
        if code not in (0, 1) or not os.path.isfile(arch):
            raise RemedyError(f"7-Zip で圧縮ファイルを更新できませんでした（{_short_output(text, work)}）")
        # 更新できたか確かめる（項目の大きさが新しい中身と同じ・取り除いたときは名前が消えている）
        _, after, _ = _list_7z(arch, _SubEnv(self.env, [pw] if pw else []), "7z")
        found = [e for e in after if norm_name(e["Path"]) == entry.name]
        if new_file is None and found:
            raise RemedyError("7-Zip が項目を取り除きませんでした（元の圧縮ファイルは変えていません）")
        if new_file is not None and (not found or int(found[0].get("Size") or -1) != os.path.getsize(new_file)):
            raise RemedyError("7-Zip が項目を更新しませんでした（元の圧縮ファイルは変えていません）")
        if self.props.get("Solid") == "+":
            notes.append("まとめて圧縮（solid）の圧縮ファイルのため、7-Zip が含まれる塊を圧縮し直しました")
        shutil.copyfile(arch, dst)
        return notes

    def encryption_text(self) -> str:
        if not self.encrypted():
            return ""
        return "7z の暗号（AES-256）" + ("・見出しも暗号化" if self.header_pw else "")


def _SubEnv(env: ArchiveEnv, passwords: list[str]) -> ArchiveEnv:
    """パスワード候補だけを差し替えた環境（更新したばかりの書庫の確かめ用）。"""
    return ArchiveEnv(env.sevenzip, passwords, env.workdir)


# ---- tar


class TarHandler(Handler):
    kind = "tar"
    writable = True

    def __init__(self, path: str, env: ArchiveEnv):
        self.path, self.env = path, env
        try:
            with tarfile.open(path, "r:", ignore_zeros=True) as tf:
                self._members = tf.getmembers()
        except (tarfile.TarError, OSError) as e:
            raise RemedyError(f"tar を読み取れませんでした（{e}）") from None
        self._entries = [
            Entry(name=m.name, native=m.name, index=n, size=m.size) for n, m in enumerate(self._members) if m.isfile()
        ]

    def entries(self) -> list[Entry]:
        return self._entries

    def extract(self, entry: Entry, dest_dir: str) -> str:
        self.env.need_space(entry.size)
        dest = os.path.join(dest_dir, _leaf_file_name(entry.name))
        with tarfile.open(self.path, "r:", ignore_zeros=True) as tf:
            src = tf.extractfile(tf.getmembers()[entry.index])
            if src is None:
                raise RemedyError("tar の中のファイルを取り出せませんでした")
            with src, open(dest, "wb") as dst:
                shutil.copyfileobj(src, dst, CHUNK)
        return dest

    def rebuild(self, dst: str, entry: Entry, new_file: str | None) -> list[str]:
        with open(self.path, "rb") as f:
            head = f.read(512)
        fmt = tarfile.GNU_FORMAT if head[257:265] == b"ustar  \x00" else tarfile.PAX_FORMAT
        notes: list[str] = []
        if any(m.issparse() for m in self._members):
            raise RemedyError("疎なファイル（sparse）を含む tar は作り直せません")
        with tarfile.open(self.path, "r:", ignore_zeros=True) as src, tarfile.open(dst, "w", format=fmt) as out:
            for n, m in enumerate(src.getmembers()):
                if n == entry.index:
                    if new_file is None:
                        continue
                    ni = copy.copy(m)
                    ni.size = os.path.getsize(new_file)
                    ni.pax_headers = {k: v for k, v in m.pax_headers.items() if k != "size"}
                    with open(new_file, "rb") as f:
                        out.addfile(ni, f)
                elif m.isreg():
                    f = src.extractfile(m)
                    out.addfile(m, f)
                else:
                    out.addfile(m)
        return notes


# ---- gz・bz2・xz（1ファイルを包む形式）


def single_entry_name(kind: str, name: str) -> str:
    """1ファイルを包む形式の、中のファイルの名前（検査と同じ決め方: 拡張子を外し、.tgz などは .tar にする）。"""
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    for s in SINGLE_SUFFIXES.get(kind, ()):
        if base.lower().endswith(s):
            return base[: -len(s)] + (".tar" if s.startswith(".t") else "")
    return base


class SingleHandler(Handler):
    single = True
    writable = True

    def __init__(self, path: str, env: ArchiveEnv, kind: str, name_hint: str):
        self.path, self.env, self.kind = path, env, kind
        name = single_entry_name(kind, name_hint or os.path.basename(path))
        self._entries = [Entry(name=name, native=name, index=0, size=0)]

    def entries(self) -> list[Entry]:
        return self._entries

    def _open(self):
        if self.kind == "gzip":
            return gzip.open(self.path, "rb")
        if self.kind == "bzip2":
            return bz2.open(self.path, "rb")
        return lzma.open(self.path, "rb")

    def extract(self, entry: Entry, dest_dir: str) -> str:
        dest = os.path.join(dest_dir, _leaf_file_name(entry.name))
        written = 0
        try:
            with self._open() as src, open(dest, "wb") as dst:
                while True:
                    chunk = src.read(CHUNK)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written % (64 * CHUNK) < len(chunk):
                        self.env.need_space(64 * CHUNK)
                    dst.write(chunk)
        except (EOFError, OSError, lzma.LZMAError, zlib.error) as e:
            raise RemedyError(
                f"圧縮データが壊れているか途中で切れているため、作り直せません（{type(e).__name__}）"
            ) from None
        return dest

    def rebuild(self, dst: str, entry: Entry, new_file: str | None) -> list[str]:
        if new_file is None:
            raise RemedyError(
                "1ファイルを包んだだけの形式（gz・bz2・xz）では、中のファイルだけを取り除けません。圧縮ファイルごとの削除を選んでください"
            )
        if self.kind == "gzip":
            self._write_gzip(dst, new_file)
        elif self.kind == "bzip2":
            with open(self.path, "rb") as f:
                head = f.read(4)
            level = int(head[3:4]) if head[3:4].isdigit() else 9
            comp = bz2.BZ2Compressor(max(1, level))
            with open(new_file, "rb") as src, open(dst, "wb") as out:
                for chunk in iter(lambda: src.read(CHUNK), b""):
                    out.write(comp.compress(chunk))
                out.write(comp.flush())
        else:
            with open(self.path, "rb") as f:
                head = f.read(12)
            check = head[7] & 0x0F if len(head) >= 8 else lzma.CHECK_CRC64
            if check not in (lzma.CHECK_NONE, lzma.CHECK_CRC32, lzma.CHECK_CRC64, lzma.CHECK_SHA256):
                check = lzma.CHECK_CRC64
            comp = lzma.LZMACompressor(format=lzma.FORMAT_XZ, check=check, preset=6)
            with open(new_file, "rb") as src, open(dst, "wb") as out:
                for chunk in iter(lambda: src.read(CHUNK), b""):
                    out.write(comp.compress(chunk))
                out.write(comp.flush())
        return []

    def _write_gzip(self, dst: str, new_file: str) -> None:
        """元の gzip の見出し（日時・元のファイル名・圧縮の速さの印・OS）を保って、1つのメンバーで包み直す。"""
        with open(self.path, "rb") as f:
            h = f.read(10)
            mtime, xfl, os_code = struct.unpack("<I", h[4:8])[0], h[8], h[9]
            fname = b""
            flg = h[3]
            if flg & 4:
                (xlen,) = struct.unpack("<H", f.read(2))
                f.read(xlen)
            if flg & 8:
                buf = b""
                while True:
                    c = f.read(1)
                    if not c or c == b"\0":
                        break
                    buf += c
                fname = buf
        level = 9 if xfl == 2 else 1 if xfl == 4 else 6
        comp = zlib.compressobj(level, zlib.DEFLATED, -15)
        crc = size = 0
        with open(new_file, "rb") as src, open(dst, "wb") as out:
            out.write(b"\x1f\x8b\x08" + bytes([8 if fname else 0]) + struct.pack("<I", mtime) + bytes([xfl, os_code]))
            if fname:
                out.write(fname + b"\0")
            for chunk in iter(lambda: src.read(CHUNK), b""):
                crc = zlib.crc32(chunk, crc)
                size += len(chunk)
                out.write(comp.compress(chunk))
            out.write(comp.flush())
            out.write(struct.pack("<II", crc & 0xFFFFFFFF, size & 0xFFFFFFFF))


# ---------------------------------------------------------------- 入れ子をたどる


@dataclass
class Hop:
    """入れ子の1段（この書庫の、この項目を取り出して次へ）。"""

    handler: Handler
    entry: Entry
    path: str  # この段の書庫のファイル（最初は元のファイル、次からは作業フォルダの中）
    name: str  # この段の書庫の名前（形式の見分けと表示用）


@dataclass
class Resolved:
    """検査のパスをたどって、対象の項目を取り出した結果。"""

    hops: list[Hop]
    leaf_path: str
    leaf_name: str
    rest: str  # 元のファイルから対象までの、書庫の中のパス（外!内）

    def describe(self) -> dict:
        """画面・下見に出す、書庫の情報（値は含まない）。"""
        levels = []
        for h in self.hops:
            levels.append(
                {
                    "kind": h.handler.kind,
                    "label": kind_label(h.handler.kind),
                    "writable": h.handler.writable,
                    "single": h.handler.single,
                    "encrypted": bool(h.handler.password) or h.entry.encrypted,
                    "encryption": h.handler.encryption_text() or ("パスワードつき" if h.handler.password else ""),
                    "name": h.entry.name,
                    "signed": h.handler.signed(),
                }
            )
        top = self.hops[0].handler
        inner_ok = all(lv["writable"] for lv in levels[1:])
        can_write = all(lv["writable"] for lv in levels)
        encrypted = any(lv["encrypted"] for lv in levels)
        convert_reason = ""
        can_convert = False
        if not can_write:
            if not inner_ok:
                convert_reason = "入れ子の途中に、書き換えられない形式（rar・cab・iso など）の圧縮ファイルがあります"
            elif encrypted or (isinstance(top, SevenZipHandler) and top.encrypted()):
                convert_reason = "パスワードつきの圧縮ファイルは、zip に作り直すと暗号が外れてしまうため作り直せません"
            else:
                can_convert = True
        return {
            "levels": levels,
            "top_kind": top.kind,
            "top_label": kind_label(top.kind),
            "can_write": can_write,
            "can_convert": can_convert,
            "convert_reason": convert_reason,
            "single": levels[-1]["single"],
            "signed": any(lv["signed"] for lv in levels),
            "encrypted": encrypted,
            "encryption": "・".join(lv["encryption"] for lv in levels if lv["encryption"]),
            "item": self.rest,
        }


def open_handler(path: str, env: ArchiveEnv, name_hint: str) -> Handler:
    kind = sniff_kind(path, name_hint)
    if kind not in ARCHIVE_KINDS:
        from . import sniff

        label = sniff.KIND_LABELS.get(kind, kind)
        raise RemedyError(
            f"「{label}」は圧縮ファイルとして扱わないため、中のファイルだけを書き換えることはできません"
            "（Office 文書など、zip の形をした文書は、その形式の対処で扱います）"
        )
    if kind == "zip":
        return ZipHandler(path, env)
    if kind == "tar":
        return TarHandler(path, env)
    if kind in ("gzip", "bzip2", "xz"):
        return SingleHandler(path, env, kind, name_hint)
    return SevenZipHandler(path, env, kind)


def _match_entry(entries: list[Entry], rest: str) -> tuple[Entry, str]:
    """rest（外!内 の先頭からの残り）が指す項目と、その項目を除いた残りを返す。名前に ! を含む項目にも対応する。"""
    target = norm_name(rest)
    exact = [e for e in entries if norm_name(e.name) == target]
    if exact:
        return exact[0], ""
    best = None
    for e in entries:
        n = norm_name(e.name)
        if target.startswith(n + "!") and (best is None or len(n) > len(norm_name(best.name))):
            best = e
    if best is None:
        raise RemedyError(
            "圧縮ファイルの中に、その項目が見つかりません（圧縮ファイルが検査のあとに変わった、または名前を読み違えた可能性）。もう一度検査してください"
        )
    return best, rest[len(best.name) + 1 :]


def extract_target(top_path: str, item_path: str, env: ArchiveEnv) -> Resolved:
    """検査のパス（外!内!…）をたどって、対象の項目を作業フォルダへ取り出す。"""
    if not item_path.startswith(top_path + "!"):
        raise RemedyError("圧縮ファイルの中のパスが正しくありません")
    rest_all = item_path[len(top_path) + 1 :]
    rest = rest_all
    cur = top_path
    name = os.path.basename(top_path)
    hops: list[Hop] = []
    for _depth in range(64):
        handler = open_handler(cur, env, name)
        entry, rest = _match_entry(handler.entries(), rest)
        leaf = handler.extract(entry, env.new_dir())
        hops.append(Hop(handler, entry, cur, name))
        if not rest:
            return Resolved(hops, leaf, os.path.basename(leaf), rest_all)
        cur, name = leaf, entry.name
    raise RemedyError("入れ子が深すぎます")


# ---------------------------------------------------------------- 作り直し（入れ子は内側から）


def zip_target_for(top_path: str) -> str:
    """zip に作り直すときの新しいファイルの名前（同じフォルダの「元の名前.zip」。拡張子を zip にする）。"""
    stem, _ext = os.path.splitext(top_path)
    return stem + ".zip"


def convert_to_zip(handler: SevenZipHandler, dst: str, entry: Entry, new_file: str | None, env: ArchiveEnv) -> None:
    """書けない形式の書庫（rar・cab・iso など）を、zip に作り直す（対象の項目だけ差し替え・取り除き）。"""
    if handler.encrypted():
        raise RemedyError("パスワードつきの圧縮ファイルは、zip に作り直すと暗号が外れてしまうため作り直せません")
    out_dir = env.new_dir()
    handler.extract_all(out_dir)
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as z:
        for e in handler.entries():
            if e.index == entry.index and new_file is None:
                continue
            src = new_file if e.index == entry.index else os.path.join(out_dir, e.native.replace("/", os.sep))
            if not os.path.isfile(src):
                raise RemedyError(f"圧縮ファイルから「{e.name}」を取り出せなかったため、zip に作り直せません")
            lt = time.localtime(os.path.getmtime(src) if e.index != entry.index else time.time())
            date_time = (max(lt.tm_year, 1980), lt.tm_mon, lt.tm_mday, lt.tm_hour, lt.tm_min, lt.tm_sec)
            zi = zipfile.ZipInfo(norm_name(e.name), date_time=date_time)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = 0o644 << 16
            size = os.path.getsize(src)
            with open(src, "rb") as s, z.open(zi, "w", force_zip64=size >= ZIP64_LIMIT) as w:
                shutil.copyfileobj(s, w, CHUNK)


def rebuild_target(res: Resolved, new_leaf: str | None, env: ArchiveEnv, dst: str, convert_zip: bool) -> list[str]:
    """対象の項目を差し替え（new_leaf）または取り除き（None）て、書庫を作り直す。結果は dst（最も外側の書庫）。

    入れ子は内側から順に作り直し、できた書庫を1つ外側の書庫の項目として差し替える。
    """
    notes: list[str] = []
    new = new_leaf
    for depth in range(len(res.hops) - 1, -1, -1):
        hop = res.hops[depth]
        out = dst if depth == 0 else os.path.join(env.new_dir(), _leaf_file_name(hop.entry.name))
        if depth == 0 and convert_zip:
            if hop.handler.writable:
                raise RemedyError("この形式はそのまま書き換えられるため、zip に作り直す必要はありません")
            if not isinstance(hop.handler, SevenZipHandler):
                raise RemedyError("この形式は zip に作り直せません")
            convert_to_zip(hop.handler, out, hop.entry, new, env)
        else:
            if not hop.handler.writable:
                raise RemedyError(
                    f"{kind_label(hop.handler.kind)} の圧縮ファイルは書き換えられません。"
                    "最も外側の圧縮ファイルなら「zip に作り直す」を選べます"
                )
            notes += hop.handler.rebuild(out, hop.entry, new)
        new = out
    return notes

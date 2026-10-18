"""アーカイブの展開（zip・7z・rar・lzh・cab・arj・iso・tar・gz/bz2/xz）。

- 暗号化された項目は、受け取ったパスワード候補を全部試す。開けなければ「要パスワード」として残す。
- 展開した中身は1つずつ再帰的に検査する（アーカイブの中のアーカイブも同じ）。
- 7-Zip（7z.exe）があれば、Python で読めない形式や AES 暗号化 zip もそれで展開する。
"""

from __future__ import annotations

import bz2
import gzip
import lzma
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

from ..engine import (
    IN_MEMORY_LIMIT,
    Blob,
    Collector,
    ItemResult,
    NeedPassword,
    ScanContext,
    Uncheckable,
    long_path,
)
from .. import safeio
from ..models import Status

NO_PASSWORD = (
    "\x01PII_CHECKER_NO_PASSWORD\x01"  # 7z に「パスワードなし」を伝えるための値（対話で止まらないように常に渡す）
)
SUPPORTED_ZIP_METHODS = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA}
CREATE_NO_WINDOW = 0x08000000


def find_7z(configured: str | None) -> str | None:
    """7z.exe を探す（設定 → 実行ファイルの隣 → Program Files → PATH）。"""
    candidates = []
    if configured:
        candidates.append(configured)
    base = Path(sys.executable).parent
    candidates += [str(base / "7z" / "7z.exe"), str(base / "7z.exe")]
    if getattr(sys, "_MEIPASS", None):
        candidates.append(str(Path(sys._MEIPASS) / "7z" / "7z.exe"))
    candidates.append(str(Path(__file__).resolve().parents[2] / "vendor" / "7zip" / "7z.exe"))
    for env in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
        if os.environ.get(env):
            candidates.append(os.path.join(os.environ[env], "7-Zip", "7z.exe"))
    w = shutil.which("7z")
    if w:
        candidates.append(w)
    for c in candidates:
        if c and os.path.isfile(c):
            return c
    return None


def _fix_zip_name(info: zipfile.ZipInfo) -> str:
    """UTF-8 フラグの無い zip の名前を cp932（日本語 Windows の既定）として読み直す。"""
    name = info.filename
    if info.flag_bits & 0x800:
        return name
    try:
        return name.encode("cp437").decode("cp932")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return name


def add_failed_item(
    ctx: ScanContext,
    display: str,
    status: Status,
    reason: str,
    depth: int,
    kind: str = "",
    password_kind: str = "",
    size: int | None = None,
) -> None:
    """展開できなかった内側のファイルを、理由つきで結果に残す（黙って捨てない）。"""
    ctx.items.append(
        ItemResult(
            path=display, kind=kind, status=status, reason=reason, depth=depth, password_kind=password_kind, size=size
        )
    )


def handle_zip(ctx: ScanContext, blob: Blob, item: ItemResult, col: Collector, depth: int) -> None:
    try:
        f = blob.open()
        z = zipfile.ZipFile(f)
    except (zipfile.BadZipFile, OSError) as e:
        if find_7z(ctx.options.sevenzip):
            item.notes.append(f"Python の zip で開けなかったため 7-Zip で展開（{e}）")
            return handle_with_7z_exe(ctx, blob, item, col, depth, kind="zip")
        raise Uncheckable(f"zip を開けなかった（壊れている可能性。7-Zip があれば再試行できる）: {e}")
    with f, z:
        infos = [i for i in z.infolist() if not i.is_dir()]
        needs_7z = any((i.flag_bits & 0x1) or i.compress_type not in SUPPORTED_ZIP_METHODS for i in infos)
        if needs_7z:
            if not find_7z(ctx.options.sevenzip):
                return _zip_python_encrypted(ctx, blob, item, z, infos, depth)
            return handle_with_7z_exe(ctx, blob, item, col, depth, kind="zip")
        item.method = f"zip を展開（{len(infos)}件）"
        for info in infos:
            name = _fix_zip_name(info)
            display = f"{blob.display}!{name}"
            try:
                data_or_path = _read_zip_member(ctx, z, info, None)
            except Uncheckable:
                raise
            except Exception as e:
                add_failed_item(
                    ctx,
                    display,
                    Status.UNCHECKABLE,
                    f"zip から取り出せなかった（{type(e).__name__}: {e}）",
                    depth + 1,
                    size=info.file_size,
                )
                continue
            _scan_extracted(ctx, display, data_or_path, depth + 1, name, info)


def _read_zip_member(ctx: ScanContext, z: zipfile.ZipFile, info: zipfile.ZipInfo, pwd: bytes | None):
    if info.file_size > IN_MEMORY_LIMIT:
        ctx.ensure_space(info.file_size)
        out = os.path.join(ctx.new_tmp_subdir(), "member")
        with z.open(info, pwd=pwd) as src, open(out, "wb") as dst:
            shutil.copyfileobj(src, dst, 1024 * 1024)
        return ("path", out)
    with z.open(info, pwd=pwd) as src:
        return ("data", src.read())


def _scan_extracted(
    ctx: ScanContext, display: str, data_or_path, depth: int, name: str, info: zipfile.ZipInfo | None = None
) -> None:
    mtime = None
    if info is not None:
        try:
            import datetime

            mtime = datetime.datetime(*info.date_time).timestamp()
        except Exception:
            mtime = None
    kind, value = data_or_path
    if kind == "data":
        ctx.scan_nested(display, data=value, depth=depth, name_hint=name, mtime=mtime)
    else:
        ctx.scan_nested(display, path=value, depth=depth, name_hint=name, mtime=mtime)


def _zip_python_encrypted(
    ctx: ScanContext, blob: Blob, item: ItemResult, z: zipfile.ZipFile, infos, depth: int
) -> None:
    """7-Zip が無いときの予備: ZipCrypto 暗号化は Python で試す（AES は検査不能として残す）。"""
    item.method = f"zip を展開（{len(infos)}件・7-Zip なし）"
    for info in infos:
        name = _fix_zip_name(info)
        display = f"{blob.display}!{name}"
        if info.compress_type not in SUPPORTED_ZIP_METHODS:
            reason = "AES 暗号化または未対応の圧縮方式のため、7-Zip が無いと展開できない（7-Zip を入れて再検査）"
            add_failed_item(ctx, display, Status.UNCHECKABLE, reason, depth + 1, size=info.file_size)
            continue
        if not (info.flag_bits & 0x1):
            try:
                _scan_extracted(ctx, display, _read_zip_member(ctx, z, info, None), depth + 1, name, info)
            except Uncheckable:
                raise
            except Exception as e:
                add_failed_item(ctx, display, Status.UNCHECKABLE, f"取り出せなかった: {e}", depth + 1)
            continue
        opened = None
        for pw in ctx.password_candidates():
            try:
                opened = _read_zip_member(ctx, z, info, pw.encode("utf-8"))
                break
            except (RuntimeError, zipfile.BadZipFile, ValueError):
                try:
                    opened = _read_zip_member(ctx, z, info, pw.encode("cp932"))
                    break
                except Exception:
                    continue
        if opened is None:
            add_failed_item(
                ctx,
                display,
                Status.NEEDS_PASSWORD,
                _pw_reason(ctx, "zip 内のファイルが暗号化されている"),
                depth + 1,
                password_kind="zip",
                size=info.file_size,
            )
            continue
        _scan_extracted(ctx, display, opened, depth + 1, name, info)


def _pw_reason(ctx: ScanContext, what: str) -> str:
    n = len(ctx.password_candidates())
    return (
        f"{what}（受け取ったパスワード {n} 個を試したが開けなかった）"
        if n
        else f"{what}（パスワードを入力すると再検査できる）"
    )


# ------------------------------------------------------------------ 7-Zip


def _run_7z(exe: str, args: list[str], timeout: int = 3600) -> subprocess.CompletedProcess:
    return subprocess.run(
        [exe] + args,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=timeout,
        creationflags=CREATE_NO_WINDOW if os.name == "nt" else 0,
    )


def _decode_7z(b: bytes) -> str:
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return b.decode("cp932", errors="replace")


def _parse_7z_list(out: str) -> list[dict]:
    """7z l -slt の出力を項目の辞書の一覧にする。"""
    entries: list[dict] = []
    body = out.split("----------", 1)
    if len(body) < 2:
        return entries
    cur: dict = {}
    for line in body[1].splitlines():
        line = line.rstrip("\r")
        if not line.strip():
            if cur.get("Path") is not None or "Size" in cur or "Packed Size" in cur:
                entries.append(cur)
            cur = {}
            continue
        if " = " in line:
            k, v = line.split(" = ", 1)
            cur[k.strip()] = v
        elif line.endswith(" ="):
            cur[line[:-2].strip()] = ""
    if cur.get("Path") is not None or "Size" in cur or "Packed Size" in cur:
        entries.append(cur)
    return entries


WRONG_PW_MARKERS = ("Wrong password", "Can not open encrypted archive", "Cannot open encrypted archive")


def handle_with_7z_exe(
    ctx: ScanContext, blob: Blob, item: ItemResult, col: Collector, depth: int, kind: str = ""
) -> None:
    """7z.exe で一覧を取り、展開して中身を検査する。暗号化はパスワード候補を全部試す。"""
    exe = find_7z(ctx.options.sevenzip)
    if not exe:
        if blob.head(6) == b"7z\xbc\xaf\x27\x1c":
            return _handle_7z_python(ctx, blob, item, col, depth)
        raise Uncheckable(
            f"{item.kind or 'このアーカイブ'}の展開には 7-Zip（7z.exe）が要るが見つからない"
            "（7-Zip を入れるか、設定で 7z.exe の場所を指定して再検査）"
        )
    path = ctx.blob_as_path(blob)
    common = ["-sccUTF-8", "-scsUTF-8"]
    if kind == "zip":
        common.append("-mcp=932")

    # 1) 一覧（ヘッダー暗号化ならパスワードが要る）
    listing = None
    header_pw = None
    broken_listing = ""
    for pw in [NO_PASSWORD] + ctx.password_candidates():
        r = _run_7z(exe, ["l", "-slt", f"-p{pw}"] + common + [path])
        out = _decode_7z(r.stdout) + _decode_7z(r.stderr)
        if r.returncode == 0 or ("----------" in out and not any(m in out for m in WRONG_PW_MARKERS)):
            listing = out
            header_pw = None if pw == NO_PASSWORD else pw
            # 一覧は取れても、途中で切れている・壊れているアーカイブは、欠けた中身があるので言い切れない
            if r.returncode != 0 or any(m in out for m in ("ERRORS:", "Unexpected end", "Headers Error", "Data Error")):
                broken_listing = out.strip()[-200:]
            break
        if not any(m in out for m in WRONG_PW_MARKERS):
            raise Uncheckable(f"7-Zip で開けなかった（壊れているか未対応）: {out.strip()[-300:]}")
    if listing is None:
        raise NeedPassword("archive", _pw_reason(ctx, "アーカイブの一覧自体が暗号化されている"))
    entries = [
        e
        for e in _parse_7z_list(listing)
        if e.get("Folder", "-") != "+" and not e.get("Attributes", "").startswith("D")
    ]
    if not entries:
        if os.path.getsize(path) > 512:
            raise Uncheckable("7-Zip で一覧を取れたが中身が1件も無い（空でないアーカイブなのに中身を取り出せない）")
        item.method = "空のアーカイブ"
        return
    if any(not e.get("Path") for e in entries):
        # 名前の無い項目がある形式（単体圧縮・入れ子を自動で開く形式）は丸ごと展開して出てきた物を全部検査する
        return _extract_all_and_scan(ctx, exe, path, blob, item, depth, common, header_pw)
    total = sum(int(e.get("Size") or 0) for e in entries)
    _check_bomb(ctx, total, os.path.getsize(path))
    encrypted = {e["Path"] for e in entries if e.get("Encrypted") == "+"}
    item.method = f"7-Zip で展開（{len(entries)}件・暗号化 {len(encrypted)}件）"
    tries = [header_pw or NO_PASSWORD] + [p for p in ctx.password_candidates() if p != header_pw]

    # 2) 一時領域を食い潰さないよう、一定量ずつ「展開→検査→片付け」を繰り返す
    for batch in _batches(entries, ctx.options.extract_batch_bytes):
        batch_size = sum(int(e.get("Size") or 0) for e in batch)
        free = safeio.free_bytes(ctx.tmpdir)
        if batch_size + safeio.reserve_bytes(ctx.tmpdir) > free:
            for e in batch:
                add_failed_item(
                    ctx,
                    f"{blob.display}!{e['Path']}",
                    Status.UNCHECKABLE,
                    f"一時領域の空きが足りず展開できない（必要 {batch_size / 1024**3:.1f}GB・空き {free / 1024**3:.1f}GB）。"
                    "設定で一時フォルダを空きの多いドライブにして再検査",
                    depth + 1,
                    size=int(e.get("Size") or 0),
                )
            continue
        dirs: list[str] = []
        done: dict[str, str] = {}
        errors: dict[str, str] = {}
        remaining = {e["Path"] for e in batch}
        for pw in tries:
            if not remaining:
                break
            if pw != tries[0] and not (remaining & encrypted):
                break  # 暗号化でないのに取り出せなかったもの（壊れている）は、パスワードを変えても無駄
            outdir = ctx.new_tmp_subdir()
            dirs.append(outdir)
            listfile = os.path.join(outdir, "_list.txt")
            with open(listfile, "w", encoding="utf-8") as lf:
                lf.write("\n".join(sorted(remaining)))
            r = _run_7z(exe, ["x", "-y", f"-o{outdir}", f"-p{pw}", "-spd"] + common + [path, f"@{listfile}"])
            err = _decode_7z(r.stdout) + "\n" + _decode_7z(r.stderr)
            failed_names = _failed_names(err, remaining)
            for name in list(remaining):
                target = os.path.join(outdir, name)
                if name in failed_names:
                    errors[name] = failed_names[name]
                    if os.path.exists(target):
                        try:
                            os.remove(target)
                        except OSError:
                            pass
                    continue
                if os.path.isfile(target):
                    done[name] = target
                    remaining.discard(name)
                    errors.pop(name, None)
            try:
                os.remove(listfile)
            except OSError:
                pass
        for e in batch:
            name = e["Path"]
            display = f"{blob.display}!{name}"
            size = int(e.get("Size") or 0)
            if name in done:
                ctx.scan_nested(display, path=done[name], depth=depth + 1, name_hint=name)
            elif name in encrypted:
                add_failed_item(
                    ctx,
                    display,
                    Status.NEEDS_PASSWORD,
                    _pw_reason(ctx, "暗号化されている"),
                    depth + 1,
                    password_kind="archive",
                    size=size,
                )
            else:
                add_failed_item(
                    ctx,
                    display,
                    Status.UNCHECKABLE,
                    f"展開できなかった（{errors.get(name, '壊れている可能性')}）",
                    depth + 1,
                    size=size,
                )
        for d in dirs:
            shutil.rmtree(d, ignore_errors=True)
    if broken_listing:
        from ..engine import PartialScan

        item.notes.append(f"7-Zip の出力（技術情報）: {broken_listing}")
        raise PartialScan(
            "アーカイブが途中で切れているか壊れている（読めた分だけ検査した。欠けた中身がある可能性）。"
            "元のファイルを取り直す（コピーし直す・送り主に再送を頼む）か、作った人に中身を確かめてもらう"
        )


def _extract_all_and_scan(ctx, exe, path, blob, item, depth, common, header_pw) -> None:
    """一覧に名前の無い項目があるとき: 丸ごと展開し、出てきたファイルを全部検査する。"""
    outdir = ctx.new_tmp_subdir()
    pw = header_pw or NO_PASSWORD
    r = _run_7z(exe, ["x", "-y", f"-o{outdir}", f"-p{pw}"] + common + [path])
    out = _decode_7z(r.stdout) + _decode_7z(r.stderr)
    files = []
    for dirpath, _dirs, names in os.walk(outdir):
        for n in names:
            files.append(os.path.join(dirpath, n))
    if not files:
        if any(m in out for m in WRONG_PW_MARKERS):
            raise NeedPassword("archive", _pw_reason(ctx, "暗号化されている"))
        raise Uncheckable(f"7-Zip で展開しても中身が出てこなかった: {out.strip()[-300:]}")
    item.method = f"7-Zip で丸ごと展開（{len(files)}件）"
    for f in sorted(files):
        rel = os.path.relpath(f, outdir).replace(os.sep, "/")
        ctx.scan_nested(f"{blob.display}!{rel}", path=f, depth=depth + 1, name_hint=rel)
    shutil.rmtree(outdir, ignore_errors=True)
    if r.returncode != 0:
        from ..engine import PartialScan

        raise PartialScan(
            f"7-Zip がエラーを返した（取り出せた分は検査した。取り出せなかった中身がある可能性）: {out.strip()[-200:]}"
        )


def _check_bomb(ctx: ScanContext, total: int, archive_size: int) -> None:
    """展開後の大きさが異常に大きいもの（zip 爆弾）を打ち切る。OS イメージのような正当な巨大さは通す。"""
    if ctx.expanded_bytes + total > ctx.options.max_expand_bytes:
        raise Uncheckable(
            f"展開後の合計（{total / 1024**3:.1f}GB）が上限を超えるため打ち切り（上限は設定で変えられる）"
        )
    if total > 10 * 1024**3 and archive_size > 0 and total / archive_size > ctx.options.max_expand_ratio:
        raise Uncheckable(
            f"圧縮率が異常（{total / archive_size:.0f}倍・展開後 {total / 1024**3:.1f}GB）のため打ち切り（zip 爆弾の疑い）"
        )


def _batches(entries: list[dict], limit: int):
    """展開する項目を、合計がおよそ limit バイトになる塊に分ける（大きな1件は単独）。"""
    batch: list[dict] = []
    size = 0
    for e in entries:
        s = int(e.get("Size") or 0)
        if batch and size + s > limit:
            yield batch
            batch, size = [], 0
        batch.append(e)
        size += s
    if batch:
        yield batch


def handle_disk_image(ctx: ScanContext, blob: Blob, item: ItemResult, col: Collector, depth: int) -> None:
    """ディスク・OS・パーティションのイメージ。7-Zip で中のファイルを取り出して検査する。"""
    from ..engine import PartialScan
    from ..textdecode import iter_strings_chunked

    exe = find_7z(ctx.options.sevenzip)
    try:
        if not exe:
            raise Uncheckable("ディスクイメージの展開には 7-Zip（7z.exe）が要るが見つからない")
        handle_with_7z_exe(ctx, blob, item, col, depth, kind="image")
        item.notes.append(
            "ファイルシステムの中のファイルを検査した（削除済みファイル・未使用領域は対象外。必要なら「イメージの未使用領域も走査」を有効に）"
        )
        if ctx.options.deep_image_sweep:
            with blob.open() as f:
                for s in iter_strings_chunked(f.read):
                    col.add_text(s, "イメージ全体の生データ", method="生データ走査", raw=True)
            item.method += "＋イメージ全体の生データ走査"
        return
    except NeedPassword:
        raise
    except Uncheckable as e:
        if not exe:
            raise
        reason = str(e)
    # 7-Zip でも開けないイメージは、文字として読める部分だけでも検査する
    with blob.open() as f:
        for s in iter_strings_chunked(f.read):
            col.add_text(s, "イメージ全体の生データ", method="生データ走査")
    item.method = "イメージ全体の生データ走査"
    raise PartialScan(f"7-Zip でイメージの中のファイルを取り出せなかったため、文字列だけを検査した（{reason[:200]}）")


def _failed_names(output: str, names: set[str]) -> dict[str, str]:
    """7z の出力から、取り出しに失敗した項目名と理由を拾う。"""
    failed: dict[str, str] = {}
    for line in output.splitlines():
        if (
            "ERROR" not in line
            and "Wrong password" not in line
            and "CRC Failed" not in line
            and "Data Error" not in line
        ):
            continue
        for n in names:
            if line.rstrip().endswith(n) or f": {n}" in line:
                if "Wrong password" in line or "encrypted" in line:
                    failed[n] = "パスワードが違う"
                else:
                    failed[n] = line.strip()[:200]
    return failed


def _handle_7z_python(ctx: ScanContext, blob: Blob, item: ItemResult, col: Collector, depth: int) -> None:
    """7-Zip が無いときの予備: py7zr で 7z を展開する。"""
    import py7zr

    last_err = None
    for pw in [None] + ctx.password_candidates():
        try:
            with blob.open() as f, py7zr.SevenZipFile(f, mode="r", password=pw) as z:
                infos = [i for i in z.list() if not i.is_directory]
                total = sum(i.uncompressed or 0 for i in infos)
                if ctx.expanded_bytes + total > ctx.options.max_expand_bytes:
                    raise Uncheckable("展開後の合計が上限を超えるため打ち切り（zip 爆弾の疑い）")
                outdir = ctx.new_tmp_subdir()
                z.extractall(path=outdir)
            item.method = f"py7zr で展開（{len(infos)}件）"
            for i in infos:
                p = os.path.join(outdir, i.filename)
                display = f"{blob.display}!{i.filename}"
                if os.path.isfile(p):
                    ctx.scan_nested(display, path=p, depth=depth + 1, name_hint=i.filename)
                else:
                    add_failed_item(ctx, display, Status.UNCHECKABLE, "展開できなかった", depth + 1)
            return
        except Uncheckable:
            raise
        except Exception as e:  # PasswordRequired・誤パスワードによる展開失敗など
            last_err = e
            continue
    msg = str(last_err) if last_err else ""
    if "password" in msg.lower() or type(last_err).__name__ in (
        "PasswordRequired",
        "LZMAError",
        "Bad7zFile",
        "CrcError",
    ):
        raise NeedPassword("archive", _pw_reason(ctx, "7z アーカイブが暗号化されている"))
    raise Uncheckable(f"7z を展開できなかった（7-Zip を入れると読める可能性）: {last_err}")


def handle_7z(ctx: ScanContext, blob: Blob, item: ItemResult, col: Collector, depth: int) -> None:
    if find_7z(ctx.options.sevenzip):
        return handle_with_7z_exe(ctx, blob, item, col, depth, kind="7z")
    return _handle_7z_python(ctx, blob, item, col, depth)


# ------------------------------------------------------------------ tar / 単体圧縮


def handle_tar(ctx: ScanContext, blob: Blob, item: ItemResult, col: Collector, depth: int) -> None:
    with blob.open() as f:
        try:
            tf = tarfile.open(fileobj=f, mode="r:*", ignore_zeros=True)  # 連結した tar の2つ目以降も読む
        except tarfile.TarError as e:
            raise Uncheckable(f"tar を開けなかった: {e}")
        n = 0
        with tf:
            # pg_dump の tar 形式: toc.dat の列名を先に読んでおく
            try:
                toc_member = next((m for m in tf.getmembers() if m.name.rsplit("/", 1)[-1] == "toc.dat"), None)
                if toc_member is not None:
                    toc = tf.extractfile(toc_member).read()
                    if toc.startswith(b"PGDMP"):
                        from .dbdump import pg_toc_mapping

                        ctx.pg_columns.update(pg_toc_mapping(toc))
            except Exception:
                pass
            for m in tf:
                display = f"{blob.display}!{m.name}"
                if m.isdir():
                    continue
                if m.issym() or m.islnk():
                    add_failed_item(
                        ctx, display, Status.OUT_OF_SCOPE, f"リンク（{m.linkname} を指す）のため中身なし", depth + 1
                    )
                    continue
                if not m.isfile():
                    continue
                n += 1
                src = tf.extractfile(m)
                if src is None:
                    add_failed_item(ctx, display, Status.UNCHECKABLE, "取り出せなかった", depth + 1)
                    continue
                if m.size > IN_MEMORY_LIMIT:
                    try:
                        ctx.ensure_space(m.size)
                    except Uncheckable as e:
                        add_failed_item(ctx, display, Status.UNCHECKABLE, str(e), depth + 1, size=m.size)
                        continue
                    out = os.path.join(ctx.new_tmp_subdir(), "member")
                    with open(out, "wb") as dst:
                        shutil.copyfileobj(src, dst, 1024 * 1024)
                    ctx.scan_nested(display, path=out, depth=depth + 1, name_hint=m.name, mtime=m.mtime)
                else:
                    ctx.scan_nested(display, data=src.read(), depth=depth + 1, name_hint=m.name, mtime=m.mtime)
        item.method = f"tar を展開（{n}件）"


class _GzipStream:
    """gzip を zlib で少しずつ展開する。途中で切れていても、そこまでに展開できた分は必ず返す。

    （gzip.open は終わりの印が無いと、直前まで展開した分ごと例外にしてしまう）連結した gzip にも対応する。
    """

    def __init__(self, f):
        import zlib

        self._zlib = zlib
        self._f = f
        self._d = zlib.decompressobj(wbits=31)
        self._buf = bytearray()
        self._pos = 0
        self._pending = b""  # まだ展開していない圧縮データ
        self._done = False
        self.truncated = ""

    OUT_STEP = 4 * 1024 * 1024  # 1回の展開で出す最大量（圧縮爆弾でもメモリを食わない）

    def _fill(self) -> None:
        if not self._pending:
            raw = self._f.read(1024 * 1024)
            if not raw:
                if not self._d.eof:
                    self._buf += self._d.flush()
                    self.truncated = "圧縮データの終わりの印が無い（途中で切れている）"
                self._done = True
                return
            self._pending = raw
        if self._d.eof:
            if len(self._pending) < 2:
                self._pending += self._f.read(1024 * 1024)  # 次のメンバーの見出しが読み込みの境目で切れている
            if self._pending[:2] == b"\x1f\x8b":
                self._d = self._zlib.decompressobj(wbits=31)  # 連結した次のメンバー
            else:
                self._done = True  # 末尾の余分なバイトは無視する
                return
        try:
            self._buf += self._d.decompress(self._pending, self.OUT_STEP)
        except self._zlib.error as e:
            self.truncated = f"圧縮データが壊れている: {e}"
            self._done = True
            return
        self._pending = self._d.unused_data if self._d.eof else self._d.unconsumed_tail

    def read(self, n: int = -1) -> bytes:
        while not self._done and (n < 0 or len(self._buf) - self._pos < n):
            self._fill()
        end = len(self._buf) if n < 0 else min(len(self._buf), self._pos + n)
        out = bytes(self._buf[self._pos : end])
        self._pos = end
        if self._pos > 8 * 1024 * 1024:  # 読み終えた分を捨てる（毎回丸ごと写さない）
            del self._buf[: self._pos]
            self._pos = 0
        return out

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _LzipReader:
    """lzip（LZIP 見出し＋生の LZMA1＋20バイトの末尾）を読む。複数メンバーにも対応。"""

    def __init__(self, f):
        self._f = f
        self._buf = b""
        self._members = self._decode_all()

    CHUNK = 1024 * 1024

    def _fill(self, buf: bytes, need: int) -> bytes:
        while len(buf) < need:
            more = self._f.read(self.CHUNK)
            if not more:
                break
            buf += more
        return buf

    def _decode_all(self):
        """入力も出力も少しずつ扱う（丸ごと読まない。圧縮爆弾でもメモリを食い潰さない）。"""
        buf = b""
        while True:
            buf = self._fill(buf, 6)
            if len(buf) < 6 or buf[:4] != b"LZIP":
                return
            ds_byte = buf[5]
            dict_size = (1 << (ds_byte & 0x1F)) - ((1 << (ds_byte & 0x1F)) // 16) * ((ds_byte >> 5) & 7)
            dec = lzma.LZMADecompressor(
                lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA1, "dict_size": dict_size, "lc": 3, "lp": 0, "pb": 2}]
            )
            data, buf = buf[6:], b""
            while True:
                out = dec.decompress(data, max_length=self.CHUNK)
                if out:
                    yield out
                if dec.eof:
                    buf = dec.unused_data
                    break
                if dec.needs_input:
                    data = self._f.read(self.CHUNK)
                    if not data:
                        return  # 途中で切れている
                else:
                    data = b""
            buf = self._fill(buf, 20)
            buf = buf[20:]  # 末尾（CRC32・元の大きさ・メンバーの大きさ）を飛ばす

    def read(self, n=-1):
        while len(self._buf) < (n if n >= 0 else 1 << 62):
            try:
                self._buf += next(self._members)
            except StopIteration:
                break
        if n < 0:
            out, self._buf = self._buf, b""
        else:
            out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _lzip_open(f):
    return _LzipReader(f)


def handle_single_compressed(ctx: ScanContext, blob: Blob, item: ItemResult, col: Collector, depth: int) -> None:
    head = blob.head(4)
    if head.startswith(b"\x1f\x8b"):
        opener, suffixes = _GzipStream, (".gz", ".gzip", ".tgz", ".z")
    elif head.startswith(b"BZh"):
        opener, suffixes = bz2.open, (".bz2", ".tbz", ".tbz2")
    elif head.startswith(b"\x28\xb5\x2f\xfd"):
        try:
            import zstandard

            def opener(f):
                return zstandard.ZstdDecompressor().stream_reader(f, read_across_frames=True)

        except ImportError:
            try:
                return handle_with_7z_exe(ctx, blob, item, col, depth, kind="zstd")
            except Uncheckable as e:
                raise Uncheckable(
                    "zstd の展開には Python の zstandard 部品が要るが入っていない（pip install zstandard）。"
                    f"7-Zip でも開けなかった: {str(e)[:150]}"
                )
        suffixes = (".zst", ".tzst", ".zstd")
    elif head.startswith(b"\x04\x22\x4d\x18"):
        try:
            import lz4.frame

            opener = lz4.frame.open
        except ImportError:
            try:
                return handle_with_7z_exe(ctx, blob, item, col, depth, kind="lz4")
            except Uncheckable as e:
                raise Uncheckable(
                    "lz4 の展開には Python の lz4 部品が要るが入っていない（pip install lz4）。"
                    f"7-Zip でも開けなかった: {str(e)[:150]}"
                )
        suffixes = (".lz4", ".tlz4")
    elif head.startswith(b"LZIP"):
        opener, suffixes = _lzip_open, (".lz", ".tlz")
    else:
        opener, suffixes = lzma.open, (".xz", ".txz", ".lzma")
    name = Path(blob.name_hint or blob.display).name
    for s in suffixes:
        if name.lower().endswith(s):
            name = name[: -len(s)] + (".tar" if s.startswith(".t") else "")
            break
    out = os.path.join(ctx.new_tmp_subdir(), "decompressed")
    written = 0
    truncated = ""
    with blob.open() as f, opener(f) as src, open(out, "wb") as dst:
        while True:
            try:
                chunk = src.read(1024 * 1024)
            except (EOFError, OSError, lzma.LZMAError) as e:
                truncated = f"{type(e).__name__}: {e}"
                break
            if not chunk:
                if getattr(src, "truncated", ""):
                    truncated = src.truncated
                break
            written += len(chunk)
            if written % (256 * 1024**2) < len(chunk):  # 256MB ごとに一時フォルダの空きを確かめる
                ctx.ensure_space(256 * 1024**2, "展開の途中で")
            if ctx.expanded_bytes + written > ctx.options.max_expand_bytes:
                raise Uncheckable("展開後の大きさが上限を超えたため打ち切り（圧縮爆弾の疑い）")
            if written > 10 * 1024**3 and written / max(1, blob.size) > ctx.options.max_expand_ratio:
                raise Uncheckable(
                    f"圧縮率が異常（{written / max(1, blob.size):.0f}倍）のため打ち切り（圧縮爆弾の疑い）"
                )
            dst.write(chunk)
    item.method = f"展開（{written:,}バイト）"
    if truncated and not written:
        raise Uncheckable(f"圧縮データが壊れていて展開できなかった（{truncated}）")
    ctx.scan_nested(f"{blob.display}!{name}", path=out, depth=depth + 1, name_hint=name)
    if truncated:
        from ..engine import PartialScan

        raise PartialScan(f"圧縮データが途中で切れていた（{truncated}）。展開できた {written:,} バイトだけを検査した")

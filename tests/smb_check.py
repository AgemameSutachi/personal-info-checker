"""本物のファイルサーバー（Hyper-V の Windows VM の SMB 共有）を相手に、ネットワーク越しの検査を確かめる。

手元の `\\\\localhost` では確かめられない、サーバーが別の機械にあるときの振る舞いを、サーバー側を操作しながら試す。
サーバー側の操作は PowerShell Direct（Invoke-Command -VMName）で行うので、VM の管理者アカウントが要る。

使い方（ホストの PowerShell から。Bash からは SMB の接続が見えないことがある）:
    python tests/smb_check.py --vm TestVM --vm-user TestVM\\piitest --vm-password-file pw.txt \\
        --unc \\\\testvm.mshome.net\\piitest --unc-ro \\\\testvm.mshome.net\\piitest_ro --share-path C:\\piishare \\
        --work <一時フォルダ> [--only atime,lock] [--corpus <検体フォルダ（共有の中の名前）>]

前提:
- 共有 --unc（読み書き）と --unc-ro（読み取り専用）が、どちらもサーバーの --share-path を指していること
- ホストからその共有へ、資格情報つきで接続済みであること（New-SmbMapping 等）
- サーバー側に作るものは --share-path の下の net\\（最後に片付ける。元からあれば始めずに断る）と、ロックを外す合図の
  ファイル（--share-path の隣の piictl_release_*）・リンクの指す先の空フォルダ（--share-path の隣の *_linktarget）。
  ホスト側は --work の下だけに書く。--corpus の検体はあらかじめ共有へ置いておく（これは片付けない）

各場面の結果を OK / NG で出し、NG があれば終了コード 1。
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# 架空の個人情報（マイナンバーは検査数字だけ正しい架空番号）
PII_TEXT = "氏名: 山田 太郎\r\nマイナンバー: 123456789018\r\n携帯: 090-1234-5678\r\n住所: 東京都千代田区丸の内1-2-3\r\n"
CLEAN_TEXT = "会議の議題: 来期の予算について\r\n備品の発注は来週までに行う。\r\n"


class Ctx:
    def __init__(self, args):
        self.args = args
        self.work = Path(args.work)
        self.work.mkdir(parents=True, exist_ok=True)
        self.results: list[tuple[str, bool, str]] = []
        self.net_unc = args.unc.rstrip("\\") + "\\net"
        self.net_unc_ro = args.unc_ro.rstrip("\\") + "\\net"
        self.net_local = args.share_path.rstrip("\\") + "\\net"

    # ------------------------------------------------------------ サーバー側
    def _ps_command(self, script_file: str) -> str:
        pw = str(Path(self.args.vm_password_file).resolve())
        return (
            "$ErrorActionPreference='Stop';"
            f"$p=ConvertTo-SecureString ((Get-Content -Raw '{pw}').Trim()) -AsPlainText -Force;"
            f"$c=New-Object System.Management.Automation.PSCredential('{self.args.vm_user}',$p);"
            f"Invoke-Command -VMName '{self.args.vm}' -Credential $c -FilePath '{script_file}'"
        )

    def _script_file(self, script: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".ps1", dir=self.work)
        os.close(fd)
        # Windows PowerShell 5.1 は BOM の無い .ps1 を cp932 として読むので、BOM 付きで書く
        with open(path, "w", encoding="utf-8-sig", newline="\r\n") as f:
            f.write("$ErrorActionPreference='Stop'\n$ProgressPreference='SilentlyContinue'\n" + script)
        return path

    def server(self, script: str, timeout: int = 120) -> str:
        """サーバー（VM）の中で PowerShell を実行し、標準出力を返す。失敗は例外。"""
        path = self._script_file(script)
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", self._ps_command(path)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
        finally:
            os.unlink(path)
        if r.returncode != 0:
            raise RuntimeError(f"サーバー側の操作が失敗した: {r.stderr.strip()[:800]}")
        return r.stdout

    def server_bg(self, script: str) -> tuple[subprocess.Popen, str]:
        """サーバー側で持ち続ける処理（ロック等）を裏で始め、READY を出すまで待つ。"""
        path = self._script_file(script)
        proc = subprocess.Popen(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", self._ps_command(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        deadline = time.time() + 120
        seen = []
        while time.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                break
            seen.append(line)
            if "READY" in line:
                return proc, path
        proc.kill()
        os.unlink(path)
        raise RuntimeError("サーバー側の処理が READY を出さなかった: " + "".join(seen)[-800:])

    def write_server_file(self, rel: str, text: str) -> None:
        """サーバー側に UTF-8（BOM なし）のテキストを置く（共有経由ではなくサーバーのローカルで書く）。"""
        b64 = __import__("base64").b64encode(text.encode("utf-8")).decode()
        self.server(
            f"$p='{self.net_local}\\{rel}'; New-Item -ItemType Directory -Force (Split-Path $p) | Out-Null;"
            f"[IO.File]::WriteAllBytes($p,[Convert]::FromBase64String('{b64}'))"
        )

    # ------------------------------------------------------------ ホスト側
    def scan(self, target: str, name: str, extra: list[str] | None = None, timeout: int = 900) -> dict:
        """CLI で検査し、結果の DB から要点を返す。"""
        db = self.work / f"{name}.sqlite3"
        out = self.work / f"{name}.xlsx"
        cmd = [sys.executable, "-m", "pii_checker", "--db", str(db), "scan", target, "--no-ask", "-o", str(out)]
        cmd += extra or []
        started = time.time()
        r = subprocess.run(
            cmd, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout
        )
        return self.read_db(db, r.stdout + r.stderr, time.time() - started, r.returncode)

    @staticmethod
    def read_db(db: Path, output: str, elapsed: float, code: int) -> dict:
        con = sqlite3.connect(db)
        try:
            job = con.execute("SELECT id, state FROM jobs ORDER BY created DESC LIMIT 1").fetchone()
            jid = job[0]
            files = con.execute(
                "SELECT top_path, state, worst_status, n_findings, reused_from, atime_kept FROM files WHERE job_id=?",
                (jid,),
            ).fetchall()
            items = con.execute("SELECT path, status, reason FROM items WHERE job_id=?", (jid,)).fetchall()
            ferr = con.execute("SELECT path, kind, reason FROM folder_errors WHERE job_id=?", (jid,)).fetchall()
        finally:
            con.close()
        verdict = ""
        for line in output.splitlines():
            if line.startswith("総合判定:"):
                verdict = line.split(":", 1)[1].strip()
        return {
            "job": jid,
            "state": job[1],
            "files": files,
            "items": items,
            "folder_errors": ferr,
            "verdict": verdict,
            "output": output,
            "elapsed": elapsed,
            "code": code,
        }

    def record(self, name: str, ok: bool, detail: str) -> None:
        self.results.append((name, ok, detail))
        print(f"{'OK' if ok else 'NG'} {name}: {detail}", flush=True)


# ---------------------------------------------------------------- 場面


def _atime(ctx: Ctx, rel: str, watch: int = 0) -> str:
    """サーバー側で見た最終アクセス日時。watch 秒のあいだ見続け、変わったらその値を返す。

    SMB のクライアントは閉じたあともハンドルをしばらく持ち続ける（handle lease）ので、読んですぐに見ると
    まだ更新されていないことがある。見続けないと「変わらなかった」が早すぎる判定になる。
    """
    p = f"{ctx.net_local}\\{rel}"
    return ctx.server(
        f"$p='{p}'; $a=(Get-Item -LiteralPath $p).LastAccessTimeUtc; $end=(Get-Date).AddSeconds({watch});"
        "while ((Get-Date) -lt $end) { Start-Sleep -Milliseconds 500; $b=(Get-Item -LiteralPath $p).LastAccessTimeUtc;"
        " if ($b -ne $a) { $a=$b; break } }; $a.ToString('o')",
        timeout=watch + 120,
    ).strip()


def _set_old_atime(ctx: Ctx, rel: str) -> None:
    ctx.server(f"(Get-Item -LiteralPath '{ctx.net_local}\\{rel}').LastAccessTimeUtc = [datetime]'2020-01-01T00:00:00Z'")


def scene_atime(ctx: Ctx) -> None:
    """最終アクセス日時: 普通に読むと変わる（陽性対照）／検査の読み方では変わらない（読み書きの共有・読み取り専用の共有）。"""
    from pii_checker import safeio

    # 小さいファイル（実測で 5KB 以下）は SMB 越しに普通に読んでもサーバー側の日時が更新されないので、
    # 陽性対照が成り立つ大きさ（200KB）にする（小さいファイルで「変わらない」のは検査の読み方の効果ではない）
    for i in range(4):
        ctx.write_server_file(f"atime\\f{i}.txt", PII_TEXT + "x" * 200_000)
        _set_old_atime(ctx, f"atime\\f{i}.txt")
    old = _atime(ctx, "atime\\f0.txt")
    # 陽性対照: 普通の open で読む
    with open(ctx.net_unc + "\\atime\\f0.txt", "rb") as f:
        f.read()
    ctrl = _atime(ctx, "atime\\f0.txt", watch=60)
    ctx.record("atime 陽性対照（普通に読むと変わる）", ctrl != old, f"前 {old} → 後 {ctrl}")
    # 検査の読み方（読み書きの共有）
    kept = []
    for i in (1, 2):
        dest = ctx.work / f"atime_{i}.bin"
        info = safeio.snapshot(ctx.net_unc + f"\\atime\\f{i}.txt", str(dest), str(ctx.work))
        after = _atime(ctx, f"atime\\f{i}.txt", watch=60)
        kept.append((after == old, info.atime_kept, after))
        dest.unlink()
    ctx.record(
        "atime 検査の読み方（読み書きの共有）",
        all(a and b for a, b, _ in kept),
        f"日時が変わらない・atime_kept: {[(a, b) for a, b, _ in kept]}",
    )
    # 読み取り専用の共有: 日時を保つ権限が無い → atime_kept=False と正直に出すか
    dest = ctx.work / "atime_ro.bin"
    info = safeio.snapshot(ctx.net_unc_ro + "\\atime\\f3.txt", str(dest), str(ctx.work))
    after = _atime(ctx, "atime\\f3.txt", watch=60)
    dest.unlink()
    changed = after != old
    # 保てなかったなら保てなかったと記録していること（変わったのに atime_kept=True は嘘になる）
    ctx.record(
        "atime 読み取り専用の共有",
        not (changed and info.atime_kept),
        f"日時が変わった={changed}・atime_kept={info.atime_kept}（{after}）",
    )


def scene_share_modes(ctx: Ctx) -> None:
    """検査が開いている間も、サーバー側で Excel 流の上書き保存（改名→書き込み→削除）ができるか。"""
    from pii_checker import safeio

    if os.name != "nt":
        return
    ctx.write_server_file("share\\book.txt", PII_TEXT)
    save = (
        f"$d='{ctx.net_local}\\share'; Rename-Item \"$d\\book.txt\" 'book.bak';"
        "[IO.File]::WriteAllText(\"$d\\book.txt\", 'new'); Remove-Item \"$d\\book.bak\"; 'SAVED'"
    )
    # 陽性対照: 普通の open で開いたままだと、サーバー側の改名が失敗する
    f = open(ctx.net_unc + "\\share\\book.txt", "rb")
    try:
        try:
            ctx.server(save)
            ctrl_blocked = False
        except RuntimeError:
            ctrl_blocked = True
    finally:
        f.close()
    ctx.record("共有モード 陽性対照（普通の open は保存を妨げる）", ctrl_blocked, f"妨げた={ctrl_blocked}")
    ctx.write_server_file("share\\book.txt", PII_TEXT)
    h, _ = safeio._open_shared(safeio_long(ctx.net_unc + "\\share\\book.txt"))
    try:
        try:
            out = ctx.server(save)
            ok = "SAVED" in out
            detail = "改名・書き込み・削除が通った"
        except RuntimeError as e:
            ok = False
            detail = str(e)[:300]
    finally:
        safeio._k32.CloseHandle(h)
    ctx.record("共有モード 検査の開き方（保存を妨げない）", ok, detail)


def safeio_long(p: str) -> str:
    from pii_checker.engine import long_path

    return long_path(p)


def _hold_script(ctx: Ctx, rel: str, mode: str) -> str:
    """サーバー側でファイルを持ち続ける（mode: exclusive=共有なしで開く / range=全体に範囲ロック）。"""
    p = f"{ctx.net_local}\\{rel}"
    rel_flag = f"{ctx.args.share_path}\\..\\piictl_release_{abs(hash(rel))}"
    if mode == "exclusive":
        open_ = f"$fs=[IO.File]::Open('{p}','Open','ReadWrite','None')"
    else:
        open_ = f"$fs=[IO.File]::Open('{p}','Open','ReadWrite','ReadWrite'); $fs.Lock(0, $fs.Length)"
    return (
        f"Remove-Item -Force -ErrorAction SilentlyContinue '{rel_flag}'\n"
        f"{open_}\n"
        "'READY'\n"
        "$t=0; while (-not (Test-Path '" + rel_flag + "') -and $t -lt 600) { Start-Sleep -Milliseconds 500; $t++ }\n"
        "$fs.Close(); Remove-Item -Force -ErrorAction SilentlyContinue '" + rel_flag + "'\n'RELEASED'\n"
    )


def _release(ctx: Ctx, rel: str, proc: subprocess.Popen, path: str) -> None:
    rel_flag = f"{ctx.args.share_path}\\..\\piictl_release_{abs(hash(rel))}"
    ctx.server(f"New-Item -ItemType File -Force '{rel_flag}' | Out-Null")
    try:
        proc.wait(timeout=60)
    except subprocess.TimeoutExpired:
        proc.kill()
    os.unlink(path)


def scene_locks(ctx: Ctx) -> None:
    """サーバー側で使用中（排他で開いている・範囲ロック）のファイル: 検査不能になり、理由が「使用中」と分かること。"""
    for mode in ("exclusive", "range"):
        rel = f"lock_{mode}\\used.txt"
        ctx.write_server_file(rel, PII_TEXT)
        ctx.write_server_file(f"lock_{mode}\\other.txt", PII_TEXT)
        proc, path = ctx.server_bg(_hold_script(ctx, rel, mode))
        try:
            res = ctx.scan(ctx.net_unc + f"\\lock_{mode}", f"lock_{mode}")
        finally:
            _release(ctx, rel, proc, path)
        used = [i for i in res["items"] if i[0].endswith("used.txt")]
        other = [f for f in res["files"] if f[0].endswith("other.txt")]
        status = used[0][1] if used else "(項目なし)"
        reason = used[0][2] if used else ""
        ok_status = status == "uncheckable"
        # 使用中なのに「権限がない」と出ると、権限を直しに行ってしまう（直すべきは使っていない時間に再検査すること）
        ok_reason = "使用中" in reason and "権限がない" not in reason
        ok_verdict = "言い切れない" in res["verdict"] or "可能性あり" in res["verdict"]
        ctx.record(
            f"使用中のファイル（{mode}）",
            ok_status and ok_reason and bool(other and other[0][3] > 0),
            f"状態={status}・理由={reason[:120]}・判定={res['verdict']}・隣のファイルの検出={other[0][3] if other else None}",
        )
        if not ok_verdict:
            ctx.record(f"使用中のファイル（{mode}）の判定", False, res["verdict"])


def scene_links(ctx: Ctx) -> None:
    """サーバー側のジャンクション（自分の親を指すループ）とシンボリックリンク: 辿らずに記録し、検査が終わること。"""
    d = f"{ctx.net_local}\\links"
    ctx.write_server_file("links\\sub\\a.txt", PII_TEXT)
    target = ctx.args.share_path.rstrip("\\") + "_linktarget"  # 共有の外の空フォルダ
    ctx.server(
        f"New-Item -ItemType Directory -Force '{target}' | Out-Null;"
        f'cmd /c mklink /J "{d}\\sub\\loop" "{d}" | Out-Null;'
        f'cmd /c mklink /D "{d}\\dirlink" "{target}" | Out-Null;'
        f'cmd /c mklink "{d}\\filelink.txt" "{d}\\sub\\a.txt" | Out-Null; \'done\''
    )
    try:
        res = ctx.scan(ctx.net_unc + "\\links", "links", timeout=300)
    finally:
        # リンクだけを外す（rmdir・del はリンクの先を辿らない。PowerShell 5.1 の Remove-Item -Recurse は辿りうる）
        ctx.server(
            f'cmd /c rmdir "{d}\\sub\\loop"; cmd /c rmdir "{d}\\dirlink"; cmd /c del "{d}\\filelink.txt";'
            f"cmd /c rmdir \"{target}\"; 'ok'"
        )
    links = [e for e in res["folder_errors"] if e[1] == "link"]
    errors = [e for e in res["folder_errors"] if e[1] == "error"]
    a = [f for f in res["files"] if f[0].endswith("sub\\a.txt")]
    dirlink = [e for e in links if e[0].endswith("dirlink")]
    # リンクを辿っていない（3つともリンクとして記録・リンクのファイルを普通のファイルとして読んでいない）、
    # 指す先がサーバー側の場所と分かる
    ok = (
        res["code"] == 0
        and len(links) == 3
        and not any(f[0].endswith("filelink.txt") for f in res["files"])
        and bool(a and a[0][3] > 0)
        and bool(dirlink and "サーバー上の" in dirlink[0][2])
    )
    ctx.record(
        "サーバー側のリンク（ループのジャンクション）",
        ok,
        f"{res['elapsed']:.1f}秒・ファイル {len(res['files'])}・リンク {len(links)}・フォルダのエラー {len(errors)}・"
        f"判定={res['verdict']}・{[(Path(e[0]).name, e[2][:60]) for e in links + errors]}",
    )


def scene_denied(ctx: Ctx) -> None:
    """権限の無いフォルダ: 黙って飛ばさず記録し、言い切らないこと。"""
    ctx.write_server_file("denied\\open\\a.txt", CLEAN_TEXT)
    ctx.write_server_file("denied\\secret\\b.txt", PII_TEXT)
    ctx.server(f"icacls '{ctx.net_local}\\denied\\secret' /deny '{ctx.args.vm_user}:(OI)(CI)(RX)' | Out-Null; 'ok'")
    try:
        res = ctx.scan(ctx.net_unc + "\\denied", "denied")
    finally:
        ctx.server(f"icacls '{ctx.net_local}\\denied\\secret' /remove:d '{ctx.args.vm_user}' | Out-Null; 'ok'")
    errs = [e for e in res["folder_errors"] if e[1] == "error"]
    ok = bool(errs) and "言い切れない" in res["verdict"]
    ctx.record(
        "権限の無いフォルダ", ok, f"フォルダのエラー={[(e[0][-20:], e[2][:60]) for e in errs]}・判定={res['verdict']}"
    )


def scene_reuse(ctx: Ctx) -> None:
    """2回目は使い回し、サーバー側で大きさと更新日時を保ったまま書き換えたファイルは読み直すこと。"""
    same = CLEAN_TEXT
    ctx.write_server_file("reuse\\keep.txt", PII_TEXT)
    ctx.write_server_file("reuse\\change.txt", same)
    db_name = "reuse"
    db = ctx.work / f"{db_name}.sqlite3"
    first = ctx.scan(ctx.net_unc + "\\reuse", db_name)
    second = ctx.scan(ctx.net_unc + "\\reuse", db_name)
    reused2 = sum(1 for f in second["files"] if f[4])
    ctx.record(
        "使い回し（2回目）", reused2 == 2, f"使い回し {reused2}/2・{first['elapsed']:.1f}秒→{second['elapsed']:.1f}秒"
    )
    # 同じ長さの個人情報入りに書き換え、更新日時を元に戻す（ChangeTime はサーバーが進める）
    n = len(same.encode("utf-8"))
    pii_same_len = ("携帯 090-1234-5678 ".encode("utf-8") + b"x" * n)[:n]
    b64 = __import__("base64").b64encode(pii_same_len).decode()
    ctx.server(
        f"$p='{ctx.net_local}\\reuse\\change.txt'; $t=(Get-Item $p).LastWriteTimeUtc;"
        f"[IO.File]::WriteAllBytes($p,[Convert]::FromBase64String('{b64}')); (Get-Item $p).LastWriteTimeUtc=$t; 'ok'"
    )
    third = ctx.scan(ctx.net_unc + "\\reuse", db_name)
    ch = [f for f in third["files"] if f[0].endswith("change.txt")][0]
    kp = [f for f in third["files"] if f[0].endswith("keep.txt")][0]
    ctx.record(
        "使い回し（大きさ・更新日時を保った書き換えを見抜く）",
        ch[4] is None and ch[3] > 0 and kp[4] is not None,
        f"change.txt 使い回し={ch[4] is not None}・検出={ch[3]}／keep.txt 使い回し={kp[4] is not None}",
    )
    _ = db


def scene_corpus(ctx: Ctx) -> None:
    """検体一式: ネットワーク越しの結果が手元と同じで、検査の前後でサーバー側が1バイト・1日時も変わらないこと。"""
    if not ctx.args.corpus:
        return
    corpus_local = ctx.args.share_path.rstrip("\\") + "\\" + ctx.args.corpus
    # 陽性対照（同じ場面の中で）: このサーバーでは普通に読むと最終アクセス日時が変わること。
    # 変わらない設定（disablelastaccess 等）なら、下の「変わらない」は何も意味しない
    ctx.write_server_file("corpus_ctrl\\big.txt", PII_TEXT + "x" * 200_000)
    _set_old_atime(ctx, "corpus_ctrl\\big.txt")
    with open(ctx.net_unc + "\\corpus_ctrl\\big.txt", "rb") as f:
        f.read()
    ctrl_changed = _atime(ctx, "corpus_ctrl\\big.txt", watch=60) != "2020-01-01T00:00:00.0000000Z"
    ctx.record("検体 陽性対照（このサーバーは普通に読むと日時が変わる）", ctrl_changed, f"変わった={ctrl_changed}")
    inv = (
        f"Get-ChildItem -LiteralPath '{corpus_local}' -Recurse -Force | ForEach-Object {{"
        " $s = ''; if (-not $_.PSIsContainer) { $s = (Get-Item -LiteralPath $_.FullName -Stream * | ForEach-Object { $_.Stream + '=' + $_.Length }) -join ',' };"
        " '{0}|{1}|{2}|{3}|{4}|{5}|{6}' -f $_.FullName, $_.Length, $_.LastWriteTimeUtc.Ticks, $_.LastAccessTimeUtc.Ticks,"
        " $_.CreationTimeUtc.Ticks, [int]$_.Attributes, $s } | Sort-Object"
    )
    # NTFS は最終アクセス日時を「前の値から1時間以上たっているとき」だけ更新するので、検体を置いてすぐ試すと
    # 何をしても変わらず、偽の合格になる（実測・2026-10-18）。先に全部を 2020 年に戻してから比べる。
    # ファイルを先に、フォルダは深い順に最後に戻す（中を開くと親フォルダの日時が更新されるため）
    ctx.server(
        f"$all = Get-ChildItem -LiteralPath '{corpus_local}' -Recurse -Force;"
        " $old = [datetime]'2020-01-01T00:00:00Z';"
        " $all | Where-Object { -not $_.PSIsContainer } | ForEach-Object { $_.LastAccessTimeUtc = $old };"
        " $all | Where-Object { $_.PSIsContainer } | Sort-Object { $_.FullName.Length } -Descending |"
        " ForEach-Object { $_.LastAccessTimeUtc = $old }; 'ok'",
        timeout=300,
    )
    before = ctx.server(inv, timeout=300).splitlines()
    remote = ctx.args.unc.rstrip("\\") + "\\" + ctx.args.corpus
    res = ctx.scan(remote, "corpus_remote", ["--csv"])
    # クライアントが閉じたあともハンドルをしばらく持つ（handle lease）ので、日時の更新が遅れて出る分を待つ
    time.sleep(60)
    after = ctx.server(inv, timeout=300).splitlines()
    diff = sorted(set(before) ^ set(after))

    # フォルダは、中のファイルを開くだけで（パスを辿るときに）サーバーの NTFS が最終アクセス日時を更新する。
    # パスで開く以上は避けられない（手元の NTFS でも同じ・実測）ので、ファイルとは分けて事実として記録する
    def is_dir_line(line: str) -> bool:
        return bool(int(line.split("|")[5]) & 0x10)  # 属性にディレクトリ

    def without_atime(line: str) -> list[str]:
        f = line.split("|")
        return f[:3] + f[4:]  # 名前|大きさ|更新|（最終アクセスを除く）|作成|属性|ストリーム

    file_diff = [d for d in diff if not is_dir_line(d)]
    dir_diff = [d for d in diff if is_dir_line(d)]
    # 最終アクセス日時だけが違う前後の組にならないもの（名前・大きさ・属性などが変わったフォルダ）
    dir_other = [d for d in dir_diff if not any(x != d and without_atime(x) == without_atime(d) for x in dir_diff)]
    ctx.record(
        "検査の前後でサーバー側のファイルが変わらない（名前・大きさ・更新/最終アクセス/作成日時・属性・ストリーム）",
        not file_diff and len(before) > 0 and len(res["files"]) > 0,
        f"{len(before)} 件を比較・ファイルの違い {len(file_diff)} 件 {file_diff[:4]}・検査したファイル {len(res['files'])}",
    )
    ctx.record(
        "検査の前後でサーバー側のフォルダは最終アクセス日時だけが変わる（NTFS の仕様。ほかは変わらない）",
        not dir_other,
        f"最終アクセス日時が変わったフォルダ {len(dir_diff) // 2} 件・それ以外の違い {len(dir_other)} 件 {dir_other[:2]}",
    )
    ok_atime = bool(res["files"]) and all(f[5] == 1 for f in res["files"])
    ctx.record(
        "検体: 全ファイルで最終アクセス日時を保てた",
        ok_atime,
        f"{sum(1 for f in res['files'] if f[5] == 1)}/{len(res['files'])}",
    )
    if ctx.args.corpus_local:
        local = ctx.scan(ctx.args.corpus_local, "corpus_local", ["--csv"])

        def norm(r, base):
            return sorted((Path(os.path.relpath(f[0], base)).as_posix(), f[2], f[3]) for f in r["files"])

        a, b = norm(res, remote), norm(local, ctx.args.corpus_local)
        d = sorted(set(a) ^ set(b))
        ctx.record(
            "検体: ネットワーク越しと手元で結果が同じ（ファイルごとの状態・検出数）",
            not d and res["verdict"] == local["verdict"],
            f"{len(a)} ファイル・違い {len(d)} {d[:4]}・判定 {res['verdict']} / {local['verdict']}・"
            f"{res['elapsed']:.1f}秒 / {local['elapsed']:.1f}秒",
        )


def scene_drop(ctx: Ctx) -> None:
    """検査中に回線が切れる: 固まらずに終わり、読めなかったものを言い切らず、つながってから続きを検査できること。"""
    n = ctx.args.drop_files
    # サーバー側で小さなファイルを大量に作る（1件ずつの往復が要る）。中身は個人情報なし
    # （個人情報入りだと判定が「可能性あり」で決まってしまい、読めなかった分を言い切らないかを試せない）
    b64 = __import__("base64").b64encode(CLEAN_TEXT.encode("utf-8")).decode()
    ctx.server(
        f"$d='{ctx.net_local}\\drop'; New-Item -ItemType Directory -Force $d | Out-Null;"
        f"$t=[Convert]::FromBase64String('{b64}');"
        f'0..{n - 1} | ForEach-Object {{ $s="$d\\g$([math]::Floor($_/100))"; if (-not (Test-Path $s)) {{ New-Item -ItemType Directory $s | Out-Null }};'
        " [IO.File]::WriteAllBytes(\"$s\\p$_.txt\", $t) }; 'ok'",
        timeout=600,
    )
    db = ctx.work / "drop.sqlite3"
    cmd = [
        sys.executable,
        "-m",
        "pii_checker",
        "--db",
        str(db),
        "scan",
        ctx.net_unc + "\\drop",
        "--no-ask",
        "-o",
        str(ctx.work / "drop.xlsx"),
        "--no-reuse",
    ]
    log = open(ctx.work / "drop.log", "w", encoding="utf-8")
    proc = subprocess.Popen(cmd, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
    # 何件か終わるまで待ってから切る
    deadline = time.time() + 300
    done = 0
    while time.time() < deadline and proc.poll() is None:
        time.sleep(1)
        try:
            con = sqlite3.connect(db)
            done = con.execute("SELECT COUNT(*) FROM files WHERE state='done'").fetchone()[0]
            con.close()
        except sqlite3.Error:
            continue
        if done >= n // 10:
            break
    running_at_cut = proc.poll() is None  # 切る前に検査が終わっていたら、この場面は何も試していない
    subprocess.run(
        ["powershell", "-NoProfile", "-Command", f"Disconnect-VMNetworkAdapter -VMName '{ctx.args.vm}'"], check=True
    )
    cut_at = time.time()
    try:
        try:
            proc.wait(timeout=ctx.args.drop_wait)
            hung = False
        except subprocess.TimeoutExpired:
            hung = True
            proc.kill()
            proc.wait()
    finally:
        subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                f"Connect-VMNetworkAdapter -VMName '{ctx.args.vm}' -SwitchName '{ctx.args.vm_switch}'",
            ],
            check=True,
        )
        log.close()
    took = time.time() - cut_at
    out = (ctx.work / "drop.log").read_text(encoding="utf-8", errors="replace")
    res = Ctx.read_db(db, out, took, proc.returncode)
    states: dict[str, int] = {}
    for f in res["files"]:
        key = f"{f[1]}/{f[2]}"
        states[key] = states.get(key, 0) + 1
    reasons = {}
    for i in res["items"]:
        if i[1] == "uncheckable":
            reasons[i[2][:70]] = reasons.get(i[2][:70], 0) + 1
    ctx.record(
        "回線断: 固まらずに終わる",
        not hung and running_at_cut,
        f"切ったのは {done} 件済みの時点（検査中だった={running_at_cut}）・切ってから {took:.0f} 秒で"
        f"{'終わらず打ち切った' if hung else '終了'}",
    )
    network_reasons = [r for r in reasons if "接続" in r or "ネットワーク" in r]
    misleading = [r for r in reasons if "削除された" in r or "権限がない" in r]
    pending_after = sum(1 for f in res["files"] if f[1] == "pending")
    ctx.record(
        "回線断: 読めなかった分を未検査で残す（削除・権限と取り違えて検査不能で確定させない）",
        not misleading and pending_after > 0,
        f"未検査で残した {pending_after}・検査不能の理由={list(reasons.items())[:3]}・回線と分かる理由 {len(network_reasons)}",
    )
    ctx.record(
        "回線断: 言い切らない",
        "言い切れない" in res["verdict"],
        f"判定={res['verdict']}・ファイルの状態={states}・検査不能の理由={list(reasons.items())[:3]}・"
        f"フォルダのエラー {len(res['folder_errors'])}",
    )
    # つながるのを待ってから続き
    deadline = time.time() + 180
    while time.time() < deadline and not os.path.isdir(ctx.net_unc + "\\drop"):
        time.sleep(3)
    r = subprocess.run(
        [
            sys.executable,
            "-m",
            "pii_checker",
            "--db",
            str(db),
            "scan",
            "--resume",
            res["job"],
            "--no-ask",
            "-o",
            str(ctx.work / "drop2.xlsx"),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=1800,
    )
    res2 = Ctx.read_db(db, r.stdout + r.stderr, 0, r.returncode)
    done2 = sum(1 for f in res2["files"] if f[1] == "done")
    unc2 = sum(1 for f in res2["files"] if f[2] == "uncheckable")
    # 「終わった」には検査不能のまま確定したものも含まれるので、全件を中身まで読めたか（検査不能 0）で見る
    ctx.record(
        "回線断: つながってから再開すると全件を中身まで検査できる",
        done2 == n and unc2 == 0 and "検出なし" in res2["verdict"],
        f"終わったファイル {done2}/{n}・検査不能 {unc2}・判定={res2['verdict']}",
    )


def scene_ads(ctx: Ctx) -> None:
    """隠しストリーム（代替データストリーム）だけに個人情報があるファイルを、SMB 越しに見つけること。"""
    ctx.write_server_file("ads\\memo.txt", CLEAN_TEXT)
    b64 = __import__("base64").b64encode(PII_TEXT.encode("utf-8")).decode()
    ctx.server(
        f"Set-Content -LiteralPath '{ctx.net_local}\\ads\\memo.txt' -Stream secret -Encoding Byte"
        f" -Value ([Convert]::FromBase64String('{b64}')); 'ok'"
    )
    res = ctx.scan(ctx.net_unc + "\\ads", "ads")
    items = {i[0]: i for i in res["items"]}
    hidden = [p for p in items if p.endswith(":secret")]
    f = res["files"][0] if res["files"] else None
    ctx.record(
        "隠しストリームだけの個人情報を SMB 越しに見つける",
        bool(hidden) and bool(f and f[3] > 0) and "可能性あり" in res["verdict"],
        f"項目={[(os.path.basename(p), items[p][1]) for p in items]}・検出={f[3] if f else None}・判定={res['verdict']}",
    )


SCENES = {
    "ads": scene_ads,
    "atime": scene_atime,
    "share": scene_share_modes,
    "lock": scene_locks,
    "links": scene_links,
    "denied": scene_denied,
    "reuse": scene_reuse,
    "corpus": scene_corpus,
    "drop": scene_drop,
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--vm", required=True)
    ap.add_argument("--vm-user", required=True)
    ap.add_argument("--vm-password-file", required=True)
    ap.add_argument("--vm-switch", default="Default Switch")
    ap.add_argument("--unc", required=True)
    ap.add_argument("--unc-ro", required=True)
    ap.add_argument("--share-path", required=True, help="共有のサーバー側の場所（例 C:\\piishare）")
    ap.add_argument("--work", required=True, help="ホスト側の作業フォルダ（一時フォルダ等）")
    ap.add_argument("--corpus", default="", help="共有の中の検体フォルダの名前")
    ap.add_argument("--corpus-local", default="", help="同じ検体の手元の場所（結果の比較用）")
    ap.add_argument("--drop-files", type=int, default=600)
    ap.add_argument("--drop-wait", type=int, default=900, help="回線断のあと終わるのを待つ秒数")
    ap.add_argument("--only", default="", help="場面の名前をカンマ区切りで（既定は全部）")
    ap.add_argument("--keep", action="store_true", help="サーバー側の net フォルダを片付けない")
    args = ap.parse_args()
    ctx = Ctx(args)
    names = [n for n in (args.only.split(",") if args.only else SCENES) if n]
    # 片付けで net フォルダを丸ごと消すので、元から無いことを確かめる（本物の共有の既存のフォルダを消さない）
    exists = ctx.server(f"Test-Path -LiteralPath '{ctx.net_local}'").strip()
    if exists == "True" and not args.keep:
        print(
            f"サーバー側に {ctx.net_local} が既にあります。試験は最後にこのフォルダを消すので、始めませんでした。"
            "前回の試験の残りなら、サーバー側で消してから流してください。本物のフォルダなら別の --share-path を指定してください"
            "（--keep を付けると片付けをしないので、既にあっても流せます）",
            file=sys.stderr,
        )
        return 2
    ctx.server(f"New-Item -ItemType Directory -Force '{ctx.net_local}' | Out-Null")
    try:
        for name in names:
            print(f"--- {name}", flush=True)
            try:
                SCENES[name](ctx)
            except Exception as e:  # 1つの場面の失敗で全体を止めない
                ctx.record(name, False, f"場面の途中で失敗: {type(e).__name__}: {str(e)[:500]}")
    finally:
        if not args.keep:
            # rmdir /s はジャンクションの先を辿らない（試験で作った net フォルダだけを片付ける）
            ctx.server(f"cmd /c rmdir /s /q \"{ctx.net_local}\"; 'ok'")
    ng = [r for r in ctx.results if not r[1]]
    print(f"\n{len(ctx.results) - len(ng)} 件 OK・{len(ng)} 件 NG")
    (Path(args.work) / "smb_check_result.json").write_text(
        json.dumps(ctx.results, ensure_ascii=False, indent=1), encoding="utf-8"
    )
    return 1 if ng else 0


if __name__ == "__main__":
    sys.exit(main())

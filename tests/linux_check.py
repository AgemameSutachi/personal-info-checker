"""本物の Samba・vsftpd（Hyper-V の Linux の VM）を相手に、接続方式（SMB・FTP・FTPS）の検査を確かめる。

Windows のファイルサーバー相手の試験は tests/smb_check.py。こちらはサーバー側の操作を SSH で行う。

使い方（ホストの PowerShell から）:
    python tests/linux_check.py --host <サーバーの IP> --ssh-key <鍵> --ssh-user piiadmin --password-file pw.txt \\
        --work <一時フォルダ> --corpus-local <手元の検体> [--vm PiiTestLinux] [--only smb_corpus,ftp_corpus]

前提（Ubuntu 等に Samba・vsftpd を入れて用意する。準備の手順書はリポジトリに含めない）:
- サーバーのユーザー piitest（Samba と FTP で同じパスワード）。共有 piitest（読み書き・ストリーム無し）・piitest_ro（読み取り専用）・
  piitest_ads（streams_xattr）。いずれも /srv/piishare。FTP（21・明示的 TLS）と暗黙的 TLS（990）の根も /srv/piishare
- /srv/piishare/corpus に検体（tests/make_corpus.py）を置いておく
- サーバー側に作るものは /srv/piishare/lnet の下だけ（最後に片付ける）。ホスト側は --work の下だけに書く

各場面の結果を OK / NG で出し、NG があれば終了コード 1。
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PII = "氏名: 山田 太郎\nマイナンバー: 123456789018\n携帯: 090-1234-5678\n"
CLEAN = "会議の議題: 来期の予算について\n"
SHARE = "/srv/piishare"
NET = SHARE + "/lnet"


class Ctx:
    def __init__(self, args):
        self.args = args
        self.work = Path(args.work)
        self.work.mkdir(parents=True, exist_ok=True)
        self.results: list[tuple[str, bool, str]] = []
        self.n = 0

    def ssh(self, cmd: str, timeout: int = 300, user: str = "root", stdin: bytes | None = None) -> str:
        """サーバーで bash のコマンドを流す（既定は root。piitest の持ち物にするときは user="piitest"）。"""
        a = self.args
        wrapped = f"sudo -u {user} bash -c {shlex.quote(cmd)}" if user != "root" else f"sudo bash -c {shlex.quote(cmd)}"
        r = subprocess.run(
            [
                "ssh",
                "-i",
                a.ssh_key,
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                f"UserKnownHostsFile={os.devnull}",
                "-o",
                "LogLevel=ERROR",
                f"{a.ssh_user}@{a.host}",
                wrapped,
            ],
            input=stdin,
            capture_output=True,
            timeout=timeout,
        )
        r.stdout = r.stdout.decode("utf-8", "replace")
        r.stderr = r.stderr.decode("utf-8", "replace")
        if r.returncode != 0:
            raise RuntimeError(f"サーバー側の操作が失敗した: {r.stderr.strip()[:600]}")
        return r.stdout

    def put(self, rel: str, text: str) -> None:
        """サーバーの lnet の下に piitest の持ち物としてテキストを置く。"""
        # 中身は標準入力で送る（コマンド行に入れると Windows の長さの上限 32K を超える・WinError 206）
        p = f"{NET}/{rel}"
        self.ssh(
            f"mkdir -p {shlex.quote(os.path.dirname(p))} && cat > {shlex.quote(p)}",
            user="piitest",
            stdin=text.encode("utf-8"),
        )

    def scan(
        self,
        kind: str,
        path: str,
        share: str = "piitest",
        extra: list[str] | None = None,
        db: str | None = None,
        timeout: int = 1800,
    ) -> dict:
        """接続方式の CLI で検査し、結果の DB の要点を返す。"""
        self.n += 1
        name = db or f"s{self.n}"
        dbp = self.work / f"{name}.sqlite3"
        cmd = [
            sys.executable,
            "-m",
            "pii_checker",
            "--db",
            str(dbp),
            "scan",
            "--connect",
            kind,
            "--host",
            self.args.host,
            "--path",
            path,
            "--user",
            "piitest",
            "--conn-password-file",
            self.args.password_file,
            "--no-ask",
            "-o",
            str(self.work / f"{name}.xlsx"),
        ]
        if kind == "smb":
            cmd += ["--share", share]
        cmd += extra or []
        started = time.time()
        r = subprocess.run(
            cmd, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout
        )
        return read_db(dbp, r.stdout + r.stderr, time.time() - started, r.returncode)

    def record(self, name: str, ok: bool, detail: str) -> None:
        self.results.append((name, ok, detail))
        print(f"{'OK' if ok else 'NG'} {name}: {detail}", flush=True)


def read_db(db: Path, output: str, elapsed: float, code: int) -> dict:
    if not db.exists():
        return {
            "files": [],
            "items": [],
            "folder_errors": [],
            "verdict": "",
            "output": output,
            "code": code,
            "elapsed": elapsed,
            "job": None,
        }
    con = sqlite3.connect(db)
    try:
        jid, state = con.execute("SELECT id, state FROM jobs ORDER BY created DESC LIMIT 1").fetchone()
        files = con.execute(
            "SELECT top_path, state, worst_status, n_findings, reused_from, atime_kept FROM files " "WHERE job_id=?",
            (jid,),
        ).fetchall()
        items = con.execute("SELECT path, status, reason FROM items WHERE job_id=?", (jid,)).fetchall()
        ferr = con.execute("SELECT path, kind, reason FROM folder_errors WHERE job_id=?", (jid,)).fetchall()
    finally:
        con.close()
    verdict = next((ln.split(":", 1)[1].strip() for ln in output.splitlines() if ln.startswith("総合判定:")), "")
    return {
        "job": jid,
        "state": state,
        "files": files,
        "items": items,
        "folder_errors": ferr,
        "verdict": verdict,
        "output": output,
        "elapsed": elapsed,
        "code": code,
    }


def server_inventory(ctx: Ctx, path: str) -> list[str]:
    """サーバー側の一覧（パス|種類|大きさ|更新|最終アクセス|変更|権限）。ナノ秒まで。"""
    out = ctx.ssh(f"find {shlex.quote(path)} -printf '%p|%y|%s|%T@|%A@|%C@|%m\\n' | sort")
    return out.splitlines()


def age_atimes(ctx: Ctx, path: str) -> None:
    """最終アクセス日時を 2020 年へ戻す（relatime は1日以上古いときに更新するので、戻さないと何をしても変わらない）。"""
    ctx.ssh(f"find {shlex.quote(path)} -depth -exec touch -a -h -d '2020-01-01 00:00:00' {{}} +")


def compare_inventory(before: list[str], after: list[str]) -> tuple[list, list, list]:
    """(ファイルの違い, フォルダの最終アクセス日時だけの違い, フォルダのそれ以外の違い)。"""
    b = {ln.split("|")[0]: ln for ln in before}
    a = {ln.split("|")[0]: ln for ln in after}
    file_diff, dir_atime, dir_other = [], [], []
    for p in sorted(set(a) | set(b)):
        x, y = b.get(p), a.get(p)
        if x == y:
            continue
        if not x or not y:
            file_diff.append((p, x, y))
            continue
        fx, fy = x.split("|"), y.split("|")
        if fx[1] == "d":
            (dir_atime if fx[:4] + fx[5:] == fy[:4] + fy[5:] else dir_other).append((p, x, y))
        else:
            file_diff.append((p, x, y))
    return file_diff, dir_atime, dir_other


def rel(p: str) -> str:
    p = p.replace("\\", "/")
    return p.split("/corpus/", 1)[1] if "/corpus/" in p else p


# ---------------------------------------------------------------- 場面


def scene_atime_control(ctx: Ctx) -> None:
    """陽性対照: このサーバーは SMB・FTP で普通に読むと最終アクセス日時が変わる（変わらないなら日時の比較は意味が無い）。"""
    import ftplib

    from pii_checker import remote

    ctx.put("ctrl/smb.txt", PII + "x" * 200_000)
    ctx.put("ctrl/ftp.txt", PII + "x" * 200_000)
    age_atimes(ctx, NET + "/ctrl")
    pw = Path(ctx.args.password_file).read_text(encoding="utf-8").strip()
    conn = remote.Connection.from_dict({"kind": "smb", "host": ctx.args.host, "share": "piitest", "user": "piitest"})
    created = remote.smb_connect(conn, pw)
    try:
        with open(rf"\\{ctx.args.host}\piitest\lnet\ctrl\smb.txt", "rb") as f:
            f.read()
    finally:
        if created:
            remote.smb_disconnect(conn)
    f = ftplib.FTP(ctx.args.host, timeout=15)
    f.login("piitest", pw)
    f.retrbinary("RETR /lnet/ctrl/ftp.txt", lambda b: None)
    f.quit()
    time.sleep(15)  # SMB のクライアントがハンドルを閉じるのを待つ
    at = dict(ln.split("|")[0::4][:2] for ln in server_inventory(ctx, NET + "/ctrl") if ln.split("|")[1] == "f")
    ok = all(not v.startswith("1577") for v in at.values())
    ctx.record("陽性対照（普通に読むとサーバー側の最終アクセス日時が変わる）", ok, f"{at}")


def scene_smb_corpus(ctx: Ctx) -> None:
    """Samba: 検体の結果が手元と同じ・サーバー側のファイルは何も変わらない（最終アクセス日時も）。"""
    age_atimes(ctx, SHARE + "/corpus")
    before = server_inventory(ctx, SHARE + "/corpus")
    res = ctx.scan("smb", "corpus", db="smb_corpus")
    time.sleep(60)  # handle lease で日時の更新が遅れる分を待つ
    after = server_inventory(ctx, SHARE + "/corpus")
    fd, da, do = compare_inventory(before, after)

    def without_atime(line: str) -> list[str]:
        f = line.split("|")
        return f[:4] + f[5:]

    atime_only = {d[0] for d in fd if d[1] and d[2] and without_atime(d[1]) == without_atime(d[2])}
    other = [d for d in fd if d[0] not in atime_only]
    ctx.record(
        "Samba: 検査の前後でサーバー側のファイルの中身・大きさ・更新日時・変更日時・権限が変わらない",
        not other and len(res["files"]) > 0,
        f"{len(before)} 件を比較・違い {len(other)} {other[:2]}・最終アクセス日時だけ変わったファイル {len(atime_only)}",
    )
    ctx.record(
        "Samba: フォルダは最終アクセス日時だけが変わりうる（ほかは変わらない）",
        not do,
        f"日時だけ変わったフォルダ {len(da)}・それ以外の違い {len(do)} {do[:2]}",
    )
    # 最終アクセス日時の記録が、サーバーの実際と一致すること（Samba は SetFileTime(-1) を守らず、読むと更新した。
    # 変わったのに「保てた」と記録しない）…は、読んだ時点では見抜けない: Windows のクライアントがファイル情報を約 10 秒
    # 手元に持ち、同じハンドルでも開き直しても古い値を返した（実測）。ツールの記録は「保つ指示を出した」までで、
    # 守るかはサーバー次第と README・画面に書いた。ここでは、Samba が守らないこと（既知の限界）を事実として確かめる
    ctx.record(
        "Samba: 最終アクセス日時は読むと更新される（既知の限界・README と画面に記載）",
        len(atime_only) == len(res["files"]) > 0,
        f"サーバーで変わった {len(atime_only)}/{len(res['files'])}（Samba は SetFileTime(-1) を守らない）",
    )
    compare_with_local(ctx, res, "Samba")


def compare_with_local(ctx: Ctx, res: dict, label: str) -> None:
    if not ctx.args.corpus_local:
        return
    if not hasattr(ctx, "_local"):
        db = ctx.work / "local.sqlite3"
        cmd = [
            sys.executable,
            "-m",
            "pii_checker",
            "--db",
            str(db),
            "scan",
            ctx.args.corpus_local,
            "--no-ask",
            "-o",
            str(ctx.work / "local.xlsx"),
        ]
        r = subprocess.run(
            cmd, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=1800
        )
        ctx._local = read_db(db, r.stdout, 0, r.returncode)
    a = sorted((rel(f[0]), f[2], f[3]) for f in res["files"])
    b = sorted((rel(f[0]), f[2], f[3]) for f in ctx._local["files"])
    ai = sorted((rel(i[0]), i[1]) for i in res["items"])
    bi = sorted((rel(i[0]), i[1]) for i in ctx._local["items"])
    d = sorted(set(a) ^ set(b)) + sorted(set(ai) ^ set(bi))
    ctx.record(
        f"{label}: 検体の結果が手元と同じ（ファイルごとの状態・検出数・中身の項目）",
        not d and res["verdict"] == ctx._local["verdict"],
        f"{len(a)} ファイル・{len(ai)} 項目・違い {len(d)} {d[:3]}・判定 {res['verdict']} / {ctx._local['verdict']}・"
        f"{res['elapsed']:.1f}秒",
    )


def scene_smb_ro(ctx: Ctx) -> None:
    """Samba の読み取り専用の共有: 結果は同じ・日時を保てなかったと正直に記録する。"""
    res = ctx.scan("smb", "corpus", share="piitest_ro", db="smb_ro")
    kept = sum(1 for f in res["files"] if f[5] == 1)
    ctx.record(
        "Samba 読み取り専用: 日時を保てなかったと記録する（保てたと言わない）",
        len(res["files"]) > 0 and kept == 0,
        f"保てた {kept}/{len(res['files'])}",
    )
    compare_with_local(ctx, res, "Samba 読み取り専用")


def scene_smb_ads(ctx: Ctx) -> None:
    """Samba の streams_xattr の共有で、隠しストリームだけの個人情報を見つける。ストリームの無い共有では一覧を取りに行かない。"""
    from pii_checker import remote

    ctx.put("ads/memo.txt", CLEAN)
    pw = Path(ctx.args.password_file).read_text(encoding="utf-8").strip()
    conn = remote.Connection.from_dict(
        {"kind": "smb", "host": ctx.args.host, "share": "piitest_ads", "user": "piitest"}
    )
    created = remote.smb_connect(conn, pw)
    try:
        with open(rf"\\{ctx.args.host}\piitest_ads\lnet\ads\memo.txt:secret", "w", encoding="utf-8") as f:
            f.write(PII)
    finally:
        if created:
            remote.smb_disconnect(conn)
    res = ctx.scan("smb", "lnet/ads", share="piitest_ads", db="smb_ads")
    hidden = [i for i in res["items"] if i[0].endswith(":secret")]
    ctx.record(
        "Samba（streams_xattr）: 隠しストリームだけの個人情報を見つける",
        bool(hidden) and "可能性あり" in res["verdict"],
        f"項目={[(Path(i[0]).name, i[1]) for i in res['items']]}",
    )
    res2 = ctx.scan("smb", "lnet/ads", share="piitest", db="smb_noads")
    bad = [i for i in res2["items"] if "一覧を取れなかった" in (i[2] or "")]
    ctx.record(
        "Samba（ストリーム無し）: 一覧を取りに行って検査不能にしない",
        not bad and len(res2["files"]) == 1,
        f"項目={[(Path(i[0]).name, i[1]) for i in res2['items']]}・判定={res2['verdict']}",
    )


def scene_smb_loop_denied(ctx: Ctx) -> None:
    ctx.put("loop/sub/a.txt", PII)
    ctx.ssh(f"ln -sfn .. {NET}/loop/sub/back", user="piitest")
    res = ctx.scan("smb", "lnet/loop", db="smb_loop", timeout=300)
    links = [e for e in res["folder_errors"] if e[1] == "link"]
    ctx.record(
        "Samba: リンクのループを二重に辿らない",
        len(res["files"]) == 1 and len(links) == 1 and res["state"] == "done",
        f"ファイル {len(res['files'])}・リンク {len(links)}・{res['elapsed']:.1f}秒・状態 {res['state']}",
    )
    ctx.put("denied/open/a.txt", CLEAN)
    ctx.put("denied/secret/b.txt", PII)
    ctx.ssh(f"chmod 000 {NET}/denied/secret")
    try:
        res = ctx.scan("smb", "lnet/denied", db="smb_denied")
        resf = ctx.scan("ftp", "lnet/denied", db="ftp_denied")
    finally:
        ctx.ssh(f"chmod 755 {NET}/denied/secret")
    for label, r in (("Samba", res), ("FTP", resf)):
        errs = [e for e in r["folder_errors"] if e[1] == "error"]
        ctx.record(
            f"{label}: 権限の無いフォルダを記録して言い切らない",
            bool(errs) and "言い切れない" in r["verdict"],
            f"{[(Path(e[0].replace(chr(92), '/')).name, e[2][:50]) for e in errs]}・判定={r['verdict']}",
        )


def scene_smb_reuse(ctx: Ctx) -> None:
    """2回目は使い回し、大きさと更新日時を保ったまま書き換えたファイルは（変更日時で）見抜く。FTP は見抜けない限界も確かめる。"""
    ctx.put("reuse/keep.txt", PII)
    ctx.put("reuse/change.txt", CLEAN)
    for kind in ("smb", "ftp"):
        db = f"{kind}_reuse"
        ctx.scan(kind, "lnet/reuse", db=db)
        second = ctx.scan(kind, "lnet/reuse", db=db)
        n = sum(1 for f in second["files"] if f[4])
        ctx.record(f"{kind}: 2回目は使い回す", n == 2, f"使い回し {n}/2")
    n = len(CLEAN.encode("utf-8"))
    import base64

    new = base64.b64encode(("携帯 090-1234-5678 ".encode("utf-8") + b"x" * n)[:n]).decode()
    p = f"{NET}/reuse/change.txt"
    ctx.ssh(f't=$(stat -c %y {p}); echo {new} | base64 -d > {p}; touch -m -d "$t" {p}', user="piitest")
    # Samba は変更日時として更新日時を返す（Linux の ctime は SMB から見えない・実測）ので、FTP と同じく見抜けない
    for kind, expect_reread in (("smb", False), ("ftp", False)):
        third = ctx.scan(kind, "lnet/reuse", db=f"{kind}_reuse")
        ch = [f for f in third["files"] if f[0].replace("\\", "/").endswith("change.txt")][0]
        reread = ch[4] is None
        if expect_reread:
            ctx.record(
                "smb: 大きさ・更新日時を保った書き換えを変更日時で見抜く",
                reread and ch[3] > 0,
                f"読み直した={reread}・検出={ch[3]}",
            )
        else:
            ctx.record(
                f"{kind}: 大きさ・更新日時を保った書き換えは見抜けない（README の限界どおり）",
                not reread,
                f"読み直した={reread}（FTP には変更日時が無い・Samba は変更日時に更新日時を返す）",
            )


def scene_ftp_corpus(ctx: Ctx) -> None:
    for kind in ("ftp", "ftps", "ftps-implicit"):
        age_atimes(ctx, SHARE + "/corpus")
        before = server_inventory(ctx, SHARE + "/corpus")
        res = ctx.scan(kind, "corpus", db=f"{kind}_corpus")
        after = server_inventory(ctx, SHARE + "/corpus")
        fd, da, do = compare_inventory(before, after)
        only_atime = [
            d
            for d in fd
            if d[1] and d[2] and d[1].split("|")[:4] + d[1].split("|")[5:] == d[2].split("|")[:4] + d[2].split("|")[5:]
        ]
        other = [d for d in fd if d not in only_atime]
        ctx.record(
            f"{kind}: 検査の前後でサーバー側のファイルの中身・大きさ・更新日時・権限が変わらない",
            not other and res["files"],
            f"違い {len(other)} {other[:2]}・最終アクセス日時が変わったファイル {len(only_atime)}"
            "（FTP には日時を保つ手段が無い）",
        )
        compare_with_local(ctx, res, kind)


def scene_ftp_names(ctx: Ctx) -> None:
    """隠しファイル・日本語の名前・空白入りの名前・リンクのループ（FTP）。"""
    ctx.put("names/.hidden", PII)
    ctx.put("names/日本語の名簿.txt", PII)
    ctx.put("names/名前 に 空白.txt", PII)
    ctx.put("names/sub/a.txt", CLEAN)
    ctx.ssh(f"ln -sfn .. {NET}/names/sub/back", user="piitest")
    for kind in ("ftp", "ftps"):
        res = ctx.scan(kind, "lnet/names", db=f"{kind}_names", timeout=300)
        names = sorted(f[0].rsplit("/", 1)[1] for f in res["files"])
        hits = sorted(f[0].rsplit("/", 1)[1] for f in res["files"] if f[3] > 0)
        links = [e for e in res["folder_errors"] if e[1] == "link"]
        ok = (
            names == [".hidden", "a.txt", "名前 に 空白.txt", "日本語の名簿.txt"] and len(hits) == 3 and len(links) == 1
        )
        ctx.record(
            f"{kind}: 隠しファイル・日本語・空白入りの名前を見つけ、リンクを辿らない",
            ok,
            f"ファイル {names}・検出 {hits}・リンク {[(e[0].rsplit('/', 1)[1], e[2][:40]) for e in links]}",
        )


def scene_drop(ctx: Ctx) -> None:
    """検査中に回線が切れる（SMB・FTP）: 中断して未検査で残し、つないで再開すると全件を中身まで検査できる。"""
    n = ctx.args.drop_files
    ctx.ssh(
        f"mkdir -p {NET}/drop && cd {NET}/drop && for i in $(seq 0 {n - 1}); do d=g$((i/100)); mkdir -p $d; "
        f"echo '{CLEAN.strip()}' > $d/p$i.txt; done",
        user="piitest",
        timeout=600,
    )
    for kind in ("smb", "ftp"):
        db = ctx.work / f"{kind}_drop.sqlite3"
        cmd = [
            sys.executable,
            "-m",
            "pii_checker",
            "--db",
            str(db),
            "scan",
            "--connect",
            kind,
            "--host",
            ctx.args.host,
            "--path",
            "lnet/drop",
            "--user",
            "piitest",
            "--conn-password-file",
            ctx.args.password_file,
            "--no-ask",
            "--no-reuse",
            "-o",
            str(ctx.work / f"{kind}_drop.xlsx"),
        ]
        if kind == "smb":
            cmd += ["--share", "piitest"]
        log = open(ctx.work / f"{kind}_drop.log", "w", encoding="utf-8")
        proc = subprocess.Popen(cmd, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        done = 0
        deadline = time.time() + 300
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
        running = proc.poll() is None
        subprocess.run(
            ["powershell", "-NoProfile", "-Command", f"Disconnect-VMNetworkAdapter -VMName '{ctx.args.vm}'"], check=True
        )
        cut = time.time()
        try:
            try:
                proc.wait(timeout=900)
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
                    f"Connect-VMNetworkAdapter -VMName '{ctx.args.vm}' -SwitchName 'Default Switch'",
                ],
                check=True,
            )
            log.close()
        took = time.time() - cut
        out = (ctx.work / f"{kind}_drop.log").read_text(encoding="utf-8", errors="replace")
        res = read_db(db, out, took, proc.returncode)
        pending = sum(1 for f in res["files"] if f[1] == "pending")
        bad = [i for i in res["items"] if i[1] == "uncheckable"]
        ctx.record(
            f"{kind} 回線断: 固まらずに中断し、読めなかった分を未検査で残す",
            running and not hung and pending > 0 and not bad and proc.returncode == 3,
            f"{done} 件済みで切断・{took:.0f}秒で終了（終了コード {proc.returncode}）・未検査 {pending}・"
            f"検査不能 {len(bad)} {[b[2][:60] for b in bad[:2]]}",
        )
        for _ in range(60):  # つながるまで待つ
            try:
                ctx.ssh("true", timeout=10)
                break
            except Exception:  # noqa: BLE001
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
                "--conn-password-file",
                ctx.args.password_file,
                "-o",
                str(ctx.work / f"{kind}_drop2.xlsx"),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=1800,
        )
        res2 = read_db(db, r.stdout + r.stderr, 0, r.returncode)
        done2 = sum(1 for f in res2["files"] if f[1] == "done")
        unc2 = sum(1 for f in res2["files"] if f[2] == "uncheckable")
        ctx.record(
            f"{kind} 回線断: 再開すると全件を中身まで検査できる",
            done2 == n and unc2 == 0 and "検出なし" in res2["verdict"],
            f"{done2}/{n}・検査不能 {unc2}・判定={res2['verdict']}",
        )


SCENES = {
    "control": scene_atime_control,
    "smb_corpus": scene_smb_corpus,
    "smb_ro": scene_smb_ro,
    "smb_ads": scene_smb_ads,
    "loop_denied": scene_smb_loop_denied,
    "reuse": scene_smb_reuse,
    "ftp_corpus": scene_ftp_corpus,
    "ftp_names": scene_ftp_names,
    "drop": scene_drop,
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", required=True)
    ap.add_argument("--ssh-key", required=True)
    ap.add_argument("--ssh-user", default="piiadmin")
    ap.add_argument("--password-file", required=True, help="Samba・FTP の piitest のパスワード（1行）")
    ap.add_argument("--work", required=True)
    ap.add_argument("--corpus-local", default="")
    ap.add_argument("--vm", default="PiiTestLinux")
    ap.add_argument("--drop-files", type=int, default=600)
    ap.add_argument("--only", default="")
    args = ap.parse_args()
    ctx = Ctx(args)
    names = [n for n in (args.only.split(",") if args.only else SCENES) if n]
    if ctx.ssh(f"test -e {NET} && echo yes || echo no").strip() == "yes":
        print(
            f"サーバー側に {NET} が既にあります。前回の試験の残りならサーバー側で消してから流してください",
            file=sys.stderr,
        )
        return 2
    ctx.ssh(f"mkdir -p {NET}", user="piitest")
    try:
        for name in names:
            print(f"--- {name}", flush=True)
            try:
                SCENES[name](ctx)
            except Exception as e:  # noqa: BLE001  1つの場面の失敗で全体を止めない
                ctx.record(name, False, f"場面の途中で失敗: {type(e).__name__}: {str(e)[:500]}")
    finally:
        ctx.ssh(f"chmod -R u+rwx {NET} 2>/dev/null; rm -rf --one-file-system {NET}")  # rm -rf はリンクの先を辿らない
    ng = [r for r in ctx.results if not r[1]]
    print(f"\n{len(ctx.results) - len(ng)} 件 OK・{len(ng)} 件 NG")
    (ctx.work / "linux_check_result.json").write_text(
        json.dumps(ctx.results, ensure_ascii=False, indent=1), encoding="utf-8"
    )
    return 1 if ng else 0


if __name__ == "__main__":
    sys.exit(main())

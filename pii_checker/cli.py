"""コマンドラインの入口。

python -m pii_checker scan <フォルダ>... [-o レポート.xlsx]   … 検査してレポートを出す
python -m pii_checker serve [--port 8765]                      … Web 版（ブラウザで操作）
python -m pii_checker app                                      … アプリ版（窓で操作）
python -m pii_checker report <ジョブID> -o レポート.xlsx       … 保存済みジョブのレポート
python -m pii_checker jobs                                     … ジョブ一覧
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import time

from . import __version__
from .models import PasswordBook, ScanOptions
from .remote import ConnectError, Connection, ftp_check, smb_connect, smb_disconnect
from .safeio import NetworkLost
from .runner import DEFAULT_TIMEOUT, JobRunner
from .safeio import output_inside_roots
from .store import Store, StoreOpenError, default_db_path


def default_output_dir() -> str:
    """レポートの既定の出力先（ドキュメント）。今いるフォルダが検査先の中でも、そこへは書かない。"""
    if os.name == "nt":
        import ctypes

        buf = ctypes.create_unicode_buffer(260)
        if ctypes.windll.shell32.SHGetFolderPathW(None, 5, None, 0, buf) == 0 and buf.value:  # 5 = ドキュメント
            return buf.value
    return os.path.join(os.path.expanduser("~"), "Documents")


STATE_JA = {
    "running": "実行中",
    "done": "完了",
    "cancelled": "中止",
    "interrupted": "中断",
    "error": "エラー",
    "created": "準備中",
}
EPILOG = r"""使用例:
  pii-checker scan \\nas01\総務 -o 結果.xlsx          NAS の共有フォルダを検査して Excel にまとめる
  pii-checker scan D:\共有 --password-file pw.txt     分かっているパスワードを全部の暗号化ファイルに試す
  pii-checker scan --resume <ジョブID>                中断した検査の続き
  pii-checker scan D:\共有 --allow-file 許可.txt --rules-file 規則.txt
                                                     拾わない値・自分で足す規則を使う
  pii-checker scan \\nas01\総務 --no-ask --exit-by-verdict
                                                     定期検査（判定を終了コード 0/1/4 で返す）
  pii-checker serve                                  ブラウザで操作する（Web 版）
  pii-checker app                                    窓で操作する（アプリ版。引数なしでも起動）
（開発環境では pii-checker の代わりに python -m pii_checker）
"""


def _progress_line(store: Store, runner: JobRunner, final: bool = False) -> str:
    s = store.summary(runner.job_id)
    st = s["item_status"]
    phase = ("中断" if runner.error else "完了") if final else runner.phase
    return (
        f"\r[{phase}] {s['files_done']:,}/{s['files_total']:,} ファイル"
        f"  検出あり {s['files_with_findings']:,}  要パスワード {st.get('needs_password', 0):,}"
        f"  検査不能 {st.get('uncheckable', 0):,}  簡易 {st.get('partial', 0):,}   "
    )


def _run_until_done(store: Store, runner: JobRunner) -> None:
    runner.start()
    try:
        while runner.running:
            sys.stdout.write(_progress_line(store, runner))
            sys.stdout.flush()
            runner.wait(1.0)
    except KeyboardInterrupt:
        print("\n中止します（ここまでの結果は保存済み。同じジョブを再開できます）…")
        runner.cancel()
        runner.wait()
    sys.stdout.write(_progress_line(store, runner, final=True) + "\n")
    if runner.error:
        # 自分から止めた理由（NAS への接続が切れた・ドライブの満杯等）。再開の仕方は最後に出す
        print(f"検査を止めました: {runner.error}")


def _interactive() -> bool:
    """人がコンソールで打てる状態か。Windows では標準入力が NUL でも isatty() が真になるので、コンソールかを確かめる。"""
    if not sys.stdin or not sys.stdin.isatty():
        return False
    if os.name != "nt":
        return True
    try:
        import ctypes
        import msvcrt

        mode = ctypes.c_uint32()
        handle = msvcrt.get_osfhandle(sys.stdin.fileno())
        return bool(ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode)))
    except Exception:
        return False


def _connection_password(conn, args) -> str:
    """接続方式のパスワードを受け取る（ファイル → コンソールで聞く の順）。保存しない。"""
    if args.conn_password_file:
        with open(args.conn_password_file, encoding="utf-8") as f:
            return f.readline().rstrip("\r\n")
    if not conn.user:
        return ""  # SMB は今の Windows のアカウント、FTP は匿名
    if not _interactive():
        raise ConnectError(
            "接続のパスワードを聞けません（無人実行）。--conn-password-file にパスワードを1行で書いたファイルを指定してください"
        )
    return getpass.getpass(f"{conn.label()} の {conn.user} のパスワード: ")


def _open_connection(conn, password: str) -> bool:
    """接続方式の接続を確かめる（SMB はつなぐ）。新しく SMB をつないだら True（最後に切る）。"""
    if conn.is_ftp:
        print(ftp_check(conn, password))
        return False
    created = smb_connect(conn, password)
    print(f"接続しました（{conn.label()}）")
    return created


def _read_user_text(path: str, what: str) -> str:
    """許可リスト・規則のファイル（UTF-8。メモ帳の BOM 付きも可）を読む。読めなければ UserTextError。"""
    try:
        with open(path, encoding="utf-8-sig") as f:
            return f.read()
    except FileNotFoundError:
        raise UserTextError(f"{what}のファイルが見つかりません: {path}") from None
    except UnicodeDecodeError:
        raise UserTextError(
            f"{what}のファイル（{path}）を UTF-8 として読めません。メモ帳の「名前を付けて保存」で文字コードを"
            "「UTF-8」にして保存し直してください"
        ) from None
    except OSError as e:
        raise UserTextError(f"{what}のファイル（{path}）を読めません: {e}") from None


class UserTextError(Exception):
    """許可リスト・規則のファイルを読めない・書き方が誤っている（文面はそのまま人に見せる）。"""


def _user_rules(args) -> tuple[list[str], list[dict]]:
    """--allow-file・--rules-file を読み、書き方を確かめる（検査を始める前に断る）。"""
    from .userrules import RuleError, parse_allow_list, parse_rules

    allow: list[str] = []
    rules: list[dict] = []
    try:
        if args.allow_file:
            allow = parse_allow_list(_read_user_text(args.allow_file, "拾わない値（許可リスト）"))
        if args.rules_file:
            rules = [r.to_dict() for r in parse_rules(_read_user_text(args.rules_file, "自分で足す規則"))]
    except RuleError as e:
        raise UserTextError(str(e)) from None
    return allow, rules


def cmd_scan(args) -> int:
    conn = None
    conn_password = ""
    smb_created = False
    if args.resume and (args.allow_file or args.rules_file):
        print(
            "--resume と --allow-file・--rules-file は一緒に使えません"
            "（再開は、始めたときの拾わない値・自分で足す規則をそのまま使います。変えるときは新しく検査してください）",
            file=sys.stderr,
        )
        return 2
    try:
        args.user_allow, args.user_rules = _user_rules(args)
    except UserTextError as e:
        print(str(e), file=sys.stderr)
        return 2
    if args.connect and args.resume:
        print(
            "--resume と --connect は一緒に使えません（再開は保存してある接続先を使います）",
            file=sys.stderr,
        )
        return 2
    stray = [f"--{n.replace('_', '-')}" for n in ("host", "share", "path", "user", "port") if getattr(args, n)]
    if stray and not args.connect:
        print(
            f"{'・'.join(stray)} は --connect と一緒に使ってください（接続方式の指定です）",
            file=sys.stderr,
        )
        return 2
    if args.connect:
        if args.roots:
            print(
                "フォルダの指定と --connect は一緒に使えません（どちらか一方にしてください）",
                file=sys.stderr,
            )
            return 2
        try:
            conn = Connection.from_dict(
                {
                    "kind": args.connect.replace("-", "_"),
                    "host": args.host or "",
                    "share": args.share or "",
                    "path": args.path or "",
                    "user": args.user or "",
                    "port": args.port,
                    "encoding": args.encoding,
                    "verify_cert": args.verify_cert,
                }
            )
            if not conn.host:
                raise ConnectError("--host でサーバーの名前か IP アドレスを指定してください")
            if conn.kind == "smb" and not conn.share:
                raise ConnectError(r"--share で共有名を指定してください（例: \\nas01\総務 なら --share 総務）")
            conn.validate()
            conn_password = _connection_password(conn, args)
            smb_created = _open_connection(conn, conn_password)
        except (
            ConnectError,
            NetworkLost,
        ) as e:  # 応答が無い等も1行の文で（Traceback にしない）
            print(str(e), file=sys.stderr)
            return 2
        args.roots = [conn.root()]
    store = None
    if args.resume:
        # 接続方式で始めたジョブの再開: 保存してある接続先へ、パスワードをもう一度受け取ってつなぐ（パスワードは保存していない）
        store = _open_store(args.db)
        job = store.job(args.resume)
        saved = job["options"].get("connection") if job else None
        if saved:
            try:
                conn = Connection.from_dict(saved)
                conn_password = _connection_password(conn, args)
                smb_created = _open_connection(conn, conn_password)
            except (
                ConnectError,
                NetworkLost,
            ) as e:  # 応答が無い等も1行の文で（Traceback にしない）
                print(str(e), file=sys.stderr)
                return 2
    try:
        return _cmd_scan(args, conn, conn_password, store)
    finally:
        if smb_created:
            smb_disconnect(conn)


def _cmd_scan(args, conn, conn_password: str, store=None) -> int:
    on_ftp = conn is not None and conn.is_ftp
    if not args.resume and not on_ftp:
        # 保存先を開くとフォルダと DB ができるので、検査先の中かどうかは開く前に確かめる（開いてから断ると検査先に残る）
        msg = output_inside_roots(
            os.path.abspath(args.db or default_db_path()),
            [os.path.abspath(r) for r in args.roots],
            "検査結果の保存先（--db で変えられる）",
        )
        if msg:
            print(msg, file=sys.stderr)
            return 2
        # 新しいジョブは、指定した場所に届くかを先に確かめる（Web 版と同じ）。届かないまま始めると、打ち間違いでも
        # 「NAS への接続が切れたため中断」と出て、再開を繰り返させてしまう（不具合の修正）
        from .engine import long_path

        missing = [r for r in args.roots if not os.path.exists(long_path(os.path.abspath(r)))]
        for r in missing:
            print(
                f"指定した場所に届きません: {r}（名前の間違い・NAS につながっていない・アクセス権が無い のどれか）。"
                "パスと接続を確かめてから、もう一度実行してください",
                file=sys.stderr,
            )
        if missing:
            return 2
    store = store or _open_store(args.db)
    opts = ScanOptions(
        ocr=not args.no_ocr,
        deep_image_sweep=args.deep_image_sweep,
        reuse=not args.no_reuse,
        temp_dir=args.temp_dir,
        sevenzip=args.sevenzip,
        connection=conn.public() if conn else None,
        allow_values=getattr(args, "user_allow", None) or [],
        custom_rules=getattr(args, "user_rules", None) or [],
    )
    roots = list(args.roots) if on_ftp else [os.path.abspath(r) for r in args.roots]
    if args.resume and store.job(args.resume):
        roots = store.job(args.resume)["roots"]
    out = args.output or os.path.join(default_output_dir(), f"個人情報チェッカー_{{job}}.xlsx")
    import tempfile

    if args.temp_dir and not os.path.isdir(args.temp_dir):
        print(
            f"展開に使う一時フォルダ（{args.temp_dir}）が見つかりません。ある場所を指定してください",
            file=sys.stderr,
        )
        return 2
    for path, what in (
        (out, "レポートの出力先"),
        (
            args.temp_dir or tempfile.gettempdir(),
            "展開に使う一時フォルダ（--temp-dir で変えられる）",
        ),
        (store.path, "検査結果の保存先（--db で変えられる）"),
    ):
        msg = None if on_ftp else output_inside_roots(path, roots, what)  # FTP の先に手元の出力は入りえない
        if msg:
            print(msg, file=sys.stderr)
            return 2
    book = PasswordBook(connection_password=conn_password)
    if args.password_file:
        with open(args.password_file, encoding="utf-8") as f:
            book.common = [ln.rstrip("\r\n") for ln in f if ln.strip()]
    if args.resume:
        job_id = args.resume
        if not store.job(job_id):
            print(f"ジョブ {job_id} が見つかりません", file=sys.stderr)
            return 2
    else:
        job_id = store.create_job(
            roots,
            opts,
            name=conn.short_name() if conn else store.default_job_name(roots),
        )
    print(f"ジョブ {job_id} を開始します（結果の保存先: {store.path}）")
    job_opts = store.job(job_id)["options"]
    if job_opts.get("allow_values") or job_opts.get("custom_rules"):
        from .userrules import rule_names

        names = rule_names(job_opts.get("custom_rules"))
        print(
            f"拾わない値 {len(job_opts.get('allow_values') or [])} 件・自分で足す規則 {len(names)} 件"
            + (f"（{'、'.join(names)}）" if names else "")
            + " を使います"
        )
    runner = JobRunner(store, job_id, workers=args.workers, timeout=args.timeout, passwords=book)
    if args.resume and book.common:
        # 再開時に受け取ったパスワードは、パスワードが必要だったファイルにも試す
        locked = store.files_with_status(job_id, ["needs_password"])
        if locked:
            store.mark_pending(job_id, locked)
            print(f"パスワードが必要だった {len(locked)} 件に、受け取ったパスワード {len(book.common)} 個を試します")
    else:
        locked = []
    _run_until_done(store, runner)
    if locked:
        still = set(store.files_with_status(job_id, ["needs_password"])) & set(locked)
        if still:
            print(
                f"受け取ったパスワードでは {len(still)} 件が開きませんでした（{len(locked) - len(still)} 件は開きました）"
            )
        else:
            print(f"{len(locked)} 件すべて開きました")

    # 要パスワードが残っていれば、まとめて聞いて全部に当てる（1ファイルずつは聞かない）
    while not args.no_ask and _interactive():
        locked = store.files_with_status(job_id, ["needs_password"])
        if not locked:
            break
        print(f"\nパスワードが必要なファイルが {len(locked)} 件あります:")
        for p in locked[:10]:
            print("  -", p)
        if len(locked) > 10:
            print(f"  …ほか {len(locked) - 10} 件")
        pw = getpass.getpass("パスワードを入力すると全件に試します（空で終了）: ")
        if not pw:
            break
        n = runner.add_password(pw)
        print(f"{n} 件を再検査します")
        _run_until_done(store, runner)

    out = out.replace("{job}", job_id)
    from .report import write_csv, write_xlsx

    write_xlsx(store, job_id, out)
    print(f"レポート: {out}")
    if args.csv:
        for p in write_csv(store, job_id, os.path.dirname(os.path.abspath(out))):
            print(f"CSV: {p}")
    from .verdict import decide

    v = decide(store.summary(job_id), store.job(job_id)["state"], target="cli")
    print(f"\n総合判定: {v.title}")
    for line in v.detail:
        print("  " + line)
    if v.next_step:
        print(f"\n次にすること: {v.next_step}")
    from .jobdiff import cli_line, compute

    print(f"\n{cli_line(compute(store, job_id))}")
    if store.files_with_status(job_id, ["needs_password"]):
        print(f"  パスワードが分かれば: pii-checker scan --resume {job_id} --password-file パスワード一覧.txt")
    if store.pending_files(job_id) or store.job(job_id)["state"] in (
        "interrupted",
        "cancelled",
    ):
        print(f"  中断した続きを調べるには: pii-checker scan --resume {job_id}")
    if store.job(job_id)["state"] in ("interrupted", "cancelled", "error"):
        # 無人で回すとき（タスクスケジューラ等）に、最後まで終わらなかったことを終了コードで分かるようにする
        return EXIT_INTERRUPTED
    if getattr(args, "exit_by_verdict", False):
        code = exit_code_for(v.level)
        print(f"\n終了コード {code}（{EXIT_MEANINGS[code]}。--exit-by-verdict）")
        return code
    return 0


# 検査を最後まで終えられなかった（NAS への接続が切れた・ドライブの満杯・中止）。続きは --resume で再開できる
EXIT_INTERRUPTED = 3
# --exit-by-verdict を付けたとき、最後まで検査できた場合の終了コード（2 と 3 はこれより優先）
EXIT_FOUND = 1  # 個人情報の可能性あり
EXIT_UNSURE = 4  # 要確認（確度の低い候補のみ）・言い切れない（調べられなかったものがある・ファイルが見つからない）
EXIT_MEANINGS = {
    0: "検出なし",
    EXIT_FOUND: "個人情報の可能性あり",
    EXIT_UNSURE: "要確認・言い切れない",
}


def exit_code_for(level: str) -> int:
    """総合判定の段階（verdict.Verdict.level）から、--exit-by-verdict の終了コードを決める。"""
    if level in ("clean", "clean_partial"):
        return 0
    if level == "found":
        return EXIT_FOUND
    return EXIT_UNSURE


def cmd_report(args) -> int:
    store = Store(args.db)
    from .report import write_csv, write_xlsx

    job = store.job(args.job)
    if not job:
        print(f"ジョブ {args.job} が見つかりません", file=sys.stderr)
        return 2
    out = args.output or os.path.join(default_output_dir(), f"個人情報チェッカー_{args.job}.xlsx")
    msg = output_inside_roots(out, job["roots"], "レポートの出力先")
    if msg:
        print(msg, file=sys.stderr)
        return 2
    write_xlsx(store, args.job, out)
    print(f"レポート: {out}")
    if args.csv:
        for p in write_csv(store, args.job, os.path.dirname(os.path.abspath(out))):
            print(f"CSV: {p}")
    return 0


def _open_store(path: str | None) -> Store:
    """結果の保存先を開き、壊れていたときの知らせと、止まったまま「実行中」のジョブの直しを済ませる。"""
    store = Store(path)
    if store.recovered:
        print(store.recovered, file=sys.stderr)
    store.reconcile_running()
    return store


def cmd_jobs(args) -> int:
    store = _open_store(args.db)
    for j in store.jobs():
        print(
            f"{j['id']}  {STATE_JA.get(j['state'], j['state']):<4} {time.strftime('%Y-%m-%d %H:%M', time.localtime(j['created']))}  {j['name']}"
        )
    return 0


def cmd_serve(args) -> int:
    from .web.server import run_server

    run_server(
        host=args.host,
        port=args.port,
        db=args.db,
        token=args.token,
        open_browser=not args.no_browser,
    )
    return 0


def cmd_app(args) -> int:
    from .desktop import run_app

    run_app(db=args.db)
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="pii-checker",
        description="フォルダ内の個人情報らしきものを探してレポートにする",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--version", action="version", version=f"個人情報チェッカー {__version__}")
    ap.add_argument(
        "--db",
        help="検査結果を保存するファイル（既定: %%LOCALAPPDATA%%/PiiChecker/jobs.sqlite3）",
    )
    sub = ap.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="フォルダを検査してレポートを出す")
    s.add_argument(
        "roots",
        nargs="*",
        help="検査するフォルダまたはファイル（\\\\NAS\\共有 の形も可）",
    )
    s.add_argument(
        "-o",
        "--output",
        help="レポート（.xlsx）の出力先（既定はドキュメント。検査するフォルダの中は指定できない）",
    )
    s.add_argument("--csv", action="store_true", help="CSV も出す")
    s.add_argument("--workers", type=int, help="同時に検査するファイル数（既定: CPU数-1、最大8）")
    s.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help="1ファイルあたりの時間制限（秒。既定 1800 = 30分）",
    )
    s.add_argument("--password-file", help="試すパスワードの一覧（UTF-8・1行1つ）")
    s.add_argument("--no-ask", action="store_true", help="最後にパスワードを聞かない")
    s.add_argument(
        "--no-reuse",
        action="store_true",
        help="前回から変わっていないファイルも全部読み直す（既定は前回の結果を使い回して速くする）",
    )
    s.add_argument(
        "--no-ocr",
        action="store_true",
        help="画像・画像PDFの OCR をしない（その分は検査不能になる）",
    )
    s.add_argument(
        "--deep-image-sweep",
        action="store_true",
        help="ディスクイメージの未使用領域（削除済みファイル）も走査する",
    )
    s.add_argument("--temp-dir", help="展開に使う一時フォルダ（空きの多いドライブを指定）")
    s.add_argument("--sevenzip", help="7z.exe の場所")
    s.add_argument("--resume", metavar="ジョブID", help="中断したジョブを続きから再開する")
    s.add_argument(
        "--exit-by-verdict",
        action="store_true",
        help="最後まで検査できたときの終了コードを総合判定で変える（0=検出なし、1=個人情報の可能性あり、"
        "4=要確認・言い切れない。2=指定の誤り・3=途中で止めた は付けなくても同じ）",
    )
    s.add_argument(
        "--allow-file",
        metavar="ファイル",
        help="拾わない値（許可リスト）の一覧（UTF-8・1行に1つ。自社の代表番号・所在地・見本の氏名など）",
    )
    s.add_argument(
        "--rules-file",
        metavar="ファイル",
        help="自分で足す規則の一覧（UTF-8・1行に1つ「名前 | 探す語か正規表現 | 確度」。例: 社員番号 | EMP-\\d{6} | 中）",
    )
    c = s.add_argument_group(
        "接続方式で指定する（フォルダの代わりに。パスワードは聞いて使うだけで保存しない）",
        "例: scan --connect smb --host nas01 --share 総務 --path 2024年度 --user taro / "
        "scan --connect ftps --host 192.168.0.5 --path 共有 --user taro",
    )
    c.add_argument(
        "--connect",
        choices=["smb", "ftp", "ftps", "ftps-implicit"],
        help="接続方式（smb = Windows 共有・Samba、ftps = 明示的 TLS、ftps-implicit = 暗黙的 TLS）",
    )
    c.add_argument("--host", help="サーバーの名前か IP アドレス")
    c.add_argument("--share", help="SMB の共有名")
    c.add_argument(
        "--path", help="共有・FTP の中のフォルダ（例 総務/2024年度。既定は SMB は共有の一番上、FTP はログインした場所）"
    )
    c.add_argument(
        "--user",
        help="ユーザー名（空なら SMB は今の Windows のアカウント、FTP は匿名）",
    )
    c.add_argument("--port", type=int, help="ポート（FTP のみ。既定 21・暗黙的 TLS は 990）")
    c.add_argument(
        "--encoding",
        choices=["auto", "utf-8", "cp932"],
        default="auto",
        help="FTP のファイル名の文字コード",
    )
    c.add_argument(
        "--verify-cert",
        action="store_true",
        help="FTPS でサーバーの証明書を確かめる（自己署名なら付けない）",
    )
    c.add_argument(
        "--conn-password-file",
        help="接続のパスワードを1行で書いたファイル（無人実行用。無ければコンソールで聞く）",
    )
    s.set_defaults(func=cmd_scan)

    r = sub.add_parser("report", help="保存済みジョブのレポートを出す")
    r.add_argument("job")
    r.add_argument("-o", "--output", help="レポート（.xlsx）の出力先（既定はドキュメント）")
    r.add_argument("--csv", action="store_true")
    r.set_defaults(func=cmd_report)

    j = sub.add_parser("jobs", help="ジョブの一覧")
    j.set_defaults(func=cmd_jobs)

    w = sub.add_parser("serve", help="Web 版を起動する（ブラウザで操作）")
    w.add_argument("--host", default="127.0.0.1", help="待ち受けるアドレス（既定は自分の PC だけ）")
    w.add_argument("--port", type=int, default=8765)
    w.add_argument(
        "--token",
        help="他の PC から使うときの合言葉（127.0.0.1 以外で待ち受けるときは必須）",
    )
    w.add_argument("--no-browser", action="store_true", help="起動時にブラウザを開かない")
    w.set_defaults(func=cmd_serve)

    a = sub.add_parser("app", help="アプリ版を起動する（窓で操作）")
    a.set_defaults(func=cmd_app)
    return ap


def main(argv: list[str] | None = None) -> int:
    ap = build_parser()
    if argv is None:
        argv = sys.argv[1:]
    args = ap.parse_args(argv)
    if not getattr(args, "cmd", None):
        # サブコマンドが無ければアプリ版。全体の指定（--db 等）はサブコマンドより前に置く決まりなので、後ろに app を足す
        # （「PiiChecker.exe --db D:\x\jobs.sqlite3」で保存先を変えて窓を開けるように）
        args = ap.parse_args(argv + ["app"])
    if args.cmd == "scan" and not args.roots and not args.resume and not args.connect:
        if any(getattr(args, n, None) for n in ("host", "share", "path", "user", "port")):
            ap.error(
                "--host などの接続方式の指定は --connect と一緒に使ってください（例: --connect smb --host nas01 --share 総務）"
            )
        ap.error("検査するフォルダを指定してください（例: python -m pii_checker scan \\\\nas\\share）")
    try:
        return args.func(args)
    except StoreOpenError as e:
        print(e, file=sys.stderr)
        if args.cmd == "app":
            # アプリ版（PiiChecker.exe）はコンソールが無く、上の表示が見えないので窓でも知らせる
            try:
                import ctypes

                ctypes.windll.user32.MessageBoxW(None, str(e), "個人情報チェッカー", 0x10)
            except Exception:
                pass
        return 2

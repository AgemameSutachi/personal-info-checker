"""コマンドの入口の試験。"""

import sys

from pii_checker import cli


def _capture_app(monkeypatch):
    seen = {}
    p = cli.build_parser()
    p._subparsers._group_actions[0].choices["app"].set_defaults(func=lambda a: seen.setdefault("db", a.db) and 0)
    monkeypatch.setattr(cli, "build_parser", lambda: p)
    return seen


def test_db_option_reaches_app_without_subcommand(monkeypatch):
    """「PiiChecker.exe --db D:\\x\\jobs.sqlite3」で保存先を変えて窓を開ける（断る文で案内している起動方法。不具合の修正）。"""
    seen = _capture_app(monkeypatch)
    cli.main(["--db", "D:/x/jobs.sqlite3"])
    assert seen["db"] == "D:/x/jobs.sqlite3"


def test_db_option_from_real_argv(monkeypatch):
    seen = _capture_app(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["PiiChecker.exe", "--db", "E:/y.sqlite3"])
    cli.main()
    assert seen["db"] == "E:/y.sqlite3"


def test_version_is_printed(capsys):
    """不具合の報告に書いてもらう版を、コマンドで確かめられる。"""
    import pytest

    from pii_checker import __version__

    with pytest.raises(SystemExit) as e:
        cli.build_parser().parse_args(["--version"])
    assert e.value.code == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert lines[0] == f"個人情報チェッカー {__version__}"
    assert lines[1].startswith("検出エンジン: ")  # Rust 拡張を使っているか（不具合の切り分けに使う）


def test_version_does_not_crash_when_output_cannot_encode_japanese(monkeypatch):
    """日本語以外の Windows でパイプへ出すとき（cp1252）も、--version で落ちない（配布版を VM で試して見つけた不具合）。"""
    import io

    import pytest

    out = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    monkeypatch.setattr(sys, "stdout", out)
    with pytest.raises(SystemExit) as e:
        cli.main(["--version"])
    assert e.value.code == 0
    out.flush()
    first_line = out.buffer.getvalue().decode("cp1252").strip().splitlines()[0]
    assert first_line.endswith(__import__("pii_checker").__version__)


def test_db_in_new_folder_is_created(tmp_path):
    """--db で無いフォルダを指しても、置き場を作って検査結果を保存できる（exe の確認で落ちていた・2026-10-17）。"""
    db = tmp_path / "new" / "sub" / "jobs.sqlite3"
    assert cli.main(["--db", str(db), "jobs"]) == 0
    assert db.is_file()


def test_db_that_cannot_open_gives_plain_message(tmp_path, capsys):
    """保存先を開けないときは、トレースバックではなく何を確かめればよいかを日本語で出して終了コード 2。"""
    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    # 「ファイルの下」はフォルダを作れず、DB も開けない
    assert cli.main(["--db", str(blocker / "jobs.sqlite3"), "jobs"]) == 2
    err = capsys.readouterr().err
    assert "検査結果の保存先" in err and "確かめてください" in err


def test_db_inside_scan_root_is_refused_before_creating(tmp_path, capsys):
    """保存先が検査先の中なら、フォルダも DB も作らずに断る（開いてから断ると検査先に残っていた・不具合の修正）。"""
    root = tmp_path / "share"
    root.mkdir()
    db = root / "newdir" / "jobs.sqlite3"
    assert cli.main(["--db", str(db), "scan", str(root), "--no-ask"]) == 2
    assert "検査結果の保存先" in capsys.readouterr().err
    assert list(root.iterdir()) == []


def test_locked_db_is_not_recreated(tmp_path, monkeypatch):
    """他が掴んでいる（ロック中の）保存先は壊れていないので、別名にせず、閉じてから実行するよう知らせる。"""
    import sqlite3

    import pytest

    from pii_checker import store as store_mod

    db = tmp_path / "jobs.sqlite3"
    store_mod.Store(str(db))._conn.close()
    holder = sqlite3.connect(str(db))
    holder.execute("PRAGMA locking_mode=EXCLUSIVE")
    holder.execute("BEGIN EXCLUSIVE")
    real_connect = sqlite3.connect
    monkeypatch.setattr(
        store_mod.sqlite3,
        "connect",
        lambda *a, **k: real_connect(*a, **{**k, "timeout": 0.2}),
    )
    try:
        with pytest.raises(store_mod.StoreOpenError) as ei:
            store_mod.Store(str(db))
    finally:
        holder.close()
    assert "閉じてから" in str(ei.value)
    assert not list(tmp_path.glob("*.broken-*"))


def test_unreachable_root_is_refused_before_starting(tmp_path, capsys):
    """届かない場所（打ち間違い・NAS 未接続）は、ジョブを作る前に分かる文で断る（「接続が切れたため中断」と出さない）。"""
    db = tmp_path / "jobs.sqlite3"
    assert cli.main(["--db", str(db), "scan", str(tmp_path / "nothing"), "--no-ask"]) == 2
    err = capsys.readouterr().err
    assert "届きません" in err and "名前の間違い" in err
    assert not db.exists()  # ジョブも DB も作らない


def test_interrupted_scan_exits_nonzero(tmp_path, monkeypatch):
    """最後まで終えられなかった（中断）ときは終了コード 3（無人実行で見分けられるように）。"""
    from pii_checker import runner

    root = tmp_path / "root"
    root.mkdir()
    (root / "a.txt").write_text("会議の議題\n", encoding="utf-8")

    def halted(self):
        self._halt(runner.NETWORK_HALT_MESSAGE)

    monkeypatch.setattr(runner.JobRunner, "_scan_pending", halted)
    out = tmp_path / "out"
    out.mkdir()
    code = cli.main(
        [
            "--db",
            str(tmp_path / "j.sqlite3"),
            "scan",
            str(root),
            "--no-ask",
            "-o",
            str(out / "r.xlsx"),
        ]
    )
    assert code == cli.EXIT_INTERRUPTED
    monkeypatch.undo()
    # 陽性対照: 最後まで終われば 0
    code = cli.main(
        [
            "--db",
            str(tmp_path / "j2.sqlite3"),
            "scan",
            str(root),
            "--no-ask",
            "-o",
            str(out / "r2.xlsx"),
        ]
    )
    assert code == 0


def _scan(tmp_path, root, name, *extra):
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    return cli.main(
        ["--db", str(tmp_path / f"{name}.sqlite3"), "scan", str(root), "--no-ask", "-o", str(out / f"{name}.xlsx")]
        + list(extra)
    )


def test_exit_code_by_verdict(tmp_path):
    """--exit-by-verdict を付けたときだけ、判定で終了コードを変える（0=検出なし・1=可能性あり・4=要確認・言い切れない）。"""
    cases = {
        "clean": ("会議の議題\n", 0),
        "found": ("顧客 携帯 090-1234-5678\n", cli.EXIT_FOUND),
        "low": ("123456789018\n", cli.EXIT_UNSURE),  # 語の無い12桁（検査数字は合う）＝確度 低 だけ
    }
    for name, (text, want) in cases.items():
        root = tmp_path / name
        root.mkdir()
        (root / "a.txt").write_text(text, encoding="utf-8")
        assert _scan(tmp_path, root, name, "--exit-by-verdict") == want, name
    # 付けないときは今までどおり 0
    assert _scan(tmp_path, tmp_path / "found", "found_plain") == 0
    # ファイルが1件も無い（言い切れない）
    empty = tmp_path / "empty"
    empty.mkdir()
    assert _scan(tmp_path, empty, "empty", "--exit-by-verdict") == cli.EXIT_UNSURE


def test_exit_by_verdict_keeps_interrupted_and_resume(tmp_path, monkeypatch):
    """途中で止めたときは --exit-by-verdict を付けても 3。--resume でも判定の終了コードを返す。"""
    from pii_checker import runner
    from pii_checker.store import Store

    root = tmp_path / "root"
    root.mkdir()
    (root / "a.txt").write_text("顧客 携帯 090-1234-5678\n", encoding="utf-8")

    def halted(self):
        self._halt(runner.NETWORK_HALT_MESSAGE)

    monkeypatch.setattr(runner.JobRunner, "_scan_pending", halted)
    assert _scan(tmp_path, root, "j", "--exit-by-verdict") == cli.EXIT_INTERRUPTED
    monkeypatch.undo()
    job = Store(str(tmp_path / "j.sqlite3")).jobs()[0]["id"]
    code = cli.main(
        ["--db", str(tmp_path / "j.sqlite3"), "scan", "--resume", job, "--no-ask", "--exit-by-verdict"]
        + ["-o", str(tmp_path / "out" / "resume.xlsx")]
    )
    assert code == cli.EXIT_FOUND


def test_exit_code_for_levels():
    assert [cli.exit_code_for(x) for x in ("clean", "clean_partial", "found", "low_only", "undetermined", "empty")] == [
        0,
        0,
        1,
        4,
        4,
        4,
    ]


def test_cli_prints_diff_line_and_totals(tmp_path, capsys):
    """コマンドの最後に前回との違いの1行を出す（前回が無ければその旨）。"""
    root = tmp_path / "data"
    root.mkdir()
    (root / "a.txt").write_text("顧客 携帯 090-1234-5678\n", encoding="utf-8")
    assert _scan(tmp_path, root, "diff") == 0
    out = capsys.readouterr().out
    assert "前回との違い: 比べる前回の検査がありません" in out
    (root / "b.txt").write_text("顧客 携帯 080-1111-2222\n", encoding="utf-8")
    assert _scan(tmp_path, root, "diff") == 0
    out = capsys.readouterr().out
    line = next(x for x in out.splitlines() if x.startswith("前回との違い:"))
    assert "新しく見つかった 1 件・無くなった 0 件・増えた 0 件・減った 0 件" in line and "前回の検査（" in line
    assert "人数の目安の合計 2" in out  # 判定の文にジョブ全体の合計


def test_rules_file_help_names_the_format():
    text = cli.build_parser()._subparsers._group_actions[0].choices["scan"].format_help()
    assert "名前 | 探す語か正規表現 | 確度" in text


def test_scan_without_console_streams_does_not_crash(tmp_path, monkeypatch):
    """標準出力・標準エラーが無い（窓の exe・pythonw）ときも、進み具合の表示で落ちずに最後まで検査する。

    再現: 窓の exe（PiiChecker.exe）へ scan の引数を渡すと、sys.stdout が None のため進み具合の表示で
    'NoneType' object has no attribute 'write' で落ち、エラーの窓が出ていた（不具合の修正）。
    """
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.txt").write_text("顧客 携帯 090-1234-5678\n", encoding="utf-8")
    monkeypatch.setattr(sys, "stdout", None)
    monkeypatch.setattr(sys, "stderr", None)
    assert _scan(tmp_path, root, "nostream", "--exit-by-verdict") == cli.EXIT_FOUND
    assert (tmp_path / "out" / "nostream.xlsx").is_file()


def _capture_app_main(monkeypatch):
    seen = {"alerts": []}
    monkeypatch.setattr(cli, "_alert", lambda m: seen["alerts"].append(m))
    monkeypatch.setattr(cli, "cmd_app", lambda a: seen.update(db=a.db, paths=a.paths) or 0)

    def no_scan(args):
        raise AssertionError("アプリ版の入口からコマンドの処理へ入った")

    monkeypatch.setattr(cli, "cmd_scan", no_scan)
    return seen


def test_app_exe_with_dropped_paths_opens_window(monkeypatch):
    """アプリ版へフォルダ・ファイルをドラッグして離す／「送る」で開くと、そのパスを対象に入れて窓を開く。"""
    seen = _capture_app_main(monkeypatch)
    assert cli.app_main([r"D:\共有 1", r"E:\名簿.xlsx"]) == 0
    assert seen["paths"] == [r"D:\共有 1", r"E:\名簿.xlsx"] and seen["db"] is None
    assert cli.app_main(["--db", "D:/x/jobs.sqlite3"]) == 0
    assert seen["paths"] == [] and seen["db"] == "D:/x/jobs.sqlite3"
    assert cli.app_main([]) == 0 and seen["paths"] == []
    assert not seen["alerts"]


def test_app_exe_with_command_args_does_not_scan(monkeypatch):
    """アプリ版にコマンドの指定（scan 等）が渡っても検査へは入らず、コマンド版を使うよう窓で知らせる。"""
    seen = _capture_app_main(monkeypatch)
    monkeypatch.setattr(sys, "stdout", None)
    monkeypatch.setattr(sys, "stderr", None)
    assert cli.app_main(["--db", "D:/x.sqlite3", "scan", r"D:\共有", "--no-ask", "-o", "r.xlsx"]) == 2
    assert "paths" not in seen
    assert len(seen["alerts"]) == 1 and "PiiChecker-cmd.exe" in seen["alerts"][0]
    # コマンドの語やオプションが先頭に無くても、パスと取り違えて窓を開かない
    assert cli.app_main(["-o", "r.xlsx", "scan", r"D:\共有"]) == 2
    assert cli.app_main([r"D:\共有", "--no-ask"]) == 2
    assert "paths" not in seen and len(seen["alerts"]) == 3


def test_app_exe_with_dropped_drive_root(monkeypatch):
    """ドライブの直下（"D:\\"）を落とすと Windows の引数の読み方で D:" で届くので、D:\\ に戻して対象に入れる。"""
    seen = _capture_app_main(monkeypatch)
    assert cli.app_main(['D:"']) == 0
    assert seen["paths"] == ["D:\\"]


def test_app_url_carries_dropped_paths():
    """窓で開く URL に、対象に入れておくパスを載せる（空白・日本語・円記号も崩さない）。"""
    from urllib.parse import parse_qs, urlparse

    from pii_checker.desktop import app_url

    q = parse_qs(urlparse(app_url(1234, "tok", [r"D:\共有 1", r"\nas01\総務&経理"])).query)
    assert q["token"] == ["tok"] and q["root"] == [r"D:\共有 1", r"\nas01\総務&経理"]
    assert "root" not in parse_qs(urlparse(app_url(1234, "tok")).query)

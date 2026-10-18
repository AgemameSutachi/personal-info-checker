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
    assert capsys.readouterr().out.strip() == f"個人情報チェッカー {__version__}"


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

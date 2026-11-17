"""Access への対処の、手段の調べ方・補助プロセス・開けないときの断りの枝の試験。

本物の ACE・Jet・Java は使わない（差し替えた部品・使い捨ての子の Python で確かめる）。
検体はすべて pytest の tmp_path に作る。画面・Access 本体は起動しない。
"""

from __future__ import annotations

import datetime
import decimal
import subprocess
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pii_checker import remedy_access as ra  # noqa: E402
from pii_checker.formats import database  # noqa: E402
from pii_checker.remedy_write import RemedyError  # noqa: E402

# ---------------------------------------------------------------- 形式の見出し


def _jet4_head(order: int, label: bytes = b"Standard Jet DB") -> bytes:
    """Jet 4（label を変えれば ACE）の見出し（並び順を伏せて書いたもの）。"""
    head = bytearray(ra.SORT_ORDER_AT + 2)
    head[4:19] = label
    head[0x14] = 1
    n = ra.SORT_ORDER_AT + 2 - ra.HEADER_MASKED_AT
    stream = ra._rc4_stream(ra.HEADER_MASK_KEY.to_bytes(4, "little"), n)
    at = ra.SORT_ORDER_AT - ra.HEADER_MASKED_AT
    head[ra.SORT_ORDER_AT] = (order & 0xFF) ^ stream[at]
    head[ra.SORT_ORDER_AT + 1] = (order >> 8) ^ stream[at + 1]
    return bytes(head)


def test_access_format_and_sort_order_unreadable(tmp_path):
    """開けない（フォルダ）・無いファイルは、形式が空・並び順が None。"""
    assert ra.access_format(str(tmp_path)) == ""
    assert ra.access_format(str(tmp_path / "missing.accdb")) == ""
    assert ra.sort_order(str(tmp_path)) is None


def test_sort_order_short_or_jet3_is_none(tmp_path):
    """見出しが短い・Jet 3（0x14 が 0）・Access でないものは None。"""
    short = tmp_path / "short.mdb"
    short.write_bytes(b"\0\0\0\0Standard Jet DB")
    assert ra.sort_order(str(short)) is None
    jet3 = tmp_path / "jet3.mdb"
    head = bytearray(_jet4_head(1033))
    head[0x14] = 0
    jet3.write_bytes(bytes(head))
    assert ra.sort_order(str(jet3)) is None
    assert ra.access_format(str(jet3)) == "jet3"
    other = tmp_path / "other.mdb"
    other.write_bytes(b"x" * 200)
    assert ra.sort_order(str(other)) is None


def test_sort_order_reads_masked_value(tmp_path):
    """伏せを戻した並び順を読む（陽性対照: 1041 と 1033 を区別する）。"""
    p = tmp_path / "ja.mdb"
    p.write_bytes(_jet4_head(1041))
    assert ra.sort_order(str(p)) == 1041
    p.write_bytes(_jet4_head(1033))
    assert ra.sort_order(str(p)) == 1033


def test_ace_head_format_and_sort_order(tmp_path):
    """ACE の見出しは形式が ace で、並び順も読める。Access でない見出しの形式は空。"""
    p = tmp_path / "ja.accdb"
    p.write_bytes(_jet4_head(1041, b"Standard ACE DB"))
    assert ra.access_format(str(p)) == "ace"
    assert ra.sort_order(str(p)) == 1041
    other = tmp_path / "other.accdb"
    other.write_bytes(b"x" * 200)
    assert ra.access_format(str(other)) == ""


def test_format_from_kind_branches():
    """種類の表示名から形式を引く（知らない名前は空）。"""
    assert ra.format_from_kind("Access 97（Jet3・mdb）") == "jet3"
    assert ra.format_from_kind("Access 2000〜2003（Jet4・mdb）") == "jet4"
    assert ra.format_from_kind("Access 2007以降（ACE・accdb）") == "ace"
    assert ra.format_from_kind("なにか") == ""


def test_unavailable_reason_by_format(tmp_path):
    """形式ごとに、利用者へ見せる理由が変わる（どれもファイルの削除はできると添える）。"""
    p = str(tmp_path / "x.mdb")
    assert "Access のファイルとして読めません" in ra.unavailable_reason(p, "")
    assert "Access 97" in ra.unavailable_reason(p, "jet3")
    assert ".mdb を書き換える部品" in ra.unavailable_reason(p, "jet4")
    assert ".accdb" in ra.unavailable_reason(p, "ace")
    for fmt in ("", "jet3", "jet4", "ace"):
        assert "ファイルの削除はできます" in ra.unavailable_reason(p, fmt)


def test_availability_reason_uses_kind_for_relative_path(monkeypatch):
    """圧縮の中の名前（相対）は、種類名から形式を決める。手段があれば空・無ければ理由。"""
    monkeypatch.setattr(ra, "plan_strategies", lambda path, fmt: ["ace"] if fmt == "ace" else [])
    assert ra.availability_reason("in/zip/a.accdb", "x", "Access 2007以降（ACE・accdb）") == ""
    reason = ra.availability_reason("in/zip/a.mdb", "x", "Access 97（Jet3・mdb）")
    assert "Access 97" in reason


def test_lock_file_problem(tmp_path):
    """隣にロックファイルがあれば断る。相対パス・無いときは空。"""
    db = tmp_path / "a.accdb"
    db.write_bytes(b"")
    assert ra.lock_file_problem(str(db)) == ""
    assert ra.lock_file_problem("a.accdb") == ""
    (tmp_path / "a.ldb").write_bytes(b"")
    assert "a.ldb" in ra.lock_file_problem(str(db))


# ---------------------------------------------------------------- 使える部品の調べ方


def test_ace_odbc_driver_without_pyodbc_or_driver(monkeypatch):
    """pyodbc が無い・ACE のドライバが無いときは None。"""
    ra.ace_odbc_driver.cache_clear()
    try:
        monkeypatch.setitem(sys.modules, "pyodbc", None)  # import すると ImportError になる
        assert ra.ace_odbc_driver() is None
        ra.ace_odbc_driver.cache_clear()
        fake = types.SimpleNamespace(drivers=lambda: ["SQL Server", "Microsoft Access Driver (*.mdb)"])
        monkeypatch.setitem(sys.modules, "pyodbc", fake)
        assert ra.ace_odbc_driver() is None
        ra.ace_odbc_driver.cache_clear()
        fake.drivers = lambda: ["Microsoft Access Driver (*.mdb, *.accdb)"]
        assert ra.ace_odbc_driver() == "Microsoft Access Driver (*.mdb, *.accdb)"
    finally:
        ra.ace_odbc_driver.cache_clear()


def test_find_rewrite_helper32_branches(tmp_path, monkeypatch):
    """検査用の補助が無い・python.exe でない・書き換え用の台本が無いときは None。揃えばコマンドを返す。"""
    script_dir = tmp_path / "helper"
    script_dir.mkdir()
    reader = script_dir / "access32_reader.py"
    reader.write_text("", encoding="utf-8")
    monkeypatch.setattr(database, "find_helper32", lambda configured=None: None)
    assert ra.find_rewrite_helper32() is None
    monkeypatch.setattr(database, "find_helper32", lambda configured=None: ["helper.exe", str(reader)])
    assert ra.find_rewrite_helper32() is None
    monkeypatch.setattr(database, "find_helper32", lambda configured=None: ["C:/py32/python.exe", str(reader)])
    assert ra.find_rewrite_helper32() is None
    (script_dir / "access32_rewrite.py").write_text("", encoding="utf-8")
    assert ra.find_rewrite_helper32() == ["C:/py32/python.exe", str(script_dir / "access32_rewrite.py")]


def test_jet_available_branches(monkeypatch):
    """コマンドが無い・起動に失敗したときは False。補助がドライバを返せば True。"""
    ra.jet_available.cache_clear()
    try:
        assert ra.jet_available(None) is False

        def boom(cmd):
            raise OSError("起動できない")

        monkeypatch.setattr(ra, "HelperProcess", boom)
        assert ra.jet_available(("a", "b")) is False

        class FakeHelper:
            def __init__(self, cmd):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return None

            def call(self, req):
                return {"ok": True, "drivers": ["Microsoft Access Driver (*.mdb)"]}

        monkeypatch.setattr(ra, "HelperProcess", FakeHelper)
        assert ra.jet_available(("c", "d")) is True
    finally:
        ra.jet_available.cache_clear()


def test_bundle_roots_prefers_meipass(monkeypatch, tmp_path):
    """配布版（_MEIPASS のある）では、その置き場を先に探す。"""
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    roots = ra._bundle_roots()
    assert roots[0] == tmp_path
    assert roots[1] == Path(sys.executable).parent


def test_find_jackcess_from_env(monkeypatch, tmp_path):
    """環境変数の java と jar の置き場で揃う。jar が1つでも欠ければ None。"""
    java = tmp_path / "java.exe"
    java.write_bytes(b"")
    jars = tmp_path / "jars"
    jars.mkdir()
    for name in ("jackcess-4.0.5.jar", "commons-lang3-3.14.jar", "commons-logging-1.3.jar"):
        (jars / name).write_bytes(b"")
    monkeypatch.setenv("PIICHK_JAVA", str(java))
    monkeypatch.setenv("PIICHK_JACKCESS_DIR", str(jars))
    monkeypatch.delenv("JAVA_HOME", raising=False)
    monkeypatch.setattr(ra.shutil, "which", lambda name: None)
    monkeypatch.setattr(ra, "_bundle_roots", lambda: [tmp_path / "nobundle"])
    monkeypatch.setattr(ra, "__file__", str(tmp_path / "pkg" / "remedy_access.py"))
    assert ra.find_jackcess() is None  # 補助そのもの（piichk-access）が無い
    (jars / "piichk-access.jar").write_bytes(b"")
    found = ra.find_jackcess()
    assert found == {
        "java": str(java),
        "classpath": [
            str(jars / n)
            for n in ("jackcess-4.0.5.jar", "commons-lang3-3.14.jar", "commons-logging-1.3.jar", "piichk-access.jar")
        ],
    }


def test_find_jackcess_without_java(monkeypatch, tmp_path):
    """java がどこにも無ければ None。"""
    monkeypatch.delenv("PIICHK_JAVA", raising=False)
    monkeypatch.delenv("JAVA_HOME", raising=False)
    monkeypatch.setattr(ra.shutil, "which", lambda name: None)
    monkeypatch.setattr(ra, "_bundle_roots", lambda: [tmp_path])
    assert ra.find_jackcess() is None


def test_forced_strategies_from_env(monkeypatch):
    """試験用の変数が無ければ、環境変数のコンマ区切りを読む（空白・空の項は捨てる）。"""
    monkeypatch.setattr(ra, "FORCED_STRATEGIES", None)
    monkeypatch.setenv(ra.STRATEGY_ENV, " jet , ,jackcess ")
    assert ra.forced_strategies() == ["jet", "jackcess"]
    monkeypatch.setenv(ra.STRATEGY_ENV, "  ")
    assert ra.forced_strategies() is None


def test_plan_strategies_order_and_only(monkeypatch):
    """Jet 4 は ACE → Jet の順。only で絞る。"""
    monkeypatch.setattr(ra, "ace_odbc_driver", lambda: "ACE")
    monkeypatch.setattr(ra, "find_rewrite_helper32", lambda: ["py.exe", "s.py"])
    monkeypatch.setattr(ra, "jet_available", lambda key: True)
    monkeypatch.setattr(ra, "find_jackcess", lambda: {"java": "j", "classpath": []})
    monkeypatch.setattr(ra, "FORCED_STRATEGIES", None)
    monkeypatch.delenv(ra.STRATEGY_ENV, raising=False)
    assert ra.plan_strategies("x.mdb", "jet4") == ["ace", "jet"]
    assert ra.plan_strategies("x.mdb", "jet4", only=["jet"]) == ["jet"]
    assert ra.plan_strategies("x.accdb", "ace", only=["ace", "jackcess"]) == ["ace", "jackcess"]
    assert ra.plan_strategies("x.mdb", "jet3", only=["jet", "ace"]) == ["jet"]


# ---------------------------------------------------------------- 値の戻し方


def test_untag_branches():
    """型の目印つきの値を戻す。戻せない文字はそのまま・目印の無い辞書はバイナリ。"""
    assert ra.untag({"i": "12"}) == 12
    assert ra.untag({"f": "1.5"}) == 1.5
    assert ra.untag({"f": "nan?"}) == "nan?"
    assert ra.untag({"d": "2026-01-02 03:04:05"}) == datetime.datetime(2026, 1, 2, 3, 4, 5)
    assert ra.untag({"d": "きのう"}) == "きのう"
    assert isinstance(ra.untag({"b": "..."}), ra.Binary)
    assert ra.untag("そのまま") == "そのまま"


def test_kind_from_pyodbc_branches():
    """pyodbc の型と長さから列の種類を決める（255 字を超える文字・長さ 0 はメモ）。"""
    assert ra.kind_from_pyodbc(bool, 1) == "bool"
    assert ra.kind_from_pyodbc(int, 4) == "int"
    assert ra.kind_from_pyodbc(float, 8) == "float"
    assert ra.kind_from_pyodbc(decimal.Decimal, 8) == "float"
    assert ra.kind_from_pyodbc(str, 255) == "text"
    assert ra.kind_from_pyodbc(str, 256) == "memo"
    assert ra.kind_from_pyodbc(str, 0) == "memo"
    assert ra.kind_from_pyodbc(datetime.date, 8) == "date"
    assert ra.kind_from_pyodbc(bytes, 10) == "bin"
    assert ra.kind_from_pyodbc(list, 10) == "other"


# ---------------------------------------------------------------- 補助プロセス


def _child(code: str) -> list[str]:
    """使い捨ての子の Python で code を走らせるコマンド。"""
    return [sys.executable, "-I", "-c", code]


def test_helper_call_unreadable_reply():
    """補助が JSON でない行を返したら、次の手段へ進む断り（Unavailable）。"""
    with ra.HelperProcess(_child("import sys; sys.stdin.readline(); print('not json', flush=True)")) as hp:
        with pytest.raises(ra.Unavailable, match="返事を読めません"):
            hp.call({"op": "probe"})


def test_pipe_readline_after_child_exit():
    """補助が何も返さずに終わったら Unavailable。"""
    with ra.HelperProcess(_child("pass")) as hp:
        hp.proc.wait(timeout=30)
        with pytest.raises(ra.Unavailable, match="途中で終わりました"):
            hp.readline()


def test_pipe_send_after_child_exit():
    """補助が終わった後に送れば Unavailable（壊れた管の OSError を利用者向けにする）。"""
    with ra.HelperProcess(_child("pass")) as hp:
        hp.proc.wait(timeout=30)
        with pytest.raises(ra.Unavailable, match="送れません"):
            hp.send("x")


def test_pipe_close_kills_when_child_hangs():
    """閉じても終わらない子は止める（kill のあと待つ）。送り口を閉じる失敗は飲み込む。"""

    class FakeStdin:
        def close(self):
            raise OSError("閉じられない")

    class FakeProc:
        def __init__(self):
            self.stdin = FakeStdin()
            self.stdout = None
            self.calls = []

        def wait(self, timeout=None):
            self.calls.append(("wait", timeout))
            if timeout is not None:
                raise subprocess.TimeoutExpired("x", timeout)

        def kill(self):
            self.calls.append(("kill", None))

    pipe = ra._Pipe.__new__(ra._Pipe)
    pipe.proc = FakeProc()
    pipe.close()
    assert pipe.proc.calls == [("wait", 30), ("kill", None), ("wait", None)]


# ---------------------------------------------------------------- 開けないときの断り


def _fake_pyodbc(message: str):
    class Error(Exception):
        pass

    calls = []

    def connect(conn_str, autocommit=False):
        calls.append(conn_str)
        raise Error(message)

    return types.SimpleNamespace(Error=Error, connect=connect, calls=calls)


@pytest.mark.parametrize(
    "message, exc, text",
    [
        (
            "[HY000] [Microsoft][ODBC Microsoft Access Driver] Not a valid password. (-1905)",
            RemedyError,
            "データベースパスワード",
        ),
        ("[HY000] パスワードが違います", RemedyError, "データベースパスワード"),
        ("[HY000] file is locked", ra.Unavailable, "ACE で開けません"),
    ],
)
def test_odbc_backend_open_failure(monkeypatch, tmp_path, message, exc, text):
    """開けなければ OPEN_TRIES 回やり直す。パスワードなら利用者向けの断り・それ以外は次の手段へ。"""
    fake = _fake_pyodbc(message)
    monkeypatch.setitem(sys.modules, "pyodbc", fake)
    sleeps = []
    monkeypatch.setattr(ra.time, "sleep", sleeps.append)
    with pytest.raises(exc, match=text):
        ra.OdbcBackend(str(tmp_path / "a.accdb"), "ACE")
    assert len(fake.calls) == ra.OPEN_TRIES
    assert sleeps == [ra.OPEN_RETRY_SECONDS * (i + 1) for i in range(ra.OPEN_TRIES)]


def test_odbc_backend_reading_wraps_driver_error(monkeypatch, tmp_path):
    """表を読む途中のドライバのエラーは、元を変えていない旨の1行の断りにする。"""

    class Error(Exception):
        pass

    fake = types.SimpleNamespace(Error=Error, connect=lambda s, autocommit=False: object())
    monkeypatch.setitem(sys.modules, "pyodbc", fake)
    backend = ra.OdbcBackend(str(tmp_path / "a.accdb"), "ACE")

    def broken():
        raise Error("HY000", "[Microsoft][ODBC] Disk I/O error\r\nSELECT * FROM t")

    with pytest.raises(RemedyError, match="元のファイルは変えていません") as info:
        backend._reading(broken)
    assert "\n" not in str(info.value)


def _fake_helper_class(replies: list[dict]):
    made = []

    class FakeHelper:
        def __init__(self, cmd):
            self.closed = False
            made.append(self)

        def call(self, req):
            reply = replies.pop(0)
            if isinstance(reply, Exception):
                raise reply
            return reply

        def close(self):
            self.closed = True

    return FakeHelper, made


def test_helper_backend_open_retries_then_password(monkeypatch):
    """Jet で開けなければやり直し、パスワードなら利用者向けの断り。"""
    fake, made = _fake_helper_class([{"ok": False, "code": "password", "message": "[x] bad password"}] * ra.OPEN_TRIES)
    monkeypatch.setattr(ra, "HelperProcess", fake)
    monkeypatch.setattr(ra.time, "sleep", lambda s: None)
    with pytest.raises(RemedyError, match="データベースパスワード"):
        ra.HelperBackend("a.mdb", ["py", "s"])
    assert len(made) == ra.OPEN_TRIES and all(h.closed for h in made)


def test_helper_backend_open_other_failure_and_unavailable(monkeypatch):
    """パスワード以外は次の手段へ。補助が落ちたら閉じてそのまま上げる。"""
    fake, _ = _fake_helper_class([{"ok": False, "message": "locked"}] * ra.OPEN_TRIES)
    monkeypatch.setattr(ra, "HelperProcess", fake)
    monkeypatch.setattr(ra.time, "sleep", lambda s: None)
    with pytest.raises(ra.Unavailable, match="Jet で開けません: locked"):
        ra.HelperBackend("a.mdb", ["py", "s"])
    fake, made = _fake_helper_class([ra.Unavailable("落ちた")])
    monkeypatch.setattr(ra, "HelperProcess", fake)
    with pytest.raises(ra.Unavailable, match="落ちた"):
        ra.HelperBackend("a.mdb", ["py", "s"])
    assert made[0].closed


def test_helper_backend_ok_refusal(monkeypatch):
    """開けた後に補助が操作を断れば、元を変えていない旨の断り。"""
    fake, _ = _fake_helper_class([{"ok": True, "driver": "Jet"}, {"ok": False, "message": "[x] [y] 拒否\nされた"}])
    monkeypatch.setattr(ra, "HelperProcess", fake)
    backend = ra.HelperBackend("a.mdb", ["py", "s"])
    assert backend.driver == "Jet"
    with pytest.raises(RemedyError, match="拒否 された"):
        backend._ok({"op": "tables"})

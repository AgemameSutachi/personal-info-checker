"""Access への対処の、SQL・Jackcess の手段と最適化の、断り・食い違いの枝の試験。

本物の ACE・Jet・Java・cscript は使わない（差し替えた相手で確かめる）。
検体はすべて pytest の tmp_path に作る。画面・Access 本体は起動しない。
"""

from __future__ import annotations

import subprocess
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pii_checker import remedy_access as ra  # noqa: E402
from pii_checker.remedy_write import RemedyError  # noqa: E402

# ---------------------------------------------------------------- 値の形


def test_detail_of_with_and_without_detail():
    """「詳細: 」があればそこから先（閉じ括弧は外す）、無ければ全文に「詳細: 」を付ける。"""
    assert ra._detail_of(RemedyError("断りました（詳細: 索引）")) == "詳細: 索引"
    assert ra._detail_of(RemedyError("ただの文")) == "詳細: ただの文"


def test_sql_literal_kinds():
    """空・真偽・整数・文字は書ける形、実数などは None。"""
    assert ra.sql_literal(None) == "NULL"
    assert ra.sql_literal(True) == "True"
    assert ra.sql_literal(False) == "False"
    assert ra.sql_literal(42) == "42"
    assert ra.sql_literal("a'b") == ra.sql_text("a'b")
    assert ra.sql_literal(1.5) is None


def test_where_clause_null_and_bool():
    """空の値は IS NULL、真偽の列は True・False で一致させる。"""
    cols = [ra.ColInfo("名前", "text"), ra.ColInfo("済", "bool"), ra.ColInfo("済2", "bool")]
    w = ra.where_clause(cols, [None, True, False])
    assert w == "[名前] IS NULL AND [済]=True AND [済2]=False"


def test_parse_cell_float_bool_date_and_binary():
    """実数の読み違いは文字のまま、真偽・日付・それ以外（バイナリ）を戻す。"""
    assert ra._parse_cell("f1.25") == 1.25
    assert ra._parse_cell("fNaNx") == "NaNx"
    assert ra._parse_cell("b1") is True
    assert ra._parse_cell("b0") is False
    assert ra._parse_cell("d2026-11-17") == "2026-11-17"
    assert isinstance(ra._parse_cell("xABC"), ra.Binary)


# ---------------------------------------------------------------- 32bit の補助


class _FakeHelper:
    def __init__(self, fail_close: bool):
        self.fail_close = fail_close
        self.closed = False

    def call(self, req):
        if self.fail_close:
            raise ra.Unavailable("終わっていた")
        return {"ok": True}

    def close(self):
        self.closed = True


def test_helper_backend_close_ignores_finished_helper():
    """補助が先に終わっていても、閉じるときは断らずにプロセスを片付ける。"""
    b = object.__new__(ra.HelperBackend)
    b.helper = _FakeHelper(fail_close=True)
    b.close()
    assert b.helper.closed


# ---------------------------------------------------------------- SQL の手段


class _FakeBackend:
    """execute の返す行の数・断りを決め打ちにする相手。"""

    strategy = "jet"

    def __init__(self, counts=None, refuse=()):
        self.counts = list(counts or [])
        self.refuse = refuse
        self.sqls: list[str] = []

    def execute(self, sql):
        self.sqls.append(sql)
        if any(sql.startswith(r) for r in self.refuse):
            raise RemedyError("Access が操作を断りました。元のファイルは変えていません（詳細: 索引で使用中）")
        return self.counts.pop(0) if self.counts else 1

    def columns(self, table):
        return [ra.ColInfo("名前", "text")]

    def close(self):
        pass


def test_sql_delete_rows_count_mismatch():
    """消えた行の数が選んだ行の数と違えば、食い違いとして断る。"""
    s = ra.SqlSession(_FakeBackend(counts=[0]))
    cols = [ra.ColInfo("名前", "text")]
    with pytest.raises(RemedyError, match="1 行のはずが 0 行"):
        s.delete_rows("顧客", cols, {0: ["山田"]})


def test_sql_update_cells_count_mismatch():
    """置き換えた行の数が見込みと違えば断る（連鎖更新で値が変わった等）。"""
    s = ra.SqlSession(_FakeBackend(counts=[2]))
    cols = [ra.ColInfo("名前", "text")]
    with pytest.raises(RemedyError, match="1 行のはずが 2 行"):
        s.update_cells("顧客", cols, {0: ["山田"]}, {0: {0: "＊＊＊"}})


def test_sql_drop_column_refused_explains():
    """列の削除を断られたら、ダミーへの置き換えを勧め、ドライバの詳細を1つの括弧で添える。"""
    s = ra.SqlSession(_FakeBackend(refuse=("ALTER TABLE",)))
    with pytest.raises(RemedyError) as e:
        s.drop_columns("顧客", ["名前"])
    msg = str(e.value)
    assert "列「名前」" in msg and "ダミーに置き換え" in msg
    assert msg.endswith("（詳細: 索引で使用中）")


def test_sql_drop_table_refused_explains():
    """表の削除を断られたら、行の削除かダミーを勧める。"""
    s = ra.SqlSession(_FakeBackend(refuse=("DROP TABLE",)))
    with pytest.raises(RemedyError, match="表「顧客」は.*「行の削除」か「ダミーに置き換え」"):
        s.drop_table("顧客")


# ---------------------------------------------------------------- Jackcess の手段


class _FakePipe:
    """送った命令ごとに、決め打ちの返事の行を返す。"""

    replies: dict[str, list[str]] = {}

    def __init__(self, cmd):
        self.sent: list[str] = []
        self.queue: list[str] = []
        self.closed = False

    def send(self, line):
        self.sent.append(line)
        head = line.split("\t")[0]
        if head in self.replies:
            self.queue += self.replies[head]

    def readline(self):
        if not self.queue:
            raise ra.Unavailable("補助プロセスが途中で終わりました")
        return self.queue.pop(0)

    def close(self):
        self.closed = True


_ENV = {"java": "java", "classpath": ["x.jar"]}


def _pipe_class(replies: dict[str, list[str]], made: list):
    class P(_FakePipe):
        pass

    P.replies = replies

    def make(cmd):
        p = P(cmd)
        made.append(p)
        return p

    return make


def test_jackcess_java_not_startable(monkeypatch):
    """Java を起動できなければ Unavailable（次の手段へ回す）。"""

    def boom(cmd):
        raise OSError("見つかりません")

    monkeypatch.setattr(ra, "_Pipe", boom)
    with pytest.raises(ra.Unavailable, match="Java を起動できません"):
        ra.JackcessSession("a.accdb", _ENV)


def test_jackcess_open_refused_becomes_unavailable(monkeypatch):
    """開くのを断られたら、パイプを閉じて Unavailable にする（行の値・一時の名前は出さない）。"""
    made: list = []
    err = "err\t" + ra._b64("New row [1, 山田] bad (Db=C:/tmp/x.accdb;")
    monkeypatch.setattr(ra, "_Pipe", _pipe_class({"open": [err]}, made))
    with pytest.raises(ra.Unavailable, match="Jackcess で開けません") as e:
        ra.JackcessSession("a.accdb", _ENV)
    assert "山田" not in str(e.value) and "x.accdb" not in str(e.value)
    assert made[0].closed


def test_jackcess_open_process_ended(monkeypatch):
    """開く途中で Java が終われば、パイプを閉じてそのまま Unavailable。"""
    made: list = []
    monkeypatch.setattr(ra, "_Pipe", _pipe_class({}, made))
    with pytest.raises(ra.Unavailable, match="途中で終わりました"):
        ra.JackcessSession("a.accdb", _ENV)
    assert made[0].closed


def _opened(monkeypatch, replies):
    made: list = []
    monkeypatch.setattr(ra, "_Pipe", _pipe_class({"open": ["ok"], **replies}, made))
    return ra.JackcessSession("a.accdb", _ENV), made[0]


def test_jackcess_known_reason_is_explained(monkeypatch):
    """よくある断り（必須の列）は言い換えて伝える。"""
    s, _ = _opened(monkeypatch, {"update": ["err\t" + ra._b64("Column 'x' cannot be null")]})
    with pytest.raises(RemedyError, match="必須の列"):
        s.update_cells("顧客", [], {}, {0: {0: "＊"}})


def test_jackcess_unknown_reason_and_empty_message(monkeypatch):
    """言い換えの無い断り（文の無い err を含む）は、そのまま短く伝える。"""
    s, _ = _opened(monkeypatch, {"count": ["err"]})
    with pytest.raises(RemedyError, match="Access の操作を断られました"):
        s.count("顧客")


def test_jackcess_delete_and_update_count_mismatch(monkeypatch):
    """消した・置き換えた行の数が見込みと違えば断る。"""
    s, _ = _opened(monkeypatch, {"delete": ["ok\t0"], "update": ["ok\t0"]})
    with pytest.raises(RemedyError, match="1 行のはずが 0 行"):
        s.delete_rows("顧客", [], {3: ["山田"]})
    with pytest.raises(RemedyError, match="置き換える行を特定できませんでした"):
        s.update_cells("顧客", [], {}, {3: {0: 7}})


def test_jackcess_update_sends_text_and_int_tokens(monkeypatch):
    """置き換えの行は、文字を s＋base64・整数を i＋数で送る。"""
    s, pipe = _opened(monkeypatch, {"update": ["ok\t1"]})
    assert s.update_cells("顧客", [], {}, {2: {0: "＊＊", 1: 5}}) == 1
    assert pipe.sent[-1] == "\t".join(["2", "0", "s" + ra._b64("＊＊"), "1", "i5"])


def test_jackcess_close_ignores_refusal(monkeypatch):
    """閉じる命令が断られても、パイプは閉じる。"""
    s, pipe = _opened(monkeypatch, {"close": ["err\t" + ra._b64("closed already")]})
    s.close()
    assert pipe.closed


# ---------------------------------------------------------------- 最適化


def test_cscript_from_32bit_process_uses_sysnative(monkeypatch, tmp_path):
    """32bit のプロセスから 64bit の cscript を探すときは Sysnative を見る。"""
    (tmp_path / "Sysnative").mkdir()
    (tmp_path / "Sysnative" / "cscript.exe").write_bytes(b"")
    monkeypatch.setenv("WINDIR", str(tmp_path))
    monkeypatch.setattr(ra, "struct_bits", lambda: 32)
    assert ra._cscript(64) == str(tmp_path / "Sysnative" / "cscript.exe")


def test_compact_not_windows(monkeypatch):
    """Windows でなければ最適化は使えない。"""
    monkeypatch.setattr(ra.os, "name", "posix")
    with pytest.raises(ra.Unavailable, match="Windows でだけ"):
        ra.compact_database("a", "b", "ace", "ace")


@pytest.mark.skipif(sys.platform != "win32", reason="Windows の分岐")
def test_compact_no_cscript(monkeypatch):
    """cscript.exe が無ければ Unavailable。"""
    monkeypatch.setattr(ra, "_cscript", lambda bits: None)
    with pytest.raises(ra.Unavailable, match="cscript.exe が見つかりません"):
        ra.compact_database("a", "b", "jet", "jet3")


@pytest.mark.skipif(sys.platform != "win32", reason="Windows の分岐")
def test_compact_timeout_and_temp_left(monkeypatch, tmp_path):
    """時間切れは Unavailable。一時の台本が消せなくても断らない。"""
    monkeypatch.setattr(ra, "_cscript", lambda bits: "cscript.exe")

    def slow(*a, **k):
        raise subprocess.TimeoutExpired("cscript", 1)

    removed: list = []

    def no_remove(p):
        removed.append(p)
        raise OSError("使用中")

    monkeypatch.setattr(ra.subprocess, "run", slow)
    monkeypatch.setattr(ra.os, "remove", no_remove)
    try:
        with pytest.raises(ra.Unavailable, match="TimeoutExpired"):
            ra.compact_database("a", str(tmp_path / "b.accdb"), "ace", "ace")
        assert removed and removed[0].endswith(".js")
    finally:
        monkeypatch.undo()
        for p in removed:  # 試験で残った一時の台本を片付ける
            Path(p).unlink(missing_ok=True)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows の分岐")
def test_compact_failed_reports_stderr(monkeypatch, tmp_path):
    """終了コードが 0 でないときは、cscript の文を添えて断る（Jet 3 は Engine Type=4 を送る）。"""
    monkeypatch.setattr(ra, "_cscript", lambda bits: "cscript.exe")
    sent: list = []

    def run(cmd, **k):
        sent.append(k["input"])
        return types.SimpleNamespace(returncode=1, stderr="エンジンがありません".encode("cp932"))

    monkeypatch.setattr(ra.subprocess, "run", run)
    with pytest.raises(ra.Unavailable, match="最適化に失敗しました: エンジンがありません"):
        ra.compact_database("a", str(tmp_path / "b.mdb"), "jet", "jet3")
    assert sent[0].startswith(b"jro\r\n") and sent[0].endswith(b"\r\n4\r\n")


@pytest.mark.skipif(sys.platform != "win32", reason="Windows の分岐")
def test_compact_success_code_but_no_output(monkeypatch, tmp_path):
    """終了コードが 0 でも、出来たはずのファイルが無ければ断る。"""
    monkeypatch.setattr(ra, "_cscript", lambda bits: "cscript.exe")
    monkeypatch.setattr(ra.subprocess, "run", lambda cmd, **k: types.SimpleNamespace(returncode=0, stderr=b""))
    with pytest.raises(ra.Unavailable, match="最適化に失敗しました"):
        ra.compact_database("a", str(tmp_path / "b.accdb"), "ace", "ace")

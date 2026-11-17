"""Access の読み手（formats/database.py）の、本物の Access が無くても通せる分岐の試験。

純 Python の読み手（access_parser）は模造の部品に差し替え、読めない表を項目に残すこと・1つも読めなければ
次へ回すことを確かめる。読み手を順に試す所は、各読み手を差し替えてパスワード違いの扱いを確かめる。
値はすべて試験のために作ったもので、実在の人の情報ではない。
"""

from __future__ import annotations

import sys
from array import array
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pii_checker.engine import Blob, Collector, NeedPassword, Uncheckable  # noqa: E402
from pii_checker.formats import database  # noqa: E402
from pii_checker.models import ItemResult, Status  # noqa: E402

PHONE = "090-1234-5678"


class _Ctx(SimpleNamespace):
    """ScanContext の代わり（使う属性だけ）。"""

    def __init__(self, tmp_path):
        super().__init__(options=SimpleNamespace(raw_sweep=False), items=[])
        self._tmp = tmp_path

    def new_tmp_subdir(self):
        d = self._tmp / f"sub{len(list(self._tmp.iterdir()))}"
        d.mkdir()
        return str(d)

    def password_candidates(self):
        return []

    def password_reason(self, what, also=""):
        return what


def _collector():
    item = ItemResult(path="db.mdb", kind="", status=Status.PENDING)
    return item, Collector(item, 20)


def _fake_access_parser(monkeypatch, tables, broken=()):
    """access_parser を、決めた表を返す模造に差し替える。broken の表は読むと例外を出す。"""

    class AccessParser:
        def __init__(self, path):
            self.catalog = {name: 0 for name in tables} | {name: 0 for name in broken}

        def parse_table(self, name):
            if name in broken:
                raise ValueError("ページが壊れている")
            return tables[name]

    monkeypatch.setitem(sys.modules, "access_parser", SimpleNamespace(AccessParser=AccessParser))


# ------------------------------------------------------------------ 純 Python の読み手


def test_access_parser_skips_system_and_keeps_broken_table(tmp_path, monkeypatch):
    """システムの表と一時の表を飛ばし、読めない表は黙って捨てずに項目に残す。短い列は空で埋めて読む。"""
    tables = {
        "MSysObjects": {"Name": ["x"]},
        "~TMP": {"v": [PHONE]},
        "名簿": {"氏名": ["架空 太郎", "架空 花子"], "電話": [PHONE]},
    }
    _fake_access_parser(monkeypatch, tables, broken=["壊れ"])
    ctx = _Ctx(tmp_path)
    item, col = _collector()
    assert database._read_access_parser(ctx, "dummy.mdb", col, item) == "access_parser（純 Python）"
    assert item.finding_counts.get("phone") == 1, item.finding_counts
    assert [(i.path, i.status) for i in ctx.items] == [("db.mdb!表「壊れ」", Status.UNCHECKABLE)]
    reason = ctx.items[0].reason
    assert database.ACCESS_REPAIR_HINT in reason and "access_parser: ページが壊れている" in reason


def test_access_parser_no_readable_table(tmp_path, monkeypatch):
    """読める表が1つも無ければ、次の読み手へ回すための例外を出す。"""
    _fake_access_parser(monkeypatch, {"MSysObjects": {"Name": ["x"]}}, broken=["壊れ"])
    item, col = _collector()
    with pytest.raises(RuntimeError, match="表を1つも読めなかった"):
        database._read_access_parser(_Ctx(tmp_path), "dummy.mdb", col, item)


# ------------------------------------------------------------------ 読み手を順に試す所


def _blob():
    # 0x14 の版の番号を 1（Jet4）にした見出しだけの .mdb
    head = bytearray(0x80)
    head[0x14] = 1
    return Blob(display="db.mdb", data=bytes(head), name_hint="db.mdb")


def _set_readers(monkeypatch, **results):
    """各読み手を、決めた結果（戻り値か例外）を返すものに差し替える。"""

    def make(r):
        def fn(*args, **kwargs):
            if isinstance(r, BaseException):
                raise r
            return r

        return fn

    for key in ("odbc", "helper32", "jackcess", "parser"):
        monkeypatch.setattr(database, f"_read_access_{key}", make(results.get(key, RuntimeError("無い"))))
    monkeypatch.setattr(database, "FORCED_READERS", None)
    monkeypatch.delenv(database.READERS_ENV, raising=False)
    monkeypatch.setattr(database, "_is_ace_format", lambda path: False)


def test_handle_access_password_wrong_then_read(tmp_path, monkeypatch):
    """先の読み手がパスワード違いでも、後の読み手で読めたら検査を済ませ、先の失敗を注記に残す。"""
    _set_readers(monkeypatch, odbc=NeedPassword("access", "x"), jackcess="Jackcess（Java）")
    item, col = _collector()
    database.handle_access(_Ctx(tmp_path), _blob(), item, col, 0)
    assert item.kind == "Access 2000-2003（Jet4・mdb）"
    assert item.method.startswith("Jackcess（Java） で全テーブル")
    assert "先に試して失敗した方法: 64bit ODBC: パスワードが違う / 32bit 補助: RuntimeError: 無い" in item.notes


def test_handle_access_password_wrong_everywhere(tmp_path, monkeypatch):
    """どの読み手でも読めず、1つでもパスワード違いがあれば、検査不能でなくパスワードを尋ねる側へ回す。"""
    _set_readers(monkeypatch, helper32=NeedPassword("access", "x"))
    item, col = _collector()
    with pytest.raises(NeedPassword, match="データベースパスワード"):
        database.handle_access(_Ctx(tmp_path), _blob(), item, col, 0)


def test_handle_access_unreadable_lists_attempts(tmp_path, monkeypatch):
    """どの読み手でも読めなければ、試した方法ごとの理由を添えて検査不能にする。"""
    _set_readers(monkeypatch)
    item, col = _collector()
    with pytest.raises(Uncheckable) as e:
        database.handle_access(_Ctx(tmp_path), _blob(), item, col, 0)
    assert "64bit ODBC: RuntimeError: 無い / 32bit 補助" in str(e.value)


# ------------------------------------------------------------------ 対処のための位置集め


def test_access_parser_records_columns_for_positions(tmp_path, monkeypatch):
    """位置を集めるときは、表ごとの列の名前を残す（ダミー化で列を引き当てるため）。"""
    _fake_access_parser(monkeypatch, {"名簿": {"氏名": ["架空 太郎"], "電話": [PHONE]}})
    item, col = _collector()
    col.collect_positions = True
    database._read_access_parser(_Ctx(tmp_path), "dummy.mdb", col, item)
    assert col.pos_info["tables"] == {"名簿": {"columns": ["氏名", "電話"]}}


def test_handle_access_discards_positions_of_failed_reader(tmp_path, monkeypatch):
    """途中まで読んで失敗した読み手の位置は捨て、次の読み手の数え直しと混ぜない。"""
    _set_readers(monkeypatch, jackcess="Jackcess（Java）")
    seen = {}

    def odbc_half_read(*args, **kwargs):
        col.positions[("名簿", "phone", 0)] = array("q", [1, 2, 0, 13])
        col.pos_info["tables"] = {"名簿": {"columns": ["電話"]}}
        col.pos_total = 1
        col.pos_overflow = True  # 上限を超えたのも失敗した読み手の分なので、次の読み手へ持ち越さない
        raise RuntimeError("途中で切れた")

    def jackcess_read(*args, **kwargs):
        seen["state"] = (dict(col.positions), dict(col.pos_info), col.pos_total, col.pos_overflow)
        return "Jackcess（Java）"

    monkeypatch.setattr(database, "_read_access_odbc", odbc_half_read)
    monkeypatch.setattr(database, "_read_access_jackcess", jackcess_read)
    item, col = _collector()
    col.collect_positions = True
    database.handle_access(_Ctx(tmp_path), _blob(), item, col, 0)
    assert col.pos_layout == "access"
    assert seen["state"] == ({}, {}, 0, False)
    assert item.method.startswith("Jackcess（Java） で全テーブル")

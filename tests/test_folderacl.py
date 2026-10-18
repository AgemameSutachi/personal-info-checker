"""誰が読めるか（親フォルダのアクセス権）の試験。

権限を変えるのは tmp_path の下に作ったフォルダだけで、試験の最後に必ず元へ戻す。
"""

from __future__ import annotations

import os
import subprocess

import pytest

from pii_checker import folderacl, runner
from pii_checker.folderacl import (
    ACCESS_ALLOWED_ACE_TYPE,
    ACCESS_DENIED_ACE_TYPE,
    BROAD,
    CONTAINER_INHERIT_ACE,
    FTP,
    INHERIT_ONLY_ACE,
    LIMITED,
    OBJECT_INHERIT_ACE,
    UNKNOWN,
    AccessCache,
    judge,
    may_lookup_name,
)
from pii_checker.models import ScanOptions
from pii_checker.store import Store

ALLOW, DENY = ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE
READ = 0x1200A9  # FILE_GENERIC_READ | FILE_EXECUTE（「読み取りと実行」）


def test_judge_broad_and_limited():
    assert judge([(ALLOW, 0, READ, "S-1-5-18"), (ALLOW, 0, READ, "S-1-5-32-544")]) == (LIMITED, [])
    assert judge([(ALLOW, 0, READ, "S-1-1-0")]) == (BROAD, ["Everyone"])
    state, who = judge([(ALLOW, 0, READ, "S-1-5-21-1-2-3-513"), (ALLOW, 0, 0x80000000, "S-1-5-11")])
    assert state == BROAD and who == ["Domain Users", "Authenticated Users"]
    # 書き込みだけ（読み取りの権利が無い）は数えない
    assert judge([(ALLOW, 0, 0x2, "S-1-1-0")])[0] == LIMITED
    # 同じ SID への読み取りの拒否は許可を打ち消す
    assert judge([(DENY, 0, 0x1, "S-1-1-0"), (ALLOW, 0, READ, "S-1-1-0")])[0] == LIMITED
    # 下のフォルダにだけ継承される項目は、このフォルダのファイルには効かない。ファイルへ継承されるものは効く
    assert judge([(ALLOW, INHERIT_ONLY_ACE | 0x2, READ, "S-1-1-0")])[0] == LIMITED
    assert judge([(ALLOW, INHERIT_ONLY_ACE | OBJECT_INHERIT_ACE, READ, "S-1-1-0")])[0] == BROAD
    # DACL が無い＝全員に許可
    assert judge(None)[0] == BROAD
    # ドメインの普通のユーザー（-1001）は「広く誰でも」ではない
    assert judge([(ALLOW, 0, READ, "S-1-5-21-1-2-3-1001")])[0] == LIMITED


def test_subfolder_only_inheritance_is_not_broad():
    """サブフォルダにだけ継承される項目（CONTAINER_INHERIT だけ）は、このフォルダのファイルに届かないので数えない。"""
    CI, OI, IO = CONTAINER_INHERIT_ACE, OBJECT_INHERIT_ACE, INHERIT_ONLY_ACE
    assert judge([(ALLOW, CI, READ, "S-1-1-0")]) == (LIMITED, [])
    assert judge([(ALLOW, CI | IO, 0x80000000, "S-1-1-0")]) == (LIMITED, [])
    # ファイルへ継承されるもの（OI を含む）と、継承の指定の無いフォルダ自身の項目は数える
    assert judge([(ALLOW, CI | OI, READ, "S-1-1-0")])[0] == BROAD
    assert judge([(ALLOW, OI | IO, READ, "S-1-1-0")])[0] == BROAD
    assert judge([(ALLOW, 0, READ, "S-1-5-11")])[0] == BROAD


def test_limited_label_does_not_claim_only_few_people():
    """「広い許可なし」は言い切らない表現にし、見ていないもの（全社員グループ・Samba のグループ等）を説明に出す。"""
    assert folderacl.LABELS[LIMITED] == "広い許可なし（目安）"
    assert "限られた人だけ" not in folderacl.LABELS[LIMITED]
    assert "見当たらない" in folderacl.DESCRIPTIONS[LIMITED]
    note = folderacl.NOT_CHECKED_NOTE
    assert "全社員" in note and "Samba" in note and "ファイル個別" in note


def test_owner_name_is_looked_up_only_locally():
    """所有者の名前は、よく知られた SID とこの PC のアカウントだけ引く（ドメインコントローラーへ問い合わせない）。"""
    local = "S-1-5-21-111-222-333"
    for sid in ("S-1-1-0", "S-1-5-18", "S-1-5-32-544", "S-1-5-11", "S-1-5-80-1-2-3-4-5", "S-1-16-12288"):
        assert may_lookup_name(sid, local), sid
    assert may_lookup_name(local + "-1001", local)  # この PC のアカウント
    assert not may_lookup_name("S-1-5-21-999-888-777-1105", local)  # ドメインのアカウント
    assert not may_lookup_name("S-1-5-21-111-222-3334-1001", local)  # 頭の数字が途中まで同じだけ
    assert not may_lookup_name(local + "-1001-5", local)
    assert not may_lookup_name("S-1-22-2-100", local)  # Samba の Unix のグループ
    assert not may_lookup_name("S-1-5-21-111-222-333-1001", "")  # この PC の SID が分からなければ引かない


@pytest.mark.skipif(os.name != "nt", reason="Windows のアクセス権の試験")
def test_account_name_returns_sid_string_without_lookup(monkeypatch):
    """引かない SID では LookupAccountSidW を呼ばず、SID の文字列のまま返す。"""
    import ctypes

    calls = []
    real = folderacl._adv.LookupAccountSidW

    def spy(*args):
        calls.append(args)
        return real(*args)

    psid = ctypes.c_void_p()
    assert ctypes.windll.advapi32.ConvertStringSidToSidW("S-1-5-21-999-888-777-1105", ctypes.byref(psid))
    try:
        monkeypatch.setattr(folderacl._adv, "LookupAccountSidW", spy)
        assert folderacl._account_name(psid) == "S-1-5-21-999-888-777-1105"
        assert calls == []
    finally:
        ctypes.windll.kernel32.LocalFree(psid)


def test_ftp_is_not_queried():
    got = AccessCache().for_file("ftp://192.0.2.1/総務/名簿.csv")
    assert got.state == FTP and got.label == "取れない（FTP）"


def test_cache_reads_each_folder_once(tmp_path, monkeypatch):
    calls = []

    def fake(path):
        calls.append(path)
        return folderacl.FolderAccess(LIMITED)

    monkeypatch.setattr(folderacl, "read_folder", fake)
    cache = AccessCache()
    for name in ("a.csv", "b.csv", "c.xlsx"):
        assert cache.for_file(str(tmp_path / name)).state == LIMITED
    cache.for_file(str(tmp_path / "sub" / "d.csv"))
    assert len(calls) == 2


def test_missing_folder_is_unknown(tmp_path):
    got = folderacl.read_folder(str(tmp_path / "無いフォルダ"))
    assert got.state == UNKNOWN and got.who


def _icacls(*args: str) -> None:
    subprocess.run(["icacls", *args], check=True, capture_output=True)


@pytest.mark.skipif(os.name != "nt", reason="Windows のアクセス権の試験")
def test_real_folder_everyone_read(tmp_path):
    folder = tmp_path / "共有"
    folder.mkdir()
    (folder / "a.txt").write_text("x", encoding="utf-8")
    before = folderacl.read_folder(str(folder))
    assert before.state in (LIMITED, BROAD), before
    assert before.owner  # 所有者の名前（自分）が取れる
    atime = os.stat(folder / "a.txt").st_atime_ns
    _icacls(str(folder), "/grant", "*S-1-1-0:(OI)(CI)R")
    try:
        got = folderacl.read_folder(str(folder))
        assert got.state == BROAD and "Everyone" in got.who, got
    finally:
        _icacls(str(folder), "/remove:g", "*S-1-1-0")
    after = folderacl.read_folder(str(folder))
    assert after.state == before.state and "Everyone" not in after.who
    assert os.stat(folder / "a.txt").st_atime_ns == atime  # ファイルの中身を開いていない


@pytest.mark.skipif(os.name != "nt", reason="Windows のアクセス権の試験")
def test_runner_records_access_only_for_files_with_findings(tmp_path):
    folder = tmp_path / "data"
    (folder / "sub").mkdir(parents=True)
    (folder / "名簿.txt").write_text("顧客 携帯 090-1234-5678", encoding="utf-8")
    (folder / "sub" / "メモ.txt").write_text("今日は晴れ", encoding="utf-8")
    store = Store(str(tmp_path / "jobs.sqlite3"))
    job = store.create_job([str(folder)], ScanOptions(temp_dir=str(tmp_path)))
    r = runner.JobRunner(store, job, workers=1)
    r.start()
    r.wait(180)
    assert store.job(job)["state"] == "done"
    rows = {os.path.basename(x["top_path"]): x for x in store.query("SELECT * FROM files WHERE job_id=?", (job,))}
    assert rows["名簿.txt"]["access"] in (LIMITED, BROAD)
    assert rows["名簿.txt"]["access_owner"]
    assert rows["メモ.txt"]["access"] is None
    s = store.summary(job)
    assert sum(s["access"].values()) == 1
    # 使い回した結果でも読み直して記録する
    job2 = store.create_job([str(folder)], ScanOptions(temp_dir=str(tmp_path)))
    r2 = runner.JobRunner(store, job2, workers=1)
    r2.start()
    r2.wait(180)
    row = store.query("SELECT reused_from, access FROM files WHERE job_id=? AND top_path LIKE ?", (job2, "%名簿.txt"))[
        0
    ]
    assert row["reused_from"] == job and row["access"] in (LIMITED, BROAD)

"""コマンドの後半の試験: 要パスワードの残りをまとめて聞く繰り返し・保存済みジョブのレポート・ジョブの一覧・許可リストの読み失敗。"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from pii_checker import cli  # noqa: E402
from pii_checker.store import Store  # noqa: E402
from zipcrypto import zipcrypto_zip  # noqa: E402

PASSWORD = "合言葉42"


def _locked_folder(tmp_path: Path, count: int = 1) -> Path:
    """同じパスワードで暗号化した zip を count 個置いたフォルダを作る。"""
    root = tmp_path / "share"
    root.mkdir()
    for i in range(count):
        blob = zipcrypto_zip("secret.txt", f"顧客 携帯 090-5555-{6000 + i:04d}\n".encode(), PASSWORD)
        (root / f"locked{i:02d}.zip").write_bytes(blob)
    return root


def _scan(tmp_path: Path, root: Path, *extra: str) -> int:
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    return cli.main(
        ["--db", str(tmp_path / "j.sqlite3"), "scan", str(root), "-o", str(out / "r.xlsx"), "--workers", "1"]
        + list(extra)
    )


def _answers(monkeypatch, *typed: str) -> list[str]:
    """人がコンソールで打つ答えを順に返す（聞かれた文を控える）。"""
    asked: list[str] = []
    rest = list(typed)
    monkeypatch.setattr(cli, "_interactive", lambda: True)
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: asked.append(prompt) or rest.pop(0))
    return asked


def _still_locked(tmp_path: Path) -> list[str]:
    store = Store(str(tmp_path / "j.sqlite3"))
    return store.files_with_status(store.jobs()[0]["id"], ["needs_password"])


def test_typed_password_opens_all_locked_files(tmp_path, monkeypatch, capsys):
    """残った要パスワードは1回まとめて聞き、打ったパスワードを全件に試す。開けば次は聞かない。"""
    root = _locked_folder(tmp_path, 2)
    asked = _answers(monkeypatch, "違う", PASSWORD)
    assert _scan(tmp_path, root) == 0
    out = capsys.readouterr().out
    assert len(asked) == 2  # 違うパスワードの後にもう一度聞き、開いたら聞かない
    assert out.count("パスワードが必要なファイルが 2 件あります") == 2
    assert out.count("2 件を再検査します") == 2
    assert _still_locked(tmp_path) == []
    assert "パスワードが分かれば" not in out


def test_empty_answer_stops_asking_and_keeps_hint(tmp_path, monkeypatch, capsys):
    """空で答えれば聞くのをやめ、残ったものは後から --password-file で開ける案内を出す。"""
    root = _locked_folder(tmp_path)
    asked = _answers(monkeypatch, "")
    assert _scan(tmp_path, root) == 0
    out = capsys.readouterr().out
    assert len(asked) == 1
    assert "再検査します" not in out
    assert len(_still_locked(tmp_path)) == 1
    assert "--password-file パスワード一覧.txt" in out


def test_long_locked_list_is_cut_at_ten(tmp_path, monkeypatch, capsys):
    """要パスワードが10件を超えたら、名前は10件まで出して残りは件数だけにする。"""
    root = _locked_folder(tmp_path, 12)
    _answers(monkeypatch, "")
    assert _scan(tmp_path, root) == 0
    out = capsys.readouterr().out
    assert sum(1 for line in out.splitlines() if line.startswith("  - ")) == 10
    assert "…ほか 2 件" in out


def test_no_ask_never_prompts(tmp_path, monkeypatch, capsys):
    """--no-ask を付ければ、コンソールで打てる状態でも聞かない（陰性対照）。"""
    root = _locked_folder(tmp_path)
    asked = _answers(monkeypatch)
    assert _scan(tmp_path, root, "--no-ask") == 0
    assert asked == []
    assert len(_still_locked(tmp_path)) == 1


def _done_job(tmp_path: Path) -> tuple[str, Path]:
    root = tmp_path / "data"
    root.mkdir()
    (root / "a.txt").write_text("顧客 携帯 090-1234-5678\n", encoding="utf-8")
    assert _scan(tmp_path, root, "--no-ask") == 0
    return Store(str(tmp_path / "j.sqlite3")).jobs()[0]["id"], root


def test_report_writes_saved_job_with_csv(tmp_path, capsys):
    """保存済みジョブのレポートを、別の名前で出し直せる（CSV も同じ場所に）。"""
    job, _ = _done_job(tmp_path)
    capsys.readouterr()
    out = tmp_path / "again" / "改めて.xlsx"
    out.parent.mkdir()
    assert cli.main(["--db", str(tmp_path / "j.sqlite3"), "report", job, "-o", str(out), "--csv"]) == 0
    printed = capsys.readouterr().out
    assert out.is_file() and f"レポート: {out}" in printed
    csvs = [line[len("CSV: ") :] for line in printed.splitlines() if line.startswith("CSV: ")]
    assert csvs and all(Path(p).is_file() and Path(p).parent == out.parent for p in csvs)


def test_report_unknown_job_is_refused(tmp_path, capsys):
    _done_job(tmp_path)
    capsys.readouterr()
    assert cli.main(["--db", str(tmp_path / "j.sqlite3"), "report", "nojob", "-o", str(tmp_path / "x.xlsx")]) == 2
    assert "ジョブ nojob が見つかりません" in capsys.readouterr().err
    assert not (tmp_path / "x.xlsx").exists()


def test_report_inside_scanned_folder_is_refused(tmp_path, capsys):
    """レポートを検査先の中へ書くと次の検査で拾ってしまうので、書かずに断る。"""
    job, root = _done_job(tmp_path)
    capsys.readouterr()
    inside = root / "r.xlsx"
    assert cli.main(["--db", str(tmp_path / "j.sqlite3"), "report", job, "-o", str(inside)]) == 2
    assert "レポートの出力先" in capsys.readouterr().err
    assert not inside.exists()


def test_jobs_lists_saved_job(tmp_path, capsys):
    job, _ = _done_job(tmp_path)
    capsys.readouterr()
    assert cli.main(["--db", str(tmp_path / "j.sqlite3"), "jobs"]) == 0
    line = capsys.readouterr().out.strip().splitlines()[0]
    assert line.startswith(f"{job}  完了")


def test_allow_file_not_utf8_is_explained(tmp_path):
    p = tmp_path / "allow.txt"
    p.write_bytes("山田".encode("cp932"))
    with pytest.raises(cli.UserTextError) as e:
        cli._read_user_text(str(p), "拾わない値（許可リスト）")
    assert "UTF-8 として読めません" in str(e.value) and "メモ帳" in str(e.value)


def test_allow_file_that_is_a_folder_is_explained(tmp_path):
    with pytest.raises(cli.UserTextError) as e:
        cli._read_user_text(str(tmp_path), "拾わない値（許可リスト）")
    assert str(e.value).startswith(f"拾わない値（許可リスト）のファイル（{tmp_path}）を読めません")


def test_allow_file_with_bom_is_read(tmp_path):
    """メモ帳の BOM 付き UTF-8 も読める（先頭に BOM の字が残らない）。"""
    p = tmp_path / "allow.txt"
    p.write_bytes("山田\n".encode("utf-8-sig"))
    assert cli._read_user_text(str(p), "拾わない値（許可リスト）") == "山田\n"

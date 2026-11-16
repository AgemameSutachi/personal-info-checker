"""フォルダの列挙（walker）の試験: リンクの指す先の表示・リンクを辿らないこと・読めない項目の記録。"""

import os
import subprocess
from types import SimpleNamespace

import pytest

from pii_checker import walker
from pii_checker.walker import FILE_ATTRIBUTE_REPARSE_POINT, describe_link_target


def test_link_on_nas_points_to_server_drive():
    """NAS の上のリンクが指すドライブ文字の場所は、サーバー側の場所と分かるように出す（手元の C: と取り違えない）。"""
    s = describe_link_target(r"\\nas01\share\links\loop", "\\\\?\\C:\\piishare\\net\\links")
    assert s == r"サーバー上の C:\piishare\net\links"


def test_link_to_unc_and_local():
    assert describe_link_target(r"\\nas01\share\a", "\\\\?\\UNC\\nas02\\data") == r"\\nas02\data"
    assert describe_link_target(r"D:\data\a", "\\\\?\\D:\\other") == r"D:\other"
    assert describe_link_target(r"D:\data\a", r"..\other") == r"..\other"
    assert describe_link_target(r"\\nas01\share\a", "\\??\\C:\\x") == r"サーバー上の C:\x"
    assert describe_link_target(r"D:\data\m", "\\\\?\\Volume{0123}\\").startswith("ボリューム Volume{0123}")


def test_mapped_network_drive_counts_as_server(monkeypatch):
    """NAS をドライブ文字に割り当てて検査したときも、リンクの先はサーバー側の場所と出す。"""
    import ctypes

    from pii_checker import walker

    monkeypatch.setattr(ctypes.windll.kernel32, "GetDriveTypeW", lambda root: 4 if root.upper() == "Z:\\" else 3)
    assert walker.describe_link_target(r"Z:\share\a", "\\\\?\\C:\\x") == r"サーバー上の C:\x"
    assert walker.describe_link_target(r"D:\data\a", "\\\\?\\C:\\x") == r"C:\x"


def test_folder_loop_via_server_symlink_is_not_followed(tmp_path, monkeypatch):
    """Samba がリンクを辿って普通のフォルダとして見せるループ（同じフォルダの識別子）を、二重に辿らずリンクとして記録する。"""
    from pii_checker import walker

    root = tmp_path / "loop"
    (root / "sub" / "back" / "sub").mkdir(parents=True)
    (root / "sub" / "a.txt").write_text("x", encoding="utf-8")
    (root / "sub" / "back" / "sub" / "a.txt").write_text("x", encoding="utf-8")
    real = walker._dir_identity

    def ident(folder):
        # sub/back は root と同じフォルダ（サーバー側のリンク）に見せる
        if folder.rstrip("\\/").endswith("back"):
            return real(str(root))
        return real(folder)

    monkeypatch.setattr(walker, "_dir_identity", ident)
    entries = list(walker.walk([str(root)]))
    files = [e.path for e in entries if e.kind == "file"]
    links = [e for e in entries if e.kind == "link"]
    assert files == [str(root / "sub" / "a.txt")]  # 二重に数えない
    assert len(links) == 1 and "既に辿ったフォルダ" in links[0].reason
    monkeypatch.undo()
    # 陽性対照: 識別子が別なら普通に辿る
    assert len([e for e in walker.walk([str(root)]) if e.kind == "file"]) == 2


@pytest.mark.skipif(os.name != "nt", reason="ジャンクションは Windows だけ")
def test_real_junction_is_recorded_as_link_and_not_followed(tmp_path):
    """本物のジャンクション（管理者権限の要らない再解析ポイント）を、辿らずにリンクとして記録する。"""
    target = tmp_path / "target"
    target.mkdir()
    (target / "inside.txt").write_text("x", encoding="utf-8")
    root = tmp_path / "root"
    root.mkdir()
    (root / "plain.txt").write_text("x", encoding="utf-8")
    made = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(root / "jn"), str(target)], capture_output=True, text=True, check=False
    )
    if made.returncode != 0:
        pytest.skip(f"ジャンクションを作れなかった: {made.stdout}{made.stderr}")
    entries = list(walker.walk([str(root)]))
    assert [e.path for e in entries if e.kind == "file"] == [str(root / "plain.txt")]
    links = [e for e in entries if e.kind == "link"]
    assert [e.path for e in links] == [str(root / "jn")]
    assert links[0].reason.startswith(f"リンク（{target} を指す）。指す先は辿っていない")
    if not walker._on_remote(str(root)):  # 一時フォルダがネットワークドライブの上なら、サーバー上の場所と出るのが正しい
        assert "サーバー上の" not in links[0].reason


def test_link_to_server_location_adds_how_to_scan_it(tmp_path, monkeypatch):
    """サーバー上の場所を指すリンクは、手元から指定できないので共有のパスで検査するよう添える。"""
    (tmp_path / "a.txt").write_text("x", encoding="utf-8")
    (tmp_path / "ln").write_text("x", encoding="utf-8")
    monkeypatch.setattr(walker, "_is_link", lambda path, st: "サーバー上の C:\\x" if path.endswith("ln") else None)
    links = [e for e in walker.walk([str(tmp_path)]) if e.kind == "link"]
    assert len(links) == 1
    assert links[0].reason.endswith(
        "（サーバー上の場所は手元から指定できないので、そこを公開している共有のパスで検査する）"
    )


def test_is_link_by_attributes_and_readlink(monkeypatch):
    plain = SimpleNamespace(st_file_attributes=0)
    reparse = SimpleNamespace(st_file_attributes=FILE_ATTRIBUTE_REPARSE_POINT)
    called = []
    # 手元の D: がネットワークドライブの PC でも結果が変わらないよう、手元のドライブとして扱う
    monkeypatch.setattr(walker, "_on_remote", lambda path: False)
    monkeypatch.setattr(walker.os, "readlink", lambda p: called.append(p) or "\\??\\D:\\other")
    # 再解析ポイントの印が無ければ、指す先を問い合わせない（NAS へ1件ずつ問い合わせ直さない）
    assert walker._is_link(r"D:\data\a", plain) is None
    assert called == []
    assert walker._is_link(r"D:\data\a", reparse) == r"D:\other"

    def not_a_link(p):
        raise OSError(4390, "クラウドの代替ファイル")

    # 再解析ポイントでもリンクでないもの（OneDrive の代替ファイル等）は普通のファイルとして扱う
    monkeypatch.setattr(walker.os, "readlink", not_a_link)
    assert walker._is_link(r"D:\data\a", reparse) is None


def test_is_link_without_windows_attributes_uses_islink(monkeypatch):
    """属性の無い環境（Windows 以外）では os.path.islink で見る。"""
    bare = SimpleNamespace()
    monkeypatch.setattr(walker.os.path, "islink", lambda p: p.endswith("ln"))
    monkeypatch.setattr(walker.os, "readlink", lambda p: "/srv/other")
    assert walker._is_link("/data/a", bare) is None
    assert walker._is_link("/data/ln", bare) == "/srv/other"


def test_on_remote_is_false_for_relative_path():
    assert walker._on_remote("relative\\path") is False
    assert walker._on_remote(r"\\nas01\share") is True


def _winerr(code: int) -> OSError:
    return OSError(None, "ネットワークの失敗", None, code)


@pytest.mark.skipif(os.name != "nt", reason="winerror は Windows だけ")
def test_really_lost_distinguishes_samba_denial_from_disconnection(tmp_path):
    assert walker._really_lost(_winerr(5), str(tmp_path)) is False  # 回線断の番号でない
    assert walker._really_lost(_winerr(64), str(tmp_path)) is True  # 回線断と決まる番号
    # 59 は起点にまだ届くなら回線断ではない（Samba の権限の無いフォルダ）、届かなければ回線断
    assert walker._really_lost(_winerr(59), str(tmp_path)) is False
    assert walker._really_lost(_winerr(59), str(tmp_path / "gone")) is True


def test_really_lost_when_root_check_fails(monkeypatch):
    monkeypatch.setattr(walker, "is_network_lost", lambda e: True)

    def boom(p):
        raise OSError("届かない")

    monkeypatch.setattr(walker.os.path, "isdir", boom)
    assert walker._really_lost(SimpleNamespace(winerror=59), r"\\nas01\share") is True


def test_dir_identity_falls_back_to_stat_identity(monkeypatch):
    from pii_checker import safeio

    monkeypatch.setattr(safeio, "file_id_128", lambda folder: "", raising=False)
    monkeypatch.setattr(safeio, "stat_identity", lambda folder: SimpleNamespace(file_id="0a0b0c0d-0000000000001234"))
    assert walker._dir_identity("X") == "0a0b0c0d-0000000000001234"
    # ファイル番号が 0（識別子を返さないファイルシステム）は、別のフォルダと取り違えるので使わない
    monkeypatch.setattr(safeio, "stat_identity", lambda folder: SimpleNamespace(file_id="0a0b0c0d-0000000000000000"))
    assert walker._dir_identity("X") == ""

    def fail(folder):
        raise OSError("開けない")

    monkeypatch.setattr(safeio, "stat_identity", fail)
    assert walker._dir_identity("X") == ""


def test_single_file_root_and_ftp_root_without_connection(tmp_path):
    f = tmp_path / "one.txt"
    f.write_text("abc", encoding="utf-8")
    entries = list(walker.walk([str(f), "ftp://192.0.2.1/share"]))
    assert entries[0].kind == "file" and entries[0].path == str(f) and entries[0].size == 3
    assert entries[1].kind == "error" and entries[1].path == "ftp://192.0.2.1/share"
    assert entries[1].reason.startswith("FTP の接続先の設定が無い")


@pytest.mark.parametrize(
    "error, message, lost",
    [
        (PermissionError(13, "アクセスが拒否されました"), "アクセスが拒否されました", False),
        # 回線断（64）なら実行器が列挙を止めて再開で読み直せるよう、回線断の印を付ける
        pytest.param(
            OSError(None, "指定されたネットワーク名は利用できません", None, 64),
            "指定されたネットワーク名は利用できません",
            True,
            marks=pytest.mark.skipif(os.name != "nt", reason="winerror は Windows だけ"),
        ),
    ],
)
def test_entry_whose_attributes_cannot_be_read_is_recorded(tmp_path, monkeypatch, error, message, lost):
    """1件の属性が読めなくても、黙って飛ばさずエラーとして残し、ほかの項目は続けて列挙する。"""
    (tmp_path / "bad.txt").write_text("x", encoding="utf-8")
    (tmp_path / "good.txt").write_text("x", encoding="utf-8")
    real = walker.os.scandir

    class BadEntry:
        def __init__(self, de):
            self._de, self.name = de, de.name

        def stat(self, follow_symlinks=True):
            raise error

        def is_dir(self, follow_symlinks=True):
            return False

    class FlakyDir:
        def __init__(self, it):
            self._it = it

        def __enter__(self):
            return [BadEntry(de) if de.name == "bad.txt" else de for de in self._it.__enter__()]

        def __exit__(self, *a):
            return self._it.__exit__(*a)

    monkeypatch.setattr(walker.os, "scandir", lambda p: FlakyDir(real(p)))
    entries = list(walker.walk([str(tmp_path)]))
    errors = [e for e in entries if e.kind == "error"]
    assert [e.path for e in errors] == [str(tmp_path / "bad.txt")]
    assert errors[0].reason.startswith(f"属性を読めなかった: {message}。")
    assert errors[0].network_lost is lost
    assert [e.path for e in entries if e.kind == "file"] == [str(tmp_path / "good.txt")]


def test_is_dir_failure_is_treated_as_file(tmp_path, monkeypatch):
    (tmp_path / "odd").write_text("x", encoding="utf-8")
    real = walker.os.scandir

    class OddEntry:
        def __init__(self, de):
            self._de, self.name = de, de.name

        def stat(self, follow_symlinks=True):
            return self._de.stat(follow_symlinks=follow_symlinks)

        def is_dir(self, follow_symlinks=True):
            raise OSError("種類を読めない")

    class Wrap:
        def __init__(self, it):
            self._it = it

        def __enter__(self):
            return [OddEntry(de) for de in self._it.__enter__()]

        def __exit__(self, *a):
            return self._it.__exit__(*a)

    monkeypatch.setattr(walker.os, "scandir", lambda p: Wrap(real(p)))
    assert [(e.kind, e.path) for e in walker.walk([str(tmp_path)])] == [("file", str(tmp_path / "odd"))]

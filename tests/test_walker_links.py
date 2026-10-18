"""リンクの指す先の表示（walker.describe_link_target）の試験。"""

from pii_checker.walker import describe_link_target


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

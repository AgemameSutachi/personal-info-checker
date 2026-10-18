"""検査の名前（一覧・見出しに出す）の試験。"""

from pii_checker.models import ScanOptions
from pii_checker.store import Store


def test_long_roots_are_not_cut_in_the_middle(tmp_path):
    """長いパスを2つ並べても、2つ目をパスの途中で切らない（切れ端の「C:\\Users\\<ユーザー名>」が名前に出ていた）。"""
    long_dir = "C:\\Users\\taro\\AppData\\Local\\Temp\\" + "x" * 150
    roots = [long_dir + "\\総務\\2024年度", long_dir + "\\総務\\古い資料"]
    name = Store.default_job_name(roots)
    assert name == roots[0] + " ほか 1 件"
    store = Store(str(tmp_path / "j.sqlite3"))
    job_id = store.create_job(roots, ScanOptions())
    assert store.job(job_id)["name"] == name


def test_short_roots_are_joined():
    assert Store.default_job_name(["\\\\nas01\\総務", "D:\\共有"]) == "\\\\nas01\\総務、D:\\共有"
    # 1つだけなら長くても切らない（どこを調べたかが分からなくなるため）
    one = "D:\\" + "y" * 300
    assert Store.default_job_name([one]) == one

"""形式ごとの検査不能の理由の試験の続き（tar・SQLite・dBase・メールの部品・PDF の添付・実行器）。

test_reason_detail_formats.py では壊れたファイルを作りやすい形式だけを確かめた。ここでは、壊れ方を
ファイルで作りにくい所（tar を開く・取り出す、メールの部品の復号、PDF の添付の取り出し、
実行器が受けた想定外のエラー）を、ライブラリの呼び出しを差し替えて確かめる。
"""

from __future__ import annotations

import email.message
import io
import sys
import tarfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pii_checker import runner  # noqa: E402
from pii_checker.engine import UNEXPECTED_HINT, scan_file  # noqa: E402
from pii_checker.formats import archive  # noqa: E402
from pii_checker.models import ScanOptions, Status  # noqa: E402
from pii_checker.store import Store  # noqa: E402


def _assert_detail_last(reason: str, start: str, hint: str) -> None:
    """理由が start で始まり、次の手 hint が（詳細: …）より前にあり、詳細が末尾の1つだけであること。"""
    assert reason.startswith(start), reason
    assert hint in reason, reason
    assert "（詳細: " in reason and reason.endswith("）"), reason
    assert reason.index(hint) < reason.index("（詳細: "), reason
    assert reason.count("（詳細: ") == 1, reason
    assert "）: " not in reason, reason  # 生の文を「…）: 」で後ろに付ける古い形が残っていない


def _scan(tmp_path, name: str, data: bytes):
    p = tmp_path / name
    p.write_bytes(data)
    return scan_file(str(p), ScanOptions(temp_dir=str(tmp_path))).items


def _tar_bytes(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for name, body in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(body)
            tf.addfile(info, io.BytesIO(body))
    return buf.getvalue()


def test_tar_unopenable(tmp_path, monkeypatch):
    """tar を開けないときは、展開したフォルダを検査する手を先に出し、生の文は詳細へ回す。"""

    def broken_open(*args, **kwargs):
        raise tarfile.ReadError("invalid header")

    data = _tar_bytes({"a.txt": b"hello\n"})
    monkeypatch.setattr(archive.tarfile, "open", broken_open)
    item = _scan(tmp_path, "a.tar", data)[0]
    assert item.status == Status.UNCHECKABLE, item.reason
    _assert_detail_last(item.reason, "tar を開けなかった（壊れている可能性）。", "展開したフォルダを検査してください")
    assert "invalid header" in item.reason


def test_tar_member_not_extractable(tmp_path, monkeypatch):
    """取り出せない項目は、通常のファイルでない場合もあると書き、次の手を出す（生の文は無い）。"""
    data = _tar_bytes({"list.csv": "氏名,電話\n山田太郎,090-1234-5678\n".encode()})
    monkeypatch.setattr(tarfile.TarFile, "extractfile", lambda self, member: None)
    items = _scan(tmp_path, "a.tar", data)
    failed = [i for i in items if i.path.endswith("list.csv")]
    assert failed and failed[0].status == Status.UNCHECKABLE, [(i.path, i.status, i.reason) for i in items]
    reason = failed[0].reason
    assert reason.startswith("tar から取り出せなかった（通常のファイルでない項目か、壊れている可能性）。"), reason
    assert archive.ARCHIVE_BROKEN_HINT in reason, reason


def test_sqlite_tables_unreadable(tmp_path):
    """頭だけ SQLite で中身が壊れているときは、生データ走査だけにして取り直し・持ち主の手を出す。"""
    data = b"SQLite format 3\x00" + b"\xff\x00" * 400
    item = _scan(tmp_path, "app.sqlite", data)[0]
    assert item.status == Status.UNCHECKABLE, (item.status, item.reason)
    assert item.reason.startswith(
        "SQLite の表を読めなかった（暗号化か壊れている可能性。生データ走査のみ。"
    ), item.reason
    assert "元のファイルを取り直し" in item.reason and "持ち主に中身を確かめて" in item.reason, item.reason
    # 生の文（file is not a database 等）は理由に混ぜず、注記に残す
    assert any(n.startswith("表を読めなかった") for n in item.notes), item.notes


def test_dbase_header_truncated(tmp_path):
    """見出しの途中で切れた dBase は、取り直す手を先に出し、生の文は詳細へ回す。"""
    head = b"\x03" + b"\x7a\x0b\x07" + (5).to_bytes(4, "little") + (200).to_bytes(2, "little")
    head += (20).to_bytes(2, "little")  # 見出しは 200 バイトと書いてあるが、12 バイトで切れている
    item = _scan(tmp_path, "list.dbf", head)[0]
    assert item.status == Status.UNCHECKABLE, (item.status, item.reason)
    _assert_detail_last(item.reason, "dBase の見出しを読めなかった（壊れている可能性）。", "取り直してください")


def test_eml_part_not_decodable(tmp_path, monkeypatch):
    """メールの部品を復号できないときは、メールのソフトで添付を保存する手を先に出す。"""
    msg = email.message.EmailMessage()
    msg["From"] = "a@example.com"
    msg["To"] = "b@example.com"
    msg["Subject"] = "名簿"
    msg.set_content("本文です")
    msg.add_attachment(b"\x00\x01\x02", maintype="application", subtype="octet-stream", filename="list.bin")
    data = msg.as_bytes()
    original = email.message.Message.get_payload

    def get_payload(self, i=None, decode=False):
        if decode and self.get_filename() == "list.bin":
            raise ValueError("bad base64")
        return original(self, i, decode)

    monkeypatch.setattr(email.message.Message, "get_payload", get_payload)
    items = _scan(tmp_path, "mail.eml", data)
    failed = [i for i in items if i.kind == "メールの部品"]
    assert failed, [(i.path, i.kind, i.status, i.reason) for i in items]
    assert failed[0].status == Status.UNCHECKABLE
    _assert_detail_last(
        failed[0].reason, "メールの部品を復号できなかった（壊れている可能性）。", "添付を保存して検査してください"
    )
    assert "ValueError: bad base64" in failed[0].reason


def test_pdf_attachment_not_extractable(tmp_path, monkeypatch):
    """PDF の添付を取り出せないときは、閲覧ソフトで添付を保存する手を先に出す。"""
    fitz = pytest.importorskip("fitz")
    doc = fitz.open()
    doc.new_page()
    doc.embfile_add("list.csv", "氏名,電話\n山田太郎,090-1234-5678\n".encode())
    data = doc.tobytes()
    doc.close()

    def broken_get(self, item):
        raise RuntimeError("cannot read embedded file")

    monkeypatch.setattr(fitz.Document, "embfile_get", broken_get)
    items = _scan(tmp_path, "doc.pdf", data)
    failed = [i for i in items if i.kind == "PDF の添付"]
    assert failed, [(i.path, i.kind, i.status, i.reason) for i in items]
    assert failed[0].status == Status.UNCHECKABLE
    _assert_detail_last(
        failed[0].reason, "添付を取り出せなかった（壊れている可能性）。", "保存したファイルを検査してください"
    )
    assert "RuntimeError: cannot read embedded file" in failed[0].reason


class _Raises:
    """pebble の future の代わり（結果を取り出すと例外を投げる）。"""

    def __init__(self, error):
        self._error = error

    def result(self):
        raise self._error


def test_runner_unexpected_error(tmp_path, monkeypatch):
    """検査プロセスから想定外の例外が返ったときも、次の手を先に出し、型と文は詳細へ回す。"""
    path = str(tmp_path / "a.txt")
    store = Store(str(tmp_path / "j.sqlite3"))
    job = store.create_job([str(tmp_path)], ScanOptions())
    store.add_files(job, [(path, 1, 0.0)])
    r = runner.JobRunner(store, job, workers=1)
    saved = []
    monkeypatch.setattr(store, "save_failure", lambda job_id, p, reason, elapsed, **kw: saved.append(reason))

    class _Expired(Exception):
        """検査プロセスの異常終了の代わり（ここでは投げない）。"""

    r._save_result(_Raises(ValueError("boom")), path, 0.0, _Expired, 0)
    assert len(saved) == 1, saved
    _assert_detail_last(saved[0], "読み取りの途中で想定外のエラーになり、検査できなかった（要目視）。", UNEXPECTED_HINT)
    assert "ValueError" in saved[0] and "boom" in saved[0], saved[0]

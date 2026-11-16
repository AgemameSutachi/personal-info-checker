"""7-Zip が無いときに、暗号化された zip を Python だけで開く道（archive._zip_python_encrypted）の試験。

ZipCrypto は受け取ったパスワードを UTF-8・cp932 の順に試して開く。AES・未対応の圧縮方式は検査不能として残す。
暗号化されていない項目は同じ書庫の中でもふつうに検査する。
"""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import pii_checker.formats.archive as archive  # noqa: E402
from pii_checker.engine import scan_file  # noqa: E402
from pii_checker.models import PasswordBook, ScanOptions, Status  # noqa: E402
from zipcrypto import zipcrypto_zip  # noqa: E402

SECRET = "携帯 090-1234-5678\n".encode("utf-8")


@pytest.fixture(autouse=True)
def no_7z(monkeypatch):
    monkeypatch.setattr(archive, "find_7z", lambda configured: None)


def scan(path: Path, tmp_path: Path, passwords: list[str]):
    """検査して、書庫の中の名前→結果の辞書を返す。書庫そのものの結果はキー "" に入れる。"""
    r = scan_file(str(path), ScanOptions(temp_dir=str(tmp_path)), PasswordBook(common=passwords))
    return {it.path.rsplit("!", 1)[-1] if "!" in it.path else "": it for it in r.items}


def write(tmp_path: Path, blob: bytes, name: str = "a.zip") -> Path:
    p = tmp_path / name
    p.write_bytes(blob)
    return p


def test_zipcrypto_opens_with_utf8_password(tmp_path):
    items = scan(write(tmp_path, zipcrypto_zip("a.txt", SECRET, "秘密の合言葉")), tmp_path, ["秘密の合言葉"])
    assert items[""].method == "zip を展開（1件・7-Zip なし）"
    assert items["a.txt"].finding_counts.get("phone", 0) == 1


def test_zipcrypto_opens_with_cp932_password(tmp_path):
    """日本語版の Windows の圧縮ソフトで作った zip は、パスワードを cp932 で暗号化していることがある。"""
    pw = "社外秘"
    assert pw.encode("cp932") != pw.encode("utf-8")
    items = scan(write(tmp_path, zipcrypto_zip("a.txt", SECRET, pw.encode("cp932"))), tmp_path, [pw])
    assert items["a.txt"].finding_counts.get("phone", 0) == 1


def test_password_that_cp932_cannot_encode_does_not_stop_the_rest(tmp_path):
    """cp932 で表せない候補（絵文字）で止まらず、次の候補を試す。"""
    items = scan(write(tmp_path, zipcrypto_zip("a.txt", SECRET, "secret")), tmp_path, ["鍵\U0001f511", "secret"])
    assert items["a.txt"].finding_counts.get("phone", 0) == 1


@pytest.mark.parametrize("passwords", [[], ["wrong-1", "wrong-2"]])
def test_wrong_or_missing_password_is_reported(tmp_path, passwords):
    items = scan(write(tmp_path, zipcrypto_zip("a.txt", SECRET, "secret")), tmp_path, passwords)
    it = items["a.txt"]
    assert it.status == Status.NEEDS_PASSWORD
    assert it.password_kind == "zip"
    assert it.size == len(SECRET)
    assert "暗号化されている" in it.reason
    if passwords:
        assert f"受け取ったパスワード {len(passwords)} 個" in it.reason, it.reason
    else:
        assert "受け取ったパスワード" not in it.reason, it.reason


def test_plain_member_beside_encrypted_one_is_scanned(tmp_path):
    """暗号化された項目と同じ書庫にある暗号化されていない項目は、パスワードが無くても検査する。"""
    p = write(tmp_path, zipcrypto_zip("locked.txt", SECRET, "secret"))
    with zipfile.ZipFile(p, "a") as z:
        z.writestr("open.txt", "連絡先 080-2222-3333\n", compress_type=zipfile.ZIP_DEFLATED)
    items = scan(p, tmp_path, [])
    assert items[""].method == "zip を展開（2件・7-Zip なし）"
    assert items["locked.txt"].status == Status.NEEDS_PASSWORD
    assert items["open.txt"].finding_counts.get("phone", 0) == 1


def test_aes_or_unknown_method_is_uncheckable(tmp_path):
    """AES（方式 99）は Python で開けないので、7-Zip を入れる案内つきの検査不能にする。

    中身は ZipCrypto のまま方式の番号だけ 99 に書き換えた擬似物（AES の追加欄 0x9901 は無い）。
    いまの実装は方式の番号だけで判断するので、これで足りる。
    """
    blob = bytearray(zipcrypto_zip("a.txt", SECRET, "secret"))
    blob[8:10] = (99).to_bytes(2, "little")  # 項目の頭の圧縮方式
    cd = blob.index(b"PK\x01\x02")
    blob[cd + 10 : cd + 12] = (99).to_bytes(2, "little")  # 目次の圧縮方式
    it = scan(write(tmp_path, bytes(blob)), tmp_path, ["secret"])["a.txt"]
    assert it.status == Status.UNCHECKABLE
    assert "7-Zip を入れて再検査" in it.reason
    assert it.size == len(SECRET)

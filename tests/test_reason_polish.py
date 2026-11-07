"""理由の文の仕上げ（パスワードの次の手・圧縮率の基準・件数の桁区切り・JPEG XR と HEIC の OCR の文）の試験。"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pii_checker import engine, ocr  # noqa: E402
from pii_checker.engine import Uncheckable, scan_file  # noqa: E402
from pii_checker.formats import archive  # noqa: E402
from pii_checker.models import PasswordBook, ScanOptions, Status  # noqa: E402

fitz = pytest.importorskip("pymupdf")

HEIC_HEAD = b"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00mif1heic" + bytes(64)
JXR_HEAD = b"II\xbc\x01" + bytes(64)


def _locked_pdf(tmp_path) -> Path:
    doc = fitz.open()
    doc.new_page().insert_text((60, 80), "会議の議題", fontname="japan", fontsize=11)
    p = tmp_path / "locked.pdf"
    doc.save(str(p), encryption=fitz.PDF_ENCRYPT_AES_256, user_pw="user-pw-1", owner_pw="owner-pw-1")
    doc.close()
    return p


def test_password_reason_without_candidates_names_screen_and_cli(tmp_path):
    """パスワードを1つも受け取っていなければ、画面の欄の名前とコマンドの引数で入れ方を出す。"""
    item = scan_file(str(_locked_pdf(tmp_path)), ScanOptions(temp_dir=str(tmp_path), reuse=False)).items[0]
    assert item.status == Status.NEEDS_PASSWORD, (item.status, item.reason)
    assert item.reason == (
        "PDF に開くためのパスワードが掛かっている（パスワードが分かれば、結果の「パスワードが必要なファイル」で"
        "入れると再検査できる。コマンドの版は --password-file で渡す）"
    ), item.reason


def test_password_reason_with_wrong_candidates_asks_for_another(tmp_path):
    """受け取ったパスワードで開けなければ、試した数と、別のパスワード・持ち主に確かめる手を出す。"""
    book = PasswordBook(common=["違う1", "違う2"])
    item = scan_file(str(_locked_pdf(tmp_path)), ScanOptions(temp_dir=str(tmp_path), reuse=False), book).items[0]
    assert item.status == Status.NEEDS_PASSWORD, (item.status, item.reason)
    assert "受け取ったパスワード 2 個を試したが開けなかった。別のパスワードを入れると再検査できる。" in item.reason
    assert item.reason.endswith("分からなければ持ち主に中身を確かめてもらう）"), item.reason


def test_password_reason_counts_with_separator_and_extra():
    """試した数は桁区切りで出し、Office の既定値のように、ほかに試したものを数の後ろに添える。"""
    ctx = SimpleNamespace(password_candidates=lambda: [str(i) for i in range(1234)])
    text = engine.ScanContext.password_reason(ctx, "暗号化されている", also="と既定値")
    assert text.startswith("暗号化されている（受け取ったパスワード 1,234 個と既定値を試したが開けなかった。"), text


@pytest.mark.parametrize("ratio_size", [1024**2, 1024])
def test_bomb_ratio_names_threshold(ratio_size):
    """圧縮率で打ち切ったときは、何倍を超えたら打ち切るか（基準）も出す。倍率は桁区切りで出す。"""
    ctx = SimpleNamespace(expanded_bytes=0, options=ScanOptions())
    total = 20 * 1024**3
    with pytest.raises(Uncheckable) as e:
        archive._check_bomb(ctx, total, ratio_size)
    reason = str(e.value)
    assert f"圧縮率が異常（{total / ratio_size:,.0f}倍・展開後 20GB。" in reason, reason
    assert "基準は 10GB を超える展開で 1,000倍）のため打ち切り" in reason, reason
    assert "展開してからそのフォルダを検査してください" in reason, reason


def test_bomb_ratio_under_threshold_passes():
    """基準に届かない倍率は打ち切らない（陽性対照の裏）。"""
    ctx = SimpleNamespace(expanded_bytes=0, options=ScanOptions())
    archive._check_bomb(ctx, 20 * 1024**3, 20 * 1024**3 // 1000 + 1)  # 999.99…倍


def test_entry_limit_reason_uses_separator():
    """内側のファイル数の上限は桁区切りで出す（「3000000件」と出さない）。"""
    ctx = SimpleNamespace(expanded_bytes=0, entries=3_000_000, options=ScanOptions(max_entries=3_000_000))
    engine.ScanContext.account(SimpleNamespace(**vars(ctx) | {"entries": 2_999_999}), 0)  # 上限ちょうどは通る
    with pytest.raises(Uncheckable) as e:
        engine.ScanContext.account(ctx, 0)
    assert "内側のファイル数が上限（3,000,000件）を超えたため打ち切り" in str(e.value), str(e.value)


@pytest.mark.parametrize(
    "name, head, label",
    [("photo.heic", HEIC_HEAD, "HEIC/AVIF"), ("photo.jxr", JXR_HEAD, "JPEG XR")],
)
def test_wic_image_ocr_off_names_setting(tmp_path, name, head, label):
    """JPEG XR・HEIC を OCR なしで検査したら、オンにして再検査する手を出す。"""
    p = tmp_path / name
    p.write_bytes(head)
    item = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path), ocr=False, reuse=False)).items[0]
    assert item.status == Status.UNCHECKABLE, (item.status, item.reason)
    assert item.reason.startswith(f"OCR を無効にして実行したため画像（{label}）の中の文字を検査していない（要目視。")
    assert "をオンにして再検査してください。コマンドの版は --no-ocr を外します" in item.reason, item.reason


@pytest.mark.parametrize(
    "name, head, start",
    [
        ("photo.heic", HEIC_HEAD, "OCR が使えないため画像（HEIC/AVIF）の中の文字を検査できない（要目視）。"),
        ("photo.jxr", JXR_HEAD, "OCR が使えないため画像（JPEG XR）の中の文字を検査できない（要目視。"),
    ],
)
def test_wic_image_ocr_unavailable_joins_install_hint(tmp_path, monkeypatch, name, head, start):
    """OCR が使えないときは、入れ方の案内を文として続ける。"""
    monkeypatch.setattr(ocr, "is_available", lambda: False)
    monkeypatch.setattr(ocr, "unavailable_reason", lambda: "日本語の OCR 認識器を入れてください。")
    p = tmp_path / name
    p.write_bytes(head)
    item = scan_file(str(p), ScanOptions(temp_dir=str(tmp_path), reuse=False)).items[0]
    assert item.status == Status.UNCHECKABLE, (item.status, item.reason)
    assert item.reason.startswith(start), item.reason
    assert item.reason.endswith("。日本語の OCR 認識器を入れてください。"), item.reason

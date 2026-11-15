"""detectors の網羅で通っていなかった分岐の試験（2026-11-15）。

Rust 拡張が入っているのに読めない・範囲の設定で落ちるときに Python の経路へ切り替える分岐、engine.log が書けないとき、
型番の語が前にある固定電話、末尾を外すと不自然なドメインになるメールの形。
"""

import builtins
import os
import sys
import types

import pytest

from pii_checker import detectors, engine
from pii_checker.models import Confidence, ItemResult, Status


def _rows(hits):
    return [(h.pii_type, h.value, h.confidence) for h in hits]


# ---------------------------------------------------------------- Rust 拡張の読み込みの失敗


def test_extension_import_error_falls_back_to_python(monkeypatch, tmp_path):
    """拡張が入っているのに読めない（DLL の読み込みの失敗など）ときは、Python の経路で動き、理由を残す。"""
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "pii_rs_detect":
            raise ImportError("DLL load failed while importing pii_rs_detect")
        return real_import(name, *args, **kwargs)

    monkeypatch.delenv("PII_CHECKER_NO_RUST", raising=False)
    monkeypatch.setattr(builtins, "__import__", fake_import)
    monkeypatch.setattr(detectors, "_RUST_NOTE", "")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))  # engine.log は試験の一時フォルダへ
    assert detectors._load_rust() is None
    assert "拡張を読み込めない" in detectors._RUST_NOTE
    assert "DLL load failed" in detectors.engine_log_path().read_text(encoding="utf-8")


def test_extension_not_installed_is_quiet(monkeypatch, tmp_path):
    """拡張が入っていないだけなら、理由を覚えるが engine.log には書かない（よくあることなので騒がない）。"""
    monkeypatch.delenv("PII_CHECKER_NO_RUST", raising=False)
    monkeypatch.setitem(sys.modules, "pii_rs_detect", None)  # import すると ModuleNotFoundError になる
    monkeypatch.setattr(detectors, "_RUST_NOTE", "")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    assert detectors._load_rust() is None
    assert detectors._RUST_NOTE == "拡張が入っていない"
    assert not detectors.engine_log_path().exists()


def test_extension_setup_failure_falls_back_to_python(monkeypatch, tmp_path):
    """読み込めても、食い違う範囲の設定で落ちる拡張は使わない。"""

    def broken_set(ranges):
        raise RuntimeError("範囲の設定に失敗")

    fake = types.ModuleType("pii_rs_detect")
    fake.set_mismatch_ranges = broken_set
    monkeypatch.delenv("PII_CHECKER_NO_RUST", raising=False)
    monkeypatch.setitem(sys.modules, "pii_rs_detect", fake)
    monkeypatch.setattr(detectors, "_guard_ranges_for", lambda ext: [])
    monkeypatch.setattr(detectors, "_RUST_NOTE", "")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    assert detectors._load_rust() is None
    assert "拡張の読み込みに失敗した" in detectors._RUST_NOTE
    assert "範囲の設定に失敗" in detectors.engine_log_path().read_text(encoding="utf-8")


def test_engine_log_unwritable_does_not_stop(monkeypatch, tmp_path):
    """engine.log を書けない（置き場がファイルで塞がれている）ときも、例外を出さずに続ける。"""
    blocker = tmp_path / "blocked"
    blocker.write_text("", encoding="utf-8")  # LOCALAPPDATA がファイルなので、その下にフォルダを作れない
    monkeypatch.setenv("LOCALAPPDATA", str(blocker))
    detectors._record_engine_event("書けないことの試験")  # 主眼: 例外が出ないこと
    assert blocker.read_text(encoding="utf-8") == ""


# ---------------------------------------------------------------- 本文の検出の分岐


@pytest.mark.parametrize("path", ["python", "detect"])
def test_landline_after_model_word_is_low(path):
    """前に「型番」などの語がある固定電話の形は、型番とみなして 低 にする。電話の語が間にあれば 中 のまま。"""
    run = (lambda t: detectors._detect_py(t, None)) if path == "python" else detectors.detect
    hits = [h for h in run("型番 03-1234-5678") if h.pii_type == "phone"]
    assert [h.confidence for h in hits] == [Confidence.LOW]
    assert "型番" in hits[0].rule
    hits = [h for h in run("型番 X-100 TEL 03-1234-5678") if h.pii_type == "phone"]
    assert [h.confidence for h in hits] == [Confidence.MEDIUM]  # 対照: 電話の語が値のすぐ左にある


def test_email_tail_trim_that_leaves_implausible_domain_is_dropped():
    """末尾の続き（「movAbc」の「Abc」）を外すと画像の倍率の名前（「@2x.mov」）になる形は、メールとして拾わない。"""
    assert not [h for h in detectors.detect("icon@2x.movAbc") if h.pii_type == "email"]
    # 対照: 外したあとが実在しうるドメインなら、外した形で拾う
    assert [h.value for h in detectors.detect("icon@example.movAbc") if h.pii_type == "email"] == ["icon@example.mov"]


# ---------------------------------------------------------------- engine の小さな関数の分岐


@pytest.mark.skipif(os.name != "nt", reason="拡張パス形式は Windows だけ")
def test_long_unc_path_uses_unc_prefix():
    r"""240文字以上の UNC パス（\\サーバー\共有\…）は、頭の「\\」を「\\?\UNC\」に置き換えた形にする。"""
    long = "\\\\server\\share\\" + "\\".join(["d" * 100] * 3) + "\\a.txt"
    assert engine.long_path(long) == "\\\\?\\UNC\\" + long[2:]
    assert engine.long_path("\\\\server\\share\\a.txt") == "\\\\server\\share\\a.txt"  # 短ければそのまま


def test_add_text_ignores_none_and_reads_non_strings():
    """セルの値が None なら何もしない。数などの文字列でない値は文字列にして検査する。"""
    item = ItemResult(path="t", kind="", status=Status.PENDING)
    col = engine.Collector(item, 20)
    col.add_text(None, location="A1")
    assert col.ticks == 0
    col.add_text(9012345678, location="A2", header="携帯電話")  # 頭の0が落ちた数（表計算の数のセル）
    col.finish()
    assert col.ticks == 1
    assert item.finding_counts.get("phone") == 1, item.finding_counts  # 文字列にして、列見出しで電話として拾う


def test_worst_status_and_risk_of_without_findings():
    """項目が無ければ「検査済み」、件数が0の内訳しか無ければ危険度は「なし」。"""
    assert engine.worst_status([]) == Status.SCANNED
    item = ItemResult(path="t", kind="", status=Status.SCANNED, conf_counts={"phone:medium": 0})
    assert engine.risk_of([item]) == "なし"
    # 対照: 件数0の 中 は飛ばし、ほかの内訳で決める（件数を見ずに 中 にしない）
    item = ItemResult(path="t", kind="", status=Status.SCANNED, conf_counts={"phone:medium": 0, "phone:low": 1})
    assert engine.risk_of([item]) == "低"
    item = ItemResult(path="t", kind="", status=Status.SCANNED, conf_counts={"phone:medium": 1})
    assert engine.risk_of([item]) == "中"

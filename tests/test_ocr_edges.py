"""pii_checker.ocr の、OCR が使えないときの断り・認識器の選び方・画像の濃淡の直し・WIC の肩代わりの枝の試験。

本物の WinRT は呼ばない（差し替えた部品で確かめる）。画面は出さない。
"""

from __future__ import annotations

import builtins
import threading
import types

import pytest
from PIL import Image

from pii_checker import ocr

# ---------------------------------------------------------------- winrt の読み込み


def _import_fails_with(monkeypatch, exc: Exception) -> None:
    """winrt の名前空間の import だけを exc で失敗させる。"""
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name.startswith("winrt"):
            raise exc
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)


def test_import_winrt_missing_package_says_how_to_install(monkeypatch):
    """winrt が無ければ、導入のコマンドを添えて断り、部品は置かない。"""
    monkeypatch.setattr(ocr, "_winrt", {})
    _import_fails_with(monkeypatch, ImportError("No module named 'winrt'"))
    with pytest.raises(ocr.OcrUnavailable) as info:
        ocr._import_winrt()
    message = str(info.value)
    assert "pip install winrt-runtime" in message
    assert "No module named 'winrt'" in message
    assert ocr._winrt == {}


def test_import_winrt_os_error_mentions_windows_version(monkeypatch):
    _import_fails_with(monkeypatch, OSError("読み込めない"))
    with pytest.raises(ocr.OcrUnavailable) as info:
        ocr._import_winrt()
    assert "Windows 10 以降" in str(info.value)
    assert "読み込めない" in str(info.value)


# ---------------------------------------------------------------- 日本語の認識器の選び方


class _Lang:
    """language_tag だけを持つ言語の代わり。"""

    def __init__(self, tag: str) -> None:
        self.language_tag = tag


def _fake_winrt(
    monkeypatch,
    *,
    ja_supported=False,
    tags=(),
    profile_tag=None,
    profile_error=False,
    probe_error=False,
):
    """_winrt に、日本語の認識器の有無を決めた差し替えを置く。"""

    class Engine:
        @staticmethod
        def is_language_supported(lang):
            if probe_error:
                raise OSError("調べられない")
            return ja_supported and lang.language_tag == "ja"

        available_recognizer_languages = [_Lang(t) for t in tags]

        @staticmethod
        def try_create_from_user_profile_languages():
            if profile_error:
                raise OSError("作れない")
            if profile_tag is None:
                return None
            return types.SimpleNamespace(recognizer_language=_Lang(profile_tag))

    monkeypatch.setitem(ocr._winrt, "ocr", types.SimpleNamespace(OcrEngine=Engine))
    monkeypatch.setitem(ocr._winrt, "glob", types.SimpleNamespace(Language=_Lang))


def test_pick_tag_prefers_plain_ja(monkeypatch):
    _fake_winrt(monkeypatch, ja_supported=True, tags=("en-US",))
    assert ocr._pick_japanese_tag() == "ja"


def test_pick_tag_uses_regional_ja_tag(monkeypatch):
    _fake_winrt(monkeypatch, tags=("en-US", "JA-jp"))
    assert ocr._pick_japanese_tag() == "JA-jp"


def test_pick_tag_falls_back_to_user_profile_language(monkeypatch):
    _fake_winrt(monkeypatch, tags=("en-US",), profile_tag="ja-JP")
    assert ocr._pick_japanese_tag() == "ja-JP"


@pytest.mark.parametrize(
    ("tags", "profile_tag", "profile_error", "installed"),
    [
        (("en-US", "fr-FR"), "en-US", False, "en-US、fr-FR"),
        ((), None, False, "なし"),
        (("en-US",), None, True, "en-US"),
    ],
)
def test_pick_tag_without_japanese_lists_installed(monkeypatch, tags, profile_tag, profile_error, installed):
    _fake_winrt(monkeypatch, tags=tags, profile_tag=profile_tag, profile_error=profile_error)
    with pytest.raises(ocr.OcrUnavailable) as info:
        ocr._pick_japanese_tag()
    message = str(info.value)
    assert f"入っている認識器: {installed}）" in message
    assert "Add-WindowsCapability" in message


def test_pick_tag_probe_failure_is_unavailable(monkeypatch):
    _fake_winrt(monkeypatch, probe_error=True)
    with pytest.raises(ocr.OcrUnavailable, match="認識器を調べられませんでした"):
        ocr._pick_japanese_tag()


def test_engine_that_cannot_be_created_is_unavailable(monkeypatch):
    class Engine:
        @staticmethod
        def try_create_from_language(lang):
            return None

    monkeypatch.setitem(ocr._winrt, "ocr", types.SimpleNamespace(OcrEngine=Engine))
    monkeypatch.setitem(ocr._winrt, "glob", types.SimpleNamespace(Language=_Lang))
    monkeypatch.setattr(ocr, "_language_tag", "ja")
    monkeypatch.setattr(ocr, "_thread_local", threading.local())
    with pytest.raises(ocr.OcrUnavailable, match="OCR エンジン（ja）を作れませんでした"):
        ocr._engine()


# ---------------------------------------------------------------- 濃淡の直し


@pytest.mark.parametrize("mode", ["I", "I;16", "F"])
def test_to_gray_stretches_deep_images(mode):
    img = Image.new(mode, (2, 1))
    img.putpixel((0, 0), 1000)
    img.putpixel((1, 0), 3000)
    gray = ocr._to_gray(img)
    assert gray.mode == "L"
    assert gray.getpixel((0, 0)) == 0
    assert gray.getpixel((1, 0)) == 255


@pytest.mark.parametrize("mode", ["I;16", "F"])
def test_to_gray_flat_deep_image_is_white(mode):
    img = Image.new(mode, (3, 2), 500)
    gray = ocr._to_gray(img)
    assert gray.mode == "L"
    assert gray.size == (3, 2)
    assert gray.getextrema() == (255, 255)


def test_to_gray_keeps_l_image_as_is():
    img = Image.new("L", (2, 2), 10)
    assert ocr._to_gray(img) is img


# ---------------------------------------------------------------- WIC の肩代わり


@pytest.fixture
def wic_ready(monkeypatch):
    """OCR が使える扱いにし、肩代わりの補助スレッドを使い捨てにする。"""
    monkeypatch.setattr(ocr, "_require_available", lambda: None)
    monkeypatch.setattr(ocr, "_sta_executor", None)
    yield
    if ocr._sta_executor is not None:
        ocr._sta_executor.shutdown(wait=True)


def test_open_with_wic_retries_on_helper_thread_from_sta(monkeypatch, wic_ready):
    """STA から呼ばれて断られたら、補助スレッドで bytes にした中身を開き直す。"""
    caller = threading.get_ident()
    seen = []

    def here(data):
        assert type(data) is bytes
        seen.append(threading.get_ident())
        if threading.get_ident() == caller:
            raise RuntimeError("Cannot call blocking method from single-threaded apartment")
        return Image.new("L", (4, 3))

    monkeypatch.setattr(ocr, "_open_with_wic_here", here)
    img = ocr.open_with_wic(bytearray(b"data"))
    assert img.size == (4, 3)
    assert len(seen) == 2
    assert seen[0] == caller
    assert seen[1] != caller


@pytest.mark.parametrize("exc", [OSError("壊れた"), RuntimeError("壊れた")])
def test_open_with_wic_helper_thread_failure_is_value_error(monkeypatch, wic_ready, exc):
    caller = threading.get_ident()

    def here(data):
        if threading.get_ident() == caller:
            raise RuntimeError("Cannot call blocking method from single-threaded apartment")
        raise exc

    monkeypatch.setattr(ocr, "_open_with_wic_here", here)
    with pytest.raises(ValueError, match="画像を読み込めませんでした.*壊れた"):
        ocr.open_with_wic(b"data")


@pytest.mark.parametrize("exc", [RuntimeError("別の失敗"), OSError("別の失敗")])
def test_open_with_wic_first_failure_is_value_error_without_retry(monkeypatch, wic_ready, exc):
    """STA の断り以外の失敗は、補助スレッドで開き直さずに ValueError にする。"""
    calls = []

    def here(data):
        calls.append(data)
        raise exc

    monkeypatch.setattr(ocr, "_open_with_wic_here", here)
    with pytest.raises(ValueError, match="別の失敗"):
        ocr.open_with_wic(b"data")
    assert len(calls) == 1
    assert ocr._sta_executor is None


def test_open_with_wic_when_ocr_unavailable(monkeypatch):
    """OCR が使えない環境では、開こうとせずに OcrUnavailable を出す。"""
    monkeypatch.setattr(ocr, "_checked", True)
    monkeypatch.setattr(ocr, "_reason", "使えない（試験）")
    with pytest.raises(ocr.OcrUnavailable, match="使えない（試験）"):
        ocr.open_with_wic(b"data")

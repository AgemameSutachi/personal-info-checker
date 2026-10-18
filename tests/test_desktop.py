"""アプリ版（desktop.py）の単体試験。窓は作らない。"""

from __future__ import annotations

import ctypes
import inspect
import json
import sys
import threading
import types
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pii_checker import desktop  # noqa: E402
from pii_checker.desktop import DesktopApi  # noqa: E402

EXPOSED = {"pick_folder", "reveal", "save_report"}


def test_js_api_exposes_only_methods():
    """pywebview は `_` で始まらない属性を再帰的にたどって JS へ公開する。

    窓などのオブジェクトを公開の属性に持たせると、.NET の窓の部品まで UI 以外のスレッドで触りに行き、
    exe で画面の初期化とサーバーが止まった（2026-10-17）。公開してよいのは画面から呼ぶメソッドだけ。
    """
    api = DesktopApi(app=object())
    api._window = object()  # run_app と同じく窓を持たせた状態で調べる
    public = {name for name in dir(api) if not name.startswith("_")}
    assert (
        public == EXPOSED
    ), f"公開名が変わった: {public ^ EXPOSED}（画面から呼ぶなら EXPOSED へ足す。呼ばないなら _ で始める）"
    for name in public:
        assert inspect.ismethod(getattr(api, name)), name


class _FakeEvents:
    """pywebview の window.events の代わり（loaded は最初から済みにして、見張り役にブラウザを開かせない）。"""

    def __init__(self):
        self.loaded = threading.Event()
        self.loaded.set()
        self.closing = _FakeHook()


class _FakeHook:
    def __iadd__(self, func):
        return self


class _FakeWebview(types.ModuleType):
    """窓を作らない pywebview。start で例外を出すかどうかを選べる。"""

    def __init__(self, start_error: Exception | None = None):
        super().__init__("webview")
        self.start_error = start_error
        self.created = 0

    def create_window(self, *args, **kwargs):
        self.created += 1
        return types.SimpleNamespace(events=_FakeEvents())

    def start(self, **kwargs):
        if self.start_error:
            raise self.start_error


def _run_fallback(monkeypatch, tmp_path, fake_webview, has_webview2):
    """run_app を走らせ、ブラウザで開いた URL・知らせた文・知らせている間のサーバーの応答を返す。"""
    opened, shown, during = [], [], {}

    def fake_message_box(hwnd, text, title, flags):
        # 知らせを出している間は、ブラウザで開いた画面が実際に使えること
        url = opened[0]
        token = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["token"][0]
        base = url.split("/?", 1)[0]
        with urllib.request.urlopen(f"{base}/api/info?token={token}", timeout=10) as r:
            during["status"] = r.status
            during["info"] = json.loads(r.read().decode("utf-8"))
        with urllib.request.urlopen(url, timeout=10) as r:
            during["page"] = r.status
        shown.append(text)
        return 1

    monkeypatch.setitem(sys.modules, "webview", fake_webview)
    monkeypatch.setattr(desktop, "webview2_available", lambda: has_webview2)
    monkeypatch.setattr(webbrowser, "open", lambda url, *a, **k: opened.append(url) or True)
    monkeypatch.setattr(ctypes.windll.user32, "MessageBoxW", fake_message_box)
    desktop.run_app(db=str(tmp_path / "jobs.sqlite3"))
    return opened, shown, during


def _assert_server_stopped(url: str) -> None:
    base = url.split("/?", 1)[0]
    with pytest.raises(urllib.error.URLError):
        urllib.request.urlopen(f"{base}/", timeout=3)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows の知らせ（MessageBoxW）を使う")
def test_falls_back_to_browser_without_webview2(monkeypatch, tmp_path):
    """WebView2 が無い PC では窓を作らず、同じ画面を既定のブラウザで開き、知らせを閉じたら終わる。"""
    fake = _FakeWebview()
    opened, shown, during = _run_fallback(monkeypatch, tmp_path, fake, has_webview2=False)
    assert fake.created == 0
    assert len(opened) == 1 and opened[0].startswith("http://127.0.0.1:") and "token=" in opened[0]
    assert len(shown) == 1 and "WebView2" in shown[0] and "ブラウザで開きました" in shown[0]
    assert during["status"] == 200 and during["page"] == 200
    assert during["info"]["desktop"] is True  # 画面側は window.pywebview が無いのでアプリ専用の機能を出さない
    _assert_server_stopped(opened[0])


@pytest.mark.skipif(sys.platform != "win32", reason="Windows の知らせ（MessageBoxW）を使う")
def test_falls_back_to_browser_when_window_fails(monkeypatch, tmp_path):
    """WebView2 はあるが窓の起動で失敗した PC でも、ブラウザで開き、失敗の理由を知らせる。"""
    fake = _FakeWebview(start_error=RuntimeError("窓を作れない"))
    opened, shown, during = _run_fallback(monkeypatch, tmp_path, fake, has_webview2=True)
    assert fake.created == 1
    assert len(opened) == 1
    assert len(shown) == 1 and "RuntimeError: 窓を作れない" in shown[0]
    assert during["status"] == 200 and during["page"] == 200
    _assert_server_stopped(opened[0])

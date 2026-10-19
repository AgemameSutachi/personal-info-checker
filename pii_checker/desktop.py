"""アプリ版。Web 版と同じサーバーと画面を、pywebview（Windows では Edge WebView2）の窓で表示する。

サーバーはこの PC の空いているポートだけで待ち受け、毎回ランダムな合言葉を使う。
フォルダ選択とレポート保存は、OS 標準のダイアログを使う（窓から JS で呼ぶ）。
"""

from __future__ import annotations

import os
import socket
import threading
import time


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class DesktopApi:
    """画面の JS から window.pywebview.api.* で呼ばれる。

    画面から呼ぶメソッド以外の属性は、必ず `_` で始める。pywebview は `_` で始まらない属性を再帰的にたどって JS へ公開するため、
    公開の属性に窓を持たせると .NET の窓の部品まで UI 以外のスレッドで触りに行き、exe で固まる
    （画面の初期化もサーバーも止まった・2026-10-17 実機で確認）。
    """

    def __init__(self, app):
        self._app = app
        self._window = None

    def pick_folder(self):
        import webview

        result = self._window.create_file_dialog(webview.FOLDER_DIALOG, allow_multiple=True)
        return list(result or [])

    def reveal(self, path: str):
        """エクスプローラーで、そのファイルの場所を開いて選択する（アーカイブの中身なら外側のファイル）。"""
        import subprocess

        outer = path.split("!", 1)[0]
        if not os.path.exists(outer):
            return {"error": f"ファイルが見つかりません（移動・削除された可能性）: {outer}"}
        subprocess.Popen(["explorer", "/select,", os.path.normpath(outer)])
        return {"ok": True}

    def save_report(self, job_id: str, kind: str = "xlsx"):
        import webview

        from .report import write_csv, write_xlsx

        from .safeio import output_inside_roots

        store = self._app.state.store
        job = store.job(job_id)
        if not job:
            return {"error": "そのジョブは見つかりません"}

        def refuse(path: str) -> dict | None:
            msg = output_inside_roots(path, job["roots"], "保存先")
            return {"error": msg} if msg else None

        if kind == "csv":
            # Web 版と同じく「検出明細」の CSV を1つ保存する
            import tempfile

            target = self._window.create_file_dialog(
                webview.SAVE_DIALOG,
                save_filename=f"検出明細_{job_id}.csv",
                file_types=("CSV (*.csv)",),
            )
            if not target:
                return {"cancelled": True}
            path = target if isinstance(target, str) else target[0]
            if refuse(path):
                return refuse(path)
            tmp = tempfile.mkdtemp(prefix="piichk_csv_")
            p1, _ = write_csv(store, job_id, tmp)
            import shutil

            shutil.move(p1, path)
            shutil.rmtree(tmp, ignore_errors=True)
            return {"path": path}
        name = f"個人情報チェッカー_{job_id}.xlsx"
        target = self._window.create_file_dialog(
            webview.SAVE_DIALOG,
            save_filename=name,
            file_types=("Excel ブック (*.xlsx)",),
        )
        if not target:
            return {"cancelled": True}
        path = target if isinstance(target, str) else target[0]
        if not path.lower().endswith(".xlsx"):
            path += ".xlsx"
        if refuse(path):
            return refuse(path)
        try:
            write_xlsx(store, job_id, path)
        except PermissionError:
            return {"error": "保存できませんでした（同じ名前のファイルを Excel で開いていませんか？）"}
        os.startfile(path)
        return {"path": path}


def app_url(port: int, token: str, roots: list[str] | None = None) -> str:
    """窓で開く URL。roots は検査の対象の欄へ最初から入れておくパス（画面が読んだあとアドレスから消す）。"""
    from urllib.parse import urlencode

    query = [("token", token)] + [("root", r) for r in roots or [] if r]
    return f"http://127.0.0.1:{port}/?{urlencode(query)}"


def run_app(db: str | None = None, roots: list[str] | None = None) -> None:
    try:
        import uvicorn
        import webview
    except ImportError as e:
        raise SystemExit(
            f"アプリ版に必要な部品が入っていません（{e.name}）。pip install -r requirements.txt を実行してください"
        )

    from .web.server import create_app

    app = create_app(db=db, desktop=True)
    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    url = app_url(port, app.state.token, roots)
    if not webview2_available():
        return _browser_fallback(url, server, t, "Microsoft Edge WebView2 ランタイムが入っていない")
    api = DesktopApi(app)
    window = webview.create_window("個人情報チェッカー", url, js_api=api, width=1320, height=900, min_size=(900, 600))
    api._window = window

    def watchdog():
        # 40 秒たっても画面が出なければ、ブラウザで開く（WebView2 の初期化に失敗して固まる PC がある）
        if not window.events.loaded.wait(40):
            import webbrowser

            webbrowser.open(url)

    threading.Thread(target=watchdog, daemon=True).start()

    def on_closing():
        # アプリ版は窓を閉じると検査が中断するので、検査中なら確かめる
        running = [r for r in app.state.registry._runners.values() if r.running]
        if not running:
            return True
        return window.create_confirmation_dialog(
            "個人情報チェッカー",
            "検査中です。閉じると検査は中断します（あとで「再開」で続きから検査できます）。閉じますか？",
        )

    window.events.closing += on_closing
    try:
        webview.start(private_mode=True)
    except Exception as e:
        return _browser_fallback(url, server, t, f"{type(e).__name__}: {e}")
    finally:
        server.should_exit = True
        t.join(timeout=5)


WEBVIEW2_KEY = r"Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"


def webview2_available() -> bool:
    """Edge WebView2 ランタイムが入っているか（入っていなければ窓を作れない）。"""
    try:
        import winreg
    except ImportError:
        return False
    places = [
        (winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\" + WEBVIEW2_KEY),
        (winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\\" + WEBVIEW2_KEY),
        (winreg.HKEY_CURRENT_USER, "Software\\" + WEBVIEW2_KEY),
    ]
    for root, key in places:
        try:
            with winreg.OpenKey(root, key) as k:
                pv, _ = winreg.QueryValueEx(k, "pv")
                if pv and pv != "0.0.0.0":
                    return True
        except OSError:
            continue
    return False


def _browser_fallback(url: str, server, thread, reason: str) -> None:
    """窓を作れないときは、同じ画面を既定のブラウザで開いて使ってもらう。"""
    import ctypes
    import webbrowser

    webbrowser.open(url)
    message = (
        f"アプリの窓を開けなかったため（{reason}）、同じ画面をブラウザで開きました。\n"
        "このメッセージを閉じると、個人情報チェッカーを終了します（検査中なら中断し、あとで再開できます）。"
    )
    print(message)
    try:
        ctypes.windll.user32.MessageBoxW(None, message, "個人情報チェッカー", 0x40)
    except Exception:
        thread.join()
    server.should_exit = True
    thread.join(timeout=5)

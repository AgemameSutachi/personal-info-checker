"""レポートを Web のページで見る試験。

- 検査して結果を出す → サーバー（アプリ）を終わらせる → 開き直すと、前の結果とレポートを取れる
- Excel のシート（判定・要対応・ファイル別・検出明細・全項目）の中身を、同じ数で Web の API からも取れる
"""

from __future__ import annotations

import json
import socket
import threading
import time
import urllib.request

import pytest
from openpyxl import load_workbook

TOKEN = "report-test-token"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _Server:
    """create_app を本物の uvicorn で立てる（アプリの起動と同じ）。"""

    def __init__(self, db: str):
        import uvicorn

        from pii_checker.web.server import create_app

        self.port = _free_port()
        self.srv = uvicorn.Server(
            uvicorn.Config(create_app(db=db, token=TOKEN), host="127.0.0.1", port=self.port, log_level="warning")
        )
        self.th = threading.Thread(target=self.srv.run, daemon=True)
        self.th.start()
        for _ in range(100):
            if self.srv.started:
                break
            time.sleep(0.05)

    def api(self, path: str, body: dict | None = None):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=json.dumps(body).encode() if body is not None else None,
            headers={"X-Token": TOKEN, "Content-Type": "application/json", "X-Requested-With": "pii-checker"},
            method="POST" if body is not None else "GET",
        )
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read())

    def stop(self):
        self.srv.should_exit = True
        self.th.join(30)


@pytest.fixture
def folder(tmp_path):
    d = tmp_path / "共有"
    (d / "sub").mkdir(parents=True)
    (d / "名簿.txt").write_text("氏名 山田太郎 電話 090-1234-5678\nメール yamada@example.jp\n", encoding="utf-8")
    (d / "sub" / "メモ.txt").write_text("連絡先 080-2222-3333\n", encoding="utf-8")
    (d / "空.txt").write_text("個人情報はありません\n", encoding="utf-8")
    return d


def test_results_survive_restart_and_match_excel(tmp_path, folder):
    db = str(tmp_path / "jobs.sqlite3")
    s1 = _Server(db)
    try:
        job = s1.api("/api/jobs", {"roots": [str(folder)], "options": {"temp_dir": str(tmp_path)}})["id"]
        for _ in range(600):
            if s1.api(f"/api/jobs/{job}")["state"] == "done":
                break
            time.sleep(0.2)
        assert s1.api(f"/api/jobs/{job}")["state"] == "done"
    finally:
        s1.stop()  # アプリを終わらせる

    s2 = _Server(db)  # 開き直す
    try:
        assert job in [j["id"] for j in s2.api("/api/jobs")]
        rep = s2.api(f"/api/jobs/{job}/report")
        assert rep["verdict"]["title"] == "個人情報の可能性あり"
        overview = {k: v for k, v in rep["overview"]}
        assert overview["列挙したファイル数"] == 3
        files = s2.api(f"/api/jobs/{job}/files?limit=500")
        meibo = next(r for r in files["rows"] if r["top_path"].endswith("名簿.txt"))
        assert meibo["types"].get("電話番号") == 1 or any("電話" in k for k in meibo["types"])
        items = s2.api(f"/api/jobs/{job}/all_items?limit=500")
        findings = s2.api(f"/api/jobs/{job}/findings?limit=500")
        attention = s2.api(f"/api/jobs/{job}/attention?limit=500")

        # Excel に書き出した5シートと、Web の API が同じ件数・同じ概要を返す
        from pii_checker.report import write_xlsx
        from pii_checker.store import Store

        out = tmp_path / "out.xlsx"
        write_xlsx(Store(db), job, str(out))
        wb = load_workbook(out, read_only=True)
        assert wb.sheetnames == ["判定", "要対応", "ファイル別", "前回との違い", "検出明細", "全項目"]
        diff = s2.api(f"/api/jobs/{job}/diff")
        assert diff["previous"] is None and "比べる前回の検査がありません" in diff["summary_text"]
        assert "比べる前回の検査がありません" in overview["前回との違い"]
        assert meibo["access"] in ("limited", "broad") and meibo["access_label"]
        rows_of = {name: list(wb[name].iter_rows(values_only=True))[1:] for name in wb.sheetnames[1:]}
        assert len(rows_of["要対応"]) == attention["total"]
        assert len(rows_of["ファイル別"]) == files["total"]
        assert len(rows_of["検出明細"]) == findings["total"]
        assert len(rows_of["全項目"]) == items["total"]
        excel_overview = {
            r[0]: r[1] for r in wb["判定"].iter_rows(values_only=True) if r and r[0] and len(r) > 1 and r[1] is not None
        }
        for k, v in overview.items():
            if k in ("出力日時",):
                continue
            assert str(excel_overview.get(k)) == str(v), k
    finally:
        s2.stop()

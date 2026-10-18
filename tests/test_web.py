"""Web 版（FastAPI）の結合試験。実際にサーバーを立てて API を叩く。

検体は make_corpus.py の部品で、その場の一時フォルダに5件だけ作る（Office・7-Zip は使わない）。
"""

from __future__ import annotations

import json
import socket
import struct
import sys
import threading
import time
import urllib.error
import urllib.request
import zipfile
import zlib
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

SAMPLES = [
    "excel/meibo.xlsx",
    "clean/orders.docx",
    "archive/zipcrypto_password.zip",
    "encrypted/password.xlsx",
    "pdf/encrypted_password.pdf",
]
TOKEN = "test-token-123"


def _zipcrypto_zip(name: str, data: bytes, password: str) -> bytes:
    """中身1件を ZipCrypto（従来の PKWARE 暗号）・無圧縮で格納した zip を作る。

    標準の zipfile は暗号化して書けないため、ヘッダーを手で組む。
    """
    crc_table = []  # CRC32（多項式 0xEDB88320）の1バイト分の表
    for i in range(256):
        v = i
        for _ in range(8):
            v = (v >> 1) ^ 0xEDB88320 if v & 1 else v >> 1
        crc_table.append(v)

    def crc_byte(crc: int, b: int) -> int:
        return (crc >> 8) ^ crc_table[(crc ^ b) & 0xFF]

    keys = [0x12345678, 0x23456789, 0x34567890]

    def update(b: int) -> None:
        keys[0] = crc_byte(keys[0], b)
        keys[1] = ((keys[1] + (keys[0] & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        keys[2] = crc_byte(keys[2], (keys[1] >> 24) & 0xFF)

    for b in password.encode():
        update(b)
    crc = zlib.crc32(data)
    plain = bytes(range(11)) + bytes([crc >> 24]) + data  # 暗号ヘッダーの末尾は CRC の上位バイト（照合用）
    out = bytearray()
    for b in plain:
        t = (keys[2] | 2) & 0xFFFF
        out.append(b ^ (((t * (t ^ 1)) >> 8) & 0xFF))
        update(b)
    fname = name.encode()
    fixed = struct.pack("<HHHHHIII", 20, 1, 0, 0, 0x21, crc, len(out), len(data))  # 版・暗号の印・無圧縮・日時
    local = b"PK\x03\x04" + fixed + struct.pack("<HH", len(fname), 0) + fname + bytes(out)
    central = (
        b"PK\x01\x02" + struct.pack("<H", 20) + fixed + struct.pack("<HHHHHII", len(fname), 0, 0, 0, 0, 0, 0) + fname
    )
    end = b"PK\x05\x06" + struct.pack("<HHHHIIH", 0, 0, 1, 1, len(central), len(local), 0)
    return local + central + end


def _make_samples(target: Path, work: Path) -> None:
    """SAMPLES の5件を target の下に作る。"""
    import docx
    import pymupdf

    import make_corpus as mc

    c = mc.Corpus(target, work)
    for rel in SAMPLES:
        (target / rel).parent.mkdir(parents=True, exist_ok=True)
    xlsx = c.xlsx_bytes()
    (target / "excel/meibo.xlsx").write_bytes(xlsx)
    d = docx.Document()
    for line in mc.clean_text().splitlines():
        d.add_paragraph(line)
    d.save(target / "clean/orders.docx")
    (target / "archive/zipcrypto_password.zip").write_bytes(_zipcrypto_zip("meibo.xlsx", xlsx, mc.PASSWORD))
    (target / "encrypted/password.xlsx").write_bytes(mc.encrypt_ooxml(xlsx, mc.PASSWORD))
    doc = pymupdf.open()
    mc._pdf_text_page(doc, mc.pii_text())
    doc.save(
        target / "pdf/encrypted_password.pdf",
        encryption=pymupdf.PDF_ENCRYPT_AES_256,
        owner_pw="owner-secret-999",
        user_pw=mc.PASSWORD,
    )
    doc.close()


def test_zipcrypto_sample_is_really_encrypted(tmp_path):
    """手で組んだ ZipCrypto の zip が、正しいパスワードでだけ元に戻ること（検体そのものの確かめ）。"""
    data = "山田太郎 090-1234-5678".encode() * 50
    path = tmp_path / "a.zip"
    path.write_bytes(_zipcrypto_zip("a.txt", data, "secret123"))
    with zipfile.ZipFile(path) as zf:
        assert zf.infolist()[0].flag_bits & 1
        with pytest.raises(RuntimeError):
            zf.read("a.txt")
        assert zf.read("a.txt", pwd=b"secret123") == data
        with pytest.raises(RuntimeError):
            zf.read("a.txt", pwd=b"wrong")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    import uvicorn

    from pii_checker.web.server import create_app

    work = tmp_path_factory.mktemp("web")
    target = work / "共有フォルダ"
    scratch = work / "作業"
    scratch.mkdir()
    _make_samples(target, scratch)
    app = create_app(db=str(work / "jobs.sqlite3"), token=TOKEN)
    port = _free_port()
    srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    th = threading.Thread(target=srv.run, daemon=True)
    th.start()
    for _ in range(100):
        if srv.started:
            break
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}", target
    srv.should_exit = True
    th.join(timeout=10)


def call(base, path, method="GET", body=None, token=TOKEN, xrw=True, host=None):
    headers = {}
    if token:
        headers["X-Token"] = token
    if method != "GET" and xrw:
        headers["X-Requested-With"] = "pii-checker"
    if body is not None:
        headers["Content-Type"] = "application/json"
    if host:
        headers["Host"] = host
    req = urllib.request.Request(
        base + path,
        data=json.dumps(body).encode() if body is not None else None,
        method=method,
        headers=headers,
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()


def wait_done(base, job_id, limit=180):
    for _ in range(limit * 2):
        st, _, data = call(base, f"/api/jobs/{job_id}")
        j = json.loads(data)
        if not j["running"] and j["state"] in ("done", "error", "cancelled"):
            return j
        time.sleep(0.5)
    raise AssertionError("検査が終わらない")


def test_guards(server):
    base, _ = server
    assert call(base, "/")[0] == 200
    assert call(base, "/api/info", token=None)[0] == 401
    assert call(base, "/api/info", token="wrong")[0] == 401
    assert call(base, "/api/info", host="evil.example.com")[0] == 403
    assert call(base, "/api/jobs", "POST", {"roots": ["C:/"]}, xrw=False)[0] == 403
    st, _, data = call(base, "/api/info")
    assert st == 200 and "pii_types" in json.loads(data)


def test_bad_root_is_rejected_with_message(server):
    base, _ = server
    st, _, data = call(base, "/api/jobs", "POST", {"roots": ["Z:/存在しないフォルダ"]})
    assert st == 400 and "見つからない" in json.loads(data)["detail"]


def test_scan_password_and_reports(server):
    base, target = server
    st, _, data = call(base, "/api/jobs", "POST", {"roots": [str(target)], "options": {"workers": 2}})
    assert st == 200, data
    job_id = json.loads(data)["id"]
    j = wait_done(base, job_id)
    s = j["summary"]
    assert s["files_total"] == len(SAMPLES) and s["files_done"] == len(SAMPLES)
    assert s["password_files"] == 3, s
    assert j["verdict"]["level"] == "found" and j["verdict"]["next_step"]
    assert j["phase"] == "完了" and j["attention_total"] == 3

    # パスワードを1回入れると、要パスワードの全件に試される
    st, _, data = call(base, f"/api/jobs/{job_id}/passwords", "POST", {"password": "secret123"})
    assert st == 200 and json.loads(data)["requeued"] == 3
    j = wait_done(base, job_id)
    assert j["summary"]["password_files"] == 0, j["summary"]
    pr = j["password_result"]
    assert pr["targets"] == 3 and pr["opened"] == 3 and pr["still"] == 0 and not pr["rechecking"], pr
    assert j["summary"]["item_status"].get("needs_password", 0) == 0

    st, _, data = call(base, f"/api/jobs/{job_id}/attention")
    assert st == 200
    st, _, data = call(base, f"/api/jobs/{job_id}/files?only_findings=true")
    files = json.loads(data)
    assert files["total"] >= 4
    top = files["rows"][0]["top_path"]
    st, _, data = call(base, "/api/jobs/" + job_id + "/items?top_path=" + urllib.request.quote(top))
    assert st == 200 and json.loads(data)
    st, _, data = call(base, f"/api/jobs/{job_id}/findings?confidence=high")
    f = json.loads(data)
    assert f["total"] > 0
    raw = json.dumps(f, ensure_ascii=False)
    assert "taro.yamada@example.jp" not in raw and "090-1234-5678" not in raw  # 生の値が出ていない

    st, headers, data = call(base, f"/api/jobs/{job_id}/report.xlsx?token={TOKEN}", token=None)
    assert st == 200 and data[:2] == b"PK" and len(data) > 5000
    st, headers, data = call(base, f"/api/jobs/{job_id}/findings.csv")
    assert st == 200 and data.startswith(b"\xef\xbb\xbf")

    # 実行中でなければ削除できる
    st, _, _ = call(base, f"/api/jobs/{job_id}", "DELETE")
    assert st == 200
    assert call(base, f"/api/jobs/{job_id}")[0] == 404


def test_empty_folder_is_not_declared_clean(server, tmp_path):
    """空のフォルダで「検出なし」と言い切らない（場所の指定違い・権限で見えないフォルダを見落とさない）。"""
    base, _ = server
    empty = tmp_path / "空のフォルダ"
    empty.mkdir()
    st, _, data = call(base, "/api/jobs", "POST", {"roots": [str(empty)]})
    assert st == 200
    j = wait_done(base, json.loads(data)["id"])
    assert j["verdict"]["level"] == "empty" and not j["verdict"]["can_declare_clean"]
    assert "アクセス権" in j["verdict"]["next_step"]

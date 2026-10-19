"""SQL のダンプを1行ずつ読む作り（巨大なダンプでも全文をメモリに載せず、列名つきの読み方を保つ）の試験。"""

from __future__ import annotations

from pii_checker import engine
from pii_checker.formats import misc
from pii_checker.models import ScanOptions, Status

# 列名だけが手がかりになる値（見出しが無ければ拾えない・確度が下がる形）を混ぜる
SQL = """-- 架空のデータ
CREATE TABLE `customers` (
  `id` int NOT NULL,
  `氏名` varchar(100),
  `電話番号` varchar(20),
  `生年月日` varchar(20),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB;
INSERT INTO `customers` VALUES (1,'山田 太郎','090-1234-5678','1980/01/02'),(2,'佐藤 花子','090-2222-3333','1975/03/04');
INSERT INTO `customers` (`id`,`氏名`,`電話番号`,`生年月日`) VALUES
(3,'鈴木 一郎','090-4444-5555','1990/05/06'),
(4,'高橋 二郎','090-6666-7777','1985/07/08');
COPY public.members (id, name, phone, birth) FROM stdin;
5\t田中 三郎\t090-8888-9999\t1970-09-10
6\t伊藤 四郎\t\\N\t1960-11-12
\\.
-- おわり 携帯 090-1111-0000
"""


def _scan(tmp_path, name, text):
    p = tmp_path / name
    p.write_bytes(text.encode("utf-8"))
    return engine.scan_file(str(p), ScanOptions(temp_dir=str(tmp_path)))


def _summary(res):
    it = res.items[0]
    locs = sorted(f.location for f in it.findings)
    return it.status, dict(it.finding_counts), dict(it.conf_counts), locs


def test_streaming_sql_matches_in_memory(tmp_path, monkeypatch):
    """丸ごと読む上限を超えて少しずつ読んでも、丸ごと読んだときと同じ種類・件数・確度・場所で拾う。"""
    whole = _scan(tmp_path, "a.sql", SQL)
    assert "SQL として読み取り（COPY 1 件・INSERT 2 文" in whole.items[0].method
    monkeypatch.setattr(misc, "TEXT_READ_ALL_LIMIT", 10)
    streamed = _scan(tmp_path, "b.sql", SQL)
    assert "巨大な SQL" in streamed.items[0].method
    assert "SQL として読み取り（COPY 1 件・INSERT 2 文" in streamed.items[0].method
    assert _summary(streamed) == _summary(whole)
    status, counts, _, locs = _summary(streamed)
    assert status == Status.SCANNED
    assert counts.get("phone", 0) >= 6 and counts.get("name", 0) >= 5
    # 列名の無い INSERT にも CREATE TABLE の列名が付く・COPY の行番号は元のファイルの行
    assert "表「customers」INSERT（9行目〜）1件目 列「電話番号」" in locs  # 列名の無い INSERT
    assert "表「customers」INSERT（10行目〜）1件目 列「電話番号」" in locs
    assert "表「public.members」データ1行目（14行目） 列「phone」" in locs


def test_streaming_sql_without_extension_and_crlf(tmp_path, monkeypatch):
    """拡張子が .txt でも中身で SQL と見分け、改行が CRLF でも同じに読む。"""
    monkeypatch.setattr(misc, "TEXT_READ_ALL_LIMIT", 10)
    res = _scan(tmp_path, "dump.txt", SQL.replace("\n", "\r\n"))
    assert "巨大な SQL" in res.items[0].method
    status, counts, _, _ = _summary(res)
    assert status == Status.SCANNED and counts.get("phone", 0) >= 6


def test_huge_text_does_not_split_line_at_sample_end(tmp_path, monkeypatch):
    """少しずつ読むとき、最初の見本（1MB）の終わりで行を2つに割らない（値が割れて拾えなくなっていた）。"""
    monkeypatch.setattr(misc, "TEXT_READ_ALL_LIMIT", 10)
    filler = "あいうえおかきくけこ\n" * 40000  # 先頭の見本 1MB をまたぐ長さ
    pad = 1024 * 1024 - len(filler) - len("携帯 090-12")
    text = filler + "x" * pad + "携帯 090-1234-5678\n" + "おわり\n"
    res = _scan(tmp_path, "big.txt", text)
    assert res.items[0].finding_counts.get("phone", 0) == 1

"""検査の速さの試験（tools/bench_scan.py の決まった材料で測る）。

ふだんの試験では、小さな材料で「どの形式も検査でき、仕込んだ値を見つけ、1ファイルが遅すぎない」ことを確かめる。
版どうしの比べ（速くなったか・遅くなったか）は、本番の大きさの材料で手元で測る:
  環境変数 PII_CHECKER_BENCH_BASELINE に基準の結果（bench_scan.py run の出力）、PII_CHECKER_BENCH_CORPUS に
  その材料のフォルダを置くと、今のコードで測り直して、合計の時間が基準の 1.2 倍を超えたら落とす。
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import bench_scan  # noqa: E402

# 小さな材料（scale 0.02）で1ファイルにかけてよい時間の上限（秒）。手元では 0.3 秒未満。CI の遅い runner でも通る幅
FILE_CEILING = 10.0
# 基準と比べるときに許す遅れ（合計の時間の比）
ALLOWED_RATIO = 1.2


@pytest.fixture(scope="module")
def small_result(tmp_path_factory):
    corpus = tmp_path_factory.mktemp("bench")
    bench_scan.make_corpus(corpus, scale=0.02)
    return bench_scan.run_bench(corpus, repeat=1)


def test_corpus_is_deterministic(tmp_path):
    """同じ scale なら毎回同じ中身（Office・PDF は作成日時が入るので、文字の材料だけを比べる）。"""
    a, b = tmp_path / "a", tmp_path / "b"
    made = bench_scan.make_corpus(a, scale=0.02)
    bench_scan.make_corpus(b, scale=0.02)
    plain = [n for n in made if n.endswith((".log", ".txt", ".csv", ".jsonl", ".gz", ".zip"))]
    assert len(plain) == 7
    for name in plain:
        assert (a / name).read_bytes() == (b / name).read_bytes(), name


def test_every_file_is_scanned(small_result):
    files = small_result["files"]
    assert set(files) == {
        "app.log",
        "notes.txt",
        "customers.csv",
        "numbers.csv",
        "events.jsonl",
        "app.log.gz",
        "export.zip",
        "customers.xlsx",
        "report.docx",
        "slides.pptx",
        "report.pdf",
        "customers.parquet",
    }
    for name, f in files.items():
        assert f["problems"] == [], name


@pytest.mark.parametrize("name", ["customers.csv", "export.zip", "customers.xlsx", "customers.parquet"])
def test_planted_values_are_found(small_result, name):
    """表の材料に仕込んだ6種類が、どれも見つかる（速くするために検出を落としていないこと）。"""
    kinds = {key.split(":", 1)[0] for key, v in small_result["files"][name]["counts"].items() if v}
    assert {"name", "address", "phone", "email", "my_number", "credit_card"} <= kinds


def test_no_file_is_too_slow(small_result):
    slow = {n: round(f["seconds"], 2) for n, f in small_result["files"].items() if f["seconds"] > FILE_CEILING}
    assert slow == {}


def test_compare_reports_ratio_and_count_diff(small_result):
    faster = json.loads(json.dumps(small_result))
    for f in faster["files"].values():
        f["seconds"] /= 2
    faster["total_seconds"] /= 2
    faster["files"]["app.log"]["counts"]["email:medium"] = (
        faster["files"]["app.log"]["counts"].get("email:medium", 0) + 3
    )
    lines, ratio = bench_scan.compare(small_result, faster)
    assert ratio == pytest.approx(0.5)
    assert any(line.startswith("app.log") and "email:medium +3" in line for line in lines)
    assert lines[-1].startswith("合計")


def test_compare_refuses_different_corpus(small_result):
    other = json.loads(json.dumps(small_result))
    other["corpus"]["scale"] = 1.0
    with pytest.raises(ValueError, match="材料が違う"):
        bench_scan.compare(small_result, other)


def test_compare_leaves_failed_files_out_of_total(small_result):
    """片方で検査できない項目のあるファイルは合計に入れない（失敗した側が速く見えないように）。"""
    broken = json.loads(json.dumps(small_result))
    broken["files"]["customers.csv"]["problems"] = ["customers.csv: uncheckable 壊れている"]
    broken["files"]["customers.csv"]["seconds"] = 0.0
    lines, ratio = bench_scan.compare(small_result, broken)
    assert ratio == pytest.approx(1.0)
    assert any(line.startswith("customers.csv") and "比べる側で検査できない" in line for line in lines)


def test_compare_warns_on_different_engine(small_result):
    other = json.loads(json.dumps(small_result))
    other["engine"] = "Python（Rust 拡張なし）"
    lines, _ = bench_scan.compare(small_result, other)
    assert any(line.startswith("！検出のエンジンが違います") for line in lines)


def test_compare_cli_explains_unreadable_result(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{", encoding="utf-8")
    assert bench_scan.main(["compare", str(tmp_path / "none.json"), str(bad)]) == 2
    assert "結果を読めません" in capsys.readouterr().err


def test_run_refuses_missing_corpus(tmp_path, capsys):
    assert bench_scan.main(["run", str(tmp_path), "-o", str(tmp_path / "r.json")]) == 2
    assert "先に make" in capsys.readouterr().err


@pytest.mark.skipif(
    not (os.environ.get("PII_CHECKER_BENCH_BASELINE") and os.environ.get("PII_CHECKER_BENCH_CORPUS")),
    reason="基準の結果と材料を環境変数で渡したときだけ測る（本番の大きさで数十秒かかる）",
)
def test_not_slower_than_baseline():
    base = json.loads(Path(os.environ["PII_CHECKER_BENCH_BASELINE"]).read_text(encoding="utf-8"))
    now = bench_scan.run_bench(Path(os.environ["PII_CHECKER_BENCH_CORPUS"]), repeat=base.get("repeat", 3))
    lines, ratio = bench_scan.compare(base, now)
    # 検査できなくなったファイルは合計から外れて速く見えるので、先に落とす
    assert {n: f["problems"] for n, f in now["files"].items() if f["problems"]} == {}
    assert ratio <= ALLOWED_RATIO, "\n".join(lines)

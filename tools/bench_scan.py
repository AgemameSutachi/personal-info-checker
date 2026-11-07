"""検査の速さを、決まった中身の材料で測って、版どうしを比べる道具。

大きな検査（ドライブ丸ごと）の時間は、その時の PC の混み具合（メモリの圧迫・ほかの重い処理）で大きく揺れ、
版の違いと切り分けられない。そこで、毎回同じ中身になる材料を作り、1つのプロセスで1ファイルずつ直列に
検査して、ファイルごとの時間（繰り返しの最小値）を測る。版を替えて同じ材料を測れば、違いはコードの差だけになる。
ほかの処理が CPU を使っている PC では、同じ版を2回測っても合計がずれる（docs/開発者向け.md の実測）。
最小値で比べ、版を交互に（A→B→A→B）測って、同じ版の2回のずれも見る。
同じプロセスで繰り返すので、覚え書き（短い本文のキャッシュ・lru_cache）は2回目から温まっている。最小値は温まった後の値。

使い方:
  python tools/bench_scan.py make <材料のフォルダ> [--scale 1.0]
      材料を作る（乱数の種は固定。同じ scale なら毎回同じ中身。個人情報はすべて架空）
  python tools/bench_scan.py run <材料のフォルダ> -o <結果.json> [--repeat 3] [--code <版のフォルダ>] [--ext-dir <拡張のフォルダ>]
      測る。--code は検査に使う pii_checker の置き場（git worktree で取り出した古い版など。省けばこのリポジトリ）。
      --ext-dir は Rust 拡張（pii_rs_detect の .pyd）を置いたフォルダ。古い版は拡張の規則も古いので、
      その版で組んだ拡張を wheel から取り出して渡す（venv の拡張は入れ替えない）。
  python tools/bench_scan.py ext <版のフォルダ> <展開先>
      その版の Rust 拡張を組んで wheel を展開する（run の --ext-dir に渡す。venv の拡張は入れ替えない）
  python tools/bench_scan.py compare <基準.json> <比べる.json>
      ファイルごと・合計の時間の比（比べる÷基準）と、検出の件数の差を並べる

測るときは、ほかの重い処理を止めてから直列に（並べて測ると互いに遅くなる）。
"""

from __future__ import annotations

import argparse
import gzip
import io
import json
import os
import platform
import random
import re
import statistics
import subprocess
import sys
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# 材料の乱数の種（変えると別の材料になり、前に測った結果と比べられなくなる）
SEED = 20261108
# 材料の版。作り方を変えたら上げる（違う版の材料で測った結果どうしは compare が断る）
# 2: docx・pptx の縮小画像を除いた（OCR の有無で結果が変わらないように）
CORPUS_VERSION = 2

SURNAMES = ["佐藤", "鈴木", "高橋", "田中", "伊藤", "渡辺", "山本", "中村", "小林", "加藤"]
GIVEN = ["太郎", "花子", "一郎", "美咲", "健司", "陽翔", "結衣", "蓮", "葵", "大輝"]
CITIES = ["東京都千代田区丸の内", "大阪府大阪市北区梅田", "愛知県名古屋市中区栄", "福岡県福岡市中央区天神"]
# 各ブランドが公開しているテスト用のカード番号
TEST_CARDS = ["4111111111111111", "5555555555554444", "378282246310005"]
WORDS = ["請求", "見積", "納品", "確認", "対応", "予定", "完了", "保留", "連絡", "資料", "会議", "変更"]


def my_number(rnd: random.Random) -> str:
    """検査数字だけ正しい架空のマイナンバー（12桁）。"""
    body = [rnd.randint(0, 9) for _ in range(11)]
    total = 0
    for n in range(1, 12):
        p = body[11 - n]
        q = n + 1 if n <= 6 else n - 5
        total += p * q
    r = total % 11
    check = 0 if r <= 1 else 11 - r
    return "".join(map(str, body)) + str(check)


def person(rnd: random.Random, i: int) -> dict:
    """架空の1人分。住所は実在しない番地（9-9-x）にする。"""
    return {
        "name": f"{rnd.choice(SURNAMES)} {rnd.choice(GIVEN)}",
        "address": f"{rnd.choice(CITIES)}9-9-{rnd.randint(1, 99)}",
        "phone": f"090-{rnd.randint(1000, 9999)}-{rnd.randint(1000, 9999)}",
        "email": f"user{i}@example.com",
        "my_number": my_number(rnd),
        "card": rnd.choice(TEST_CARDS),
    }


def noise_line(rnd: random.Random, i: int) -> str:
    """個人情報を含まない業務ログの1行（数字の並びを多く含めて、誤検出の判定の重さも測る）。"""
    return (
        f"2026-11-08 10:{i % 60:02d}:{rnd.randint(0, 59):02d} INFO job={rnd.randint(100000, 999999)} "
        f"{rnd.choice(WORDS)}{rnd.choice(WORDS)} id={rnd.getrandbits(48):012d} size={rnd.randint(0, 10**9)} "
        f"host=192.0.2.{rnd.randint(1, 254)} elapsed={rnd.random():.4f}"
    )


def _log_text(rnd: random.Random, n: int) -> str:
    lines = []
    for i in range(n):
        if i % 25 == 0:
            p = person(rnd, i)
            lines.append(f"2026-11-08 11:00:00 WARN 問い合わせ {p['name']}様 {p['phone']} {p['email']}")
        else:
            lines.append(noise_line(rnd, i))
    return "\n".join(lines) + "\n"


def _people_rows(rnd: random.Random, n: int) -> list[list[str]]:
    rows = [["氏名", "住所", "電話番号", "メールアドレス", "個人番号", "カード番号", "金額"]]
    for i in range(n):
        p = person(rnd, i)
        rows.append(
            [p["name"], p["address"], p["phone"], p["email"], p["my_number"], p["card"], str(rnd.randint(0, 10**7))]
        )
    return rows


def _numeric_rows(rnd: random.Random, n: int) -> list[list[str]]:
    """個人情報を含まない数字だけの表（12桁・16桁の値を含めて、誤検出を落とす判定の重さを測る）。"""
    rows = [["伝票番号", "品番", "数量", "単価", "計測値"]]
    for _ in range(n):
        rows.append(
            [
                f"{rnd.getrandbits(40):012d}",
                f"{rnd.getrandbits(53):016d}",
                str(rnd.randint(1, 999)),
                str(rnd.randint(100, 99999)),
                f"{rnd.random() * 1000:.3f}",
            ]
        )
    return rows


def _csv(rows: list[list[str]]) -> str:
    return "\n".join(",".join(r) for r in rows) + "\n"


def _doc_paragraphs(rnd: random.Random, n: int) -> list[str]:
    out = []
    for i in range(n):
        if i % 10 == 0:
            p = person(rnd, i)
            out.append(f"担当: {p['name']}（{p['phone']}）住所 {p['address']}")
        else:
            out.append("".join(rnd.choice(WORDS) for _ in range(20)) + "について確認しました。")
    return out


def _drop_thumbnail(data: bytes) -> bytes:
    """docx・pptx の zip から縮小画像（docProps/thumbnail.*）とその関係を除く。

    縮小画像は画像なので OCR に回り、日本語の OCR が無い環境（CI 等）では「検査できない」になって時間も件数も
    環境で変わる。材料は環境に依らず同じ処理を通るようにしたいので除く。
    """
    src = zipfile.ZipFile(io.BytesIO(data))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for info in src.infolist():
            if info.filename.startswith("docProps/thumbnail."):
                continue
            body = src.read(info)
            if info.filename == "_rels/.rels":
                body = re.sub(rb"<Relationship [^>]*Target=\"docProps/thumbnail\.[^\"]*\"[^>]*/>", b"", body)
            z.writestr(info, body, compress_type=zipfile.ZIP_DEFLATED)
    return buf.getvalue()


def make_corpus(out: Path, scale: float = 1.0) -> list[str]:
    """材料を out に作り、作ったファイルの名前を返す。scale は件数の倍率（試験では小さくする）。"""
    out.mkdir(parents=True, exist_ok=True)
    rnd = random.Random(SEED)

    def n(base: int) -> int:
        return max(5, int(base * scale))

    made: list[str] = []

    def put(name: str, data: bytes) -> None:
        (out / name).write_bytes(data)
        made.append(name)

    put("app.log", _log_text(rnd, n(40000)).encode("utf-8"))
    put("notes.txt", "\n".join(_doc_paragraphs(rnd, n(3000))).encode("utf-8"))
    put("customers.csv", _csv(_people_rows(rnd, n(20000))).encode("utf-8"))
    put("numbers.csv", _csv(_numeric_rows(rnd, n(30000))).encode("utf-8"))
    put(
        "events.jsonl",
        "\n".join(
            json.dumps(dict(zip(["name", "address", "phone", "email"], r[:4])), ensure_ascii=False)
            for r in _people_rows(rnd, n(8000))[1:]
        ).encode("utf-8"),
    )
    put("app.log.gz", gzip.compress(_log_text(rnd, n(20000)).encode("utf-8"), mtime=0))

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for k in range(4):
            info = zipfile.ZipInfo(f"export/part{k}.csv", date_time=(2026, 11, 8, 0, 0, 0))
            z.writestr(info, _csv(_people_rows(rnd, n(3000))), compress_type=zipfile.ZIP_DEFLATED)
        info = zipfile.ZipInfo("export/readme.txt", date_time=(2026, 11, 8, 0, 0, 0))
        z.writestr(info, "\n".join(_doc_paragraphs(rnd, n(500))), compress_type=zipfile.ZIP_DEFLATED)
    put("export.zip", buf.getvalue())

    import openpyxl

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "顧客"
    for r in _people_rows(rnd, n(5000)):
        ws.append(r)
    ws2 = wb.create_sheet("集計")
    for r in _numeric_rows(rnd, n(5000)):
        ws2.append(r)
    buf = io.BytesIO()
    wb.save(buf)
    put("customers.xlsx", buf.getvalue())

    import docx

    d = docx.Document()
    for para in _doc_paragraphs(rnd, n(1500)):
        d.add_paragraph(para)
    table = d.add_table(rows=0, cols=4)
    for r in _people_rows(rnd, n(200)):
        cells = table.add_row().cells
        for c, v in zip(cells, r[:4]):
            c.text = v
    buf = io.BytesIO()
    d.save(buf)
    put("report.docx", _drop_thumbnail(buf.getvalue()))

    import pptx

    pres = pptx.Presentation()
    paras = _doc_paragraphs(rnd, n(600))
    for k in range(0, len(paras), 10):
        slide = pres.slides.add_slide(pres.slide_layouts[1])
        slide.shapes.title.text = f"資料 {k // 10 + 1}"
        slide.placeholders[1].text = "\n".join(paras[k : k + 10])
    buf = io.BytesIO()
    pres.save(buf)
    put("slides.pptx", _drop_thumbnail(buf.getvalue()))

    import pymupdf

    pdf = pymupdf.open()
    paras = _doc_paragraphs(rnd, n(1200))
    for k in range(0, len(paras), 40):
        page = pdf.new_page()
        page.insert_text((40, 50), "\n".join(paras[k : k + 40]), fontname="japan", fontsize=9)
    put("report.pdf", pdf.tobytes(garbage=3, deflate=True))
    pdf.close()

    import pyarrow as pa
    import pyarrow.parquet as pq

    rows = _people_rows(rnd, n(30000))
    table = pa.table({h: [r[c] for r in rows[1:]] for c, h in enumerate(rows[0])})
    buf = io.BytesIO()
    pq.write_table(table, buf)
    put("customers.parquet", buf.getvalue())

    meta = {"corpus_version": CORPUS_VERSION, "seed": SEED, "scale": scale, "files": made}
    (out / "bench_corpus.json").write_text(json.dumps(meta, ensure_ascii=False, indent=1), encoding="utf-8")
    return made


def _describe_code(code: Path) -> str:
    """版のフォルダの git の版（取れなければ空）。"""
    try:
        r = subprocess.run(
            ["git", "-C", str(code), "describe", "--tags", "--always", "--dirty"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return r.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def run_bench(corpus: Path, repeat: int = 3) -> dict:
    """材料の各ファイルを、いま読み込める pii_checker で repeat 回ずつ直列に検査して時間を測る。

    1回目の前に、どのファイルにも当たらない小さな検査を1回して、読み込みの時間（拡張・部品の import）を除く。
    """
    from pii_checker import detectors
    from pii_checker.engine import scan_file
    from pii_checker.models import ScanOptions, Status

    meta = json.loads((corpus / "bench_corpus.json").read_text(encoding="utf-8"))
    options = ScanOptions()
    warm = corpus / "bench_corpus.json"
    scan_file(str(warm), options)

    files = {}
    for name in meta["files"]:
        path = corpus / name
        times = []
        result = None
        for _ in range(max(1, repeat)):
            t0 = time.perf_counter()
            result = scan_file(str(path), options)
            times.append(time.perf_counter() - t0)
        counts: dict[str, int] = {}
        bad = []
        for item in result.items:
            for key, v in item.conf_counts.items():
                counts[key] = counts.get(key, 0) + v
            if item.status not in (Status.SCANNED, Status.PARTIAL):
                bad.append(f"{item.path}: {item.status.value} {item.reason}")
        files[name] = {
            "kind": path.suffix.lstrip(".").lower() or "none",
            "size": path.stat().st_size,
            # 比べるのは最小値（ほかの処理に割り込まれた回ほど長くなるので、最小が一番コードの差に近い）
            "seconds": min(times),
            "median": statistics.median(times),
            "times": times,
            "items": len(result.items),
            "counts": counts,
            "problems": bad,
        }
    # 古い版に rust_status が無ければ、拡張を使っているかだけを書く
    if hasattr(detectors, "rust_status"):
        engine = detectors.rust_status()
    else:
        engine = "Rust 拡張" if getattr(detectors, "_RUST", None) is not None else "Python"
    import pii_checker

    return {
        "corpus": meta,
        "repeat": repeat,
        # どこから読み込んだか（--code・--ext-dir が効いたかの確かめ）
        "module": pii_checker.__file__,
        "ext_module": getattr(getattr(detectors, "_RUST", None), "__file__", ""),
        "python": platform.python_version(),
        "engine": engine,
        "files": files,
        "total_seconds": sum(f["seconds"] for f in files.values()),
    }


def compare(base: dict, new: dict) -> tuple[list[str], float]:
    """基準と比べる結果を並べた行と、合計の時間の比（比べる÷基準）を返す。材料が違えば ValueError。

    合計は、両方にあって両方とも問題なく検査できたファイルだけで出す（片方だけ失敗したファイルを入れると、
    失敗した側が速く見える）。検出のエンジン（Rust 拡張の有無）や Python の版が違えば、先頭に「！」の行で知らせる。
    """
    for key in ("corpus_version", "seed", "scale"):
        if base["corpus"].get(key) != new["corpus"].get(key):
            raise ValueError(
                f"材料が違うので比べられません（{key}: {base['corpus'].get(key)} と {new['corpus'].get(key)}）。同じ材料で測り直してください"
            )
    lines = [f"基準: {base.get('code_version') or '?'} / 比べる: {new.get('code_version') or '?'}"]
    for key, label in (("engine", "検出のエンジン"), ("python", "Python の版")):
        if base.get(key) != new.get(key):
            lines.append(
                f"！{label}が違います（{base.get(key)} と {new.get(key)}）。コードの差だけを比べるなら、--ext-dir などをそろえて測り直してください"
            )
    lines.append(f"{'ファイル':<20}{'基準(秒)':>10}{'比べる(秒)':>12}{'比':>8}  検出の差")
    base_total = new_total = 0.0
    for name, b in base["files"].items():
        nw = new["files"].get(name)
        if nw is None:
            lines.append(f"{name:<20}{b['seconds']:>10.3f}{'-':>12}{'-':>8}  比べる側に無い（合計に入れない）")
            continue
        if b["problems"] or nw["problems"]:
            side = "両方" if b["problems"] and nw["problems"] else ("基準" if b["problems"] else "比べる側")
            lines.append(
                f"{name:<20}{b['seconds']:>10.3f}{nw['seconds']:>12.3f}{'-':>8}  {side}で検査できない項目がある（合計に入れない）"
            )
            continue
        base_total += b["seconds"]
        new_total += nw["seconds"]
        ratio = nw["seconds"] / b["seconds"] if b["seconds"] > 0 else float("inf")
        diffs = []
        for key in sorted(set(b["counts"]) | set(nw["counts"])):
            d = nw["counts"].get(key, 0) - b["counts"].get(key, 0)
            if d:
                diffs.append(f"{key} {d:+d}")
        lines.append(
            f"{name:<20}{b['seconds']:>10.3f}{nw['seconds']:>12.3f}{ratio:>8.2f}  {', '.join(diffs) or '同じ'}"
        )
    for name in sorted(new["files"].keys() - base["files"].keys()):
        lines.append(f"{name:<20}{'-':>10}{new['files'][name]['seconds']:>12.3f}{'-':>8}  基準に無い（合計に入れない）")
    total = new_total / base_total if base_total > 0 else float("inf")
    lines.append(f"{'合計':<20}{base_total:>10.3f}{new_total:>12.3f}{total:>8.2f}")
    return lines, total


def build_ext(code: Path, out: Path) -> Path:
    """版のフォルダの Rust 拡張を組み、wheel を out へ展開して、その置き場を返す（venv には入れない）。

    cargo と maturin が要る。cargo の作業場は CARGO_TARGET_DIR があればそこ（パスが長いと link.exe が落ちるので、
    深い所の worktree なら短い場所を指す）、無ければ版のフォルダの rust/pii_rs_detect/target。
    """
    import shutil

    crate = code.resolve() / "rust" / "pii_rs_detect"
    if not (crate / "Cargo.toml").is_file():
        raise SystemExit(f"この版には Rust 拡張がありません: {crate}")
    # 数分かかる build の前に、展開先を確かめる
    if out.exists() and any(out.iterdir()):
        raise SystemExit(f"展開先が空ではありません: {out}（新しいフォルダを指定してください）")
    target = Path(os.environ.get("CARGO_TARGET_DIR") or crate / "target")
    wheels = target / "wheels"
    for old in wheels.glob("pii_rs_detect-*.whl"):
        old.unlink()  # 前に組んだ別の版を拾わないように
    cmd = [sys.executable, "-m", "maturin", "build", "--release", "-m", str(crate / "Cargo.toml"), "-i", sys.executable]
    if subprocess.run(cmd).returncode != 0:
        raise SystemExit("maturin build が失敗しました（cargo と maturin が入っているか確かめてください）")
    found = sorted(wheels.glob("pii_rs_detect-*.whl"), key=lambda p: p.stat().st_mtime)
    if not found:
        raise SystemExit(f"wheel が見つかりません: {wheels}")
    out.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(found[-1]) as z:
        z.extractall(out)
    shutil.copy2(found[-1], out / found[-1].name)
    return out


def _use_code(code: Path | None, ext_dir: Path | None) -> Path:
    """検査に使う pii_checker と拡張の置き場を、import の先頭に置く。"""
    code = (code or ROOT).resolve()
    if not (code / "pii_checker" / "__init__.py").is_file():
        raise SystemExit(f"pii_checker が見つかりません: {code}（--code にはリポジトリの最上位を渡してください）")
    sys.path.insert(0, str(code))
    if ext_dir is not None:
        if not any(ext_dir.glob("pii_rs_detect*")):
            raise SystemExit(
                f"--ext-dir に pii_rs_detect が見つかりません: {ext_dir}（wheel を展開したフォルダを渡してください）"
            )
        sys.path.insert(0, str(ext_dir.resolve()))
    return code


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="検査の速さを決まった材料で測って版どうしを比べる")
    sub = ap.add_subparsers(dest="cmd", required=True)
    mk = sub.add_parser("make", help="材料を作る")
    mk.add_argument("corpus")
    mk.add_argument(
        "--scale", type=float, default=1.0, help="件数の倍率（既定 1.0。違う倍率の結果どうしは比べられない）"
    )
    rn = sub.add_parser("run", help="測る")
    rn.add_argument("corpus")
    rn.add_argument("-o", "--output", required=True, help="結果の JSON の書き出し先")
    rn.add_argument("--repeat", type=int, default=3, help="1ファイルを何回測るか（最小値で比べる。既定 3）")
    rn.add_argument("--code", type=Path, help="検査に使う版のリポジトリの最上位（省けばこのリポジトリ）")
    rn.add_argument("--ext-dir", type=Path, help="ext で展開したその版の Rust 拡張のフォルダ")
    ex = sub.add_parser("ext", help="版のフォルダの Rust 拡張を組んで展開する（venv には入れない）")
    ex.add_argument("code", type=Path)
    ex.add_argument("out", type=Path)
    cp = sub.add_parser("compare", help="2つの結果を比べる")
    cp.add_argument("base")
    cp.add_argument("new")
    args = ap.parse_args(argv)

    if args.cmd == "make":
        made = make_corpus(Path(args.corpus), args.scale)
        print(f"材料を {len(made)} 件作りました: {args.corpus}")
        return 0
    if args.cmd == "ext":
        print(f"拡張を展開しました: {build_ext(args.code, args.out)}（run の --ext-dir に渡してください）")
        return 0
    if args.cmd == "run":
        corpus = Path(args.corpus)
        if not (corpus / "bench_corpus.json").is_file():
            print(f"材料が見つかりません: {corpus}（先に make で作ってください）", file=sys.stderr)
            return 2
        output = Path(args.output)
        if not output.parent.is_dir():
            print(f"結果の書き出し先のフォルダがありません: {output.parent}", file=sys.stderr)
            return 2
        code = _use_code(args.code, args.ext_dir)
        result = run_bench(corpus, args.repeat)
        result["code_version"] = _describe_code(code)
        output.write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
        for name, f in result["files"].items():
            mark = "  ！" + "; ".join(f["problems"]) if f["problems"] else ""
            print(f"{name:<20}{f['seconds']:>9.3f} 秒{mark}")
        print(f"合計 {result['total_seconds']:.3f} 秒（{result['engine']}・{result['code_version']}）")
        return 0
    loaded = []
    for path in (args.base, args.new):
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            if not isinstance(data, dict) or not {"corpus", "files"} <= data.keys():
                raise ValueError("run の結果の形ではありません")
        except (OSError, ValueError) as exc:
            print(f"結果を読めません: {path}（{exc}）。run -o で書き出した JSON を渡してください", file=sys.stderr)
            return 2
        loaded.append(data)
    try:
        lines, _ = compare(*loaded)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())

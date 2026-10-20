"""Docker の Linux コンテナで、Windows だけでは作れない試験用検体を作る。

作るもの:
  - ディスク・OS イメージ（FAT32・ext4・MBR 生ディスク・vhdx/vhd/vmdk/qcow2/vdi・iso・wim・squashfs）
  - Linux 系の圧縮・アーカイブ（tar.zst/tar.lz4/tar.xz/tar.bz2/tgz/.Z/.lz/cpio/deb/rpm）
  - PostgreSQL のダンプ各形式とデータフォルダ一式
  - MariaDB の mysqldump
  - Oracle の expdp（Data Pump）ダンプ（使えれば旧 exp も）
  - 対照（個人情報なし）の ext4 イメージと pg_dump

PostgreSQL と MariaDB のコンテナは、ダンプを取り終えたら外す（このツールは DB へ接続しないので残さない）。

個人情報はすべて架空。値は tests/make_corpus.py の検体と同じ。

使い方:
  python tests/make_corpus_docker.py <出力先> [--corpus <既存検体フォルダ>]

  --corpus には tests/make_corpus.py が作った検体フォルダを渡す
  （word/body.docx と excel/meibo.xlsx をイメージの中身として流用する）。
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

# Docker CLI の場所（Docker Desktop 既定）
DOCKER = r"C:\Program Files\Docker\Docker\resources\bin\docker.exe"

# 使うイメージ
TOOLS_IMAGE = "debian:bookworm"
PG_IMAGE = "postgres:16"
MARIADB_IMAGE = "mariadb:11"
ORACLE_IMAGES = ["gvenzl/oracle-xe:21-slim-faststart", "gvenzl/oracle-free:slim"]

# 自分が作るコンテナの名前（すべて piichk- で始める）
TOOLS_CONTAINER = "piichk-tools"
PG_LIVE = "piichk-pg"
PG_DATA = "piichk-pgdata"
PG_TAR = "piichk-pgtar"
MARIADB_LIVE = "piichk-mariadb"
ORACLE_CONTAINER = "piichk-ora"

# 試験用の架空の認証情報（本物の秘密ではない）
DB_USER = "piichk"
DB_PASSWORD = "piichk-test-pw"
DB_NAME = "piichk"
ORACLE_SYS_PASSWORD = "PiichkSys1"

ALL_KINDS = [
    "name",
    "address",
    "postal_code",
    "phone",
    "email",
    "birthdate",
    "my_number",
    "bank_account",
    "credit_card",
]

# 架空の人物（tests/make_corpus.py と同じ値）
PEOPLE = [
    {
        "id": 1,
        "name": "山田 太郎",
        "kana": "ヤマダ タロウ",
        "postal": "〒100-0005",
        "address": "東京都千代田区丸の内1-2-3",
        "phone": "03-1234-5678",
        "mobile": "090-1234-5678",
        "email": "taro.yamada@example.jp",
        "birth": "1985年4月1日",
        "birth_iso": "1985-04-01",
        "my_number": "123456789018",
        "bank": "サンプル銀行 丸の内支店 普通 1234567",
        "account_no": "1234567",
        "card": "4111 1111 1111 1111",
        "limit": 500000,
    },
    {
        "id": 2,
        "name": "佐藤 花子",
        "kana": "サトウ ハナコ",
        "postal": "〒530-0001",
        "address": "大阪府大阪市北区梅田9-8-7",
        "phone": "06-9876-5432",
        "mobile": "080-9876-5432",
        "email": "hanako.sato@example.com",
        "birth": "1990年12月24日",
        "birth_iso": "1990-12-24",
        "my_number": "987654321093",
        "bank": "サンプル銀行 梅田支店 普通 7654321",
        "account_no": "7654321",
        "card": "5555 5555 5555 4444",
        "limit": 300000,
    },
    {
        "id": 3,
        "name": "鈴木 一郎",
        "kana": "スズキ イチロウ",
        "postal": "〒220-0012",
        "address": "神奈川県横浜市西区みなとみらい4-5-6",
        "phone": "045-123-4567",
        "mobile": "070-1111-2222",
        "email": "ichiro.suzuki@example.net",
        "birth": "1978年7月7日",
        "birth_iso": "1978-07-07",
        "my_number": "246813579021",
        "bank": "サンプル銀行 横浜支店 当座 2468135",
        "account_no": "2468135",
        "card": "3530 1113 3330 0000",
        "limit": 800000,
    },
]

# 対照用の商品マスタ（個人情報なし）
PRODUCTS = [
    (1, "ボールペン 黒", 120, "文房具"),
    (2, "A4 コピー用紙 500枚", 480, "用紙"),
    (3, "ホッチキス 針 1000本", 150, "文房具"),
]


class Corpus:
    """生成物の記録（manifest.json）を持ち、途中経過を随時書き出す。"""

    def __init__(self, out: Path) -> None:
        self.out = out
        self.work = out / "_work"
        self.work.mkdir(parents=True, exist_ok=True)
        self.log_path = self.work / "run.log"
        self.manifest_path = out / "manifest.json"
        self.entries: list[dict] = []
        self.images_used: list[str] = []

    def log(self, text: str) -> None:
        """実行ログへ追記する（標準出力にも出す）。"""
        stamp = dt.datetime.now().strftime("%H:%M:%S")
        line = f"[{stamp}] {text}"
        print(line, flush=True)
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")

    def add(
        self,
        path: str,
        expect: str,
        fmt: str,
        kinds: list[str] | None = None,
        note: str = "",
        skipped: str = "",
    ) -> None:
        """manifest に1件足す。外側のファイルが無ければ skipped を自動で付ける。"""
        if kinds is None:
            kinds = list(ALL_KINDS) if expect in ("detect", "partial") else []
        entry: dict = {"path": path, "expect": expect, "kinds": kinds, "format": fmt}
        if note:
            entry["note"] = note
        outer = self.out / path.split("!")[0]
        if not skipped and not outer.exists():
            skipped = "生成に失敗した（_work/run.log・_work/tools.log を参照）"
        if skipped:
            entry["skipped"] = skipped
        self.entries.append(entry)
        self.save()

    def save(self) -> None:
        """manifest.json を書き出す（打ち切られても途中まで残るように毎回書く）。"""
        data = {
            "generated_at": dt.datetime.now().isoformat(timespec="seconds"),
            "generator": "tests/make_corpus_docker.py",
            "people": PEOPLE,
            "images": self.images_used,
            "entries": self.entries,
            "skipped": [e for e in self.entries if "skipped" in e],
        }
        tmp = self.manifest_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), "utf-8")
        tmp.replace(self.manifest_path)


# ---------------------------------------------------------------- Docker 操作


def docker(
    corpus: Corpus,
    args: list[str],
    stdin: bytes | None = None,
    check: bool = True,
    timeout: int = 1800,
    quiet: bool = False,
) -> subprocess.CompletedProcess:
    """docker CLI を呼ぶ。出力はバイト列で返し、ログへも残す。"""
    if not quiet:
        corpus.log("docker " + " ".join(args)[:300])
    proc = subprocess.run(
        [DOCKER, *args],
        input=stdin,
        capture_output=True,
        timeout=timeout,
    )
    if not quiet or proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip()
        if err:
            corpus.log("  stderr: " + err[-2000:])
    if check and proc.returncode != 0:
        raise RuntimeError(f"docker {' '.join(args[:3])} が終了コード {proc.returncode} で失敗しました")
    return proc


def remove_container(corpus: Corpus, name: str, volumes: bool = True) -> None:
    """自分が作ったコンテナ（piichk-*）を止めて消す。匿名ボリュームも消す。"""
    assert name.startswith("piichk-"), "自分のコンテナ以外は消さない"
    flags = ["rm", "-f", "-v", name] if volumes else ["rm", "-f", name]
    docker(corpus, flags, check=False, quiet=True)


def image_exists(corpus: Corpus, image: str) -> bool:
    """ローカルにイメージがあるか。"""
    proc = docker(corpus, ["image", "inspect", image], check=False, quiet=True)
    return proc.returncode == 0


def free_port(preferred: int) -> int:
    """127.0.0.1 で空いているポートを preferred から順に探す。"""
    for port in range(preferred, preferred + 50):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RuntimeError(f"{preferred} 付近に空きポートがありません")


def wait_until(corpus: Corpus, probe, tries: int = 60, interval: float = 1.0) -> bool:
    """probe() が真になるまで有限回だけ試す（無限待ちはしない）。"""
    for _ in range(tries):
        if probe():
            return True
        time.sleep(interval)
    return False


# ---------------------------------------------------------------- 中身の用意


def meibo_csv() -> str:
    """表形式（見出し＋3行）の CSV 本文。"""
    header = [
        "氏名",
        "フリガナ",
        "郵便番号",
        "住所",
        "電話番号",
        "携帯電話",
        "メールアドレス",
        "生年月日",
        "マイナンバー",
        "口座",
        "クレジットカード",
    ]
    rows = [",".join(header)]
    for p in PEOPLE:
        rows.append(
            ",".join(
                [
                    p["name"],
                    p["kana"],
                    p["postal"],
                    p["address"],
                    p["phone"],
                    p["mobile"],
                    p["email"],
                    p["birth"],
                    p["my_number"],
                    p["bank"],
                    p["card"],
                ]
            )
        )
    return "\n".join(rows) + "\n"


def products_csv() -> str:
    """対照用の商品マスタ CSV。"""
    rows = ["商品番号,商品名,単価,分類"]
    rows += [f"{a},{b},{c},{d}" for a, b, c, d in PRODUCTS]
    return "\n".join(rows) + "\n"


README_TEXT = "このフォルダは個人情報チェッカーの試験用検体です。\n"


def prepare_sources(corpus: Corpus, existing: Path | None) -> dict[str, bool]:
    """イメージの中身にするファイルを _work/src と _work/clean に置く。"""
    src = corpus.work / "src"
    clean = corpus.work / "clean"
    for d in (src, clean):
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True)
    (src / "meibo.csv").write_text(meibo_csv(), "utf-8", newline="\n")
    (src / "個人情報名簿.csv").write_text(meibo_csv(), "utf-8", newline="\n")
    (src / "readme.txt").write_text(README_TEXT, "utf-8", newline="\n")
    (clean / "products.csv").write_text(products_csv(), "utf-8", newline="\n")
    (clean / "readme.txt").write_text(README_TEXT, "utf-8", newline="\n")
    have = {"docx": False, "xlsx": False}
    if existing:
        for key, rel in (("docx", "word/body.docx"), ("xlsx", "excel/meibo.xlsx")):
            p = existing / rel
            if p.exists():
                shutil.copy2(p, src / p.name)
                have[key] = True
    corpus.log(f"中身を用意しました（docx={have['docx']} xlsx={have['xlsx']}）")
    return have


# ---------------------------------------------------------------- ツール用コンテナ

TOOLS_SCRIPT = r"""#!/bin/bash
# ツール用コンテナの中で走る。各段の成否を /out/_work/status.txt に書く。
set -u
export DEBIAN_FRONTEND=noninteractive
export LANG=C.UTF-8
export MTOOLS_SKIP_CHECK=1
LOG=/out/_work/tools.log
ST=/out/_work/status.txt
: > "$ST"
S=/out/_work/src
C=/out/_work/clean
W=/tmp/w
mkdir -p "$W" /out/disk /out/linux_archive /out/clean

step() {
  local name=$1; shift
  echo "=== $name" >> "$LOG"
  if "$@" >> "$LOG" 2>&1; then echo "OK $name" >> "$ST"; else echo "NG $name" >> "$ST"; fi
}

install_tools() {
  apt-get update -qq && apt-get install -y -qq --no-install-recommends \
    dosfstools mtools e2fsprogs fdisk qemu-utils xorriso wimtools \
    squashfs-tools zstd lz4 xz-utils bzip2 ncompress lzip cpio dpkg-dev rpm
}

fat32() {
  rm -f /out/disk/fat32.img
  truncate -s 40M /out/disk/fat32.img
  mkfs.vfat -F 32 -n PIICHK /out/disk/fat32.img
  mcopy -i /out/disk/fat32.img "$S/meibo.csv" "$S/readme.txt" ::/
  for f in body.docx meibo.xlsx; do
    if [ -f "$S/$f" ]; then mcopy -i /out/disk/fat32.img "$S/$f" ::/; fi
  done
  mdir -i /out/disk/fat32.img ::/
}

ext4() {
  rm -f /out/disk/ext4.img
  mkfs.ext4 -q -F -L piichk -d "$S" /out/disk/ext4.img 16M
}

ext4_clean() {
  rm -f /out/clean/ext4_clean.img
  mkfs.ext4 -q -F -L clean -d "$C" /out/clean/ext4_clean.img 8M
}

mbr_disk() {
  rm -f /out/disk/disk_mbr.img "$W/part.img"
  truncate -s 64M /out/disk/disk_mbr.img
  printf 'label: dos\nstart=2048, type=c\n' | sfdisk /out/disk/disk_mbr.img
  truncate -s 63M "$W/part.img"
  mkfs.vfat -F 32 -n PIICHKDISK "$W/part.img"
  mcopy -i "$W/part.img" "$S/meibo.csv" "$S/readme.txt" ::/
  for f in body.docx meibo.xlsx; do
    if [ -f "$S/$f" ]; then mcopy -i "$W/part.img" "$S/$f" ::/; fi
  done
  dd if="$W/part.img" of=/out/disk/disk_mbr.img bs=1M seek=1 conv=notrunc status=none
  sfdisk -l /out/disk/disk_mbr.img
}

convert_one() {
  rm -f "/out/disk/disk.$2"
  qemu-img convert -f raw -O "$1" /out/disk/disk_mbr.img "/out/disk/disk.$2"
  qemu-img info "/out/disk/disk.$2"
}

iso() {
  rm -f /out/disk/meibo.iso
  xorriso -as mkisofs -input-charset utf-8 -J -joliet-long -R -V PIICHK \
    -o /out/disk/meibo.iso "$S"
}

wim() {
  rm -f /out/disk/meibo.wim
  wimlib-imagex capture "$S" /out/disk/meibo.wim piichk
}

squash() {
  rm -f /out/disk/meibo.squashfs
  mksquashfs "$S" /out/disk/meibo.squashfs -noappend -quiet
}

archives() {
  local L=$W/l A=/out/linux_archive
  mkdir -p "$L"
  cp "$S/meibo.csv" "$S/readme.txt" "$L/"
  rm -f "$A"/*
  step tar_zst  tar --zstd -cf "$A/meibo.tar.zst" -C "$L" meibo.csv readme.txt
  step tar_lz4  tar -I lz4 -cf "$A/meibo.tar.lz4" -C "$L" meibo.csv readme.txt
  step tar_xz   tar -cJf "$A/meibo.tar.xz" -C "$L" meibo.csv readme.txt
  step tar_bz2  tar -cjf "$A/meibo.tar.bz2" -C "$L" meibo.csv readme.txt
  step tgz      tar -czf "$A/meibo.tgz" -C "$L" meibo.csv readme.txt
  step compress_z sh -c "compress -c '$L/meibo.csv' > '$A/meibo.csv.Z'"
  step lzip     sh -c "lzip -c '$L/meibo.csv' > '$A/meibo.csv.lz'"
  step cpio     sh -c "cd '$L' && printf 'meibo.csv\nreadme.txt\n' | cpio -o -H newc > '$A/meibo.cpio'"
  step deb      build_deb
  step rpm      build_rpm
}

build_deb() {
  local P=$W/deb
  rm -rf "$P"
  mkdir -p "$P/DEBIAN" "$P/usr/share/piichk"
  cp "$S/meibo.csv" "$P/usr/share/piichk/"
  cat > "$P/DEBIAN/control" <<'CTRL'
Package: piichk-meibo
Version: 1.0
Architecture: all
Maintainer: piichk test <test@example.jp>
Description: piichk test corpus (fictional personal data)
CTRL
  dpkg-deb --root-owner-group --build "$P" /out/linux_archive/piichk-meibo_1.0_all.deb
}

build_rpm() {
  local T=$W/rpm
  rm -rf "$T"
  mkdir -p "$T/SOURCES" "$T/SPECS"
  cp "$S/meibo.csv" "$T/SOURCES/"
  cat > "$T/SPECS/piichk.spec" <<'SPEC'
Name: piichk-meibo
Version: 1.0
Release: 1
Summary: piichk test corpus
License: none
BuildArch: noarch
Source0: meibo.csv
%description
piichk test corpus (fictional personal data)
%prep
%build
%install
mkdir -p %{buildroot}/usr/share/piichk
cp %{SOURCE0} %{buildroot}/usr/share/piichk/meibo.csv
%files
/usr/share/piichk/meibo.csv
SPEC
  rpmbuild --define "_topdir $T" -bb "$T/SPECS/piichk.spec"
  cp "$T"/RPMS/noarch/*.rpm /out/linux_archive/piichk-meibo-1.0-1.noarch.rpm
}

step install_tools install_tools
step fat32 fat32
step ext4 ext4
step ext4_clean ext4_clean
step mbr_disk mbr_disk
step vhdx convert_one vhdx vhdx
step vhd convert_one vpc vhd
step vmdk convert_one vmdk vmdk
step qcow2 convert_one qcow2 qcow2
step vdi convert_one vdi vdi
step iso iso
step wim wim
step squashfs squash
archives
echo DONE >> "$ST"
"""


def read_status(corpus: Corpus) -> dict[str, bool]:
    """ツール用コンテナが書いた各段の成否を読む。"""
    p = corpus.work / "status.txt"
    result: dict[str, bool] = {}
    if p.exists():
        for line in p.read_text("utf-8").splitlines():
            parts = line.split(" ", 1)
            if len(parts) == 2:
                result[parts[1]] = parts[0] == "OK"
    return result


def build_tools_samples(corpus: Corpus, have: dict[str, bool]) -> None:
    """ディスク・OS イメージと Linux 系アーカイブをツール用コンテナで作る。"""
    script = corpus.work / "tools.sh"
    script.write_text(TOOLS_SCRIPT, "utf-8", newline="\n")
    (corpus.work / "tools.log").write_text("", "utf-8")
    remove_container(corpus, TOOLS_CONTAINER)
    corpus.images_used.append(TOOLS_IMAGE)
    docker(
        corpus,
        [
            "run",
            "--rm",
            "--name",
            TOOLS_CONTAINER,
            "-v",
            f"{corpus.out}:/out",
            TOOLS_IMAGE,
            "bash",
            "/out/_work/tools.sh",
        ],
        check=False,
        timeout=3600,
    )
    st = read_status(corpus)
    corpus.log(f"ツール用コンテナの結果: {st}")

    def why(step: str) -> str:
        """その段が失敗していれば skipped の理由を返す。"""
        if st.get(step):
            return ""
        return f"コンテナ内の {step} が失敗（_work/tools.log）"

    inner = ["meibo.csv"] + [n for n, k in (("body.docx", "docx"), ("meibo.xlsx", "xlsx")) if have[k]]
    inner_fmt = {"meibo.csv": "csv", "body.docx": "docx", "meibo.xlsx": "xlsx"}

    def add_fs(path: str, fmt: str, step: str, note: str, names: list[str]) -> None:
        """ファイルシステムイメージとその中身を manifest に足す。"""
        corpus.add(path, "detect", fmt, note=note, skipped=why(step))
        for n in names:
            corpus.add(f"{path}!{n}", "detect", inner_fmt.get(n, "csv"), skipped=why(step))
        corpus.add(f"{path}!readme.txt", "clean", "txt", skipped=why(step))

    add_fs(
        "disk/fat32.img",
        "fat32",
        "fat32",
        "区画表なしの FAT32 区画イメージ（mkfs.vfat + mcopy）",
        inner,
    )
    add_fs(
        "disk/ext4.img",
        "ext4",
        "ext4",
        "区画表なしの ext4 区画イメージ（mkfs.ext4 -d）。日本語名 個人情報名簿.csv も入る",
        inner + ["個人情報名簿.csv"],
    )
    disk_note = (
        "MBR 区画表つきの生ディスク。区画1（開始 2048 セクタ・type 0x0c）が FAT32 で、"
        "中に " + "・".join(inner) + "・readme.txt"
    )
    corpus.add(
        "disk/disk_mbr.img",
        "detect",
        "raw_disk_mbr",
        note=disk_note,
        skipped=why("mbr_disk"),
    )
    for ext, fmt, step in (
        ("vhdx", "vhdx", "vhdx"),
        ("vhd", "vhd", "vhd"),
        ("vmdk", "vmdk", "vmdk"),
        ("qcow2", "qcow2", "qcow2"),
        ("vdi", "vdi", "vdi"),
    ):
        corpus.add(
            f"disk/disk.{ext}",
            "detect",
            fmt,
            note=f"disk_mbr.img を qemu-img convert で {fmt} にしたもの（中身は同じ）",
            skipped=why(step),
        )
    add_fs(
        "disk/meibo.iso",
        "iso9660",
        "iso",
        "ISO9660 + Joliet + Rock Ridge（xorriso）。日本語名 個人情報名簿.csv も入る",
        inner + ["個人情報名簿.csv"],
    )
    add_fs(
        "disk/meibo.wim",
        "wim",
        "wim",
        "wimlib-imagex capture（既定の LZX 圧縮）",
        inner + ["個人情報名簿.csv"],
    )
    add_fs(
        "disk/meibo.squashfs",
        "squashfs",
        "squashfs",
        "mksquashfs（既定の gzip 圧縮）",
        inner + ["個人情報名簿.csv"],
    )

    # Linux 系アーカイブ
    for name, fmt, step in (
        ("meibo.tar.zst", "tar.zst", "tar_zst"),
        ("meibo.tar.lz4", "tar.lz4", "tar_lz4"),
        ("meibo.tar.xz", "tar.xz", "tar_xz"),
        ("meibo.tar.bz2", "tar.bz2", "tar_bz2"),
        ("meibo.tgz", "tgz", "tgz"),
        ("meibo.cpio", "cpio_newc", "cpio"),
    ):
        path = f"linux_archive/{name}"
        corpus.add(path, "detect", fmt, skipped=why(step))
        corpus.add(f"{path}!meibo.csv", "detect", "csv", skipped=why(step))
        corpus.add(f"{path}!readme.txt", "clean", "txt", skipped=why(step))
    corpus.add(
        "linux_archive/meibo.csv.Z",
        "detect",
        "unix_compress",
        note="compress（LZW）で単体圧縮した meibo.csv",
        skipped=why("compress_z"),
    )
    corpus.add(
        "linux_archive/meibo.csv.lz",
        "detect",
        "lzip",
        note="lzip で単体圧縮した meibo.csv",
        skipped=why("lzip"),
    )
    corpus.add(
        "linux_archive/piichk-meibo_1.0_all.deb",
        "detect",
        "deb",
        note="ar 圧縮ファイルの中の data.tar.* に usr/share/piichk/meibo.csv",
        skipped=why("deb"),
    )
    corpus.add(
        "linux_archive/piichk-meibo-1.0-1.noarch.rpm",
        "detect",
        "rpm",
        note="rpmbuild。ペイロード（cpio・既定は zstd か xz 圧縮）に /usr/share/piichk/meibo.csv",
        skipped=why("rpm"),
    )

    # 対照の ext4
    corpus.add(
        "clean/ext4_clean.img",
        "clean",
        "ext4",
        note="個人情報の無い ext4（products.csv・readme.txt のみ）",
        skipped=why("ext4_clean"),
    )
    corpus.add("clean/ext4_clean.img!products.csv", "clean", "csv", skipped=why("ext4_clean"))


# ---------------------------------------------------------------- DB 用 SQL


def pg_sql() -> str:
    """PostgreSQL 用の表とデータ。"""
    lines = [
        "CREATE TABLE 顧客 (",
        "  顧客番号 integer PRIMARY KEY,",
        "  氏名 text NOT NULL,",
        "  フリガナ text,",
        "  郵便番号 varchar(10),",
        "  住所 text,",
        "  電話番号 varchar(20),",
        "  携帯電話 varchar(20),",
        "  メールアドレス text,",
        "  生年月日 date,",
        "  生年月日_文字 text,",
        "  マイナンバー char(12),",
        "  マイナンバー_数値 bigint,",
        "  口座 text,",
        "  口座番号 integer,",
        "  クレジットカード text,",
        "  与信限度額 numeric(12,0)",
        ");",
    ]
    for p in PEOPLE:
        lines.append(
            "INSERT INTO 顧客 VALUES ("
            f"{p['id']}, '{p['name']}', '{p['kana']}', '{p['postal']}', '{p['address']}', "
            f"'{p['phone']}', '{p['mobile']}', '{p['email']}', DATE '{p['birth_iso']}', "
            f"'{p['birth']}', '{p['my_number']}', {int(p['my_number'])}, '{p['bank']}', "
            f"{int(p['account_no'])}, '{p['card']}', {p['limit']});"
        )
    return "\n".join(lines) + "\n"


def pg_clean_sql() -> str:
    """PostgreSQL 用の対照（商品マスタだけ）。"""
    lines = ["CREATE TABLE 商品 (商品番号 integer PRIMARY KEY, 商品名 text, 単価 integer, 分類 text);"]
    for a, b, c, d in PRODUCTS:
        lines.append(f"INSERT INTO 商品 VALUES ({a}, '{b}', {c}, '{d}');")
    return "\n".join(lines) + "\n"


def mysql_sql() -> str:
    """MariaDB 用の表とデータ。"""
    lines = [
        "SET NAMES utf8mb4;",
        "CREATE TABLE `顧客` (",
        "  `顧客番号` INT PRIMARY KEY,",
        "  `氏名` VARCHAR(100) NOT NULL,",
        "  `フリガナ` VARCHAR(100),",
        "  `郵便番号` VARCHAR(10),",
        "  `住所` VARCHAR(200),",
        "  `電話番号` VARCHAR(20),",
        "  `携帯電話` VARCHAR(20),",
        "  `メールアドレス` VARCHAR(200),",
        "  `生年月日` DATE,",
        "  `生年月日_文字` VARCHAR(20),",
        "  `マイナンバー` CHAR(12),",
        "  `マイナンバー_数値` BIGINT,",
        "  `口座` VARCHAR(100),",
        "  `口座番号` INT,",
        "  `クレジットカード` VARCHAR(30),",
        "  `与信限度額` DECIMAL(12,0)",
        ") DEFAULT CHARSET=utf8mb4;",
    ]
    for p in PEOPLE:
        lines.append(
            "INSERT INTO `顧客` VALUES ("
            f"{p['id']}, '{p['name']}', '{p['kana']}', '{p['postal']}', '{p['address']}', "
            f"'{p['phone']}', '{p['mobile']}', '{p['email']}', '{p['birth_iso']}', "
            f"'{p['birth']}', '{p['my_number']}', {int(p['my_number'])}, '{p['bank']}', "
            f"{int(p['account_no'])}, '{p['card']}', {p['limit']});"
        )
    return "\n".join(lines) + "\n"


def oracle_sql() -> str:
    """Oracle 用の表とデータ（piichk ユーザーで流す）。"""
    lines = [
        "WHENEVER SQLERROR EXIT FAILURE",
        'CREATE TABLE "顧客" (',
        '  "顧客番号" NUMBER(10) PRIMARY KEY,',
        '  "氏名" VARCHAR2(100 CHAR) NOT NULL,',
        '  "フリガナ" VARCHAR2(100 CHAR),',
        '  "郵便番号" VARCHAR2(10 CHAR),',
        '  "住所" VARCHAR2(200 CHAR),',
        '  "電話番号" VARCHAR2(20 CHAR),',
        '  "携帯電話" VARCHAR2(20 CHAR),',
        '  "メールアドレス" VARCHAR2(200 CHAR),',
        '  "生年月日" DATE,',
        '  "生年月日_文字" VARCHAR2(20 CHAR),',
        '  "マイナンバー" CHAR(12),',
        '  "マイナンバー_数値" NUMBER(12),',
        '  "口座" VARCHAR2(100 CHAR),',
        '  "口座番号" NUMBER(10),',
        '  "クレジットカード" VARCHAR2(30 CHAR),',
        '  "与信限度額" NUMBER(12)',
        ");",
    ]
    for p in PEOPLE:
        lines.append(
            'INSERT INTO "顧客" VALUES ('
            f"{p['id']}, '{p['name']}', '{p['kana']}', '{p['postal']}', '{p['address']}', "
            f"'{p['phone']}', '{p['mobile']}', '{p['email']}', DATE '{p['birth_iso']}', "
            f"'{p['birth']}', '{p['my_number']}', {int(p['my_number'])}, '{p['bank']}', "
            f"{int(p['account_no'])}, '{p['card']}', {p['limit']});"
        )
    lines += ["COMMIT;", "EXIT"]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- PostgreSQL


def start_pg(corpus: Corpus, name: str, port: int | None) -> None:
    """PostgreSQL コンテナを起こし、TCP で受け付けるまで待つ。"""
    remove_container(corpus, name)
    args = [
        "run",
        "-d",
        "--name",
        name,
        "-e",
        f"POSTGRES_USER={DB_USER}",
        "-e",
        f"POSTGRES_PASSWORD={DB_PASSWORD}",
        "-e",
        f"POSTGRES_DB={DB_NAME}",
    ]
    if port:
        args += ["-p", f"127.0.0.1:{port}:5432"]
    args.append(PG_IMAGE)
    docker(corpus, args)

    # 初期化中の一時サーバーはソケットのみで待ち受けるため、-h 127.0.0.1 で本番の起動を見る
    def ready() -> bool:
        p = docker(
            corpus,
            [
                "exec",
                name,
                "pg_isready",
                "-h",
                "127.0.0.1",
                "-U",
                DB_USER,
                "-d",
                DB_NAME,
            ],
            check=False,
            quiet=True,
        )
        return p.returncode == 0

    if not wait_until(corpus, ready, tries=60, interval=1.0):
        raise RuntimeError(f"{name} が60秒以内に起動しませんでした")


def psql(corpus: Corpus, name: str, db: str, sql: str) -> None:
    """psql に SQL を標準入力で流す。"""
    docker(
        corpus,
        [
            "exec",
            "-i",
            name,
            "psql",
            "-v",
            "ON_ERROR_STOP=1",
            "-q",
            "-U",
            DB_USER,
            "-d",
            db,
        ],
        stdin=sql.encode("utf-8"),
    )


def build_postgres(corpus: Corpus) -> None:
    """PostgreSQL の生きた DB を作り、各形式のダンプを取る。"""
    dest = corpus.out / "db" / "postgres"
    dest.mkdir(parents=True, exist_ok=True)
    clean_dest = corpus.out / "clean"
    clean_dest.mkdir(parents=True, exist_ok=True)
    corpus.images_used.append(PG_IMAGE)
    port = free_port(55432)
    start_pg(corpus, PG_LIVE, port)
    psql(corpus, PG_LIVE, DB_NAME, pg_sql())
    psql(corpus, PG_LIVE, DB_NAME, "CREATE DATABASE piichk_clean;")
    psql(corpus, PG_LIVE, "piichk_clean", pg_clean_sql())
    corpus.save()

    docker(corpus, ["exec", PG_LIVE, "rm", "-rf", "/tmp/d"], check=False)
    docker(corpus, ["exec", PG_LIVE, "mkdir", "-p", "/tmp/d"])
    dumps = [
        ("plain.sql", ["-Fp"], "pg_dump_plain", "pg_dump の plain（COPY 文）"),
        ("custom.dump", ["-Fc"], "pg_dump_custom", "pg_dump -Fc（既定の gzip 圧縮）"),
        (
            "custom_z0.dump",
            ["-Fc", "-Z0"],
            "pg_dump_custom",
            "pg_dump -Fc -Z0（圧縮なし）",
        ),
        ("archive.tar", ["-Ft"], "pg_dump_tar", "pg_dump -Ft（tar 形式）"),
    ]
    for fname, opts, fmt, note in dumps:
        ok = run_quiet(
            corpus,
            [
                "exec",
                PG_LIVE,
                "pg_dump",
                "-U",
                DB_USER,
                *opts,
                "-f",
                f"/tmp/d/{fname}",
                DB_NAME,
            ],
        ) and run_quiet(corpus, ["cp", f"{PG_LIVE}:/tmp/d/{fname}", str(dest / fname)])
        corpus.add(
            f"db/postgres/{fname}",
            "detect",
            fmt,
            note=note,
            skipped="" if ok else "pg_dump に失敗",
        )

    # directory 形式（フォルダそのものと、tar にまとめたもの）
    ok = run_quiet(
        corpus,
        [
            "exec",
            PG_LIVE,
            "pg_dump",
            "-U",
            DB_USER,
            "-Fd",
            "-f",
            "/tmp/d/dump_dir",
            DB_NAME,
        ],
    )
    if ok:
        target = dest / "dump_dir"
        if target.exists():
            shutil.rmtree(target)
        ok = run_quiet(corpus, ["cp", f"{PG_LIVE}:/tmp/d/dump_dir", str(target)])
    corpus.add(
        "db/postgres/dump_dir",
        "detect",
        "pg_dump_directory",
        note="pg_dump -Fd のフォルダそのもの（toc.dat と表ごとの NNNN.dat.gz）。フォルダ単位で1件",
        skipped="" if ok else "pg_dump -Fd に失敗",
    )
    ok = run_quiet(
        corpus,
        [
            "exec",
            PG_LIVE,
            "tar",
            "-C",
            "/tmp/d",
            "-cf",
            "/tmp/d/dump_dir.tar",
            "dump_dir",
        ],
    ) and run_quiet(corpus, ["cp", f"{PG_LIVE}:/tmp/d/dump_dir.tar", str(dest / "dump_dir.tar")])
    corpus.add(
        "db/postgres/dump_dir.tar",
        "detect",
        "tar",
        note="pg_dump -Fd のフォルダを tar にまとめたもの（中の NNNN.dat.gz に値）",
        skipped="" if ok else "tar に失敗",
    )

    # 対照（商品マスタだけ）
    for fname, opts, fmt in (
        ("products_clean.sql", ["-Fp"], "pg_dump_plain"),
        ("products_clean.dump", ["-Fc"], "pg_dump_custom"),
    ):
        ok = run_quiet(
            corpus,
            [
                "exec",
                PG_LIVE,
                "pg_dump",
                "-U",
                DB_USER,
                *opts,
                "-f",
                f"/tmp/d/{fname}",
                "piichk_clean",
            ],
        ) and run_quiet(corpus, ["cp", f"{PG_LIVE}:/tmp/d/{fname}", str(clean_dest / fname)])
        corpus.add(
            f"clean/{fname}",
            "clean",
            fmt,
            note="商品マスタだけの pg_dump（個人情報なし）",
            skipped="" if ok else "pg_dump に失敗",
        )
    remove_container(corpus, PG_LIVE)


def build_pgdata(corpus: Corpus) -> None:
    """停止した PostgreSQL のデータフォルダ一式を tar にまとめる（別の使い捨てコンテナで）。"""
    dest = corpus.out / "db" / "postgres"
    try:
        start_pg(corpus, PG_DATA, None)
        psql(corpus, PG_DATA, DB_NAME, pg_sql())
        psql(corpus, PG_DATA, DB_NAME, "CHECKPOINT;")
        # 公式イメージの停止シグナルは SIGINT（fast shutdown）で、停止時にチェックポイントが走る
        docker(corpus, ["stop", "-t", "60", PG_DATA])
        remove_container(corpus, PG_TAR)
        docker(
            corpus,
            [
                "run",
                "--rm",
                "--name",
                PG_TAR,
                "--volumes-from",
                PG_DATA,
                "-v",
                f"{corpus.out}:/out",
                TOOLS_IMAGE,
                "tar",
                "-C",
                "/var/lib/postgresql",
                "-cf",
                "/out/db/postgres/pgdata.tar",
                "data",
            ],
        )
        skipped = ""
    except Exception as exc:  # noqa: BLE001 - 失敗は skipped として残す
        corpus.log(f"データフォルダの作成に失敗: {exc}")
        skipped = f"データフォルダの作成に失敗: {exc}"
    finally:
        remove_container(corpus, PG_DATA)
    corpus.add(
        "db/postgres/pgdata.tar",
        "partial",
        "postgres_datadir_tar",
        note=(
            "停止後の /var/lib/postgresql/data 一式（PostgreSQL 16）。"
            "base/<oid>/<relfilenode> のヒープに文字列は生のまま入るが、date・integer・numeric は"
            "バイナリなので、文字列型の値だけ見つかる簡易検査が正しい"
        ),
        skipped=skipped,
    )
    _ = dest


def run_quiet(corpus: Corpus, args: list[str]) -> bool:
    """docker を呼び、成否だけ返す。"""
    return docker(corpus, args, check=False).returncode == 0


# ---------------------------------------------------------------- MariaDB


def build_mariadb(corpus: Corpus) -> None:
    """MariaDB の生きた DB を作り、mysqldump（拡張 INSERT）を取る。"""
    dest = corpus.out / "db" / "mariadb"
    dest.mkdir(parents=True, exist_ok=True)
    corpus.images_used.append(MARIADB_IMAGE)
    port = free_port(53306)
    remove_container(corpus, MARIADB_LIVE)
    docker(
        corpus,
        [
            "run",
            "-d",
            "--name",
            MARIADB_LIVE,
            "-p",
            f"127.0.0.1:{port}:3306",
            "-e",
            f"MARIADB_ROOT_PASSWORD={DB_PASSWORD}",
            "-e",
            f"MARIADB_USER={DB_USER}",
            "-e",
            f"MARIADB_PASSWORD={DB_PASSWORD}",
            "-e",
            f"MARIADB_DATABASE={DB_NAME}",
            MARIADB_IMAGE,
            "--character-set-server=utf8mb4",
            "--collation-server=utf8mb4_unicode_ci",
        ],
    )
    base = [
        "exec",
        "-i",
        MARIADB_LIVE,
        "mariadb",
        "-h127.0.0.1",
        f"-u{DB_USER}",
        f"-p{DB_PASSWORD}",
        "--default-character-set=utf8mb4",
    ]

    # 初期化中の一時サーバーは TCP を開かないので、TCP で SELECT 1 が通るまで待つ
    def ready() -> bool:
        p = docker(corpus, [*base, "-e", "SELECT 1"], check=False, quiet=True)
        return p.returncode == 0

    if not wait_until(corpus, ready, tries=60, interval=1.0):
        raise RuntimeError("MariaDB が60秒以内に起動しませんでした")
    docker(corpus, [*base, DB_NAME], stdin=mysql_sql().encode("utf-8"))
    corpus.save()
    proc = docker(
        corpus,
        [
            "exec",
            MARIADB_LIVE,
            "mariadb-dump",
            "-h127.0.0.1",
            "-uroot",
            f"-p{DB_PASSWORD}",
            "--default-character-set=utf8mb4",
            "--extended-insert",
            "--databases",
            DB_NAME,
        ],
        check=False,
    )
    skipped = ""
    if proc.returncode == 0 and proc.stdout:
        (dest / "mysqldump.sql").write_bytes(proc.stdout)
    else:
        skipped = "mariadb-dump に失敗"
    corpus.add(
        "db/mariadb/mysqldump.sql",
        "detect",
        "mysqldump",
        note="mariadb-dump --extended-insert（1つの INSERT に3行）。生年月日は DATE 列と文字列列の両方",
        skipped=skipped,
    )
    remove_container(corpus, MARIADB_LIVE)


# ---------------------------------------------------------------- Oracle


def build_oracle(corpus: Corpus) -> None:
    """Oracle の expdp（と使えれば旧 exp）のダンプを作る。終わったらコンテナは消す。"""
    dest = corpus.out / "db" / "oracle"
    dest.mkdir(parents=True, exist_ok=True)
    entries = [
        (
            "db/oracle/expdp.dmp",
            "partial",
            "oracle_datapump",
            "expdp（Data Pump・圧縮なし）。文字列は AL32UTF8 で読めるが日付・数値は内部形式なので簡易検査が正しい",
        ),
        (
            "db/oracle/expdp_compressed.dmp",
            "uncheckable",
            "oracle_datapump",
            "expdp COMPRESSION=ALL。データ部が圧縮されており値は読めないので検査不能が正しい",
        ),
        (
            "db/oracle/exp.dmp",
            "partial",
            "oracle_exp",
            "旧 exp のダンプ。文字列は読めるが日付・数値は内部形式なので簡易検査が正しい",
        ),
    ]
    image = next((i for i in ORACLE_IMAGES if image_exists(corpus, i)), "")
    if not image:
        for e in entries:
            corpus.add(
                e[0],
                e[1],
                e[2],
                note=e[3],
                skipped="Oracle のイメージがローカルに無い（取得は重いので見送り）",
            )
        return
    corpus.images_used.append(image)
    results: dict[str, str] = {}
    try:
        remove_container(corpus, ORACLE_CONTAINER)
        docker(
            corpus,
            [
                "run",
                "-d",
                "--name",
                ORACLE_CONTAINER,
                "-e",
                f"ORACLE_PASSWORD={ORACLE_SYS_PASSWORD}",
                "-e",
                f"APP_USER={DB_USER}",
                "-e",
                f"APP_USER_PASSWORD={DB_PASSWORD}",
                image,
            ],
        )

        def ready() -> bool:
            p = docker(corpus, ["logs", ORACLE_CONTAINER], check=False, quiet=True)
            text = (p.stdout + p.stderr).decode("utf-8", "replace")
            return "DATABASE IS READY TO USE" in text

        # 最大 15 分（2秒×450回）。超えたら skipped にする
        if not wait_until(corpus, ready, tries=450, interval=2.0):
            raise RuntimeError("Oracle が15分以内に起動しませんでした")
        corpus.log("Oracle が起動しました")
        pdb = "FREEPDB1" if "oracle-free" in image else "XEPDB1"
        nls = ["-e", "NLS_LANG=JAPANESE_JAPAN.AL32UTF8"]
        load = corpus.work / "oracle_load.sql"
        load.write_text(oracle_sql(), "utf-8", newline="\n")
        docker(corpus, ["cp", str(load), f"{ORACLE_CONTAINER}:/tmp/oracle_load.sql"])
        docker(
            corpus,
            [
                "exec",
                *nls,
                ORACLE_CONTAINER,
                "sqlplus",
                "-s",
                f"{DB_USER}/{DB_PASSWORD}@//localhost/{pdb}",
                "@/tmp/oracle_load.sql",
            ],
        )
        docker(corpus, ["exec", ORACLE_CONTAINER, "mkdir", "-p", "/tmp/piichk_dp"])
        sys_sql = (
            "WHENEVER SQLERROR EXIT FAILURE\n"
            f"ALTER SESSION SET CONTAINER={pdb};\n"
            "CREATE OR REPLACE DIRECTORY PIICHK_DIR AS '/tmp/piichk_dp';\n"
            f"GRANT READ, WRITE ON DIRECTORY PIICHK_DIR TO {DB_USER};\n"
            "EXIT\n"
        )
        docker(
            corpus,
            ["exec", "-i", ORACLE_CONTAINER, "sqlplus", "-s", "/", "as", "sysdba"],
            stdin=sys_sql.encode("utf-8"),
        )
        conn = f"{DB_USER}/{DB_PASSWORD}@//localhost/{pdb}"
        jobs = [
            (
                "expdp.dmp",
                [
                    "expdp",
                    conn,
                    "directory=PIICHK_DIR",
                    "dumpfile=expdp.dmp",
                    "logfile=expdp.log",
                    f"schemas={DB_USER}",
                ],
            ),
            (
                "expdp_compressed.dmp",
                [
                    "expdp",
                    conn,
                    "directory=PIICHK_DIR",
                    "dumpfile=expdp_compressed.dmp",
                    "logfile=expdp_compressed.log",
                    f"schemas={DB_USER}",
                    "compression=ALL",
                ],
            ),
            (
                "exp.dmp",
                ["exp", conn, "file=/tmp/piichk_dp/exp.dmp", f"owner={DB_USER}"],
            ),
        ]
        for fname, cmd in jobs:
            p = docker(corpus, ["exec", *nls, ORACLE_CONTAINER, *cmd], check=False)
            out = (p.stdout + p.stderr).decode("utf-8", "replace")
            with (corpus.work / "oracle.log").open("a", encoding="utf-8") as f:
                f.write(f"=== {fname}\n{out}\n")
            ok = p.returncode == 0 and run_quiet(
                corpus,
                ["cp", f"{ORACLE_CONTAINER}:/tmp/piichk_dp/{fname}", str(dest / fname)],
            )
            if not ok:
                tail = out.strip().splitlines()[-3:] if out.strip() else []
                results[fname] = f"{cmd[0]} が失敗（終了コード {p.returncode}）: " + " / ".join(tail)[:300]
    except Exception as exc:  # noqa: BLE001 - 失敗は skipped として残す
        corpus.log(f"Oracle の処理に失敗: {exc}")
        for e in entries:
            results.setdefault(e[0].split("/")[-1], f"Oracle の処理に失敗: {exc}")
    finally:
        remove_container(corpus, ORACLE_CONTAINER)
    for path, expect, fmt, note in entries:
        corpus.add(path, expect, fmt, note=note, skipped=results.get(path.split("/")[-1], ""))


# ---------------------------------------------------------------- 照合


def verify(corpus: Corpus) -> tuple[int, int, list[str]]:
    """manifest の外側の件数と、出力先の実ファイル数を突き合わせる。"""
    outer = {e["path"] for e in corpus.entries if "!" not in e["path"] and "skipped" not in e}
    dir_entries = {p for p in outer if (corpus.out / p).is_dir()}
    actual: set[str] = set()
    for f in corpus.out.rglob("*"):
        rel = f.relative_to(corpus.out).as_posix()
        if rel.startswith("_work") or rel == "manifest.json" or f.is_dir():
            continue
        top_dir = next((d for d in dir_entries if rel.startswith(d + "/")), None)
        actual.add(top_dir or rel)
    diff = sorted((outer ^ actual))
    return len(outer), len(actual), diff


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("out", type=Path, help="出力先フォルダ")
    parser.add_argument(
        "--corpus",
        type=Path,
        default=None,
        help="既存の検体フォルダ（docx/xlsx を流用）",
    )
    parser.add_argument(
        "--only",
        default="tools,postgres,pgdata,mariadb,oracle",
        help="作る系統をカンマ区切りで（既定はすべて）",
    )
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    corpus = Corpus(out)
    only = set(args.only.split(","))
    if not Path(DOCKER).exists():
        print(f"Docker CLI が見つかりません: {DOCKER}", file=sys.stderr)
        return 2
    have = prepare_sources(corpus, args.corpus)

    steps = [
        ("tools", lambda: build_tools_samples(corpus, have)),
        ("postgres", lambda: build_postgres(corpus)),
        ("pgdata", lambda: build_pgdata(corpus)),
        ("mariadb", lambda: build_mariadb(corpus)),
        ("oracle", lambda: build_oracle(corpus)),
    ]
    for key, fn in steps:
        if key not in only:
            continue
        corpus.log(f"--- {key} を開始")
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - 1系統の失敗で全体を止めない
            corpus.log(f"{key} が失敗しました: {exc}")
            corpus.add(f"_failed/{key}", "clean", key, skipped=f"{key} 系統の処理が失敗: {exc}")
        corpus.save()

    n_manifest, n_actual, diff = verify(corpus)
    corpus.log(f"照合: manifest の外側（skipped 除く）{n_manifest} 件 / 実ファイル {n_actual} 件")
    if diff:
        corpus.log("不一致: " + ", ".join(diff))
    skipped = [e for e in corpus.entries if "skipped" in e]
    corpus.log(f"skipped {len(skipped)} 件")
    return 0 if not diff else 1


if __name__ == "__main__":
    sys.exit(main())

"""検査結果を表すデータ型。

ワーカープロセスとの受け渡し（pickle）と SQLite への保存に使うため、
すべて素朴な dataclass で表す。通常の検査では生の個人情報の値は保持しない（マスク済みの値だけ）。
画面の詳細のための読み直し（ScanOptions.reveal）のときだけ、Finding の raw_* に入れてメモリの中で返す。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Status(str, Enum):
    """1つの検査対象（ファイル・アーカイブ内のファイル・フォルダ）の状態。"""

    PENDING = "pending"  # 未検査
    SCANNED = "scanned"  # 中身を構造ごと読んで検査した
    PARTIAL = "partial"  # 構造を解釈できず、文字として読める部分だけ検査した（簡易検査）
    NEEDS_PASSWORD = "needs_password"  # パスワードが要る（人に聞く）
    UNCHECKABLE = "uncheckable"  # 破損・未対応・時間切れ・権限なし等で検査できない
    OUT_OF_SCOPE = "out_of_scope"  # 動画・音声・実行ファイル等、対象外として扱った

    @property
    def label(self) -> str:
        return STATUS_LABELS[self]

    @property
    def blocks_clean_verdict(self) -> bool:
        """この状態が1件でもあると「個人情報なし」と言い切れない。"""
        return self in (Status.PENDING, Status.NEEDS_PASSWORD, Status.UNCHECKABLE)


STATUS_LABELS = {
    Status.PENDING: "未検査",
    Status.SCANNED: "検査済み",
    Status.PARTIAL: "簡易検査",
    Status.NEEDS_PASSWORD: "要パスワード",
    Status.UNCHECKABLE: "検査不能",
    Status.OUT_OF_SCOPE: "対象外",
}


class Confidence(str, Enum):
    """検出の確からしさ。"""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def label(self) -> str:
        return {"high": "高", "medium": "中", "low": "低"}[self.value]

    @property
    def rank(self) -> int:
        return {"high": 3, "medium": 2, "low": 1}[self.value]


@dataclass
class Finding:
    """個人情報らしきものの検出1件（値はマスク済み）。"""

    pii_type: str  # detectors.PII_TYPES のキー
    confidence: Confidence
    masked_value: str
    location: str  # 「Sheet1!B3」「3ページ」「表 顧客 / 12行目 / 列 氏名」等
    context: str  # 前後の文脈（マスク済み）
    rule: str  # どの規則で検出したか（説明用）
    method: str = ""  # 構造解析 / 生データ走査 / OCR 等
    # 画面で詳細を開いたときだけ、元のファイルを読み直して入れる検出した値そのもの・伏せていない前後の文脈。
    # 通常の検査では空のまま。store は保存しない（DB・レポート・途中経過のどこにも書かない）
    raw_value: str = ""
    raw_context: str = ""


@dataclass
class ItemResult:
    """検査対象1件の結果。アーカイブ内のファイルは「外側!内側」のパスで1件になる。"""

    path: str  # 表示用パス（アーカイブ内は 外側.zip!内側/a.xlsx）
    kind: str  # 判定した形式（日本語の短い名前）
    status: Status
    reason: str = ""  # 状態の理由（検査不能・要パスワードのときは必須）
    method: str = ""  # どう読んだか（例: 「openpyxl（全シート）＋XML全部品」）
    size: int | None = None
    mtime: float | None = None
    depth: int = 0  # 0=実ファイル、1以上=アーカイブ等の内側
    password_kind: str = ""  # 要パスワードのとき: zip / 7z / pdf / office / access 等
    findings: list[Finding] = field(default_factory=list)
    finding_counts: dict[str, int] = field(default_factory=dict)  # 種類→件数（明細の上限に関係なく全数）
    conf_counts: dict[str, int] = field(default_factory=dict)  # 「種類:確度」→件数（判定はこれで決める）
    notes: list[str] = field(default_factory=list)  # 補足（例: 画像PDFのためOCRした）
    allowed: int = 0  # 許可リストの値と一致したため数えなかった検出の件数（黙って消さず、件数は残す）
    # 「種類:確度」→異なる値の数（正規化した値で同じものを1つと数える。確度は同じ値で見た最も高いもの）。
    # 値もハッシュも持たない（数え終えたら捨てる）
    distinct_counts: dict[str, int] = field(default_factory=dict)
    # 利用者の規則の名前→件数（全数。finding_counts の「custom」を規則ごとに分けたもの。内訳の表示に使う）
    rule_counts: dict[str, int] = field(default_factory=dict)
    # 対処のための位置の集め直し（ScanOptions.collect_positions）のときだけ入る。通常の検査では空のまま・保存しない。
    # （シート名, 種類, 確度の順位）→ 4つ組（行, 列, 値の開始, 値の終了）を並べた array('q')。生の値は持たない
    positions: dict = field(default_factory=dict)
    # 位置の意味: "csv,"・"csv\t"（行・列）/ "lines"（行）/ "xlsx"（シート・行・列）/ ""（位置を持たない）
    pos_layout: str = ""
    pos_overflow: bool = False  # 位置の数が上限を超えて、途中までしか集めていない


@dataclass
class FileResult:
    """実ファイル1件の検査結果（内側の項目を平らに並べて持つ）。"""

    top_path: str
    items: list[ItemResult]
    elapsed: float = 0.0
    source: dict | None = None  # 元のファイルの識別情報と SHA-256（safeio.SourceInfo）。写せなかったときは None
    # NAS への接続が切れて元のファイルを読めなかった（ファイルの問題ではない）。実行器は済みにせず、つながってから読み直す
    network_lost: bool = False
    # ファイル全体（zip の中身・埋め込みを含む）での「種類:確度」→異なる値の数。同じ値が2つの項目にあれば1つと数える
    distinct_counts: dict[str, int] = field(default_factory=dict)


@dataclass
class ScanOptions:
    """検査の設定。ワーカーへ pickle で渡す。"""

    max_samples_per_type: int = 20  # 1項目・1種類あたり明細に残す件数（件数自体は全数数える）
    max_depth: int = 10  # アーカイブ・埋め込みの入れ子の上限
    max_expand_bytes: int = 4 * 1024**4  # 1つの実ファイルから展開してよい合計バイト数（OS イメージも通る大きさ）
    max_expand_ratio: int = 1000  # 圧縮率がこれを超え、かつ 10GB を超える展開は zip 爆弾とみなす
    max_entries: int = 3_000_000  # 1つの実ファイルから展開してよい項目数（OS イメージは数十万件）
    extract_batch_bytes: int = 4 * 1024**3  # 7-Zip で一度に展開する量（一時領域を食い潰さないよう分割する）
    ocr: bool = True  # 画像・画像PDFを OCR する
    min_image_px: int = 48  # これより小さい画像は文字を含みえないので OCR しない
    raw_sweep: bool = True  # OLE形式・Access 等で生データ走査も重ねる（削除済み残留の検出）
    deep_image_sweep: bool = False  # ディスクイメージの未使用領域（削除済みファイル）も生データ走査する
    temp_dir: str | None = None  # 展開に使う一時フォルダ（空きの多いドライブを指定できる）
    access_helper32: str | None = None  # 32bit 補助（exe か python.exe+スクリプト）の起動コマンド
    sevenzip: str | None = None  # 7z.exe のパス
    max_rows_per_table: int = 0  # 0=無制限
    allow_recall: bool = False  # クラウドの代替ファイルも読む（読むとダウンロードが起き、元のファイルの状態が変わる）
    reuse: bool = True  # 前回から変わっていないファイルは前回の結果を使い回す（False で全部読み直す）
    # 接続方式で指定したときの接続先（remote.Connection.public()。パスワードは入れない。ジョブと一緒に保存する）
    connection: dict | None = None
    # 許可リスト（拾わない値。利用者が入れた値をそのまま持つ。照合は userrules.normalize_allow で寄せてから）
    allow_values: list[str] = field(default_factory=list)
    # 利用者の規則（userrules.UserRule.to_dict() の形。受け付けるときに書き方と速さを確かめてある）
    custom_rules: list[dict] = field(default_factory=list)
    # 画面の詳細用の読み直しだけ True（Finding に raw_value・raw_context を入れ、途中経過は書かない）。
    # ジョブの設定としては保存しない（store.create_job が外す）・検査器の版にも含めない
    reveal: bool = False
    # 対処（remediate）のための読み直しだけ True（構造の位置を全部集める。生の値は持たず、途中経過は書かない）。
    # reveal と同じく、ジョブの設定としては保存しない・検査器の版にも含めない
    collect_positions: bool = False


@dataclass
class PasswordBook:
    """人から受け取ったパスワード。メモリ上だけで使い、保存しない。"""

    common: list[str] = field(default_factory=list)  # どのファイルにも試すもの
    per_file: dict[str, list[str]] = field(default_factory=dict)  # 実ファイルのパス→候補
    # 接続方式（FTP 等）でサーバーへログインするパスワード。暗号化ファイルの候補には混ぜない
    connection_password: str = ""

    def candidates_for(self, top_path: str) -> list[str]:
        """そのファイルで試す順のパスワード一覧（個別指定→共通）。重複は除く。"""
        seen: list[str] = []
        for pw in self.per_file.get(top_path, []) + self.common:
            if pw not in seen:
                seen.append(pw)
        return seen

"""PDF・docx・pptx の対処で共通の部分（本文の外に残った値を見つける判定）。

本文の検出した値を黒塗り・ダミー化・削除しても、文書のプロパティ（作成者・題）・しおり・注釈・リンク・埋め込みファイルなど、
本文の外に同じ値が残りうる。そこに「消した値」か「選んだ種類・確度の検出」が残っていないかを調べる。
生の値は、この判定のためにメモリの中で持つだけで、記録・DB・ログには出さない。
"""

from __future__ import annotations

import os
import re
import tempfile

from . import detectors
from .remedy_write import Selection

CONF_RANK = {"high": 3, "medium": 2, "low": 1}
MIN_VALUE_LEN = 3  # これより短い値は、本文の外の文字との偶然の一致が多いので、値の一致では探さない（検出の判定は使う）
RE_TAGS = re.compile(r"<[^>]{0,4000}>")


class Residue:
    """本文の外に残った値の判定。values は消した値（NFKC で正規化したもの）、types・ranks は選んだ種類と確度の順位。"""

    def __init__(self, values=(), types=(), ranks=()):
        self.values: set[str] = {v for v in values if len(v) >= MIN_VALUE_LEN}
        self.types = set(types)
        self.ranks = set(ranks)

    @classmethod
    def from_selection(cls, sel: Selection, values=()) -> "Residue":
        return cls(values, {k[1] for k in sel.groups}, {k[2] for k in sel.groups})

    def add(self, value: str) -> None:
        norm = detectors.normalize(value)
        if len(norm) >= MIN_VALUE_LEN:
            self.values.add(norm)

    def known(self, text: str) -> bool:
        """消した値そのものを含むか。"""
        if not text or not self.values:
            return False
        norm = detectors.normalize(text)
        return any(v in norm for v in self.values)

    def detected(self, text: str) -> bool:
        """選んだ種類・確度の検出を含むか（検査と同じ判定。見出しなし）。"""
        if not text or not self.types:
            return False
        for hit in detectors.detect(detectors.normalize(text), None):
            if hit.pii_type in self.types and hit.confidence.rank in self.ranks:
                return True
        return False

    def hit(self, text: str) -> bool:
        return self.known(text) or self.detected(text)

    def hit_markup(self, markup: str) -> bool:
        """XML の文字列に、タグを除いた文字（と属性値の文字）として残っているか。"""
        if not markup:
            return False
        return self.hit(RE_TAGS.sub(" ", markup)) or any(v in markup for v in self.values)

    def embedded_has_pii(self, data: bytes, name: str) -> bool:
        """埋め込みファイルの中に値が残っているか。値の一致（主な文字コード）か、検査と同じ読み方で選んだ種類・確度の検出があるか。"""
        for v in self.values:
            for enc in ("utf-8", "utf-16-le", "utf-16-be", "cp932", "euc_jp"):
                try:
                    if v.encode(enc) in data:
                        return True
                except UnicodeEncodeError:
                    continue
        if not self.types:
            return False
        from . import engine
        from .models import PasswordBook, ScanOptions

        ext = os.path.splitext(os.path.basename(name.replace("\\", "/")))[1][:12]
        ext = ext if re.fullmatch(r"\.[0-9A-Za-z]{1,10}", ext) else ""
        with tempfile.TemporaryDirectory(prefix="piichk-emb-") as folder:
            path = os.path.join(folder, "embedded" + ext)
            with open(path, "wb") as f:
                f.write(data)
            result = engine.scan_file(path, ScanOptions(temp_dir=folder, reuse=False), PasswordBook())
        for item in result.items:
            for key, n in item.conf_counts.items():
                pii_type, conf = key.split(":", 1)
                if n and pii_type in self.types and CONF_RANK.get(conf, 0) in self.ranks:
                    return True
        return False

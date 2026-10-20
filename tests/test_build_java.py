"""build.py の、Java 実行環境と Jackcess を配布フォルダへ入れる部分（Access の中身の対処。T2-e）の試験。

ネットワークも本物の JDK も使わない（取得する関数を差し替える）。exe のビルドはしない。
本物の JDK・Maven Central を使った取り込み（jlink・javac・jdeps・Java 補助の起動の確認）は、手元で
`build.add_java` を作業用のフォルダへ向けて確かめる手順が docs/開発者向け.md にある。
"""

from __future__ import annotations

import hashlib
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import build  # noqa: E402


def test_jdk_home_is_found_directly_or_one_level_down(tmp_path):
    (tmp_path / "jdk-21" / "bin").mkdir(parents=True)
    (tmp_path / "jdk-21" / "bin" / "jlink.exe").write_bytes(b"")
    assert build._jdk_home_of(tmp_path) == tmp_path / "jdk-21"  # zip の展開直下に1段フォルダがある作り
    assert build._jdk_home_of(tmp_path / "jdk-21") == tmp_path / "jdk-21"
    assert build._jdk_home_of(tmp_path / "nothing") is None


def test_find_jdk_refuses_a_jre_without_javac(tmp_path):
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "jlink.exe").write_bytes(b"")  # jlink だけで javac・jar・jdeps が無い
    with pytest.raises(SystemExit, match="JDK に"):
        build.find_jdk(str(tmp_path))


def test_jar_license_texts_reads_license_and_notice(tmp_path):
    jar = tmp_path / "x.jar"
    with zipfile.ZipFile(jar, "w") as z:
        z.writestr("META-INF/LICENSE.txt", "Apache License Version 2.0")
        z.writestr("META-INF/NOTICE.txt", "Copyright Example")
        z.writestr("a/B.class", b"\xca\xfe")
    text = build.jar_license_texts(jar)
    assert "Apache License Version 2.0" in text and "Copyright Example" in text and "B.class" not in text


def test_java_license_section_collects_staged_texts(tmp_path, monkeypatch):
    internal = tmp_path / "_internal"
    (internal / "jackcess" / "licenses").mkdir(parents=True)
    (internal / "jackcess" / "licenses" / "jackcess-4.0.8-LICENSE.txt").write_text(
        "JACKCESS-LICENSE-BODY", encoding="utf-8"
    )
    (internal / "java" / "legal" / "java.base").mkdir(parents=True)
    (internal / "java" / "legal" / "java.base" / "LICENSE").write_text("GPL-V2-BODY", encoding="utf-8")
    (internal / "java" / "legal" / "java.base" / "ASSEMBLY_EXCEPTION").write_text(
        "CLASSPATH-EXCEPTION", encoding="utf-8"
    )
    monkeypatch.setattr(build, "INTERNAL", internal)
    text = build.java_license_section()
    assert "JACKCESS-LICENSE-BODY" in text and "GPL-V2-BODY" in text and "CLASSPATH-EXCEPTION" in text
    assert "Apache License 2.0" in text and "Classpath Exception" in text
    monkeypatch.setattr(build, "INTERNAL", tmp_path / "empty")
    assert build.java_license_section() == ""  # 同梱していなければ何も足さない


def test_fetch_jackcess_jars_verifies_the_published_checksum(tmp_path, monkeypatch):
    payload = b"fake jar"
    monkeypatch.setattr(build, "CACHE", tmp_path / "cache")
    monkeypatch.setattr(
        build,
        "_download",
        lambda url, dest: (dest.parent.mkdir(parents=True, exist_ok=True), dest.write_bytes(payload)),
    )
    good = hashlib.sha1(payload).hexdigest()
    monkeypatch.setattr(build, "_remote_text", lambda url: good + "\n")
    out = build.fetch_jackcess_jars(tmp_path / "jars")
    assert sorted(out) == sorted(build.JACKCESS_JARS) and all(p.read_bytes() == payload for p in out.values())
    # 公開値と合わないものは、取り込まずに断る（キャッシュからも消す）
    monkeypatch.setattr(build, "CACHE", tmp_path / "cache2")
    monkeypatch.setattr(build, "_remote_text", lambda url: "0" * 40 + "\n")
    with pytest.raises(SystemExit, match="チェックサム"):
        build.fetch_jackcess_jars(tmp_path / "jars2")
    assert not any((tmp_path / "cache2" / "jackcess").glob("*.jar"))  # 合わないキャッシュは消してある

"""IANA の TLD の一覧を取り、pii_checker/tlds.py を書き直す。

メールアドレスの形の検出は、実在する TLD で終わるものだけを残す（detectors._email_domain_plausible）。
プログラムの識別子（「z@FlaxRobertaPreLayerNormLayerCollection.setup」「x@org.jspecify.annotations.Nullable」）が
メールの形に当たるのを捨てるため。TLD は年に数個ずつ増減するので、ときどきこの道具で作り直す。
国際化ドメインの TLD（xn--…）は検出の式（英字だけの TLD）に当たらないので入れない。

使い方: python tools/update_tlds.py            … IANA から取って tlds.py を書き直す
        python tools/update_tlds.py <ファイル>  … 手元に取ってある一覧（tlds-alpha-by-domain.txt）から書き直す
"""

import os
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "pii_checker", "tlds.py")
URL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"


def main() -> int:
    try:
        if len(sys.argv) > 1:
            with open(sys.argv[1], encoding="ascii") as f:
                raw = f.read()
        else:
            with urllib.request.urlopen(URL, timeout=30) as r:
                raw = r.read().decode("ascii")
    except (OSError, UnicodeDecodeError) as e:
        where = sys.argv[1] if len(sys.argv) > 1 else URL
        print(f"一覧を読めませんでした（{where}・{type(e).__name__}: {e}）。tlds.py は変えていません", file=sys.stderr)
        return 1
    lines = raw.splitlines()
    if not lines or not lines[0].startswith("# Version"):
        print("IANA の一覧の形ではありません（先頭が「# Version」でない）", file=sys.stderr)
        return 1
    version = lines[0].lstrip("# ").strip()
    tlds = sorted({x.strip().lower() for x in lines[1:] if x.strip() and not x.upper().startswith("XN--")})
    if len(tlds) < 1000:
        print(f"TLD が {len(tlds)} 個しかありません（取り損ねの疑い）。書き直しません", file=sys.stderr)
        return 1
    rows = []
    row = ""
    for t in tlds:
        if len(row) + len(t) + 1 > 110:
            rows.append(row)
            row = ""
        row = f"{row} {t}" if row else t
    rows.append(row)
    body = "\n".join(rows)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write(
            f'"""IANA の TLD の一覧（{version}）。tools/update_tlds.py が作る（手で書き換えない）。"""\n\n'
            f'TLDS = frozenset("""\n{body}\n""".split())\n'  # black が変えない形
        )
    print(f"{OUT} に {len(tlds)} 個を書きました（{version}）")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""見出しが住所・氏名の列でも、プログラムの識別子・コードの断片の値は拾わない試験。

陽性対照: 英語・日本語の本物の住所・名前（こぶ1つの McDonald を含む）は今までどおり列見出しで拾う。
"""

from __future__ import annotations

import pytest

from pii_checker import detectors

HEADER_RULE = "列見出しが"


def _header_hits(value: str, header: str) -> list[detectors.Hit]:
    return [h for h in detectors.detect(value, header) if h.rule.startswith(HEADER_RULE)]


@pytest.mark.parametrize(
    "header,value",
    [
        ("Address", "AddressBookType"),
        ("Address", "ElectronicAddressProperties"),
        ("住所", "ContactAddressIndex"),
        ("name", "user_name"),
        ("name", "os.path.join"),
        ("name", "value = cookie_pair.split('='"),
        ("name", "'DisplayName'"),
        ("Name", "self.on_cookie(name"),
        ("Address", "{ street: x }"),
        ("name", "std::string"),
        ("name", "node->next"),
    ],
)
def test_code_like_values_not_header_hits(header, value):
    assert _header_hits(value, header) == []


@pytest.mark.parametrize(
    "header,value,kind",
    [
        ("Name", "Taro Yamada", "name"),
        ("Name", "McDonald", "name"),
        ("Name", "DeVito", "name"),
        ("Name", "YAMADA", "name"),
        ("Name", "O'Brien", "name"),
        ("氏名", "山田 太郎", "name"),
        ("Address", "9-9-9 Marunouchi, Chiyoda-ku", "address"),
        ("Address", "Tokyo", "address"),
        ("住所", "東京都千代田区丸の内9-9-9", "address"),
    ],
)
def test_real_values_still_header_hits(header, value, kind):
    """陽性対照: 本物の値は今までどおり拾う。"""
    assert [h.pii_type for h in _header_hits(value, header)] == [kind]

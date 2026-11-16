"""試験用の ZipCrypto（従来の PKWARE 暗号）の zip の書き手。

標準の zipfile は暗号化して書けないため、ヘッダーを手で組む。複数の試験から使う。
"""

from __future__ import annotations

import struct
import zlib


def _make_crc_table() -> list[int]:
    """CRC32（多項式 0xEDB88320）の1バイト分の表を作る。"""
    table = []
    for i in range(256):
        v = i
        for _ in range(8):
            v = (v >> 1) ^ 0xEDB88320 if v & 1 else v >> 1
        table.append(v)
    return table


_CRC_TABLE = _make_crc_table()


def _crc_byte(crc: int, b: int) -> int:
    return (crc >> 8) ^ _CRC_TABLE[(crc ^ b) & 0xFF]


def zipcrypto_zip(name: str, data: bytes, password: str | bytes) -> bytes:
    """中身1件を ZipCrypto・無圧縮で格納した zip を作る。

    password は str なら UTF-8 で符号化する。cp932 など別の符号化のパスワードを試すときは bytes で渡す。
    """
    keys = [0x12345678, 0x23456789, 0x34567890]

    def update(b: int) -> None:
        keys[0] = _crc_byte(keys[0], b)
        keys[1] = ((keys[1] + (keys[0] & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        keys[2] = _crc_byte(keys[2], (keys[1] >> 24) & 0xFF)

    for b in password.encode() if isinstance(password, str) else password:
        update(b)
    crc = zlib.crc32(data)
    # 暗号ヘッダー12バイト: 先頭11バイトは本来乱数だが、試験では結果を毎回同じにするため固定値。末尾は CRC の上位バイト（照合用）
    plain = bytes(range(11)) + bytes([crc >> 24]) + data
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

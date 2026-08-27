"""数据库解密 — SQLCipher 4 AES-256-CBC、页 HMAC 与 SQLite WAL 校验。"""

import hashlib
import hmac
import os
import struct

from Crypto.Cipher import AES


PAGE_SZ = 4096
KEY_SZ = 32
SALT_SZ = 16
RESERVE_SZ = 80  # IV(16) + HMAC-SHA512(64)
SQLITE_HDR = b"SQLite format 3\x00"
WAL_HEADER_SZ = 32
WAL_FRAME_HEADER_SZ = 24
_WAL_MAGIC_LITTLE = 0x377F0682
_WAL_MAGIC_BIG = 0x377F0683


def _derive_hmac_key(enc_key, database_salt):
    if len(enc_key) != KEY_SZ or len(database_salt) != SALT_SZ:
        raise ValueError("SQLCipher key 或 salt 长度无效")
    hmac_salt = bytes(value ^ 0x3A for value in database_salt)
    return hashlib.pbkdf2_hmac("sha512", enc_key, hmac_salt, 2, dklen=KEY_SZ)


def _verify_page_hmac(enc_key, database_salt, page_data, pgno):
    if len(page_data) != PAGE_SZ or pgno <= 0:
        raise ValueError("SQLCipher 页大小或页号无效")
    hmac_key = _derive_hmac_key(enc_key, database_salt)
    authenticated_end = PAGE_SZ - RESERVE_SZ + 16
    start = SALT_SZ if pgno == 1 else 0
    payload = page_data[start:authenticated_end] + struct.pack("<I", pgno)
    expected = hmac.new(hmac_key, payload, hashlib.sha512).digest()
    actual = page_data[authenticated_end:PAGE_SZ]
    if not hmac.compare_digest(expected, actual):
        raise ValueError(f"SQLCipher 第 {pgno} 页 HMAC 校验失败")


def decrypt_page(enc_key, database_salt, page_data, pgno):
    _verify_page_hmac(enc_key, database_salt, page_data, pgno)
    iv = page_data[PAGE_SZ - RESERVE_SZ: PAGE_SZ - RESERVE_SZ + 16]
    if pgno == 1:
        encrypted = page_data[SALT_SZ: PAGE_SZ - RESERVE_SZ]
        decrypted = AES.new(enc_key, AES.MODE_CBC, iv).decrypt(encrypted)
        return SQLITE_HDR + decrypted + b"\x00" * RESERVE_SZ
    encrypted = page_data[:PAGE_SZ - RESERVE_SZ]
    decrypted = AES.new(enc_key, AES.MODE_CBC, iv).decrypt(encrypted)
    return decrypted + b"\x00" * RESERVE_SZ


def full_decrypt(db_path, out_path, enc_key):
    file_size = os.path.getsize(db_path)
    if file_size == 0 or file_size % PAGE_SZ:
        raise ValueError("加密数据库大小不是完整 SQLCipher 页")
    total_pages = file_size // PAGE_SZ
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(db_path, "rb") as source, open(out_path, "wb") as destination:
        first_page = source.read(PAGE_SZ)
        database_salt = first_page[:SALT_SZ]
        destination.write(decrypt_page(enc_key, database_salt, first_page, 1))
        for pgno in range(2, total_pages + 1):
            page = source.read(PAGE_SZ)
            if len(page) != PAGE_SZ:
                raise ValueError("加密数据库读取到截断页")
            destination.write(decrypt_page(enc_key, database_salt, page, pgno))
    return total_pages


def _wal_checksum(data, byte_order, checksum=(0, 0)):
    if len(data) % 8:
        raise ValueError("WAL checksum 输入长度无效")
    values = struct.unpack(f"{byte_order}{len(data) // 4}I", data)
    s0, s1 = checksum
    for index in range(0, len(values), 2):
        s0 = (s0 + values[index] + s1) & 0xFFFFFFFF
        s1 = (s1 + values[index + 1] + s0) & 0xFFFFFFFF
    return s0, s1


def decrypt_wal(wal_path, out_path, enc_key, database_salt):
    if not os.path.exists(wal_path):
        return 0
    wal_size = os.path.getsize(wal_path)
    if wal_size <= WAL_HEADER_SZ:
        return 0
    with open(wal_path, "rb") as wal:
        header = wal.read(WAL_HEADER_SZ)
        magic, version, page_size = struct.unpack(">III", header[:12])
        if magic not in (_WAL_MAGIC_LITTLE, _WAL_MAGIC_BIG):
            raise ValueError("WAL magic 无效")
        if version != 3_007_000 or page_size != PAGE_SZ:
            raise ValueError("WAL 版本或页大小不受支持")
        byte_order = "<" if magic == _WAL_MAGIC_LITTLE else ">"
        checksum = _wal_checksum(header[:24], byte_order)
        if checksum != struct.unpack(">II", header[24:32]):
            raise ValueError("WAL header checksum 无效")
        salt = header[16:24]
        valid_frames = []
        last_commit_index = -1
        last_commit_size = 0
        frame_size = WAL_FRAME_HEADER_SZ + PAGE_SZ
        while wal.tell() + frame_size <= wal_size:
            frame_header = wal.read(WAL_FRAME_HEADER_SZ)
            page = wal.read(PAGE_SZ)
            pgno, database_size = struct.unpack(">II", frame_header[:8])
            if pgno == 0 or frame_header[8:16] != salt:
                break
            checksum = _wal_checksum(frame_header[:8], byte_order, checksum)
            checksum = _wal_checksum(page, byte_order, checksum)
            if checksum != struct.unpack(">II", frame_header[16:24]):
                break
            valid_frames.append((pgno, page))
            if database_size:
                last_commit_index = len(valid_frames) - 1
                last_commit_size = database_size

    if last_commit_index < 0:
        return 0
    patched = 0
    with open(out_path, "r+b") as database:
        for pgno, page in valid_frames[: last_commit_index + 1]:
            if pgno > last_commit_size:
                continue
            decrypted = decrypt_page(enc_key, database_salt, page, pgno)
            database.seek((pgno - 1) * PAGE_SZ)
            database.write(decrypted)
            patched += 1
        database.truncate(last_commit_size * PAGE_SZ)
    return patched

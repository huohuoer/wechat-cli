"""跨平台密钥候选校验、数据库首页收集与安全保存。"""

import hashlib
import hmac
import os
import struct

PAGE_SZ = 4096
KEY_SZ = 32
SALT_SZ = 16


def verify_enc_key(enc_key, db_page1):
    """SQLCipher 4 首页 HMAC-SHA512；短页和错误密钥不会被接受。"""
    if len(enc_key) != KEY_SZ or len(db_page1) != PAGE_SZ:
        return False
    salt = db_page1[:SALT_SZ]
    mac_salt = bytes(b ^ 0x3A for b in salt)
    mac_key = hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, 2, dklen=KEY_SZ)
    hm = hmac.new(mac_key, db_page1[SALT_SZ:PAGE_SZ - 64], hashlib.sha512)
    hm.update(struct.pack("<I", 1))
    return hmac.compare_digest(hm.digest(), db_page1[PAGE_SZ - 64:])


def collect_db_files(db_dir):
    """收集当前账号的完整加密首页，不跟随数据库符号链接。"""
    if not os.path.isdir(db_dir):
        raise ValueError("数据库目录不存在")
    db_files, salt_to_dbs = [], {}
    for root, dirs, files in os.walk(db_dir):
        dirs[:] = sorted(d for d in dirs if not os.path.islink(os.path.join(root, d)))
        for name in sorted(files):
            path = os.path.join(root, name)
            if not name.endswith(".db") or os.path.islink(path):
                continue
            size = os.path.getsize(path)
            if size < PAGE_SZ:
                continue
            with open(path, "rb") as handle:
                page = handle.read(PAGE_SZ)
            if len(page) != PAGE_SZ or page.startswith(b"SQLite format 3\x00"):
                continue
            rel = os.path.relpath(path, db_dir).replace("\\", "/")
            salt = page[:SALT_SZ].hex()
            db_files.append((rel, path, size, salt, page))
            salt_to_dbs.setdefault(salt, []).append(rel)
    return db_files, salt_to_dbs


def scan_memory_for_keys(data, hex_re, db_files, salt_to_dbs, key_map,
                         remaining_salts, base_addr, pid, print_fn):
    """传统 hex 候选扫描；不将候选、地址或账号信息输出到日志。"""
    matches = 0
    for match in hex_re.finditer(data):
        run = match.group(1)
        matches += 1
        if len(run) < 64 or len(run) % 2:
            continue
        candidate = bytes.fromhex(run[:64].decode())
        for _, _, _, salt, page in db_files:
            if salt in remaining_salts and verify_enc_key(candidate, page):
                key_map[salt] = candidate.hex()
                remaining_salts.discard(salt)
    return matches


def cross_verify_keys(db_files, salt_to_dbs, key_map, print_fn):
    """允许经各库独立 HMAC 验证的共享密钥。"""
    candidates = tuple(set(key_map.values()))
    for _, _, _, salt, page in db_files:
        if salt in key_map:
            continue
        for key in candidates:
            if verify_enc_key(bytes.fromhex(key), page):
                key_map[salt] = key
                break


def save_results(db_files, salt_to_dbs, key_map, output_path, print_fn):
    """重新逐库验证；output_path=None 时只返回，不保存秘密。"""
    from ..core.key_utils import private_write_json

    result, verified_map = {}, {}
    for rel, _, size, salt, page in db_files:
        value = key_map.get(salt)
        if value is not None and verify_enc_key(bytes.fromhex(value), page):
            verified_map[salt] = value
            result[rel] = {"enc_key": value, "salt": salt,
                           "size_mb": round(size / 1024 / 1024, 1)}
    print_fn(f"HMAC 验证通过: {len(result)}/{len(db_files)} 个数据库")
    if not result:
        raise RuntimeError("没有候选通过数据库首页 HMAC 验证；可能是权限、布局或账号不匹配")
    if output_path is not None:
        private_write_json(output_path, result)
        print_fn("已安全保存验证通过的密钥")
    return verified_map

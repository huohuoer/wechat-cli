"""
跨平台共享的内存扫描逻辑：HMAC 验证、DB 收集、hex 模式匹配与结果输出。

从 wechat-decrypt/key_scan_common.py 适配，save_results 改为返回 dict。
"""

import hashlib
import hmac as hmac_mod
import json
import os
import re
import struct

PAGE_SZ = 4096
KEY_SZ = 32
SALT_SZ = 16


def verify_enc_key(enc_key, db_page1):
    """通过 HMAC-SHA1 (新版) 或 HMAC-SHA512 (旧版) 校验 page 1 验证 enc_key 是否正确。

    微信 3.9+ 使用 HMAC-SHA1，更早版本使用 HMAC-SHA512。
    """
    salt = db_page1[:SALT_SZ]
    mac_salt = bytes(b ^ 0x3A for b in salt)

    # 尝试 HMAC-SHA1 (新版微信 3.9+, 包括 4.1.x)
    try:
        mac_key = hashlib.pbkdf2_hmac("sha1", enc_key, mac_salt, 64000, dklen=KEY_SZ)
        hmac_data = db_page1[SALT_SZ: PAGE_SZ - 32]
        stored_hmac = db_page1[PAGE_SZ - 32: PAGE_SZ - 12]
        hm = hmac_mod.new(mac_key, hmac_data, hashlib.sha1)
        hm.update(struct.pack("<I", 1))
        if hm.digest()[:20] == stored_hmac:
            return True
    except Exception:
        pass

    # 回退到 HMAC-SHA512 (旧版微信)
    try:
        mac_key = hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, 2, dklen=KEY_SZ)
        hmac_data = db_page1[SALT_SZ: PAGE_SZ - 80 + 16]
        stored_hmac = db_page1[PAGE_SZ - 64: PAGE_SZ]
        hm = hmac_mod.new(mac_key, hmac_data, hashlib.sha512)
        hm.update(struct.pack("<I", 1))
        return hm.digest() == stored_hmac
    except Exception:
        return False


def collect_db_files(db_dir):
    """遍历 db_dir 收集所有 .db 文件及其 salt。

    返回 (db_files, salt_to_dbs):
      db_files: [(rel_path, abs_path, size, salt_hex, page1_bytes), ...]
      salt_to_dbs: {salt_hex: [rel_path, ...]}
    """
    db_files = []
    salt_to_dbs = {}
    for root, dirs, files in os.walk(db_dir):
        for name in files:
            if not name.endswith(".db") or name.endswith("-wal") or name.endswith("-shm"):
                continue
            path = os.path.join(root, name)
            size = os.path.getsize(path)
            if size < PAGE_SZ:
                continue
            with open(path, "rb") as f:
                page1 = f.read(PAGE_SZ)
            rel = os.path.relpath(path, db_dir)
            salt = page1[:SALT_SZ].hex()
            db_files.append((rel, path, size, salt, page1))
            salt_to_dbs.setdefault(salt, []).append(rel)
    return db_files, salt_to_dbs


def scan_memory_for_keys(data, hex_re, db_files, salt_to_dbs, key_map,
                         remaining_salts, base_addr, pid, print_fn):
    """扫描一段内存数据，匹配 hex 模式并验证密钥。

    返回本次扫描匹配到的 hex 模式数量。
    """
    matches = 0
    for m in hex_re.finditer(data):
        hex_str = m.group(1).decode()
        addr = base_addr + m.start()
        matches += 1
        hex_len = len(hex_str)

        if hex_len == 96:
            enc_key_hex = hex_str[:64]
            salt_hex = hex_str[64:]
            if salt_hex in remaining_salts:
                enc_key = bytes.fromhex(enc_key_hex)
                for rel, path, sz, s, page1 in db_files:
                    if s == salt_hex and verify_enc_key(enc_key, page1):
                        key_map[salt_hex] = enc_key_hex
                        remaining_salts.discard(salt_hex)
                        dbs = salt_to_dbs[salt_hex]
                        print_fn(f"\n  [FOUND] salt={salt_hex}")
                        print_fn(f"    enc_key={enc_key_hex}")
                        print_fn(f"    PID={pid} 地址: 0x{addr:016X}")
                        print_fn(f"    数据库: {', '.join(dbs)}")
                        break

        elif hex_len == 64:
            if not remaining_salts:
                continue
            enc_key_hex = hex_str
            enc_key = bytes.fromhex(enc_key_hex)
            for rel, path, sz, salt_hex_db, page1 in db_files:
                if salt_hex_db in remaining_salts and verify_enc_key(enc_key, page1):
                    key_map[salt_hex_db] = enc_key_hex
                    remaining_salts.discard(salt_hex_db)
                    dbs = salt_to_dbs[salt_hex_db]
                    print_fn(f"\n  [FOUND] salt={salt_hex_db}")
                    print_fn(f"    enc_key={enc_key_hex}")
                    print_fn(f"    PID={pid} 地址: 0x{addr:016X}")
                    print_fn(f"    数据库: {', '.join(dbs)}")
                    break

        elif hex_len > 96 and hex_len % 2 == 0:
            enc_key_hex = hex_str[:64]
            salt_hex = hex_str[-32:]
            if salt_hex in remaining_salts:
                enc_key = bytes.fromhex(enc_key_hex)
                for rel, path, sz, s, page1 in db_files:
                    if s == salt_hex and verify_enc_key(enc_key, page1):
                        key_map[salt_hex] = enc_key_hex
                        remaining_salts.discard(salt_hex)
                        dbs = salt_to_dbs[salt_hex]
                        print_fn(f"\n  [FOUND] salt={salt_hex} (long hex {hex_len})")
                        print_fn(f"    enc_key={enc_key_hex}")
                        print_fn(f"    PID={pid} 地址: 0x{addr:016X}")
                        print_fn(f"    数据库: {', '.join(dbs)}")
                        break

    return matches


def cross_verify_keys(db_files, salt_to_dbs, key_map, print_fn):
    """用已找到的 key 交叉验证未匹配的 salt。"""
    missing_salts = set(salt_to_dbs.keys()) - set(key_map.keys())
    if not missing_salts or not key_map:
        return
    print_fn(f"\n还有 {len(missing_salts)} 个 salt 未匹配，尝试交叉验证...")
    for salt_hex in list(missing_salts):
        for rel, path, sz, s, page1 in db_files:
            if s == salt_hex:
                for known_salt, known_key_hex in key_map.items():
                    enc_key = bytes.fromhex(known_key_hex)
                    if verify_enc_key(enc_key, page1):
                        key_map[salt_hex] = known_key_hex
                        print_fn(f"  [CROSS] salt={salt_hex} 可用 key from salt={known_salt}")
                        missing_salts.discard(salt_hex)
                break


def save_results(db_files, salt_to_dbs, key_map, output_path, print_fn):
    """保存密钥结果到 JSON 文件。

    Args:
        db_files: collect_db_files 返回的 db_files
        salt_to_dbs: collect_db_files 返回的 salt_to_dbs
        key_map: {salt_hex: enc_key_hex}
        output_path: 输出 JSON 文件路径
        print_fn: 日志输出函数

    Returns:
        dict: salt_hex -> enc_key_hex 映射

    Raises:
        RuntimeError: 未提取到任何密钥
    """
    print_fn(f"\n{'=' * 60}")
    print_fn(f"结果: {len(key_map)}/{len(salt_to_dbs)} salts 找到密钥")

    result = {}
    for rel, path, sz, salt_hex, page1 in db_files:
        if salt_hex in key_map:
            result[rel] = {
                "enc_key": key_map[salt_hex],
                "salt": salt_hex,
                "size_mb": round(sz / 1024 / 1024, 1)
            }
            print_fn(f"  OK: {rel} ({sz / 1024 / 1024:.1f}MB)")
        else:
            print_fn(f"  MISSING: {rel} (salt={salt_hex})")

    if not result:
        print_fn(f"\n[!] 未提取到任何密钥")
        raise RuntimeError("未能从任何微信进程中提取到密钥")

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print_fn(f"\n密钥保存到: {output_path}")

    missing = [rel for rel, path, sz, salt_hex, page1 in db_files if salt_hex not in key_map]
    if missing:
        print_fn(f"\n未找到密钥的数据库:")
        for rel in missing:
            print_fn(f"  {rel}")

    return key_map

"""Windows 密钥提取 — 扫描 Weixin.exe 进程内存"""

import ctypes
import ctypes.wintypes as wt
import functools
import os
import re
import struct
import subprocess
import time

from .common import collect_db_files, scan_memory_for_keys, cross_verify_keys, save_results, KEY_SZ, verify_enc_key

print = functools.partial(print, flush=True)

kernel32 = ctypes.windll.kernel32
MEM_COMMIT = 0x1000
READABLE = {0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80}

# Windows 4.1+ Config.Cipher 扫描常量
WINDOWS_CONFIG_CIPHER_NAME = b"com.Tencent.WCDB.Config.Cipher"
WINDOWS_CONFIG_XOR_MASK = bytes.fromhex(
    "d2c7442458020000004889442450488b"
    "450048844c2448488944254048584c24"
)
WINDOWS_MAX_USER_ADDRESS = 0x0000_8000_0000_0000
WINDOWS_CONFIG_BLOB_MAX = 1024
WINDOWS_CONFIG_LITERAL_RE = re.compile(rb"[xX]'([0-9a-fA-F]{64,192})'")


class MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_uint64), ("AllocationBase", ctypes.c_uint64),
        ("AllocationProtect", wt.DWORD), ("_pad1", wt.DWORD),
        ("RegionSize", ctypes.c_uint64), ("State", wt.DWORD),
        ("Protect", wt.DWORD), ("Type", wt.DWORD), ("_pad2", wt.DWORD),
    ]


def _get_pids():
    """返回所有 Weixin.exe 进程的 (pid, mem_kb) 列表，按内存降序"""
    r = subprocess.run(["tasklist", "/FI", "IMAGENAME eq Weixin.exe", "/FO", "CSV", "/NH"],
                       capture_output=True, text=True)
    pids = []
    for line in r.stdout.strip().split('\n'):
        if not line.strip():
            continue
        p = line.strip('"').split('","')
        if len(p) >= 5:
            pid = int(p[1])
            mem = int(p[4].replace(',', '').replace(' K', '').strip() or '0')
            pids.append((pid, mem))
    if not pids:
        raise RuntimeError("Weixin.exe 未运行")
    pids.sort(key=lambda x: x[1], reverse=True)
    for pid, mem in pids:
        print(f"[+] Weixin.exe PID={pid} ({mem // 1024}MB)")
    return pids


def _read_mem(h, addr, sz):
    buf = ctypes.create_string_buffer(sz)
    n = ctypes.c_size_t(0)
    if kernel32.ReadProcessMemory(h, ctypes.c_uint64(addr), buf, sz, ctypes.byref(n)):
        return buf.raw[:n.value]
    return None


def _enum_regions(h):
    regs = []
    addr = 0
    mbi = MBI()
    while addr < 0x7FFFFFFFFFFF:
        if kernel32.VirtualQueryEx(h, ctypes.c_uint64(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
            break
        if mbi.State == MEM_COMMIT and mbi.Protect in READABLE and 0 < mbi.RegionSize < 500 * 1024 * 1024:
            regs.append((mbi.BaseAddress, mbi.RegionSize))
        nxt = mbi.BaseAddress + mbi.RegionSize
        if nxt <= addr:
            break
        addr = nxt
    return regs


def _xor_repeat(data, mask):
    """XOR 解码：用 mask 循环异或 data"""
    return bytes(value ^ mask[index % len(mask)] for index, value in enumerate(data))


def _u64_from(data, offset):
    """从 data 的 offset 位置读取小端 uint64"""
    if offset < 0 or offset + 8 > len(data):
        return 0
    return struct.unpack_from("<Q", data, offset)[0]


def _probable_32_byte_key(data):
    """判断是否可能是 32 字节密钥"""
    return len(data) == KEY_SZ and len(set(data)) >= 15 and data not in {b"\x00" * KEY_SZ, b"\xff" * KEY_SZ}


def _find_bytes_in_regions(regions, read_fn, needle):
    """在内存区域中查找字节串，返回所有匹配地址"""
    addresses = set()
    overlap = max(0, len(needle) - 1)
    for base, size in regions:
        offset = 0
        tail = b""
        tail_base = base
        chunk_size = 2 * 1024 * 1024

        while offset < size:
            current_size = min(chunk_size, size - offset)
            chunk = read_fn(base + offset, current_size) or b""
            data_base = tail_base if tail else base + offset
            data = tail + chunk

            if data:
                pos = data.find(needle)
                while pos >= 0:
                    addresses.add(data_base + pos)
                    pos = data.find(needle, pos + 1)

                if overlap:
                    tail = data[-overlap:]
                    tail_base = data_base + max(0, len(data) - len(tail))
                else:
                    tail = b""
                    tail_base = base + offset + current_size
            else:
                tail = b""
                tail_base = base + offset + current_size
            offset += current_size

    return addresses


def _windows_v411_config_key_candidates(blob):
    """从 Config.Cipher blob 中提取密钥候选"""
    if not blob or len(blob) > WINDOWS_CONFIG_BLOB_MAX:
        return []
    decoded = _xor_repeat(blob, WINDOWS_CONFIG_XOR_MASK)
    out = []
    seen = set()

    for match in WINDOWS_CONFIG_LITERAL_RE.finditer(decoded):
        run = match.group(1).decode("ascii").lower()
        starts = [0]
        if len(run) > 96:
            starts.extend(range(0, len(run) - 63, 32))
            starts.append(len(run) - 64)

        for start in dict.fromkeys(starts):
            if start < 0 or start + 64 > len(run):
                continue
            enc_key_hex = run[start:start + 64]
            try:
                enc_key = bytes.fromhex(enc_key_hex)
            except ValueError:
                continue
            if not _probable_32_byte_key(enc_key):
                continue

            embedded_salt = None
            if start + 96 <= len(run):
                embedded_salt = run[start + 64:start + 96]

            item = (enc_key_hex, embedded_salt)
            if item not in seen:
                seen.add(item)
                out.append(item)

    return out


def _verify_direct_key_candidate(enc_key_hex, embedded_salt, db_files, salt_to_dbs, key_map, remaining_salts):
    """验证单个密钥候选"""
    if not remaining_salts:
        return 0
    try:
        enc_key = bytes.fromhex(enc_key_hex)
    except ValueError:
        return 0
    if not _probable_32_byte_key(enc_key):
        return 0

    matched = 0
    target_salts = [embedded_salt] if embedded_salt in remaining_salts else list(remaining_salts)

    for salt_hex in target_salts:
        if salt_hex not in remaining_salts:
            continue
        for _rel, _path, _sz, s, page1 in db_files:
            if s == salt_hex and verify_enc_key(enc_key, page1):
                key_map[salt_hex] = enc_key_hex
                remaining_salts.discard(salt_hex)
                matched += 1
                break

    return matched


def _scan_config_cipher(pid, h, regions, db_files, salt_to_dbs, key_map, remaining_salts):
    """Windows 4.1+ Config.Cipher 扫描"""
    if not remaining_salts:
        return 0

    # 查找 Config.Cipher 名称字符串
    needle_addresses = _find_bytes_in_regions(regions, lambda addr, sz: _read_mem(h, addr, sz), WINDOWS_CONFIG_CIPHER_NAME)
    if not needle_addresses:
        return 0

    print(f"[*] Config.Cipher 扫描: 找到 {len(needle_addresses)} 个名称匹配")

    # 构建地址+长度对的字节模式
    pair_patterns = [
        struct.pack("<Q", addr) + struct.pack("<Q", len(WINDOWS_CONFIG_CIPHER_NAME))
        for addr in needle_addresses
    ]

    seen_config_ptrs = set()
    seen_candidates = set()
    matched_count = 0
    candidate_count = 0

    # 扫描内存区域查找指向 Config.Cipher 的引用
    for base, size in regions:
        if not remaining_salts:
            break

        data = _read_mem(h, base, size)
        if not data:
            continue

        for pattern in pair_patterns:
            pos = data.find(pattern)
            while pos >= 0:
                qaddr = base + pos
                node_base = qaddr - 0x10
                node = _read_mem(h, node_base, 0x50)
                if not node or len(node) < 0x40:
                    pos = data.find(pattern, pos + 1)
                    continue

                if _u64_from(node, 0x10) not in needle_addresses or _u64_from(node, 0x18) != len(WINDOWS_CONFIG_CIPHER_NAME):
                    pos = data.find(pattern, pos + 1)
                    continue

                config_ptr = _u64_from(node, 0x28)
                if not (0x10000 <= config_ptr < WINDOWS_MAX_USER_ADDRESS):
                    pos = data.find(pattern, pos + 1)
                    continue

                seen_config_ptrs.add(config_ptr)

                # 读取 Config 对象
                obj = _read_mem(h, config_ptr + 0x88, 0x28)
                if not obj or len(obj) < 0x18:
                    pos = data.find(pattern, pos + 1)
                    continue

                data_ptr = _u64_from(obj, 0x8)
                data_len = _u64_from(obj, 0x10)
                if not (0 < data_len <= WINDOWS_CONFIG_BLOB_MAX and 0x10000 <= data_ptr < WINDOWS_MAX_USER_ADDRESS):
                    pos = data.find(pattern, pos + 1)
                    continue

                blob = _read_mem(h, data_ptr, int(data_len))
                if not blob or len(blob) != data_len:
                    pos = data.find(pattern, pos + 1)
                    continue

                # 提取并验证密钥候选
                for enc_key_hex, embedded_salt in _windows_v411_config_key_candidates(blob):
                    candidate = (enc_key_hex, embedded_salt)
                    if candidate in seen_candidates:
                        continue
                    seen_candidates.add(candidate)
                    candidate_count += 1

                    matched = _verify_direct_key_candidate(
                        enc_key_hex, embedded_salt, db_files, salt_to_dbs,
                        key_map, remaining_salts
                    )
                    if matched:
                        matched_count += matched

                pos = data.find(pattern, pos + 1)

    if matched_count:
        print(f"[+] Config.Cipher 扫描匹配 {matched_count}/{len(salt_to_dbs)} salts (候选={candidate_count})")

    return matched_count



def extract_keys(db_dir, output_path, pid=None):
    """提取 Windows 微信数据库密钥。

    Args:
        db_dir: 微信数据库目录
        output_path: all_keys.json 输出路径
        pid: 可选，指定 PID（默认自动检测所有 Weixin.exe）

    Returns:
        dict: salt_hex -> enc_key_hex 映射
    """
    print("=" * 60)
    print("  提取所有微信数据库密钥")
    print("=" * 60)

    db_files, salt_to_dbs = collect_db_files(db_dir)

    print(f"\n找到 {len(db_files)} 个数据库, {len(salt_to_dbs)} 个不同的salt")
    for salt_hex, dbs in sorted(salt_to_dbs.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"  salt {salt_hex}: {', '.join(dbs)}")

    pids = _get_pids() if pid is None else [(pid, 0)]

    hex_re = re.compile(b"x'([0-9a-fA-F]{64,192})'")
    key_map = {}
    remaining_salts = set(salt_to_dbs.keys())
    all_hex_matches = 0
    t0 = time.time()

    # 优先尝试 Config.Cipher 扫描（Windows 4.1+）
    for pid_val, mem_kb in pids:
        if not remaining_salts:
            break

        h = kernel32.OpenProcess(0x0010 | 0x0400, False, pid_val)
        if not h:
            print(f"[WARN] 无法打开进程 PID={pid_val}，跳过")
            continue

        try:
            regions = _enum_regions(h)
            total_bytes = sum(s for _, s in regions)
            total_mb = total_bytes / 1024 / 1024
            print(f"\n[*] PID={pid_val} ({total_mb:.0f}MB, {len(regions)} 区域)")

            # 先尝试 Config.Cipher 扫描
            matched = _scan_config_cipher(pid_val, h, regions, db_files, salt_to_dbs, key_map, remaining_salts)
            if matched and not remaining_salts:
                print(f"[+] Config.Cipher 扫描已覆盖所有数据库")
                kernel32.CloseHandle(h)
                break

            # 如果还有剩余，回退到传统扫描
            if remaining_salts:
                print(f"[*] 传统内存扫描 (剩余 {len(remaining_salts)} salts)")
                scanned_bytes = 0
                for reg_idx, (base, size) in enumerate(regions):
                    data = _read_mem(h, base, size)
                    scanned_bytes += size
                    if not data:
                        continue

                    all_hex_matches += scan_memory_for_keys(
                        data, hex_re, db_files, salt_to_dbs,
                        key_map, remaining_salts, base, pid_val, print,
                    )

                    if (reg_idx + 1) % 200 == 0:
                        elapsed = time.time() - t0
                        progress = scanned_bytes / total_bytes * 100 if total_bytes else 100
                        print(
                            f"  [{progress:.1f}%] {len(key_map)}/{len(salt_to_dbs)} salts matched, "
                            f"{all_hex_matches} hex patterns, {elapsed:.1f}s"
                        )
        finally:
            kernel32.CloseHandle(h)

        if not remaining_salts:
            print(f"\n[+] 所有密钥已找到，跳过剩余进程")
            break

    elapsed = time.time() - t0
    print(f"\n扫描完成: {elapsed:.1f}s, {len(pids)} 个进程, {all_hex_matches} hex模式")

    cross_verify_keys(db_files, salt_to_dbs, key_map, print)
    return save_results(db_files, salt_to_dbs, key_map, output_path, print)

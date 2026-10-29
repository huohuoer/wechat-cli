"""Windows 密钥提取 — 扫描 Weixin.exe 进程内存。

支持两条路径：

1. 明文扫描（WeChat <= 4.1.8）：内存里直接有 `x'<key><salt>'` 的 ASCII 字面量。
2. 掩码扫描（WeChat 4.1+）：字面量还在，但整段被一个固定 32 字节掩码异或过，
   ASCII 的 `x'` 锚点因此消失，明文扫描命中数为 0。这里把锚点也按同样的掩码
   异或一遍再搜，解出来仍是同一个 `x'<key><salt>'` 格式。
"""

import ctypes
import ctypes.wintypes as wt
import functools
import os
import re
import subprocess
import time

from .common import (
    collect_db_files, scan_memory_for_keys, cross_verify_keys, save_results,
    verify_enc_key,
)

print = functools.partial(print, flush=True)

kernel32 = ctypes.windll.kernel32
MEM_COMMIT = 0x1000
READABLE = {0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80}

# --- WeChat 4.1+ 的 Config.Cipher 混淆掩码 ---
# 4.1+ 用这 32 个字节把 `x'<64 hex key><32 hex salt>'` 整段异或后再放进内存。
# 异或是可逆的，所以这不是加密，只是让按 "x'" 做字符串扫描的工具全部失效。
CIPHER_MASK = bytes.fromhex(
    "d2c7442458020000004889442450488b"
    "450048844c2448488944254048584c24"
)
# 一个完整的 96 字符字面量 + 引号约 100 字节，留足余量按同一相位往后解。
LITERAL_WINDOW = 220
LITERAL_RE = re.compile(rb"^[xX]'([0-9a-fA-F]{64,192})'")


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


def _masked_anchors():
    """32 个相位下，`x'` 两字节被掩码异或后的样子。"""
    n = len(CIPHER_MASK)
    return [
        (k, bytes([ord("x") ^ CIPHER_MASK[k], ord("'") ^ CIPHER_MASK[(k + 1) % n]]))
        for k in range(n)
    ]


def _decode_at(data, start, phase):
    n = len(CIPHER_MASK)
    window = data[start:start + LITERAL_WINDOW]
    return bytes(b ^ CIPHER_MASK[(phase + i) % n] for i, b in enumerate(window))


def _record_literal(run, addr, db_files, salt_to_dbs, key_map, remaining_salts, pid, print_fn):
    """把解出的 hex 串按 `key + salt` 拆开；HMAC 校验通过才记账。"""
    if len(run) < 96:
        return
    enc_key_hex = run[:64]
    salt_candidates = [run[64:96]]
    if len(run) > 96:
        salt_candidates.append(run[-32:])

    salt_hex = next((s for s in salt_candidates if s in remaining_salts), None)
    if salt_hex is None:
        return

    enc_key = bytes.fromhex(enc_key_hex)
    for rel, path, sz, s, page1 in db_files:
        if s != salt_hex:
            continue
        if verify_enc_key(enc_key, page1):
            key_map[salt_hex] = enc_key_hex
            remaining_salts.discard(salt_hex)
            print_fn(f"\n  [FOUND:masked] salt={salt_hex}")
            print_fn(f"    enc_key={enc_key_hex}")
            print_fn(f"    PID={pid} 地址: 0x{addr:016X}")
            print_fn(f"    数据库: {', '.join(salt_to_dbs[salt_hex])}")
        return


def scan_memory_for_masked_literals(data, base_addr, db_files, salt_to_dbs, key_map,
                                    remaining_salts, pid, print_fn):
    """扫描 WeChat 4.1+ 的掩码字面量，返回解出的字面量个数。

    只在两字节锚点命中处解码 + HMAC 校验，不逐字节枚举，所以额外开销很小
    （命中候选通常只有几十个）。
    """
    if not remaining_salts:
        return 0
    decoded_count = 0
    visited = set()
    for phase, anchor in _masked_anchors():
        pos = data.find(anchor)
        while pos >= 0:
            if pos not in visited:
                visited.add(pos)
                m = LITERAL_RE.match(_decode_at(data, pos, phase))
                if m:
                    decoded_count += 1
                    _record_literal(m.group(1).decode(), base_addr + pos, db_files,
                                    salt_to_dbs, key_map, remaining_salts, pid, print_fn)
            pos = data.find(anchor, pos + 1)
    return decoded_count


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
    masked_literals = 0
    t0 = time.time()

    for pid_val, mem_kb in pids:
        h = kernel32.OpenProcess(0x0010 | 0x0400, False, pid_val)
        if not h:
            print(f"[WARN] 无法打开进程 PID={pid_val}，跳过")
            continue

        try:
            regions = _enum_regions(h)
            total_bytes = sum(s for _, s in regions)
            total_mb = total_bytes / 1024 / 1024
            print(f"\n[*] 扫描 PID={pid_val} ({total_mb:.0f}MB, {len(regions)} 区域)")

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

                # 4.1+ 的字面量被异或过，明文扫描必然 0 命中，这里补第二遍。
                masked_literals += scan_memory_for_masked_literals(
                    data, base, db_files, salt_to_dbs,
                    key_map, remaining_salts, pid_val, print,
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
    print(f"\n扫描完成: {elapsed:.1f}s, {len(pids)} 个进程, "
          f"{all_hex_matches} 明文命中, {masked_literals} 掩码字面量")

    cross_verify_keys(db_files, salt_to_dbs, key_map, print)
    return save_results(db_files, salt_to_dbs, key_map, output_path, print)

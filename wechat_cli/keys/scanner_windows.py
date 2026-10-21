"""Windows 密钥提取 — Cipher 配置优先，传统 hex 扫描回退。"""

import ctypes
import os
import subprocess

from .common import collect_db_files, scan_memory_for_keys, cross_verify_keys, save_results
from .cipher_config import HEX_LITERAL_RE, iter_memory_chunks, quiet_log, scan_cipher_config

print = quiet_log
MEM_COMMIT = 0x1000
READABLE = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}


class MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_uint32),
        ("RegionSize", ctypes.c_size_t), ("State", ctypes.c_uint32),
        ("Protect", ctypes.c_uint32), ("Type", ctypes.c_uint32),
    ]


def _bind_kernel32():
    if os.name != "nt":
        return None
    lib = ctypes.WinDLL("kernel32", use_last_error=True)
    lib.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    lib.OpenProcess.restype = ctypes.c_void_p
    lib.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                     ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    lib.ReadProcessMemory.restype = ctypes.c_int
    lib.VirtualQueryEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(MBI),
                                  ctypes.c_size_t]
    lib.VirtualQueryEx.restype = ctypes.c_size_t
    lib.CloseHandle.argtypes = [ctypes.c_void_p]
    lib.CloseHandle.restype = ctypes.c_int
    return lib


kernel32 = _bind_kernel32()


def _get_pids():
    """返回所有 Weixin.exe 进程的 (pid, mem_kb)，按内存降序。"""
    result = subprocess.run(
        ["tasklist", "/FI", "IMAGENAME eq Weixin.exe", "/FO", "CSV", "/NH"],
        capture_output=True, text=True, check=True,
    )
    pids = []
    for line in result.stdout.splitlines():
        parts = line.strip('"').split('","')
        if len(parts) >= 5 and parts[1].isdigit():
            memory = int(parts[4].replace(',', '').replace(' K', '').strip() or '0')
            pids.append((int(parts[1]), memory))
    if not pids:
        raise RuntimeError("Weixin.exe 未运行")
    return sorted(pids, key=lambda item: item[1], reverse=True)


def _read_mem(handle, address, size):
    buf = ctypes.create_string_buffer(size)
    actual = ctypes.c_size_t()
    kernel32.ReadProcessMemory(handle, address, buf, size, ctypes.byref(actual))
    # ERROR_PARTIAL_COPY 仍可能返回有效前缀，精确对象读取另行检查长度。
    return buf.raw[:actual.value] if actual.value else None


def _enum_regions(handle):
    regions = []
    address = 0
    mbi = MBI()
    while address < 0x800000000000:
        if not kernel32.VirtualQueryEx(handle, address, ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        base = mbi.BaseAddress or 0
        if (mbi.State == MEM_COMMIT and not mbi.Protect & 0x100
                and mbi.Protect & 0xFF in READABLE and mbi.RegionSize > 0):
            regions.append((base, mbi.RegionSize))
        next_address = base + mbi.RegionSize
        if next_address <= address:
            break
        address = next_address
    return regions


def extract_keys(db_dir, output_path=None, pid=None, method="auto"):
    """返回已验证的 salt → hex key；output_path=None 由共享保存层处理。"""
    if method not in ("auto", "config", "legacy"):
        raise ValueError("Windows method 仅支持 auto/config/legacy")
    if kernel32 is None or ctypes.sizeof(ctypes.c_void_p) != 8:
        raise RuntimeError("Windows Cipher 扫描需要 64 位 Windows Python")
    if pid is not None and (not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0):
        raise ValueError("pid 必须为正整数")
    db_files, salt_to_dbs = collect_db_files(db_dir)
    if not db_files:
        raise RuntimeError("未找到可验证的 .db 文件")
    pids = _get_pids() if pid is None else [(pid, 0)]
    key_map = {}
    remaining_salts = set(salt_to_dbs)
    for pid_value, _ in pids:
        handle = kernel32.OpenProcess(0x0010 | 0x0400, False, pid_value)
        if not handle:
            print(f"[WARN] 无法只读打开 PID={pid_value}，跳过")
            continue
        try:
            regions = _enum_regions(handle)
            read = lambda address, size: _read_mem(handle, address, size)
            if method != "legacy":
                scan_cipher_config(read, regions, db_files, key_map, remaining_salts)
            if remaining_salts and method != "config":
                for base, data in iter_memory_chunks(read, regions):
                    scan_memory_for_keys(data, HEX_LITERAL_RE, db_files, salt_to_dbs,
                                         key_map, remaining_salts, base, pid_value, print)
                    if not remaining_salts:
                        break
        finally:
            kernel32.CloseHandle(handle)
        if not remaining_salts:
            break
    cross_verify_keys(db_files, salt_to_dbs, key_map, print)
    return save_results(db_files, salt_to_dbs, key_map, output_path, print)

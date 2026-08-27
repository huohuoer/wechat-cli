"""Linux 密钥提取 — 通过 /proc 读取微信进程内存"""

import functools
import os
import re
import sys
import time

from .common import collect_db_files, scan_memory_for_keys, cross_verify_keys, save_results

print = functools.partial(print, flush=True)


def _safe_readlink(path):
    try:
        return os.path.realpath(os.readlink(path))
    except OSError:
        return ""


_KNOWN_COMMS = {"wechat", "wechatappex", "weixin"}
_INTERPRETER_PREFIXES = ("python", "bash", "sh", "zsh", "node", "perl", "ruby")


def _is_wechat_process(pid):
    """检查 pid 是否为微信进程。"""
    if pid == os.getpid():
        return False
    try:
        with open(f"/proc/{pid}/comm") as f:
            comm = f.read().strip()
        if comm.lower() in _KNOWN_COMMS:
            return True
        exe_path = _safe_readlink(f"/proc/{pid}/exe")
        exe_name = os.path.basename(exe_path)
        if any(exe_name.lower().startswith(p) for p in _INTERPRETER_PREFIXES):
            return False
        return "wechat" in exe_name.lower() or "weixin" in exe_name.lower()
    except (PermissionError, FileNotFoundError, ProcessLookupError):
        return False


def _get_pids():
    """返回所有疑似微信主进程的 (pid, rss_kb) 列表，按内存降序。"""
    pids = []
    for pid_str in os.listdir("/proc"):
        if not pid_str.isdigit():
            continue
        pid = int(pid_str)
        try:
            if not _is_wechat_process(pid):
                continue
            with open(f"/proc/{pid}/statm") as f:
                rss_pages = int(f.read().split()[1])
            rss_kb = rss_pages * 4
            pids.append((pid, rss_kb))
        except (PermissionError, FileNotFoundError, ProcessLookupError):
            continue

    if not pids:
        raise RuntimeError("未检测到 Linux 微信进程")

    pids.sort(key=lambda item: item[1], reverse=True)
    for pid, rss_kb in pids:
        exe_path = _safe_readlink(f"/proc/{pid}/exe")
        print(f"[+] WeChat PID={pid} ({rss_kb // 1024}MB) {exe_path}")
    return pids


_SKIP_MAPPINGS = {"[vdso]", "[vsyscall]", "[vvar]"}
_SKIP_PATH_PREFIXES = ("/usr/lib/", "/lib/", "/usr/share/")


def _get_readable_regions(pid):
    """解析 /proc/<pid>/maps，返回可读内存区域列表。"""
    regions = []
    with open(f"/proc/{pid}/maps") as f:
        for line in f:
            parts = line.split()
            if len(parts) < 2:
                continue
            if "r" not in parts[1]:
                continue
            if len(parts) >= 6:
                mapping_name = parts[5]
                if mapping_name in _SKIP_MAPPINGS:
                    continue
                mapping_lower = mapping_name.lower()
                if (any(mapping_name.startswith(p) for p in _SKIP_PATH_PREFIXES)
                        and "wcdb" not in mapping_lower
                        and "wechat" not in mapping_lower
                        and "weixin" not in mapping_lower):
                    continue
            start_s, end_s = parts[0].split("-")
            start = int(start_s, 16)
            size = int(end_s, 16) - start
            if 0 < size < 500 * 1024 * 1024:
                regions.append((start, size))
    return regions


def _check_permissions():
    """检查是否有读取进程内存的权限。"""
    if os.geteuid() == 0:
        return
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("CapEff:"):
                    cap_eff = int(line.split(":")[1].strip(), 16)
                    CAP_SYS_PTRACE = 1 << 19
                    if cap_eff & CAP_SYS_PTRACE:
                        return
                    break
    except (OSError, ValueError):
        pass
    raise RuntimeError(
        "需要 root 权限或 CAP_SYS_PTRACE 才能读取进程内存\n"
        "请以普通用户运行 wechat-cli init，由工具单独提权扫描 helper"
    )


def extract_keys(db_dir, output_path, pid=None):
    """提取 Linux 微信数据库密钥。

    Args:
        db_dir: 微信数据库目录
        output_path: all_keys.json 输出路径
        pid: 可选，指定 PID（默认自动检测）

    Returns:
        dict: salt_hex -> enc_key_hex 映射
    """
    from .capabilities import require_supported_memory_scan

    require_supported_memory_scan()
    _check_permissions()

    print("=" * 60)
    print("  提取 Linux 微信数据库密钥（内存扫描）")
    print("=" * 60)

    db_files, salt_to_dbs = collect_db_files(db_dir)
    if not db_files:
        raise RuntimeError(f"在 {db_dir} 未找到可解密的 .db 文件")

    print(f"\n找到 {len(db_files)} 个数据库, {len(salt_to_dbs)} 个不同的 salt")
    for salt_hex, dbs in sorted(salt_to_dbs.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"  salt {salt_hex}: {', '.join(dbs)}")

    pids = _get_pids() if pid is None else [(pid, 0)]

    hex_re = re.compile(rb"x'([0-9a-fA-F]{64,192})'")
    key_map = {}
    remaining_salts = set(salt_to_dbs.keys())
    all_hex_matches = 0
    t0 = time.time()

    for pid_val, rss_kb in pids:
        try:
            regions = _get_readable_regions(pid_val)
        except PermissionError:
            print(f"[WARN] 无法读取 /proc/{pid_val}/maps，权限不足，跳过")
            continue
        except (FileNotFoundError, ProcessLookupError):
            print(f"[WARN] PID {pid_val} 已退出，跳过")
            continue

        total_bytes = sum(s for _, s in regions)
        total_mb = total_bytes / 1024 / 1024
        print(f"\n[*] 扫描 PID={pid_val} ({total_mb:.0f}MB, {len(regions)} 区域)")

        scanned_bytes = 0
        try:
            mem = open(f"/proc/{pid_val}/mem", "rb")
        except PermissionError:
            print(f"[WARN] 无法打开 /proc/{pid_val}/mem，权限不足，跳过")
            continue
        except (FileNotFoundError, ProcessLookupError):
            print(f"[WARN] PID {pid_val} 已退出，跳过")
            continue

        if not _is_wechat_process(pid_val):
            print(f"[WARN] PID {pid_val} 已不是微信进程，跳过")
            mem.close()
            continue

        try:
            for reg_idx, (base, size) in enumerate(regions):
                try:
                    mem.seek(base)
                    data = mem.read(size)
                except (OSError, ValueError):
                    continue
                scanned_bytes += len(data)

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
            mem.close()

        if not remaining_salts:
            print(f"\n[+] 所有密钥已找到，跳过剩余进程")
            break

    elapsed = time.time() - t0
    print(f"\n扫描完成: {elapsed:.1f}s, {len(pids)} 个进程, {all_hex_matches} hex 模式")

    cross_verify_keys(db_files, salt_to_dbs, key_map, print)
    return save_results(db_files, salt_to_dbs, key_map, output_path, print)

"""按平台选择显式提取方法；查询不会自动调用这里。"""

import platform


def extract_keys(db_dir, output_path=None, pid=None, method="auto", timeout=120):
    system = platform.system().lower()
    if system == "darwin":
        from .scanner_macos import extract_keys as extract
        if method not in ("auto", "config", "memory", "frida"):
            raise ValueError("macOS 支持 auto/config；Frida 需独立安全路由，目前未支持")
        return extract(db_dir, output_path, pid=pid,
                       method="memory" if method == "config" else method, timeout=timeout)
    if system == "windows":
        from .scanner_windows import extract_keys as extract
        if method not in ("auto", "config", "legacy"):
            raise ValueError("Windows 仅支持 auto/config/legacy")
        return extract(db_dir, output_path, pid=pid, method=method)
    if system == "linux":
        from .scanner_linux import extract_keys as extract
        if method not in ("auto", "legacy", "gdb"):
            raise ValueError("Linux 仅支持 auto/legacy/gdb；不会自动调用调试器")
        return extract(db_dir, output_path, pid=pid,
                       method="gdb" if method == "gdb" else "memory", timeout=timeout)
    raise RuntimeError(f"不支持的平台: {platform.system()}")

#!/usr/bin/env python3
"""使用 PyInstaller 构建当前主机的独立可执行文件。"""

import importlib.util
import os
import platform as host_platform
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
NPM_DIR = ROOT / "npm"
PLATFORMS_DIR = NPM_DIR / "platforms"

PLATFORM_MAP = {
    "darwin-arm64": {"target": "macos"},
    "darwin-x64": {"target": "macos"},
    "linux-x64": {"target": "linux"},
    "linux-arm64": {"target": "linux"},
    "win32-x64": {"target": "win"},
}


def current_platform():
    system = {"Darwin": "darwin", "Linux": "linux", "Windows": "win32"}.get(
        host_platform.system(), host_platform.system().lower()
    )
    machine = host_platform.machine().lower()
    arch = {"x86_64": "x64", "amd64": "x64", "aarch64": "arm64"}.get(machine, machine)
    return f"{system}-{arch}"


def ensure_pyinstaller():
    if importlib.util.find_spec("PyInstaller") is None:
        raise RuntimeError("缺少 PyInstaller，请先在构建环境安装 wechat-cli[build]；不会自动安装依赖")


def build_platform(platform: str):
    if platform not in PLATFORM_MAP or platform != current_platform():
        print(f"[-] 仅能构建当前主机 {current_platform()}，不能构建 {platform}")
        return False
    ensure_pyinstaller()
    ext = ".exe" if platform.startswith("win32-") else ""
    binary_name = f"wechat-cli{ext}"
    output_dir = PLATFORMS_DIR / platform / "bin"
    output_dir.mkdir(parents=True, exist_ok=True)
    print(f"[+] 正在构建 {platform}...")
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--name", "wechat-cli",
        "--distpath", str(output_dir),
        "--workpath", str(ROOT / "build" / f"wechat-cli_{platform}"),
        "--specpath", str(ROOT / "build"),
        "--noconfirm",
        "--clean",
    ]

    # 只捆绑源码和配置，不复用旧预编译 arm64 helper；新版编译及签名由探针负责。
    for directory, patterns in (
        ("bin", ("*.c", "*.plist")),
        ("keys", ("*.js", "*.plist")),
    ):
        resource_dir = ROOT / "wechat_cli" / directory
        for pattern in patterns:
            for resource in sorted(resource_dir.glob(pattern)):
                cmd.extend(["--add-data", f"{resource}{os.pathsep}wechat_cli/{directory}"])

    for module in ("Crypto", "zstandard"):
        cmd.extend(["--hidden-import", module])
    # 可选 Frida 包含原生扩展和运行资源；查询构建无需安装它。
    if importlib.util.find_spec("frida") is not None:
        cmd.extend(["--collect-all", "frida"])
    cmd.append(str(ROOT / "entry.py"))
    print(f"[+] 执行: {' '.join(cmd)}")
    try:
        subprocess.check_call(cmd, cwd=str(ROOT))
    except subprocess.CalledProcessError as e:
        print(f"[-] {platform} 构建失败: {e}")
        return False
    binary_path = output_dir / binary_name
    if not binary_path.exists():
        print(f"[-] 未找到可执行文件: {binary_path}")
        return False
    print(f"[+] 已构建: {binary_path}")
    print(f"    大小: {binary_path.stat().st_size / 1024 / 1024:.1f} MB")
    return True


def main():
    platforms = sys.argv[1:] or [current_platform()]
    if any(p not in PLATFORM_MAP or p != current_platform() for p in platforms):
        print(f"[-] PyInstaller 只能构建当前主机: {current_platform()}")
        sys.exit(1)
    try:
        ensure_pyinstaller()
    except RuntimeError as e:
        print(f"[-] {e}")
        sys.exit(1)
    results = {p: build_platform(p) for p in platforms}
    print("\n构建汇总:")
    for p, ok in results.items():
        print(f"  {p}: {'成功' if ok else '失败'}")
    if not all(results.values()):
        sys.exit(1)


if __name__ == "__main__":
    main()

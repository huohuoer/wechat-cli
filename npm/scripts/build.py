#!/usr/bin/env python3
"""Build wechat-cli standalone binaries with PyInstaller."""

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
NPM_DIR = ROOT / "npm"
PLATFORMS_DIR = NPM_DIR / "platforms"

PLATFORM_MAP = {
    "darwin-arm64":  {"target": "macos"},
    "darwin-x64":    {"target": "macos"},
    "linux-x64":     {"target": "linux"},
    "linux-arm64":   {"target": "linux"},
    "win32-x64":     {"target": "win"},
}


def current_platform():
    import platform as host

    system = host.system().lower()
    machine = host.machine().lower()
    if system == "darwin":
        return "darwin-arm64" if machine == "arm64" else "darwin-x64"
    if system == "windows" and machine in {"amd64", "x86_64"}:
        return "win32-x64"
    if system == "linux":
        return "linux-arm64" if machine in {"arm64", "aarch64"} else "linux-x64"
    raise RuntimeError(f"Unsupported build host: {system}-{machine}")


def build_macos_scanner(platform):
    source = ROOT / "wechat_cli" / "bin" / "find_all_keys_macos.c"
    arch = "arm64" if platform == "darwin-arm64" else "x86_64"
    output_dir = ROOT / "build" / "native" / platform
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / f"find_all_keys_macos.{arch}"
    subprocess.check_call([
        "/usr/bin/clang", "-O2", "-arch", arch, str(source),
        "-framework", "Foundation", "-o", str(output),
    ])
    payload = output.read_bytes()
    if b"[REDACTED]" not in payload or b"%-25s %-66s %s" in payload:
        output.unlink(missing_ok=True)
        raise RuntimeError("macOS scanner failed the redaction artifact gate")
    return output


def ensure_pyinstaller():
    try:
        import PyInstaller  # noqa: F401
        return
    except ImportError:
        pass
    print("[+] Installing PyInstaller...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])


def build_platform(platform: str):
    host_platform = current_platform()
    if platform != host_platform:
        print(f"[-] Refusing cross-labelled build: host={host_platform}, target={platform}")
        return False
    os_name, arch = platform.split("-")
    ext = ".exe" if os_name == "win32" else ""
    binary_name = f"wechat-cli{ext}"

    output_dir = PLATFORMS_DIR / platform / "bin"
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*60}")
    print(f"Building for {platform}...")
    print(f"{'='*60}")

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

    # macOS scanner must be rebuilt from the current source on the matching host.
    if os_name == "darwin":
        try:
            scanner = build_macos_scanner(platform)
        except (OSError, subprocess.CalledProcessError, RuntimeError) as error:
            print(f"[-] macOS scanner build/gate failed: {error}")
            return False
        cmd.extend(["--add-binary", f"{scanner}:wechat_cli/bin"])

    # Hidden imports
    hidden = ["pysqlcipher3", "sqlcipher3", "Cryptodome", "zstandard"]
    for h in hidden:
        cmd.extend(["--hidden-import", h])

    cmd.append(str(ROOT / "entry.py"))

    print(f"[+] Running: {' '.join(cmd)}")

    try:
        subprocess.check_call(cmd, cwd=str(ROOT))
    except subprocess.CalledProcessError as e:
        print(f"[-] Build failed for {platform}: {e}")
        return False

    binary_path = output_dir / binary_name
    if not binary_path.exists():
        print(f"[-] Binary not found: {binary_path}")
        return False

    print(f"[+] Built: {binary_path}")
    print(f"    Size: {binary_path.stat().st_size / 1024 / 1024:.1f} MB")
    return True


def main():
    if len(sys.argv) > 1:
        platforms = sys.argv[1:]
    else:
        # Default: build for current platform only
        try:
            platforms = [current_platform()]
        except RuntimeError as error:
            print(error)
            print(f"Usage: {sys.argv[0]} [platform...]")
            print(f"  Platforms: {', '.join(PLATFORM_MAP.keys())}")
            sys.exit(1)

    print(f"[+] Building for: {', '.join(platforms)}")
    unknown = [name for name in platforms if name not in PLATFORM_MAP]
    if unknown:
        print(f"[-] Unknown platform(s): {', '.join(unknown)}")
        sys.exit(1)
    host_platform = current_platform()
    if any(name != host_platform for name in platforms):
        print(f"[-] Refusing cross-labelled build: host={host_platform}, targets={platforms}")
        sys.exit(1)
    ensure_pyinstaller()

    results = {}
    for p in platforms:
        if p not in PLATFORM_MAP:
            print(f"[-] Unknown platform: {p}")
            results[p] = False
            continue
        results[p] = build_platform(p)

    print(f"\n{'='*60}")
    print("Build Summary:")
    for p, ok in results.items():
        status = "OK" if ok else "FAILED"
        print(f"  {p}: {status}")
    print(f"{'='*60}")

    if not all(results.values()):
        sys.exit(1)


if __name__ == "__main__":
    main()

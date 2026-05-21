#!/usr/bin/env python3
"""Build wechat-cli standalone binaries with PyInstaller."""

import os
import shutil
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


def ensure_pyinstaller():
    try:
        import PyInstaller  # noqa: F401
        return
    except ImportError:
        pass
    print("[+] Installing PyInstaller...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])


def clear_macos_xattrs(path: Path):
    if sys.platform != "darwin":
        return
    subprocess.run(
        ["xattr", "-cr", str(path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )


def build_platform(platform: str):
    info = PLATFORM_MAP[platform]
    os_name, arch = platform.split("-")
    ext = ".exe" if os_name == "win32" else ""
    binary_name = f"wechat-cli{ext}"

    output_dir = PLATFORMS_DIR / platform / "bin"
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*60}")
    print(f"Building for {platform}...")
    print(f"{'='*60}")

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onedir",
        "--name", "wechat-cli",
        "--distpath", str(output_dir),
        "--workpath", str(ROOT / "build" / f"wechat-cli_{platform}"),
        "--specpath", str(ROOT / "build"),
        "--noconfirm",
        "--clean",
    ]

    # Bundle C binaries for key extraction
    bin_dir = ROOT / "wechat_cli" / "bin"
    if bin_dir.exists():
        for f in bin_dir.iterdir():
            if not f.name.startswith(".") and f.is_file():
                cmd.extend(["--add-binary", f"{f}:wechat_cli/bin"])

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

    bundle_dir = output_dir / "wechat-cli"
    binary_path = bundle_dir / binary_name
    if not binary_path.exists():
        print(f"[-] Binary not found: {binary_path}")
        return False

    # Keep the npm package contract stable: platform packages expose
    # bin/wechat-cli, with PyInstaller's support files next to it.
    flattened_bundle_dir = output_dir / "_pyinstaller_bundle"
    if flattened_bundle_dir.exists():
        shutil.rmtree(flattened_bundle_dir)
    bundle_dir.rename(flattened_bundle_dir)
    for item in flattened_bundle_dir.iterdir():
        shutil.move(str(item), str(output_dir / item.name))
    flattened_bundle_dir.rmdir()
    binary_path = output_dir / binary_name
    clear_macos_xattrs(output_dir)

    print(f"[+] Built: {binary_path}")
    bundle_size = sum(p.stat().st_size for p in output_dir.rglob("*") if p.is_file())
    print(f"    Bundle size: {bundle_size / 1024 / 1024:.1f} MB")
    return True


def main():
    if len(sys.argv) > 1:
        platforms = sys.argv[1:]
    else:
        # Default: build for current platform only
        import platform as _pf
        current = f"{_pf.system().lower()}-{_pf.machine()}"
        # Normalize
        if current == "darwin-arm64":
            platforms = ["darwin-arm64"]
        elif current == "darwin-x86_64" or current == "darwin-amd64":
            platforms = ["darwin-x64"]
        else:
            # Try to match
            platforms = []
            for p in PLATFORM_MAP:
                os_name, arch = p.split("-")
                if os_name in current and (arch in current or
                    (arch == "x64" and ("x86_64" in current or "amd64" in current))):
                    platforms = [p]
                    break
            if not platforms:
                print(f"Cannot determine platform from '{current}'")
                print(f"Usage: {sys.argv[0]} [platform...]")
                print(f"  Platforms: {', '.join(PLATFORM_MAP.keys())}")
                sys.exit(1)

    print(f"[+] Building for: {', '.join(platforms)}")
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

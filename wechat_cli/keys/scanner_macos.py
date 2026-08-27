"""macOS 密钥提取 — 通过 C 二进制扫描微信进程内存"""

import os
import platform
import subprocess
import sys
import tempfile

from ..core.key_document import JsonDatabaseKeyProvider, validate_key_document
from ..core.secure_files import read_private_json, redact_sensitive_text


def _find_binary():
    """查找对应架构的 C 二进制。"""
    machine = platform.machine()
    if machine == "arm64":
        name = "find_all_keys_macos.arm64"
    elif machine == "x86_64":
        name = "find_all_keys_macos.x86_64"
    else:
        raise RuntimeError(f"不支持的 macOS 架构: {machine}")

    # PyInstaller 运行时：从临时解压目录查找
    if getattr(sys, 'frozen', False):
        base = sys._MEIPASS
    else:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    bin_path = os.path.join(base, "wechat_cli", "bin", name)
    if os.path.isfile(bin_path):
        return bin_path

    # fallback: 直接在 bin/ 下
    bin_path = os.path.join(base, "bin", name)
    if os.path.isfile(bin_path):
        return bin_path

    raise RuntimeError(
        f"找不到密钥提取二进制: {bin_path}\n"
        "请确认安装包完整"
    )


def extract_keys(db_dir, output_path, pid=None):
    """通过 C 二进制提取 macOS 微信数据库密钥。

    C 二进制只扫描显式 db_storage，并写入私有临时输出。

    Args:
        db_dir: 微信 db_storage 目录
        output_path: all_keys.json 输出路径
        pid: 可选微信进程 PID（默认由 C 二进制自动检测）

    Returns:
        dict: salt_hex -> enc_key_hex 映射
    """
    from .capabilities import require_supported_memory_scan

    require_supported_memory_scan()
    binary = _find_binary()
    with open(binary, "rb") as stream:
        binary_bytes = stream.read()
    if b"[REDACTED]" not in binary_bytes or b"%-25s %-66s %s" in binary_bytes:
        raise RuntimeError("macOS 扫描器版本不安全；请安装由当前源码重建的脱敏二进制")

    db_dir = os.path.realpath(db_dir)
    if not os.path.isdir(db_dir) or os.path.islink(db_dir):
        raise RuntimeError(f"微信数据目录不存在或不安全: {db_dir}")

    print(f"[+] 使用 C 二进制提取密钥: {binary}")
    with tempfile.TemporaryDirectory(prefix="wechat-cli-native-scan-") as native_dir:
        native_output = os.path.join(native_dir, "all_keys.json")
        try:
            command = [binary, "--db-dir", db_dir, "--output", native_output]
            if pid is not None:
                command.extend(["--pid", str(pid)])
            result = subprocess.run(
                command,
                cwd=native_dir,
                capture_output=True,
                text=True,
                timeout=120,
                preexec_fn=lambda: os.umask(0o077),
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("密钥提取超时（120s）") from None
        except PermissionError:
            raise RuntimeError(
                f"无法执行 {binary}\n"
                "请确保文件有执行权限: chmod +x " + binary
            ) from None

        # 临时输出只能在私有目录存活期间读取和迁移。
        if result.stdout:
            print(redact_sensitive_text(result.stdout))
        if result.stderr:
            print(redact_sensitive_text(result.stderr), file=sys.stderr)

        combined_output = (result.stdout or "") + (result.stderr or "")
        if "task_for_pid" in combined_output:
            raise RuntimeError(
                "task_for_pid 被 macOS 拒绝；wechat-cli 不会自动重签 WeChat.app。"
                "请由管理员评估并显式处理调试权限后重试"
            )
        if result.returncode != 0:
            raise RuntimeError("C 二进制扫描失败；请检查上方已脱敏的扫描诊断")
        if not os.path.isfile(native_output):
            raise RuntimeError(
                "C 二进制未能生成密钥文件；请检查上方已脱敏的扫描诊断"
            )
        keys_data = validate_key_document(read_private_json(native_output), "原生扫描结果")
        JsonDatabaseKeyProvider(output_path).replace(keys_data)

    # 构建 salt -> key 映射
    key_map = {}
    for rel, info in keys_data.items():
        if isinstance(info, dict) and "enc_key" in info and "salt" in info:
            key_map[info["salt"]] = info["enc_key"]

    print(f"\n[+] 提取到 {len(key_map)} 个密钥，保存到: {output_path}")
    return key_map

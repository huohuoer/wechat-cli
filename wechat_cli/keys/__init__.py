"""密钥提取模块 — 根据平台调用对应的 scanner。"""

import json
import os
import platform
import subprocess
import sys

from ..core.key_document import validate_key_document
from ..core.secure_files import redact_sensitive_text
from .capabilities import require_supported_memory_scan


def extract_keys(db_dir, output_path, pid=None):
    """提取微信数据库密钥并保存到 output_path。

    Args:
        db_dir: 微信数据库目录（db_storage）
        output_path: all_keys.json 输出路径
        pid: 可选，指定微信进程 PID（默认自动检测）

    Returns:
        dict: salt_hex -> enc_key_hex 的映射

    Raises:
        RuntimeError: 提取失败
    """
    require_supported_memory_scan()
    system = platform.system().lower()
    if system == "darwin":
        from .scanner_macos import extract_keys as _extract
        return _extract(db_dir, output_path, pid=pid)
    elif system == "windows":
        from .scanner_windows import extract_keys as _extract
        return _extract(db_dir, output_path, pid=pid)
    elif system == "linux":
        from .scanner_linux import extract_keys as _extract
        return _extract(db_dir, output_path, pid=pid)
    else:
        raise RuntimeError(f"不支持的平台: {platform.system()}")


def extract_keys_for_init(db_dir):
    """以最小权限提取密钥，返回经过校验的密钥文档但不负责持久化。"""
    require_supported_memory_scan()
    system = platform.system().lower()
    if system == "windows":
        from tempfile import TemporaryDirectory

        from ..core.secure_files import read_private_json

        with TemporaryDirectory(prefix="wechat-cli-scan-") as temp_dir:
            output_path = os.path.join(temp_dir, "all_keys.json")
            extract_keys(db_dir, output_path)
            return validate_key_document(read_private_json(output_path), "扫描结果")

    if system not in {"darwin", "linux"}:
        raise RuntimeError(f"不支持的平台: {platform.system()}")
    if hasattr(os, "geteuid") and os.geteuid() == 0 and os.environ.get("SUDO_USER"):
        raise RuntimeError("请以普通用户运行 wechat-cli init；工具会仅为内存扫描请求 sudo")

    sudo_path = "/usr/bin/sudo"
    if not os.path.isfile(sudo_path):
        raise RuntimeError("找不到 /usr/bin/sudo，无法启动最小权限扫描 helper")

    if getattr(sys, "frozen", False):
        command = [sudo_path, "--", sys.executable, "_elevated-scan-helper", db_dir]
    else:
        command = [
            sudo_path, "--", sys.executable, "-m",
            "wechat_cli.keys.elevated_helper", db_dir,
        ]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("提权扫描超时") from None

    diagnostic = redact_sensitive_text(result.stderr or "").strip()
    if diagnostic:
        print(diagnostic, file=sys.stderr)
    if result.returncode != 0:
        raise RuntimeError("提权扫描失败；请检查上方已脱敏诊断")
    try:
        document = json.loads(result.stdout)
    except json.JSONDecodeError:
        raise RuntimeError("提权扫描返回了无效结果") from None
    return validate_key_document(document, "提权扫描结果")

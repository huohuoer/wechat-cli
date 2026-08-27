"""私有状态文件：严格权限、原子替换和无密钥诊断。"""

import json
import os
import re
import stat
import tempfile
from subprocess import run as _run


PRIVATE_DIR_MODE = 0o700
PRIVATE_FILE_MODE = 0o600
_SECRET_PATTERNS = (
    re.compile(r"(?i)(enc_key\s*[=:]\s*)[0-9a-f]{64,192}"),
    re.compile(r"(?i)(\"enc_key\"\s*:\s*\")[0-9a-f]{64,192}(\")"),
    re.compile(r"(?i)x'[0-9a-f]{64,192}'"),
    re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{64,192}(?![0-9a-f])"),
)


def redact_sensitive_text(value):
    """删除诊断文本中的数据库密钥，不改变非敏感上下文。"""
    if not value:
        return value
    redacted = value
    redacted = _SECRET_PATTERNS[0].sub(r"\1[REDACTED]", redacted)
    redacted = _SECRET_PATTERNS[1].sub(r"\1[REDACTED]\2", redacted)
    redacted = _SECRET_PATTERNS[2].sub("x'[REDACTED]'", redacted)
    redacted = _SECRET_PATTERNS[3].sub("[REDACTED]", redacted)
    return redacted


def ensure_private_directory(path, *, tighten_existing=False):
    """创建私有目录；只在调用方明确拥有目录时收紧既有权限。"""
    if os.path.lexists(path) and os.path.islink(path):
        raise PermissionError(f"私有状态目录不能是符号链接: {path}")
    existed = os.path.isdir(path)
    os.makedirs(path, mode=PRIVATE_DIR_MODE, exist_ok=True)
    if not existed or tighten_existing:
        if os.name == "nt":
            _secure_windows_acl(path, is_directory=True)
        else:
            info = os.lstat(path)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
                raise PermissionError(f"私有状态目录不属于当前用户: {path}")
            os.chmod(path, PRIVATE_DIR_MODE)


def assert_private_file(path):
    """POSIX 上拒绝读取 group/other 可访问的敏感文件。"""
    if not os.path.exists(path):
        return
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode):
        raise PermissionError(f"敏感文件必须是普通文件且不能是符号链接: {path}")
    if os.name == "nt":
        return
    if info.st_uid != os.geteuid():
        raise PermissionError(f"敏感文件必须是当前用户拥有的普通文件: {path}")
    mode = info.st_mode & 0o777
    if mode & 0o077:
        raise PermissionError(
            f"敏感文件权限过宽: {path} (mode {mode:03o})；请执行 chmod 600"
        )


def _windows_system_binary(name):
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    return os.path.join(system_root, "System32", name)


def _windows_current_user_sid():
    result = _run(
        [_windows_system_binary("whoami.exe"), "/user", "/fo", "csv", "/nh"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if result.returncode != 0:
        raise PermissionError("无法解析当前 Windows 用户 SID")
    match = re.search(r'"(S-[0-9-]+)"', result.stdout)
    if not match:
        raise PermissionError("当前 Windows 用户 SID 格式无效")
    return match.group(1)


def _secure_windows_acl(path, *, is_directory):
    if os.name != "nt":
        return
    sid = _windows_current_user_sid()
    suffix = ":(OI)(CI)F" if is_directory else ":F"
    result = _run(
        [
            _windows_system_binary("icacls.exe"),
            os.path.abspath(path),
            "/inheritance:r",
            "/grant:r",
            f"*{sid}{suffix}",
            f"*S-1-5-18{suffix}",
            f"*S-1-5-32-544{suffix}",
        ],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    if result.returncode != 0:
        raise PermissionError("无法收紧 Windows 私有状态 ACL")


def atomic_write_bytes(path, data):
    """在私有目录中写临时文件，fsync 后原子替换目标。"""
    parent = os.path.dirname(os.path.abspath(path))
    ensure_private_directory(parent)
    fd, temp_path = tempfile.mkstemp(prefix=f".{os.path.basename(path)}.", dir=parent)
    try:
        if os.name != "nt":
            os.fchmod(fd, PRIVATE_FILE_MODE)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name == "nt":
            # ACL 必须在换入前成功；否则调用失败但活动文件已经改变。
            _secure_windows_acl(temp_path, is_directory=False)
        os.replace(temp_path, path)
        if os.name != "nt":
            directory_fd = os.open(parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def atomic_write_json(path, value):
    """以 UTF-8、稳定缩进和私有权限原子写入 JSON。"""
    payload = json.dumps(value, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
    atomic_write_bytes(path, payload)


def read_private_json(path):
    """检查权限后读取 JSON；解析错误不会回显含密钥的源行。"""
    assert_private_file(path)
    try:
        with open(path, encoding="utf-8") as stream:
            return json.load(stream)
    except json.JSONDecodeError as error:
        raise ValueError(
            f"敏感 JSON 无效: {path}，第 {error.lineno} 行第 {error.colno} 列"
        ) from None

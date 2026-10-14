"""密钥格式、路径校验和私有文件保存。"""

import json
import ntpath
import os
import posixpath
import shutil
import subprocess
import tempfile


def strip_key_metadata(keys):
    if not isinstance(keys, dict):
        raise ValueError("密钥文件必须是 JSON 对象")
    return {k: v for k, v in keys.items() if not k.startswith("_")}


def _is_safe_rel_path(path):
    if not isinstance(path, str) or not path or "\x00" in path:
        return False
    normalized = path.replace("\\", "/")
    return (not ntpath.splitdrive(normalized)[0]
            and not normalized.startswith("/")
            and ".." not in normalized.split("/")
            and posixpath.normpath(normalized) not in (".", ""))


def key_path_variants(rel_path):
    normalized = rel_path.replace("\\", "/")
    return list(dict.fromkeys((rel_path, normalized, normalized.replace("/", "\\"),
                               normalized.replace("/", os.sep))))


def get_key_info(keys, rel_path):
    if not _is_safe_rel_path(rel_path):
        return None
    for candidate in key_path_variants(rel_path):
        if candidate in keys and not candidate.startswith("_"):
            return keys[candidate]
    return None


def normalize_keys(keys):
    """兼容 enc_key 简版与带 salt 的完整元数据；导入时另行验证当前首页。"""
    result = {}
    for path, info in strip_key_metadata(keys).items():
        if not _is_safe_rel_path(path) or not path.lower().endswith(".db"):
            raise ValueError("密钥文件包含非法数据库相对路径")
        key = info.get("enc_key") if isinstance(info, dict) else None
        try:
            raw = bytes.fromhex(key) if isinstance(key, str) and len(key) == 64 else b""
        except ValueError:
            raw = b""
        if len(raw) != 32:
            raise ValueError("密钥文件包含非法的 32 字节 enc_key")
        normalized = posixpath.normpath(path.replace("\\", "/"))
        if normalized in result and result[normalized]["enc_key"] != raw.hex():
            raise ValueError("同一数据库路径存在冲突密钥")
        result[normalized] = {"enc_key": raw.hex()}
        salt = info.get("salt")
        if salt is not None:
            try:
                raw_salt = bytes.fromhex(salt) if isinstance(salt, str) and len(salt) == 32 else b""
            except ValueError:
                raw_salt = b""
            if len(raw_salt) != 16:
                raise ValueError("密钥元数据的 salt 必须为 16 字节")
            result[normalized]["salt"] = raw_salt.hex()
    return result


def load_keys(path):
    path = os.path.abspath(os.path.expanduser(os.fspath(path)))
    if os.path.islink(path):
        raise ValueError("拒绝读取符号链接密钥文件")
    try:
        with open(path, encoding="utf-8") as handle:
            return normalize_keys(json.load(handle))
    except json.JSONDecodeError:
        raise ValueError("密钥文件 JSON 格式无效") from None


def validate_keys(keys, db_dir):
    """只读首页 HMAC；返回可用密钥和无内容覆盖计数。"""
    from ..keys.common import collect_db_files, verify_enc_key

    normalized = normalize_keys(keys)
    db_files, _ = collect_db_files(db_dir)
    valid = {}
    rejected = 0
    for rel, _, size, salt, page in db_files:
        info = get_key_info(normalized, rel)
        if not info:
            continue
        if verify_enc_key(bytes.fromhex(info["enc_key"]), page):
            valid[rel.replace("\\", "/")] = {
                "enc_key": info["enc_key"], "salt": salt,
                "size_mb": round(size / 1024 / 1024, 1),
            }
        else:
            rejected += 1
    return valid, {"database_count": len(db_files), "valid_count": len(valid),
                   "invalid_count": rejected, "missing_count": len(db_files) - len(valid)}


def _restrict_file(path):
    if os.name == "nt":
        # 在写入秘密之前移除继承 ACL，只保留当前 Windows 登录身份。
        identity = subprocess.run(["whoami"], capture_output=True, text=True, check=True).stdout.strip()
        if not identity:
            raise RuntimeError("无法确定 Windows 当前身份")
        subprocess.run(["icacls", path, "/inheritance:r", "/grant:r", f"{identity}:(F)"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    else:
        os.chmod(path, 0o600)


def private_write_json(path, data, backup=True):
    """私有临时文件、旧文件备份、原子替换；失败保留原文件。"""
    path = os.path.abspath(os.path.expanduser(os.fspath(path)))
    parent = os.path.dirname(path)
    os.makedirs(parent, mode=0o700, exist_ok=True)
    if os.path.islink(path) or os.path.islink(parent):
        raise ValueError("拒绝写入符号链接目标")
    temporary = None
    backup_temp = None
    try:
        fd, temporary = tempfile.mkstemp(prefix=".wechat-", dir=parent)
        os.close(fd)
        _restrict_file(temporary)
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        if backup and os.path.exists(path):
            backup_path = path + ".bak"
            if os.path.islink(backup_path):
                raise ValueError("拒绝写入符号链接备份")
            fd, backup_temp = tempfile.mkstemp(prefix=".wechat-backup-", dir=parent)
            os.close(fd)
            _restrict_file(backup_temp)
            with open(path, "rb") as source, open(backup_temp, "wb") as target:
                shutil.copyfileobj(source, target)
                target.flush()
                os.fsync(target.fileno())
            os.replace(backup_temp, backup_path)
            backup_temp = None
        os.replace(temporary, path)
        temporary = None
    finally:
        for leftover in (temporary, backup_temp):
            if leftover is not None:
                os.unlink(leftover)

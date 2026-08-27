"""受信 helper 密钥文档的数据库页绑定校验。"""

from ..core.key_document import validate_key_document
from .common import collect_db_files, verify_enc_key


def verify_imported_key_document(db_dir, document):
    """只保留能被目标数据库首页 HMAC 证明的条目。"""
    document = validate_key_document(document, "stdin 密钥文档")
    db_files, _salt_to_dbs = collect_db_files(db_dir)
    by_path = {}
    for rel_path, _path, size, salt, page1 in db_files:
        normalized = rel_path.replace("\\", "/")
        if normalized in by_path:
            raise ValueError("[WXCLI_IMPORT_DB_AMBIGUOUS] 数据库相对路径发生冲突")
        by_path[normalized] = (rel_path, size, salt, page1)

    verified = {}
    seen = set()
    for supplied_path, info in document.items():
        normalized = supplied_path.replace("\\", "/")
        if normalized in seen:
            raise ValueError("[WXCLI_IMPORT_DUPLICATE_PATH] 密钥文档包含重复数据库路径")
        seen.add(normalized)
        target = by_path.get(normalized)
        if target is None:
            raise ValueError(
                f"[WXCLI_IMPORT_DB_NOT_FOUND] 密钥条目没有对应数据库: {supplied_path!r}"
            )
        rel_path, size, actual_salt, page1 = target
        if info.get("salt") is not None and info["salt"].lower() != actual_salt:
            raise ValueError(
                f"[WXCLI_IMPORT_SALT_MISMATCH] 数据库 salt 不匹配: {supplied_path!r}"
            )
        enc_key = bytes.fromhex(info["enc_key"])
        if not verify_enc_key(enc_key, page1):
            raise ValueError(
                f"[WXCLI_IMPORT_HMAC_FAILED] 数据库页校验失败: {supplied_path!r}"
            )
        verified[rel_path] = {
            "enc_key": info["enc_key"].lower(),
            "salt": actual_salt,
            "size_mb": round(size / 1024 / 1024, 1),
        }
    return verified

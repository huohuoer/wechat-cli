"""状态 generation、初始化锁和原子切换。"""

import contextlib
import os
import re
import shutil
import tempfile
import time
import uuid

from .secure_files import atomic_write_json, ensure_private_directory, read_private_json


_GENERATION_RE = re.compile(r"^[0-9a-f]{32}$")


def _generation_root(state_dir):
    return os.path.join(state_dir, "generations")


def active_pointer_path(state_dir):
    return os.path.join(state_dir, "active.json")


def resolve_active_generation(state_dir):
    pointer = active_pointer_path(state_dir)
    if not os.path.exists(pointer):
        return None
    document = read_private_json(pointer)
    generation = document.get("generation") if isinstance(document, dict) else None
    if not isinstance(generation, str) or not _GENERATION_RE.fullmatch(generation):
        raise ValueError("active.json 包含无效 generation")
    root = os.path.realpath(_generation_root(state_dir))
    candidate = os.path.realpath(os.path.join(root, generation))
    if os.path.commonpath((root, candidate)) != root or not os.path.isdir(candidate):
        raise ValueError("active.json 指向无效 generation")
    return candidate


def resolve_config_path(state_dir, legacy_path):
    generation = resolve_active_generation(state_dir)
    if generation:
        config_path = os.path.join(generation, "config.json")
        if not os.path.isfile(config_path):
            raise ValueError("活动 generation 缺少 config.json")
        return config_path
    return legacy_path


@contextlib.contextmanager
def state_lock(state_dir, timeout=10):
    """跨平台独占锁；超时失败关闭。"""
    ensure_private_directory(state_dir, tighten_existing=True)
    path = os.path.join(state_dir, ".state.lock")
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    if os.name != "nt":
        os.fchmod(descriptor, 0o600)
    deadline = time.monotonic() + timeout
    acquired = False
    try:
        while not acquired:
            try:
                if os.name == "nt":
                    import msvcrt

                    os.lseek(descriptor, 0, os.SEEK_SET)
                    if os.fstat(descriptor).st_size == 0:
                        os.write(descriptor, b"0")
                        os.fsync(descriptor)
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
            except OSError:
                if time.monotonic() >= deadline:
                    raise TimeoutError("另一个 wechat-cli 状态事务仍在运行") from None
                time.sleep(0.05)
        yield
    finally:
        if acquired:
            if os.name == "nt":
                import msvcrt

                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def commit_generation(state_dir, config, key_document, backend=None):
    """完整物化新 generation 后，以单文件原子切换激活。"""
    from .key_document import validate_key_document

    key_document = validate_key_document(key_document, "初始化密钥文档")
    generation_root = _generation_root(state_dir)
    ensure_private_directory(generation_root)
    generation_id = uuid.uuid4().hex
    pending = tempfile.mkdtemp(prefix=f".{generation_id}.", dir=generation_root)
    final = os.path.join(generation_root, generation_id)
    try:
        ensure_private_directory(pending, tighten_existing=True)
        from .key_document import create_key_provider, select_default_key_backend

        backend = backend or select_default_key_backend()
        key_path = os.path.join(pending, "all_keys.json")
        provider = create_key_provider(key_path, backend=backend, namespace=generation_id)
        provider.replace(key_document)
        generation_config = dict(config)
        generation_config["keys_file"] = "all_keys.json"
        generation_config["generation"] = generation_id
        generation_config["key_backend"] = backend
        if backend == "secret-service":
            generation_config["key_namespace"] = generation_id
        atomic_write_json(os.path.join(pending, "config.json"), generation_config)

        # 完整读回后才允许换入。
        if set(provider.references()) != set(key_document):
            raise ValueError("密钥后端读回条目不完整")
        for rel_path in key_document:
            if provider.resolve(rel_path) != key_document[rel_path]:
                raise ValueError("密钥后端读回校验失败")
        read_private_json(os.path.join(pending, "config.json"))
        os.replace(pending, final)
        atomic_write_json(
            active_pointer_path(state_dir),
            {"version": 1, "generation": generation_id},
        )
        return final
    finally:
        if os.path.isdir(pending):
            shutil.rmtree(pending)

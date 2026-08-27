"""解密数据库缓存 — 稳定快照、进程租约和退出清理。"""

import hashlib
import os
import re
import shutil
import time
import uuid

from .crypto import decrypt_wal, full_decrypt
from .key_document import DatabaseKeyProvider
from .key_utils import _is_safe_rel_path
from .secure_files import ensure_private_directory


_RUN_DIR_RE = re.compile(r"^run-[0-9]+-[0-9a-f]{32}$")
_SNAPSHOT_ATTEMPTS = 3


def _lock_descriptor(descriptor, *, nonblocking):
    if os.name == "nt":
        import msvcrt

        os.lseek(descriptor, 0, os.SEEK_SET)
        if os.fstat(descriptor).st_size == 0:
            os.write(descriptor, b"0")
            os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        mode = msvcrt.LK_NBLCK if nonblocking else msvcrt.LK_LOCK
        msvcrt.locking(descriptor, mode, 1)
    else:
        import fcntl

        mode = fcntl.LOCK_EX | (fcntl.LOCK_NB if nonblocking else 0)
        fcntl.flock(descriptor, mode)


def _unlock_descriptor(descriptor):
    if os.name == "nt":
        import msvcrt

        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(descriptor, fcntl.LOCK_UN)


def _source_signature(path):
    try:
        stat = os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if os.path.islink(path) or not os.path.isfile(path):
        raise ValueError("数据库源必须是普通文件且不能是符号链接")
    return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)


def _cleanup_stale_runs(cache_root):
    for name in os.listdir(cache_root):
        if not _RUN_DIR_RE.fullmatch(name):
            continue
        run_dir = os.path.join(cache_root, name)
        if os.path.islink(run_dir) or not os.path.isdir(run_dir):
            continue
        lease_path = os.path.join(run_dir, ".lease")
        try:
            descriptor = os.open(lease_path, os.O_CREAT | os.O_RDWR, 0o600)
        except OSError:
            continue
        acquired = False
        closed = False
        try:
            _lock_descriptor(descriptor, nonblocking=True)
            acquired = True
            if os.name == "nt":
                # UUID 运行目录不会被复用；确认无人持锁后可先关闭再删除。
                _unlock_descriptor(descriptor)
                os.close(descriptor)
                closed = True
            shutil.rmtree(run_dir)
        except OSError:
            pass
        finally:
            if acquired and not closed:
                _unlock_descriptor(descriptor)
            if not closed:
                os.close(descriptor)


class DBCache:
    def __init__(self, key_provider: DatabaseKeyProvider, db_dir, state_dir):
        self._key_provider = key_provider
        self._db_dir = os.path.realpath(db_dir)
        self._cache = {}  # rel_key -> (db_sig, wal_sig, key_digest, tmp_path)
        cache_root = os.path.join(state_dir, "cache")
        ensure_private_directory(cache_root, tighten_existing=True)
        _cleanup_stale_runs(cache_root)
        self._cache_dir = os.path.join(
            cache_root, f"run-{os.getpid()}-{uuid.uuid4().hex}"
        )
        os.mkdir(self._cache_dir, 0o700)
        self._lease_descriptor = os.open(
            os.path.join(self._cache_dir, ".lease"), os.O_CREAT | os.O_RDWR, 0o600
        )
        _lock_descriptor(self._lease_descriptor, nonblocking=False)

    def _cache_path(self, rel_key):
        digest = hashlib.sha256(rel_key.encode()).hexdigest()[:24]
        return os.path.join(self._cache_dir, f"{digest}.db")

    def _source_paths(self, rel_key):
        if not _is_safe_rel_path(rel_key):
            raise ValueError("数据库相对路径不安全")
        rel_path = rel_key.replace("\\", "/").replace("/", os.sep)
        db_path = os.path.realpath(os.path.join(self._db_dir, rel_path))
        try:
            contained = os.path.commonpath((self._db_dir, db_path)) == self._db_dir
        except ValueError:
            contained = False
        if not contained:
            raise ValueError("数据库路径越出配置目录")
        return db_path, db_path + "-wal"

    def _stable_snapshot(self, db_path, wal_path, token):
        snapshot_db = os.path.join(self._cache_dir, f".{token}.encrypted-db")
        snapshot_wal = os.path.join(self._cache_dir, f".{token}.encrypted-wal")
        for attempt in range(_SNAPSHOT_ATTEMPTS):
            before_db = _source_signature(db_path)
            before_wal = _source_signature(wal_path)
            if before_db is None:
                return None
            try:
                shutil.copyfile(db_path, snapshot_db)
                if before_wal is not None:
                    shutil.copyfile(wal_path, snapshot_wal)
                elif os.path.exists(snapshot_wal):
                    os.remove(snapshot_wal)
                after_db = _source_signature(db_path)
                after_wal = _source_signature(wal_path)
                if before_db == after_db and before_wal == after_wal:
                    return (
                        snapshot_db,
                        snapshot_wal if before_wal is not None else None,
                        before_db,
                        before_wal,
                    )
            except FileNotFoundError:
                pass
            if attempt + 1 < _SNAPSHOT_ATTEMPTS:
                time.sleep(0.05)
        for path in (snapshot_db, snapshot_wal):
            try:
                os.remove(path)
            except FileNotFoundError:
                pass
        raise RuntimeError("数据库或 WAL 持续变化，无法取得一致快照；请稍后重试")

    def get(self, rel_key):
        key_info = self._key_provider.resolve(rel_key)
        if not key_info:
            return None
        db_path, wal_path = self._source_paths(rel_key)
        try:
            db_sig = _source_signature(db_path)
            wal_sig = _source_signature(wal_path)
        except OSError:
            return None
        if db_sig is None:
            return None

        enc_key = bytes.fromhex(key_info["enc_key"])
        key_digest = hashlib.sha256(enc_key).digest()
        if rel_key in self._cache:
            cached_db, cached_wal, cached_key, cached_path = self._cache[rel_key]
            if (
                cached_db == db_sig
                and cached_wal == wal_sig
                and cached_key == key_digest
                and os.path.exists(cached_path)
            ):
                return cached_path

        tmp_path = self._cache_path(rel_key)
        token = hashlib.sha256((rel_key + uuid.uuid4().hex).encode()).hexdigest()[:24]
        snapshot = self._stable_snapshot(db_path, wal_path, token)
        if snapshot is None:
            return None
        snapshot_db, snapshot_wal, db_sig, wal_sig = snapshot
        try:
            with open(snapshot_db, "rb") as source:
                database_salt = source.read(16)
            configured_salt = key_info.get("salt")
            if configured_salt and database_salt.hex() != configured_salt.lower():
                raise ValueError("数据库 salt 与密钥引用不匹配")
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            descriptor = os.open(tmp_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
            full_decrypt(snapshot_db, tmp_path, enc_key)
            if snapshot_wal:
                decrypt_wal(snapshot_wal, tmp_path, enc_key, database_salt)
        except Exception:
            try:
                os.remove(tmp_path)
            except OSError:
                pass
            raise
        finally:
            for path in (snapshot_db, snapshot_wal):
                if path:
                    try:
                        os.remove(path)
                    except FileNotFoundError:
                        pass
        self._cache[rel_key] = (db_sig, wal_sig, key_digest, tmp_path)
        return tmp_path

    def cleanup(self):
        self._cache.clear()
        descriptor = getattr(self, "_lease_descriptor", None)
        if descriptor is not None:
            _unlock_descriptor(descriptor)
            os.close(descriptor)
            self._lease_descriptor = None
        if os.path.isdir(self._cache_dir):
            shutil.rmtree(self._cache_dir)

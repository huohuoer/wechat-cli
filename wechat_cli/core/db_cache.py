"""私有解密缓存 — 按数据库目录、密钥集和每库身份隔离。"""

import hashlib
import json
import ntpath
import os
import stat
import tempfile

from .crypto import PAGE_SZ, SALT_SZ, full_decrypt, decrypt_wal
from .key_utils import get_key_info


def _digest(value):
    encoded = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    return hashlib.sha256(encoded).hexdigest()


def _private_directory(path):
    os.makedirs(path, mode=0o700, exist_ok=True)
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode) or (hasattr(os, 'getuid') and st.st_uid != os.getuid()):
        raise ValueError("缓存目录不是当前用户拥有的真实目录")
    os.chmod(path, 0o700)


def _private_file(path):
    try:
        st = os.lstat(path)
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
                or (hasattr(os, 'getuid') and st.st_uid != os.getuid())):
            return False
        os.chmod(path, 0o600)
        return True
    except OSError:
        return False


class DBCache:
    CACHE_DIR = os.path.join(os.path.expanduser('~'), '.cache', 'wechat-cli')

    def __init__(self, all_keys, db_dir):
        self._all_keys = all_keys
        self._db_dir = os.path.realpath(db_dir)
        self._cache_root = os.path.abspath(self.CACHE_DIR)
        self._identity = None
        self._cache = {}
        _private_directory(self._cache_root)
        self._set_namespace()

    def _set_namespace(self):
        keyset = {
            name: {field: info.get(field) for field in ('enc_key', 'salt')}
            for name, info in self._all_keys.items()
            if not name.startswith('_') and isinstance(info, dict)
        }
        identity = _digest([self._db_dir, keyset])
        if identity == self._identity:
            return
        self._identity = identity
        self.CACHE_DIR = os.path.join(self._cache_root, identity)
        self.MTIME_FILE = os.path.join(self.CACHE_DIR, '_mtimes.json')
        _private_directory(self.CACHE_DIR)
        self._cache = {}
        self._load_persistent_cache()

    def _db_path(self, rel_key):
        if not isinstance(rel_key, str) or not rel_key or '\x00' in rel_key:
            raise ValueError("数据库路径必须为非空相对路径")
        normalized = rel_key.replace('\\', '/')
        parts = normalized.split('/')
        if ntpath.splitdrive(normalized)[0] or normalized.startswith('/') or any(
            part in ('', '.', '..') for part in parts
        ):
            raise ValueError("数据库路径不能为绝对路径或包含路径穿越")
        path = os.path.realpath(os.path.join(self._db_dir, *parts))
        if os.path.commonpath([self._db_dir, path]) != self._db_dir:
            raise ValueError("数据库路径超出配置目录")
        wal_path = path + '-wal'
        if os.path.lexists(wal_path) and os.path.realpath(wal_path) != wal_path:
            raise ValueError("WAL 路径不能为符号链接")
        return path

    def _cache_path(self, rel_key, fingerprint):
        return os.path.join(self.CACHE_DIR, _digest([rel_key, fingerprint]) + '.db')

    def _load_persistent_cache(self):
        if not _private_file(self.MTIME_FILE):
            return
        try:
            with open(self.MTIME_FILE, encoding='utf-8') as f:
                saved = json.load(f)
            if not isinstance(saved, dict) or saved.get('version') != 2:
                return
            entries = saved.get('entries')
            if not isinstance(entries, dict):
                return
            self._cache = {
                name: fingerprint for name, fingerprint in entries.items()
                if isinstance(name, str) and isinstance(fingerprint, str)
                and len(fingerprint) == 64
                and all(ch in '0123456789abcdef' for ch in fingerprint)
            }
        except (ValueError, OSError):
            return

    def _save_persistent_cache(self):
        temporary = None
        try:
            _private_directory(self.CACHE_DIR)
            fd, temporary = tempfile.mkstemp(prefix='.metadata-', dir=self.CACHE_DIR)
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump({'version': 2, 'entries': self._cache}, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temporary, self.MTIME_FILE)
        except OSError:
            pass  # 元数据持久化失败不影响已校验的数据库。
        finally:
            if temporary and os.path.exists(temporary):
                os.unlink(temporary)

    @staticmethod
    def _stamp(path):
        st = os.stat(path)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError("数据库或 WAL 不是普通文件")
        return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns

    def _source_fingerprint(self, db_path, key_info, enc_key):
        db_stamp = self._stamp(db_path)
        with open(db_path, 'rb') as f:
            first_page = f.read(PAGE_SZ)
        if len(first_page) != PAGE_SZ:
            raise ValueError("数据库首页长度无效")
        salt = first_page[:SALT_SZ].hex()
        expected_salt = key_info.get('salt')
        if expected_salt is not None and bytes.fromhex(expected_salt).hex() != salt:
            raise ValueError("数据库 salt 已变化，请重新提取密钥")
        wal_path = db_path + '-wal'
        try:
            wal_stamp = self._stamp(wal_path)
        except FileNotFoundError:
            wal_stamp = None
        return _digest([
            enc_key.hex(), expected_salt, salt, hashlib.sha256(first_page).hexdigest(),
            db_stamp, wal_stamp,
        ])

    def get(self, rel_key):
        db_path = self._db_path(rel_key)
        self._set_namespace()
        key_info = get_key_info(self._all_keys, rel_key)
        if not key_info:
            return None
        enc_key = bytes.fromhex(key_info['enc_key'])
        try:
            fingerprint = self._source_fingerprint(db_path, key_info, enc_key)
        except FileNotFoundError:
            return None
        # 不信任持久化文件中的任何路径，只从当前身份生成目标文件名。
        path = self._cache_path(rel_key, fingerprint)
        _private_directory(self.CACHE_DIR)
        if self._cache.get(rel_key) == fingerprint and _private_file(path):
            return path

        fd, temporary = tempfile.mkstemp(prefix='.database-', dir=self.CACHE_DIR)
        os.close(fd)
        try:
            full_decrypt(db_path, temporary, enc_key)
            decrypt_wal(db_path + '-wal', temporary, enc_key)
            if self._source_fingerprint(db_path, key_info, enc_key) != fingerprint:
                raise ValueError("数据库或 WAL 在缓存构建期间发生变化，请重试")
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        self._cache[rel_key] = fingerprint
        self._save_persistent_cache()
        return path

    def cleanup(self):
        self._save_persistent_cache()

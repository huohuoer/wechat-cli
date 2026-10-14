"""只使用临时目录与合成 SQLCipher/WAL 数据，不访问微信。"""

import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import tempfile
import unittest
from unittest import mock

from Crypto.Cipher import AES

from wechat_cli.core import crypto
from wechat_cli.core.db_cache import DBCache

ROOT = Path(__file__).resolve().parents[1]
KEY = bytes(range(32))
SALT = bytes(range(16))


def encrypted_page(pgno, marker=b'A', key=KEY, salt=SALT):
    """生成符合 SQLCipher 4 布局的加密页与期望明文。"""
    start = crypto.SALT_SZ if pgno == 1 else 0
    plaintext = marker * (crypto.PAGE_SZ - crypto.RESERVE_SZ - start)
    iv = bytes([pgno % 256]) * 16
    ciphertext = AES.new(key, AES.MODE_CBC, iv).encrypt(plaintext)
    mac_salt = bytes(b ^ 0x3a for b in salt)
    mac_key = hashlib.pbkdf2_hmac('sha512', key, mac_salt, 2, dklen=32)
    mac = hmac.new(mac_key, ciphertext + iv + struct.pack('<I', pgno), hashlib.sha512).digest()
    encrypted = (salt if pgno == 1 else b'') + ciphertext + iv + mac
    plain = (crypto.SQLITE_HDR if pgno == 1 else b'') + plaintext + b'\x00' * 80
    return encrypted, plain


def checksum(data, byte_order, seed=(0, 0)):
    """独立生成 SQLite 官方滚动校验和，避免调用被测实现。"""
    values = struct.unpack(byte_order + 'I' * (len(data) // 4), data)
    s1, s2 = seed
    for i in range(0, len(values), 2):
        s1 = (s1 + values[i] + s2) % (1 << 32)
        s2 = (s2 + values[i + 1] + s1) % (1 << 32)
    return s1, s2


def make_wal(frames, byte_order='<', version=3007000, page_size=4096):
    magic = 0x377f0682 if byte_order == '<' else 0x377f0683
    header = struct.pack('>6I', magic, version, page_size, 0, 123, 456)
    rolling = checksum(header, byte_order)
    data = bytearray(header + struct.pack('>II', *rolling))
    for pgno, db_size, page in frames:
        frame = struct.pack('>4I', pgno, db_size, 123, 456)
        rolling = checksum(frame[:8] + page, byte_order, rolling)
        data.extend(frame + struct.pack('>II', *rolling) + page)
    return bytes(data)


class CryptoCacheTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.db_dir = self.root / 'account'
        self.db_dir.mkdir()
        self.db = self.db_dir / 'main.db'
        self.out = self.root / 'plain.db'
        self.wal = Path(str(self.db) + '-wal')
        self.keys = {'main.db': {'enc_key': KEY.hex(), 'salt': SALT.hex()}}
        self.patch = mock.patch.object(DBCache, 'CACHE_DIR', str(self.root / 'cache'))
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.write_database()

    def write_database(self, key=KEY, salt=SALT, pages=3, marker=b'A'):
        pairs = [encrypted_page(pgno, marker, key, salt) for pgno in range(1, pages + 1)]
        self.db.write_bytes(b''.join(encrypted for encrypted, _ in pairs))
        return b''.join(plain for _, plain in pairs)

    def test_full_decrypt_validates_first_page_and_keeps_interface(self):
        expected = self.write_database()
        self.assertEqual(crypto.full_decrypt(self.db, self.out, KEY), 3)
        self.assertEqual(self.out.read_bytes(), expected)
        self.assertEqual(stat.S_IMODE(self.out.stat().st_mode), 0o600)
        self.assertEqual(crypto.decrypt_page(KEY, encrypted_page(1)[0], 1), expected[:4096])

    def test_bad_key_hmac_or_partial_page_never_replaces_output(self):
        original = self.db.read_bytes()
        self.out.write_bytes('旧输出'.encode())
        cases = [
            (original, b'B' * 32),
            (original, KEY[:-1]),
            (original[:-1], KEY),
            (b'', KEY),
            (original[:4095] + bytes([original[4095] ^ 1]) + original[4096:], KEY),
        ]
        for data, key in cases:
            with self.subTest(length=len(data), key_length=len(key)):
                self.db.write_bytes(data)
                with self.assertRaises(ValueError):
                    crypto.full_decrypt(self.db, self.out, key)
                self.assertEqual(self.out.read_bytes(), '旧输出'.encode())
        self.assertFalse(list(self.root.glob('.wechat-decrypt-*')))

    def test_page_validation_rejects_invalid_lengths_and_page_numbers(self):
        for page, pgno in [(b'', 1), (b'x' * 4095, 2), (b'x' * 4096, 0)]:
            with self.subTest(pgno=pgno), self.assertRaises(ValueError):
                crypto.decrypt_page(KEY, page, pgno)

    def test_full_decrypt_write_failure_is_atomic(self):
        self.out.write_bytes('旧输出'.encode())
        real = crypto.decrypt_page
        def fail_second(key, page, pgno):
            if pgno == 2:
                raise RuntimeError('合成写入失败')
            return real(key, page, pgno)
        with mock.patch.object(crypto, 'decrypt_page', side_effect=fail_second):
            with self.assertRaises(RuntimeError):
                crypto.full_decrypt(self.db, self.out, KEY)
        self.assertEqual(self.out.read_bytes(), '旧输出'.encode())
        self.assertFalse(list(self.root.glob('.wechat-decrypt-*')))

    def test_wal_both_endians_commit_boundary_and_truncation(self):
        for byte_order in ('<', '>'):
            with self.subTest(byte_order=byte_order):
                crypto.full_decrypt(self.db, self.out, KEY)
                page1, plain1 = encrypted_page(1, b'B')
                page2, plain2 = encrypted_page(2, b'C')
                self.wal.write_bytes(make_wal([
                    (1, 0, page1), (2, 2, page2),
                    (2, 0, encrypted_page(2, b'D')[0]),
                    (3, 0, encrypted_page(3, b'E')[0]),
                ], byte_order))
                self.assertEqual(crypto.decrypt_wal(self.wal, self.out, KEY), 2)
                self.assertEqual(self.out.read_bytes(), plain1 + plain2)

    def test_wal_last_commit_wins_and_discards_deleted_pages(self):
        crypto.full_decrypt(self.db, self.out, KEY)
        committed, plain = encrypted_page(1, b'C')
        self.wal.write_bytes(make_wal([
            (2, 2, encrypted_page(2, b'B')[0]),
            (3, 0, encrypted_page(3, b'D')[0]),
            (1, 1, committed),
            (1, 0, encrypted_page(1, b'E')[0]),
        ]))
        self.assertEqual(crypto.decrypt_wal(self.wal, self.out, KEY), 1)
        self.assertEqual(self.out.read_bytes(), plain)

    def test_wal_growth_requires_all_new_committed_pages(self):
        crypto.full_decrypt(self.db, self.out, KEY)
        original = self.out.read_bytes()
        page4, plain4 = encrypted_page(4, b'D')
        page5, plain5 = encrypted_page(5, b'E')
        self.wal.write_bytes(make_wal([(4, 0, page4), (5, 5, page5)]))
        self.assertEqual(crypto.decrypt_wal(self.wal, self.out, KEY), 2)
        self.assertEqual(self.out.read_bytes(), original + plain4 + plain5)
        self.out.write_bytes(original)
        self.wal.write_bytes(make_wal([(5, 5, page5)]))
        with self.assertRaisesRegex(ValueError, '缺少扩展'):
            crypto.decrypt_wal(self.wal, self.out, KEY)
        self.assertEqual(self.out.read_bytes(), original)

    def test_no_commit_missing_empty_and_header_only_wal_do_not_write(self):
        crypto.full_decrypt(self.db, self.out, KEY)
        before = self.out.read_bytes()
        with mock.patch.object(crypto, '_temporary_output', side_effect=AssertionError('不应写入')):
            self.assertEqual(crypto.decrypt_wal(self.wal, self.out, KEY), 0)
            for wal in (b'', make_wal([]), make_wal([(2, 0, encrypted_page(2)[0])])):
                self.wal.write_bytes(wal)
                self.assertEqual(crypto.decrypt_wal(self.wal, self.out, KEY), 0)
                self.assertEqual(self.out.read_bytes(), before)

    def test_wal_bad_header_frame_salt_checksum_or_tail_never_publishes(self):
        crypto.full_decrypt(self.db, self.out, KEY)
        before = self.out.read_bytes()
        valid = make_wal([(2, 2, encrypted_page(2, b'B')[0])])
        cases = [valid[:10], valid[:-1], valid + b'x',
                 make_wal([], version=1), make_wal([], page_size=8192),
                 make_wal([(0, 2, encrypted_page(2)[0])])]
        for offset in (0, 24, 32 + 8, 32 + 16, 32 + 24 + 99):
            damaged = bytearray(valid)
            damaged[offset] ^= 1
            cases.append(bytes(damaged))
        # 提交后的损坏未提交帧也必须使整个发布失败。
        damaged_tail = bytearray(make_wal([
            (2, 2, encrypted_page(2)[0]), (3, 0, encrypted_page(3)[0]),
        ]))
        damaged_tail[-1] ^= 1
        cases.append(bytes(damaged_tail))
        for index, data in enumerate(cases):
            with self.subTest(case=index):
                self.wal.write_bytes(data)
                with self.assertRaises(ValueError):
                    crypto.decrypt_wal(self.wal, self.out, KEY)
                self.assertEqual(self.out.read_bytes(), before)
        self.assertFalse(list(self.root.glob('.wechat-decrypt-*')))

    def test_wal_page_one_bad_hmac_fails_after_checksum_validation(self):
        crypto.full_decrypt(self.db, self.out, KEY)
        before = self.out.read_bytes()
        damaged = bytearray(encrypted_page(1)[0])
        damaged[-1] ^= 1
        self.wal.write_bytes(make_wal([(1, 1, bytes(damaged))]))
        with self.assertRaisesRegex(ValueError, 'HMAC'):
            crypto.decrypt_wal(self.wal, self.out, KEY)
        self.assertEqual(self.out.read_bytes(), before)

    def test_cache_reuses_across_sessions_with_private_permissions(self):
        cache = DBCache(self.keys, self.db_dir)
        path = Path(cache.get('main.db'))
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        for directory in (cache.CACHE_DIR, self.root / 'cache'):
            self.assertEqual(stat.S_IMODE(Path(directory).stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(Path(cache.MTIME_FILE).stat().st_mode), 0o600)
        saved = Path(cache.MTIME_FILE).read_text()
        self.assertNotIn(KEY.hex(), saved)
        self.assertNotIn(str(path), saved)
        cache.cleanup()
        with mock.patch('wechat_cli.core.db_cache.full_decrypt', side_effect=AssertionError('不应重解密')):
            self.assertEqual(DBCache(self.keys, self.db_dir).get('main.db'), str(path))

    def test_accounts_and_keysets_do_not_share_same_mtime_cache(self):
        first = DBCache(self.keys, self.db_dir)
        path = first.get('main.db')
        second_dir = self.root / 'other-account'
        second_dir.mkdir()
        second_db = second_dir / 'main.db'
        second_db.write_bytes(self.db.read_bytes())
        timestamp = self.db.stat().st_mtime_ns
        os.utime(second_db, ns=(timestamp, timestamp))
        second = DBCache(self.keys, second_dir)
        self.assertNotEqual(path, second.get('main.db'))
        other_keys = dict(self.keys, extra={'enc_key': KEY.hex(), 'salt': SALT.hex()})
        self.assertNotEqual(first.CACHE_DIR, DBCache(other_keys, self.db_dir).CACHE_DIR)
        bad_keys = {'main.db': {'enc_key': (b'Z' * 32).hex(), 'salt': SALT.hex()}}
        with self.assertRaisesRegex(ValueError, 'HMAC'):
            DBCache(bad_keys, self.db_dir).get('main.db')

    def test_key_and_salt_rotation_invalidate_live_cache_at_same_mtime(self):
        cache = DBCache(self.keys, self.db_dir)
        first = cache.get('main.db')
        timestamp = self.db.stat().st_mtime_ns
        new_key, new_salt = b'B' * 32, b'C' * 16
        expected = self.write_database(new_key, new_salt, marker=b'D')
        os.utime(self.db, ns=(timestamp, timestamp))
        with self.assertRaisesRegex(ValueError, 'salt'):
            cache.get('main.db')
        self.keys['main.db'].update(enc_key=new_key.hex(), salt=new_salt.hex())
        second = cache.get('main.db')
        self.assertNotEqual(first, second)
        self.assertEqual(Path(second).read_bytes(), expected)
        self.keys['main.db']['enc_key'] = (b'E' * 32).hex()
        with self.assertRaisesRegex(ValueError, 'HMAC'):
            cache.get('main.db')

    def test_actual_salt_change_without_key_metadata_invalidates(self):
        del self.keys['main.db']['salt']
        cache = DBCache(self.keys, self.db_dir)
        first = cache.get('main.db')
        timestamp = self.db.stat().st_mtime_ns
        expected = self.write_database(salt=b'B' * 16)
        os.utime(self.db, ns=(timestamp, timestamp))
        second = cache.get('main.db')
        self.assertNotEqual(first, second)
        self.assertEqual(Path(second).read_bytes(), expected)

    def test_cache_failed_wal_does_not_publish_database_or_metadata(self):
        cache = DBCache(self.keys, self.db_dir)
        first = cache.get('main.db')
        metadata = Path(cache.MTIME_FILE).read_bytes()
        self.wal.write_bytes('无效 WAL'.encode())
        with self.assertRaises(ValueError):
            cache.get('main.db')
        self.assertEqual(Path(cache.MTIME_FILE).read_bytes(), metadata)
        self.assertEqual(list(Path(cache.CACHE_DIR).glob('*.db')), [Path(first)])
        self.assertFalse(list(Path(cache.CACHE_DIR).glob('.database-*')))
        self.assertFalse(list(Path(cache.CACHE_DIR).glob('.wechat-decrypt-*')))

    def test_wal_changes_at_same_mtime_invalidate_cache(self):
        first_page, first_plain = encrypted_page(2, b'B')
        self.wal.write_bytes(make_wal([(2, 3, first_page)]))
        cache = DBCache(self.keys, self.db_dir)
        first = cache.get('main.db')
        self.assertEqual(Path(first).read_bytes()[4096:8192], first_plain)
        timestamp = self.wal.stat().st_mtime_ns
        second_page, second_plain = encrypted_page(2, b'C')
        self.wal.write_bytes(make_wal([(2, 3, second_page)]))
        os.utime(self.wal, ns=(timestamp, timestamp))
        second = cache.get('main.db')
        self.assertNotEqual(first, second)
        self.assertEqual(Path(second).read_bytes()[4096:8192], second_plain)

    def test_cache_source_change_before_publish_fails(self):
        cache = DBCache(self.keys, self.db_dir)
        real = crypto.full_decrypt
        def mutate(db, out, key):
            result = real(db, out, key)
            self.write_database(marker=b'B')
            return result
        with mock.patch('wechat_cli.core.db_cache.full_decrypt', side_effect=mutate):
            with self.assertRaisesRegex(ValueError, '发生变化'):
                cache.get('main.db')
        self.assertFalse(list(Path(cache.CACHE_DIR).glob('*.db')))

    def test_path_traversal_absolute_windows_paths_and_wal_symlink_rejected(self):
        cache = DBCache(self.keys, self.db_dir)
        for rel in ('../main.db', 'a/../../main.db', '/main.db', 'C:\\main.db',
                    '\\\\host\\main.db', 'a/../main.db', 'a//main.db', 'main.db\x00'):
            with self.subTest(rel=rel), self.assertRaises(ValueError):
                cache.get(rel)
        external = self.root / 'external.db'
        external.write_bytes(self.db.read_bytes())
        (self.db_dir / 'escape.db').symlink_to(external)
        with self.assertRaises(ValueError):
            cache.get('escape.db')
        self.wal.symlink_to(external)
        with self.assertRaises(ValueError):
            cache.get('main.db')

    def test_windows_relative_paths_and_missing_database_are_supported(self):
        subdir = self.db_dir / 'message'
        subdir.mkdir()
        (subdir / 'main.db').write_bytes(self.db.read_bytes())
        keys = {'message/main.db': self.keys['main.db'], 'missing.db': self.keys['main.db']}
        cache = DBCache(keys, self.db_dir)
        self.assertTrue(Path(cache.get('message\\main.db')).is_file())
        self.assertIsNone(cache.get('missing.db'))
        self.assertIsNone(cache.get('unknown.db'))

    def test_untrusted_metadata_paths_and_symlink_cache_files_are_not_followed(self):
        cache = DBCache(self.keys, self.db_dir)
        target = self.root / 'outside.db'
        target.write_bytes('不能覆盖'.encode())
        Path(cache.MTIME_FILE).write_text(json.dumps({
            'main.db': {'path': str(target), 'db_mt': self.db.stat().st_mtime},
        }))
        cache = DBCache(self.keys, self.db_dir)
        path = Path(cache.get('main.db'))
        path.unlink()
        path.symlink_to(target)
        self.assertEqual(cache.get('main.db'), str(path))
        self.assertFalse(path.is_symlink())
        self.assertEqual(target.read_bytes(), '不能覆盖'.encode())
        Path(cache.MTIME_FILE).unlink()
        Path(cache.MTIME_FILE).symlink_to(target)
        cache.cleanup()
        self.assertFalse(Path(cache.MTIME_FILE).is_symlink())
        self.assertEqual(target.read_bytes(), '不能覆盖'.encode())

    def test_hardlinked_cache_file_is_replaced_without_changing_external_file(self):
        cache = DBCache(self.keys, self.db_dir)
        path = Path(cache.get('main.db'))
        target = self.root / 'outside.db'
        target.write_bytes(b'outside')
        target.chmod(0o644)
        path.unlink()
        os.link(target, path)
        self.assertEqual(cache.get('main.db'), str(path))
        self.assertEqual(path.stat().st_nlink, 1)
        self.assertEqual(target.read_bytes(), b'outside')
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o644)

    def test_symlink_cache_root_is_rejected(self):
        cache_root = self.root / 'cache'
        cache_root.symlink_to(self.db_dir, target_is_directory=True)
        with self.assertRaises(ValueError):
            DBCache(self.keys, self.db_dir)


class PackagingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('wechat_cli_build_test', ROOT / 'npm/scripts/build.py')
        cls.build = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.build)

    def test_python_npm_and_all_five_platform_versions(self):
        package = json.loads((ROOT / 'npm/wechat-cli/package.json').read_text())
        self.assertEqual(package['version'], '0.3.0')
        expected = {}
        for platform in self.build.PLATFORM_MAP:
            platform_package = json.loads((ROOT / f'npm/platforms/{platform}/package.json').read_text())
            self.assertEqual(platform_package['version'], '0.3.0')
            expected[platform_package['name']] = '0.3.0'
        self.assertEqual(package['optionalDependencies'], expected)
        config = (ROOT / 'pyproject.toml').read_text()
        self.assertIn('version = "0.3.0"', config)
        self.assertIn('[project.optional-dependencies]\nfrida = ', config)
        for resource in ('bin/*.c', 'keys/*.js', 'keys/*.plist'):
            self.assertIn(resource, config)
        self.assertNotIn('"bin/*"', config)
        self.assertNotIn('frida', config.split('dependencies = [', 1)[1].split(']', 1)[0])

    def test_platform_normalization_and_no_cross_build(self):
        for system, machine, expected in (
            ('Windows', 'AMD64', 'win32-x64'), ('Linux', 'aarch64', 'linux-arm64'),
            ('Darwin', 'x86_64', 'darwin-x64'), ('Darwin', 'arm64', 'darwin-arm64'),
        ):
            with mock.patch.object(self.build.host_platform, 'system', return_value=system), \
                 mock.patch.object(self.build.host_platform, 'machine', return_value=machine):
                self.assertEqual(self.build.current_platform(), expected)
        with mock.patch.object(self.build, 'current_platform', return_value='darwin-arm64'), \
             mock.patch.object(self.build.subprocess, 'check_call') as run:
            self.assertFalse(self.build.build_platform('win32-x64'))
            self.assertFalse(self.build.build_platform('unknown'))
            run.assert_not_called()

    def test_missing_pyinstaller_never_installs(self):
        with mock.patch.object(self.build.importlib.util, 'find_spec', return_value=None), \
             mock.patch.object(self.build.subprocess, 'check_call') as run:
            with self.assertRaisesRegex(RuntimeError, '不会自动安装'):
                self.build.ensure_pyinstaller()
            run.assert_not_called()

    def test_build_resources_and_optional_frida_collection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ('bin/probe.c', 'bin/probe.plist', 'bin/old.arm64',
                         'keys/capture.js', 'keys/capture.plist'):
                path = root / 'wechat_cli' / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('合成资源')
            output = root / 'npm/platforms/darwin-arm64'
            (output / 'bin').mkdir(parents=True)
            (output / 'bin/wechat-cli').write_text('合成产物')
            for installed in (False, True):
                def find_spec(name):
                    return object() if name != 'frida' or installed else None
                with self.subTest(frida=installed), \
                     mock.patch.object(self.build, 'ROOT', root), \
                     mock.patch.object(self.build, 'PLATFORMS_DIR', root / 'npm/platforms'), \
                     mock.patch.object(self.build, 'current_platform', return_value='darwin-arm64'), \
                     mock.patch.object(self.build.importlib.util, 'find_spec', side_effect=find_spec), \
                     mock.patch.object(self.build.subprocess, 'check_call') as run:
                    with mock.patch('builtins.print'):
                        self.assertTrue(self.build.build_platform('darwin-arm64'))
                    command = run.call_args.args[0]
                    self.assertEqual('frida' in command, installed)
                    if installed:
                        self.assertIn('--collect-all', command)
                    joined = ' '.join(command)
                    for resource in ('probe.c', 'probe.plist', 'capture.js', 'capture.plist'):
                        self.assertIn(resource, joined)
                    self.assertNotIn('old.arm64', joined)
                    self.assertNotIn('--add-binary', command)
                    self.assertNotIn('pysqlcipher3', command)

    @unittest.skipUnless(shutil.which('node'), '需要 Node.js 验证 npm wrapper')
    def test_npm_wrapper_missing_platform_package_is_chinese_without_stack(self):
        # 在 VM 中强制两次 require.resolve 均失败，不依赖真实 node_modules。
        script = r"""
const vm = require('vm');
const fs = require('fs');
const assert = require('assert');
const errors = [];
let resolves = 0;
const fakeRequire = name => {
  if (name === 'child_process') return {execFileSync() { assert.fail('不能执行真实程序'); }};
  if (name === 'path') return require('path');
  if (name === 'fs') return {existsSync() { return false; }};
  assert.fail(name);
};
fakeRequire.resolve = () => { resolves++; throw new Error('MODULE_NOT_FOUND'); };
const stopped = {};
try {
  vm.runInNewContext(fs.readFileSync(process.argv[1], 'utf8'), {
    require: fakeRequire,
    process: {platform: 'darwin', arch: 'arm64', env: {}, argv: ['node', 'wrapper'],
      exit(code) { assert.equal(code, 1); throw stopped; }},
    console: {error(message) { errors.push(message); }}
  });
  assert.fail('应停止执行');
} catch (error) { assert.strictEqual(error, stopped); }
assert.equal(resolves, 2);
assert(errors.some(message => message.includes('未找到')));
assert(errors.some(message => message.includes('@canghe_ai/wechat-cli@0.3.0')));
assert(!errors.some(message => message.includes('MODULE_NOT_FOUND')));
"""
        result = subprocess.run([
            shutil.which('node'), '-e', script, str(ROOT / 'npm/wechat-cli/bin/wechat-cli.js'),
        ], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()

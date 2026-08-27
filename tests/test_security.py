import hashlib
import hmac
import json
import os
import struct
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from click.testing import CliRunner
from Crypto.Cipher import AES

from wechat_cli.commands.doctor import build_doctor_report
from wechat_cli.commands.favorites import _parse_fav_content
from wechat_cli.commands.init import init as init_command
from wechat_cli.commands.keys import keys as keys_command
from wechat_cli.core.config import load_config
from wechat_cli.core.crypto import (
    PAGE_SZ,
    RESERVE_SZ,
    _derive_hmac_key,
    _wal_checksum,
    decrypt_page,
    decrypt_wal,
)
from wechat_cli.core.db_cache import DBCache
from wechat_cli.core.key_document import (
    DpapiDatabaseKeyProvider,
    JsonDatabaseKeyProvider,
    MacKeychainDatabaseKeyProvider,
    SecretServiceDatabaseKeyProvider,
    create_key_provider,
    validate_key_document,
)
from wechat_cli.core.key_utils import _is_safe_rel_path
from wechat_cli.core.secure_files import (
    assert_private_file,
    atomic_write_bytes,
    atomic_write_json,
    ensure_private_directory,
    read_private_json,
    redact_sensitive_text,
)
from wechat_cli.core.state import commit_generation, resolve_active_generation
from wechat_cli.keys.capabilities import ScannerProfile, evaluate_scan_capability
from wechat_cli.keys.common import save_results
from wechat_cli.keys.scanner_macos import extract_keys as extract_macos_keys
from wechat_cli.keys.trusted_import import verify_imported_key_document

KEY = "ab" * 32
SALT = "cd" * 16
_MEMORY_READ_GUARD = None


def setUpModule():
    """安全回归禁止触达真实进程内存，错误门禁应在这里立即失败。"""
    global _MEMORY_READ_GUARD
    if os.name == "nt":
        _MEMORY_READ_GUARD = patch(
            "wechat_cli.keys.scanner_windows._read_mem",
            side_effect=AssertionError("tests must never read real process memory"),
        )
        _MEMORY_READ_GUARD.start()


def tearDownModule():
    if _MEMORY_READ_GUARD is not None:
        _MEMORY_READ_GUARD.stop()


def _encrypted_page(enc_key, salt, pgno, plaintext_byte):
    iv = bytes([pgno]) * 16
    start = 16 if pgno == 1 else 0
    plaintext = bytes([plaintext_byte]) * (PAGE_SZ - RESERVE_SZ - start)
    encrypted = AES.new(enc_key, AES.MODE_CBC, iv).encrypt(plaintext)
    prefix = salt + encrypted if pgno == 1 else encrypted
    partial = prefix + iv
    mac_key = _derive_hmac_key(enc_key, salt)
    digest = hmac.new(mac_key, partial[start:] + struct.pack("<I", pgno), hashlib.sha512).digest()
    return partial + digest


class SecureFilesTests(unittest.TestCase):
    def test_atomic_json_round_trip_and_private_mode(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "private", "keys.json")
            atomic_write_json(path, {"message/a.db": {"enc_key": KEY, "salt": SALT}})

            self.assertEqual(read_private_json(path)["message/a.db"]["enc_key"], KEY)
            if os.name != "nt":
                self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
                self.assertEqual(os.stat(os.path.dirname(path)).st_mode & 0o777, 0o700)

    @unittest.skipIf(os.name == "nt", "POSIX permission contract")
    def test_existing_parent_is_not_repermissioned_unless_explicit(self):
        with tempfile.TemporaryDirectory() as root:
            parent = os.path.join(root, "shared")
            os.mkdir(parent, 0o755)
            os.chmod(parent, 0o755)
            atomic_write_json(os.path.join(parent, "keys.json"), {"value": "private"})
            self.assertEqual(os.stat(parent).st_mode & 0o777, 0o755)
            ensure_private_directory(parent, tighten_existing=True)
            self.assertEqual(os.stat(parent).st_mode & 0o777, 0o700)

    @unittest.skipIf(os.name == "nt", "POSIX permission contract")
    def test_rejects_group_readable_sensitive_file(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "keys.json")
            Path(path).write_text("{}", encoding="utf-8")
            os.chmod(path, 0o640)
            with self.assertRaises(PermissionError):
                assert_private_file(path)

    def test_redacts_prefixed_json_pragma_and_bare_keys(self):
        source = "\n".join([
            f"enc_key={KEY}",
            json.dumps({"enc_key": KEY}),
            f"x'{KEY}{SALT}'",
            f"message/a.db {KEY} {SALT}",
        ])
        result = redact_sensitive_text(source)
        self.assertNotIn(KEY, result)
        self.assertIn("[REDACTED]", result)

    def test_invalid_json_error_does_not_echo_source(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "keys.json")
            secret = "secret-shaped-value"
            Path(path).write_text('{"enc_key": "' + secret, encoding="utf-8")
            if os.name != "nt":
                os.chmod(path, 0o600)
            with self.assertRaises(ValueError) as caught:
                read_private_json(path)
            self.assertNotIn(secret, str(caught.exception))

    @unittest.skipUnless(os.name == "nt", "Windows ACL replacement contract")
    def test_acl_failure_does_not_replace_active_file(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "active")
            Path(path).write_bytes(b"old")
            with patch(
                "wechat_cli.core.secure_files._secure_windows_acl",
                side_effect=PermissionError("denied"),
            ):
                with self.assertRaises(PermissionError):
                    atomic_write_bytes(path, b"new")
            self.assertEqual(Path(path).read_bytes(), b"old")


class KeyDocumentTests(unittest.TestCase):
    def test_accepts_valid_document_without_returning_metadata(self):
        result = validate_key_document({
            "_source": "scanner",
            "message/a.db": {"enc_key": KEY, "salt": SALT, "size_mb": 1.0},
        })
        self.assertEqual(list(result), ["message/a.db"])

    def test_rejects_invalid_key_without_echoing_it(self):
        invalid = "not-a-valid-key"
        with self.assertRaises(ValueError) as caught:
            validate_key_document({"message/a.db": {"enc_key": invalid}})
        self.assertNotIn(invalid, str(caught.exception))

    def test_rejects_absolute_and_parent_paths(self):
        self.assertFalse(_is_safe_rel_path("../outside.db"))
        self.assertFalse(_is_safe_rel_path("/outside.db"))
        self.assertFalse(_is_safe_rel_path(r"C:\\outside.db"))
        self.assertFalse(_is_safe_rel_path(r"C:outside.db"))
        self.assertFalse(_is_safe_rel_path("message//a.db"))
        self.assertFalse(_is_safe_rel_path("message/./a.db"))

    def test_provider_is_value_free_on_describe_and_reloads_each_operation(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "all_keys.json")
            provider = JsonDatabaseKeyProvider(path)
            provider.replace({"message/a.db": {"enc_key": KEY, "salt": SALT}})

            self.assertEqual(provider.references(), ("message/a.db",))
            self.assertNotIn("enc_key", provider.describe("message/a.db"))
            self.assertEqual(provider.resolve("message/a.db")["enc_key"], KEY)

            rotated = "ef" * 32
            provider.replace({"message/a.db": {"enc_key": rotated, "salt": SALT}})
            self.assertEqual(provider.resolve("message/a.db")["enc_key"], rotated)

    def test_factory_rejects_legacy_plaintext_without_explicit_opt_in(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "all_keys.json")
            JsonDatabaseKeyProvider(path).replace(
                {"message/a.db": {"enc_key": KEY, "salt": SALT}}
            )
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("WECHAT_CLI_ALLOW_PLAINTEXT_KEYS", None)
                with self.assertRaisesRegex(RuntimeError, "旧版明文"):
                    create_key_provider(path)

    @unittest.skipUnless(os.name == "nt", "Windows DPAPI contract")
    def test_dpapi_manifest_never_contains_plaintext_key(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "keys.json")
            provider = DpapiDatabaseKeyProvider(path)
            provider.replace({"message/a.db": {"enc_key": KEY, "salt": SALT}})

            self.assertEqual(provider.resolve("message/a.db")["enc_key"], KEY)
            self.assertNotIn(KEY, Path(path).read_text(encoding="utf-8"))

    def test_secret_service_sends_secret_only_over_stdin(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "keys.json")
            provider = SecretServiceDatabaseKeyProvider(path, "a" * 32)
            stored = {}
            observed_commands = []

            def fake_run(command, **kwargs):
                observed_commands.append(command)
                operation = command[1]
                token = command[-1]
                if operation == "store":
                    stored[token] = kwargs["input"]
                    return SimpleNamespace(returncode=0, stdout="", stderr="")
                if operation == "lookup":
                    return SimpleNamespace(returncode=0, stdout=stored[token], stderr="")
                if operation == "clear":
                    stored.pop(token, None)
                    return SimpleNamespace(returncode=0, stdout="", stderr="")
                raise AssertionError(operation)

            with patch("wechat_cli.core.key_document.os.path.isfile", return_value=True), \
                    patch("wechat_cli.core.key_document.subprocess.run", side_effect=fake_run):
                provider.replace({"message/a.db": {"enc_key": KEY, "salt": SALT}})
                self.assertEqual(provider.resolve("message/a.db")["enc_key"], KEY)

            self.assertTrue(all(KEY not in " ".join(command) for command in observed_commands))
            self.assertNotIn(KEY, Path(path).read_text(encoding="utf-8"))

    def test_macos_keychain_manifest_contains_only_references(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "keys.json")
            provider = MacKeychainDatabaseKeyProvider(path, "b" * 32)
            stored = {}

            with patch.object(provider, "_store", side_effect=lambda token, data: stored.__setitem__(token, data)), \
                    patch.object(provider, "_lookup", side_effect=lambda token: stored[token]), \
                    patch.object(provider, "_clear", side_effect=lambda token: stored.pop(token, None)):
                provider.replace({"message/a.db": {"enc_key": KEY, "salt": SALT}})
                self.assertEqual(provider.resolve("message/a.db")["enc_key"], KEY)

            self.assertNotIn(KEY, Path(path).read_text(encoding="utf-8"))


class StateGenerationTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Current test host validates DPAPI generation")
    def test_generation_switches_only_after_provider_readback(self):
        with tempfile.TemporaryDirectory() as root:
            document = {"message/a.db": {"enc_key": KEY, "salt": SALT}}
            first = commit_generation(root, {"db_dir": root}, document, backend="dpapi-current-user")
            cfg = load_config(os.path.join(first, "config.json"))
            self.assertEqual(cfg["key_backend"], "dpapi-current-user")
            self.assertTrue(os.path.isabs(cfg["keys_file"]))
            self.assertTrue(os.path.samefile(resolve_active_generation(root), first))

            with patch.object(DpapiDatabaseKeyProvider, "replace", side_effect=RuntimeError("fail")):
                with self.assertRaises(RuntimeError):
                    commit_generation(root, {"db_dir": root}, document, backend="dpapi-current-user")
            self.assertTrue(os.path.samefile(resolve_active_generation(root), first))


class XmlBoundaryTests(unittest.TestCase):
    def test_favorites_rejects_large_and_declaration_xml(self):
        self.assertEqual(_parse_fav_content("<favitem>" + "x" * 20_001 + "</favitem>", 1), "")
        self.assertEqual(
            _parse_fav_content('<!DOCTYPE x [<!ENTITY y "z">]><favitem>&y;</favitem>', 1),
            "",
        )


class CryptoIntegrityTests(unittest.TestCase):
    def test_page_hmac_rejects_corruption(self):
        key = bytes.fromhex(KEY)
        salt = bytes.fromhex(SALT)
        page = bytearray(_encrypted_page(key, salt, 1, 0x41))
        page[100] ^= 1
        with self.assertRaisesRegex(ValueError, "HMAC"):
            decrypt_page(key, salt, bytes(page), 1)

    def test_wal_applies_only_checksum_valid_committed_frames(self):
        key = bytes.fromhex(KEY)
        salt = bytes.fromhex(SALT)
        wal_salt = b"12345678"
        header_prefix = struct.pack(">IIII", 0x377F0682, 3_007_000, PAGE_SZ, 0) + wal_salt
        checksum = _wal_checksum(header_prefix, "<")
        wal = bytearray(header_prefix + struct.pack(">II", *checksum))
        for pgno, database_size, marker in ((1, 0, 0x42), (2, 2, 0x43)):
            page = _encrypted_page(key, salt, pgno, marker)
            frame_prefix = struct.pack(">II", pgno, database_size) + wal_salt
            checksum = _wal_checksum(frame_prefix[:8], "<", checksum)
            checksum = _wal_checksum(page, "<", checksum)
            wal.extend(frame_prefix + struct.pack(">II", *checksum) + page)
        wal.extend(b"corrupt trailing frame")

        with tempfile.TemporaryDirectory() as root:
            wal_path = os.path.join(root, "db-wal")
            db_path = os.path.join(root, "db")
            Path(wal_path).write_bytes(wal)
            Path(db_path).write_bytes(b"\0" * (PAGE_SZ * 3))
            self.assertEqual(decrypt_wal(wal_path, db_path, key, salt), 2)
            data = Path(db_path).read_bytes()
            self.assertEqual(len(data), PAGE_SZ * 2)
            self.assertEqual(data[:16], b"SQLite format 3\0")
            self.assertEqual(data[PAGE_SZ], 0x43)


class ScannerPersistenceTests(unittest.TestCase):
    def test_save_results_never_logs_key_and_writes_private_document(self):
        with tempfile.TemporaryDirectory() as root:
            output = os.path.join(root, "state", "all_keys.json")
            logs = []
            db_files = [("message/a.db", "unused", 4096, SALT, b"")]
            result = save_results(db_files, {SALT: ["message/a.db"]}, {SALT: KEY}, output, logs.append)

            self.assertEqual(result, {SALT: KEY})
            self.assertFalse(any(KEY in line for line in logs))
            self.assertEqual(read_private_json(output)["message/a.db"]["enc_key"], KEY)

    def test_macos_wrapper_redacts_binary_output_and_removes_intermediate(self):
        with tempfile.TemporaryDirectory() as root:
            db_dir = os.path.join(root, "db_storage")
            os.mkdir(db_dir)
            output = os.path.join(root, "state", "all_keys.json")
            historical_output = os.path.join(root, "all_keys.json")
            binary = os.path.join(root, "scanner")
            Path(binary).write_bytes(b"safe scanner [REDACTED]")
            observed_command = []

            def fake_run(command, **_kwargs):
                observed_command.extend(command)
                native_output = command[command.index("--output") + 1]
                atomic_write_json(native_output, {
                    "message/a.db": {"enc_key": KEY, "salt": SALT}
                })
                return SimpleNamespace(
                    returncode=0,
                    stdout=f"message/a.db {KEY} {SALT}",
                    stderr="",
                )

            rendered = StringIO()
            with patch("wechat_cli.keys.capabilities.require_supported_memory_scan"), \
                    patch("wechat_cli.keys.scanner_macos._find_binary", return_value=binary), \
                    patch("wechat_cli.keys.scanner_macos.subprocess.run", side_effect=fake_run), \
                    redirect_stdout(rendered):
                result = extract_macos_keys(db_dir, output)

            self.assertEqual(result, {SALT: KEY})
            self.assertNotIn(KEY, rendered.getvalue())
            self.assertFalse(os.path.exists(historical_output))
            self.assertEqual(
                observed_command[observed_command.index("--db-dir") + 1],
                os.path.realpath(db_dir),
            )
            self.assertNotEqual(
                observed_command[observed_command.index("--output") + 1],
                historical_output,
            )
            self.assertEqual(read_private_json(output)["message/a.db"]["enc_key"], KEY)

    def test_frozen_posix_helper_reenters_executable_without_python_module(self):
        from wechat_cli.keys import extract_keys_for_init

        response = json.dumps({"message/a.db": {"enc_key": KEY, "salt": SALT}})
        with patch("wechat_cli.keys.platform.system", return_value="Linux"), \
                patch("wechat_cli.keys.require_supported_memory_scan"), \
                patch("wechat_cli.keys.os.path.isfile", return_value=True), \
                patch("wechat_cli.keys.subprocess.run") as run, \
                patch.object(sys, "frozen", True, create=True), \
                patch.object(sys, "executable", "/opt/wechat-cli"):
            run.return_value = SimpleNamespace(returncode=0, stdout=response, stderr="")
            document = extract_keys_for_init("/safe/db_storage")

        self.assertEqual(document["message/a.db"]["enc_key"], KEY)
        command = run.call_args.args[0]
        self.assertEqual(
            command,
            [
                "/usr/bin/sudo", "--", "/opt/wechat-cli",
                "_elevated-scan-helper", "/safe/db_storage",
            ],
        )
        self.assertNotIn("-m", command)
        self.assertNotIn(KEY, " ".join(command))


class SafeBootstrapTests(unittest.TestCase):
    def test_shared_extract_entrypoint_enforces_capability_gate(self):
        from wechat_cli.keys import extract_keys

        with tempfile.TemporaryDirectory() as root, patch(
            "wechat_cli.keys.require_supported_memory_scan",
            side_effect=RuntimeError("WXCLI_SCAN_UNSUPPORTED_CLIENT"),
        ):
            with self.assertRaisesRegex(RuntimeError, "WXCLI_SCAN_UNSUPPORTED_CLIENT"):
                extract_keys(root, os.path.join(root, "keys.json"))
        self.assertFalse(os.path.exists(os.path.join(root, "keys.json")))

    def test_unknown_client_is_rejected_by_exact_capability_manifest(self):
        identity = {
            "platform": "windows",
            "executable": "Weixin.exe",
            "client_version": "4.1.13.12",
            "publisher": "Tencent Technology (Shenzhen) Company Limited",
            "signature_valid": True,
            "process_running": True,
        }
        self.assertFalse(evaluate_scan_capability(identity)["supported"])

        verified_profile = ScannerProfile(
            profile_id="test-only",
            platform="windows",
            executable="Weixin.exe",
            client_version="4.1.13.12",
            publisher=identity["publisher"],
            scanner_algorithm="legacy-hex-v1",
            acceptance="verified",
        )
        result = evaluate_scan_capability(identity, (verified_profile,))
        self.assertTrue(result["supported"])
        self.assertEqual(result["profile"]["profile_id"], "test-only")

    def test_init_defaults_to_plan_and_never_calls_scanner(self):
        with tempfile.TemporaryDirectory() as db_dir, patch(
            "wechat_cli.commands.init.evaluate_scan_capability",
            return_value={
                "supported": False,
                "reason_code": "WXCLI_SCAN_UNSUPPORTED_CLIENT",
                "profile": None,
                "identity": {
                    "platform": "windows",
                    "executable": "Weixin.exe",
                    "client_version": "4.1.13.12",
                    "publisher": "unknown",
                    "process_running": True,
                },
            },
        ), patch("wechat_cli.keys.extract_keys_for_init") as scanner:
            result = CliRunner().invoke(init_command, ["--db-dir", db_dir])
        self.assertEqual(result.exit_code, 2, result.output)
        self.assertIn("未执行扫描", result.output)
        scanner.assert_not_called()

    def test_unknown_scan_stops_before_scanner_even_with_confirmation(self):
        capability = {
            "supported": False,
            "reason_code": "WXCLI_SCAN_UNSUPPORTED_CLIENT",
            "profile": None,
            "identity": {
                "platform": "windows",
                "executable": "Weixin.exe",
                "client_version": "4.1.13.12",
                "publisher": "unknown",
                "process_running": True,
            },
        }
        with tempfile.TemporaryDirectory() as db_dir, patch(
            "wechat_cli.commands.init.evaluate_scan_capability", return_value=capability
        ), patch("wechat_cli.keys.extract_keys_for_init") as scanner:
            result = CliRunner().invoke(
                init_command,
                ["--db-dir", db_dir, "--scan-memory", "--confirm-memory-scan"],
            )
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("WXCLI_SCAN_UNSUPPORTED_CLIENT", result.output)
        scanner.assert_not_called()

    def test_doctor_declares_and_observes_no_memory_read(self):
        with patch("wechat_cli.keys.scanner_windows._read_mem") as read_mem:
            report = build_doctor_report()
        self.assertFalse(report["read_process_memory"])
        read_mem.assert_not_called()

    def test_trusted_import_requires_real_database_page_hmac(self):
        key = bytes.fromhex(KEY)
        salt = bytes.fromhex(SALT)
        with tempfile.TemporaryDirectory() as db_dir:
            db_path = os.path.join(db_dir, "message", "a.db")
            os.makedirs(os.path.dirname(db_path))
            Path(db_path).write_bytes(_encrypted_page(key, salt, 1, 0x41))
            verified = verify_imported_key_document(
                db_dir, {"message/a.db": {"enc_key": KEY, "salt": SALT}}
            )
            self.assertEqual(verified[os.path.join("message", "a.db")]["enc_key"], KEY)
            with self.assertRaisesRegex(ValueError, "WXCLI_IMPORT_HMAC_FAILED"):
                verify_imported_key_document(
                    db_dir, {"message/a.db": {"enc_key": "ef" * 32, "salt": SALT}}
                )

    def test_keys_import_rejects_invalid_json_without_committing(self):
        with patch("wechat_cli.commands.keys.commit_generation") as commit:
            result = CliRunner().invoke(keys_command, ["import", "--stdin"], input="not-json")
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("WXCLI_IMPORT_INVALID_JSON", result.output)
        commit.assert_not_called()

    def test_keys_import_rejects_duplicate_json_properties(self):
        payload = '{"message/a.db":{"enc_key":"' + KEY + '","enc_key":"' + KEY + '"}}'
        with patch("wechat_cli.commands.keys.commit_generation") as commit:
            result = CliRunner().invoke(keys_command, ["import", "--stdin"], input=payload)
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("WXCLI_IMPORT_INVALID_JSON", result.output)
        commit.assert_not_called()

    def test_macos_wrapper_rejects_historical_unredacted_artifact(self):
        with tempfile.TemporaryDirectory() as root:
            binary = os.path.join(root, "scanner")
            Path(binary).write_bytes(b"%-25s %-66s %s")
            with patch("wechat_cli.keys.capabilities.require_supported_memory_scan"), \
                    patch("wechat_cli.keys.scanner_macos._find_binary", return_value=binary), \
                    patch("wechat_cli.keys.scanner_macos.subprocess.run") as run:
                with self.assertRaisesRegex(RuntimeError, "版本不安全"):
                    extract_macos_keys(root, os.path.join(root, "keys.json"))
            run.assert_not_called()


class CacheLifecycleTests(unittest.TestCase):
    def test_cache_redecrypts_after_provider_key_rotation(self):
        with tempfile.TemporaryDirectory() as root:
            state = os.path.join(root, "state")
            db_path = os.path.join(root, "message", "a.db")
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
            Path(db_path).write_bytes(bytes.fromhex(SALT) + b"encrypted")

            provider = JsonDatabaseKeyProvider(os.path.join(state, "all_keys.json"))
            provider.replace({"message/a.db": {"enc_key": KEY, "salt": SALT}})
            cache = DBCache(provider, root, state)
            observed_keys = []

            def fake_decrypt(_source, destination, enc_key):
                observed_keys.append(enc_key.hex())
                Path(destination).write_bytes(b"SQLite format 3\0")

            rotated = "ef" * 32
            try:
                with patch("wechat_cli.core.db_cache.full_decrypt", side_effect=fake_decrypt):
                    first = cache.get("message/a.db")
                    self.assertEqual(cache.get("message/a.db"), first)
                    provider.replace({"message/a.db": {"enc_key": rotated, "salt": SALT}})
                    self.assertEqual(cache.get("message/a.db"), first)
            finally:
                cache.cleanup()

            self.assertEqual(observed_keys, [KEY, rotated])

    def test_cache_uses_run_private_directory_and_cleanup_is_scoped(self):
        with tempfile.TemporaryDirectory() as root:
            state = os.path.join(root, "state")
            sibling = os.path.join(state, "cache", "keep.txt")
            os.makedirs(os.path.dirname(sibling), exist_ok=True)
            Path(sibling).write_text("keep", encoding="utf-8")

            key_path = os.path.join(state, "all_keys.json")
            provider = JsonDatabaseKeyProvider(key_path)
            provider.replace({"message/a.db": {"enc_key": KEY, "salt": SALT}})
            cache = DBCache(provider, root, state)
            run_dir = cache._cache_dir
            Path(os.path.join(run_dir, "decrypted.db")).write_bytes(b"SQLite format 3\0")
            cache.cleanup()

            self.assertFalse(os.path.exists(run_dir))
            self.assertTrue(os.path.exists(sibling))

    def test_cache_removes_only_unlocked_well_formed_stale_runs(self):
        with tempfile.TemporaryDirectory() as root:
            state = os.path.join(root, "state")
            cache_root = os.path.join(state, "cache")
            stale = os.path.join(cache_root, "run-999-" + "a" * 32)
            unrelated = os.path.join(cache_root, "keep-directory")
            os.makedirs(stale)
            os.makedirs(unrelated)
            Path(os.path.join(stale, ".lease")).write_bytes(b"0")
            provider = JsonDatabaseKeyProvider(os.path.join(state, "all_keys.json"))
            provider.replace({"message/a.db": {"enc_key": KEY, "salt": SALT}})

            cache = DBCache(provider, root, state)
            try:
                self.assertFalse(os.path.exists(stale))
                self.assertTrue(os.path.exists(unrelated))
            finally:
                cache.cleanup()

    def test_cache_rejects_drive_relative_database_reference(self):
        with tempfile.TemporaryDirectory() as root:
            state = os.path.join(root, "state")
            provider = JsonDatabaseKeyProvider(os.path.join(state, "all_keys.json"))
            provider.replace({"message/a.db": {"enc_key": KEY, "salt": SALT}})
            cache = DBCache(provider, root, state)
            try:
                with self.assertRaises(ValueError):
                    cache._source_paths(r"C:outside.db")
            finally:
                cache.cleanup()


if __name__ == "__main__":
    unittest.main()

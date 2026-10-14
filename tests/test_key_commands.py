"""导入与授权命令回归；只使用合成首页和 mock。"""

import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from click.testing import CliRunner

from wechat_cli.core import key_utils
from wechat_cli.commands.init import _inside_directory, save_initialization
from wechat_cli.keys import extract_keys
from wechat_cli.main import cli
from test_macos_keys import KEY, page_for


class KeyCommandTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.directory = self.root / "db_storage"
        self.directory.mkdir()
        self.salt = bytes(range(16))
        self.page = page_for(self.salt)
        (self.directory / "one.db").write_bytes(self.page)
        self.source = self.root / "wx_keys.json"
        self.source.write_text(json.dumps({"_meta": {}, "one.db": {"enc_key": KEY.hex()}}))
        self.config = self.root / "state" / "config.json"
        self.runner = CliRunner()

    def invoke(self, args):
        return self.runner.invoke(cli, ["--config", str(self.config), *args])

    def init_args(self):
        return ["init", "--db-dir", str(self.directory), "--keys", str(self.source)]

    def test_default_init_read_only_and_does_not_extract(self):
        with patch("wechat_cli.keys.extract_keys", side_effect=AssertionError("禁止内存读取")):
            result = self.invoke(["init", "--db-dir", str(self.directory)])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertFalse(self.config.parent.exists())
        self.assertNotIn(KEY.hex(), result.output)
        self.assertEqual((self.directory / "one.db").read_bytes(), self.page)

    def test_import_wx_format_validates_and_saves_private_files(self):
        with patch("wechat_cli.keys.extract_keys", side_effect=AssertionError("禁止内存读取")):
            result = self.invoke(self.init_args())
        self.assertEqual(result.exit_code, 0, result.output)
        cfg = json.loads(self.config.read_text())
        keys = Path(cfg["keys_file"])
        info = json.loads(keys.read_text())["one.db"]
        self.assertEqual(info["enc_key"], KEY.hex())
        self.assertEqual(info["salt"], self.salt.hex())
        self.assertNotIn(KEY.hex(), result.output)
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(keys.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(self.config.stat().st_mode), 0o600)
        self.assertEqual((self.directory / "one.db").read_bytes(), self.page)

    def test_force_only_replaces_after_hmac_verification_and_keeps_backup(self):
        self.assertEqual(self.invoke(self.init_args()).exit_code, 0)
        target = self.config.parent / "all_keys.json"
        original = target.read_bytes()
        self.assertNotEqual(self.invoke(self.init_args()).exit_code, 0)
        self.source.write_text(json.dumps({"one.db": {"enc_key": "ff" * 32}}))
        result = self.invoke([*self.init_args(), "--force"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertEqual(target.read_bytes(), original)
        self.source.write_text(json.dumps({"one.db": {"enc_key": KEY.hex(), "salt": "ff" * 16}}))
        result = self.invoke([*self.init_args(), "--force"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(Path(str(target) + ".bak").read_bytes(), original)
        self.assertEqual(json.loads(target.read_text())["one.db"]["salt"], self.salt.hex())

    def test_unknown_paths_and_wrong_account_are_not_imported(self):
        for mapping in ({"other.db": {"enc_key": KEY.hex()}},
                        {"../one.db": {"enc_key": KEY.hex()}}):
            self.source.write_text(json.dumps(mapping))
            result = self.invoke(self.init_args())
            self.assertNotEqual(result.exit_code, 0, result.output)
            self.assertFalse(self.config.exists())

    def test_check_is_content_free_and_never_constructs_query_context(self):
        self.assertEqual(self.invoke(self.init_args()).exit_code, 0)
        with patch("wechat_cli.main.AppContext", side_effect=AssertionError("禁止查询缓存")):
            result = self.invoke(["keys", "check"])
        self.assertEqual(result.exit_code, 0, result.output)
        report = json.loads(result.output)
        self.assertEqual(report["valid_count"], 1)
        self.assertNotIn(KEY.hex(), result.output)
        self.assertNotIn(self.salt.hex(), result.output)

    def test_extract_probe_prepare_require_flags_before_any_work(self):
        with patch("wechat_cli.keys.extract_keys", side_effect=AssertionError("禁止读取")), patch(
            "wechat_cli.commands.keys.initialization_paths", side_effect=AssertionError("禁止读取配置")
        ), patch("wechat_cli.keys.scanner_macos.build_probe", side_effect=AssertionError("禁止签名")):
            for args in (["keys", "extract"], ["keys", "extract", "--method", "gdb"],
                         ["keys", "probe"], ["keys", "prepare"]):
                with self.subTest(args=args):
                    result = self.invoke(args)
                    self.assertNotEqual(result.exit_code, 0)
                    self.assertIn("需 --allow", result.output)

    def test_authorized_extract_default_no_save_and_save_explicit(self):
        base = ["keys", "extract", "--db-dir", str(self.directory), "--allow-memory-read"]
        with patch("wechat_cli.keys.extract_keys", return_value={self.salt.hex(): KEY.hex()}) as extract:
            result = self.invoke(base)
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertFalse(self.config.exists())
            extract.assert_called_once_with(os.path.realpath(self.directory), pid=None, method="auto", timeout=120)
            result = self.invoke([*base, "--save"])
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertTrue(self.config.exists())
            self.assertNotIn(KEY.hex(), result.output)

    def test_frida_is_rejected_before_side_effects_even_authorized(self):
        with patch("wechat_cli.keys.extract_keys", side_effect=AssertionError("禁止读取")):
            result = self.invoke(["keys", "extract", "--method", "frida", "--allow-memory-read"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("隔离", result.output)
        self.assertFalse(self.config.exists())

    def test_help_and_version_work_without_existing_config(self):
        for args in (["--help"], ["keys", "--help"], ["keys", "extract", "--help"], ["--version"]):
            result = self.invoke(args)
            self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("0.3.0", self.invoke(["--version"]).output)
        self.assertFalse(self.config.exists())

    def test_cross_platform_paths_and_invalid_key_format(self):
        info = {"enc_key": KEY.hex()}
        self.assertEqual(key_utils.normalize_keys({r"message\one.db": info}), {"message/one.db": info})
        for path in ("/one.db", "../one.db", "a/../../one.db", r"C:\one.db", "C:one.db", "a/../one.db"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                key_utils.normalize_keys({path: info})
        for value in ([], {"one.db": {}}, {"one.db": {"enc_key": "xy" * 32}}):
            with self.assertRaises(ValueError):
                key_utils.normalize_keys(value)

    def test_symlink_key_source_and_target_are_refused(self):
        if os.name == "nt":
            self.skipTest("Windows 创建符号链接需额外权限")
        source_link = self.root / "linked.json"
        source_link.symlink_to(self.source)
        with self.assertRaises(ValueError):
            key_utils.load_keys(source_link)
        with self.assertRaises(ValueError):
            key_utils.private_write_json(source_link, {})
        self.assertIn("one.db", self.source.read_text())

    def test_initialization_config_failure_rolls_back_old_or_new_keys(self):
        self.config.parent.mkdir()
        target = self.config.parent / "all_keys.json"
        self.config.write_text(json.dumps({"db_dir": str(self.directory)}))
        original_config = self.config.read_bytes()
        write = key_utils.private_write_json
        def fail_config(path, data):
            if path == str(self.config):
                raise OSError("模拟配置发布失败")
            write(path, data)
        for old_keys in (None, {"old.db": {"enc_key": "ff" * 32}}):
            if old_keys is not None:
                write(target, old_keys)
            original = target.read_bytes() if target.exists() else None
            with patch("wechat_cli.commands.init.private_write_json", side_effect=fail_config):
                with self.assertRaises(OSError):
                    save_initialization(str(self.config), str(self.directory), str(target), {}, {})
            self.assertEqual(self.config.read_bytes(), original_config)
            self.assertEqual(target.read_bytes() if target.exists() else None, original)

    def test_config_key_alias_and_source_paths_refused_before_writes(self):
        aliases = [(str(self.config), str(self.config)),
                   (str(self.config), str(self.config) + ".bak"),
                   (str(self.config) + ".bak", str(self.config)),
                   (str(self.directory / "config.json"), str(self.root / "keys.json"))]
        if os.name != "nt":
            link = self.root / "alias"
            link.symlink_to(self.directory, target_is_directory=True)
            aliases.append((str(self.config), str(link / "nested" / "keys.json")))
        for config, keys in aliases:
            with self.subTest(config=config, keys=keys), patch("wechat_cli.commands.init.private_write_json") as write:
                with self.assertRaises(ValueError):
                    save_initialization(config, str(self.directory), keys, {}, {})
                write.assert_not_called()

    def test_windows_different_drives_not_inside_source(self):
        with patch("wechat_cli.commands.init.os.path.commonpath", side_effect=ValueError("不同盘符")):
            self.assertFalse(_inside_directory("D:/wx/db_storage", "C:/state/all_keys.json"))

    def test_full_metadata_retains_salt_for_query_and_import_rechecks(self):
        salt = self.salt.hex()
        source = {"one.db": {"enc_key": KEY.hex(), "salt": salt, "size_mb": 123}}
        normalized = key_utils.normalize_keys(source)
        self.assertEqual(normalized["one.db"]["salt"], salt)
        self.assertEqual(key_utils.validate_keys(source, self.directory)[0]["one.db"]["salt"], salt)
        for bad in ("xx" * 16, "a", 1):
            with self.assertRaises(ValueError):
                key_utils.normalize_keys({"one.db": {"enc_key": KEY.hex(), "salt": bad}})

    def test_macos_timeout_is_forwarded(self):
        with patch("wechat_cli.keys.platform.system", return_value="Darwin"), patch(
            "wechat_cli.keys.scanner_macos.extract_keys", return_value={}
        ) as scanner:
            extract_keys(self.directory, method="config", timeout=2)
        scanner.assert_called_once_with(self.directory, None, pid=None, method="memory", timeout=2)

    def test_failed_atomic_replace_preserves_original_and_cleans_temp(self):
        path = self.root / "private.json"
        key_utils.private_write_json(path, {"old": 1})
        original = path.read_bytes()
        replace = os.replace
        def fail_publish(source, destination):
            if destination == str(path):
                raise OSError("模拟原子替换失败")
            return replace(source, destination)
        with patch.object(key_utils.os, "replace", side_effect=fail_publish), self.assertRaises(OSError):
            key_utils.private_write_json(path, {"new": 2})
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(Path(str(path) + ".bak").read_bytes(), original)
        self.assertFalse(list(self.root.glob(".wechat-*")))


if __name__ == "__main__":
    unittest.main()

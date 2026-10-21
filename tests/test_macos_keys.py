"""macOS 密钥边界测试：仅合成数据库、匿名 FD 和 mock，不接触真实微信。"""

from contextlib import ExitStack, redirect_stderr, redirect_stdout
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import plistlib
import socket
import struct
import subprocess
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from wechat_cli.keys import common, scanner_macos as scanner


KEY = bytes(range(32))
PID = 123


def page_for(salt, key=KEY):
    """生成满足项目 HMAC 约定的首页，无真实用户数据。"""
    page = bytearray(b"\x81" * 4096)
    page[:16] = salt
    mac_key = hashlib.pbkdf2_hmac("sha512", key, bytes(b ^ 0x3A for b in salt), 2, 32)
    page[-64:] = hmac.new(mac_key, page[16:4032] + struct.pack("<I", 1), hashlib.sha512).digest()
    return bytes(page)


def report_for(extract=True, count=1, **extra):
    return {
        "protocol": 1, "pid": PID, "task_port": True, "kr": 0,
        "scan_complete": True, "candidate_channel": extract,
        "candidate_count": count, "candidate_write_ok": True, **extra,
    }


class FakeProcess:
    """模拟子进程，使用真实匿名 FD 但不启动任何系统程序。"""

    def __init__(self, args, *, stdout_data, stderr_data=b"", payload=b"", code=0,
                 keep_running=False, **kwargs):
        self.args = args
        self.returncode = None if keep_running else code
        self.killed = False
        self.waited = False
        self.stdout = self._pipe(stdout_data)
        self.stderr = self._pipe(stderr_data)
        if kwargs.get("pass_fds"):
            fd = kwargs["pass_fds"][0]
            self.peer = socket.socket(fileno=os.dup(fd))
            def send_payload():
                try:
                    if payload:
                        self.peer.sendall(payload)
                    self.peer.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                finally:
                    self.peer.close()

            self.sender = threading.Thread(target=send_payload, daemon=True)
            self.sender.start()

    @staticmethod
    def _pipe(data):
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, data)
        finally:
            os.close(write_fd)
        return os.fdopen(read_fd, "rb")

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.waited = True
        if self.returncode is None:
            raise subprocess.TimeoutExpired(self.args, timeout)
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9


class MacOSKeysTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = self.root / "db_storage"
        self.db.mkdir()
        self.salt = bytes(range(16, 32))
        self.page = page_for(self.salt)
        (self.db / "one.db").write_bytes(self.page)
        # 所有外部程序默认禁止；具体测试只能覆盖为 mock。
        self.command_mock = self.stack.enter_context(patch.object(scanner.subprocess, "run", side_effect=AssertionError("禁止系统命令")))
        self.popen = self.stack.enter_context(patch.object(scanner.subprocess, "Popen", side_effect=AssertionError("禁止启动进程")))
        self.stack.enter_context(patch.object(scanner.platform, "machine", return_value="arm64"))
        self.stack.enter_context(patch.object(scanner.sys, "platform", "darwin"))

    def extract_with(self, payload, report=None, output=None, **kwargs):
        with patch.object(scanner, "_find_binary", return_value="/synthetic/helper"), patch.object(
            scanner, "_run_helper", return_value=(report or report_for(), payload)
        ):
            return scanner.extract_keys(self.db, output, pid=PID, **kwargs)

    def test_verified_candidates_only_and_no_logging_or_implicit_output(self):
        second_salt = bytes(range(32, 48))
        (self.db / "two.db").write_bytes(page_for(second_salt))
        payload = bytearray(b"\xff" * 32 + KEY + KEY)
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(output), patch.object(common, "save_results") as save:
            keys = self.extract_with(payload)
        self.assertEqual(keys, {self.salt.hex(): KEY.hex(), second_salt.hex(): KEY.hex()})
        self.assertEqual(output.getvalue(), "")
        save.assert_not_called()
        self.assertEqual(payload, bytearray(len(payload)))
        self.assertEqual((self.db / "one.db").read_bytes(), self.page)
        self.assertFalse((self.db.parent / "all_keys.json").exists())

    def test_explicit_save_uses_common_without_key_logging(self):
        target = self.root / "results.json"
        with patch.object(common, "save_results", wraps=common.save_results) as save:
            result = self.extract_with(bytearray(KEY), output=target)
        self.assertEqual(result[self.salt.hex()], KEY.hex())
        save.assert_called_once()
        self.assertEqual(json.loads(target.read_text())["one.db"]["enc_key"], KEY.hex())
        self.assertEqual((self.db / "one.db").read_bytes(), self.page)

    def test_invalid_key_never_saves(self):
        payload = bytearray(b"\x42" * 32)
        with patch.object(common, "save_results") as save, self.assertRaisesRegex(RuntimeError, "HMAC"):
            self.extract_with(payload, output=self.root / "results.json")
        save.assert_not_called()
        self.assertEqual(payload, bytearray(32))

    def test_permission_denial_never_resigns_restarts_or_saves(self):
        with patch.object(common, "save_results") as save, self.assertRaisesRegex(RuntimeError, "权限被系统拒绝"):
            self.extract_with(bytearray(), {"task_port": False}, allow_restart=True)
        self.command_mock.assert_not_called()
        self.popen.assert_not_called()
        save.assert_not_called()
        self.assertFalse(hasattr(scanner, "_resign_wechat"))

    def test_frida_fails_explicitly_before_any_side_effect(self):
        for restart in (False, True):
            with self.subTest(restart=restart), self.assertRaisesRegex(RuntimeError, "尚未可靠实现"):
                scanner.extract_keys("/nonexistent", method="frida", allow_restart=restart)
        self.command_mock.assert_not_called()
        self.popen.assert_not_called()

    def test_probe_aggregates_only(self):
        memory = report_for(extract=False, count=0)
        with patch.object(scanner, "_find_binary", return_value="/synthetic/helper"), patch.object(
            scanner, "_run_helper", return_value=(memory, bytearray())
        ) as helper, patch.object(scanner, "_signature_diagnostics", return_value={"status": "verified"}), patch.object(
            scanner, "_process_path", return_value="/Applications/WeChat.app/Contents/MacOS/WeChat"
        ), patch.object(common, "verify_enc_key") as verify, patch.object(common, "save_results") as save:
            result = scanner.probe(self.db, pid=PID)
        helper.assert_called_once_with("/synthetic/helper", PID)
        verify.assert_not_called()
        save.assert_not_called()
        self.assertEqual(result["database_count"], 1)
        self.assertEqual(result["salt_count"], 1)
        self.assertNotIn(KEY.hex(), json.dumps(result))
        self.assertFalse(result["frida_available"])

    def test_plaintext_and_short_pages_are_excluded(self):
        (self.db / "plain.db").write_bytes(b"SQLite format 3\0" + b"\0" * 4080)
        (self.db / "short.db").write_bytes(b"\0" * 100)
        rows, salts = scanner._db_files(self.db)
        self.assertEqual(len(rows), 1)
        self.assertEqual(set(salts), {self.salt.hex()})

    def test_pid_selection_and_validation(self):
        for pid in (True, 0, -1, "123", 2**31):
            with self.subTest(pid=pid), self.assertRaises(ValueError):
                scanner._resolve_pid(pid)
        with patch.object(scanner, "_run_command", return_value=SimpleNamespace(returncode=0, stdout=b"123\n")):
            self.assertEqual(scanner._resolve_pid(None), PID)
        for raw in (b"", b"123\n456\n", b"not-a-pid"):
            with patch.object(scanner, "_run_command", return_value=SimpleNamespace(returncode=0, stdout=raw)):
                with self.assertRaises(RuntimeError):
                    scanner._resolve_pid(None)

    def test_method_validation(self):
        for method in ("probe", "unknown"):
            with self.assertRaises(ValueError):
                scanner.extract_keys(self.db, method=method)
        with self.assertRaises(ValueError):
            scanner.extract_keys(self.db, allow_restart="yes")

    def test_protocol_rejects_secrets_unknown_fields_and_wrong_types(self):
        for value in (
            {"protocol": 0, "pid": PID}, {"protocol": 1, "pid": PID + 1},
            {"protocol": 1, "pid": PID, "key": KEY.hex()},
            {"protocol": 1, "pid": PID, "needle_hits": KEY.hex()},
            {"protocol": 1, "pid": PID, "candidate_count": True}, [],
        ):
            with self.subTest(value=value), self.assertRaises(RuntimeError) as exc:
                scanner._parse_report(json.dumps(value).encode(), PID)
            self.assertNotIn(KEY.hex(), str(exc.exception))

    def fake_helper(self, report=None, payload=b"", stderr=b"", code=0, keep_running=False):
        created = []

        def factory(args, **kwargs):
            proc = FakeProcess(args, stdout_data=json.dumps(report or report_for()).encode(),
                               stderr_data=stderr, payload=payload, code=code,
                               keep_running=keep_running, **kwargs)
            created.append(proc)
            return proc

        mock = self.stack.enter_context(patch.object(scanner.subprocess, "Popen", side_effect=factory))
        return created, mock

    def test_anonymous_fd_transport_and_no_database_argument(self):
        created, mock = self.fake_helper(payload=KEY)
        report, payload = scanner._run_helper("/synthetic/helper", PID, extract=True)
        self.assertEqual(payload, KEY)
        self.assertEqual(report["candidate_count"], 1)
        args, kwargs = mock.call_args
        self.assertEqual(args[0][:4], ["/synthetic/helper", "--extract-candidates", "--pid", str(PID)])
        self.assertEqual(len(kwargs["pass_fds"]), 1)
        self.assertTrue(kwargs["close_fds"])
        self.assertNotIn("cwd", kwargs)
        self.assertNotIn(str(self.db), args[0])
        self.assertTrue(created[0].waited)
        self.assertTrue(created[0].stdout.closed)
        self.assertTrue(created[0].stderr.closed)
        with self.assertRaises(OSError):
            os.fstat(kwargs["pass_fds"][0])

    def test_probe_helper_never_opens_candidate_channel(self):
        _, mock = self.fake_helper(report_for(extract=False, count=0))
        report, payload = scanner._run_helper("/synthetic/helper", PID)
        self.assertEqual(payload, b"")
        self.assertFalse(report["candidate_channel"])
        self.assertEqual(mock.call_args.kwargs["pass_fds"], ())
        self.assertEqual(mock.call_args.args[0], ["/synthetic/helper", "--pid", str(PID)])

    def test_helper_permission_report_is_read_only(self):
        self.fake_helper({"protocol": 1, "pid": PID, "task_port": False, "kr": 5}, code=27)
        report, payload = scanner._run_helper("/synthetic/helper", PID)
        self.assertFalse(report["task_port"])
        self.assertEqual(payload, b"")

    def test_transport_rejects_truncation_mismatch_and_stderr(self):
        cases = [(KEY[:-1], report_for(), b""), (KEY, report_for(count=2), b""),
                 (KEY, report_for(candidate_channel=False), b""),
                 (KEY, report_for(), KEY.hex().encode()),
                 (KEY, report_for(scan_complete=False), b"")]
        for payload, report, stderr in cases:
            with self.subTest(length=len(payload), report=report):
                created, _ = self.fake_helper(report, payload, stderr)
                with self.assertRaises(RuntimeError) as exc:
                    scanner._run_helper("/synthetic/helper", PID, extract=True)
                self.assertNotIn(KEY.hex(), str(exc.exception))
                self.assertTrue(created[0].waited)

    def test_transport_size_limit_and_timeout_cleanup(self):
        created, _ = self.fake_helper(payload=KEY * 257, report=report_for(count=257))
        with self.assertRaisesRegex(RuntimeError, "长度限制"):
            scanner._run_helper("/synthetic/helper", PID, extract=True)
        self.assertTrue(created[0].waited)
        created, _ = self.fake_helper(keep_running=True)
        with patch.object(scanner, "_TIMEOUT", 0), self.assertRaisesRegex(RuntimeError, "超时"):
            scanner._run_helper("/synthetic/helper", PID)
        self.assertTrue(created[0].killed)
        self.assertTrue(created[0].waited)

    def test_signature_diagnostics_are_read_only_and_sanitized(self):
        entitlements = plistlib.dumps({"com.apple.security.cs.debugger": True,
                                     "com.apple.security.get-task-allow": False,
                                     "unexpected": KEY.hex()})
        with patch.object(scanner, "_run_command", side_effect=[
            SimpleNamespace(returncode=0), SimpleNamespace(returncode=0, stdout=b"", stderr=b"prefix\n" + entitlements),
        ]) as run:
            result = scanner._signature_diagnostics("/Applications/WeChat.app")
        self.assertTrue(result["debugger"])
        self.assertFalse(result["get_task_allow"])
        self.assertNotIn(KEY.hex(), json.dumps(result))
        self.assertTrue(all("--sign" not in call.args[0] and "--force" not in call.args[0]
                            for call in run.call_args_list))

    def test_resources_and_pyinstaller_paths(self):
        for name in ("find_all_keys_macos.c", "MemoryProbe-Info.plist", "memory_probe.entitlements.plist"):
            self.assertTrue(scanner._resource_path(name).is_file())
        for layout in ("wechat_cli/bin", "bin"):
            frozen = self.root / layout.replace("/", "-")
            resource = frozen / layout / "MemoryProbe-Info.plist"
            resource.parent.mkdir(parents=True)
            resource.write_bytes(b"synthetic")
            with patch.object(scanner.sys, "frozen", True, create=True), patch.object(
                scanner.sys, "_MEIPASS", str(frozen), create=True
            ):
                self.assertEqual(scanner._resource_path("MemoryProbe-Info.plist"), resource)

    def test_old_binary_is_never_used_or_built_implicitly(self):
        with patch.object(scanner, "_build_root", return_value=self.root), self.assertRaisesRegex(RuntimeError, "build_probe"):
            scanner._find_binary()
        self.command_mock.assert_not_called()
        self.popen.assert_not_called()

    def test_build_signs_only_fresh_helper_and_never_executes_it(self):
        commands = []

        def command(args, timeout=15):
            commands.append(args)
            if "clang" in args:
                Path(args[-1]).write_bytes(b"synthetic executable")
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

        with patch.object(scanner, "_run_command", side_effect=command), patch.object(
            scanner, "_signature_diagnostics", return_value={"status": "verified", "debugger": True}
        ):
            result = scanner.build_probe(self.root / "build")
        bundle = Path(result["bundle"])
        self.assertTrue(Path(result["binary"]).is_file())
        signed = [args[-1] for args in commands if "--sign" in args]
        self.assertEqual(signed, [result["binary"], result["bundle"]])
        self.assertTrue(all(Path(target).is_relative_to(bundle) for target in signed))
        self.popen.assert_not_called()
        with self.assertRaises(FileExistsError):
            scanner.build_probe(self.root / "build")

    def test_build_refuses_app_directories_and_cleans_failed_build(self):
        with self.assertRaises(ValueError):
            scanner.build_probe(self.root / "Official.app" / "Contents")
        with patch.object(scanner, "_run_command", return_value=SimpleNamespace(returncode=1)), self.assertRaisesRegex(
            RuntimeError, "编译失败"
        ):
            scanner.build_probe(self.root / "build")
        self.assertFalse((self.root / "build" / scanner._bundle_name()).exists())
        self.command_mock.assert_not_called()
        self.popen.assert_not_called()

    def test_native_source_is_read_only_and_retains_license(self):
        source = scanner._resource_path("find_all_keys_macos.c").read_text()
        self.assertIn("Copyright 2026 wechat4mac contributors", source)
        self.assertIn('Licensed under the Apache License, Version 2.0', source)
        for forbidden in ("fopen(", "popen(", "mach_vm_write(", "all_keys.json", "codesign"):
            self.assertNotIn(forbidden, source)
        self.assertIn("private_candidate_fd(candidate_fd)", source)
        self.assertIn("if (extract_mode) collect_hex_candidates", source)
        entitlements = plistlib.loads(scanner._resource_path("memory_probe.entitlements.plist").read_bytes())
        self.assertEqual(entitlements, {"com.apple.security.cs.debugger": True})
        info = plistlib.loads(scanner._resource_path("MemoryProbe-Info.plist").read_bytes())
        self.assertEqual(info["CFBundleIdentifier"], scanner._BUNDLE_ID)
        self.assertEqual(info["CFBundleExecutable"], scanner._EXECUTABLE)


if __name__ == "__main__":
    unittest.main()

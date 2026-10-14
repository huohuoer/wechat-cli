"""跨平台密钥合成回归；不读取真实进程、不附加 GDB、不更改权限。"""

import contextlib
import ctypes
import hashlib
import hmac
import io
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

from wechat_cli.keys import capture_linux as capture
from wechat_cli.keys import cipher_config as cipher
from wechat_cli.keys import common
from wechat_cli.keys import scanner_linux as linux
from wechat_cli.keys import scanner_windows as windows


def make_page(key, salt=bytes(range(16))):
    page = bytearray(salt + bytes([0x57]) * (4096 - 16))
    mac_key = hashlib.pbkdf2_hmac("sha512", key, bytes(b ^ 0x3A for b in salt), 2, 32)
    page[4032:] = hmac.new(mac_key, bytes(page[16:4032]) + struct.pack("<I", 1),
                          hashlib.sha512).digest()
    return bytes(page)


def database(page):
    salt = page[:16].hex()
    return [("test.db", "/synthetic/test.db", 4096, salt, page)], {salt: ["test.db"]}


class SyntheticMemory:
    def __init__(self, phase=0, literal=None, blob_offset=0x90):
        self.base = 0x10000
        self.data = bytearray(0x3000)
        self.key = bytes(range(32))
        self.marker = self.base + 0x100
        self.node = self.base + 0x200
        self.config = self.base + 0x500
        self.blob = self.base + 0x1000
        self.data[0x100:0x100 + len(cipher.CONFIG_CIPHER_NAME)] = cipher.CONFIG_CIPHER_NAME
        struct.pack_into("<QQ", self.data, 0x210, self.marker, len(cipher.CONFIG_CIPHER_NAME))
        struct.pack_into("<Q", self.data, 0x228, self.config)
        plain = literal or b"x'" + self.key.hex().encode() + b"'"
        encoded = bytes(value ^ cipher.CONFIG_XOR_MASK[(i + phase) % 32]
                        for i, value in enumerate(plain))
        struct.pack_into("<QQ", self.data, 0x500 + blob_offset, self.blob, len(encoded))
        self.data[0x1000:0x1000 + len(encoded)] = encoded
        self.reads = []

    def read(self, address, size):
        self.reads.append((address, size))
        offset = address - self.base
        if offset < 0 or offset + size > len(self.data):
            return None
        return bytes(self.data[offset:offset + size])

    def scan(self, page=None):
        dbs, salts = database(page or make_page(self.key))
        result = {}
        cipher.scan_cipher_config(self.read, [(self.base, len(self.data))], dbs,
                                  result, set(salts))
        return result


def make_elf(text_va=0x6000, ambiguous=False):
    data = bytearray(0x2100)
    data[:6] = b"\x7fELF\x02\x01"
    etype = 2 if text_va >= 0x400000 else 3
    struct.pack_into("<HHIQQQIHHHHHH", data, 16, etype, 62, 1, 0, 64, 0x300,
                     0, 64, 56, 1, 64, 4, 1)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0x1000, text_va, 0, 0x200, 0x1000, 0x1000)
    names = b"\0.shstrtab\0.text\0.rodata\0"
    data[0x200:0x200 + len(names)] = names
    for index, values in enumerate([
        (0, 0, 0, 0, 0, 0), (1, 3, 0, 0, 0x200, len(names)),
        (11, 1, 6, text_va, 0x1000, 0x200), (17, 1, 2, 0xA000, 0x2000, 0x100),
    ]):
        struct.pack_into("<IIQQQQIIQQ", data, 0x300 + index * 64, *values, 0, 0, 1, 0)
    text = bytearray(0x200)

    def lea(offset, opcode, target):
        text[offset:offset + 3] = opcode
        struct.pack_into("<i", text, offset + 3, target - (text_va + offset + 7))

    text[0x20:0x23] = b"\x55\x41\x57"
    lea(0x40, b"\x48\x8d\x35", 0x9000)
    lea(0x100, b"\x48\x8d\x3d", 0x9000)
    lea(0x107, b"\x48\x8d\x35", 0xA000)
    if ambiguous:
        text[0x170:0x173] = b"\x55\x41\x57"
        lea(0x180, b"\x48\x8d\x35", 0x9000)
    data[0x1000:0x1200] = text
    data[0x2000:0x2000 + len(cipher.CONFIG_CIPHER_NAME)] = cipher.CONFIG_CIPHER_NAME
    return data


class CipherTests(unittest.TestCase):
    def test_known_object_xor_hmac(self):
        memory = SyntheticMemory()
        self.assertEqual(memory.scan(), {bytes(range(16)).hex(): memory.key.hex()})
        self.assertIn((memory.config + 0x88, 0x28), memory.reads)

    def test_bounded_alternate_object_offset_and_xor_phase(self):
        memory = SyntheticMemory(phase=13, blob_offset=0x150)
        self.assertTrue(memory.scan())

    def test_long_literal_windows_and_uppercase(self):
        key = bytes(range(32))
        literal = b"X'" + b"f" * 32 + key.hex().upper().encode() + b"a" * 32 + b"'"
        self.assertTrue(SyntheticMemory(literal=literal).scan())

    def test_bad_hmac_rejected(self):
        self.assertEqual(SyntheticMemory().scan(make_page(b"Q" * 32)), {})

    def test_corrupt_marker_reference_rejected(self):
        memory = SyntheticMemory()
        struct.pack_into("<Q", memory.data, 0x218, 99)
        self.assertEqual(memory.scan(), {})

    def test_no_marker_does_not_follow_unrelated_objects(self):
        memory = SyntheticMemory()
        memory.data[0x100:0x140] = b"\0" * 64
        self.assertEqual(memory.scan(), {})
        self.assertEqual(len(memory.reads), 1)

    def test_invalid_pointer_and_oversize_blob_rejected(self):
        for pointer, size in [(0, 67), (0x800000000000, 67), (0x11000, 0),
                              (0x11000, cipher.MAX_BLOB + 1)]:
            with self.subTest(pointer=pointer, size=size):
                memory = SyntheticMemory()
                struct.pack_into("<QQ", memory.data, 0x590, pointer, size)
                self.assertEqual(memory.scan(), {})
                self.assertFalse(any(address == memory.blob for address, _ in memory.reads))

    def test_partial_blob_rejected(self):
        memory = SyntheticMemory()
        original = memory.read

        def read(address, size):
            result = original(address, size)
            return result[:-1] if address == memory.blob else result

        memory.read = read
        self.assertEqual(memory.scan(), {})

    def test_marker_and_reference_cross_chunk_boundaries(self):
        for pattern in [cipher.CONFIG_CIPHER_NAME, struct.pack("<QQ", 0x11111, 28)]:
            payload = b"_" * 55 + pattern + b"_" * 50
            read = lambda addr, size: payload[addr:addr + size]
            with mock.patch.object(cipher, "SCAN_CHUNK", 64), mock.patch.object(
                    cipher, "iter_memory_chunks", side_effect=lambda r, regs, overlap:
                    original(r, regs, overlap, chunk_size=64)):
                original = cipher.iter_memory_chunks.__dict__.get("unused")
                # 原实现显式设置小块，避免测试构造真实大小内存。
                original = iter_chunks
                self.assertEqual(cipher._find_addresses(read, [(0, len(payload))],
                                                        [pattern], 10), [55])

    def test_read_gap_is_not_joined(self):
        payload = b"_" * 60 + b"x'" + b"a" * 64 + b"'"
        read = lambda addr, size: None if addr == 0 else payload[addr:addr + size]
        chunks = list(cipher.iter_memory_chunks(read, [(0, len(payload))], chunk_size=64))
        self.assertFalse(any(cipher.HEX_LITERAL_RE.search(data) for _, data in chunks))

    def test_log_does_not_print_key(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            cipher.quiet_log("    enc_key=" + "a" * 64)
            cipher.quiet_log("PASSPHRASE=" + "b" * 64)
            cipher.quiet_log("验证完成")
        self.assertEqual(output.getvalue().strip(), "验证完成")


iter_chunks = cipher.iter_memory_chunks


class ElfTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "wechat"
        self.path.write_bytes(make_elf())

    def test_dynamic_hook_location(self):
        self.assertEqual(capture.find_hook_offset(self.path), 0x6020)

    def test_pie_load_bias_not_executable_mapping_start(self):
        maps = f"70006000-70007000 r-xp 00001000 00:00 1 {self.path}\n"
        self.assertEqual(capture.find_runtime_base(123, self.path, maps), 0x70000000)

    def test_non_pie_load_bias_zero(self):
        self.path.write_bytes(make_elf(text_va=0x406000))
        maps = f"00406000-00407000 r-xp 00001000 00:00 1 {self.path}\n"
        self.assertEqual(capture.find_runtime_base(123, self.path, maps), 0)
        self.assertEqual(capture.find_hook_offset(self.path), 0x406020)

    def test_same_basename_mapping_not_accepted(self):
        maps = "70006000-70007000 r-xp 00001000 00:00 1 /elsewhere/wechat\n"
        with self.assertRaises(capture.CaptureError):
            capture.find_runtime_base(123, self.path, maps)

    def test_reject_unsupported_arch_truncated_and_ambiguous(self):
        arm = make_elf()
        struct.pack_into("<H", arm, 18, 183)
        for data in [arm, b"\x7fELF", make_elf()[:0x1000], make_elf(ambiguous=True)]:
            with self.subTest(length=len(data)):
                self.path.write_bytes(data)
                with self.assertRaises(capture.CaptureError):
                    capture.find_hook_offset(self.path)

    def test_missing_anchor_rejected(self):
        data = make_elf()
        data[0x2000:0x2100] = b"\0" * 256
        self.path.write_bytes(data)
        with self.assertRaises(capture.CaptureError):
            capture.find_hook_offset(self.path)


class CaptureTests(unittest.TestCase):
    def test_pbkdf2_and_hmac_for_each_salt(self):
        passphrase = bytes(range(32))
        dbs, salts, expected = [], {}, {}
        for value in (3, 7):
            salt = bytes([value]) * 16
            key = hashlib.pbkdf2_hmac("sha512", passphrase, salt, 256000, 32)
            rows, mapping = database(make_page(key, salt))
            dbs.extend(rows)
            salts.update(mapping)
            expected[salt.hex()] = key.hex()
        self.assertEqual(capture.derive_keys_from_passphrase(passphrase, dbs, salts), expected)
        self.assertEqual(capture.derive_keys_from_passphrase(b"X" * 32, dbs, salts), {})

    def test_bad_passphrase_length_rejected(self):
        for phrase in (b"", b"X" * 31, "X" * 32):
            with self.assertRaises(ValueError):
                capture.derive_keys_from_passphrase(phrase, [], {})

    def test_gdb_known_parameter_layouts_use_only_pipe(self):
        phrase = bytes(range(32))
        for indirect in (False, True):
            reads, writes, commands = [], [], []

            def read_memory(address, size):
                reads.append((address, size))
                return memoryview(struct.pack("<QQ", 0x20000, 32) if size == 16 else phrase)

            class Breakpoint:
                def __init__(self, address):
                    self.address = address
                    fake.bp = self

                def delete(self):
                    commands.append("delete")

            def execute(command):
                commands.append(command)
                if command == "continue":
                    self.assertTrue(fake.bp.stop())

            fake = types.SimpleNamespace(
                Breakpoint=Breakpoint, execute=execute,
                parse_and_eval=lambda register: 0x10000 if register == "$rsi" else (0 if indirect else 32),
                selected_inferior=lambda: types.SimpleNamespace(read_memory=read_memory),
            )
            script = capture._gdb_script(123, 0x70006020, 9)
            code = script.split("\npython\n", 1)[1].rsplit("\nend\n", 1)[0]
            with mock.patch.dict(sys.modules, {"gdb": fake}), mock.patch.object(
                    os, "write", side_effect=lambda fd, data: writes.append((fd, data))):
                exec(code, {})
            self.assertEqual(writes, [(9, phrase)])
            self.assertEqual(commands, ["continue", "delete", "detach"])
            self.assertNotIn(".hex()", script)
            self.assertNotIn("print(", script)

    def _mock_capture(self, timeout=False):
        phrase = bytes(range(32))
        process = mock.Mock(returncode=0)
        process.poll.return_value = 0
        kwargs_seen = {}

        def start(args, **kwargs):
            kwargs_seen.update(kwargs)
            self.assertNotIn("sudo", args)
            self.assertIn("--nx", args)
            if not timeout:
                os.write(kwargs["pass_fds"][0], phrase)
            return process

        if timeout:
            process.communicate.side_effect = [subprocess.TimeoutExpired("gdb", 1), (None, None)]
        with mock.patch.object(capture.shutil, "which", return_value="/mock/gdb"), mock.patch.object(
                capture.Path, "read_text", return_value="TracerPid:\t0\n"), mock.patch.object(
                capture.os, "readlink", return_value="/mock/wechat"), mock.patch.object(
                capture, "find_hook_offset", return_value=0x6020), mock.patch.object(
                capture, "find_runtime_base", return_value=0x70000000), mock.patch.object(
                capture.subprocess, "Popen", side_effect=start):
            if timeout:
                with self.assertRaisesRegex(capture.CaptureError, "超时"):
                    capture.capture_passphrase(123, timeout=1)
                process.send_signal.assert_called_once_with(signal.SIGINT)
                process.kill.assert_not_called()
            else:
                self.assertEqual(capture.capture_passphrase(123), phrase)
                self.assertEqual(kwargs_seen["stdout"], subprocess.DEVNULL)
                self.assertEqual(kwargs_seen["stderr"], subprocess.DEVNULL)
            fd = kwargs_seen["pass_fds"][0]
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_capture_pipe_and_fd_cleanup(self):
        self._mock_capture()

    def test_timeout_interrupts_only_own_gdb(self):
        self._mock_capture(timeout=True)

    def test_missing_gdb_does_not_start_process(self):
        with mock.patch.object(capture.shutil, "which", return_value=None), mock.patch.object(
                capture.subprocess, "Popen") as start:
            with self.assertRaises(capture.CaptureError):
                capture.capture_passphrase(123)
            start.assert_not_called()

    def test_existing_tracer_does_not_start_process(self):
        with mock.patch.object(capture.shutil, "which", return_value="/mock/gdb"), mock.patch.object(
                capture.Path, "read_text", return_value="TracerPid:\t99\n"), mock.patch.object(
                capture.subprocess, "Popen") as start:
            with self.assertRaises(capture.CaptureError):
                capture.capture_passphrase(123)
            start.assert_not_called()


class ScannerTests(unittest.TestCase):
    def test_windows_mbi_native_64bit_offsets(self):
        if ctypes.sizeof(ctypes.c_void_p) == 8:
            self.assertEqual(ctypes.sizeof(windows.MBI), 48)
            self.assertEqual(windows.MBI.RegionSize.offset, 24)

    def test_windows_binding_pointer_sized_signatures(self):
        lib = mock.Mock()
        with mock.patch.object(windows.os, "name", "nt"), mock.patch.object(
                windows.ctypes, "WinDLL", return_value=lib, create=True):
            self.assertIs(windows._bind_kernel32(), lib)
        self.assertIs(lib.OpenProcess.restype, ctypes.c_void_p)
        self.assertIs(lib.VirtualQueryEx.restype, ctypes.c_size_t)
        self.assertIs(lib.ReadProcessMemory.argtypes[0], ctypes.c_void_p)
        self.assertIs(lib.CloseHandle.argtypes[0], ctypes.c_void_p)

    def test_windows_partial_read_keeps_prefix(self):
        def native_read(handle, address, buf, size, actual):
            ctypes.memmove(buf, b"abc", 3)
            ctypes.cast(actual, ctypes.POINTER(ctypes.c_size_t))[0] = 3
            return 0

        with mock.patch.object(windows, "kernel32", types.SimpleNamespace(ReadProcessMemory=native_read)):
            self.assertEqual(windows._read_mem(0x100000001, 0x10000, 10), b"abc")

    def test_windows_primary_before_fallback_no_key_log_and_none_forwarded(self):
        memory = SyntheticMemory()
        dbs, salts = database(make_page(memory.key))
        events = []
        lib = mock.Mock()
        lib.OpenProcess.return_value = 0x100000001
        saver = lambda rows, mapping, result, output, logger: result
        with mock.patch.object(windows, "kernel32", lib), mock.patch.object(
                windows, "collect_db_files", return_value=(dbs, salts)), mock.patch.object(
                windows, "_enum_regions", return_value=[(memory.base, len(memory.data))]), mock.patch.object(
                windows, "_read_mem", side_effect=lambda h, a, s: memory.read(a, s)), mock.patch.object(
                windows, "scan_cipher_config", side_effect=lambda *args: events.append("config")), mock.patch.object(
                windows, "scan_memory_for_keys", wraps=common.scan_memory_for_keys) as fallback, mock.patch.object(
                windows, "save_results", side_effect=saver) as save, contextlib.redirect_stdout(io.StringIO()) as out:
            memory.data[0x1800:0x1800 + 67] = b"x'" + memory.key.hex().encode() + b"'"
            result = windows.extract_keys("/synthetic", pid=123)
        self.assertEqual(events, ["config"])
        fallback.assert_called_once()
        self.assertEqual(result, {next(iter(salts)): memory.key.hex()})
        self.assertIsNone(save.call_args.args[3])
        lib.CloseHandle.assert_called_once_with(0x100000001)
        self.assertNotIn(memory.key.hex(), out.getvalue())

    def test_windows_config_success_skips_traditional_scan(self):
        memory = SyntheticMemory()
        dbs, salts = database(make_page(memory.key))
        lib = mock.Mock()
        with mock.patch.object(windows, "kernel32", lib), mock.patch.object(
                windows, "collect_db_files", return_value=(dbs, salts)), mock.patch.object(
                windows, "_enum_regions", return_value=[(memory.base, len(memory.data))]), mock.patch.object(
                windows, "_read_mem", side_effect=lambda h, a, s: memory.read(a, s)), mock.patch.object(
                windows, "scan_memory_for_keys") as fallback, mock.patch.object(windows, "save_results"):
            windows.extract_keys("/synthetic", pid=123)
        fallback.assert_not_called()
        lib.CloseHandle.assert_called_once()

    def test_linux_actual_open_does_not_require_root(self):
        with mock.patch("builtins.open", return_value=io.BytesIO(b"memory")) as opened:
            mem = linux._check_permissions(123)
        opened.assert_called_once_with("/proc/123/mem", "rb")
        mem.close()

    def test_linux_default_memory_does_not_capture_and_suppresses_key(self):
        key = bytes(range(32))
        dbs, salts = database(make_page(key))
        data = b"x'" + key.hex().encode() + b"'"
        with mock.patch.object(linux, "collect_db_files", return_value=(dbs, salts)), mock.patch.object(
                linux, "_get_readable_regions", return_value=[(0, len(data))]), mock.patch.object(
                linux, "_check_permissions", return_value=io.BytesIO(data)), mock.patch.object(
                linux, "_is_wechat_process", return_value=True), mock.patch.object(
                linux, "capture_passphrase") as gdb, mock.patch.object(
                linux, "save_results", side_effect=lambda d, s, result, o, p: result), contextlib.redirect_stdout(
                io.StringIO()) as out:
            result = linux.extract_keys("/synthetic", pid=123)
        self.assertEqual(result, {next(iter(salts)): key.hex()})
        gdb.assert_not_called()
        self.assertNotIn(key.hex(), out.getvalue())

    def test_linux_gdb_explicit_and_none_forwarded(self):
        dbs, salts = database(make_page(bytes(range(32))))
        with mock.patch.object(linux, "collect_db_files", return_value=(dbs, salts)), mock.patch.object(
                linux, "_is_wechat_process", return_value=True), mock.patch.object(
                linux, "capture_passphrase", return_value=bytes(range(32))) as gdb, mock.patch.object(
                linux, "derive_keys_from_passphrase", return_value={}) as derive, mock.patch.object(
                linux, "save_results") as save, mock.patch.object(linux, "_check_permissions") as memory, contextlib.redirect_stdout(io.StringIO()):
            linux.extract_keys("/synthetic", pid=123, method="gdb", timeout=10)
        gdb.assert_called_once_with(123, timeout=10)
        derive.assert_called_once()
        self.assertIsNone(save.call_args.args[3])
        memory.assert_not_called()

    def test_linux_permission_denied_is_actionable_without_setcap(self):
        dbs, salts = database(make_page(bytes(range(32))))
        with mock.patch.object(linux, "collect_db_files", return_value=(dbs, salts)), mock.patch.object(
                linux, "_get_readable_regions", return_value=[]), mock.patch.object(
                linux, "_check_permissions", side_effect=PermissionError), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(RuntimeError) as error:
                linux.extract_keys("/synthetic", pid=123)
        self.assertIn("权限", str(error.exception))
        self.assertNotIn("setcap", str(error.exception))
        self.assertNotIn("sudo", str(error.exception))

    def test_invalid_method_and_pid_rejected_before_access(self):
        with self.assertRaises(ValueError):
            linux.extract_keys("/synthetic", method="auto")
        with self.assertRaises(ValueError):
            linux.extract_keys("/synthetic", pid=-1)


if __name__ == "__main__":
    unittest.main()

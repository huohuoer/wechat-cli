"""macOS 微信 4.x 只读探针及经数据库 HMAC 验证的密钥提取。"""

import ctypes
import json
import math
import os
from pathlib import Path
import platform
import plistlib
import selectors
import shutil
import socket
import subprocess
import sys
import time

from . import common


_PROTOCOL = 1
_MAX_CANDIDATES = 256
_MAX_DIAGNOSTICS = 16384
_TIMEOUT = 180
_BUNDLE_ID = "com.local.wechat-cli.memory-probe"
_EXECUTABLE = "WeChatMemoryProbe"
_FRIDA_UNAVAILABLE = (
    "Frida Gadget 链尚未可靠实现：独立容器数据路由、权限边界、token 认证、"
    "副本子进程回收及上游许可尚未完整验证；不会修改或启动官方微信。"
)
_BOOL_FIELDS = {"task_port", "scan_complete", "candidate_channel", "candidate_write_ok"}
_COUNT_FIELDS = {
    "protocol", "pid", "kr", "needle_hits", "pair_refs", "candidate_nodes",
    "unique_config_ptrs", "referenced_blobs", "plain_hex_literals", "xor_hex_literals",
    "regions_scanned", "read_failures", "candidate_count",
}


def _architecture():
    machine = platform.machine()
    if machine not in ("arm64", "x86_64"):
        raise RuntimeError(f"不支持的 macOS 架构: {machine}")
    return machine


def _resource_path(name):
    """按包路径定位资源，兼容两种 PyInstaller 布局。"""
    bases = [Path(__file__).resolve().parent.parent]
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        bases[:0] = [Path(sys._MEIPASS) / "wechat_cli", Path(sys._MEIPASS)]
    for base in bases:
        path = base / "bin" / name
        if path.is_file():
            return path
    raise RuntimeError(f"缺少 macOS helper 资源: {name}；请检查打包内容")


def _bundle_name():
    return f"WeChatMemoryProbe.v{_PROTOCOL}.{_architecture()}.app"


def _build_root():
    return Path.home() / "Library" / "Caches" / "wechat-cli" / "macos-probe"


def _find_binary():
    name = f"{_bundle_name()}/Contents/MacOS/{_EXECUTABLE}"
    try:
        binary = _resource_path(name)
    except RuntimeError:
        binary = _build_root() / name
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise RuntimeError("未找到新版签名 helper；请显式调用 build_probe()，不会自动编译或签名")
    # 不回退到会打印和落盘密钥的旧 find_all_keys_macos 二进制。
    return str(binary)


def _run_command(args, timeout=15):
    """系统命令输出仅内部使用，不向日志转发。"""
    try:
        return subprocess.run(args, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("macOS 诊断或构建命令不可用/超时") from None


def _signature_diagnostics(path):
    """只读检查，不将目标 entitlement 当成授权或尝试修复。"""
    if not path:
        return {"status": "path_unavailable"}
    try:
        verified = _run_command(["/usr/bin/codesign", "--verify", "--strict", str(path)])
        result = _run_command([
            "/usr/bin/codesign", "-d", "--entitlements", ":-", str(path),
        ])
    except RuntimeError:
        return {"status": "diagnostics_unavailable"}
    entitlements = None
    if result.returncode == 0:
        # 部分系统版本把 plist 写入 stderr；仅解析 plist，不回显原始输出。
        for raw in (result.stdout, result.stderr):
            start = raw.find(b"<?xml")
            if start < 0:
                start = raw.find(b"<plist")
            end = raw.find(b"</plist>", max(start, 0))
            if start >= 0 and end >= 0:
                try:
                    value = plistlib.loads(raw[start:end + len(b"</plist>")])
                    if isinstance(value, dict):
                        entitlements = value
                        break
                except (ValueError, plistlib.InvalidFileException):
                    continue
    fields = {
        "debugger": "com.apple.security.cs.debugger",
        "get_task_allow": "com.apple.security.get-task-allow",
        "sandbox": "com.apple.security.app-sandbox",
        "disable_library_validation": "com.apple.security.cs.disable-library-validation",
    }
    return {
        "status": "verified" if verified.returncode == 0 else "invalid_or_unsigned",
        "entitlements_available": entitlements is not None,
        **{name: entitlements.get(key) is True if entitlements is not None else None
           for name, key in fields.items()},
    }


def build_probe(output_dir=None, sign_identity="-"):
    """显式编译并签名自己的新 helper Bundle；从不执行 helper 或处理微信。"""
    if sys.platform != "darwin":
        raise RuntimeError("build_probe 仅支持 macOS")
    if not isinstance(sign_identity, str) or not sign_identity or sign_identity.startswith("--"):
        raise ValueError("签名身份无效")
    root = Path(output_dir).expanduser().resolve() if output_dir is not None else _build_root().resolve()
    if any(p.suffix.lower() == ".app" for p in (root, *root.parents)):
        raise ValueError("构建目录不能位于任何 App Bundle 内")
    source = _resource_path("find_all_keys_macos.c")
    entitlements = _resource_path("memory_probe.entitlements.plist")
    info = _resource_path("MemoryProbe-Info.plist")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    bundle = root / _bundle_name()
    # 拒绝覆盖或复用已有路径，包括符号链接；只签名本次新建的 helper。
    bundle.mkdir(mode=0o700, exist_ok=False)
    try:
        macos = bundle / "Contents" / "MacOS"
        macos.mkdir(parents=True, mode=0o700)
        shutil.copyfile(info, bundle / "Contents" / "Info.plist")
        binary = macos / _EXECUTABLE
        compiled = _run_command([
            "/usr/bin/xcrun", "clang", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
            "-arch", _architecture(), str(source), "-o", str(binary),
        ], timeout=120)
        if compiled.returncode != 0:
            raise RuntimeError("helper 编译失败；请检查 Xcode Command Line Tools")
        binary.chmod(0o700)
        for target in (binary, bundle):
            signed = _run_command([
                "/usr/bin/codesign", "--force", "--sign", sign_identity,
                "--options", "runtime", "--identifier", _BUNDLE_ID,
                "--entitlements", str(entitlements), str(target),
            ], timeout=60)
            if signed.returncode != 0:
                raise RuntimeError("自己的 helper 签名失败；未触碰官方微信")
        signature = _signature_diagnostics(binary)
        if signature.get("status") != "verified" or signature.get("debugger") is not True:
            raise RuntimeError("helper 签名或 debugger entitlement 验证失败")
        return {"binary": str(binary), "bundle": str(bundle), "signature": signature}
    except BaseException:
        shutil.rmtree(bundle)
        raise


def _resolve_pid(pid):
    if pid is not None:
        if type(pid) is not int or not 0 < pid <= 2147483647:
            raise ValueError("pid 必须为正整数且在 macOS PID 范围内")
        return pid
    result = _run_command(["/usr/bin/pgrep", "-x", "WeChat"])
    if result.returncode not in (0, 1):
        raise RuntimeError("无法查询微信进程")
    try:
        pids = sorted({int(value) for value in result.stdout.split()})
    except ValueError:
        raise RuntimeError("微信进程查询结果无效") from None
    if not pids:
        raise RuntimeError("微信未运行；不会自动启动微信")
    if len(pids) != 1:
        raise RuntimeError("存在多个微信进程，请显式指定 pid")
    return _resolve_pid(pids[0])


def _process_path(pid):
    try:
        libproc = ctypes.CDLL("/usr/lib/libproc.dylib")
        function = libproc.proc_pidpath
        function.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        function.restype = ctypes.c_int
        buffer = ctypes.create_string_buffer(4096)
        if function(pid, buffer, len(buffer)) > 0:
            return os.fsdecode(buffer.value)
    except (OSError, AttributeError):
        pass
    return None


def _parse_report(stdout, pid):
    """只接受有版本号的计数/布尔值，防止旧 helper 或敏感输出进入诊断。"""
    try:
        report = json.loads(stdout)
    except (ValueError, UnicodeDecodeError):
        raise RuntimeError("helper 诊断协议无效；原始输出已丢弃") from None
    if not isinstance(report, dict) or set(report) - _COUNT_FIELDS - _BOOL_FIELDS:
        raise RuntimeError("helper 诊断包含未允许字段；原始输出已丢弃")
    for field, value in report.items():
        if field in _BOOL_FIELDS:
            valid = type(value) is bool
        else:
            valid = type(value) is int and 0 <= value <= 2**63 - 1
        if not valid:
            raise RuntimeError("helper 诊断字段类型无效；原始输出已丢弃")
    if report.get("protocol") != _PROTOCOL or report.get("pid") != pid:
        raise RuntimeError("helper 协议版本或 PID 不匹配；请显式重建新版 helper")
    return report


def _run_helper(binary, pid, extract=False, timeout=None):
    """并发读取有界匿名管道；超时/异常时杀死并回收自己启动的 helper。"""
    read_fd = write_fd = None
    proc = None
    payload = bytearray()
    outputs = {"stdout": bytearray(), "stderr": bytearray(), "candidates": payload}
    try:
        args = [binary, "--pid", str(pid)]
        if extract:
            reader, writer = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            read_fd, write_fd = reader.detach(), writer.detach()
            args = [binary, "--extract-candidates", "--pid", str(pid),
                    "--candidate-fd", str(write_fd)]
        proc = subprocess.Popen(
            args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            pass_fds=(write_fd,) if extract else (), close_fds=True,
        )
        if write_fd is not None:
            os.close(write_fd)
            write_fd = None
        deadline = time.monotonic() + (_TIMEOUT if timeout is None else timeout)
        with selectors.DefaultSelector() as selector:
            for stream, name in ((proc.stdout, "stdout"), (proc.stderr, "stderr"),
                                 (read_fd, "candidates")):
                if stream is not None:
                    os.set_blocking(stream if isinstance(stream, int) else stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, name)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("helper 超时，已中止；不会重启微信")
                for event, _ in selector.select(min(remaining, 0.2)):
                    chunk = os.read(event.fd, 4096)
                    if not chunk:
                        selector.unregister(event.fileobj)
                        continue
                    output = outputs[event.data]
                    limit = _MAX_CANDIDATES * 32 if event.data == "candidates" else _MAX_DIAGNOSTICS
                    if len(output) + len(chunk) > limit:
                        raise RuntimeError("helper 通道超出协议长度限制；输出已丢弃")
                    output.extend(chunk)
        try:
            proc.wait(timeout=max(0.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            raise RuntimeError("helper 超时，已中止") from None
        # stderr 不得包含任何内容，尤其不允许转发意外泄漏的候选。
        if outputs["stderr"]:
            raise RuntimeError("helper 标准错误违反静默协议；输出已丢弃")
        report = _parse_report(outputs["stdout"], pid)
        if proc.returncode == 27 and report.get("task_port") is False:
            if payload:
                raise RuntimeError("权限拒绝时收到候选；helper 协议无效")
            return report, bytearray()
        if proc.returncode != 0 or report.get("task_port") is not True or report.get("scan_complete") is not True:
            raise RuntimeError("helper 扫描失败或不完整；不会绕过系统权限")
        if (report.get("candidate_channel") is not extract
                or report.get("candidate_write_ok") is not True
                or type(report.get("candidate_count")) is not int
                or report["candidate_count"] != len(payload) // 32
                or len(payload) % 32):
            raise RuntimeError("helper 候选通道或记录计数不一致")
        result = bytearray(payload)
        return report, result
    except OSError:
        raise RuntimeError("helper 无法执行或通道读取失败") from None
    finally:
        if proc is not None:
            try:
                if proc.poll() is None:
                    proc.kill()
                proc.wait()
            finally:
                for stream in (proc.stdout, proc.stderr):
                    if stream is not None:
                        stream.close()
        for fd in (read_fd, write_fd):
            if fd is not None:
                os.close(fd)
        for output in outputs.values():
            output[:] = b"\0" * len(output)


def _db_files(db_dir):
    if not Path(db_dir).is_dir():
        raise ValueError("db_dir 必须为存在的数据库目录")
    db_files, salt_to_dbs = common.collect_db_files(db_dir)
    # common 也会收集明文 SQLite；这里只验证完整的加密首页。
    encrypted = [row for row in db_files
                 if len(row[4]) == common.PAGE_SZ and not row[4].startswith(b"SQLite format 3\0")]
    salts = {row[3] for row in encrypted}
    return encrypted, {salt: rels for salt, rels in salt_to_dbs.items() if salt in salts}


def probe(db_dir, pid=None):
    """只聚合数据库/内存计数及只读签名诊断；不收集、返回或保存候选。"""
    db_files, salts = _db_files(db_dir)
    pid = _resolve_pid(pid)
    binary = _find_binary()
    report, _ = _run_helper(binary, pid)
    return {
        "database_count": len(db_files), "salt_count": len(salts),
        "memory": report, "helper_signature": _signature_diagnostics(binary),
        "target_signature": _signature_diagnostics(_process_path(pid)),
        "permission_note": "签名诊断不代表授权；task_for_pid 仍受 SIP、AMFI 和用户权限约束",
        "frida_available": False,
    }


def extract_keys(db_dir, output_path=None, pid=None, method="auto", allow_restart=False, timeout=None):
    """返回 salt -> key；仅显式 output_path 才保存，auto 不重签或启动微信。"""
    if method not in ("auto", "memory", "frida"):
        raise ValueError("method 必须为 auto、memory 或 frida")
    if timeout is not None and (not math.isfinite(timeout) or timeout <= 0):
        raise ValueError("timeout 必须为有限正数")
    if type(allow_restart) is not bool:
        raise ValueError("allow_restart 必须为布尔值")
    if method == "frida":
        raise RuntimeError(_FRIDA_UNAVAILABLE)
    db_files, salts = _db_files(db_dir)
    if output_path is not None:
        destination = Path(output_path).expanduser().resolve()
        if destination.is_relative_to(Path(db_dir).resolve()):
            raise ValueError("结果文件不能写入源数据库目录")
        if destination.exists():
            for row in db_files:
                if os.path.samefile(destination, row[1]):
                    raise ValueError("结果文件不能覆盖源数据库或其硬链接")
    if not db_files:
        raise RuntimeError("未找到可验证的加密数据库首页")
    pid = _resolve_pid(pid)
    arguments = {} if timeout is None else {"timeout": timeout}
    report, payload = _run_helper(_find_binary(), pid, extract=True, **arguments)
    try:
        if report.get("task_port") is not True:
            raise RuntimeError(
                "task_for_pid 权限被系统拒绝；请用 probe() 查看签名和 entitlement 诊断。"
                "不会重签官方微信、关闭 SIP、启动或重启微信；Frida Gadget 当前不支持。"
            )
        key_map = {}
        seen = set()
        for offset in range(0, len(payload), 32):
            candidate = bytes(payload[offset:offset + 32])
            if candidate in seen:
                continue
            seen.add(candidate)
            for _, _, _, salt, page in db_files:
                if salt not in key_map and common.verify_enc_key(candidate, page):
                    key_map[salt] = candidate.hex()
        if not key_map:
            raise RuntimeError("候选未通过任何数据库首页 HMAC 验证；未保存结果")
        if output_path is not None:
            common.save_results(db_files, salts, key_map, output_path, print_fn=lambda _: None)
        return key_map
    finally:
        payload[:] = b"\0" * len(payload)

"""macOS 密钥提取 — 通过 C 二进制扫描微信进程内存"""

import json
import os
import platform
import plistlib
import signal
import shlex
import shutil
import subprocess
import sys
import tempfile

from .common import collect_db_files, verify_derived_keys, verify_enc_key
from .macho_arm64 import locate_codec_capture_offset


def _find_binary():
    """查找对应架构的 C 二进制。"""
    machine = platform.machine()
    if machine == "arm64":
        name = "find_all_keys_macos.arm64"
    elif machine == "x86_64":
        name = "find_all_keys_macos.x86_64"
    else:
        raise RuntimeError(f"不支持的 macOS 架构: {machine}")

    # PyInstaller 运行时：从临时解压目录查找
    if getattr(sys, 'frozen', False):
        base = sys._MEIPASS
    else:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    bin_path = os.path.join(base, "wechat_cli", "bin", name)
    if os.path.isfile(bin_path):
        return bin_path

    # fallback: 直接在 bin/ 下
    bin_path = os.path.join(base, "bin", name)
    if os.path.isfile(bin_path):
        return bin_path

    raise RuntimeError(
        f"找不到密钥提取二进制: {bin_path}\n"
        "请确认安装包完整"
    )


def _get_original_entitlements(app_path):
    """提取 app 当前的签名 entitlements，返回 dict 或 None。"""
    try:
        result = subprocess.run(
            ["codesign", "-d", "--entitlements", ":-", app_path],
            capture_output=True,
            timeout=15,
        )
        if result.returncode == 0 and result.stdout:
            return plistlib.loads(result.stdout)
    except Exception:
        pass
    return None


def _build_entitlements_xml(app_path):
    """构建 entitlements：保留原有权限 + 添加 get-task-allow。"""
    entitlements = _get_original_entitlements(app_path)
    if entitlements is None:
        entitlements = {}

    entitlements["com.apple.security.get-task-allow"] = True

    return plistlib.dumps(entitlements, fmt=plistlib.FMT_XML)


def _resign_wechat():
    """Re-sign WeChat: 保留原有 entitlements，仅添加 get-task-allow。"""
    wechat_paths = [
        "/Applications/WeChat.app",
        os.path.expanduser("~/Applications/WeChat.app"),
    ]
    wechat_app = None
    for p in wechat_paths:
        if os.path.isdir(p):
            wechat_app = p
            break

    if wechat_app is None:
        return False, "未找到 WeChat.app（已搜索 /Applications 和 ~/Applications）"

    print(f"\n[*] 检测到 task_for_pid 权限不足，正在对微信重新签名...")
    print(f"    目标: {wechat_app}")

    # 提取并合并 entitlements
    try:
        ent_data = _build_entitlements_xml(wechat_app)
    except Exception as e:
        return False, f"提取微信原始权限失败: {e}"

    ent_fd, ent_path = tempfile.mkstemp(suffix=".plist")
    try:
        with os.fdopen(ent_fd, "wb") as f:
            f.write(ent_data)

        result = subprocess.run(
            ["codesign", "--force", "--sign", "-", "--entitlements", ent_path, wechat_app],
            capture_output=True,
            text=True,
            timeout=60,
        )
    finally:
        os.unlink(ent_path)

    if result.returncode != 0:
        return False, f"codesign 失败: {result.stderr.strip()}"

    print("[+] 签名完成（已保留微信原有权限，仅添加调试访问权限）。")
    print("[+] 请重新启动微信后再执行 init。")
    print("[!] 注意：如果微信自动更新，可能需要重新签名。")
    return True, None


def _find_wechat_dylib():
    candidates = (
        "/Applications/WeChat.app/Contents/Resources/wechat.dylib",
        os.path.expanduser("~/Applications/WeChat.app/Contents/Resources/wechat.dylib"),
    )
    return next((path for path in candidates if os.path.isfile(path)), None)


def _get_wechat_pid(pid=None):
    if pid is not None:
        return int(pid)
    result = subprocess.run(
        ["pgrep", "-x", "WeChat"], capture_output=True, text=True, timeout=5
    )
    pids = [int(value) for value in result.stdout.split() if value.isdigit()]
    if not pids:
        raise RuntimeError("未检测到 WeChat 主进程")
    return pids[0]


def _atomic_write_json(path, payload):
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".all_keys.", dir=directory)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _database_index(db_dir):
    return {
        rel.replace("\\", "/"): (rel, path, size, salt, page)
        for rel, path, size, salt, page in collect_db_files(db_dir)[0]
    }


def _validated_keys(db_dir, payload):
    """Return only key entries that still verify against a current DB page."""
    databases = _database_index(db_dir)
    validated = {}
    for rel, original in payload.items():
        if not isinstance(original, dict):
            continue
        normalized = rel.replace("\\", "/")
        target = databases.get(normalized)
        if target is None:
            continue
        canonical_rel, _path, size, salt, page = target
        entry = dict(original)
        try:
            if entry.get("key_type") == "sqlcipher_derived_pair":
                valid = verify_derived_keys(
                    bytes.fromhex(entry["derived_encryption_key"]),
                    bytes.fromhex(entry["derived_hmac_key"]),
                    page,
                )
            else:
                valid = verify_enc_key(bytes.fromhex(entry["enc_key"]), page)
        except (KeyError, TypeError, ValueError):
            valid = False
        if not valid:
            continue
        entry["salt"] = salt
        entry["size_mb"] = round(size / 1024 / 1024, 1)
        validated[canonical_rel.replace("\\", "/")] = entry
    return validated


def _load_existing_valid_keys(db_dir, output_path):
    if not os.path.isfile(output_path):
        return {}
    try:
        with open(output_path, encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    return _validated_keys(db_dir, payload)


def _capture_one_derived_key(target, capture_offset, pid, timeout):
    rel, path, size, salt, page = target
    lldb_path = shutil.which("lldb")
    if not lldb_path:
        return None, "lldb is not installed"
    script_path = os.path.join(os.path.dirname(__file__), "codec_capture_lldb.py")
    with tempfile.TemporaryDirectory(prefix="wechat-cli-codec-") as temp_dir:
        output_path = os.path.join(temp_dir, "keys.json")
        report_path = os.path.join(temp_dir, "report.json")
        init_command = "wechat-codec-key-init " + shlex.join([
            hex(capture_offset), path, rel, output_path, report_path, str(timeout)
        ])
        command = [
            lldb_path, "-b",
            "-o", f"command script import {shlex.quote(script_path)}",
            "-o", init_command,
            "-o", "continue",
            "-o", "wechat-codec-key-report",
            "-o", "detach",
            "-o", "quit",
            "-p", str(pid),
        ]
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=timeout + 20
            )
        except subprocess.TimeoutExpired:
            # A killed debugger must not leave the desktop client suspended.
            try:
                os.kill(pid, signal.SIGCONT)
            except OSError:
                pass
            return None, "lldb codec capture timed out"
        if not os.path.isfile(output_path):
            detail = (result.stderr or result.stdout or "no key captured").strip()
            return None, detail[-500:]
        try:
            with open(output_path, encoding="utf-8") as handle:
                entry = json.load(handle)[rel]
            encryption_key = bytes.fromhex(entry["derived_encryption_key"])
            hmac_key = bytes.fromhex(entry["derived_hmac_key"])
        except (KeyError, ValueError, OSError, json.JSONDecodeError) as error:
            return None, f"invalid codec capture output: {error}"
        if entry.get("salt") != salt or not verify_derived_keys(
            encryption_key, hmac_key, page
        ):
            return None, "captured codec keys failed independent page verification"
        entry["size_mb"] = round(size / 1024 / 1024, 1)
        return entry, None


def _capture_missing_derived_keys(db_dir, keys_data, pid=None):
    if platform.machine() != "arm64":
        return {}
    max_targets = max(1, int(os.environ.get("WECHAT_CLI_CODEC_MAX_TARGETS", "8")))
    db_files, salt_to_dbs = collect_db_files(db_dir)
    known_salts = {
        info.get("salt") for info in keys_data.values() if isinstance(info, dict)
    }
    targets_by_salt = {}
    for target in db_files:
        if target[3] not in known_salts:
            targets_by_salt.setdefault(target[3], target)

    def target_priority(item):
        normalized = item[0].replace("\\", "/")
        name = os.path.basename(normalized)
        prefix = next((
            value for value in ("message_", "biz_message_")
            if name.startswith(value)
        ), None)
        is_message_shard = bool(
            prefix and name.endswith(".db") and name[len(prefix):-3].isdigit()
        )
        return (0 if is_message_shard else 1, normalized)

    targets = sorted(
        targets_by_salt.values(),
        key=target_priority,
    )[:max_targets]
    if not targets:
        return {}

    dylib_path = _find_wechat_dylib()
    if not dylib_path:
        return {}
    capture_offset = locate_codec_capture_offset(dylib_path)
    process_id = _get_wechat_pid(pid)
    timeout = max(3, int(os.environ.get("WECHAT_CLI_CODEC_TIMEOUT", "12")))

    print(
        f"[+] 旧版扫描缺少 {len(targets_by_salt)} 个 salt，"
        f"尝试运行时 codec 捕获（最多 {len(targets)} 个）"
    )
    captured = {}
    for target in targets:
        rel, _path, _size, salt, _page = target
        print(f"[*] codec 捕获: {rel}")
        entry, error = _capture_one_derived_key(
            target, capture_offset, process_id, timeout
        )
        if entry is None:
            print(f"[WARN] codec 捕获未命中 {rel}: {error}")
            continue
        print(f"[+] codec key 已验证: {rel}")
        for matching_rel in salt_to_dbs[salt]:
            copied = dict(entry)
            matching_path = os.path.join(db_dir, matching_rel.replace("/", os.sep))
            copied["size_mb"] = round(os.path.getsize(matching_path) / 1024 / 1024, 1)
            captured[matching_rel] = copied
    return captured


def _raise_task_for_pid_error():
    print("\n[!] task_for_pid 失败：macOS 安全策略阻止了进程内存访问。")
    print(
        "[!] 需要对微信重新签名以允许调试访问"
        "（不影响微信正常功能）。"
    )
    ok, err = _resign_wechat()
    if ok:
        raise RuntimeError(
            "已对微信重新签名（保留原有权限）。"
            "请完全退出并重启微信后重试"
        )
    raise RuntimeError(f"自动签名失败: {err}")


def extract_keys(db_dir, output_path, pid=None):
    """通过 C 二进制提取 macOS 微信数据库密钥。

    C 二进制需要在微信数据目录的父目录下运行，
    因为它会自动检测 db_storage 子目录。
    输出 all_keys.json 到当前工作目录。

    Args:
        db_dir: 微信 db_storage 目录
        output_path: all_keys.json 输出路径
        pid: 可选，指定运行时 codec 捕获所附加的 WeChat PID

    Returns:
        dict: salt_hex -> enc_key_hex 映射
    """
    binary = _find_binary()
    existing_keys = _load_existing_valid_keys(db_dir, output_path)

    # Run in an isolated directory because the legacy binary always writes
    # all_keys.json to its current working directory.
    work_dir = os.path.dirname(db_dir)
    if not os.path.isdir(work_dir):
        raise RuntimeError(f"微信数据目录不存在: {work_dir}")

    print(f"[+] 使用 C 二进制提取密钥: {binary}")
    print(f"[+] 工作目录: {work_dir}")

    try:
        with tempfile.TemporaryDirectory(prefix="wechat-cli-scan-") as scan_dir:
            os.symlink(db_dir, os.path.join(scan_dir, "db_storage"))
            command = [binary] + ([str(pid)] if pid is not None else [])
            result = subprocess.run(
                command, cwd=scan_dir, capture_output=True, text=True, timeout=120
            )
            c_output = os.path.join(scan_dir, "all_keys.json")
            if os.path.isfile(c_output):
                with open(c_output, encoding="utf-8") as handle:
                    scanned_payload = json.load(handle)
            else:
                scanned_payload = {}
    except subprocess.TimeoutExpired:
        raise RuntimeError("密钥提取超时（120s）")
    except PermissionError:
        raise RuntimeError(
            f"无法执行 {binary}\n请确保文件有执行权限: chmod +x {binary}"
        )

    # 打印 C 二进制的输出
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)

    combined_output = (result.stdout or "") + (result.stderr or "")
    keys_data = dict(existing_keys)
    if isinstance(scanned_payload, dict):
        keys_data.update(_validated_keys(db_dir, scanned_payload))
    try:
        keys_data.update(_capture_missing_derived_keys(db_dir, keys_data, pid))
    except (RuntimeError, ValueError, OSError) as error:
        print(f"[WARN] 运行时 codec 捕获不可用: {error}")

    if not keys_data:
        if "task_for_pid" in combined_output:
            _raise_task_for_pid_error()
        raise RuntimeError(
            "未提取到任何已验证密钥；现有 all_keys.json 未被修改"
        )

    if existing_keys:
        print(f"[+] 保留并重新验证了 {len(existing_keys)} 个现有数据库 key")

    _atomic_write_json(output_path, keys_data)

    # 构建 salt -> key 映射
    key_map = {}
    for rel, info in keys_data.items():
        if not isinstance(info, dict) or "salt" not in info:
            continue
        if "enc_key" in info:
            key_map[info["salt"]] = info["enc_key"]
        elif info.get("key_type") == "sqlcipher_derived_pair":
            key_map[info["salt"]] = info["derived_encryption_key"]

    print(f"\n[+] 提取到 {len(key_map)} 个密钥，保存到: {output_path}")
    return key_map

"""macOS 密钥提取 — 通过 C 二进制扫描微信进程内存"""

import os
import platform
import plistlib
import subprocess
import sys
import tempfile

from .common import (
    collect_db_files,
    cross_verify_keys,
    save_results,
    verify_enc_key,
)


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


def extract_keys(db_dir, output_path, pid=None):
    """通过 C 二进制提取 macOS 微信数据库密钥。

    C 二进制需要在微信数据目录的父目录下运行，
    因为它会自动检测 db_storage 子目录。
    输出 all_keys.json 到当前工作目录。

    Args:
        db_dir: 微信 db_storage 目录
        output_path: all_keys.json 输出路径
        pid: 未使用（C 二进制自动检测进程）

    Returns:
        dict: salt_hex -> enc_key_hex 映射
    """
    import json

    db_files, salt_to_dbs = collect_db_files(db_dir)
    if not db_files:
        raise RuntimeError(f"在 {db_dir} 未找到可解密的 .db 文件")

    print(f"[+] 找到 {len(db_files)} 个数据库, {len(salt_to_dbs)} 个不同的 salt")
    binary = _find_binary()

    # C 二进制的工作目录需要是 db_storage 的父目录
    work_dir = os.path.dirname(db_dir)
    if not os.path.isdir(work_dir):
        raise RuntimeError(f"微信数据目录不存在: {work_dir}")

    print(f"[+] 使用 C 二进制提取密钥: {binary}")
    print(f"[+] 工作目录: {work_dir}")

    try:
        result = subprocess.run(
            [binary],
            cwd=work_dir,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("密钥提取超时（120s）")
    except PermissionError:
        raise RuntimeError(
            f"无法执行 {binary}\n"
            "请确保文件有执行权限: chmod +x " + binary
        )

    # 打印 C 二进制的输出
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)

    # 检测 task_for_pid 失败 → 尝试 re-sign
    combined_output = (result.stdout or "") + (result.stderr or "")
    if "task_for_pid" in combined_output:
        print("\n[!] task_for_pid 失败：macOS 安全策略阻止了进程内存访问。")
        print("[!] 需要对微信重新签名以允许调试访问（不影响微信正常功能）。")

        ok, err = _resign_wechat()
        if ok:
            raise RuntimeError(
                "已对微信重新签名（保留原有权限）。请执行以下步骤后重试：\n"
                "  1. 退出微信（完全退出，不是最小化）\n"
                "  2. 重新打开微信并登录\n"
                "  3. 再次执行: sudo wechat-cli init"
            )
        else:
            # 手动命令也需要保留原有权限
            raise RuntimeError(
                f"自动签名失败: {err}\n"
                "请手动执行以下命令后重试：\n"
                "  # 1. 提取微信原有权限\n"
                "  codesign -d --entitlements wechat_ent.plist /Applications/WeChat.app\n"
                "  # 2. 用 PlistBuddy 添加 get-task-allow\n"
                '  /usr/libexec/PlistBuddy -c "Add :com.apple.security.get-task-allow bool true" wechat_ent.plist\n'
                "  # 3. 重新签名\n"
                "  codesign --force --sign - --entitlements wechat_ent.plist /Applications/WeChat.app\n"
                "  # 4. 清理\n"
                "  rm wechat_ent.plist\n"
                "然后重启微信，再执行: sudo wechat-cli init"
            )

    if result.returncode != 0:
        raise RuntimeError(
            f"密钥扫描程序退出（状态码 {result.returncode}）"
            + (f": {result.stderr.strip()}" if result.stderr else "")
        )

    # C 二进制输出 all_keys.json 到 work_dir
    c_output = os.path.join(work_dir, "all_keys.json")
    if not os.path.exists(c_output):
        raise RuntimeError(
            "C 二进制未能生成密钥文件。\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

    # C 扫描器输出的是候选值；在 Python 中用数据库页的 HMAC 再校验一次。
    # 这样既能支持新版 Config.Cipher，也不会把误匹配写入用户配置。
    try:
        with open(c_output, encoding="utf-8") as f:
            keys_data = json.load(f)
    finally:
        # all_keys.json 只是 C 扫描器和当前进程之间的临时通信文件。
        if os.path.abspath(c_output) != os.path.abspath(output_path):
            try:
                os.remove(c_output)
            except FileNotFoundError:
                pass

    if not isinstance(keys_data, dict):
        raise RuntimeError("密钥扫描程序输出格式无效")

    db_by_rel = {item[0]: item for item in db_files}
    key_map = {}
    candidate_count = 0
    verified_count = 0
    for rel, info in keys_data.items():
        if not isinstance(info, dict) or "enc_key" not in info:
            continue
        enc_key_hex = info["enc_key"]
        if not isinstance(enc_key_hex, str):
            continue
        try:
            enc_key = bytes.fromhex(enc_key_hex)
        except ValueError:
            continue
        if len(enc_key) != 32:
            continue

        candidate_count += 1
        salt_hex = info.get("salt")
        if not isinstance(salt_hex, str):
            db_info = db_by_rel.get(rel)
            salt_hex = db_info[3] if db_info else None
        if salt_hex not in salt_to_dbs:
            continue

        for _db_rel, _path, _size, db_salt, page1 in db_files:
            if db_salt == salt_hex and verify_enc_key(enc_key, page1):
                key_map[salt_hex] = enc_key_hex.lower()
                verified_count += 1
                break

    print(f"[+] 候选密钥 {candidate_count} 个，HMAC 校验通过 {verified_count} 个")

    # 构建 salt -> key 映射，并交叉验证同一密钥对应的其他数据库。
    cross_verify_keys(db_files, salt_to_dbs, key_map, print)

    print(f"\n[+] 提取到 {len(key_map)} 个密钥，保存到: {output_path}")
    return save_results(db_files, salt_to_dbs, key_map, output_path, print)

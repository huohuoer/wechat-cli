"""无聊天内容的诊断和明确授权的密钥操作。"""

import json
import os
import platform
import stat

import click

from .init import initialization_paths, save_initialization
from ..core.key_utils import load_keys, validate_keys
from ..keys.common import collect_db_files


def _output(value):
    click.echo(json.dumps(value, ensure_ascii=False))


@click.group()
def keys():
    """密钥诊断、显式提取与独立 helper 构建；不自动操作微信。"""


@keys.command("check")
@click.option("--db-dir", default=None)
@click.option("--keys", "source_keys", type=click.Path(exists=True, dir_okay=False), default=None)
@click.pass_context
def check(ctx, db_dir, source_keys):
    """只读检查首页密钥覆盖及提取能力，不创建解密缓存。"""
    try:
        _, directory, key_path, _ = initialization_paths(ctx, db_dir)
        path = source_keys or key_path
        rows, _ = collect_db_files(directory)
        report = {"database_count": len(rows), "valid_count": 0,
                  "invalid_count": 0, "missing_count": len(rows)}
        if os.path.isfile(path):
            _, report = validate_keys(load_keys(path), directory)
        system = platform.system().lower()
        methods = {"darwin": ["config"], "windows": ["config", "legacy"],
                   "linux": ["legacy", "gdb (x86_64)"]}.get(system, [])
        result = {"platform": system, "architecture": platform.machine(),
                  "keys_present": os.path.isfile(path), "methods": methods,
                  "frida_supported": False, **report}
        if os.path.isfile(path):
            result["keys_mode"] = oct(stat.S_IMODE(os.stat(path).st_mode))
        if system == "darwin":
            from ..keys.scanner_macos import _find_binary, _signature_diagnostics
            try:
                result["helper_signature"] = _signature_diagnostics(_find_binary())
            except RuntimeError:
                result["helper_signature"] = {"status": "not_built"}
        _output(result)
    except (ValueError, OSError, RuntimeError) as exc:
        raise click.ClickException(str(exc)) from None


@keys.command("extract")
@click.option("--db-dir", default=None)
@click.option("--pid", type=click.IntRange(min=1), default=None)
@click.option("--method", type=click.Choice(["auto", "config", "legacy", "gdb", "frida"]), default="auto", show_default=True)
@click.option("--timeout", type=click.IntRange(min=1, max=600), default=120)
@click.option("--allow-memory-read", is_flag=True, help="明确允许本次读取进程内存；GDB 会临时附加和暂停目标")
@click.option("--save", is_flag=True, help="明确保存验证密钥并更新配置，已有密钥先备份")
@click.pass_context
def extract(ctx, db_dir, pid, method, timeout, allow_memory_read, save):
    """只在授权后提取；默认仅验证不保存，不自动重启或重签微信。"""
    if not allow_memory_read:
        raise click.ClickException("需 --allow-memory-read 明确授权；未读取内存")
    if method == "frida":
        raise click.ClickException("Frida 独立副本的数据库写入隔离尚未验证；为保护官方数据库，当前不支持")
    try:
        config_path, directory, key_path, cfg = initialization_paths(ctx, db_dir)
        if method == "gdb":
            click.echo("GDB 将等待登录期密钥计算。请自行在微信退出登录并重新登录；不会自动操作微信。", err=True)
        from ..keys import extract_keys
        key_map = extract_keys(directory, pid=pid, method=method, timeout=timeout)
        rows, _ = collect_db_files(directory)
        candidate_keys = {rel: {"enc_key": key_map[salt]}
                          for rel, _, _, salt, _ in rows if salt in key_map}
        valid, report = validate_keys(candidate_keys, directory)
        if not valid or report["invalid_count"]:
            raise ValueError("数据库已变化或候选无效；未保存")
        if save:
            save_initialization(config_path, directory, key_path, cfg, valid)
        _output({"saved": save, "method": method, **report})
    except (ValueError, RuntimeError, OSError) as exc:
        raise click.ClickException(str(exc)) from None


@keys.command("probe")
@click.option("--db-dir", default=None)
@click.option("--pid", type=click.IntRange(min=1), default=None)
@click.option("--allow-memory-read", is_flag=True)
@click.pass_context
def probe(ctx, db_dir, pid, allow_memory_read):
    """macOS 探针只输出聚合计数；其他平台仅检测只读内存访问权限。"""
    if not allow_memory_read:
        raise click.ClickException("需 --allow-memory-read 明确授权；未读取内存")
    try:
        _, directory, _, _ = initialization_paths(ctx, db_dir)
        system = platform.system().lower()
        if system == "darwin":
            from ..keys.scanner_macos import probe as run_probe
            _output(run_probe(directory, pid))
        elif system == "windows":
            from ..keys import scanner_windows as scanner
            selected = pid or scanner._get_pids()[0][0]
            handle = scanner.kernel32.OpenProcess(0x0010 | 0x0400, False, selected)
            if not handle:
                raise RuntimeError("无法只读打开微信进程")
            try:
                _output({"memory_access": True, "region_count": len(scanner._enum_regions(handle)), "candidate_count": 0})
            finally:
                scanner.kernel32.CloseHandle(handle)
        elif system == "linux":
            from ..keys import scanner_linux as scanner
            selected = pid or scanner._get_pids()[0][0]
            if not scanner._is_wechat_process(selected):
                raise ValueError("指定 PID 不是微信进程")
            with scanner._check_permissions(selected):
                _output({"memory_access": True, "region_count": len(scanner._get_readable_regions(selected)), "candidate_count": 0})
        else:
            raise RuntimeError("不支持当前平台")
    except (ValueError, OSError, RuntimeError) as exc:
        raise click.ClickException(str(exc)) from None


@keys.command("prepare")
@click.option("--allow-helper-build", is_flag=True, help="明确编译并签名本工具 helper，不触碰官方微信")
def prepare(allow_helper_build):
    """显式构建 macOS 独立签名探针；不运行探针、不复制或重签微信。"""
    if not allow_helper_build:
        raise click.ClickException("需 --allow-helper-build 明确授权编译签名 helper")
    try:
        from ..keys.scanner_macos import build_probe
        result = build_probe()
        _output({"built": True, "signature": result["signature"]})
    except (ValueError, OSError, RuntimeError) as exc:
        raise click.ClickException(str(exc)) from None

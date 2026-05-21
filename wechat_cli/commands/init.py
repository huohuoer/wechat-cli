"""init 命令 — 交互式初始化，提取密钥并生成配置"""

import json
import os
import sys
from contextlib import redirect_stdout

import click

from ..core.config import STATE_DIR, CONFIG_FILE, KEYS_FILE, auto_detect_db_dir
from ..output.formatter import INIT_FORMATS, output_json
from .schema_option import schema_option


@click.command()
@schema_option("init")
@click.option("--db-dir", metavar="", default=None, help="微信数据目录路径 (默认自动检测)")
@click.option("--force", is_flag=True, help="强制重新提取密钥")
@click.option("--format", "fmt", default="text", type=click.Choice(INIT_FORMATS), metavar="", help="输出格式: text, json (默认 text)")
def init(db_dir, force, fmt):
    """初始化 wechat-cli：提取密钥并生成配置"""
    json_mode = fmt == "json"
    _echo("WeChat CLI 初始化", json_mode)
    _echo("=" * 40, json_mode)

    # 1. 检查是否已初始化
    if os.path.exists(CONFIG_FILE) and os.path.exists(KEYS_FILE) and not force:
        if json_mode:
            output_json({
                "status": "already_initialized",
                "config": CONFIG_FILE,
                "keys": KEYS_FILE,
            })
            return
        click.echo(f"已初始化（配置: {CONFIG_FILE}）")
        click.echo("使用 --force 重新提取密钥")
        return

    # 2. 创建状态目录
    os.makedirs(STATE_DIR, exist_ok=True)

    # 3. 确定 db_dir
    if db_dir is None:
        db_dir = auto_detect_db_dir()
        if db_dir is None:
            _exit_error(json_mode, "未能自动检测到微信数据目录", hint="wechat-cli init --db-dir ~/path/to/db_storage")
            sys.exit(1)
        _echo(f"[+] 检测到微信数据目录: {db_dir}", json_mode)
    else:
        db_dir = os.path.abspath(db_dir)
        if not os.path.isdir(db_dir):
            _exit_error(json_mode, f"目录不存在: {db_dir}")
            sys.exit(1)
        _echo(f"[+] 使用指定数据目录: {db_dir}", json_mode)

    # 4. 提取密钥
    _echo("\n开始提取密钥...", json_mode)
    try:
        from ..keys import extract_keys
        if json_mode:
            with redirect_stdout(sys.stderr):
                key_map = extract_keys(db_dir, KEYS_FILE)
        else:
            key_map = extract_keys(db_dir, KEYS_FILE)
    except RuntimeError as e:
        hint = None if "sudo" in str(e).lower() else "macOS/Linux 可能需要 sudo 权限"
        _exit_error(json_mode, f"密钥提取失败: {e}", hint=hint)
        sys.exit(1)
    except Exception as e:
        _exit_error(json_mode, f"密钥提取出错: {e}")
        sys.exit(1)

    # 5. 写入配置
    cfg = {
        "db_dir": db_dir,
    }
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)

    if json_mode:
        output_json({
            "status": "initialized",
            "config": CONFIG_FILE,
            "keys": KEYS_FILE,
            "db_dir": db_dir,
            "key_count": len(key_map),
        })
        return

    click.echo(f"\n[+] 初始化完成!")
    click.echo(f"    配置: {CONFIG_FILE}")
    click.echo(f"    密钥: {KEYS_FILE}")
    click.echo(f"    提取到 {len(key_map)} 个数据库密钥")
    click.echo("\n现在可以使用:")
    click.echo("  wechat-cli sessions")
    click.echo("  wechat-cli history \"联系人\"")


def _echo(message, json_mode):
    click.echo(message, err=json_mode)


def _exit_error(json_mode, message, hint=None):
    if json_mode:
        data = {"status": "error", "error": message}
        if hint:
            data["hint"] = hint
        output_json(data)
        return
    click.echo(f"[!] {message}", err=True)
    if hint:
        click.echo(f"提示: {hint}", err=True)

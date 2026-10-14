"""只读初始化诊断；显式导入现有有效密钥。"""

import json
import os

import click

from ..core.config import CONFIG_FILE, auto_detect_db_dir
from ..core.key_utils import load_keys, private_write_json, validate_keys


def initialization_paths(ctx, db_dir=None):
    config_path = (ctx.find_root().params.get("config_path") or CONFIG_FILE)
    config_path = os.path.abspath(os.path.expanduser(config_path))
    cfg = {}
    if os.path.isfile(config_path):
        with open(config_path, encoding="utf-8") as handle:
            cfg = json.load(handle)
        if not isinstance(cfg, dict):
            raise ValueError("配置必须为 JSON 对象")
    state_dir = os.path.dirname(config_path)
    directory = db_dir or cfg.get("db_dir") or auto_detect_db_dir()
    if not directory:
        raise ValueError("未检测到数据库目录，请通过 --db-dir 指定")
    directory = os.path.expanduser(directory)
    if not os.path.isabs(directory):
        directory = os.path.join(state_dir, directory) if not db_dir else os.path.abspath(directory)
    if not os.path.isdir(directory):
        raise ValueError("数据库目录不存在")
    key_path = os.path.expanduser(cfg.get("keys_file") or os.path.join(state_dir, "all_keys.json"))
    if not os.path.isabs(key_path):
        key_path = os.path.join(state_dir, key_path)
    return config_path, os.path.realpath(directory), key_path, cfg


def _inside_directory(directory, path):
    directory, path = os.path.realpath(directory), os.path.realpath(path)
    try:
        return os.path.commonpath([directory, path]) == directory
    except ValueError:
        return False  # Windows 不同盘符不可能包含彼此。


def save_initialization(config_path, db_dir, key_path, cfg, valid):
    if any(_inside_directory(db_dir, path) for path in (config_path, key_path)):
        raise ValueError("配置和密钥不能写入源数据库目录")
    targets = [config_path, key_path, config_path + ".bak", key_path + ".bak"]
    for index, path in enumerate(targets):
        for other in targets[index + 1:]:
            if (os.path.realpath(path) == os.path.realpath(other)
                    or (os.path.exists(path) and os.path.exists(other)
                        and os.path.samefile(path, other))):
                raise ValueError("配置、密钥及其备份不能指向同一个文件")
    # 提前检查配置目标，避免密钥发布后才发现明显非法路径。
    if os.path.islink(config_path) or os.path.isdir(config_path):
        raise ValueError("配置目标必须为普通文件路径")
    had_keys = os.path.exists(key_path)
    private_write_json(key_path, valid)
    cfg = {**cfg, "db_dir": db_dir, "keys_file": key_path}
    try:
        private_write_json(config_path, cfg)
    except BaseException:
        # 配置发布失败时回滚密钥，不留下旧账号配置配新账号密钥。
        if had_keys:
            os.replace(key_path + ".bak", key_path)
        else:
            os.unlink(key_path)
        raise


@click.command()
@click.option("--db-dir", default=None, help="微信数据库目录（默认检测，多个账号需明确选择）")
@click.option("--keys", "source_keys", type=click.Path(exists=True, dir_okay=False), help="明确导入已有密钥，例如 ~/.wx-cli/all_keys.json")
@click.option("--force", is_flag=True, help="允许替换现有密钥（旧文件安全备份）；不触发提取")
@click.pass_context
def init(ctx, db_dir, source_keys, force):
    """默认只读检查；提供 --keys 才导入，不扫描内存或重签微信。"""
    try:
        config_path, directory, key_path, cfg = initialization_paths(ctx, db_dir)
        if source_keys is not None:
            if os.path.exists(key_path) and not force:
                raise ValueError("目标密钥已存在，需 --force 明确替换并备份")
            valid, report = validate_keys(load_keys(source_keys), directory)
            if not valid or report["invalid_count"]:
                raise ValueError("导入密钥未通过首页 HMAC 验证；未覆盖现有配置")
            save_initialization(config_path, directory, key_path, cfg, valid)
            click.echo(json.dumps({"initialized": True, **report}, ensure_ascii=False))
        else:
            from ..keys.common import collect_db_files
            rows, _ = collect_db_files(directory)
            report = {"database_count": len(rows), "valid_count": 0}
            if os.path.isfile(key_path):
                _, report = validate_keys(load_keys(key_path), directory)
            click.echo(json.dumps({"initialized": bool(report["valid_count"]), **report}, ensure_ascii=False))
            click.echo("默认只读。导入: wechat-cli init --keys ~/.wx-cli/all_keys.json；提取: wechat-cli keys extract --allow-memory-read --save", err=True)
    except (ValueError, RuntimeError, OSError) as exc:
        raise click.ClickException(str(exc)) from None

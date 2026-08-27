"""init 命令 — 显式授权后扫描并以 generation 原子初始化。"""

import os

import click

from ..core.config import CONFIG_FILE, KEYS_FILE, STATE_DIR, auto_detect_db_dir
from ..core.secure_files import ensure_private_directory, redact_sensitive_text
from ..core.state import commit_generation, resolve_active_generation, state_lock
from ..keys.capabilities import evaluate_scan_capability


def _resolve_db_dir(db_dir):
    if db_dir is None:
        db_dir = auto_detect_db_dir()
        if db_dir is None:
            raise click.ClickException(
                "[WXCLI_DB_NOT_FOUND] 未能自动检测微信数据目录，请使用 --db-dir 指定"
            )
    db_dir = os.path.abspath(db_dir)
    if not os.path.isdir(db_dir):
        raise click.ClickException(f"[WXCLI_DB_NOT_FOUND] 目录不存在: {db_dir}")
    return db_dir


def _render_scan_plan(db_dir, capability):
    identity = capability["identity"]
    click.echo("初始化计划（只读，尚未读取微信进程内存）")
    click.echo(f"  数据目录: {db_dir}")
    click.echo(f"  客户端: {identity['executable']} {identity['client_version']}")
    click.echo(f"  发布者: {identity['publisher']}")
    click.echo(f"  扫描能力: {'已验收' if capability['supported'] else '未验收'}")
    click.echo(f"  结果代码: {capability['reason_code']}")


@click.command()
@click.option("--db-dir", default=None, help="微信数据目录路径（默认自动检测）")
@click.option("--force", is_flag=True, help="替换已有初始化状态")
@click.option("--dry-run", is_flag=True, help="只显示计划，不读进程内存且不写状态")
@click.option("--scan-memory", is_flag=True, help="明确请求读取微信进程内存")
@click.option(
    "--confirm-memory-scan",
    is_flag=True,
    help="确认已知晓进程内存扫描可能触发客户端安全告警",
)
def init(db_dir, force, dry_run, scan_memory, confirm_memory_scan):
    """初始化 wechat-cli；默认只做安全预检，不会扫描进程内存。"""
    if hasattr(os, "geteuid") and os.geteuid() == 0 and os.environ.get("SUDO_USER"):
        raise click.ClickException(
            "[WXCLI_ROOT_SESSION_DENIED] 请以普通用户运行；仅扫描 helper 可请求 sudo"
        )

    db_dir = _resolve_db_dir(db_dir)
    capability = evaluate_scan_capability()
    _render_scan_plan(db_dir, capability)

    if dry_run:
        return
    if not scan_memory:
        click.echo(
            "\n未执行扫描。推荐将受信 helper 的 JSON 输出通过 "
            "wechat-cli keys import --stdin 导入。"
        )
        click.echo("如确需内存扫描，必须同时使用 --scan-memory --confirm-memory-scan。")
        click.get_current_context().exit(2)
    if not confirm_memory_scan:
        raise click.ClickException(
            "[WXCLI_SCAN_CONFIRMATION_REQUIRED] 缺少 --confirm-memory-scan"
        )
    if not capability["supported"]:
        raise click.ClickException(
            "[WXCLI_SCAN_UNSUPPORTED_CLIENT] 当前客户端版本/发布者没有通过真实环境验收；"
            "已在申请进程内存读取权限前停止"
        )

    ensure_private_directory(STATE_DIR, tighten_existing=True)
    with state_lock(STATE_DIR):
        active = resolve_active_generation(STATE_DIR)
        legacy_ready = os.path.exists(CONFIG_FILE) and os.path.exists(KEYS_FILE)
        if active and not force:
            click.echo(f"已初始化（配置: {active}）")
            click.echo("使用 --force 替换已有状态")
            return
        if legacy_ready and not force:
            raise click.ClickException(
                "[WXCLI_LEGACY_KEYS_PRESENT] 检测到旧版明文密钥状态；使用 --force 迁移"
            )

        click.echo("\n开始已授权的内存扫描...")
        try:
            from ..keys import extract_keys_for_init

            key_document = extract_keys_for_init(db_dir)
            generation = commit_generation(STATE_DIR, {"db_dir": db_dir}, key_document)
        except Exception as error:
            raise click.ClickException(redact_sensitive_text(str(error))) from None

    click.echo("\n[+] 初始化完成")
    click.echo(f"    配置: {os.path.join(generation, 'config.json')}")
    click.echo(f"    提取到 {len(key_document)} 个数据库密钥")

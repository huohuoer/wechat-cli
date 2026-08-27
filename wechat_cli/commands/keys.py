"""密钥导入命令。"""

import json
import os
import sys

import click

from ..core.config import CONFIG_FILE, KEYS_FILE, STATE_DIR, auto_detect_db_dir
from ..core.secure_files import ensure_private_directory, redact_sensitive_text
from ..core.state import commit_generation, resolve_active_generation, state_lock
from ..keys.trusted_import import verify_imported_key_document

MAX_STDIN_BYTES = 2 * 1024 * 1024


@click.group("keys")
def keys():
    """管理数据库密钥；不会读取微信进程内存。"""


def _reject_duplicate_pairs(pairs):
    document = {}
    for name, value in pairs:
        if name in document:
            raise ValueError("duplicate JSON property")
        document[name] = value
    return document


def _read_stdin_document():
    if sys.stdin.isatty():
        raise click.ClickException(
            "[WXCLI_IMPORT_PIPE_REQUIRED] --stdin 只接受管道输入，不接受交互粘贴"
        )
    payload = click.get_text_stream("stdin").read(MAX_STDIN_BYTES + 1)
    if len(payload.encode("utf-8")) > MAX_STDIN_BYTES:
        raise click.ClickException("[WXCLI_IMPORT_TOO_LARGE] stdin 密钥文档超过 2 MiB")
    try:
        return json.loads(payload, object_pairs_hook=_reject_duplicate_pairs)
    except (json.JSONDecodeError, UnicodeError, ValueError):
        raise click.ClickException("[WXCLI_IMPORT_INVALID_JSON] stdin 不是有效 JSON") from None


@keys.command("import")
@click.option("--stdin", "from_stdin", is_flag=True, help="从标准输入读取 JSON 密钥文档")
@click.option("--db-dir", default=None, help="微信数据目录路径（默认自动检测）")
@click.option("--force", is_flag=True, help="替换已有初始化状态")
def import_keys(from_stdin, db_dir, force):
    """导入受信 helper 输出；每个密钥必须通过真实数据库页 HMAC。"""
    if not from_stdin:
        raise click.ClickException("[WXCLI_IMPORT_STDIN_REQUIRED] 必须显式使用 --stdin")
    document = _read_stdin_document()
    detected = db_dir or auto_detect_db_dir()
    if not detected:
        raise click.ClickException("[WXCLI_DB_NOT_FOUND] 未找到微信数据目录")
    db_dir = os.path.abspath(detected)
    if not os.path.isdir(db_dir):
        raise click.ClickException("[WXCLI_DB_NOT_FOUND] 未找到微信数据目录")
    try:
        verified = verify_imported_key_document(db_dir, document)
    except Exception as error:
        raise click.ClickException(redact_sensitive_text(str(error))) from None

    ensure_private_directory(STATE_DIR, tighten_existing=True)
    with state_lock(STATE_DIR):
        active = resolve_active_generation(STATE_DIR)
        legacy_ready = os.path.exists(CONFIG_FILE) and os.path.exists(KEYS_FILE)
        if (active or legacy_ready) and not force:
            raise click.ClickException(
                "[WXCLI_STATE_EXISTS] 已存在初始化状态；如需替换请使用 --force"
            )
        try:
            generation = commit_generation(STATE_DIR, {"db_dir": db_dir}, verified)
        except Exception as error:
            raise click.ClickException(redact_sensitive_text(str(error))) from None
    click.echo(f"[+] 已安全导入 {len(verified)} 个数据库密钥")
    click.echo(f"    配置: {os.path.join(generation, 'config.json')}")

"""只读安全预检。"""

import json
import os

import click

from ..core.config import STATE_DIR, auto_detect_db_dir
from ..core.key_document import select_default_key_backend
from ..core.state import resolve_active_generation
from ..keys.capabilities import evaluate_scan_capability


def build_doctor_report(db_dir=None):
    detected = os.path.abspath(db_dir) if db_dir else auto_detect_db_dir()
    try:
        active = resolve_active_generation(STATE_DIR)
        state_error = None
    except Exception as error:
        active = None
        state_error = type(error).__name__
    try:
        backend = select_default_key_backend()
        backend_available = True
    except RuntimeError:
        backend = None
        backend_available = False
    return {
        "schema_version": 1,
        "read_process_memory": False,
        "db_dir_present": bool(detected and os.path.isdir(detected)),
        "state": {
            "initialized": active is not None,
            "valid": state_error is None,
            "error_type": state_error,
        },
        "key_store": {"available": backend_available, "backend": backend},
        "memory_scan": evaluate_scan_capability(),
    }


@click.command("doctor")
@click.option("--db-dir", default=None, help="待检查的微信数据目录")
@click.option("--json", "as_json", is_flag=True, help="输出机器可读 JSON")
def doctor(db_dir, as_json):
    """检查数据库、状态和扫描能力；不会读取微信进程内存。"""
    report = build_doctor_report(db_dir)
    if as_json:
        click.echo(json.dumps(report, ensure_ascii=False, sort_keys=True))
        return
    click.echo("WeChat CLI 安全检查")
    click.echo(f"  数据目录: {'可用' if report['db_dir_present'] else '未找到'}")
    click.echo(f"  初始化状态: {'可用' if report['state']['initialized'] else '未初始化'}")
    click.echo(f"  系统密钥库: {report['key_store']['backend'] or '不可用'}")
    scan = report["memory_scan"]
    click.echo(f"  内存扫描: {'已验收' if scan['supported'] else '未验收'}")
    click.echo(f"  结果代码: {scan['reason_code']}")
    click.echo("  本次检查读取进程内存: 否")

import click

from ..core.login_status import detect_login_status
from ..output.formatter import output


_EXIT_CODE = {
    "logged_in": 0,
    "not_running": 10,
    "logged_out": 11,
    "unknown": 13,
}

_TEXT = {
    "logged_in": "已登录",
    "not_running": "未运行",
    "logged_out": "未登录",
    "unknown": "未知",
}


@click.command("login-status")
@click.option("--format", "fmt", default="json", type=click.Choice(["json", "text"]), help="输出格式")
@click.pass_context
def login_status(ctx, fmt):
    """检测本机微信是否已登录"""
    status = detect_login_status()
    if status not in _EXIT_CODE:
        status = "unknown"

    if fmt == "json":
        output({"status": status}, "json")
    else:
        output(_TEXT.get(status, "未知"), "text")

    ctx.exit(_EXIT_CODE[status])


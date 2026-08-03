"""send 命令 — 向精确解析出的群聊发送文本。"""

import math

import click

from ..core.sending import (
    SEND_INIT_ERROR_META_KEY,
    SendError,
    SendInputError,
    SendRequest,
    SendStatus,
    SendUnknownError,
    SendUnavailableError,
    get_send_service,
    resolve_send_group,
    validate_send_result,
)
from ..output.formatter import output


def _emit_error(error, fmt):
    if fmt == "json":
        payload = {
            "success": False,
            "status": error.status,
            "error": str(error),
        }
        if error.exit_code == 4:
            payload["auto_retry"] = False
        output(payload, "json")
    else:
        click.echo(f"发送失败：{error}", err=True)


def _emit_unknown_result(result, fmt):
    if fmt == "json":
        payload = result.as_dict()
        payload["auto_retry"] = False
        output(payload, "json")
    else:
        click.echo(
            f"发送结果未知，禁止自动重试（request_id: {result.request_id}）",
            err=True,
        )


def _emit_success(result, fmt):
    if fmt == "json":
        output(result.as_dict(), "json")
    else:
        message = (
            f"服务器已接受发往“{result.group}”的消息"
            f"（request_id: {result.request_id}）"
        )
        output(
            message,
            "text",
        )


@click.command("send")
@click.argument("group")
@click.argument("text")
@click.option(
    "--timeout",
    default=15.0,
    type=float,
    show_default=True,
    help="发送超时秒数（必须大于 0）",
)
@click.option(
    "--format",
    "fmt",
    default="json",
    type=click.Choice(["json", "text"]),
    help="输出格式",
)
@click.pass_context
def send(ctx, group, text, timeout, fmt):
    """向唯一精确匹配的群聊 GROUP 发送纯文本 TEXT。

    \b
    示例:
      wechat-cli send "AI交流群" "大家好"
      wechat-cli send "123456@chatroom" "第一行\\n第二行" --timeout 15
      wechat-cli send "AI交流群" "大家好 👋" --format text
    """
    app = ctx.obj

    try:
        if not text.strip():
            raise SendInputError("TEXT 不能为空或仅包含空白")
        if not math.isfinite(timeout) or timeout <= 0:
            raise SendInputError("timeout 必须为正数")

        init_error = ctx.meta.get(SEND_INIT_ERROR_META_KEY)
        if init_error is not None:
            raise SendUnavailableError(
                f"发送前环境不可用: {init_error}；未发送任何消息"
            )

        target = resolve_send_group(group, app.cache, app.decrypted_dir)
        request = SendRequest(
            group=target.group,
            username=target.username,
            text=text,
            timeout=timeout,
        )
        result = validate_send_result(
            get_send_service(app).send_text(request),
            request,
        )
    except SendError as error:
        _emit_error(error, fmt)
        ctx.exit(int(error.exit_code))
    except Exception as error:
        unknown = SendUnknownError(f"发送结果无法确认，禁止自动重试: {error}")
        _emit_error(unknown, fmt)
        ctx.exit(int(unknown.exit_code))

    if result.status == SendStatus.UNKNOWN or not result.success:
        _emit_unknown_result(result, fmt)
        ctx.exit(4)
    if result.status != SendStatus.SERVER_ACCEPTED:
        unknown = SendUnknownError("发送服务返回未知状态，禁止自动重试")
        _emit_error(unknown, fmt)
        ctx.exit(int(unknown.exit_code))

    _emit_success(result, fmt)

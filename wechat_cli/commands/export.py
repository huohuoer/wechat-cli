"""export 命令 — 导出聊天记录为 markdown 或 txt"""

import click
from datetime import datetime

from ..core.contacts import get_contact_names
from ..core.messages import (
    collect_chat_history,
    parse_time_range,
    resolve_chat_context,
    validate_pagination,
)
from ..output.formatter import output


@click.command("export")
@click.argument("chat_name")
@click.option("--format", "fmt", default="markdown", type=click.Choice(["markdown", "txt"]), help="导出格式")
@click.option("--output", "output_path", default=None, help="输出文件路径（默认输出到 stdout）")
@click.option("--start-time", default="", help="起始时间 YYYY-MM-DD [HH:MM[:SS]]")
@click.option("--end-time", default="", help="结束时间 YYYY-MM-DD [HH:MM[:SS]]")
@click.option("--limit", default=500, help="导出消息数量")
@click.option("--media", is_flag=True, help="解析媒体文件路径（图片/文件/视频/语音）")
@click.pass_context
def export(ctx, chat_name, fmt, output_path, start_time, end_time, limit, media):
    """导出聊天记录为 markdown 或纯文本

    \b
    示例:
      wechat-cli export "张三" --format markdown
      wechat-cli export "AI交流群" --format txt --output chat.txt
      wechat-cli export "张三" --start-time "2026-04-01" --limit 1000
      wechat-cli export "张三" --media --output chat.md          # 解析图片/文件本地路径
    """
    app = ctx.obj

    try:
        validate_pagination(limit, 0, limit_max=None)
        start_ts, end_ts = parse_time_range(start_time, end_time)
    except ValueError as e:
        click.echo(f"错误: {e}", err=True)
        ctx.exit(2)

    chat_ctx = resolve_chat_context(chat_name, app.msg_db_keys, app.cache, app.decrypted_dir)
    if not chat_ctx:
        click.echo(f"找不到聊天对象: {chat_name}", err=True)
        ctx.exit(1)
    if not chat_ctx['db_path']:
        click.echo(f"找不到 {chat_ctx['display_name']} 的消息记录", err=True)
        ctx.exit(1)

    names = get_contact_names(app.cache, app.decrypted_dir)
    lines, failures = collect_chat_history(
        chat_ctx, names, app.display_name_fn,
        start_ts=start_ts, end_ts=end_ts, limit=limit, offset=0,
        resolve_media=media, db_dir=app.db_dir,
    )

    if not lines:
        click.echo(f"{chat_ctx['display_name']} 无消息记录", err=True)
        ctx.exit(0)

    now = datetime.now().strftime('%Y-%m-%d %H:%M')
    chat_type = "群聊" if chat_ctx['is_group'] else "私聊"
    time_range = f"{start_time or '最早'} ~ {end_time or '最新'}"

    if fmt == 'markdown':
        content = _format_markdown(chat_ctx['display_name'], chat_type, time_range, now, lines)
    else:
        content = _format_txt(chat_ctx['display_name'], chat_type, time_range, now, lines)

    if output_path:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
            if not content.endswith('\n'):
                f.write('\n')
        click.echo(f"已导出到: {output_path}（{len(lines)} 条消息）", err=True)
    else:
        output(content, 'text')


def _format_markdown(display_name, chat_type, time_range, export_time, lines):
    header = (
        f"# 聊天记录: {display_name}\n\n"
        f"**时间范围:** {time_range}\n\n"
        f"**导出时间:** {export_time}\n\n"
        f"**消息数量:** {len(lines)}\n\n"
        f"**类型:** {chat_type}\n\n---\n"
    )
    body = "\n".join(f"- {line}" for line in lines)
    return header + body


def _format_txt(display_name, chat_type, time_range, export_time, lines):
    header = (
        f"聊天记录: {display_name}\n"
        f"类型: {chat_type}\n"
        f"时间范围: {time_range}\n"
        f"导出时间: {export_time}\n"
        f"消息数量: {len(lines)}\n"
        f"{'=' * 60}"
    )
    body = "\n".join(lines)
    return header + "\n" + body

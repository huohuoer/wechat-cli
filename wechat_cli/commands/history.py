"""get-chat-history 命令"""

import click

from ..core.contacts import get_contact_names
from ..core.messages import (
    MSG_TYPE_FILTERS,
    collect_chat_history,
    parse_time_range,
    resolve_chat_context,
    validate_pagination,
)
from ..output.formatter import Column, QUERY_FORMATS, render_result, warn
from .schema_option import schema_option
from .filters import MSG_TYPE_CHOICE


@click.command("history")
@schema_option("history")
@click.argument("chat_name")
@click.option("--limit", metavar="", default=50, help="返回数量 (默认 50)")
@click.option("--offset", metavar="", default=0, help="分页偏移量 (默认 0)")
@click.option("--from", "from_time", metavar="", default="", help="起始时间 (YYYY-MM-DD [HH:MM[:SS]])")
@click.option("--to", "to_time", metavar="", default="", help="结束时间 (YYYY-MM-DD [HH:MM[:SS]])")
@click.option("--format", "fmt", default="json", type=click.Choice(QUERY_FORMATS), metavar="", help="输出格式: json, ndjson, table, text (默认 json)")
@click.option("--msg-type", "msg_type", default=None, type=MSG_TYPE_CHOICE, metavar="", help="消息类型: text, image, voice, video, sticker, location, link, file, call, system")
@click.option("--type", "type_alias", default=None, type=MSG_TYPE_CHOICE, metavar="", help="[DEPRECATED] 使用 --msg-type 代替")
@click.option("--media", is_flag=True, help="解析媒体文件路径")
@click.option("--sort", "sort_order", default="desc", type=click.Choice(("desc", "asc")), metavar="", help="排序方向: desc (最新优先), asc (最旧优先) (默认 desc)")
@click.option("--fields", metavar="", default=None, help="字段选择器 (逗号分隔)")
@click.pass_context
def history(ctx, chat_name, limit, offset, from_time, to_time, fmt, msg_type, type_alias, media, sort_order, fields):
    """获取指定聊天的消息记录

    \b
    示例:
      wechat-cli history "张三"                          # 最近 50 条消息
      wechat-cli history "张三" --limit 100 --offset 50  # 分页查询
      wechat-cli history "AI交流群" --from "2026-04-01" --to "2026-04-02"
      wechat-cli history "张三" --format table            # 表格输出
    """
    if type_alias and not msg_type:
        warn("--type is deprecated, use --msg-type instead")
        msg_type = type_alias
    elif type_alias and msg_type and type_alias != msg_type:
        click.echo("错误: --type 和 --msg-type 不能同时指定不同的消息类型", err=True)
        ctx.exit(2)

    app = ctx.obj

    try:
        validate_pagination(limit, offset, limit_max=None)
        start_ts, end_ts = parse_time_range(from_time, to_time)
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
    type_filter = MSG_TYPE_FILTERS[msg_type] if msg_type else None
    sort_reverse = sort_order == 'desc'
    lines, total, failures = collect_chat_history(
        chat_ctx, names, app.display_name_fn,
        start_ts=start_ts, end_ts=end_ts, limit=limit, offset=offset,
        msg_type_filter=type_filter, resolve_media=media, db_dir=app.db_dir,
        sort_reverse=sort_reverse,
    )

    data = {
        'chat': chat_ctx['display_name'],
        'username': chat_ctx['username'],
        'is_group': chat_ctx['is_group'],
        'sort': sort_order,
        'count': len(lines),
        'total': total,
        'has_more': (offset + len(lines)) < total,
        'offset': offset,
        'limit': limit,
        'from': from_time or None,
        'to': to_time or None,
        'type': msg_type or None,
        'messages': lines,
        'failures': failures if failures else None,
    }
    records_key = 'messages'
    if fmt in ('ndjson', 'table'):
        data = {**data, 'message_records': [{'message': line} for line in lines]}
        records_key = 'message_records'
    render_result(
        data, fmt, records_key=records_key, fields=fields,
        columns=[Column("message", "MESSAGE", min_width=40, max_width=120)],
        text_fn=_format_history_text,
    )


def _format_history_text(data):
    header = f"{data['chat']} 的消息记录（返回 {data['count']} 条，共 {data['total']} 条，offset={data['offset']}, limit={data['limit']}）"
    if data['is_group']:
        header += " [群聊]"
    if data['from'] or data['to']:
        header += f"\n时间范围: {data['from'] or '最早'} ~ {data['to'] or '最新'}"
    if data['has_more']:
        header += "\n(还有更多消息)"
    if data['failures']:
        header += "\n查询失败: " + "；".join(data['failures'])
    if data['messages']:
        return header + ":\n\n" + "\n".join(data['messages'])
    return f"{data['chat']} 无消息记录"

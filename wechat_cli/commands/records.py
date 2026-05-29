"""records 命令 — 展开微信合并聊天记录"""

import click

from ..core.contacts import get_contact_names
from ..core.messages import (
    collect_forwarded_records,
    parse_time_range,
    resolve_chat_context,
    validate_pagination,
)
from ..output.formatter import output


@click.command("records")
@click.argument("chat_name")
@click.option("--limit", default=20, help="返回的合并聊天记录数量")
@click.option("--offset", default=0, help="分页偏移量")
@click.option("--scan-limit", default=5000, help="最多扫描的链接/文件消息数量")
@click.option("--start-time", default="", help="起始时间 YYYY-MM-DD [HH:MM[:SS]]")
@click.option("--end-time", default="", help="结束时间 YYYY-MM-DD [HH:MM[:SS]]")
@click.option("--format", "fmt", default="json", type=click.Choice(["json", "text"]), help="输出格式")
@click.option("--output", "output_path", default=None, help="输出文件路径（默认输出到 stdout）")
@click.pass_context
def records(ctx, chat_name, limit, offset, scan_limit, start_time, end_time, fmt, output_path):
    """展开指定聊天里的“合并聊天记录”卡片

    \b
    示例:
      wechat-cli records "张三"                         # 展开最近 20 条合并聊天记录
      wechat-cli records "AI交流群" --limit 5 --format text
      wechat-cli records "张三" --start-time "2026-04-01" --output records.txt
    """
    app = ctx.obj

    try:
        validate_pagination(limit, offset, limit_max=None)
        if scan_limit <= 0:
            raise ValueError("scan-limit 必须大于 0")
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
    records_data, failures = collect_forwarded_records(
        chat_ctx, names, app.display_name_fn,
        start_ts=start_ts, end_ts=end_ts, limit=limit, offset=offset,
        scan_limit=scan_limit,
    )

    if fmt == "json":
        result = {
            'chat': chat_ctx['display_name'],
            'username': chat_ctx['username'],
            'is_group': chat_ctx['is_group'],
            'count': len(records_data),
            'offset': offset,
            'limit': limit,
            'scan_limit': scan_limit,
            'start_time': start_time or None,
            'end_time': end_time or None,
            'records': records_data,
            'failures': failures if failures else None,
        }
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                output(result, 'json', file=f)
            click.echo(f"已导出到: {output_path}（{len(records_data)} 条合并聊天记录）", err=True)
        else:
            output(result, 'json')
        return

    content = _format_text(chat_ctx['display_name'], records_data, failures, offset, limit)
    if output_path:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
            if not content.endswith('\n'):
                f.write('\n')
        click.echo(f"已导出到: {output_path}（{len(records_data)} 条合并聊天记录）", err=True)
    else:
        output(content, 'text')


def _format_text(display_name, records_data, failures, offset, limit):
    header = f"{display_name} 的合并聊天记录（返回 {len(records_data)} 条，offset={offset}, limit={limit}）"
    if failures:
        header += "\n查询失败: " + "；".join(failures)
    if not records_data:
        return header + "\n\n无合并聊天记录"

    chunks = [header]
    for record in records_data:
        chunks.append("=" * 80)
        chunks.append(f"[{record['time']}] local_id={record['local_id']}")
        if record.get('sender'):
            chunks.append(f"发送者: {record['sender']}")
        if record.get('title'):
            chunks.append(f"标题: {record['title']}")
        if record.get('summary'):
            chunks.append(f"摘要: {record['summary']}")
        count_line = f"展开条数: {record['item_count']}"
        if record.get('expanded_item_count') and record['expanded_item_count'] != record['item_count']:
            count_line += f"（含嵌套 {record['expanded_item_count']} 条）"
        chunks.append(count_line)
        chunks.append("")
        for item in record['items']:
            chunks.extend(_format_item_lines(item))
        chunks.append("")
    return "\n".join(chunks)


def _format_item_lines(item, label=None, indent=0):
    label = label or f"{item['index']:03d}"
    prefix = "  " * indent
    continuation = "\n" + prefix + "      "
    text = item['text'].replace("\n", continuation)
    time = item['time'] or "未知时间"
    source = item['source'] or "未知发送者"
    lines = [f"{prefix}{label}. [{time}] {source} ({item['type']}): {text}"]
    for child in item.get('children') or []:
        child_label = f"{label}.{child['index']:03d}"
        lines.extend(_format_item_lines(child, label=child_label, indent=indent + 1))
    return lines

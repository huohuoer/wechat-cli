"""stats 命令 — 聊天统计分析"""

import click

from ..core.contacts import get_contact_names
from ..core.messages import (
    collect_chat_stats,
    parse_time_range,
    resolve_chat_context,
)
from ..output.formatter import (
    Column,
    QUERY_FORMATS,
    output_json,
    output_ndjson,
    output_table,
    output_text,
)
from .schema_option import schema_option


@click.command("stats")
@schema_option("stats")
@click.argument("chat_name")
@click.option("--from", "from_time", metavar="", default="", help="起始时间 (YYYY-MM-DD [HH:MM[:SS]])")
@click.option("--to", "to_time", metavar="", default="", help="结束时间 (YYYY-MM-DD [HH:MM[:SS]])")
@click.option("--format", "fmt", default="json", type=click.Choice(QUERY_FORMATS), metavar="", help="输出格式: json, ndjson, table, text (默认 json)")
@click.pass_context
def stats(ctx, chat_name, from_time, to_time, fmt):
    """聊天统计分析

    \b
    示例:
      wechat-cli stats "AI交流群"
      wechat-cli stats "张三" --from "2026-04-01" --to "2026-04-03"
      wechat-cli stats "群名" --format table
    """
    app = ctx.obj

    try:
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
    result = collect_chat_stats(
        chat_ctx, names, app.display_name_fn,
        start_ts=start_ts, end_ts=end_ts,
    )

    data = {
        'chat': chat_ctx['display_name'],
        'username': chat_ctx['username'],
        'is_group': chat_ctx['is_group'],
        'from': from_time or None,
        'to': to_time or None,
        **result,
    }
    if fmt == 'json':
        output_json(data)
    elif fmt == 'ndjson':
        output_ndjson(_stats_records(data))
    elif fmt == 'table':
        _output_stats_table(data)
    else:
        output_text(_format_stats_text(data))


def _stats_records(data):
    yield {'section': 'summary', 'chat': data['chat'], 'total': data['total']}
    for name, count in data['type_breakdown'].items():
        yield {'section': 'type_breakdown', 'type': name, 'count': count}
    for sender in data['top_senders']:
        yield {'section': 'top_senders', **sender}
    for hour, count in data['hourly'].items():
        yield {'section': 'hourly', 'hour': hour, 'count': count}


def _output_stats_table(data):
    output_text(f"{data['chat']} 聊天统计")
    output_table([{'metric': '消息总数', 'value': data['total']}], [
        Column("metric", "METRIC", min_width=12, max_width=20),
        Column("value", "VALUE", min_width=8, max_width=16),
    ])
    if data['type_breakdown']:
        output_text("\n消息类型分布:")
        output_table([
            {'type': name, 'count': count, 'percent': f"{count / data['total'] * 100:.1f}%" if data['total'] else "0.0%"}
            for name, count in data['type_breakdown'].items()
        ], [
            Column("type", "TYPE", min_width=8, max_width=18),
            Column("count", "COUNT", width=8),
            Column("percent", "PERCENT", width=8),
        ])
    if data['top_senders']:
        output_text("\n发言排行 Top 10:")
        output_table(data['top_senders'], [
            Column("name", "NAME", min_width=12, max_width=32),
            Column("count", "COUNT", width=8),
        ])
    output_text("\n24小时活跃分布:")
    output_table([
        {'hour': f"{hour:02d}", 'count': count}
        for hour, count in data['hourly'].items()
    ], [
        Column("hour", "HOUR", width=4),
        Column("count", "COUNT", width=8),
    ])


def _format_stats_text(data):
    lines = [f"{data['chat']} 聊天统计"]
    if data['is_group']:
        lines[0] += " [群聊]"
    lines.append(f"消息总数: {data['total']}")
    if data['from'] or data['to']:
        lines.append(f"时间范围: {data['from'] or '最早'} ~ {data['to'] or '最新'}")

    lines.append("\n消息类型分布:")
    for t, cnt in data['type_breakdown'].items():
        pct = cnt / data['total'] * 100 if data['total'] > 0 else 0
        lines.append(f"  {t}: {cnt} ({pct:.1f}%)")

    if data['top_senders']:
        lines.append("\n发言排行 Top 10:")
        for s in data['top_senders']:
            lines.append(f"  {s['name']}: {s['count']}")

    lines.append("\n24小时活跃分布:")
    max_count = max(data['hourly'].values()) if data['hourly'] else 0
    bar_max = 30
    for h in range(24):
        count = data['hourly'].get(h, 0)
        bar_len = int(count / max_count * bar_max) if max_count > 0 else 0
        bar = '█' * bar_len
        lines.append(f"  {h:02d}时 |{bar} {count}")
    return "\n".join(lines)

"""get-recent-sessions 命令"""

import os
import sqlite3
from contextlib import closing
from datetime import datetime

import click

from ..core.contacts import get_contact_names, classify_chat_type
from ..core.messages import decompress_content, format_msg_type
from .filters import BOOL_CHOICE, MSG_TYPE_CHOICE, CHAT_TYPE_CHOICE, matches_session_filters
from .schema_option import schema_option
from ..output.formatter import Column, QUERY_FORMATS, render_result


@click.command("sessions")
@schema_option("sessions")
@click.option("--limit", metavar="", default=20, help="返回数量 (默认 20)")
@click.option("--chat", metavar="", default="", help="按聊天名或 username 过滤")
@click.option("--is-group", "is_group_filter", default=None, type=BOOL_CHOICE, metavar="", help="群聊过滤 (true/false)")
@click.option("--chat-type", "chat_type_filter", default=None, type=CHAT_TYPE_CHOICE, metavar="", help="会话类型: group, subscription, contact, openim, kefu")
@click.option("--msg-type", "msg_type_filter", default=None, type=MSG_TYPE_CHOICE, metavar="", help="消息类型: text, image, voice, video, sticker, location, link, file, call, system")
@click.option("--unread", "unread_filter", default=None, type=BOOL_CHOICE, metavar="", help="未读过滤 (true/false)")
@click.option("--format", "fmt", default="json", type=click.Choice(QUERY_FORMATS), metavar="", help="输出格式: json, ndjson, table, text (默认 json)")
@click.option("--fields", metavar="", default=None, help="字段选择器 (逗号分隔)")
@click.pass_context
def sessions(ctx, limit, chat, is_group_filter, chat_type_filter, msg_type_filter, unread_filter, fmt, fields):
    """获取最近会话列表

    \b
    示例:
      wechat-cli sessions                # 默认返回最近 20 个会话 (JSON)
      wechat-cli sessions --limit 10     # 最近 10 个会话
      wechat-cli sessions --chat "AI交流群" --is-group true
      wechat-cli sessions --format table # 表格输出
    """
    app = ctx.obj

    path = app.cache.get(os.path.join("session", "session.db"))
    if not path:
        click.echo("错误: 无法解密 session.db", err=True)
        ctx.exit(3)

    names = get_contact_names(app.cache, app.decrypted_dir)
    with closing(sqlite3.connect(path)) as conn:
        rows = conn.execute("""
            SELECT username, unread_count, summary, last_timestamp,
                   last_msg_type, last_msg_sender, last_sender_display_name
            FROM SessionTable
            WHERE last_timestamp > 0
            ORDER BY last_timestamp DESC
        """).fetchall()

    results = []
    for r in rows:
        username, unread_count, summary, ts, raw_msg_type, sender, sender_name = r
        display = names.get(username, username)
        chat_type = classify_chat_type(username)
        is_group = chat_type == 'group'
        if not matches_session_filters(
            username, display, unread_count, raw_msg_type,
            chat=chat, is_group=is_group_filter, chat_type=chat_type_filter, unread=unread_filter, msg_type=msg_type_filter,
        ):
            continue

        if isinstance(summary, bytes):
            summary = decompress_content(summary, 4) or '(压缩内容)'
        if isinstance(summary, str) and ':\n' in summary:
            summary = summary.split(':\n', 1)[1]

        sender_display = ''
        if is_group and sender:
            sender_display = names.get(sender, sender_name or sender)

        results.append({
            'chat': display,
            'username': username,
            'chat_type': chat_type,
            'is_group': is_group,
            'unread': unread_count or 0,
            'last_message': str(summary or ''),
            'msg_type': format_msg_type(raw_msg_type),
            'sender': sender_display,
            'timestamp': ts,
            'time': datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M'),
        })

    total = len(results)
    has_more = total > limit
    results = results[:limit]

    data = {
        'total': total,
        'has_more': has_more,
        'limit': limit,
        'sessions': results,
    }
    render_result(
        data, fmt, records_key='sessions', fields=fields,
        columns=[
            Column("time", "TIME", width=16),
            Column("unread", "UNREAD", width=6),
            Column("chat", "CHAT", min_width=10, max_width=24),
            Column("msg_type", "TYPE", width=10),
            Column("sender", "SENDER", min_width=8, max_width=16),
            Column("last_message", "LAST MESSAGE", min_width=20, max_width=60),
        ],
        text_fn=_format_sessions_text,
    )


_CHAT_TYPE_LABELS = {
    'group': '[群]',
    'subscription': '[公众号]',
    'openim': '[企微]',
    'kefu': '[客服]',
}


def _format_sessions_text(data):
    results = data['sessions']
    lines = []
    for r in results:
        entry = f"[{r['time']}] {r['chat']}"
        label = _CHAT_TYPE_LABELS.get(r['chat_type'])
        if label:
            entry += f" {label}"
        if r['unread'] > 0:
            entry += f" ({r['unread']}条未读)"
        entry += f"\n  {r['msg_type']}: "
        if r['sender']:
            entry += f"{r['sender']}: "
        entry += r['last_message']
        lines.append(entry)
    header = f"最近 {len(results)} 个会话（共 {data['total']} 个）"
    if data['has_more']:
        header += "，还有更多"
    return header + ":\n\n" + "\n\n".join(lines)

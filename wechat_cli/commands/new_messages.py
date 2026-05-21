"""get-new-messages 命令 — 增量消息查询，状态持久化到磁盘"""

import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime

import click

from ..core.config import STATE_DIR
from ..core.contacts import get_contact_names, classify_chat_type
from ..core.messages import decompress_content, format_msg_type
from .filters import BOOL_CHOICE, MSG_TYPE_CHOICE, CHAT_TYPE_CHOICE, matches_session_filters
from ..output.formatter import Column, QUERY_FORMATS, render_result
from .schema_option import schema_option

STATE_FILE = os.path.join(STATE_DIR, "last_check.json")


def _load_last_state():
    if not os.path.exists(STATE_FILE):
        return {}
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save_last_state(state):
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(STATE_FILE, 'w', encoding="utf-8") as f:
        json.dump(state, f)


@click.command("new-messages")
@schema_option("new-messages")
@click.option("--chat", metavar="", default="", help="按聊天名或 username 过滤")
@click.option("--is-group", "is_group_filter", default=None, type=BOOL_CHOICE, metavar="", help="群聊过滤 (true/false)")
@click.option("--chat-type", "chat_type_filter", default=None, type=CHAT_TYPE_CHOICE, metavar="", help="会话类型: group, subscription, contact, openim, kefu")
@click.option("--msg-type", "msg_type_filter", default=None, type=MSG_TYPE_CHOICE, metavar="", help="消息类型: text, image, voice, video, sticker, location, link, file, call, system")
@click.option("--unread", "unread_filter", default=None, type=BOOL_CHOICE, metavar="", help="未读过滤 (true/false)")
@click.option("--limit", metavar="", default=50, help="返回数量 (默认 50)")
@click.option("--format", "fmt", default="json", type=click.Choice(QUERY_FORMATS), metavar="", help="输出格式: json, ndjson, table, text (默认 json)")
@click.option("--fields", metavar="", default=None, help="字段选择器 (逗号分隔)")
@click.pass_context
def new_messages(ctx, chat, is_group_filter, chat_type_filter, msg_type_filter, unread_filter, limit, fmt, fields):
    """获取自上次调用以来的新消息

    \b
    示例:
      wechat-cli new-messages               # 首次: 返回未读消息并记录状态
      wechat-cli new-messages               # 再次: 仅返回新增消息
      wechat-cli new-messages --chat "AI交流群" --unread true
      wechat-cli new-messages --format table # 表格输出
    \b
    状态文件: ~/.wechat-cli/last_check.json (删除此文件可重置)
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

    curr_state = {}
    for r in rows:
        username, unread, summary, ts, msg_type, sender, sender_name = r
        curr_state[username] = {
            'unread': unread, 'summary': summary, 'timestamp': ts,
            'msg_type': msg_type, 'sender': sender or '', 'sender_name': sender_name or '',
        }

    last_state = _load_last_state()

    if not last_state:
        # 首次调用：保存状态，返回未读
        _save_last_state({u: s['timestamp'] for u, s in curr_state.items()})

        unread_msgs = []
        for username, s in curr_state.items():
            if s['unread'] and s['unread'] > 0:
                display = names.get(username, username)
                chat_type = classify_chat_type(username)
                is_group = chat_type == 'group'
                if not matches_session_filters(
                    username, display, s['unread'], s['msg_type'],
                    chat=chat, is_group=is_group_filter, chat_type=chat_type_filter, unread=unread_filter, msg_type=msg_type_filter,
                ):
                    continue
                summary = s['summary']
                if isinstance(summary, bytes):
                    summary = decompress_content(summary, 4) or '(压缩内容)'
                if isinstance(summary, str) and ':\n' in summary:
                    summary = summary.split(':\n', 1)[1]
                time_str = datetime.fromtimestamp(s['timestamp']).strftime('%Y-%m-%d %H:%M')
                unread_msgs.append({
                    'chat': display,
                    'username': username,
                    'chat_type': chat_type,
                    'is_group': is_group,
                    'unread': s['unread'],
                    'last_message': str(summary or ''),
                    'msg_type': format_msg_type(s['msg_type']),
                    'time': time_str,
                    'timestamp': s['timestamp'],
                })

        total = len(unread_msgs)
        has_more = total > limit
        data = {
            'first_call': True,
            'total': total,
            'has_more': has_more,
            'unread_count': total,
            'limit': limit,
            'messages': unread_msgs[:limit],
        }
        _render_messages(data, fmt, fields)
        return

    # 后续调用：对比差异
    new_msgs = []
    for username, s in curr_state.items():
        prev_ts = last_state.get(username, 0)
        if s['timestamp'] > prev_ts:
            display = names.get(username, username)
            chat_type = classify_chat_type(username)
            is_group = chat_type == 'group'
            if not matches_session_filters(
                username, display, s['unread'], s['msg_type'],
                chat=chat, is_group=is_group_filter, chat_type=chat_type_filter, unread=unread_filter, msg_type=msg_type_filter,
            ):
                continue
            summary = s['summary']
            if isinstance(summary, bytes):
                summary = decompress_content(summary, 4) or '(压缩内容)'
            if isinstance(summary, str) and ':\n' in summary:
                summary = summary.split(':\n', 1)[1]

            sender_display = ''
            if is_group and s['sender']:
                sender_display = names.get(s['sender'], s['sender_name'] or s['sender'])

            new_msgs.append({
                'chat': display,
                'username': username,
                'chat_type': chat_type,
                'is_group': is_group,
                'unread': s['unread'] or 0,
                'last_message': str(summary or ''),
                'msg_type': format_msg_type(s['msg_type']),
                'sender': sender_display,
                'time': datetime.fromtimestamp(s['timestamp']).strftime('%Y-%m-%d %H:%M'),
                'timestamp': s['timestamp'],
            })

    _save_last_state({u: s['timestamp'] for u, s in curr_state.items()})

    new_msgs.sort(key=lambda m: m['timestamp'], reverse=True)

    total = len(new_msgs)
    has_more = total > limit
    data = {
        'first_call': False,
        'total': total,
        'has_more': has_more,
        'new_count': total,
        'limit': limit,
        'messages': new_msgs[:limit],
    }
    _render_messages(data, fmt, fields)


def _render_messages(data, fmt, fields=None):
    render_result(
        data, fmt, records_key='messages', fields=fields,
        columns=[
            Column("time", "TIME", width=16),
            Column("chat", "CHAT", min_width=10, max_width=24),
            Column("unread", "UNREAD", width=6),
            Column("msg_type", "TYPE", width=10),
            Column("sender", "SENDER", min_width=8, max_width=16),
            Column("last_message", "LAST MESSAGE", min_width=20, max_width=64),
        ],
        text_fn=_format_messages_text,
    )


_CHAT_TYPE_LABELS = {
    'group': '[群]',
    'subscription': '[公众号]',
    'openim': '[企微]',
    'kefu': '[客服]',
}


def _format_messages_text(data):
    messages = data['messages']
    if data.get('first_call'):
        if messages:
            lines = []
            for m in messages:
                label = _CHAT_TYPE_LABELS.get(m.get('chat_type', ''), '')
                tag = f" {label}" if label else ""
                lines.append(f"[{m['time']}] {m['chat']}{tag} ({m['unread']}条未读): {m['last_message']}")
            return f"当前 {len(messages)} 个未读会话:\n\n" + "\n".join(lines)
        return "当前无未读消息（已记录状态，下次调用将返回新消息）"

    if not messages:
        return "无新消息"
    lines = []
    for m in messages:
        entry = f"[{m['time']}] {m['chat']}"
        label = _CHAT_TYPE_LABELS.get(m.get('chat_type', ''), '')
        if label:
            entry += f" {label}"
        entry += f": {m['msg_type']}"
        if m.get('sender'):
            entry += f" ({m['sender']})"
        entry += f" - {m['last_message']}"
        lines.append(entry)
    return f"{len(messages)} 条新消息:\n\n" + "\n".join(lines)

"""search-messages 命令"""

import os
import sqlite3
from contextlib import closing

import click

from ..core.contacts import get_contact_names
from ..core.messages import (
    MSG_TYPE_FILTERS,
    collect_chat_search,
    parse_time_range,
    resolve_chat_context,
    resolve_chat_contexts,
    search_all_messages,
    validate_pagination,
    _candidate_page_size,
    _page_ranked_entries,
)
from .filters import BOOL_CHOICE, MSG_TYPE_CHOICE, matches_is_group, parse_bool_option
from ..output.formatter import Column, QUERY_FORMATS, render_result, warn
from .schema_option import schema_option


@click.command("search")
@schema_option("search")
@click.argument("keyword")
@click.option("--chat", multiple=True, metavar="", help="按聊天名或 username 过滤")
@click.option("--from", "from_time", metavar="", default="", help="起始时间 (YYYY-MM-DD [HH:MM[:SS]])")
@click.option("--to", "to_time", metavar="", default="", help="结束时间 (YYYY-MM-DD [HH:MM[:SS]])")
@click.option("--limit", metavar="", default=20, help="返回数量 (默认 20, 最大 500)")
@click.option("--offset", metavar="", default=0, help="分页偏移量 (默认 0)")
@click.option("--format", "fmt", default="json", type=click.Choice(QUERY_FORMATS), metavar="", help="输出格式: json, ndjson, table, text (默认 json)")
@click.option("--msg-type", "msg_type", default=None, type=MSG_TYPE_CHOICE, metavar="", help="消息类型: text, image, voice, video, sticker, location, link, file, call, system")
@click.option("--type", "type_alias", default=None, type=MSG_TYPE_CHOICE, metavar="", help="[DEPRECATED] 使用 --msg-type 代替")
@click.option("--is-group", default=None, type=BOOL_CHOICE, metavar="", help="群聊过滤 (true/false)")
@click.option("--unread", default=None, type=BOOL_CHOICE, metavar="", help="未读过滤 (true/false)")
@click.option("--sort", "sort_order", default="desc", type=click.Choice(("desc", "asc")), metavar="", help="排序方向: desc (最新优先), asc (最旧优先) (默认 desc)")
@click.option("--fields", metavar="", default=None, help="字段选择器 (逗号分隔)")
@click.pass_context
def search(ctx, keyword, chat, from_time, to_time, limit, offset, fmt, msg_type, type_alias, is_group, unread, sort_order, fields):
    """搜索消息内容

    \b
    示例:
      wechat-cli search "Claude"                         # 全局搜索
      wechat-cli search "Claude" --chat "AI交流群"        # 在指定群搜索
      wechat-cli search "开会" --chat "群A" --chat "群B"  # 同时搜多个群
      wechat-cli search "Claude" --is-group true --unread true
      wechat-cli search "你好" --from "2026-04-01" --limit 50
    """
    if type_alias and not msg_type:
        warn("--type is deprecated, use --msg-type instead")
        msg_type = type_alias
    elif type_alias and msg_type and type_alias != msg_type:
        click.echo("错误: --type 和 --msg-type 不能同时指定不同的消息类型", err=True)
        ctx.exit(2)

    app = ctx.obj

    try:
        validate_pagination(limit, offset)
        start_ts, end_ts = parse_time_range(from_time, to_time)
    except ValueError as e:
        click.echo(f"错误: {e}", err=True)
        ctx.exit(2)

    names = get_contact_names(app.cache, app.decrypted_dir)
    candidate_limit = _candidate_page_size(limit, offset)
    chat_names = list(chat)
    type_filter = MSG_TYPE_FILTERS[msg_type] if msg_type else None
    unread_usernames = _load_unread_usernames(app, ctx) if unread is not None else None

    if len(chat_names) == 1:
        chat_ctx = resolve_chat_context(chat_names[0], app.msg_db_keys, app.cache, app.decrypted_dir)
        if not chat_ctx:
            click.echo(f"找不到聊天对象: {chat_names[0]}", err=True)
            ctx.exit(1)
        if not chat_ctx['db_path']:
            click.echo(f"找不到 {chat_ctx['display_name']} 的消息记录", err=True)
            ctx.exit(1)
        if _matches_context_filters(chat_ctx, is_group, unread, unread_usernames):
            entries, total, failures = collect_chat_search(
                chat_ctx, names, keyword, app.display_name_fn,
                start_ts=start_ts, end_ts=end_ts, candidate_limit=candidate_limit,
                msg_type_filter=type_filter,
            )
        else:
            entries, total, failures = [], 0, []
        scope = chat_ctx['display_name']

    elif len(chat_names) > 1:
        resolved, unresolved, missing = resolve_chat_contexts(chat_names, app.msg_db_keys, app.cache, app.decrypted_dir)
        if not resolved:
            click.echo("错误: 没有可查询的聊天对象", err=True)
            ctx.exit(1)
        entries = []
        failures = []
        total = 0
        resolved = [rc for rc in resolved if _matches_context_filters(rc, is_group, unread, unread_usernames)]
        for rc in resolved:
            e, t, f = collect_chat_search(
                rc, names, keyword, app.display_name_fn,
                start_ts=start_ts, end_ts=end_ts, candidate_limit=candidate_limit,
                msg_type_filter=type_filter,
            )
            entries.extend(e)
            total += t
            failures.extend(f)
        if unresolved:
            failures.append("未找到: " + "、".join(unresolved))
        scope = f"{len(resolved)} 个聊天对象"

    else:
        entries, total, failures = search_all_messages(
            app.msg_db_keys, app.cache, names, keyword, app.display_name_fn,
            start_ts=start_ts, end_ts=end_ts, candidate_limit=candidate_limit,
            msg_type_filter=type_filter,
            context_filter=lambda search_ctx: _matches_context_filters(search_ctx, is_group, unread, unread_usernames),
        )
        scope = "全部消息"

    paged = _page_ranked_entries(entries, limit, offset, reverse=(sort_order == 'desc'))

    result_lines = [item[1] for item in paged]
    data = {
        'scope': scope,
        'keyword': keyword,
        'sort': sort_order,
        'count': len(paged),
        'total': total,
        'has_more': (offset + len(paged)) < total,
        'offset': offset,
        'limit': limit,
        'from': from_time or None,
        'to': to_time or None,
        'type': msg_type or None,
        'results': result_lines,
        'failures': failures if failures else None,
    }
    records_key = 'results'
    if fmt in ('ndjson', 'table'):
        data = {**data, 'result_records': [{'result': line} for line in result_lines]}
        records_key = 'result_records'
    render_result(
        data, fmt, records_key=records_key, fields=fields,
        columns=[Column("result", "RESULT", min_width=40, max_width=120)],
        text_fn=_format_search_text, highlight_keyword=keyword,
    )


def _load_unread_usernames(app, ctx):
    path = app.cache.get(os.path.join("session", "session.db"))
    if not path:
        click.echo("错误: 无法解密 session.db", err=True)
        ctx.exit(3)
    unread_usernames = set()
    with closing(sqlite3.connect(path)) as conn:
        rows = conn.execute("SELECT username, unread_count FROM SessionTable").fetchall()
    for username, unread_count in rows:
        if unread_count and unread_count > 0:
            unread_usernames.add(username)
    return unread_usernames


def _matches_context_filters(search_ctx, is_group, unread, unread_usernames):
    username = search_ctx.get('username', '')
    if not matches_is_group(username, is_group):
        return False
    expected_unread = parse_bool_option(unread)
    if expected_unread is None:
        return True
    return (username in (unread_usernames or set())) == expected_unread


def _format_search_text(data):
    if not data['results']:
        return f"在 {data['scope']} 中未找到包含 \"{data['keyword']}\" 的消息"
    header = (
        f"在 {data['scope']} 中搜索 \"{data['keyword']}\" 找到 {data['count']} 条结果"
        f"（共 {data['total']} 条，offset={data['offset']}, limit={data['limit']}）"
    )
    if data['has_more']:
        header += "，还有更多"
    if data['from'] or data['to']:
        header += f"\n时间范围: {data['from'] or '最早'} ~ {data['to'] or '最新'}"
    if data['failures']:
        header += "\n查询失败: " + "；".join(data['failures'])
    return header + ":\n\n" + "\n\n".join(data['results'])

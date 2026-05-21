"""members 命令 — 查询群聊成员列表"""

import click

from ..core.contacts import get_contact_names, resolve_username, get_group_members
from ..output.formatter import Column, QUERY_FORMATS, render_result
from .schema_option import schema_option


@click.command("members")
@schema_option("members")
@click.argument("group_name")
@click.option("--limit", metavar="", default=50, help="返回数量 (默认 50)")
@click.option("--format", "fmt", default="json", type=click.Choice(QUERY_FORMATS), metavar="", help="输出格式: json, ndjson, table, text (默认 json)")
@click.option("--fields", metavar="", default=None, help="字段选择器 (逗号分隔)")
@click.pass_context
def members(ctx, group_name, limit, fmt, fields):
    """查询群聊成员列表

    \b
    示例:
      wechat-cli members "AI交流群"
      wechat-cli members "群名" --format table
    """
    app = ctx.obj

    username = resolve_username(group_name, app.cache, app.decrypted_dir)
    if not username:
        click.echo(f"找不到: {group_name}", err=True)
        ctx.exit(1)

    if '@chatroom' not in username:
        click.echo(f"{group_name} 不是一个群聊", err=True)
        ctx.exit(1)

    names = get_contact_names(app.cache, app.decrypted_dir)
    display_name = names.get(username, username)

    result = get_group_members(username, app.cache, app.decrypted_dir)

    all_members = result['members']
    total = len(all_members)
    has_more = total > limit
    members_list = all_members[:limit]

    data = {
        'group': display_name,
        'username': username,
        'member_count': total,
        'has_more': has_more,
        'limit': limit,
        'owner': result['owner'],
        'members': members_list,
    }
    render_result(
        data, fmt, records_key='members', fields=fields,
        columns=[
            Column("display_name", "DISPLAY NAME", min_width=12, max_width=28),
            Column("username", "USERNAME", min_width=16, max_width=32),
            Column("remark", "REMARK", min_width=8, max_width=24),
            Column("nick_name", "NICK", min_width=8, max_width=24),
        ],
        text_fn=_format_members_text,
    )


def _format_members_text(data):
    lines = []
    for m in data['members']:
        line = f"{m['display_name']}  ({m['username']})"
        if m['remark']:
            line += f"  备注: {m['remark']}"
        lines.append(line)
    header = f"{data['group']} 的群成员（共 {data['member_count']} 人）"
    if data['owner']:
        header += f"，群主: {data['owner']}"
    return header + ":\n\n" + "\n".join(lines)

"""contacts 命令 — 搜索或查看联系人"""

import click

from ..core.contacts import get_contact_full, get_contact_names, resolve_username, get_contact_detail
from ..output.formatter import Column, QUERY_FORMATS, render_result
from .schema_option import schema_option


@click.command("contacts")
@schema_option("contacts")
@click.option("--query", metavar="", default="", help="搜索关键词")
@click.option("--detail", metavar="", default=None, help="查看联系人详情 (传入昵称/备注/wxid)")
@click.option("--limit", metavar="", default=50, help="返回数量 (默认 50)")
@click.option("--format", "fmt", default="json", type=click.Choice(QUERY_FORMATS), metavar="", help="输出格式: json, ndjson, table, text (默认 json)")
@click.option("--fields", metavar="", default=None, help="字段选择器 (逗号分隔)")
@click.pass_context
def contacts(ctx, query, detail, limit, fmt, fields):
    """搜索或列出联系人

    \b
    示例:
      wechat-cli contacts --query "李"              # 搜索联系人
      wechat-cli contacts --detail "张三"          # 查看联系人详情
      wechat-cli contacts --detail "wxid_xxx"       # 通过 wxid 查看
    """
    app = ctx.obj

    if detail:
        _show_detail(app, detail, fmt)
        return

    names = get_contact_names(app.cache, app.decrypted_dir)
    full = get_contact_full(app.cache, app.decrypted_dir)

    if query:
        q_lower = query.lower()
        matched = [c for c in full if q_lower in c.get('nick_name', '').lower()
                   or q_lower in c.get('remark', '').lower()
                   or q_lower in c.get('username', '').lower()]
    else:
        matched = full

    total = len(matched)
    has_more = total > limit
    matched = matched[:limit]

    for c in matched:
        c['display_name'] = c['remark'] or c['nick_name'] or c['username']

    data = {
        'total': total,
        'has_more': has_more,
        'limit': limit,
        'contacts': matched,
    }
    render_result(
        data, fmt, records_key='contacts', fields=fields,
        columns=[
            Column("display_name", "DISPLAY NAME", min_width=12, max_width=28),
            Column("username", "USERNAME", min_width=16, max_width=32),
            Column("remark", "REMARK", min_width=8, max_width=24),
            Column("nick_name", "NICK", min_width=8, max_width=24),
        ],
        text_fn=_format_contacts_text,
    )


def _show_detail(app, name_or_id, fmt):
    """显示联系人详情。"""
    names = get_contact_names(app.cache, app.decrypted_dir)

    # 尝试解析为 username
    username = resolve_username(name_or_id, app.cache, app.decrypted_dir)
    if not username:
        # 直接用原始输入试试
        username = name_or_id

    info = get_contact_detail(username, app.cache, app.decrypted_dir)
    if not info:
        click.echo(f"找不到联系人: {name_or_id}", err=True)
        return

    rows = [{'field': k, 'value': v} for k, v in info.items()]
    if fmt == 'table':
        render_result(rows, fmt, columns=[
            Column("field", "FIELD", min_width=12, max_width=20),
            Column("value", "VALUE", min_width=20, max_width=80),
        ])
        return
    render_result(info, fmt, text_fn=_format_contact_detail_text)


def _format_contacts_text(data):
    results = data['contacts']
    header = f"找到 {len(results)} 个联系人（共 {data['total']} 个）"
    if data['has_more']:
        header += "，还有更多"
    lines = []
    for c in results:
        line = f"{c['display_name']}  ({c['username']})"
        if c['remark']:
            line += f"  备注: {c['remark']}"
        lines.append(line)
    return header + ":\n\n" + "\n".join(lines)


def _format_contact_detail_text(info):
    lines = [f"联系人详情: {info['nick_name']}"]
    if info['remark']:
        lines.append(f"备注: {info['remark']}")
    if info['alias']:
        lines.append(f"微信号: {info['alias']}")
    lines.append(f"wxid: {info['username']}")
    if info['description']:
        lines.append(f"个性签名: {info['description']}")
    if info['is_group']:
        lines.append("类型: 群聊")
    elif info['is_subscription']:
        lines.append("类型: 公众号")
    elif info['verify_flag'] and info['verify_flag'] >= 8:
        lines.append("类型: 企业认证")
    if info['avatar']:
        lines.append(f"头像: {info['avatar']}")
    return "\n".join(lines)

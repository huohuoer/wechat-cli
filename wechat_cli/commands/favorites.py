"""favorites 命令 — 查看微信收藏"""

import os
import sqlite3
import xml.etree.ElementTree as ET
from contextlib import closing
from datetime import datetime

import click

from ..core.contacts import get_contact_names
from ..output.formatter import Column, QUERY_FORMATS, render_result
from .schema_option import schema_option

_FAV_TYPE_MAP = {
    1: '文本', 2: '图片', 5: '文章', 19: '名片', 20: '视频号',
}

_FAV_TYPE_FILTERS = {
    'text': 1, 'image': 2, 'article': 5, 'card': 19, 'video': 20,
}


def _parse_fav_content(content, fav_type):
    """从 XML content 提取摘要信息。"""
    if not content:
        return ''
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return ''
    item = root if root.tag == 'favitem' else root.find('.//favitem')
    if item is None:
        return ''

    if fav_type == 1:
        return (item.findtext('desc') or '').strip()
    if fav_type == 2:
        return '[图片收藏]'
    if fav_type == 5:
        title = (item.findtext('.//pagetitle') or '').strip()
        desc = (item.findtext('.//pagedesc') or '').strip()
        return f"{title} - {desc}" if desc else title
    if fav_type == 19:
        return (item.findtext('desc') or '').strip()
    if fav_type == 20:
        nickname = (item.findtext('.//nickname') or '').strip()
        desc = (item.findtext('.//desc') or '').strip()
        parts = [p for p in [nickname, desc] if p]
        return ' '.join(parts) if parts else '[视频号]'
    desc = (item.findtext('desc') or '').strip()
    return desc if desc else '[收藏]'


@click.command("favorites")
@schema_option("favorites")
@click.option("--limit", metavar="", default=20, help="返回数量 (默认 20)")
@click.option("--msg-type", "fav_type", default=None,
              type=click.Choice(list(_FAV_TYPE_FILTERS.keys())),
              metavar="", help="收藏类型: text, image, article, card, video")
@click.option("--query", metavar="", default=None, help="搜索关键词")
@click.option("--format", "fmt", default="json", type=click.Choice(QUERY_FORMATS), metavar="", help="输出格式: json, ndjson, table, text (默认 json)")
@click.option("--fields", metavar="", default=None, help="字段选择器 (逗号分隔)")
@click.pass_context
def favorites(ctx, limit, fav_type, query, fmt, fields):
    """查看微信收藏

    \b
    示例:
      wechat-cli favorites                        # 最近收藏
      wechat-cli favorites --msg-type article     # 只看文章
      wechat-cli favorites --query "计算机网络"    # 搜索收藏
      wechat-cli favorites --limit 5 --format table
    """

    app = ctx.obj

    # 查找 favorite.db
    fav_path = None
    pre_decrypted = os.path.join(app.decrypted_dir, "favorite", "favorite.db")
    if os.path.exists(pre_decrypted):
        fav_path = pre_decrypted
    else:
        fav_path = app.cache.get(os.path.join("favorite", "favorite.db"))
    if not fav_path:
        click.echo("错误: 无法访问 favorite.db", err=True)
        ctx.exit(3)

    names = get_contact_names(app.cache, app.decrypted_dir)

    with closing(sqlite3.connect(fav_path)) as conn:
        where_parts = []
        params = []

        if fav_type:
            where_parts.append('type = ?')
            params.append(_FAV_TYPE_FILTERS[fav_type])

        if query:
            where_parts.append('content LIKE ?')
            params.append(f'%{query}%')

        where_sql = f"WHERE {' AND '.join(where_parts)}" if where_parts else ''

        total = conn.execute(
            f"SELECT COUNT(*) FROM fav_db_item {where_sql}", params
        ).fetchone()[0]

        rows = conn.execute(f"""
            SELECT local_id, type, update_time, content, fromusr, realchatname
            FROM fav_db_item
            {where_sql}
            ORDER BY update_time DESC
            LIMIT ?
        """, (*params, limit)).fetchall()

    results = []
    for local_id, typ, ts, content, fromusr, realchat in rows:
        from_display = names.get(fromusr, fromusr) if fromusr else ''
        chat_display = names.get(realchat, realchat) if realchat else ''

        summary = _parse_fav_content(content, typ)

        results.append({
            'id': local_id,
            'type': _FAV_TYPE_MAP.get(typ, f'type={typ}'),
            'time': datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M'),
            'summary': summary,
            'from': from_display,
            'source_chat': chat_display,
        })

    data = {
        'total': total,
        'has_more': total > limit,
        'limit': limit,
        'count': len(results),
        'favorites': results,
    }
    render_result(
        data, fmt, records_key='favorites', fields=fields,
        columns=[
            Column("time", "TIME", width=16),
            Column("type", "TYPE", width=10),
            Column("summary", "SUMMARY", min_width=20, max_width=64),
            Column("from", "FROM", min_width=8, max_width=18),
            Column("source_chat", "SOURCE", min_width=8, max_width=18),
        ],
        text_fn=_format_favorites_text,
    )


def _format_favorites_text(data):
    results = data['favorites']
    if not results:
        return "没有找到收藏"
    header = f"收藏列表（{len(results)} 条，共 {data['total']} 条）"
    if data['has_more']:
        header += "，还有更多"
    lines = []
    for r in results:
        entry = f"[{r['time']}] [{r['type']}] {r['summary']}"
        if r['from']:
            entry += f"\n  来自: {r['from']}"
        if r['source_chat']:
            entry += f"  聊天: {r['source_chat']}"
        lines.append(entry)
    return header + ":\n\n" + "\n\n".join(lines)

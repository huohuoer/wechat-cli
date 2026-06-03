"""export 命令 — 导出聊天记录为 markdown、txt 或 JSON"""

import os
from datetime import datetime

import click

from ..core.contacts import get_contact_names
from ..core.media_export import (
    asset_dir_for_output,
    build_export_payload,
    materialize_record_media,
    prepare_export_targets,
    readme_path_for_output,
    write_export_readme,
    write_json_export,
)
from ..core.messages import (
    collect_chat_export_records,
    collect_chat_history,
    parse_time_range,
    resolve_chat_context,
    validate_pagination,
)
from ..output.formatter import output


@click.command("export")
@click.argument("chat_name")
@click.option("--format", "fmt", default="markdown", type=click.Choice(["markdown", "txt", "json"]), help="导出格式")
@click.option("--output", "output_path", default=None, help="输出文件路径（默认输出到 stdout）")
@click.option("--start-time", default="", help="起始时间 YYYY-MM-DD [HH:MM[:SS]]")
@click.option("--end-time", default="", help="结束时间 YYYY-MM-DD [HH:MM[:SS]]")
@click.option("--limit", default=None, type=int, help="导出消息数量（JSON 默认全部，markdown/txt 默认 500）")
@click.option("--overwrite", is_flag=True, help="覆盖已存在的 JSON 输出文件和资产目录（仅 JSON）")
@click.option("--download-stickers", is_flag=True, help="JSON 导出时从 WeChat CDN 下载/解密本地不可解码的表情")
@click.pass_context
def export(ctx, chat_name, fmt, output_path, start_time, end_time, limit, overwrite, download_stickers):
    """导出聊天记录为 markdown、纯文本或结构化 JSON

    \b
    示例:
      wechat-cli export "张三" --format markdown
      wechat-cli export "AI交流群" --format txt --output chat.txt
      wechat-cli export "AI交流群" --format json --output chat.json
      wechat-cli export "张三" --start-time "2026-04-01" --limit 1000
    """
    app = ctx.obj

    try:
        if limit is not None:
            validate_pagination(limit, 0, limit_max=None)
        start_ts, end_ts = parse_time_range(start_time, end_time)
    except ValueError as e:
        click.echo(f"错误: {e}", err=True)
        ctx.exit(2)

    if fmt == "json" and not output_path:
        click.echo("错误: JSON 导出必须指定 --output，以便生成自包含资产目录", err=True)
        ctx.exit(2)

    chat_ctx = resolve_chat_context(chat_name, app.msg_db_keys, app.cache, app.decrypted_dir)
    if not chat_ctx:
        click.echo(f"找不到聊天对象: {chat_name}", err=True)
        ctx.exit(1)
    if not chat_ctx['db_path']:
        click.echo(f"找不到 {chat_ctx['display_name']} 的消息记录", err=True)
        ctx.exit(1)

    names = get_contact_names(app.cache, app.decrypted_dir)

    if fmt == "json":
        output_path_abs = os.path.abspath(output_path)
        assets_dir = asset_dir_for_output(output_path_abs)
        readme_path = readme_path_for_output(output_path_abs)
        try:
            prepare_export_targets(output_path_abs, assets_dir, readme_path=readme_path, overwrite=overwrite)
        except (FileExistsError, ValueError) as e:
            click.echo(f"错误: {e}", err=True)
            ctx.exit(2)

        resource_failures = []
        try:
            resource_db_path = app.cache.get(os.path.join("message", "message_resource.db"))
        except Exception as e:
            resource_db_path = None
            resource_failures.append(f"message/message_resource.db: {e}")

        records, failures = collect_chat_export_records(
            chat_ctx, names, app.display_name_fn,
            start_ts=start_ts, end_ts=end_ts, limit=limit, db_dir=app.db_dir,
            resource_db_path=resource_db_path,
        )
        failures = resource_failures + failures
        warnings = materialize_record_media(
            records, assets_dir, output_path_abs, download_stickers=download_stickers
        )
        payload = build_export_payload(
            chat_ctx, records,
            start_time=start_time, end_time=end_time, limit=limit,
            failures=failures, warnings=warnings,
        )
        write_json_export(payload, output_path_abs)
        write_export_readme(payload, output_path_abs, assets_dir, readme_path)
        click.echo(f"已导出到: {output_path_abs}（{len(records)} 条消息，资产目录: {assets_dir}，说明: {readme_path}）", err=True)
        return

    text_limit = limit if limit is not None else 500
    lines, failures = collect_chat_history(
        chat_ctx, names, app.display_name_fn,
        start_ts=start_ts, end_ts=end_ts, limit=text_limit, offset=0,
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

"""输出格式化 — JSON/NDJSON (机器友好) / Table/Text (人类可读)"""

import json
import os
import re
import sys
from dataclasses import dataclass
from shutil import get_terminal_size
from unicodedata import east_asian_width


QUERY_FORMATS = ("json", "ndjson", "table", "text")
EXPORT_FORMATS = ("markdown", "txt", "json", "ndjson")
INIT_FORMATS = ("text", "json")


@dataclass(frozen=True)
class Column:
    key: str
    header: str
    width: int | None = None
    min_width: int = 3
    max_width: int | None = None


def output_json(data, file=None):
    file = file or sys.stdout
    json.dump(data, file, ensure_ascii=False, indent=2)
    file.write('\n')


def output_ndjson(records, file=None):
    file = file or sys.stdout
    for record in records:
        json.dump(record, file, ensure_ascii=False, separators=(',', ':'))
        file.write('\n')


def output_text(text, file=None):
    file = file or sys.stdout
    text = str(text)
    file.write(text)
    if not text.endswith('\n'):
        file.write('\n')


def _display_width(value):
    width = 0
    for ch in str(value):
        width += 2 if east_asian_width(ch) in ("F", "W") else 1
    return width


def _truncate(value, width):
    value = str(value).replace('\n', ' ')
    if width <= 0 or _display_width(value) <= width:
        return value
    ellipsis = '...'
    target = max(0, width - len(ellipsis))
    out = ''
    used = 0
    for ch in value:
        ch_width = 2 if east_asian_width(ch) in ("F", "W") else 1
        if used + ch_width > target:
            break
        out += ch
        used += ch_width
    return out + ellipsis


def _pad(value, width):
    return value + ' ' * max(0, width - _display_width(value))


def _cell_value(row, key):
    if isinstance(row, dict):
        value = row.get(key, '')
    else:
        value = getattr(row, key, '')
    if value is None:
        return ''
    if isinstance(value, bool):
        return 'yes' if value else 'no'
    return str(value)


def _resolve_table_widths(rows, columns, max_width=None):
    max_width = max_width or get_terminal_size((120, 20)).columns
    widths = []
    flexible = []
    for idx, col in enumerate(columns):
        if col.width is not None:
            width = col.width
        else:
            values = [_cell_value(row, col.key) for row in rows]
            width = max([_display_width(col.header), *(min(_display_width(v), col.max_width or 80) for v in values)])
            width = max(width, col.min_width)
            if col.max_width is not None:
                width = min(width, col.max_width)
            flexible.append(idx)
        widths.append(width)

    separators = max(0, len(columns) - 1) * 2
    total = sum(widths) + separators
    if total <= max_width or not flexible:
        return widths

    overflow = total - max_width
    for idx in reversed(flexible):
        col = columns[idx]
        reducible = max(0, widths[idx] - col.min_width)
        cut = min(reducible, overflow)
        widths[idx] -= cut
        overflow -= cut
        if overflow <= 0:
            break
    return widths


def output_table(rows, columns, file=None, max_width=None, highlight_keyword=None):
    file = file or sys.stdout
    rows = list(rows or [])
    columns = list(columns or [])
    if not columns:
        output_json(rows, file)
        return

    do_highlight = bool(highlight_keyword) and sys.stdout.isatty() and not os.environ.get('NO_COLOR')
    widths = _resolve_table_widths(rows, columns, max_width=max_width)
    header = '  '.join(_pad(_truncate(col.header, widths[i]), widths[i]) for i, col in enumerate(columns))
    divider = '  '.join('-' * widths[i] for i in range(len(columns)))
    file.write(header.rstrip() + '\n')
    file.write(divider.rstrip() + '\n')
    for row in rows:
        line = '  '.join(
            _pad(_truncate(_cell_value(row, col.key), widths[i]), widths[i])
            for i, col in enumerate(columns)
        )
        if do_highlight:
            line = highlight(line, highlight_keyword)
        file.write(line.rstrip() + '\n')


def primary_records(data, records_key=None):
    if records_key and isinstance(data, dict):
        records = data.get(records_key, [])
    else:
        records = data
    if records is None:
        return []
    if isinstance(records, list):
        return records
    if isinstance(records, tuple):
        return list(records)
    if isinstance(records, dict):
        return [records]
    return [{"value": records}]


def render_result(data, fmt='json', records_key=None, columns=None, text_fn=None, file=None, fields=None, highlight_keyword=None):
    if fmt in ('json', 'ndjson') and fields:
        data = filter_fields(data, fields)
    if fmt == 'json':
        output_json(data, file)
    elif fmt == 'ndjson':
        records = primary_records(data, records_key)
        normalized = [r if isinstance(r, dict) else {"value": r} for r in records]
        output_ndjson(normalized, file)
    elif fmt == 'table':
        rows = primary_records(data, records_key)
        output_table(rows, columns or [], file=file, highlight_keyword=highlight_keyword)
    elif fmt == 'text':
        if text_fn is None:
            output(data, 'json', file=file)
        else:
            text = text_fn(data)
            if highlight_keyword:
                text = highlight(text, highlight_keyword)
            output_text(text, file=file)
    else:
        raise ValueError(f"unsupported output format: {fmt}")


def output(data, fmt='json', file=None):
    if fmt == 'json':
        output_json(data, file)
    elif fmt == 'ndjson':
        output_ndjson(primary_records(data), file)
    elif fmt == 'table':
        output_table(primary_records(data), [], file=file)
    else:
        if isinstance(data, str):
            output_text(data, file)
        elif isinstance(data, dict) and 'text' in data:
            output_text(data['text'], file)
        else:
            output_json(data, file)


def filter_fields(data, fields_str):
    """Filter top-level keys in a dict or list of dicts based on comma-separated field names.

    Only applies to dict/list-of-dict data. Non-dict data is returned as-is.
    """
    if not fields_str or not data:
        return data
    fields = [f.strip() for f in fields_str.split(',') if f.strip()]
    if not fields:
        return data
    if isinstance(data, dict):
        return {k: v for k, v in data.items() if k in fields}
    if isinstance(data, list):
        return [{k: v for k, v in item.items() if k in fields} for item in data if isinstance(item, dict)]
    return data


def highlight(text, keyword):
    """Highlight keyword matches in text using ANSI codes.

    Only applies when stdout is a TTY and NO_COLOR is not set.
    Returns text unchanged otherwise.
    """
    if not keyword or not text:
        return text
    if not sys.stdout.isatty():
        return text
    if os.environ.get('NO_COLOR'):
        return text
    try:
        import click
        pattern = re.compile(re.escape(keyword), re.IGNORECASE)
        return pattern.sub(lambda m: click.style(m.group(), bg='yellow', fg='black'), text)
    except Exception:
        return text


def warn(message, file=None):
    """Output a warning message to stderr with colored 'warning:' prefix."""
    import click
    file = file or sys.stderr
    if file.isatty() and not os.environ.get('NO_COLOR'):
        prefix = click.style("warning:", fg="yellow", bold=True)
    else:
        prefix = "warning:"
    click.echo(f"{prefix} {message}", err=True, file=file)

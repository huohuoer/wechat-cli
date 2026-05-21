"""Shared command JSON schemas for --schema flag."""

SCHEMAS = {
    "sessions": {
        "command": "sessions",
        "description": "List recent chat sessions",
        "output": {
            "type": "object",
            "properties": {
                "total": {"type": "integer", "description": "Total matching sessions"},
                "has_more": {"type": "boolean", "description": "More results available beyond limit"},
                "limit": {"type": "integer"},
                "sessions": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "chat": {"type": "string", "description": "Display name"},
                            "username": {"type": "string", "description": "WeChat ID or chatroom ID"},
                            "is_group": {"type": "boolean"},
                            "unread": {"type": "integer"},
                            "last_message": {"type": "string"},
                            "msg_type": {"type": "string", "enum": ["文本", "图片", "语音", "视频", "表情", "位置", "链接/文件", "通话", "系统", "撤回"]},
                            "sender": {"type": "string"},
                            "timestamp": {"type": "integer", "description": "Unix timestamp"},
                            "time": {"type": "string", "description": "Formatted time YYYY-MM-DD HH:MM"},
                        },
                    },
                },
            },
        },
        "options": {
            "limit": {"type": "integer", "default": 20},
            "chat": {"type": "string", "description": "Filter by chat name"},
            "is-group": {"type": "string", "enum": ["true", "false"]},
            "msg-type": {"type": "string", "enum": ["text", "image", "voice", "video", "sticker", "location", "link", "file", "call", "system"]},
            "unread": {"type": "string", "enum": ["true", "false"]},
            "format": {"type": "string", "enum": ["json", "ndjson", "table", "text"], "default": "json"},
            "fields": {"type": "string", "description": "Comma-separated field selector"},
        },
    },
    "history": {
        "command": "history",
        "description": "Get message history for a chat",
        "output": {
            "type": "object",
            "properties": {
                "chat": {"type": "string"},
                "username": {"type": "string"},
                "is_group": {"type": "boolean"},
                "count": {"type": "integer", "description": "Number of messages returned"},
                "total": {"type": "integer", "description": "Total messages available"},
                "has_more": {"type": "boolean"},
                "offset": {"type": "integer"},
                "limit": {"type": "integer"},
                "from": {"type": ["string", "null"]},
                "to": {"type": ["string", "null"]},
                "type": {"type": ["string", "null"]},
                "messages": {"type": "array", "items": {"type": "string"}},
                "failures": {"type": ["array", "null"], "items": {"type": "string"}},
            },
        },
        "options": {
            "chat_name": {"type": "string", "required": True, "description": "Chat display name or username"},
            "limit": {"type": "integer", "default": 50},
            "offset": {"type": "integer", "default": 0},
            "from": {"type": "string", "description": "Start time YYYY-MM-DD [HH:MM[:SS]]"},
            "to": {"type": "string", "description": "End time YYYY-MM-DD [HH:MM[:SS]]"},
            "format": {"type": "string", "enum": ["json", "ndjson", "table", "text"], "default": "json"},
            "msg-type": {"type": "string", "enum": ["text", "image", "voice", "video", "sticker", "location", "link", "file", "call", "system"]},
            "type": {"type": "string", "description": "[DEPRECATED] Use --msg-type instead"},
            "media": {"type": "boolean", "default": False},
            "fields": {"type": "string", "description": "Comma-separated field selector"},
        },
    },
    "search": {
        "command": "search",
        "description": "Search messages by keyword",
        "output": {
            "type": "object",
            "properties": {
                "scope": {"type": "string"},
                "keyword": {"type": "string"},
                "count": {"type": "integer"},
                "total": {"type": "integer"},
                "has_more": {"type": "boolean"},
                "offset": {"type": "integer"},
                "limit": {"type": "integer"},
                "from": {"type": ["string", "null"]},
                "to": {"type": ["string", "null"]},
                "type": {"type": ["string", "null"]},
                "results": {"type": "array", "items": {"type": "string"}},
                "failures": {"type": ["array", "null"], "items": {"type": "string"}},
            },
        },
        "options": {
            "keyword": {"type": "string", "required": True},
            "chat": {"type": "string", "multiple": True},
            "from": {"type": "string", "description": "Start time YYYY-MM-DD [HH:MM[:SS]]"},
            "to": {"type": "string", "description": "End time YYYY-MM-DD [HH:MM[:SS]]"},
            "limit": {"type": "integer", "default": 20},
            "offset": {"type": "integer", "default": 0},
            "format": {"type": "string", "enum": ["json", "ndjson", "table", "text"], "default": "json"},
            "msg-type": {"type": "string", "enum": ["text", "image", "voice", "video", "sticker", "location", "link", "file", "call", "system"]},
            "type": {"type": "string", "description": "[DEPRECATED] Use --msg-type instead"},
            "is-group": {"type": "string", "enum": ["true", "false"]},
            "unread": {"type": "string", "enum": ["true", "false"]},
            "fields": {"type": "string", "description": "Comma-separated field selector"},
        },
    },
    "contacts": {
        "command": "contacts",
        "description": "Search or list contacts",
        "output": {
            "type": "object",
            "properties": {
                "total": {"type": "integer"},
                "has_more": {"type": "boolean"},
                "limit": {"type": "integer"},
                "contacts": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "display_name": {"type": "string"},
                            "username": {"type": "string"},
                            "remark": {"type": "string"},
                            "nick_name": {"type": "string"},
                        },
                    },
                },
            },
        },
        "options": {
            "query": {"type": "string", "description": "Search keyword"},
            "detail": {"type": "string", "description": "Show contact detail by name/wxid"},
            "limit": {"type": "integer", "default": 50},
            "format": {"type": "string", "enum": ["json", "ndjson", "table", "text"], "default": "json"},
            "fields": {"type": "string", "description": "Comma-separated field selector"},
        },
    },
    "unread": {
        "command": "unread",
        "description": "List unread sessions",
        "output": {
            "type": "object",
            "properties": {
                "total": {"type": "integer"},
                "has_more": {"type": "boolean"},
                "limit": {"type": "integer"},
                "unread": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "chat": {"type": "string"},
                            "username": {"type": "string"},
                            "is_group": {"type": "boolean"},
                            "unread": {"type": "integer"},
                            "last_message": {"type": "string"},
                            "msg_type": {"type": "string"},
                            "sender": {"type": "string"},
                            "timestamp": {"type": "integer"},
                            "time": {"type": "string"},
                        },
                    },
                },
            },
        },
        "options": {
            "limit": {"type": "integer", "default": 50},
            "chat": {"type": "string"},
            "is-group": {"type": "string", "enum": ["true", "false"]},
            "msg-type": {"type": "string", "enum": ["text", "image", "voice", "video", "sticker", "location", "link", "file", "call", "system"]},
            "unread": {"type": "string", "enum": ["true", "false"]},
            "format": {"type": "string", "enum": ["json", "ndjson", "table", "text"], "default": "json"},
            "fields": {"type": "string", "description": "Comma-separated field selector"},
        },
    },
    "new-messages": {
        "command": "new-messages",
        "description": "Get incremental new messages since last call",
        "output": {
            "type": "object",
            "properties": {
                "first_call": {"type": "boolean"},
                "total": {"type": "integer"},
                "has_more": {"type": "boolean"},
                "unread_count": {"type": "integer", "description": "Present on first call"},
                "new_count": {"type": "integer", "description": "Present on subsequent calls"},
                "messages": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "chat": {"type": "string"},
                            "username": {"type": "string"},
                            "is_group": {"type": "boolean"},
                            "unread": {"type": "integer"},
                            "last_message": {"type": "string"},
                            "msg_type": {"type": "string"},
                            "sender": {"type": "string"},
                            "time": {"type": "string"},
                            "timestamp": {"type": "integer"},
                        },
                    },
                },
            },
        },
        "options": {
            "chat": {"type": "string"},
            "is-group": {"type": "string", "enum": ["true", "false"]},
            "msg-type": {"type": "string", "enum": ["text", "image", "voice", "video", "sticker", "location", "link", "file", "call", "system"]},
            "unread": {"type": "string", "enum": ["true", "false"]},
            "format": {"type": "string", "enum": ["json", "ndjson", "table", "text"], "default": "json"},
            "fields": {"type": "string", "description": "Comma-separated field selector"},
        },
    },
    "members": {
        "command": "members",
        "description": "List group chat members",
        "output": {
            "type": "object",
            "properties": {
                "group": {"type": "string"},
                "username": {"type": "string"},
                "member_count": {"type": "integer"},
                "owner": {"type": "string"},
                "members": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "display_name": {"type": "string"},
                            "username": {"type": "string"},
                            "remark": {"type": "string"},
                            "nick_name": {"type": "string"},
                        },
                    },
                },
            },
        },
        "options": {
            "group_name": {"type": "string", "required": True},
            "format": {"type": "string", "enum": ["json", "ndjson", "table", "text"], "default": "json"},
            "fields": {"type": "string", "description": "Comma-separated field selector"},
        },
    },
    "stats": {
        "command": "stats",
        "description": "Chat statistics",
        "output": {
            "type": "object",
            "properties": {
                "chat": {"type": "string"},
                "username": {"type": "string"},
                "is_group": {"type": "boolean"},
                "from": {"type": ["string", "null"]},
                "to": {"type": ["string", "null"]},
                "total": {"type": "integer"},
                "type_breakdown": {"type": "object", "additionalProperties": {"type": "integer"}},
                "top_senders": {"type": "array", "items": {"type": "object", "properties": {"name": {"type": "string"}, "count": {"type": "integer"}}}},
                "hourly": {"type": "object", "additionalProperties": {"type": "integer"}},
            },
        },
        "options": {
            "chat_name": {"type": "string", "required": True},
            "from": {"type": "string", "description": "Start time YYYY-MM-DD [HH:MM[:SS]]"},
            "to": {"type": "string", "description": "End time YYYY-MM-DD [HH:MM[:SS]]"},
            "format": {"type": "string", "enum": ["json", "ndjson", "table", "text"], "default": "json"},
        },
    },
    "favorites": {
        "command": "favorites",
        "description": "View WeChat favorites/bookmarks",
        "output": {
            "type": "object",
            "properties": {
                "total": {"type": "integer"},
                "has_more": {"type": "boolean"},
                "limit": {"type": "integer"},
                "count": {"type": "integer"},
                "favorites": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "integer"},
                            "type": {"type": "string", "enum": ["文本", "图片", "文章", "名片", "视频号"]},
                            "time": {"type": "string"},
                            "summary": {"type": "string"},
                            "from": {"type": "string"},
                            "source_chat": {"type": "string"},
                        },
                    },
                },
            },
        },
        "options": {
            "limit": {"type": "integer", "default": 20},
            "msg-type": {"type": "string", "enum": ["text", "image", "article", "card", "video"]},
            "query": {"type": "string"},
            "format": {"type": "string", "enum": ["json", "ndjson", "table", "text"], "default": "json"},
            "fields": {"type": "string", "description": "Comma-separated field selector"},
        },
    },
    "export": {
        "command": "export",
        "description": "Export chat history to file",
        "output": {
            "type": "object",
            "description": "Format-dependent. json/ndjson produce structured data; markdown/txt produce text.",
            "properties_json": {
                "chat": {"type": "string"},
                "username": {"type": "string"},
                "is_group": {"type": "boolean"},
                "chat_type": {"type": "string"},
                "time_range": {"type": "string"},
                "export_time": {"type": "string"},
                "count": {"type": "integer"},
                "messages": {"type": "array", "items": {"type": "string"}},
                "failures": {"type": ["array", "null"]},
            },
        },
        "options": {
            "chat_name": {"type": "string", "required": True},
            "format": {"type": "string", "enum": ["markdown", "txt", "json", "ndjson"], "default": "markdown"},
            "output": {"type": "string", "description": "Output file path"},
            "from": {"type": "string", "description": "Start time YYYY-MM-DD [HH:MM[:SS]]"},
            "to": {"type": "string", "description": "End time YYYY-MM-DD [HH:MM[:SS]]"},
            "limit": {"type": "integer", "default": 500},
        },
    },
    "init": {
        "command": "init",
        "description": "Initialize wechat-cli: extract keys and generate config",
        "output": {
            "type": "object",
            "description": "Format-dependent. json produces structured status; text produces human-readable output.",
            "properties_json": {
                "status": {"type": "string", "enum": ["already_initialized", "initialized", "error"]},
                "config": {"type": "string", "description": "Path to config.json"},
                "keys": {"type": "string", "description": "Path to all_keys.json"},
                "db_dir": {"type": "string", "description": "WeChat data directory (on init)"},
                "key_count": {"type": "integer", "description": "Number of extracted keys (on init)"},
                "error": {"type": "string", "description": "Error message (on error)"},
                "hint": {"type": "string", "description": "Suggested fix (on error)"},
            },
        },
        "options": {
            "db-dir": {"type": "string", "description": "WeChat data directory path"},
            "force": {"type": "boolean", "default": False, "description": "Force re-extraction of keys"},
            "format": {"type": "string", "enum": ["text", "json"], "default": "text"},
        },
    },
}


def get_schema(command_name):
    return SCHEMAS.get(command_name)


def output_schema(command_name):
    import json
    import sys
    schema = get_schema(command_name)
    if schema:
        json.dump(schema, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write('\n')

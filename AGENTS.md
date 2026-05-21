# AGENTS.md

Project guide for agents working on `wechat-cli`.

## Scope

`wechat-cli` is a local-first personal WeChat CLI for reading local chat data. Keep the scope on personal WeChat local databases. Do not mix in Enterprise WeChat, public account APIs, or cloud OpenAPI work unless the task explicitly asks for that.

The CLI is agent-oriented: `json` is the default output for query commands and should remain backward compatible.

## Architecture

```text
wechat-cli
  -> wechat_cli.main:cli
  -> wechat_cli.commands.<command>
  -> AppContext
     -> ~/.wechat-cli/config.json
     -> ~/.wechat-cli/all_keys.json
     -> DBCache decrypts DB/WAL on demand
  -> wechat_cli.core query helpers
  -> wechat_cli.output.formatter
```

Key paths:

- `wechat_cli/main.py`: Click root command and subcommand registration.
- `wechat_cli/commands/`: thin command wrappers.
- `wechat_cli/core/`: config, context, crypto, DB cache, contacts, messages.
- `wechat_cli/keys/`: platform-specific key extraction.
- `wechat_cli/output/formatter.py`: shared JSON, NDJSON, table, and text rendering.
- `npm/`: PyInstaller build script and npm wrapper/platform packages.

## Output Contract

Use shared constants from `wechat_cli.output.formatter`:

- Query commands: `json|ndjson|table|text`.
- Export command: `markdown|txt|json|ndjson`.
- Init command: `text|json`.

Rules:

- Preserve `json` as the default for query commands.
- Keep JSON envelopes and existing keys stable unless a breaking change is intentional.
- `ndjson` emits one primary record per line.
- `table` is display-only and may truncate; JSON and NDJSON must not truncate.
- Primary machine-readable output goes to stdout. Progress, warnings, and export success messages go to stderr.
- Never output raw encryption keys.

## Development Guidelines

- Keep command modules thin. Put reusable parsing, query, and formatting behavior in `core/` or `output/`.
- Validate pagination, time ranges, and user inputs before querying.
- Guard dynamic SQL table names with `_is_safe_msg_table_name()`.
- Keep XML parsing defensive; reject unsafe or oversized XML before parsing.
- Runtime state belongs in `~/.wechat-cli` or temp cache directories, never in the repo.
- Be careful with macOS key extraction; it may require Full Disk Access, sudo, and WeChat re-signing.

## Common Commands

```bash
python -m pip install -e .
python entry.py --help
python entry.py sessions --help
python npm/scripts/build.py
```

Runtime commands require an initialized local WeChat environment:

```bash
wechat-cli init
wechat-cli sessions --format table
wechat-cli history "联系人" --format ndjson
wechat-cli export "联系人" --format markdown --output chat.md
```

## Testing Notes

There is no dedicated test suite currently.

- For pure helper changes, run import/compile checks.
- For CLI surface changes, run `python entry.py --help` and changed command help where dependencies are installed.
- For packaging changes, run `python npm/scripts/build.py <platform>` when feasible.
- Do not claim runtime DB behavior is verified unless tested against a real initialized WeChat profile.

## Real Initialized Profile Verification

When the user has already installed the npm package globally and completed `wechat-cli init`, prefer verifying the current source branch against that existing init state instead of rebuilding the global npm package.

The init state is shared across install methods because runtime commands read:

- `~/.wechat-cli/config.json`
- `~/.wechat-cli/all_keys.json`
- `~/.wechat-cli/last_check.json` for `new-messages`

Use the current checkout's Python entry point after installing local Python dependencies:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python entry.py sessions --help
```

Verification order for option flag changes:

```bash
python entry.py sessions --limit 5
python entry.py sessions --is-group true --limit 5
python entry.py sessions --is-group false --limit 5
python entry.py sessions --msg-type text --limit 5
python entry.py sessions --msg-type link --limit 5
python entry.py sessions --chat "聊天名" --limit 5
python entry.py sessions --unread true --limit 5

python entry.py unread --limit 5
python entry.py unread --chat "聊天名" --limit 5
python entry.py unread --is-group true --limit 5
python entry.py unread --msg-type text --limit 5

python entry.py search "关键词" --chat "聊天名" --msg-type text --limit 5
python entry.py search "关键词" --is-group true --unread true --limit 5
python entry.py search "关键词" --msg-type link --limit 5
python entry.py search "关键词" --type text --msg-type link
```

Before testing `new-messages`, back up `~/.wechat-cli/last_check.json` because the command updates incremental state:

```bash
cp ~/.wechat-cli/last_check.json ~/.wechat-cli/last_check.json.bak 2>/dev/null || true
python entry.py new-messages --chat "聊天名"
python entry.py new-messages --is-group true --unread true
python entry.py new-messages --msg-type text
mv ~/.wechat-cli/last_check.json.bak ~/.wechat-cli/last_check.json 2>/dev/null || true
```

Do not include private chat contents in reports. Summarize only exit codes, counts, filter behavior, and whether outputs are valid JSON/NDJSON/table/text.

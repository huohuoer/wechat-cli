<div align="center">

# WeChat CLI

**Query local WeChat data and optionally send group text in the background.**

[![npm version](https://img.shields.io/npm/v/@canghe_ai/wechat-cli.svg)](https://www.npmjs.com/package/@canghe_ai/wechat-cli)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Windows%20%7C%20Linux-lightgrey.svg)](https://github.com/freestylefly/wechat-cli)

Chat history · Contacts · Sessions · Favorites · Statistics · Export · Group send

[中文文档](README_CN.md)

</div>

---

## ✨ Highlights

- **🚀 Zero-config install** — `npm install -g` and you're done, no Python needed
- **📦 12 commands** — all existing query commands plus exact-group background text sending with `send`
- **🤖 AI-first** — JSON output by default, designed for LLM agent tool calls
- **🔒 Local queries** — on-the-fly SQLCipher decryption; queried data stays on your machine
- **📊 Rich analytics** — top senders, message type breakdown, 24-hour activity charts
- **📝 Flexible export** — Markdown or plain text, with time range filtering

---

## 📥 Installation (For Humans)

AI Agents — skip ahead to "Installation (For AI Agents)" below.

### npm (Recommended)

```bash
npm install -g @canghe_ai/wechat-cli
```

> Currently ships a **macOS arm64** binary. Other platforms can use the pip method below. PRs with additional platform binaries are welcome.

**Update to the latest version:**

```bash
npm update -g @canghe_ai/wechat-cli
```

### pip

```bash
pip install wechat-cli
```

Requires Python >= 3.10.

### From Source

```bash
git clone https://github.com/freestylefly/wechat-cli.git
cd wechat-cli
pip install -e .
```

---

## 📥 Installation (For AI Agents)

Simply paste the following prompt into Claude Code, OpenClaw, or any AI coding agent:

```bash
帮我配置并安装：npm install -g @canghe_ai/wechat-cli
```

For example, in Claude Code:

![install-claude-code-1](image/install-claude-code-1.png)

Note: Make sure you have Node.js installed first. You can ask your agent to set it up if needed.

---

## 🚀 Quick Start

### Step 1 — Initialize

Make sure WeChat is running, then:

```bash
# macOS/Linux: may need sudo for memory scanning
sudo wechat-cli init

# Windows: run in a terminal with sufficient privileges
wechat-cli init
```

This auto-detects your WeChat data directory, extracts encryption keys, and saves config to `~/.wechat-cli/`.

![init-claude-code-1](image/init-claude-code-1.png)

On macOS, you'll need to run the `sudo` command and enter your password:

![init-claude-code-2](image/init-claude-code-2.png)

If you have multiple WeChat accounts logged in locally, you'll be prompted to choose one. Select the account you're currently using (the default is the first one):

![init-claude-code-3](image/init-claude-code-3.png)

If you're unsure which WeChat account is currently active, navigate to the data folder and sort by modification date to find out:

![init-claude-code-4](image/init-claude-code-4.png)

#### macOS: Grant Full Disk Access to Terminal

Before running `init`, make sure your terminal app has **Full Disk Access**:

1. Open **System Settings → Privacy & Security → Full Disk Access**
2. Add your terminal app (e.g. Terminal, iTerm2, or the terminal in your IDE)
3. Restart the terminal after enabling

Without this permission, the tool cannot access WeChat's data directory and key extraction will fail.

#### macOS: `task_for_pid failed` Error

On some macOS systems, `init` may fail with `task_for_pid failed` even when running with `sudo`. This is due to macOS security restrictions on process memory access.

**WeChat CLI will automatically attempt to fix this** by re-signing WeChat with the required entitlement (original entitlements are preserved). Just follow the on-screen instructions:

1. The tool will re-sign WeChat automatically
2. Quit WeChat completely (not just minimize)
3. Reopen WeChat and log in
4. Run `sudo wechat-cli init` again

If auto re-signing fails, you can do it manually:

```bash
# Quit WeChat first, then:
sudo codesign --force --sign - --entitlements /dev/stdin /Applications/WeChat.app <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.get-task-allow</key>
    <true/>
    <key>com.apple.security.cs.disable-library-validation</key>
    <true/>
</dict>
</plist>
EOF
```

> Re-signing changes the app signature and may affect auto-update, app features, or account risk controls. Reinstall WeChat from its official site to restore the original app.

### Step 2 — Use It

```bash
wechat-cli sessions                        # Recent chats
wechat-cli history "Alice" --limit 20      # Chat messages
wechat-cli search "deadline" --chat "Team" # Search messages
wechat-cli send "Team" "Hello everyone"    # Background group text
```

---

## 🤖 Using with AI Agents

WeChat CLI is designed as an AI agent tool. All commands output structured JSON by default.

### Claude Code

Add to your project's `CLAUDE.md`:

```markdown
## WeChat CLI

You can use `wechat-cli` to query my local WeChat data.

Common commands:
- `wechat-cli sessions --limit 10` — list recent chats
- `wechat-cli history "NAME" --limit 20 --format text` — read chat history
- `wechat-cli search "KEYWORD" --chat "CHAT_NAME"` — search messages
- `wechat-cli contacts --query "NAME"` — search contacts
- `wechat-cli unread` — show unread sessions
- `wechat-cli new-messages` — get messages since last check
- `wechat-cli members "GROUP"` — list group members
- `wechat-cli stats "CHAT" --format text` — chat statistics
```

Then in conversation you can ask Claude things like:
- "Check my unread WeChat messages"
- "Search for messages about the project deadline in the Team group"
- "Who sent the most messages in the AI group this week?"

### OpenClaw / MCP Integration

WeChat CLI works with any AI tool that can execute shell commands:

```bash
# Get recent conversations
wechat-cli sessions --limit 5

# Read specific chat
wechat-cli history "Alice" --limit 30 --format text

# Search with filters
wechat-cli search "report" --type file --limit 10

# Monitor for new messages (great for cron/automation)
wechat-cli new-messages --format text
```

---

## 📖 Command Reference

### `sessions` — Recent Chats

```bash
wechat-cli sessions                        # Last 20 sessions
wechat-cli sessions --limit 10             # Last 10
wechat-cli sessions --format text          # Human-readable
```

### `history` — Chat Messages

```bash
wechat-cli history "Alice"                 # Last 50 messages
wechat-cli history "Alice" --limit 100 --offset 50
wechat-cli history "Team" --start-time "2026-04-01" --end-time "2026-04-03"
wechat-cli history "Alice" --type link     # Only links
wechat-cli history "Alice" --format text
```

**Options:** `--limit`, `--offset`, `--start-time`, `--end-time`, `--type`, `--format`

### `search` — Search Messages

```bash
wechat-cli search "hello"                  # Global search
wechat-cli search "hello" --chat "Alice"   # In specific chat
wechat-cli search "meeting" --chat "TeamA" --chat "TeamB"  # Multiple chats
wechat-cli search "report" --type file     # Only files
```

**Options:** `--chat` (repeatable), `--start-time`, `--end-time`, `--limit`, `--offset`, `--type`, `--format`

### `contacts` — Contact Search & Details

```bash
wechat-cli contacts --query "Li"           # Search contacts
wechat-cli contacts --detail "Alice"       # Contact details
wechat-cli contacts --detail "wxid_xxx"    # By WeChat ID
```

Returns: nickname, remark, WeChat ID, bio, avatar URL, account type.

### `members` — Group Members

```bash
wechat-cli members "Team Group"            # All members (JSON)
wechat-cli members "Team Group" --format text
```

### `send` — Background Group Text (Experimental)

```bash
wechat-cli send "Exact Unique Group Name" "Message text"
wechat-cli send "54597320555@chatroom" $'Line one\nLine two' --timeout 15 --format json
```

`send` **only sends text messages to group chats**. It does not support direct messages, File Transfer, images, files, voice, video, stickers, or other message types. The group name must be a unique exact match, or a real `@chatroom` ID present in the contact database. Fuzzy names, duplicate group names, forged `@chatroom` IDs, and non-group contacts are rejected before submission.

The send flow is:

1. Strictly verify macOS ARM64, WeChat 4.1.8, process identity, the binary UUID, and pinned function signatures.
2. Capture the target group's local-message baseline, then load a locally authenticated in-process bridge on the first call.
3. On WeChat's main thread, the bridge invokes the pinned official message-task builder and submit chain. It does not focus WeChat, use the input box, or simulate keyboard or mouse input.
4. WeChat performs its normal network submission and writes its own local message record. The CLI never modifies the WeChat database directly; it polls the database read-only, so a confirmed message is visible on both mobile and the current Mac client.
5. Success is returned only after a post-baseline outgoing text row matches the target, sender, and exact text and has a positive `local_id`, positive `server_id`, text type, and sent status.

The default JSON success result includes `success`, `status`, `request_id`, `group`, `username`, `local_id`, and `server_id`. `status: server_accepted` means the local database contains a server-assigned message ID.

| Exit code | Meaning | Retry guidance |
|---|---|---|
| `0` | Server acceptance and Mac-local visibility confirmed | No retry needed |
| `1` | Target is missing, ambiguous, or not a group | Correct the target, then retry |
| `2` | Text or `timeout` is invalid | Correct the input, then retry |
| `3` | Environment, version, permission, or bridge failed before submission | Correct the environment, then retry |
| `4` | Submission boundary was crossed, but the final result is unknown | **Never retry automatically** |

Submission is irreversible. Exit code `4` / `status: unknown` means the action may have happened but could not be confirmed; inspect the target group manually before deciding what to do. Unsupported builds, signing problems, and missing permissions are rejected before submission whenever they can be identified safely.

### `stats` — Chat Statistics

```bash
wechat-cli stats "Team Group"
wechat-cli stats "Alice" --start-time "2026-04-01" --end-time "2026-04-03"
wechat-cli stats "Team Group" --format text
```

Returns: total messages, type breakdown, top 10 senders, 24-hour activity distribution.

### `export` — Export Conversations

```bash
wechat-cli export "Alice" --format markdown              # To stdout
wechat-cli export "Alice" --format txt --output chat.txt  # To file
wechat-cli export "Team" --start-time "2026-04-01" --limit 1000
```

**Options:** `--format markdown|txt`, `--output`, `--start-time`, `--end-time`, `--limit`

### `favorites` — WeChat Bookmarks

```bash
wechat-cli favorites                       # Recent bookmarks
wechat-cli favorites --type article        # Articles only
wechat-cli favorites --query "machine learning"  # Search
```

**Types:** text, image, article, card, video

### `unread` — Unread Sessions

```bash
wechat-cli unread                          # All unread sessions
wechat-cli unread --limit 10 --format text
```

### `new-messages` — Incremental New Messages

```bash
wechat-cli new-messages                    # First: return unread + save state
wechat-cli new-messages                    # Subsequent: only new since last call
```

State saved at `~/.wechat-cli/last_check.json`. Delete to reset.

---

## 🔍 Message Type Filter

The `--type` option (on `history` and `search`):

| Value | Description |
|-------|-------------|
| `text` | Text messages |
| `image` | Images |
| `voice` | Voice messages |
| `video` | Videos |
| `sticker` | Stickers/emojis |
| `location` | Location shares |
| `link` | Links and app messages |
| `file` | File attachments |
| `call` | Voice/video calls |
| `system` | System messages |

---

## 💻 System Requirements

- **macOS** ≥ 26.3.1
- **WeChat for Mac** 4.1.8

> `send` additionally validates a pinned WeChat 4.1.8 binary fingerprint. Other WeChat versions may not be compatible.

---

## 🖥️ Platform Support

| Platform | Status | Notes |
|----------|--------|-------|
| macOS (Apple Silicon) | ✅ Supported | Bundled arm64 binary |
| macOS (Intel) | ✅ Supported | x86_64 binary needed |
| Windows | ✅ Supported | Reads Weixin.exe process memory |
| Linux | ✅ Supported | Reads /proc/pid/mem, requires root |

`send` currently supports macOS ARM64 WeChat 4.1.8 and validates a pinned binary fingerprint at runtime.

---

## 🔧 How It Works

WeChat stores chat data in SQLCipher-encrypted SQLite databases locally. WeChat CLI:

1. **Extracts keys** — scans WeChat process memory for encryption keys (`init`)
2. **Decrypts on-the-fly** — transparent page-level AES-256-CBC decryption with caching
3. **Queries locally** — all data stays on your machine, no network access
4. **Optional background send** — `send` submits group text through the running desktop WeChat process; query commands remain read-only

---

## 📄 License

[Apache License 2.0](LICENSE)

---

## ⚖️ Disclaimer

This project is for personal management of local WeChat data and opt-in group text sending. Please note:

- **Read-only queries** — query commands do not modify WeChat databases; `send` creates a real, irreversible external message
- **Local processing** — queried data is not uploaded to this tool's servers; sent text is submitted normally by the WeChat client
- **Version and account risk** — `send` supports WeChat 4.1.8 with a pinned binary fingerprint and process loading/re-signing, and may crash, stop working, affect updates, or trigger account controls
- **Never retry unknown results** — after a timeout or incomplete receipt, the message may already have been sent
- **Use at your own risk** — this project is for personal learning and research purposes only. Users are responsible for ensuring compliance with local laws and regulations

---

## 🙏 Acknowledgements

This project is built on top of [wechat-decrypt](https://github.com/ylytdeng/wechat-decrypt), which provides the core WeChat database decryption and data parsing capabilities.

---

## ⭐ Star History

[![Star History Chart](https://api.star-history.com/svg?repos=freestylefly/wechat-cli&type=Date)](https://star-history.com/#freestylefly/wechat-cli&Date)

<div align="center">

# WeChat CLI

**命令行查询本地微信数据，专为 AI 集成设计。**

[![npm version](https://img.shields.io/npm/v/@canghe_ai/wechat-cli.svg)](https://www.npmjs.com/package/@canghe_ai/wechat-cli)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Windows%20%7C%20Linux-lightgrey.svg)](https://github.com/freestylefly/wechat-cli)

聊天记录 · 联系人 · 会话 · 收藏 · 统计 · 导出

[English](README.md)

</div>

---

## ✨ 功能亮点

- **🚀 开箱即用** — `npm install -g` 一键安装，无需 Python
- **📦 11 个命令** — sessions、history、search、contacts、members、stats、export、favorites、unread、new-messages、init
- **🤖 AI 优先** — 默认 JSON 输出，专为 LLM Agent 工具调用设计
- **🔒 全程本地** — SQLCipher 即时解密，数据不出本机
- **📊 丰富统计** — 发言排行、消息类型分布、24 小时活跃图
- **📝 灵活导出** — Markdown 或纯文本，支持时间范围过滤

---

## 📥 安装（给人类看）

AI Agent 请直接移步到“安装（给 Agent 看）”

### npm（推荐）

```bash
npm install -g @canghe_ai/wechat-cli
```

> 目前提供 **macOS arm64** 二进制。其他平台可使用下方 pip 安装。欢迎提交其他平台二进制 PR。

**更新到最新版本：**

```bash
npm update -g @canghe_ai/wechat-cli
```

### pip

```bash
pip install wechat-cli
```

需要 Python >= 3.10。

### 从源码安装

```bash
git clone https://github.com/freestylefly/wechat-cli.git
cd wechat-cli
pip install -e .
```

---

## 📥 安装（给 Agent 看）

直接将在你的 Claude Code 或者 OpenClaw 中输入以下提示即可：

```bash
帮我配置并安装：npm install -g @canghe_ai/wechat-cli
```

比如在 Claude Code 中输入：

![install-claude-code-1](image/install-claude-code-1.png)

注意：请先确保有 node.js 环境。没雨可以让你的 cc 安装环境。

## 🚀 快速开始

### 第一步 — 初始化

先执行只读检查；它不会读取微信进程内存：

```bash
wechat-cli doctor
wechat-cli init --dry-run
```

`init` 默认也只显示计划，不再自动扫描进程内存。推荐由经过审计的独立 helper 生成密钥文档，并仅通过标准输入导入：

```bash
trusted-wechat-key-helper | wechat-cli keys import --stdin
```

导入时每个密钥都必须通过对应真实数据库首页的 HMAC 校验，之后才会保存到 `~/.wechat-cli/`。新配置与密钥先写入独立 generation，完整读回后才原子切换。Windows 使用 CurrentUser DPAPI，macOS 使用登录钥匙串，Linux 使用 Secret Service；系统密钥库不可用时默认拒绝写入明文密钥。

内存扫描属于高风险兼容路径，必须同时使用 `--scan-memory --confirm-memory-scan`，并且客户端平台、精确版本、有效发布者签名和扫描算法必须存在于已验收能力清单；未知版本会在申请进程内存读取权限前停止。目前能力清单没有已验收版本，因此不会执行内存扫描。

从旧版本升级且已有 `~/.wechat-cli/all_keys.json` 时，执行 `wechat-cli init --force` 迁移；默认不会继续静默使用旧版明文密钥文件。

![init-claude-code-1](image/init-claude-code-1.png)

macOS/Linux 扫描 helper 请求提权时，系统可能要求输入密码：

![init-claude-code-code-2](image/init-claude-code-2.png)

特别注意，如果你本地有登录微信多个账号，会有多份数据需要你做选择，选择你当前登录的微信账号（默认是第一个）：

![init-claude-code-3](image/init-claude-code-3.png)

这里不确定自己现在的登录微信号，可以找到该文件夹，然后按照修改时间排序，你就可以看到了。（）

![init-claude-code-4](image/init-claude-code-4.png)

#### macOS：提前开启终端的完全磁盘访问权限

在执行 `init` 之前，请确保已为终端开启**完全磁盘访问权限**：

1. 打开 **系统设置 → 隐私与安全性 → 完全磁盘访问权限**
2. 添加你使用的终端应用（如 Terminal、iTerm2 或 IDE 内置终端）
3. 开启后重启终端

未开启此权限会导致工具无法访问微信数据目录，密钥提取将失败。

#### macOS 遇到 `task_for_pid failed` 错误？

在某些 macOS 系统上，即使使用了 `sudo`，`init` 也可能报 `task_for_pid failed`。这是 macOS 的安全策略限制了进程内存访问。

WeChat CLI 会失败关闭并保留原始 `WeChat.app`，不会自动重签、注入或修改第三方应用。调试权限如确有必要，必须由设备管理员独立评估并显式操作。当前仓库内置的 arm64 扫描器是历史产物；在 macOS 上从当前 C 源码重建并通过脱敏产物门禁前，CLI 会拒绝执行它。仓库目前没有 x86_64 产物。

### 第二步 — 开始使用

```bash
wechat-cli sessions                        # 最近会话
wechat-cli history "张三" --limit 20       # 聊天记录
wechat-cli search "截止日期" --chat "项目组" # 搜索消息
```

---

## 🤖 AI 工具集成

WeChat CLI 专为 AI Agent 设计，所有命令默认输出结构化 JSON。

### Claude Code

在项目的 `CLAUDE.md` 中添加：

```markdown
## WeChat CLI

你可以使用 `wechat-cli` 查询我的本地微信数据。

常用命令：
- `wechat-cli sessions --limit 10` — 列出最近会话
- `wechat-cli history "名称" --limit 20 --format text` — 读取聊天记录
- `wechat-cli search "关键词" --chat "聊天名"` — 搜索消息
- `wechat-cli contacts --query "名称"` — 搜索联系人
- `wechat-cli unread` — 显示未读会话
- `wechat-cli new-messages` — 获取上次以来的新消息
- `wechat-cli members "群名"` — 列出群成员
- `wechat-cli stats "聊天名" --format text` — 聊天统计
```

然后在对话中可以直接问 Claude：
- "帮我看看微信有没有未读消息"
- "在项目群里搜索关于截止日期的消息"
- "看看这周 AI 群里谁发言最多？"

### OpenClaw / MCP 集成

WeChat CLI 兼容任何能执行 shell 命令的 AI 工具：

```bash
# 获取最近会话
wechat-cli sessions --limit 5

# 读取指定聊天
wechat-cli history "张三" --limit 30 --format text

# 带过滤条件搜索
wechat-cli search "报告" --type file --limit 10

# 监控新消息（适合定时任务）
wechat-cli new-messages --format text
```

---

## 📖 命令一览

### `sessions` — 最近会话

```bash
wechat-cli sessions                        # 最近 20 个会话
wechat-cli sessions --limit 10             # 最近 10 个
wechat-cli sessions --format text          # 纯文本输出
```

### `history` — 聊天记录

```bash
wechat-cli history "张三"                  # 最近 50 条消息
wechat-cli history "张三" --limit 100 --offset 50
wechat-cli history "交流群" --start-time "2026-04-01" --end-time "2026-04-03"
wechat-cli history "张三" --type link      # 只看链接
wechat-cli history "张三" --format text
```

**选项：** `--limit`、`--offset`、`--start-time`、`--end-time`、`--type`、`--format`

### `search` — 搜索消息

```bash
wechat-cli search "Claude"                 # 全局搜索
wechat-cli search "Claude" --chat "交流群"  # 指定聊天搜索
wechat-cli search "开会" --chat "群A" --chat "群B"  # 多个聊天
wechat-cli search "报告" --type file        # 只搜文件
```

**选项：** `--chat`（可多次指定）、`--start-time`、`--end-time`、`--limit`、`--offset`、`--type`、`--format`

### `contacts` — 联系人搜索与详情

```bash
wechat-cli contacts --query "李"           # 搜索联系人
wechat-cli contacts --detail "张三"        # 查看详情
wechat-cli contacts --detail "wxid_xxx"    # 通过 wxid 查看
```

详情包括：昵称、备注、微信号、个性签名、头像 URL、账号类型。

### `members` — 群成员列表

```bash
wechat-cli members "AI交流群"              # 成员列表
wechat-cli members "AI交流群" --format text
```

### `stats` — 聊天统计

```bash
wechat-cli stats "AI交流群"
wechat-cli stats "张三" --start-time "2026-04-01" --end-time "2026-04-03"
wechat-cli stats "AI交流群" --format text
```

返回：消息总数、类型分布、发言 Top 10、24 小时活跃分布。

### `export` — 导出聊天记录

```bash
wechat-cli export "张三" --format markdown              # 输出到 stdout
wechat-cli export "张三" --format txt --output chat.txt  # 输出到文件
wechat-cli export "群聊" --start-time "2026-04-01" --limit 1000
```

**选项：** `--format markdown|txt`、`--output`、`--start-time`、`--end-time`、`--limit`

### `favorites` — 微信收藏

```bash
wechat-cli favorites                       # 最近收藏
wechat-cli favorites --type article        # 只看文章
wechat-cli favorites --query "计算机网络"    # 搜索收藏
```

**类型：** text、image、article、card、video

### `unread` — 未读会话

```bash
wechat-cli unread                          # 所有未读会话
wechat-cli unread --limit 10 --format text
```

### `new-messages` — 增量新消息

```bash
wechat-cli new-messages                    # 首次: 返回未读消息 + 保存状态
wechat-cli new-messages                    # 后续: 仅返回上次以来的新消息
```

状态保存在 `~/.wechat-cli/last_check.json`，删除此文件可重置。

---

## 🔍 消息类型过滤

`--type` 选项（适用于 `history` 和 `search`）：

| 值 | 说明 |
|---|------|
| `text` | 文本消息 |
| `image` | 图片 |
| `voice` | 语音 |
| `video` | 视频 |
| `sticker` | 表情 |
| `location` | 位置 |
| `link` | 链接/应用消息 |
| `file` | 文件 |
| `call` | 音视频通话 |
| `system` | 系统消息 |

---

## 💻 系统要求

- **macOS** ≥ 26.3.1
- **微信 Mac 版** ≤ 4.1.8.100

> macOS 老版本或更新的微信版本可能不兼容。

---

## 🖥️ 平台支持

| 平台 | 状态 | 说明 |
|------|------|------|
| macOS (Apple Silicon) | ⚠️ 需重建 | 历史 arm64 产物被安全门禁拒绝，须从当前源码重建 |
| macOS (Intel) | ❌ 未提供 | 仓库没有 x86_64 二进制 |
| Windows | ⚠️ 查询/导入可用 | 内存扫描须命中已验收的精确版本能力清单 |
| Linux | ⚠️ 查询/导入可用 | 内存扫描须命中已验收的精确版本能力清单 |

---

## 🔧 工作原理

微信将聊天数据存储在本地的 SQLCipher 加密 SQLite 数据库中。WeChat CLI：

1. **受控取得密钥** — 默认使用受信 helper 标准输入导入并以真实数据库页校验；内存扫描仅限已验收版本
2. **即时解密** — 透明页级 AES-256-CBC 解密；解密缓存只存于本次进程的私有目录，正常退出时删除
3. **本地查询** — 所有数据留在本机，无需网络访问

### 密钥与缓存安全边界

- 初始化结果保存在 `~/.wechat-cli/generations/<id>/`，`active.json` 只在配置与密钥全部读回成功后切换。
- `doctor`、`init --dry-run` 和默认 `init` 不会读取微信进程内存；未知客户端版本在申请进程内存读取权限前失败关闭。
- 初始化和扫描日志只显示匹配状态、数据库路径和密钥数量，不回显完整密钥。
- Windows 使用 CurrentUser DPAPI 并显式收紧 NTFS ACL；macOS 使用登录钥匙串；Linux 使用 Secret Service。若系统密钥库不可用，默认失败关闭。仅可通过 `WECHAT_CLI_ALLOW_PLAINTEXT_KEYS=1` 显式启用兼容明文文件后端。
- 解密前先复制稳定的 DB/WAL 快照；SQLCipher 页 HMAC、SQLite WAL checksum 与最后提交帧均通过后才应用。明文缓存位于带独占租约的 `cache/run-*`；启动时只清理确认无人持锁的规范遗留目录。

---

## 📄 开源协议

[Apache License 2.0](LICENSE)

---

## ⚖️ 免责声明

本项目为个人使用的本地数据查询工具，请注意：

- **只读不写** — 本工具仅读取本地存储的数据，不会发送、修改或删除任何消息
- **数据不出本机** — 所有数据仅在你本机处理，不会上传至任何云端服务器
- **不破坏微信生态** — 本工具不会干扰微信正常运行，不会自动化任何操作，不违反微信使用协议
- **风险自担** — 本项目仅供个人学习研究使用，使用者需确保遵守当地法律法规

---

## 🙏 致谢

本项目基于 [wechat-decrypt](https://github.com/ylytdeng/wechat-decrypt) 开发，该仓库提供了微信数据库解密和数据解析的核心能力。

---

## ⭐ Star History

[![Star History Chart](https://api.star-history.com/svg?repos=freestylefly/wechat-cli&type=Date)](https://star-history.com/#freestylefly/wechat-cli&Date)

<div align="center">

# WeChat CLI

**命令行查询本地微信数据，专为 AI 集成设计。**

[![npm 版本](https://img.shields.io/npm/v/@canghe_ai/wechat-cli.svg)](https://www.npmjs.com/package/@canghe_ai/wechat-cli)
[![开源协议：Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![平台](https://img.shields.io/badge/platform-macOS%20%7C%20Windows%20%7C%20Linux-lightgrey.svg)](https://github.com/freestylefly/wechat-cli)

聊天记录 · 联系人 · 会话 · 收藏 · 统计 · 导出

[同内容中文副本](README_CN.md)；本文件为中文主文档。

</div>

---

## ✨ 功能亮点

- **🚀 开箱即用** — `npm install -g` 一键安装，无需 Python
- **📦 11 个命令** — sessions、history、search、contacts、members、stats、export、favorites、unread、new-messages、init
- **🤖 AI 优先** — 默认 JSON 输出，专为 LLM Agent 工具调用设计
- **🔒 本地查询** — SQLCipher 即时解密；查询路径不主动上传，AI 集成和输出转发需自行审查隐私风险
- **📊 丰富统计** — 发言排行、消息类型分布、24 小时活跃图
- **📝 灵活导出** — Markdown 或纯文本，支持时间范围过滤

---

## 📥 安装（给人类看）

AI Agent 请直接移步到“安装（给 Agent 看）”

`pyproject.toml` 与 npm 包配置的工作区版本为 **0.3.0，尚未发布**。下述新密钥流程对应当前源码，不能假定 npm 或 PyPI 已发布包包含这些功能；顶部版本徽章反映注册表版本，而非工作区发布状态。

需要 **Python >= 3.10**。在仓库目录使用虚拟环境，避免将系统 Python 或旧版全局命令误当作当前版本：

```bash
git clone https://github.com/freestylefly/wechat-cli.git
cd wechat-cli
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
wechat-cli --version
```

请先确认 `python3 --version` 满足要求；Windows 使用对应虚拟环境的激活方式（如 PowerShell 的 `.venv\Scripts\Activate.ps1`）。

### 已发布包安装与更新

以下命令安装注册表中的已发布版本，不代表安装当前尚未发布的 0.3.0：

```bash
npm install -g @canghe_ai/wechat-cli
npm update -g @canghe_ai/wechat-cli

# 使用满足版本要求的 Python 环境
python -m pip install wechat-cli
```

npm 需要 Node.js >= 14。`optionalDependencies` 声明了 `darwin-arm64`、`darwin-x64`、`linux-arm64`、`linux-x64`、`win32-x64` 五个平台包，**不代表五个平台二进制均已构建或发布**，也不代表密钥提取已在全部平台验证。

`npm/scripts/build.py` 使用 PyInstaller **只构建当前主机平台与架构**，不交叉编译。构建需在各目标主机安装构建依赖：

```bash
python -m pip install -e '.[build]'
python npm/scripts/build.py
```

构建仅捆绑源码与配置，不复用旧预编译 macOS helper；macOS helper 的编译签名须单独显式授权。

---

## 📥 安装（给 Agent 看）

直接将在你的 Claude Code 或者 OpenClaw 中输入以下提示即可：

```text
请在仓库内使用 Python >= 3.10 创建虚拟环境并执行 python -m pip install -e .。
只运行只读诊断；未经我明确授权，不要读取微信内存、编译签名 helper 或保存密钥。
不要重签、复制、启动或重启官方微信，也不要关闭 SIP。
```

下图保留作为 AI 工具安装交互示意，其中旧安装命令不代表当前工作区版本已发布：

![AI 工具安装交互示意](image/install-claude-code-1.png)

## 🚀 快速开始

### 第一步 — 初始化

确保微信正在运行，然后：

```bash
# macOS/Linux: 可能需要 sudo 权限
sudo wechat-cli init

# Windows: 在有足够权限的终端中运行
wechat-cli init
wechat-cli keys check

# 明确导入已有有效密钥；这是旧工具路径示例，不是自动导入
wechat-cli init --keys ~/.wx-cli/all_keys.json

# 目标密钥已经存在时，明确允许替换并安全备份
wechat-cli init --keys ~/.wx-cli/all_keys.json --force
```

默认状态目录为 `~/.wechat-cli/`，配置为 `config.json`，密钥为 `all_keys.json`。导入会验证当前数据库首页 HMAC；无有效密钥或存在无效密钥时拒绝覆盖。已有目标需 `--force`，旧配置与密钥保存为对应 `.bak`，采用私有临时文件与原子替换；`--force` 不触发提取。

可通过全局 `--config`（须放在子命令之前）或 `WECHAT_CLI_CONFIG` 指定配置，通过 `--db-dir` 指定账号的 `db_storage`：

```bash
wechat-cli --config ~/.wechat-cli/config.json init --db-dir "/你的账号路径/db_storage"
wechat-cli keys check --db-dir "/你的账号路径/db_storage" --keys ~/.wx-cli/all_keys.json
```

多个账号必须明确选择；交互终端会提示选择，非交互环境须传入 `--db-dir`，不会默认选择第一个账号。目录修改时间可辅助辨认，但不应据此保证当前登录身份。

以下图片保留为旧界面的初始化交互、账号选择与目录定位示意；旧提示中的自动提取或提权流程不适用于当前版本：

![初始化交互示意](image/init-claude-code-1.png)

![多账号选择示意](image/init-claude-code-3.png)

![数据目录定位示意](image/init-claude-code-4.png)

#### macOS：磁盘访问与内存访问是两类权限

若终端无法读取微信数据目录，请检查 **系统设置 → 隐私与安全性 → 完全磁盘访问权限**，按需授权实际使用的终端应用（Terminal、iTerm2 或 IDE）。此权限**不等于**获取进程内存访问权限。

`task_for_pid` 仍可能被 **SIP、AMFI 或用户权限**拒绝，即使自己的 helper 签名验证通过且 `debugger: true`。权限拒绝不是自动绕过的理由：工具不会自动重签官方微信、关闭 SIP、启动或重启微信。

### 可选步骤 — 明确授权密钥诊断与提取

已有可用密钥优先导入，不必执行此步骤。只有提取或内存探针需要微信进程已经运行；工具不会替你启动、登录或重启。

```bash
# 只读检查覆盖计数与平台能力，不读取进程内存或创建解密缓存
wechat-cli keys check

# 仅 macOS：显式编译并签名本工具自己的新 helper Bundle，不运行探针
wechat-cli keys prepare --allow-helper-build

# 显式授权探针；只输出聚合诊断，不收集候选密钥
wechat-cli keys probe --allow-memory-read

# 显式授权提取；仅在内存中提取并验证，未加 --save 不落盘保存密钥或配置
wechat-cli keys extract --allow-memory-read --method auto

# 验证后明确保存有效密钥并更新配置；已有文件先安全备份
wechat-cli keys extract --allow-memory-read --method auto --save
```

- `keys prepare --allow-helper-build` 需要 **Xcode 命令行工具**（`xcrun clang` 与系统 `codesign`），只编译签名本工具自己的新 Bundle，不复制或重签微信，不运行探针。
- `keys probe --allow-memory-read` 在 macOS 返回数据库/内存聚合计数与签名诊断；Windows/Linux 仅检测只读内存访问权限及区域计数。各平台均不收集、返回或保存候选密钥。
- `keys extract` 需要 `--allow-memory-read`；默认只在内存中提取并进行数据库首页 HMAC 验证，输出覆盖计数而非原始密钥。只有 `--save` 才写密钥及配置，并备份已有文件；无有效结果或发现无效候选时不保存。
- `extract` 支持 `--db-dir`、`--pid`、`--method`、`--timeout`、`--allow-memory-read`、`--save`；`probe` 支持 `--db-dir`、`--pid`、`--allow-memory-read`。`--timeout` 默认 120 秒，允许 1–600 秒，**仅限制 macOS helper 和 Linux GDB 等待，不限制 Windows 扫描或 Linux 传统扫描**。
- `--method frida` 虽保留在命令选项中，但当前明确拒绝执行：独立副本的数据库写入隔离与安全路由尚未验证，为保护官方数据库不支持 Frida。可选依赖存在不代表此流程可用。

**微信升级、退出后重新登录或切换账号后，旧密钥可能失效。请先运行 `wechat-cli keys check`，根据覆盖与 HMAC 结果再决定重新导入或显式提取；不能保证旧配置和密钥继续可用。**

### 第二步 — 开始使用

```bash
wechat-cli sessions                        # 最近会话
wechat-cli history "张三" --limit 20       # 聊天记录
wechat-cli search "截止日期" --chat "项目组" # 搜索消息
```

---

## 🤖 AI 工具集成

WeChat CLI 面向 AI 工具集成，查询与诊断通常默认输出结构化 JSON；`export` 使用 Markdown 或纯文本导出。

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

WeChat CLI 可由能执行命令行的 AI 工具调用：

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

返回：消息总数、类型分布、发言前 10 名、24 小时活跃分布。

### `export` — 导出聊天记录

```bash
wechat-cli export "张三" --format markdown              # 输出到标准输出
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

**类型：** `text`（文本）、`image`（图片）、`article`（文章）、`card`（卡片）、`video`（视频）

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

## 💻 系统要求与平台边界

- 源码查询需要 Python >= 3.10、可读取的本地数据库及通过验证的密钥。读取加密数据库和内存的系统权限须分别满足。
- macOS helper 支持 `arm64`、`x86_64` 构建；Windows 扫描需要 64 位 Windows Python。实现存在不等于全部微信/系统版本兼容。
- 历史环境记录包括 macOS 26.3.1、微信 Mac 版 4.1.8.100，**不是最低/最高兼容版本保证**。当前版本的提取能力受微信内存布局、架构与系统安全策略影响。

| 平台 | 显式提取方法 | 限制 |
|------|--------------|------|
| macOS（Apple Silicon / Intel） | `auto` / `config` | 两者使用自己的 helper 读取配置候选并验证；需先显式构建，`task_for_pid` 可能被拒绝，不自动重签或重启 |
| Windows（64 位） | `auto` / `config` / `legacy` | `config` 扫描配置；`auto` 先配置扫描，未覆盖部分回退传统 `legacy`；`legacy` 仅传统扫描，`--timeout` 不作用于 Windows |
| Linux | `auto` / `legacy` / `gdb` | `auto` 等同传统 `legacy`，读取 `/proc/<pid>/mem`，不会自动调用 ptrace/GDB；仅显式 `gdb` 附加捕获，**GDB 当前仅支持 x86_64，不支持 ARM64 参数布局** |

Linux 权限以实际打开结果为准，不是一律要求 root；工具不自动调整 ptrace 策略或权限。显式 GDB 需要已安装 GDB 与附加权限，会临时附加并暂停目标，通过断点等待登录期密钥计算。若需触发重新登录，由使用者自行操作，不会自动退出登录、登录或启动微信：

```bash
# Linux：明确选择传统扫描
wechat-cli keys extract --allow-memory-read --method legacy

# 仅 Linux x86_64：明确授权 GDB，默认仍不保存密钥
wechat-cli keys extract --allow-memory-read --method gdb --timeout 120
```

npm 的 `linux-arm64` 包声明不能作为 ARM64 GDB 可用的依据，也不能作为该平台二进制已发布或实机验证通过的依据。

---

## 🔧 工作原理

微信将聊天数据存储在本地的 SQLCipher 加密 SQLite 数据库中。WeChat CLI：

1. **验证或获取密钥** — `init` / `keys check` 默认只读验证；明确 `--keys` 导入，或授权 `keys extract --allow-memory-read`，再以 `--save` 决定是否保存。
2. **即时解密** — 校验并执行页级 AES-256-CBC 解密，缓存位于 `~/.cache/wechat-cli/`，按账号数据库目录与密钥集隔离命名空间，再按每库身份校验，避免跨账号/密钥复用。
3. **处理 WAL** — 校验 WAL 头部与帧的滚动校验和，只应用最后提交边界之前的已提交帧，按提交页数截断；无效或变化中的数据库/WAL 不作为可信缓存发布。
4. **本地查询** — 查询与解密不需要上传数据；会写本工具的解密缓存、状态文件及显式指定的导出文件，不能把“读取源数据库”理解为整个工具零写入。

### 敏感文件

密钥、备份和明文缓存均应视为敏感数据，不要提交仓库或发送给 AI 服务。私有保存使用文件权限 `600`、新建目录 `700`；缓存目录收紧为 `700`，缓存文件为 `600`。Windows 密钥/配置保存使用 `icacls` 移除继承 ACL 并授予当前登录身份权限，不能只依赖 POSIX 权限数字判断安全。已有状态目录、其他状态文件和导出文件仍需自行检查访问控制，并妥善管理备份与明文缓存。

---

## 回归与验证范围

安装当前源码与依赖后可运行：

```bash
python -m unittest discover -s tests -v
```

当前测试源码包含 **99 个测试项**，主要使用合成数据库/内存数据与模拟（mock），覆盖命令授权、平台路由、密钥验证、缓存和 WAL 等边界；测试项数量或通过结果**不代表全部平台与微信版本兼容**。

### 2026-10-14 macOS 实机验证

验证环境：**macOS 26.6（25G72）、Apple Silicon arm64、微信 4.1.15（270102）**。直接执行本仓库源码，不调用外部 `wx`、旧预编译 helper 或 `/tmp/wechat4mac`。

| 验证项 | 实际结果 |
|--------|----------|
| 独立 helper 编译与签名 | `keys prepare --allow-helper-build` 成功；签名验证通过，`debugger: true` |
| 实际内存探针 | `task_port: true`、`scan_complete: true`；发现 54 个 XOR hex 模式，传统明文 hex 模式为 0；不收集候选密钥 |
| 实际密钥提取 | `keys extract --method config --allow-memory-read --timeout 120` 成功，**22/22 个数据库首页 HMAC 验证通过**，无缺失或无效项，`saved: false` |
| 微信退出与重新打开 | AppleScript 退出请求返回“用户已取消”（错误 -128），但后续检查确认原进程已退出；未强制终止，随后正常重新打开微信并确认新进程 |
| 重新打开后内存提取 | 对新进程再次执行无落盘 `config` 提取，约 72 秒完成，**22/22 个数据库首页 HMAC 验证通过**，`saved: false`；已有密钥只读检查也为 22/22 |
| 回归测试 | **99 项全部通过**；仍以合成/mock 边界测试为主 |

重启前探针与提取两步合计约 127 秒，重新打开后的提取约 72 秒。候选仅通过匿名通道传递，不输出原始密钥、不使用 `--save`，未调用聊天查询或直接修改源数据库。测试后微信二进制摘要与严格签名验证结果不变，现有配置和两份密钥文件摘要不变，探针子进程已回收。工具仅编译并签名自己的 helper，不对微信 App 重新签名；微信自身的正常运行仍会更新数据库。

**重要限制：本机微信在测试前就已有 ad-hoc 签名、`get-task-allow: true` 且未开启 App Sandbox；SIP 保持启用。这不是原始官方签名微信的内存权限验证，也不能推导出所有 4.x 版本可提取。** 原始官方签名环境仍可能被系统拒绝；Windows/Linux 本轮未进行实机提取。已有密钥 22/22 验证通过与本轮独立内存提取成功是两项不同证据，不代表所有消息内容、系统版本或账号都已验证。

---

## 📄 开源协议

[Apache 2.0 开源协议](LICENSE)

---

## ⚖️ 免责声明

本项目为个人使用的本地数据查询工具，请注意：

- **只读不写** — 本工具仅读取本地存储的数据，不会发送、修改或删除任何消息
- **数据不出本机** — 所有数据仅在你本机处理，不会上传至任何云端服务器
- **不破坏微信生态** — 本工具不会干扰微信正常运行，不会自动化任何操作，不违反微信使用协议
- **操作边界** — 查询路径以读取本地源数据库为目标，不提供消息发送、修改或删除功能，但不作“任何情况下绝不修改消息”的绝对保证。本工具会写自身配置、密钥（显式保存）、备份、缓存、增量状态及导出文件；显式 GDB 会临时暂停微信进程，不能保证完全不影响运行。
- **本地处理与外部集成** — 查询/解密路径本地处理数据，不主动上传；安装下载、徽章/图片加载以及 AI 工具或使用者转发输出可能涉及网络与第三方服务，应自行审查隐私风险。
- **尊重系统保护** — 不自动重签官方微信、关闭 SIP 或重启微信；当前不支持未验证隔离与路由的 Frida 独立副本流程，不将权限拒绝视为绕过授权的依据。
- **法律与账号风险自担** — 仅对自己有权访问的数据使用本工具，并自行确认符合当地法律、隐私要求及微信相关协议。本项目不保证账号安全、不保证不会封号，也不承诺所有平台和微信版本均可用。

---

## 🙏 致谢

本项目基于 [wechat-decrypt](https://github.com/ylytdeng/wechat-decrypt) 开发，该仓库提供了微信数据库解密和数据解析的核心能力。

微信 4.x 密钥获取参考 [wechat4mac](https://github.com/444167838yhq-gif/wechat4mac) 的签名探针和配置候选验证，以及 [wcdb-key-tool](https://github.com/TANGandXUE/wcdb-key-tool) 的 Linux 捕获与派生逻辑；相关移植源码保留原许可声明。另研究了 [wechat4-macos-frida-export](https://github.com/TimFang4162/wechat4-macos-frida-export) 的 Gadget 方案，但本项目未启用未验证的数据写入隔离流程。

---

## ⭐ 星标历史

[![星标历史图](https://api.star-history.com/svg?repos=freestylefly/wechat-cli&type=Date)](https://star-history.com/#freestylefly/wechat-cli&Date)

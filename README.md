# WeChat 4.0 Database Decryptor

微信 4.0 (Windows) 本地数据库解密工具。从运行中的微信进程内存提取加密密钥，解密所有 SQLCipher 4 加密数据库，并提供实时消息监听。

## 更新日志

### 2025-03-03 — 富媒体内容 & 组合消息修复

- **表情包内联显示**: 自动从 emoticon.db 构建 MD5→CDN 映射，支持自定义表情（NonStore）和商店表情（Store），CDN 下载后本地缓存
- **富媒体内容解析**: 链接卡片（type 49）、文件、视频号、小程序、引用回复、位置分享等在 Web UI 中完整渲染
- **文字+图片组合消息不再丢失**: 修复同时发送文字和图片时只显示最后一条的问题（前端去重 key 增加消息类型）
- **隐藏消息检测**: 新增 `_check_hidden_messages` 机制，session.db 只保存最后一条消息摘要，现在会异步查 message DB 找回同一秒内的其他消息
- **MonitorDBCache 线程安全**: 引入 per-key 锁，防止多线程并发解密同一数据库导致文件损坏
- **Web UI 改进**: 消息气泡样式优化、群聊发送者显示、图片缩略图点击放大

## 原理

微信 4.0 使用 SQLCipher 4 加密本地数据库：
- **加密算法**: AES-256-CBC + HMAC-SHA512
- **KDF**: PBKDF2-HMAC-SHA512, 256,000 iterations
- **页面大小**: 4096 bytes, reserve = 80 (IV 16 + HMAC 64)
- **每个数据库有独立的 salt 和 enc_key**

WCDB (微信的 SQLCipher 封装) 会在进程内存中缓存派生后的 raw key，格式为 `x'<64hex_enc_key><32hex_salt>'`。本工具通过扫描进程内存中的这种模式，匹配数据库文件的 salt，并通过 HMAC 验证来提取正确的密钥。

## 使用方法

### 环境要求

- Windows 10/11
- Python 3.10+
- 微信 4.0 (正在运行)
- 需要管理员权限 (读取进程内存)

### 安装依赖

```bash
pip install pycryptodome
```

### 1. 配置

复制配置模板并修改：

```bash
copy config.example.json config.json
```

编辑 `config.json`：
```json
{
    "db_dir": "D:\\xwechat_files\\你的微信ID\\db_storage",
    "keys_file": "all_keys.json",
    "decrypted_dir": "decrypted",
    "wechat_process": "Weixin.exe"
}
```

`db_dir` 路径可以在 微信设置 → 文件管理 中找到。

### 2. 提取密钥

确保微信正在运行，以**管理员权限**运行：

```bash
python find_all_keys.py
```

密钥将保存到 `all_keys.json`。

### 3. 解密数据库

```bash
python decrypt_db.py
```

解密后的数据库保存在 `decrypted/` 目录，可以直接用 SQLite 工具打开。

### 4. 实时消息监听

#### Web UI (推荐)

```bash
python monitor_web.py
```

打开 http://localhost:5678 查看实时消息流。

- 30ms 轮询 WAL 文件变化 (mtime)
- 检测到变化后全量解密 + WAL patch (~70ms)
- SSE 实时推送到浏览器
- 总延迟约 100ms
- **图片消息内联预览**（支持旧 XOR / V1 / V2 三种 .dat 加密格式）

#### 命令行

```bash
python monitor.py
```

每 3 秒轮询一次，在终端显示新消息。

### 5. MCP Server (Claude AI 集成)

将微信数据查询能力接入 [Claude Code](https://claude.ai/claude-code)，让 AI 直接读取你的微信消息。

```bash
pip install mcp
```

注册到 Claude Code：

```bash
claude mcp add wechat -- python C:\Users\你的用户名\wechat-decrypt\mcp_server.py
```

或手动编辑 `~/.claude.json`：

```json
{
  "mcpServers": {
    "wechat": {
      "type": "stdio",
      "command": "python",
      "args": ["C:\\Users\\你的用户名\\wechat-decrypt\\mcp_server.py"]
    }
  }
}
```

注册后在 Claude Code 中即可使用以下工具：

| Tool | 功能 |
|------|------|
| `get_recent_sessions(limit)` | 最近会话列表（含消息摘要、未读数） |
| `get_chat_history(chat_name, limit)` | 指定聊天的消息记录（支持模糊匹配名字） |
| `search_messages(keyword, limit)` | 全库搜索消息内容 |
| `get_contacts(query, limit)` | 搜索/列出联系人 |
| `get_new_messages()` | 获取自上次调用以来的新消息 |

前置条件：需要先完成步骤 1-2（配置 + 提取密钥）。

**[查看使用案例 →](USAGE.md)**

### 6. 图片解密 (V2 格式)

微信 4.0 (2025-08+) 的 .dat 图片文件使用 AES-128-ECB + XOR 混合加密 (V2 格式)。AES 密钥需要从运行中的微信进程内存中提取：

```bash
# 1. 在微信中打开查看 2-3 张图片（点击看大图）
# 2. 立即运行密钥提取（持续监控版）：
python find_image_key_monitor.py

# 或单次扫描版：
python find_image_key.py
```

密钥会自动保存到 `config.json` 的 `image_aes_key` 字段。之后 `monitor_web.py` 启动时会自动加载密钥，图片消息将显示内联预览。

> **注意**: AES 密钥仅在微信查看图片时临时加载到内存中。如果扫描未找到密钥，请先在微信中查看几张图片，然后立即重新运行脚本。

### 7. 历史图片覆盖 Round（open_tasks / report round）

使用统一入口创建一轮覆盖工件：

```bash
python -m tools.image_coverage.run_round --dry-run
python -m tools.image_coverage.run_round
```

每次执行都会在 `work/image_coverage/round-YYYYMMDD-HHMM`（同分钟自动加 `-01`、`-02`）生成：

- `open_tasks.md`：本轮需要在微信里打开的目标任务清单
- `report.md`：本轮 report round 记录（包含 dry_run 标记和 round_dir）

推荐流程：

1. 先执行 dry-run，确认 round 目录和 `open_tasks.md` 已生成
2. 按 `open_tasks.md` 在微信中逐项打开图片并抓取 key
3. 执行正式 round，再更新本轮 `report.md` 结论并进入下一轮

## 文件说明

| 文件 | 说明 |
|------|------|
| `config.py` | 配置加载器 |
| `find_all_keys.py` | 从微信进程内存提取所有数据库密钥 |
| `decrypt_db.py` | 全量解密所有数据库 |
| `mcp_server.py` | MCP Server，让 Claude AI 查询微信数据 |
| `monitor_web.py` | 实时消息监听 (Web UI + SSE + 图片预览) |
| `monitor.py` | 实时消息监听 (命令行) |
| `decode_image.py` | 图片 .dat 文件解密模块 (XOR / V1 / V2) |
| `find_image_key.py` | 从微信进程内存提取图片 AES 密钥 |
| `find_image_key_monitor.py` | 持续监控版密钥提取（推荐） |
| `latency_test.py` | 延迟测量诊断工具 |

## 技术细节

### WAL 处理

微信使用 SQLite WAL 模式，WAL 文件是**预分配固定大小** (4MB)。检测变化时：
- 不能用文件大小 (永远不变)
- 使用 mtime 检测写入
- 解密 WAL frame 时需校验 salt 值，跳过旧周期遗留的 frame

### 图片 .dat 加密格式

微信本地图片 (.dat) 有三种加密格式：

| 格式 | 时期 | Magic | 加密方式 | 密钥来源 |
|------|------|-------|---------|---------|
| 旧 XOR | ~2025-07 | 无 | 单字节 XOR | 自动检测 (对比 magic bytes) |
| V1 | 过渡期 | `07 08 V1 08 07` | AES-ECB + XOR | 固定 key: `cfcd208495d565ef` |
| V2 | 2025-08+ | `07 08 V2 08 07` | AES-128-ECB + XOR | 从进程内存提取 |

V2 文件结构: `[6B signature] [4B aes_size LE] [4B xor_size LE] [1B padding]` + `[AES-ECB encrypted] [raw unencrypted] [XOR encrypted]`

### 数据库结构

解密后包含约 26 个数据库：
- `session/session.db` - 会话列表 (最新消息摘要)
- `message/message_*.db` - 聊天记录
- `contact/contact.db` - 联系人
- `media_*/media_*.db` - 媒体文件索引
- 其他: head_image, favorite, sns, emoticon 等

## 免责声明

本工具仅用于学习和研究目的，用于解密**自己的**微信数据。请遵守相关法律法规，不要用于未经授权的数据访问。

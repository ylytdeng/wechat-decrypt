# WeChat 4.x Database Decryptor

微信 4.0 (Windows、MacOS、Linux) 本地数据库解密工具。从运行中的微信进程内存提取加密密钥，解密所有 SQLCipher 4 加密数据库，并提供实时消息监听。

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

WCDB (微信的 SQLCipher 封装) 会在进程内存中缓存派生后的 raw key，格式为 `x'<64hex_enc_key><32hex_salt>'`。三个平台（Windows / Linux / macOS）均可通过扫描进程内存匹配此模式，再通过 HMAC 校验 page 1 确认密钥正确性。

## 使用方法

### 环境要求

- Python 3.10+
- 微信 4.x
- `pip install pycryptodome`

Windows：

- Windows 10/11
- 微信正在运行
- 需要管理员权限（读取进程内存）

Linux：

- 64-bit Linux
- 需要 root 权限或 `CAP_SYS_PTRACE`（读取 `/proc/<pid>/mem`）
- `db_dir` 默认类似 `~/Documents/xwechat_files/<wxid>/db_storage`

### 安装依赖

### 快速开始

Windows：

```bash
python main.py
python main.py decrypt
```

Linux：

```bash
python3 main.py decrypt
```

程序会自动完成：配置检测 → 内存扫描提取密钥 → 解密。首次运行会自动检测微信数据目录并生成 `config.json`。微信只要在运行中即可，无需重启或重新登录。

如果自动检测失败（例如微信安装在非默认位置），手动创建 `config.json`：
```json
{
    "db_dir": "D:\\xwechat_files\\你的微信ID\\db_storage",
    "keys_file": "all_keys.json",
    "decrypted_dir": "decrypted",
    "wechat_process": "Weixin.exe"
}
```

Linux 版 `config.json` 示例：

```json
{
    "db_dir": "/home/yourname/Documents/xwechat_files/your_wxid/db_storage",
    "keys_file": "all_keys.json",
    "decrypted_dir": "decrypted",
    "wechat_process": "wechat"
}
```

`db_dir` 路径：Windows 可在微信设置 → 文件管理中找到；Linux 默认在 `~/Documents/xwechat_files/<wxid>/db_storage`。

### Web UI 说明

`python main.py` 启动后打开 http://localhost:5678 查看实时消息流。

- 30ms 轮询 WAL 文件变化 (mtime)
- 检测到变化后全量解密 + WAL patch (~70ms)
- SSE 实时推送到浏览器
- 总延迟约 100ms
- **图片消息内联预览**（支持旧 XOR / V1 / V2 三种 .dat 加密格式）

### MCP Server (Claude AI 集成)

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

前置条件：需要先运行 `python main.py` 或 `python find_all_keys.py` 完成密钥提取。

**[查看使用案例 →](USAGE.md)**

### 图片解密 (V2 格式)

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

## 文件说明

| 文件 | 说明 |
|------|------|
| `main.py` | **一键启动入口** — 自动配置、提取密钥、启动服务 |
| `config.py` | 配置加载器（自动检测微信数据目录） |
| `find_all_keys.py` | 平台分发入口（Windows / Linux） |
| `find_all_keys_windows.py` | Windows 版内存扫描提 key |
| `find_all_keys_linux.py` | Linux 版内存扫描提 key |
| `decrypt_db.py` | 全量解密所有数据库 |
| `mcp_server.py` | MCP Server，让 Claude AI 查询微信数据 |
| `monitor_web.py` | 实时消息监听 (Web UI + SSE + 图片预览) |
| `monitor.py` | 实时消息监听 (命令行) |
| `decode_image.py` | 图片 .dat 文件解密模块 (XOR / V1 / V2) |
| `find_image_key.py` | 从微信进程内存提取图片 AES 密钥 |
| `find_image_key_monitor.py` | 持续监控版密钥提取（推荐） |
| `latency_test.py` | 延迟测量诊断工具 |
| `find_all_keys_macos.c` | macOS 版内存密钥扫描器 (C, Mach VM API) |

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

## macOS 数据库密钥扫描 (WeChat 4.x)


macOS 版微信 4.x 使用 SQLCipher 4 加密本地数据库，密钥格式为 `x'<64hex_key><32hex_salt>'`。C 版扫描器通过 Mach VM API 扫描微信进程内存提取密钥。

### 前置条件

- macOS (Apple Silicon / Intel)
- WeChat 4.x (macOS 版)
- Xcode Command Line Tools: `xcode-select --install`
- 微信需要 ad-hoc 签名（或安装了防撤回补丁）：
  `sudo codesign --force --deep --sign - /Applications/WeChat.app`

### 编译和使用

```bash
# 编译
cc -O2 -o find_all_keys_macos find_all_keys_macos.c -framework Foundation

# 运行（自动查找微信进程、扫描内存、匹配 DB salt）
sudo ./find_all_keys_macos

# 或指定 PID
sudo ./find_all_keys_macos <pid>
```

输出 `all_keys.json`，格式兼容 `decrypt_db.py`，可直接用于解密：

```bash
python3 decrypt_db.py
```

## 免责声明

本工具仅用于学习和研究目的，用于解密**自己的**微信数据。请遵守相关法律法规，不要用于未经授权的数据访问。

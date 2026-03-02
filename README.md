# WeChat 4.0 Database Decryptor

微信 4.0 本地数据库解密工具，支持 **Windows** 和 **macOS**。从运行中的微信进程内存提取加密密钥，解密所有 SQLCipher 4 加密数据库，并提供实时消息监听。

## 原理

微信 4.0 使用 SQLCipher 4 加密本地数据库：
- **加密算法**: AES-256-CBC + HMAC-SHA512
- **KDF**: PBKDF2-HMAC-SHA512, 256,000 iterations
- **页面大小**: 4096 bytes, reserve = 80 (IV 16 + HMAC 64)
- **每个数据库有独立的 salt 和 enc_key**

WCDB (微信的 SQLCipher 封装) 会在进程内存中缓存派生后的 raw key，格式为 `x'<64hex_enc_key><32hex_salt>'`。本工具通过扫描进程内存中的这种模式，匹配数据库文件的 salt，并通过 HMAC 验证来提取正确的密钥。

- **Windows**: 通过 `kernel32.dll` 的 `ReadProcessMemory` 扫描内存
- **macOS**: 通过 Mach VM API (`task_for_pid` + `mach_vm_read`) 扫描内存

## 使用方法

### 环境要求

- Windows 10/11 或 macOS 13+ (ARM64/x86_64)
- Python 3.10+
- 微信 4.0 (正在运行)
- 需要管理员权限 (Windows) 或 sudo (macOS)

### 安装依赖

```bash
pip install pycryptodome
```

### 1. 配置

复制配置模板并修改：

```bash
copy config.example.json config.json    # Windows
cp config.example.json config.json      # macOS/Linux
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

> **macOS 用户**：`db_dir` 路径通常为 `/Users/你的用户名/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/你的微信ID/db_storage`，`wechat_process` 改为 `"WeChat"`。

### 2. 提取密钥

确保微信正在运行，以**管理员权限**运行：

**Windows:**
```bash
python find_all_keys.py
```

**macOS** (需要 sudo):
```bash
sudo python3 find_all_keys_macos.py    # 扫描微信进程内存
sudo python3 match_keys_macos.py       # 匹配密钥到数据库 + HMAC 校验
```

密钥将保存到 `all_keys.json`。

### 3. 解密数据库

```bash
python decrypt_db.py            # Windows
sudo python3 decrypt_db.py      # macOS (无 Full Disk Access 时需要 sudo)
```

解密后的数据库保存在 `decrypted/` 目录，可以直接用 SQLite 工具打开。

### 4. 实时消息监听

#### Web UI (推荐)

```bash
python monitor_web.py           # Windows
sudo python3 monitor_web.py     # macOS
```

打开 http://localhost:5678 查看实时消息流。

- 30ms 轮询 WAL 文件变化 (mtime)
- 检测到变化后全量解密 + WAL patch (~70ms)
- SSE 实时推送到浏览器
- 总延迟约 100ms

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
# Windows
claude mcp add wechat -- python C:\Users\你的用户名\wechat-decrypt\mcp_server.py

# macOS
claude mcp add wechat -- sudo python3 /path/to/wechat-decrypt/mcp_server.py
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

## 文件说明

| 文件 | 说明 |
|------|------|
| `config.py` | 配置加载器 |
| `find_all_keys.py` | 从微信进程内存提取所有数据库密钥 (Windows) |
| `find_all_keys_macos.py` | 从微信进程内存提取密钥 (macOS, Mach VM API) |
| `match_keys_macos.py` | macOS 密钥匹配 + HMAC 校验 |
| `decrypt_db.py` | 全量解密所有数据库 |
| `mcp_server.py` | MCP Server，让 Claude AI 查询微信数据 |
| `monitor_web.py` | 实时消息监听 (Web UI + SSE) |
| `monitor.py` | 实时消息监听 (命令行) |
| `latency_test.py` | 延迟测量诊断工具 |

## 技术细节

### WAL 处理

微信使用 SQLite WAL 模式，WAL 文件是**预分配固定大小** (4MB)。检测变化时：
- 不能用文件大小 (永远不变)
- 使用 mtime 检测写入
- 解密 WAL frame 时需校验 salt 值，跳过旧周期遗留的 frame

### 数据库结构

解密后包含约 26 个数据库：
- `session/session.db` - 会话列表 (最新消息摘要)
- `message/message_*.db` - 聊天记录
- `contact/contact.db` - 联系人
- `media_*/media_*.db` - 媒体文件索引
- 其他: head_image, favorite, sns, emoticon 等

## macOS 说明

### macOS 密钥提取原理

`find_all_keys_macos.py` 使用 Python ctypes 直接调用 macOS Mach VM API：

1. `task_for_pid(pid)` — 获取 WeChat 进程的 Mach task port
2. `mach_vm_region()` — 枚举所有可读写内存区域
3. `mach_vm_read()` — 按 8MB 分块读取内存，搜索 `x'<key><salt>'` 模式
4. `match_keys_macos.py` — 将找到的 salt 与 .db 文件的前 16 字节比对 + HMAC 校验

### 为什么 macOS 需要 sudo？

1. **读取进程内存**: `task_for_pid()` 即使开启了 DevToolsSecurity 也需要 root 权限
2. **读取微信文件**: 微信数据在 macOS 沙箱容器内 (`~/Library/Containers/com.tencent.xinWeChat/`)，受系统保护

**免去部分 sudo 的方法**：给终端 App 授予 **Full Disk Access** (系统设置 → 隐私与安全性 → 完全磁盘访问权限)，授权后 `decrypt_db.py` 和 `monitor_web.py` 不再需要 sudo。但 `find_all_keys_macos.py` 始终需要 sudo。

## 免责声明

本工具仅用于学习和研究目的，用于解密**自己的**微信数据。请遵守相关法律法规，不要用于未经授权的数据访问。

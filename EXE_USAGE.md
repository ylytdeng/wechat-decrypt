# WeChat Decrypt 工具箱 使用说明

## 快速开始

1. **启动微信**并登录账号
2. 双击 `WeChatDecrypt.exe` 打开工具箱
3. 按顺序点击三个按钮：
   - **① 解密数据库** → 从微信进程提取密钥并解密数据库到 `decrypted/` 目录
   - **② 导出消息** → 将聊天记录导出为 CSV / HTML / JSON 到 `export/` 目录
   - **③ 转换音频** → 将语音消息从 SILK 格式转为 MP3 到 `data/` 目录

## 前置要求

- Windows 10 / 11
- 微信 PC 版已登录（解密时需要微信进程运行）
- [FFmpeg](https://ffmpeg.org/download.html) 已安装并加入 PATH（转换音频需要）

### 检查 FFmpeg

打开命令提示符，输入：
```
ffmpeg -version
```
如果提示"不是内部或外部命令"，需要先安装 FFmpeg。

## 输出目录说明

运行后在 exe 所在目录下生成以下文件夹：

```
WeChatDecrypt.exe
config.json          ← 首次运行自动生成的配置文件
decrypted/           ← ① 解密后的数据库文件
export/              ← ② 导出的聊天记录
  张三/
    .info            ← 联系人信息（username/alias/remark/nick_name）
    message_0.db.csv ← CSV 格式（Excel 可直接打开）
    message_0.db.html← HTML 格式（浏览器打开，微信气泡样式）
    message_0.db.json← JSON 格式（程序处理用）
  李四/
    ...
data/                ← ③ 语音 MP3 文件
  张三/
    .info
    20250101_120000_1.mp3
    ...
```

## 导出格式说明

### CSV
- 编码：UTF-8 with BOM，Excel 双击即可正确显示中文
- 字段：时间、发送者、消息类型、内容、server_id

### HTML
- 浏览器打开，模拟微信聊天界面
- 左侧气泡为接收消息，右侧为发送消息
- 按日期自动分组

### JSON
- 完整结构化数据，包含所有元信息
- 适合程序二次处理或 AI 训练

## 配置文件

首次运行会自动检测微信数据目录并生成 `config.json`：

```json
{
    "db_dir": "D:\\xwechat_files\\wxid_xxx\\db_storage",
    "keys_file": "all_keys.json",
    "decrypted_dir": "decrypted",
    "wechat_process": "Weixin.exe"
}
```

如果自动检测失败，请手动修改 `db_dir` 为你的微信数据目录。
路径可在：微信设置 → 文件管理 中找到。

## 常见问题

**Q: 点击"解密数据库"提示未检测到微信进程**
A: 请确保微信 PC 版已启动并登录，然后重试。

**Q: 解密失败 / 密钥提取失败**
A: 检查 `config.json` 中的 `db_dir` 是否与当前登录的微信账号匹配。切换账号后需要删除 `all_keys.json` 重新提取。

**Q: 转换音频没有输出**
A: 确认已安装 FFmpeg 并加入系统 PATH。确认已先执行"① 解密数据库"。

**Q: 导出消息为空**
A: 确认已先执行"① 解密数据库"，且 `decrypted/message/` 下有 `.db` 文件。

**Q: 目录名是 wxid_xxx 而不是昵称**
A: 该联系人不在通讯录中（contact.db 无记录），会使用原始 username。

## 自行打包

安装依赖后双击 `build.bat` 即可重新打包：

```
pip install pyinstaller pycryptodome zstandard pilk
build.bat
```

输出文件：`dist\WeChatDecrypt.exe`

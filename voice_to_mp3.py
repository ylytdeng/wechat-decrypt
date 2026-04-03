"""从 media_0.db 提取所有语音数据，按用户名分目录，SILK_V3 转 MP3"""
import sqlite3
import subprocess
import tempfile
import os
import sys
from datetime import datetime

if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import pilk

DB_PATH = r"decrypted\message\media_0.db"
CONTACT_DB_PATH = r"decrypted\contact\contact.db"
OUTPUT_DIR = "data"

def silk_to_mp3(voice_data, output_path):
    """将微信 SILK 语音数据转换为 MP3"""
    # 去掉微信格式的 0x02 前缀
    if voice_data[0:1] == b'\x02':
        silk_data = voice_data[1:]
    else:
        silk_data = voice_data

    if not silk_data.startswith(b'#!SILK_V3'):
        print(f"  警告：数据不以 #!SILK_V3 开头，跳过")
        return False

    # 补上结尾标记
    if not silk_data.endswith(b'\xff\xff'):
        silk_data += b'\xff\xff'

    silk_file = tempfile.mktemp(suffix=".silk")
    pcm_file = tempfile.mktemp(suffix=".pcm")
    try:
        with open(silk_file, "wb") as f:
            f.write(silk_data)

        pilk.decode(silk_file, pcm_file)

        result = subprocess.run([
            "ffmpeg", "-y", "-f", "s16le", "-ar", "24000", "-ac", "1",
            "-i", pcm_file, output_path
        ], capture_output=True, encoding="utf-8", errors="replace")
        return result.returncode == 0
    finally:
        if os.path.exists(silk_file):
            os.remove(silk_file)
        if os.path.exists(pcm_file):
            os.remove(pcm_file)

# 1. 读取 Name2Id 映射 (rowid -> user_name)
conn = sqlite3.connect(DB_PATH)
name_map = {}
for rowid, user_name in conn.execute("SELECT rowid, user_name FROM Name2Id"):
    name_map[rowid] = user_name
print(f"共 {len(name_map)} 个用户")

# 2. 读取 contact 信息 (user_name -> {remark, nick_name, alias, ...})
contact_map = {}
try:
    cconn = sqlite3.connect(CONTACT_DB_PATH)
    for row in cconn.execute("SELECT username, alias, remark, nick_name FROM contact"):
        uname, alias, remark, nick_name = row
        contact_map[uname] = {"username": uname, "alias": alias or "", "remark": remark or "", "nick_name": nick_name or ""}
    cconn.close()
    print(f"联系人数据库加载: {len(contact_map)} 条")
except Exception as e:
    print(f"联系人数据库读取失败: {e}")

def display_name(user_name):
    """优先 remark > nick_name > user_name"""
    info = contact_map.get(user_name, {})
    return info.get("remark") or info.get("nick_name") or user_name

def safe_dirname(name):
    """替换目录名中的非法字符"""
    for ch in r'\/:*?"<>|':
        name = name.replace(ch, "_")
    return name.strip() or "unknown"

# 2. 查询所有语音，按 chat_name_id 关联用户名
rows = conn.execute("SELECT chat_name_id, create_time, local_id, voice_data FROM VoiceInfo ORDER BY chat_name_id, create_time").fetchall()
conn.close()
print(f"共 {len(rows)} 条语音")

# 3. 遍历转换
success = 0
fail = 0
for chat_name_id, create_time, local_id, voice_data in rows:
    user_name = name_map.get(chat_name_id, f"unknown_{chat_name_id}")
    dname = safe_dirname(display_name(user_name))
    dt = datetime.fromtimestamp(create_time)
    filename = dt.strftime("%Y%m%d_%H%M%S") + f"_{local_id}.mp3"

    user_dir = os.path.join(OUTPUT_DIR, dname)
    os.makedirs(user_dir, exist_ok=True)

    # 写入 .info 文件（只写一次）
    info_path = os.path.join(user_dir, ".info")
    if not os.path.exists(info_path):
        info = contact_map.get(user_name, {"username": user_name, "alias": "", "remark": "", "nick_name": ""})
        with open(info_path, "w", encoding="utf-8") as f:
            f.write(f"username:  {info['username']}\n")
            f.write(f"alias:     {info['alias']}\n")
            f.write(f"nick_name: {info['nick_name']}\n")
            f.write(f"remark:    {info['remark']}\n")

    output_path = os.path.join(user_dir, filename)
    if os.path.exists(output_path):
        success += 1
        continue

    ok = silk_to_mp3(voice_data, output_path)
    if ok:
        success += 1
        print(f"  [{success}/{len(rows)}] {dname}/{filename}")
    else:
        fail += 1
        print(f"  失败: {dname}/{filename}")

print(f"\n完成: 成功 {success}, 失败 {fail}")

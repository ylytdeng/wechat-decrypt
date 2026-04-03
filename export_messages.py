"""导出微信消息记录到 CSV / HTML / JSON
目录结构: export/<display_name>/messages.csv|html|json
"""
import sqlite3
import glob
import hashlib
import os
import json
import csv
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime

import zstandard as zstd

# Windows PowerShell 控制台设为 UTF-8
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

MSG_DB_DIR = r"decrypted\message"
CONTACT_DB_PATH = r"decrypted\contact\contact.db"
OUTPUT_DIR = "export"

MSG_TYPES = {
    1: "文本",
    3: "图片",
    34: "语音",
    42: "名片",
    43: "视频",
    47: "表情包",
    48: "位置",
    49: "分享/文件/小程序",
    10000: "系统消息",
    10002: "系统通知",
}

_zstd_ctx = zstd.ZstdDecompressor()

def decompress_zstd(data: bytes) -> str:
    try:
        return _zstd_ctx.decompress(data).decode("utf-8", errors="replace")
    except Exception:
        return ""

def get_content(raw, ct_flag) -> str:
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        if ct_flag == 4:
            return decompress_zstd(raw)
        return raw.decode("utf-8", errors="replace")
    return str(raw)

def safe_dirname(name: str) -> str:
    for ch in r'\/:*?"<>|':
        name = name.replace(ch, "_")
    return name.strip() or "unknown"

def xml_extract(content: str, *tags) -> str:
    """从 XML 中提取第一个匹配的 tag 文本"""
    try:
        root = ET.fromstring(content)
        for tag in tags:
            el = root.find(".//" + tag)
            if el is not None and el.text:
                return el.text
    except Exception:
        pass
    for tag in tags:
        m = re.search(rf"<{tag}>(.*?)</{tag}>", content, re.DOTALL)
        if m:
            return m.group(1).strip()
    return content[:200]

def friendly_content(msg_type: int, content: str) -> str:
    """返回适合显示的内容摘要"""
    if msg_type == 1:
        return content
    if msg_type == 3:
        return "[图片]"
    if msg_type == 34:
        return "[语音]"
    if msg_type == 42:
        title = xml_extract(content, "nickname")
        return f"[名片: {title}]"
    if msg_type == 43:
        return "[视频]"
    if msg_type == 47:
        return "[表情包]"
    if msg_type == 48:
        loc = xml_extract(content, "label")
        return f"[位置: {loc}]"
    if msg_type == 49:
        title = xml_extract(content, "title")
        return f"[分享: {title}]" if title else "[文件/链接]"
    if msg_type in (10000, 10002):
        return f"[系统: {content[:100]}]"
    return content[:200]

HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#ededed;font-family:"PingFang SC","Helvetica Neue",Arial,sans-serif;font-size:14px}}
.header{{background:#44A848;color:#fff;padding:12px 16px;font-size:17px;font-weight:bold;position:sticky;top:0;z-index:10;box-shadow:0 1px 3px rgba(0,0,0,.3)}}
.chat{{padding:10px 0;max-width:800px;margin:0 auto}}
.date-sep{{text-align:center;margin:12px 0;color:#999;font-size:12px}}
.date-sep span{{background:#ddd;border-radius:10px;padding:2px 10px}}
.msg{{display:flex;align-items:flex-start;margin:6px 12px;max-width:100%}}
.msg.sent{{flex-direction:row-reverse}}
.msg.system{{justify-content:center;margin:4px 12px}}
.msg.system .bubble{{background:transparent;color:#999;font-size:12px;box-shadow:none;border-radius:0;padding:2px 8px}}
.avatar{{width:40px;height:40px;border-radius:6px;background:#7CC;color:#fff;display:flex;align-items:center;justify-content:center;font-size:16px;font-weight:bold;flex-shrink:0}}
.msg.sent .avatar{{background:#4CAF50}}
.msg-body{{max-width:70%;margin:0 8px}}
.sender-name{{font-size:12px;color:#888;margin-bottom:3px}}
.msg.sent .sender-name{{text-align:right}}
.bubble{{display:inline-block;padding:8px 12px;border-radius:6px;word-break:break-word;line-height:1.5;box-shadow:0 1px 2px rgba(0,0,0,.1);white-space:pre-wrap}}
.received .bubble{{background:#fff;border-radius:0 6px 6px 6px}}
.sent .bubble{{background:#95EC69;border-radius:6px 0 6px 6px}}
.type-tag{{font-size:11px;color:#aaa;margin-top:2px}}
</style>
</head>
<body>
<div class="header">{title}</div>
<div class="chat">
{body}
</div>
</body>
</html>
"""

def _html_escape(s: str) -> str:
    return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"','&quot;')

def _write_html(path: str, title: str, is_group: bool, messages: list):
    parts = []
    last_date = None
    for m in messages:
        dt = datetime.fromtimestamp(m["create_time"])
        day = dt.strftime("%Y年%m月%d日")
        if day != last_date:
            parts.append(f'<div class="date-sep"><span>{day}</span></div>')
            last_date = day

        if m["is_system"]:
            parts.append(
                f'<div class="msg system"><div class="bubble">'
                f'{_html_escape(m["display_content"])}</div></div>'
            )
            continue

        side = "received" if m["is_received"] else "sent"
        initial = (m["sender"] or "?")[0].upper()
        sender_label = ""
        if is_group or m["is_received"]:
            sender_label = f'<div class="sender-name">{_html_escape(m["sender"])}</div>'

        type_tag = ""
        if m["type"] != 1:
            type_tag = f'<div class="type-tag">{m["type_name"]}</div>'

        parts.append(
            f'<div class="msg {side}">'
            f'<div class="avatar">{initial}</div>'
            f'<div class="msg-body">'
            f'{sender_label}'
            f'<div class="bubble">{_html_escape(m["display_content"])}</div>'
            f'{type_tag}'
            f'<div class="type-tag">{m["time_str"]}</div>'
            f'</div></div>'
        )

    body = "\n".join(parts)
    with open(path, "w", encoding="utf-8") as f:
        f.write(HTML_TEMPLATE.format(title=_html_escape(title), body=body))


# ─── 加载联系人信息 ─────────────────────────────────────────────────────────────
contact_map: dict[str, dict] = {}
try:
    cconn = sqlite3.connect(CONTACT_DB_PATH)
    for uname, alias, remark, nick_name in cconn.execute(
        "SELECT username, alias, remark, nick_name FROM contact"
    ):
        contact_map[uname] = {
            "username": uname,
            "alias": alias or "",
            "remark": remark or "",
            "nick_name": nick_name or "",
        }
    cconn.close()
    print(f"联系人数据库: {len(contact_map)} 条")
except Exception as e:
    print(f"联系人数据库读取失败: {e}")

def display_name(username: str) -> str:
    info = contact_map.get(username, {})
    return info.get("remark") or info.get("nick_name") or username

# ─── 遍历所有 message_*.db ──────────────────────────────────────────────────────
db_files = sorted(
    f for f in glob.glob(os.path.join(MSG_DB_DIR, "message_*.db"))
    if not f.endswith(("_fts.db", "_resource.db"))
)
print(f"找到 {len(db_files)} 个消息数据库")

total_chats = 0
total_msgs = 0

for db_path in sorted(db_files):
    db_name = os.path.basename(db_path)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    # rowid -> username
    sender_map: dict[int, str] = {}
    for row in conn.execute("SELECT rowid, user_name FROM Name2Id"):
        sender_map[row[0]] = row[1]

    # 计算 username -> hash 映射
    hash_to_username: dict[str, str] = {}
    for username in sender_map.values():
        if username:
            h = hashlib.md5(username.encode()).hexdigest()
            hash_to_username[h] = username

    # 找出所有 Msg_<hash> 表
    all_tables = [
        r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'"
        )
    ]

    for table_name in all_tables:
        h = table_name[4:]  # strip "Msg_"
        chat_username = hash_to_username.get(h, f"unknown_{h[:8]}")
        dname = safe_dirname(display_name(chat_username))
        is_group = chat_username.endswith("@chatroom") or chat_username.endswith("@openim")

        # 读取该表所有消息
        try:
            rows = conn.execute(
                f"SELECT local_id, server_id, local_type, sort_seq, real_sender_id,"
                f" create_time, status, message_content, WCDB_CT_message_content"
                f" FROM {table_name} ORDER BY sort_seq"
            ).fetchall()
        except Exception as e:
            print(f"  读取 {table_name} 失败: {e}")
            continue

        if not rows:
            continue

        messages = []
        for r in rows:
            (local_id, server_id, local_type, sort_seq, real_sender_id,
             create_time, status, raw_content, ct_flag) = tuple(r)

            content = get_content(raw_content, ct_flag or 0)
            sender_uname = sender_map.get(real_sender_id, "")
            sender_dn = display_name(sender_uname) if sender_uname else "我"
            msg_type_name = MSG_TYPES.get(local_type, f"未知({local_type})")
            display_content = friendly_content(local_type, content)
            is_system = local_type in (10000, 10002)

            messages.append({
                "local_id": local_id,
                "server_id": server_id,
                "type": local_type,
                "type_name": msg_type_name,
                "sort_seq": sort_seq,
                "sender_username": sender_uname,
                "sender": sender_dn,
                "create_time": create_time,
                "time_str": datetime.fromtimestamp(create_time).strftime("%Y-%m-%d %H:%M:%S"),
                "status": status,
                "content": content,
                "display_content": display_content,
                "is_system": is_system,
                # 1-on-1: sender==chat_partner -> received(left), else sent(right)
                "is_received": (sender_uname == chat_username) if not is_group else True,
            })

        # ── 输出目录 ──────────────────────────────────────────────────────────
        out_dir = os.path.join(OUTPUT_DIR, dname)
        os.makedirs(out_dir, exist_ok=True)

        # ── .info 文件 ────────────────────────────────────────────────────────
        info_path = os.path.join(out_dir, ".info")
        if not os.path.exists(info_path):
            info = contact_map.get(chat_username, {
                "username": chat_username, "alias": "", "remark": "", "nick_name": ""
            })
            with open(info_path, "w", encoding="utf-8") as f:
                f.write(f"username:  {info['username']}\n")
                f.write(f"alias:     {info['alias']}\n")
                f.write(f"nick_name: {info['nick_name']}\n")
                f.write(f"remark:    {info['remark']}\n")
                f.write(f"is_group:  {is_group}\n")

        # ── CSV ───────────────────────────────────────────────────────────────
        csv_path = os.path.join(out_dir, f"{db_name}.csv")
        with open(csv_path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(["时间", "发送者", "消息类型", "内容", "server_id"])
            for m in messages:
                w.writerow([
                    m["time_str"], m["sender"], m["type_name"],
                    m["display_content"], m["server_id"]
                ])

        # ── JSON ──────────────────────────────────────────────────────────────
        json_path = os.path.join(out_dir, f"{db_name}.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump({
                "chat_username": chat_username,
                "display_name": dname,
                "is_group": is_group,
                "message_count": len(messages),
                "messages": messages,
            }, f, ensure_ascii=False, indent=2)

        # ── HTML ──────────────────────────────────────────────────────────────
        html_path = os.path.join(out_dir, f"{db_name}.html")
        _write_html(html_path, dname, is_group, messages)

        total_chats += 1
        total_msgs += len(messages)
        print(f"  [{db_name}] {dname}: {len(messages)} 条消息")

    conn.close()

print(f"\n完成: {total_chats} 个会话, 共 {total_msgs} 条消息")
print(f"输出目录: {os.path.abspath(OUTPUT_DIR)}")

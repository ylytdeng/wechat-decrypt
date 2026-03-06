"""
微信实时消息监听器

原理: 定期解密 session.db (2MB, <1秒), 检测新消息
session.db 包含每个聊天的最新消息摘要、发送者、时间戳
"""
import hashlib, struct, os, sys, json, time, sqlite3, io
import hmac as hmac_mod
from datetime import datetime
from Crypto.Cipher import AES
import zstandard as zstd
from key_utils import get_key_info, strip_key_metadata

_zstd_dctx = zstd.ZstdDecompressor()

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import functools
print = functools.partial(print, flush=True)

PAGE_SZ = 4096
KEY_SZ = 32
SALT_SZ = 16
IV_SZ = 16
HMAC_SZ = 64
RESERVE_SZ = 80
SQLITE_HDR = b'SQLite format 3\x00'

from config import load_config
_cfg = load_config()
DB_DIR = _cfg["db_dir"]
KEYS_FILE = _cfg["keys_file"]
CONTACT_CACHE = os.path.join(_cfg["decrypted_dir"], "contact", "contact.db")

POLL_INTERVAL = 3  # 秒


def derive_mac_key(enc_key, salt):
    mac_salt = bytes(b ^ 0x3a for b in salt)
    return hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, 2, dklen=KEY_SZ)


def decrypt_page(enc_key, page_data, pgno):
    iv = page_data[PAGE_SZ - RESERVE_SZ : PAGE_SZ - RESERVE_SZ + IV_SZ]
    if pgno == 1:
        encrypted = page_data[SALT_SZ : PAGE_SZ - RESERVE_SZ]
        cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        page = bytearray(SQLITE_HDR + decrypted + b'\x00' * RESERVE_SZ)
        return bytes(page)
    else:
        encrypted = page_data[:PAGE_SZ - RESERVE_SZ]
        cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        return decrypted + b'\x00' * RESERVE_SZ


def decrypt_db_to_memory(db_path, enc_key):
    """解密DB到内存中的bytes, 返回可用于sqlite3的数据"""
    file_size = os.path.getsize(db_path)
    total_pages = file_size // PAGE_SZ
    if file_size % PAGE_SZ != 0:
        total_pages += 1

    chunks = []
    with open(db_path, 'rb') as fin:
        for pgno in range(1, total_pages + 1):
            page = fin.read(PAGE_SZ)
            if len(page) < PAGE_SZ:
                if len(page) > 0:
                    page = page + b'\x00' * (PAGE_SZ - len(page))
                else:
                    break
            decrypted = decrypt_page(enc_key, page, pgno)
            chunks.append(decrypted)

    return b''.join(chunks)


def decrypt_db_to_sqlite(db_path, enc_key):
    """解密DB并返回sqlite3连接 (内存数据库)"""
    data = decrypt_db_to_memory(db_path, enc_key)

    # 写临时文件 (sqlite3不支持直接从bytes打开)
    tmp_path = db_path + ".tmp_monitor"
    with open(tmp_path, 'wb') as f:
        f.write(data)

    conn = sqlite3.connect(tmp_path)
    conn.row_factory = sqlite3.Row
    return conn, tmp_path


def load_contact_names():
    """从已解密的contact.db加载联系人昵称映射"""
    names = {}
    if not os.path.exists(CONTACT_CACHE):
        return names
    try:
        conn = sqlite3.connect(CONTACT_CACHE)
        rows = conn.execute(
            "SELECT username, nick_name, remark FROM contact"
        ).fetchall()
        for r in rows:
            username, nick, remark = r
            names[username] = remark if remark else nick if nick else username
        conn.close()
    except Exception as e:
        print(f"[WARN] 加载联系人失败: {e}")
    return names


def get_session_state(conn):
    """获取当前session状态"""
    state = {}
    try:
        rows = conn.execute("""
            SELECT username, unread_count, summary, last_timestamp,
                   last_msg_type, last_msg_sender, last_sender_display_name
            FROM SessionTable
            WHERE last_timestamp > 0
        """).fetchall()
        for r in rows:
            state[r[0]] = {
                'unread': r[1],
                'summary': r[2] or '',
                'timestamp': r[3],
                'msg_type': r[4],
                'sender': r[5] or '',
                'sender_name': r[6] or '',
            }
    except Exception as e:
        print(f"[ERROR] 读取session失败: {e}")
    return state


def format_msg_type(t):
    types = {
        1: '文本', 3: '图片', 34: '语音', 42: '名片',
        43: '视频', 47: '表情', 48: '位置', 49: '链接/文件',
        50: '语音/视频通话', 10000: '系统消息', 10002: '撤回',
    }
    return types.get(t, f'type={t}')


def main():
    print("=" * 60)
    print("  微信实时消息监听器")
    print("=" * 60)

    # 加载密钥
    with open(KEYS_FILE) as f:
        keys = strip_key_metadata(json.load(f))

    session_key_info = get_key_info(keys, os.path.join("session", "session.db"))
    if not session_key_info:
        print("[ERROR] 找不到session.db的密钥")
        sys.exit(1)

    enc_key = bytes.fromhex(session_key_info["enc_key"])
    session_db = os.path.join(DB_DIR, "session", "session.db")

    # 加载联系人
    print("加载联系人...")
    contact_names = load_contact_names()
    print(f"已加载 {len(contact_names)} 个联系人")

    # 初始状态
    print("读取初始状态...")
    conn, tmp_path = decrypt_db_to_sqlite(session_db, enc_key)
    prev_state = get_session_state(conn)
    conn.close()
    os.remove(tmp_path)

    print(f"跟踪 {len(prev_state)} 个会话")
    print(f"轮询间隔: {POLL_INTERVAL}秒")
    print(f"\n{'='*60}")
    print("开始监听... (Ctrl+C 停止)\n")

    poll_count = 0
    try:
        while True:
            time.sleep(POLL_INTERVAL)
            poll_count += 1

            try:
                conn, tmp_path = decrypt_db_to_sqlite(session_db, enc_key)
                curr_state = get_session_state(conn)
                conn.close()
                os.remove(tmp_path)
            except Exception as e:
                if poll_count % 10 == 0:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] 读取失败: {e}")
                continue

            # 比较差异
            for username, curr in curr_state.items():
                prev = prev_state.get(username)

                if prev is None:
                    # 新会话
                    display = contact_names.get(username, username)
                    ts = datetime.fromtimestamp(curr['timestamp']).strftime('%H:%M:%S')
                    print(f"[{ts}] 新会话 [{display}]")
                    print(f"  {curr['summary']}")
                    print()
                    continue

                # 检查时间戳变化 (有新消息)
                if curr['timestamp'] > prev['timestamp']:
                    display = contact_names.get(username, username)
                    ts = datetime.fromtimestamp(curr['timestamp']).strftime('%H:%M:%S')
                    msg_type = format_msg_type(curr['msg_type'])
                    sender = curr['sender_name'] or curr['sender'] or ''

                    # 群聊显示发送者
                    if '@chatroom' in username and sender:
                        sender_display = contact_names.get(curr['sender'], sender)
                        print(f"[{ts}] [{display}] {sender_display}:")
                    else:
                        print(f"[{ts}] [{display}]")

                    # 消息内容
                    summary = curr['summary']
                    if isinstance(summary, bytes):
                        try:
                            summary = _zstd_dctx.decompress(summary).decode('utf-8', errors='replace')
                        except Exception:
                            summary = '(压缩内容)'
                    if summary:
                        # 群消息格式: "wxid_xxx:\n内容" - 提取内容部分
                        if ':\n' in summary:
                            summary = summary.split(':\n', 1)[1]
                        print(f"  [{msg_type}] {summary}")
                    else:
                        print(f"  [{msg_type}]")

                    # 未读数变化
                    if curr['unread'] > 0:
                        print(f"  (未读: {curr['unread']})")
                    print()

            prev_state = curr_state

            # 心跳
            if poll_count % 20 == 0:
                now = datetime.now().strftime('%H:%M:%S')
                print(f"--- {now} 运行中 (第{poll_count}次轮询) ---")

    except KeyboardInterrupt:
        print(f"\n监听结束, 共 {poll_count} 次轮询")

    # 清理
    tmp = session_db + ".tmp_monitor"
    if os.path.exists(tmp):
        os.remove(tmp)


if __name__ == '__main__':
    main()

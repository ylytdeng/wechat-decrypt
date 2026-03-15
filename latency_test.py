"""测量消息延迟 - 用mtime检测WAL变化（WAL文件是预分配固定大小的）"""
import time, os, sys, io, hashlib, struct, sqlite3, json
from datetime import datetime
from Crypto.Cipher import AES

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

PAGE_SZ = 4096; KEY_SZ = 32; SALT_SZ = 16; RESERVE_SZ = 80
SQLITE_HDR = b'SQLite format 3\x00'
WAL_HEADER_SZ = 32; WAL_FRAME_HEADER_SZ = 24

from config import load_config
_cfg = load_config()
DB_DIR = _cfg["db_dir"]
KEYS_FILE = _cfg["keys_file"]
DECRYPTED = os.path.join(_cfg["decrypted_dir"], "session", "session.db")

with open(KEYS_FILE, "r", encoding="utf-8") as f:
    keys = json.load(f)
enc_key = bytes.fromhex(keys["session/session.db"]["enc_key"])

session_db = os.path.join(DB_DIR, "session", "session.db")
wal_path = session_db + "-wal"


def decrypt_page(enc_key, page_data, pgno):
    iv = page_data[PAGE_SZ - RESERVE_SZ: PAGE_SZ - RESERVE_SZ + 16]
    if pgno == 1:
        encrypted = page_data[SALT_SZ: PAGE_SZ - RESERVE_SZ]
        cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        return bytearray(SQLITE_HDR + decrypted + b'\x00' * RESERVE_SZ)
    else:
        encrypted = page_data[:PAGE_SZ - RESERVE_SZ]
        cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        return decrypted + b'\x00' * RESERVE_SZ


def full_decrypt(src, dst):
    t0 = time.perf_counter()
    total = os.path.getsize(src) // PAGE_SZ
    with open(src, 'rb') as fin, open(dst, 'wb') as fout:
        for pgno in range(1, total + 1):
            page = fin.read(PAGE_SZ)
            if len(page) < PAGE_SZ: break
            fout.write(decrypt_page(enc_key, page, pgno))
    return total, (time.perf_counter() - t0) * 1000


def decrypt_wal_full(wal_path, dst):
    """解密WAL当前有效frame，patch到dst (校验salt跳过旧周期遗留frame)"""
    t0 = time.perf_counter()
    wal_sz = os.path.getsize(wal_path)
    frame_size = WAL_FRAME_HEADER_SZ + PAGE_SZ
    patched = 0

    with open(wal_path, 'rb') as wf, open(dst, 'r+b') as df:
        wal_hdr = wf.read(WAL_HEADER_SZ)
        wal_salt1 = struct.unpack('>I', wal_hdr[16:20])[0]
        wal_salt2 = struct.unpack('>I', wal_hdr[20:24])[0]

        while wf.tell() + frame_size <= wal_sz:
            fh = wf.read(WAL_FRAME_HEADER_SZ)
            if len(fh) < WAL_FRAME_HEADER_SZ: break
            pgno = struct.unpack('>I', fh[0:4])[0]
            frame_salt1 = struct.unpack('>I', fh[8:12])[0]
            frame_salt2 = struct.unpack('>I', fh[12:16])[0]
            ep = wf.read(PAGE_SZ)
            if len(ep) < PAGE_SZ: break
            if pgno == 0 or pgno > 1000000: continue
            if frame_salt1 != wal_salt1 or frame_salt2 != wal_salt2: continue
            dec = decrypt_page(enc_key, ep, pgno)
            df.seek((pgno - 1) * PAGE_SZ)
            df.write(dec)
            patched += 1

    return patched, (time.perf_counter() - t0) * 1000


# 初始化: 全量解密
print("初始全量解密...", flush=True)
pages, ms = full_decrypt(session_db, DECRYPTED)
print(f"  DB: {pages}页 {ms:.0f}ms", flush=True)
if os.path.exists(wal_path):
    patched, ms2 = decrypt_wal_full(wal_path, DECRYPTED)
    print(f"  WAL: {patched}页 {ms2:.0f}ms", flush=True)

# 获取初始状态
conn = sqlite3.connect(DECRYPTED)
prev_sessions = {}
for r in conn.execute("SELECT username, last_timestamp FROM SessionTable WHERE last_timestamp>0"):
    prev_sessions[r[0]] = r[1]
conn.close()

# 记录初始mtime
prev_wal_mtime = os.path.getmtime(wal_path) if os.path.exists(wal_path) else 0
prev_db_mtime = os.path.getmtime(session_db)
wal_sz = os.path.getsize(wal_path) if os.path.exists(wal_path) else 0

print(f"\nWAL大小: {wal_sz} bytes (固定预分配)", flush=True)
print(f"跟踪 {len(prev_sessions)} 个会话", flush=True)
print(f"\n等待微信新消息... (60秒超时, 30ms轮询)\n", flush=True)

start = time.time()

while time.time() - start < 60:
    time.sleep(0.03)

    # 用mtime检测变化
    try:
        wal_mtime = os.path.getmtime(wal_path) if os.path.exists(wal_path) else 0
        db_mtime = os.path.getmtime(session_db)
    except:
        continue

    if wal_mtime == prev_wal_mtime and db_mtime == prev_db_mtime:
        continue

    t_detect = time.perf_counter()
    detect_str = datetime.now().strftime('%H:%M:%S.%f')[:-3]

    wal_changed = wal_mtime != prev_wal_mtime
    db_changed = db_mtime != prev_db_mtime
    print(f"[{detect_str}] 变化检测: WAL={'变' if wal_changed else '不变'} DB={'变' if db_changed else '不变'}", flush=True)

    # 如果DB变了(checkpoint), 全量重解密
    if db_changed and not wal_changed:
        pages, ms = full_decrypt(session_db, DECRYPTED)
        print(f"  全量解密: {pages}页 {ms:.0f}ms", flush=True)
    else:
        # WAL变了, 重新patch所有WAL frame (因为不知道哪些是新的)
        # 先全量解密DB基础
        pages, ms = full_decrypt(session_db, DECRYPTED)
        patched, ms2 = decrypt_wal_full(wal_path, DECRYPTED)
        print(f"  DB {pages}页/{ms:.0f}ms + WAL {patched}页/{ms2:.0f}ms", flush=True)

    t_decrypt = time.perf_counter()

    # 查询变化
    conn = sqlite3.connect(DECRYPTED)
    new_msgs = []
    for r in conn.execute("""
        SELECT username, last_timestamp, summary, last_sender_display_name
        FROM SessionTable WHERE last_timestamp > 0
    """):
        uname, ts, summary, sender = r
        if ts > prev_sessions.get(uname, 0):
            delay = time.time() - ts
            new_msgs.append((uname, ts, summary or '', sender or '', delay))
            prev_sessions[uname] = ts
    conn.close()

    t_query = time.perf_counter()

    decrypt_ms = (t_decrypt - t_detect) * 1000
    query_ms = (t_query - t_decrypt) * 1000
    total_ms = (t_query - t_detect) * 1000

    print(f"  处理总耗时: {total_ms:.1f}ms (解密{decrypt_ms:.1f}ms + 查询{query_ms:.1f}ms)", flush=True)

    for uname, ts, summary, sender, delay in sorted(new_msgs, key=lambda x: x[1]):
        if ':\n' in summary:
            summary = summary.split(':\n', 1)[1]
        msg_time = datetime.fromtimestamp(ts).strftime('%H:%M:%S')
        print(f"  >>> 消息时间={msg_time} | 微信→DB延迟={delay:.1f}s | {sender}: {summary}", flush=True)

    if not new_msgs:
        print(f"  (无新消息变化)", flush=True)

    prev_wal_mtime = wal_mtime
    prev_db_mtime = db_mtime
    print(flush=True)

print("超时退出", flush=True)

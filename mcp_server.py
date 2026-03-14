r"""
WeChat MCP Server - query WeChat messages, contacts via Claude

Based on FastMCP (stdio transport), reuses existing decryption.
Runs on Windows Python (needs access to D:\ WeChat databases).
"""

import os, sys, json, time, sqlite3, tempfile, struct, hashlib, atexit, re
import hmac as hmac_mod
from contextlib import closing
from datetime import datetime
import xml.etree.ElementTree as ET
from Crypto.Cipher import AES
from mcp.server.fastmcp import FastMCP
import zstandard as zstd
from decode_image import ImageResolver
from key_utils import get_key_info, key_path_variants, strip_key_metadata

# ============ 加密常量 ============
PAGE_SZ = 4096
KEY_SZ = 32
SALT_SZ = 16
RESERVE_SZ = 80
SQLITE_HDR = b'SQLite format 3\x00'
WAL_HEADER_SZ = 32
WAL_FRAME_HEADER_SZ = 24

# ============ 配置加载 ============
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "config.json")

with open(CONFIG_FILE) as f:
    _cfg = json.load(f)
for _key in ("keys_file", "decrypted_dir"):
    if _key in _cfg and not os.path.isabs(_cfg[_key]):
        _cfg[_key] = os.path.join(SCRIPT_DIR, _cfg[_key])

DB_DIR = _cfg["db_dir"]
KEYS_FILE = _cfg["keys_file"]
DECRYPTED_DIR = _cfg["decrypted_dir"]

# 图片相关路径
_db_dir = _cfg["db_dir"]
if os.path.basename(_db_dir) == "db_storage":
    WECHAT_BASE_DIR = os.path.dirname(_db_dir)
else:
    WECHAT_BASE_DIR = _db_dir

DECODED_IMAGE_DIR = _cfg.get("decoded_image_dir")
if not DECODED_IMAGE_DIR:
    DECODED_IMAGE_DIR = os.path.join(SCRIPT_DIR, "decoded_images")
elif not os.path.isabs(DECODED_IMAGE_DIR):
    DECODED_IMAGE_DIR = os.path.join(SCRIPT_DIR, DECODED_IMAGE_DIR)

with open(KEYS_FILE) as f:
    ALL_KEYS = strip_key_metadata(json.load(f))

# ============ 解密函数 ============

def decrypt_page(enc_key, page_data, pgno):
    iv = page_data[PAGE_SZ - RESERVE_SZ : PAGE_SZ - RESERVE_SZ + 16]
    if pgno == 1:
        encrypted = page_data[SALT_SZ : PAGE_SZ - RESERVE_SZ]
        cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        return bytes(bytearray(SQLITE_HDR + decrypted + b'\x00' * RESERVE_SZ))
    else:
        encrypted = page_data[: PAGE_SZ - RESERVE_SZ]
        cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        return decrypted + b'\x00' * RESERVE_SZ


def full_decrypt(db_path, out_path, enc_key):
    file_size = os.path.getsize(db_path)
    total_pages = file_size // PAGE_SZ
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(db_path, 'rb') as fin, open(out_path, 'wb') as fout:
        for pgno in range(1, total_pages + 1):
            page = fin.read(PAGE_SZ)
            if len(page) < PAGE_SZ:
                if len(page) > 0:
                    page = page + b'\x00' * (PAGE_SZ - len(page))
                else:
                    break
            fout.write(decrypt_page(enc_key, page, pgno))
    return total_pages


def decrypt_wal(wal_path, out_path, enc_key):
    if not os.path.exists(wal_path):
        return 0
    wal_size = os.path.getsize(wal_path)
    if wal_size <= WAL_HEADER_SZ:
        return 0
    frame_size = WAL_FRAME_HEADER_SZ + PAGE_SZ
    patched = 0
    with open(wal_path, 'rb') as wf, open(out_path, 'r+b') as df:
        wal_hdr = wf.read(WAL_HEADER_SZ)
        wal_salt1 = struct.unpack('>I', wal_hdr[16:20])[0]
        wal_salt2 = struct.unpack('>I', wal_hdr[20:24])[0]
        while wf.tell() + frame_size <= wal_size:
            fh = wf.read(WAL_FRAME_HEADER_SZ)
            if len(fh) < WAL_FRAME_HEADER_SZ:
                break
            pgno = struct.unpack('>I', fh[0:4])[0]
            frame_salt1 = struct.unpack('>I', fh[8:12])[0]
            frame_salt2 = struct.unpack('>I', fh[12:16])[0]
            ep = wf.read(PAGE_SZ)
            if len(ep) < PAGE_SZ:
                break
            if pgno == 0 or pgno > 1000000:
                continue
            if frame_salt1 != wal_salt1 or frame_salt2 != wal_salt2:
                continue
            dec = decrypt_page(enc_key, ep, pgno)
            df.seek((pgno - 1) * PAGE_SZ)
            df.write(dec)
            patched += 1
    return patched


# ============ DB 缓存 ============

class DBCache:
    """缓存解密后的 DB，通过 mtime 检测变化。使用固定文件名，重启后可复用。"""

    CACHE_DIR = os.path.join(tempfile.gettempdir(), "wechat_mcp_cache")
    MTIME_FILE = os.path.join(tempfile.gettempdir(), "wechat_mcp_cache", "_mtimes.json")

    def __init__(self):
        self._cache = {}  # rel_key -> (db_mtime, wal_mtime, tmp_path)
        os.makedirs(self.CACHE_DIR, exist_ok=True)
        self._load_persistent_cache()

    def _cache_path(self, rel_key):
        """rel_key -> 固定的缓存文件路径"""
        h = hashlib.md5(rel_key.encode()).hexdigest()[:12]
        return os.path.join(self.CACHE_DIR, f"{h}.db")

    def _load_persistent_cache(self):
        """启动时从磁盘恢复缓存映射，验证 mtime 后复用"""
        if not os.path.exists(self.MTIME_FILE):
            return
        try:
            with open(self.MTIME_FILE) as f:
                saved = json.load(f)
        except (json.JSONDecodeError, OSError):
            return
        reused = 0
        for rel_key, info in saved.items():
            tmp_path = info["path"]
            if not os.path.exists(tmp_path):
                continue
            rel_path = rel_key.replace('\\', os.sep)
            db_path = os.path.join(DB_DIR, rel_path)
            wal_path = db_path + "-wal"
            try:
                db_mtime = os.path.getmtime(db_path)
                wal_mtime = os.path.getmtime(wal_path) if os.path.exists(wal_path) else 0
            except OSError:
                continue
            if db_mtime == info["db_mt"] and wal_mtime == info["wal_mt"]:
                self._cache[rel_key] = (db_mtime, wal_mtime, tmp_path)
                reused += 1
        if reused:
            print(f"[DBCache] reused {reused} cached decrypted DBs from previous run", flush=True)

    def _save_persistent_cache(self):
        """持久化缓存映射到磁盘"""
        data = {}
        for rel_key, (db_mt, wal_mt, path) in self._cache.items():
            data[rel_key] = {"db_mt": db_mt, "wal_mt": wal_mt, "path": path}
        try:
            with open(self.MTIME_FILE, 'w') as f:
                json.dump(data, f)
        except OSError:
            pass

    def get(self, rel_key):
        key_info = get_key_info(ALL_KEYS, rel_key)
        if not key_info:
            return None
        rel_path = rel_key.replace('\\', '/').replace('/', os.sep)
        db_path = os.path.join(DB_DIR, rel_path)
        wal_path = db_path + "-wal"
        if not os.path.exists(db_path):
            return None

        try:
            db_mtime = os.path.getmtime(db_path)
            wal_mtime = os.path.getmtime(wal_path) if os.path.exists(wal_path) else 0
        except OSError:
            return None

        if rel_key in self._cache:
            c_db_mt, c_wal_mt, c_path = self._cache[rel_key]
            if c_db_mt == db_mtime and c_wal_mt == wal_mtime and os.path.exists(c_path):
                return c_path

        tmp_path = self._cache_path(rel_key)
        enc_key = bytes.fromhex(key_info["enc_key"])
        full_decrypt(db_path, tmp_path, enc_key)
        if os.path.exists(wal_path):
            decrypt_wal(wal_path, tmp_path, enc_key)
        self._cache[rel_key] = (db_mtime, wal_mtime, tmp_path)
        self._save_persistent_cache()
        return tmp_path

    def cleanup(self):
        """正常退出时保存缓存映射（不删文件，下次启动可复用）"""
        self._save_persistent_cache()


_cache = DBCache()
atexit.register(_cache.cleanup)


# ============ 联系人缓存 ============

_contact_names = None  # {username: display_name}
_contact_full = None   # [{username, nick_name, remark}]
_self_username = None
_XML_UNSAFE_RE = re.compile(r'<!DOCTYPE|<!ENTITY', re.IGNORECASE)
_XML_PARSE_MAX_LEN = 20000
_QUERY_LIMIT_MAX = 500
_HISTORY_QUERY_BATCH_SIZE = 500


def _load_contacts_from(db_path):
    names = {}
    full = []
    conn = sqlite3.connect(db_path)
    try:
        for r in conn.execute("SELECT username, nick_name, remark FROM contact").fetchall():
            uname, nick, remark = r
            display = remark if remark else nick if nick else uname
            names[uname] = display
            full.append({'username': uname, 'nick_name': nick or '', 'remark': remark or ''})
    finally:
        conn.close()
    return names, full


def get_contact_names():
    global _contact_names, _contact_full
    if _contact_names is not None:
        return _contact_names

    # 优先用已解密的 contact.db
    pre_decrypted = os.path.join(DECRYPTED_DIR, "contact", "contact.db")
    if os.path.exists(pre_decrypted):
        try:
            _contact_names, _contact_full = _load_contacts_from(pre_decrypted)
            return _contact_names
        except Exception:
            pass

    # 实时解密
    path = _cache.get(os.path.join("contact", "contact.db"))
    if path:
        try:
            _contact_names, _contact_full = _load_contacts_from(path)
            return _contact_names
        except Exception:
            pass

    return {}


def get_contact_full():
    global _contact_full
    if _contact_full is None:
        get_contact_names()
    return _contact_full or []


# ============ 辅助函数 ============

def format_msg_type(t):
    base_type, _ = _split_msg_type(t)
    return {
        1: '文本', 3: '图片', 34: '语音', 42: '名片',
        43: '视频', 47: '表情', 48: '位置', 49: '链接/文件',
        50: '通话', 10000: '系统', 10002: '撤回',
    }.get(base_type, f'type={t}')


def _split_msg_type(t):
    try:
        t = int(t)
    except (TypeError, ValueError):
        return 0, 0
    # WeChat packs the base type into the low 32 bits and app subtype into the high 32 bits.
    if t > 0xFFFFFFFF:
        return t & 0xFFFFFFFF, t >> 32
    return t, 0


def resolve_username(chat_name):
    """将聊天名/备注名/wxid 解析为 username"""
    names = get_contact_names()

    # 直接是 username
    if chat_name in names or chat_name.startswith('wxid_') or '@chatroom' in chat_name:
        return chat_name

    # 模糊匹配(优先精确包含)
    chat_lower = chat_name.lower()
    for uname, display in names.items():
        if chat_lower == display.lower():
            return uname
    for uname, display in names.items():
        if chat_lower in display.lower():
            return uname

    return None


_zstd_dctx = zstd.ZstdDecompressor()


def _decompress_content(content, ct):
    """解压 zstd 压缩的消息内容"""
    if ct and ct == 4 and isinstance(content, bytes):
        try:
            return _zstd_dctx.decompress(content).decode('utf-8', errors='replace')
        except Exception:
            return None
    if isinstance(content, bytes):
        try:
            return content.decode('utf-8', errors='replace')
        except Exception:
            return None
    return content


def _parse_message_content(content, local_type, is_group):
    """解析消息内容，返回 (sender_id, text)"""
    if content is None:
        return '', ''
    if isinstance(content, bytes):
        return '', '(二进制内容)'

    sender = ''
    text = content
    if is_group and ':\n' in content:
        sender, text = content.split(':\n', 1)

    return sender, text


def _collapse_text(text):
    if not text:
        return ''
    return re.sub(r'\s+', ' ', text).strip()


def _get_self_username():
    global _self_username
    if _self_username:
        return _self_username

    if not DB_DIR:
        return ''

    names = get_contact_names()
    account_dir = os.path.basename(os.path.dirname(DB_DIR))
    candidates = [account_dir]

    m = re.fullmatch(r'(.+)_([0-9a-fA-F]{4,})', account_dir)
    if m:
        candidates.insert(0, m.group(1))

    for candidate in candidates:
        if candidate and candidate in names:
            _self_username = candidate
            return _self_username

    return ''


def _load_name2id_maps(conn):
    id_to_username = {}
    try:
        rows = conn.execute("SELECT rowid, user_name FROM Name2Id").fetchall()
    except sqlite3.Error:
        return id_to_username

    for rowid, user_name in rows:
        if not user_name:
            continue
        id_to_username[rowid] = user_name
    return id_to_username


def _display_name_for_username(username, names):
    if not username:
        return ''
    if username == _get_self_username():
        return 'me'
    return names.get(username, username)


def _resolve_sender_label(real_sender_id, sender_from_content, is_group, chat_username, chat_display_name, names, id_to_username):
    sender_username = id_to_username.get(real_sender_id, '')

    if is_group:
        if sender_username and sender_username != chat_username:
            return _display_name_for_username(sender_username, names)
        if sender_from_content:
            return _display_name_for_username(sender_from_content, names)
        return ''

    if sender_username == chat_username:
        return chat_display_name
    if sender_username:
        return _display_name_for_username(sender_username, names)
    return ''


def _resolve_quote_sender_label(ref_user, ref_display_name, is_group, chat_username, chat_display_name, names):
    if is_group:
        if ref_user:
            return _display_name_for_username(ref_user, names)
        return ref_display_name or ''

    self_username = _get_self_username()
    if ref_user:
        if ref_user == chat_username:
            return chat_display_name
        if self_username and ref_user == self_username:
            return 'me'
        return names.get(ref_user, ref_display_name or ref_user)
    if ref_display_name:
        if ref_display_name == chat_display_name:
            return chat_display_name
        self_display_name = names.get(self_username, self_username) if self_username else ''
        if self_display_name and ref_display_name == self_display_name:
            return 'me'
        return ref_display_name
    return ''


def _parse_xml_root(content):
    if not content or len(content) > _XML_PARSE_MAX_LEN or _XML_UNSAFE_RE.search(content):
        return None

    try:
        return ET.fromstring(content)
    except ET.ParseError:
        return None


def _parse_int(value, fallback=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def _format_app_message_text(content, local_type, is_group, chat_username, chat_display_name, names):
    if not content or '<appmsg' not in content:
        return None

    _, sub_type = _split_msg_type(local_type)
    root = _parse_xml_root(content)
    if root is None:
        return None

    appmsg = root.find('.//appmsg')
    if appmsg is None:
        return None

    title = _collapse_text(appmsg.findtext('title') or '')
    app_type_text = (appmsg.findtext('type') or '').strip()
    app_type = _parse_int(app_type_text, _parse_int(sub_type, 0))

    if app_type == 57:
        ref = appmsg.find('.//refermsg')
        ref_user = ''
        ref_display_name = ''
        ref_content = ''
        if ref is not None:
            ref_user = (ref.findtext('fromusr') or '').strip()
            ref_display_name = (ref.findtext('displayname') or '').strip()
            ref_content = _collapse_text(ref.findtext('content') or '')
        if len(ref_content) > 160:
            ref_content = ref_content[:160] + "..."

        quote_text = title or "[引用消息]"
        if ref_content:
            ref_label = _resolve_quote_sender_label(
                ref_user, ref_display_name, is_group, chat_username, chat_display_name, names
            )
            prefix = f"回复 {ref_label}: " if ref_label else "回复: "
            quote_text += f"\n  ↳ {prefix}{ref_content}"
        return quote_text

    if app_type == 6:
        return f"[文件] {title}" if title else "[文件]"
    if app_type == 5:
        return f"[链接] {title}" if title else "[链接]"
    if app_type in (33, 36, 44):
        return f"[小程序] {title}" if title else "[小程序]"
    if title:
        return f"[链接/文件] {title}"
    return "[链接/文件]"


def _format_voip_message_text(content):
    if not content or '<voip' not in content:
        return None

    root = _parse_xml_root(content)
    if root is None:
        return "[通话]"

    raw_text = _collapse_text(root.findtext('.//msg') or '')
    if not raw_text:
        return "[通话]"

    status_map = {
        'Canceled': '已取消',
        'Line busy': '对方忙线',
        'Already answered elsewhere': '已在其他设备接听',
        'Declined on other device': '已在其他设备拒接',
        'Call canceled by caller': '主叫已取消',
        'Call not answered': '未接听',
        "Call wasn't answered": '未接听',
    }

    if raw_text.startswith('Duration:'):
        duration = raw_text.split(':', 1)[1].strip()
        return f"[通话] 通话时长 {duration}" if duration else "[通话]"

    return f"[通话] {status_map.get(raw_text, raw_text)}"


def _format_message_text(local_id, local_type, content, is_group, chat_username, chat_display_name, names):
    sender_from_content, text = _parse_message_content(content, local_type, is_group)
    base_type, _ = _split_msg_type(local_type)

    if base_type == 3:
        text = f"[图片] (local_id={local_id})"
    elif base_type == 47:
        text = "[表情]"
    elif base_type == 50:
        text = _format_voip_message_text(text) or "[通话]"
    elif base_type == 49:
        text = _format_app_message_text(
            text, local_type, is_group, chat_username, chat_display_name, names
        ) or "[链接/文件]"
    elif base_type != 1:
        type_label = format_msg_type(local_type)
        text = f"[{type_label}] {text}" if text else f"[{type_label}]"

    return sender_from_content, text


def _is_safe_msg_table_name(table_name):
    return bool(re.fullmatch(r'Msg_[0-9a-f]{32}', table_name))


# 消息 DB 的 rel_keys
# 用 message_\d+\.db$ 匹配，自然排除 message_resource.db / message_fts_*.db
MSG_DB_KEYS = sorted([
    k for k in ALL_KEYS
    if any(v.startswith("message/") for v in key_path_variants(k))
    and any(re.search(r"message_\d+\.db$", v) for v in key_path_variants(k))
])


def _find_msg_table_for_user(username):
    """在所有 message_N.db 中查找用户的消息表，返回 (db_path, table_name)"""
    table_hash = hashlib.md5(username.encode()).hexdigest()
    table_name = f"Msg_{table_hash}"
    if not _is_safe_msg_table_name(table_name):
        return None, None

    for rel_key in MSG_DB_KEYS:
        path = _cache.get(rel_key)
        if not path:
            continue
        conn = sqlite3.connect(path)
        try:
            exists = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                (table_name,)
            ).fetchone()
            if exists:
                conn.close()
                return path, table_name
        except Exception:
            pass
        finally:
            conn.close()

    return None, None


def _find_msg_tables_for_user(username):
    """返回用户在所有 message_N.db 中对应的消息表，按最新消息时间倒序排列。"""
    table_hash = hashlib.md5(username.encode()).hexdigest()
    table_name = f"Msg_{table_hash}"
    if not _is_safe_msg_table_name(table_name):
        return []

    matches = []
    for rel_key in MSG_DB_KEYS:
        path = _cache.get(rel_key)
        if not path:
            continue
        conn = sqlite3.connect(path)
        try:
            exists = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                (table_name,)
            ).fetchone()
            if not exists:
                continue
            max_create_time = conn.execute(
                f"SELECT MAX(create_time) FROM [{table_name}]"
            ).fetchone()[0] or 0
            matches.append({
                'db_path': path,
                'table_name': table_name,
                'max_create_time': max_create_time,
            })
        except Exception:
            pass
        finally:
            conn.close()

    matches.sort(key=lambda item: item['max_create_time'], reverse=True)
    return matches


def _validate_pagination(limit, offset=0, limit_max=_QUERY_LIMIT_MAX):
    if limit <= 0:
        raise ValueError("limit 必须大于 0")
    if limit_max is not None and limit > limit_max:
        raise ValueError(f"limit 不能大于 {limit_max}")
    if offset < 0:
        raise ValueError("offset 不能小于 0")


def _parse_time_value(value, field_name, is_end=False):
    value = (value or '').strip()
    if not value:
        return None

    formats = [
        ('%Y-%m-%d %H:%M:%S', False),
        ('%Y-%m-%d %H:%M', False),
        ('%Y-%m-%d', True),
    ]
    for fmt, date_only in formats:
        try:
            dt = datetime.strptime(value, fmt)
            if date_only and is_end:
                dt = dt.replace(hour=23, minute=59, second=59)
            return int(dt.timestamp())
        except ValueError:
            continue

    raise ValueError(
        f"{field_name} 格式无效: {value}。支持 YYYY-MM-DD / YYYY-MM-DD HH:MM / YYYY-MM-DD HH:MM:SS"
    )


def _parse_time_range(start_time='', end_time=''):
    start_ts = _parse_time_value(start_time, 'start_time', is_end=False)
    end_ts = _parse_time_value(end_time, 'end_time', is_end=True)
    if start_ts is not None and end_ts is not None and start_ts > end_ts:
        raise ValueError('start_time 不能晚于 end_time')
    return start_ts, end_ts


def _build_message_filters(start_ts=None, end_ts=None, keyword=''):
    clauses = []
    params = []
    if start_ts is not None:
        clauses.append('create_time >= ?')
        params.append(start_ts)
    if end_ts is not None:
        clauses.append('create_time <= ?')
        params.append(end_ts)
    if keyword:
        clauses.append('message_content LIKE ?')
        params.append(f'%{keyword}%')
    return clauses, params


def _query_messages(conn, table_name, start_ts=None, end_ts=None, keyword='', limit=20, offset=0):
    if not _is_safe_msg_table_name(table_name):
        raise ValueError(f'非法消息表名: {table_name}')

    clauses, params = _build_message_filters(start_ts, end_ts, keyword)
    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ''
    sql = f"""
        SELECT local_id, local_type, create_time, real_sender_id, message_content,
               WCDB_CT_message_content
        FROM [{table_name}]
        {where_sql}
        ORDER BY create_time DESC
    """
    if limit is None:
        return conn.execute(sql, params).fetchall()
    sql += "\n        LIMIT ? OFFSET ?"
    return conn.execute(sql, (*params, limit, offset)).fetchall()


def _resolve_chat_context(chat_name):
    username = resolve_username(chat_name)
    if not username:
        return None

    names = get_contact_names()
    display_name = names.get(username, username)
    message_tables = _find_msg_tables_for_user(username)
    if not message_tables:
        return {
            'query': chat_name,
            'username': username,
            'display_name': display_name,
            'db_path': None,
            'table_name': None,
            'message_tables': [],
            'is_group': '@chatroom' in username,
        }

    primary = message_tables[0]
    return {
        'query': chat_name,
        'username': username,
        'display_name': display_name,
        'db_path': primary['db_path'],
        'table_name': primary['table_name'],
        'message_tables': message_tables,
        'is_group': '@chatroom' in username,
    }


def _resolve_chat_contexts(chat_names):
    if not chat_names:
        raise ValueError('chat_names 不能为空')

    resolved = []
    unresolved = []
    missing_tables = []
    seen = set()

    for chat_name in chat_names:
        name = (chat_name or '').strip()
        if not name:
            unresolved.append('(空)')
            continue
        ctx = _resolve_chat_context(name)
        if not ctx:
            unresolved.append(name)
            continue
        if not ctx['message_tables']:
            missing_tables.append(ctx['display_name'])
            continue
        if ctx['username'] in seen:
            continue
        seen.add(ctx['username'])
        resolved.append(ctx)

    return resolved, unresolved, missing_tables


def _normalize_chat_names(chat_name):
    if chat_name is None:
        return []
    if isinstance(chat_name, str):
        value = chat_name.strip()
        return [value] if value else []
    if isinstance(chat_name, (list, tuple, set)):
        normalized = []
        for item in chat_name:
            if item is None:
                continue
            value = str(item).strip()
            if value:
                normalized.append(value)
        return normalized
    value = str(chat_name).strip()
    return [value] if value else []


def _format_history_lines(rows, username, display_name, is_group, names, id_to_username):
    lines = []
    ctx = {
        'username': username,
        'display_name': display_name,
        'is_group': is_group,
    }
    for row in reversed(rows):
        _, line = _build_history_line(row, ctx, names, id_to_username)
        lines.append(line)
    return lines


def _build_search_entry(row, ctx, names, id_to_username):
    local_id, local_type, create_time, real_sender_id, content, ct = row
    content = _decompress_content(content, ct)
    if content is None:
        return None

    sender, text = _format_message_text(
        local_id, local_type, content, ctx['is_group'], ctx['username'], ctx['display_name'], names
    )
    if text and len(text) > 300:
        text = text[:300] + '...'

    sender_label = _resolve_sender_label(
        real_sender_id,
        sender,
        ctx['is_group'],
        ctx['username'],
        ctx['display_name'],
        names,
        id_to_username,
    )
    time_str = datetime.fromtimestamp(create_time).strftime('%Y-%m-%d %H:%M')
    entry = f"[{time_str}] [{ctx['display_name']}]"
    if sender_label:
        entry += f" {sender_label}:"
    entry += f" {text}"
    return create_time, entry


def _build_history_line(row, ctx, names, id_to_username):
    local_id, local_type, create_time, real_sender_id, content, ct = row
    time_str = datetime.fromtimestamp(create_time).strftime('%Y-%m-%d %H:%M')
    content = _decompress_content(content, ct)
    if content is None:
        content = '(无法解压)'

    sender, text = _format_message_text(
        local_id, local_type, content, ctx['is_group'], ctx['username'], ctx['display_name'], names
    )

    sender_label = _resolve_sender_label(
        real_sender_id, sender, ctx['is_group'], ctx['username'], ctx['display_name'], names, id_to_username
    )
    if sender_label:
        return create_time, f'[{time_str}] {sender_label}: {text}'
    return create_time, f'[{time_str}] {text}'


def _get_chat_message_tables(ctx):
    if ctx.get('message_tables'):
        return ctx['message_tables']
    if ctx.get('db_path') and ctx.get('table_name'):
        return [{'db_path': ctx['db_path'], 'table_name': ctx['table_name']}]
    return []


def _iter_table_contexts(ctx):
    for table in _get_chat_message_tables(ctx):
        yield {
            'query': ctx['query'],
            'username': ctx['username'],
            'display_name': ctx['display_name'],
            'db_path': table['db_path'],
            'table_name': table['table_name'],
            'is_group': ctx['is_group'],
        }


def _candidate_page_size(limit, offset):
    return limit + offset


def _message_query_batch_size(candidate_limit):
    return candidate_limit


def _history_query_batch_size(candidate_limit):
    return min(candidate_limit, _HISTORY_QUERY_BATCH_SIZE)


def _page_ranked_entries(entries, limit, offset):
    ordered = sorted(entries, key=lambda item: item[0], reverse=True)
    paged = ordered[offset:offset + limit]
    paged.sort(key=lambda item: item[0])
    return paged


def _collect_chat_history_lines(ctx, names, start_ts=None, end_ts=None, limit=20, offset=0):
    collected = []
    failures = []
    candidate_limit = _candidate_page_size(limit, offset)
    batch_size = _history_query_batch_size(candidate_limit)

    for table_ctx in _iter_table_contexts(ctx):
        try:
            with closing(sqlite3.connect(table_ctx['db_path'])) as conn:
                id_to_username = _load_name2id_maps(conn)
                fetch_offset = 0
                collected_before_table = len(collected)
                # 当前页上的消息一定落在各分表最近的 offset+limit 条记录内。
                while len(collected) - collected_before_table < candidate_limit:
                    rows = _query_messages(
                        conn,
                        table_ctx['table_name'],
                        start_ts=start_ts,
                        end_ts=end_ts,
                        limit=batch_size,
                        offset=fetch_offset,
                    )
                    if not rows:
                        break
                    fetch_offset += len(rows)

                    for row in rows:
                        try:
                            collected.append(_build_history_line(row, table_ctx, names, id_to_username))
                        except Exception as e:
                            failures.append(
                                f"{table_ctx['display_name']} local_id={row[0]} create_time={row[2]}: {e}"
                            )
                        if len(collected) - collected_before_table >= candidate_limit:
                            break

                    if len(rows) < batch_size:
                        break
        except Exception as e:
            failures.append(f"{table_ctx['db_path']}: {e}")

    paged = _page_ranked_entries(collected, limit, offset)
    return [line for _, line in paged], failures


def _collect_chat_search_entries(ctx, names, keyword, start_ts=None, end_ts=None, candidate_limit=20):
    collected = []
    failures = []
    contexts_by_db = {}
    for table_ctx in _iter_table_contexts(ctx):
        contexts_by_db.setdefault(table_ctx['db_path'], []).append(table_ctx)

    for db_path, db_contexts in contexts_by_db.items():
        try:
            with closing(sqlite3.connect(db_path)) as conn:
                db_entries, db_failures = _collect_search_entries(
                    conn,
                    db_contexts,
                    names,
                    keyword,
                    start_ts=start_ts,
                    end_ts=end_ts,
                    candidate_limit=candidate_limit,
                )
                collected.extend(db_entries)
                failures.extend(db_failures)
        except Exception as e:
            failures.extend(f"{table_ctx['display_name']}: {e}" for table_ctx in db_contexts)

    return collected, failures


def _load_search_contexts_from_db(conn, db_path, names):
    tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'"
    ).fetchall()

    table_to_username = {}
    try:
        for (user_name,) in conn.execute("SELECT user_name FROM Name2Id").fetchall():
            if not user_name:
                continue
            table_hash = hashlib.md5(user_name.encode()).hexdigest()
            table_to_username[f"Msg_{table_hash}"] = user_name
    except sqlite3.Error:
        pass

    contexts = []
    for (table_name,) in tables:
        username = table_to_username.get(table_name, '')
        display_name = names.get(username, username) if username else table_name
        contexts.append({
            'query': display_name,
            'username': username,
            'display_name': display_name,
            'db_path': db_path,
            'table_name': table_name,
            'is_group': '@chatroom' in username,
        })
    return contexts


def _collect_search_entries(conn, contexts, names, keyword, start_ts=None, end_ts=None, candidate_limit=20):
    collected = []
    failures = []
    id_to_username = _load_name2id_maps(conn)
    batch_size = _message_query_batch_size(candidate_limit)

    for ctx in contexts:
        try:
            fetch_offset = 0
            collected_before_table = len(collected)
            # 全局分页只需要每个分表最新的 offset+limit 条有效命中，无需把整表命中读进内存。
            while len(collected) - collected_before_table < candidate_limit:
                rows = _query_messages(
                    conn,
                    ctx['table_name'],
                    start_ts=start_ts,
                    end_ts=end_ts,
                    keyword=keyword,
                    limit=batch_size,
                    offset=fetch_offset,
                )
                if not rows:
                    break
                fetch_offset += len(rows)

                for row in rows:
                    formatted = _build_search_entry(row, ctx, names, id_to_username)
                    if formatted:
                        collected.append(formatted)
                        if len(collected) - collected_before_table >= candidate_limit:
                            break

                if len(rows) < batch_size:
                    break
        except Exception as e:
            failures.append(f"{ctx['display_name']}: {e}")

    return collected, failures


def _page_search_entries(entries, limit, offset):
    return _page_ranked_entries(entries, limit, offset)


def _search_single_chat(ctx, keyword, start_ts, end_ts, start_time, end_time, limit, offset):
    names = get_contact_names()
    candidate_limit = _candidate_page_size(limit, offset)

    entries, failures = _collect_chat_search_entries(
        ctx,
        names,
        keyword,
        start_ts=start_ts,
        end_ts=end_ts,
        candidate_limit=candidate_limit,
    )

    paged = _page_search_entries(entries, limit, offset)

    if not paged:
        if failures:
            return "查询失败: " + "；".join(failures)
        return f"未在 {ctx['display_name']} 中找到包含 \"{keyword}\" 的消息"

    header = f"在 {ctx['display_name']} 中搜索 \"{keyword}\" 找到 {len(paged)} 条结果（offset={offset}, limit={limit}）"
    if start_time or end_time:
        header += f"\n时间范围: {start_time or '最早'} ~ {end_time or '最新'}"
    if failures:
        header += "\n查询失败: " + "；".join(failures)
    return header + ":\n\n" + "\n\n".join(item[1] for item in paged)


def _search_multiple_chats(chat_names, keyword, start_ts, end_ts, start_time, end_time, limit, offset):
    try:
        resolved_contexts, unresolved, missing_tables = _resolve_chat_contexts(chat_names)
    except ValueError as e:
        return f"错误: {e}"

    if not resolved_contexts:
        details = []
        if unresolved:
            details.append("未找到联系人: " + "、".join(unresolved))
        if missing_tables:
            details.append("无消息表: " + "、".join(missing_tables))
        suffix = f"\n{chr(10).join(details)}" if details else ""
        return f"错误: 没有可查询的聊天对象{suffix}"

    names = get_contact_names()
    candidate_limit = _candidate_page_size(limit, offset)
    collected = []
    failures = []
    for ctx in resolved_contexts:
        chat_entries, chat_failures = _collect_chat_search_entries(
            ctx,
            names,
            keyword,
            start_ts=start_ts,
            end_ts=end_ts,
            candidate_limit=candidate_limit,
        )
        collected.extend(chat_entries)
        failures.extend(chat_failures)

    paged = _page_search_entries(collected, limit, offset)

    notes = []
    if unresolved:
        notes.append("未找到联系人: " + "、".join(unresolved))
    if missing_tables:
        notes.append("无消息表: " + "、".join(missing_tables))
    if failures:
        notes.append("查询失败: " + "；".join(failures))

    if not paged:
        header = f"在 {len(resolved_contexts)} 个聊天对象中未找到包含 \"{keyword}\" 的消息"
        if start_time or end_time:
            header += f"\n时间范围: {start_time or '最早'} ~ {end_time or '最新'}"
        if notes:
            header += "\n" + "\n".join(notes)
        return header

    header = (
        f"在 {len(resolved_contexts)} 个聊天对象中搜索 \"{keyword}\" 找到 {len(paged)} 条结果"
        f"（offset={offset}, limit={limit}）"
    )
    if start_time or end_time:
        header += f"\n时间范围: {start_time or '最早'} ~ {end_time or '最新'}"
    if notes:
        header += "\n" + "\n".join(notes)
    return header + ":\n\n" + "\n\n".join(item[1] for item in paged)


def _search_all_messages(keyword, start_ts, end_ts, start_time, end_time, limit, offset):
    names = get_contact_names()
    collected = []
    failures = []
    candidate_limit = _candidate_page_size(limit, offset)

    for rel_key in MSG_DB_KEYS:
        path = _cache.get(rel_key)
        if not path:
            continue

        try:
            with closing(sqlite3.connect(path)) as conn:
                contexts = _load_search_contexts_from_db(conn, path, names)
                db_entries, db_failures = _collect_search_entries(
                    conn,
                    contexts,
                    names,
                    keyword,
                    start_ts=start_ts,
                    end_ts=end_ts,
                    candidate_limit=candidate_limit,
                )
                collected.extend(db_entries)
                failures.extend(db_failures)
        except Exception as e:
            failures.append(f"{rel_key}: {e}")

    paged = _page_search_entries(collected, limit, offset)

    if not paged:
        header = f"未找到包含 \"{keyword}\" 的消息"
        if start_time or end_time:
            header += f"\n时间范围: {start_time or '最早'} ~ {end_time or '最新'}"
        if failures:
            header += "\n查询失败: " + "；".join(failures)
        return header

    header = f"搜索 \"{keyword}\" 找到 {len(paged)} 条结果（offset={offset}, limit={limit}）"
    if start_time or end_time:
        header += f"\n时间范围: {start_time or '最早'} ~ {end_time or '最新'}"
    if failures:
        header += "\n查询失败: " + "；".join(failures)
    return header + ":\n\n" + "\n\n".join(item[1] for item in paged)


# ============ MCP Server ============

mcp = FastMCP("wechat", instructions="查询微信消息、联系人等数据")

# 新消息追踪
_last_check_state = {}  # {username: last_timestamp}


@mcp.tool()
def get_recent_sessions(limit: int = 20) -> str:
    """获取微信最近会话列表，包含最新消息摘要、未读数、时间等。
    用于了解最近有哪些人/群在聊天。

    Args:
        limit: 返回的会话数量，默认20
    """
    path = _cache.get(os.path.join("session", "session.db"))
    if not path:
        return "错误: 无法解密 session.db"

    names = get_contact_names()
    with closing(sqlite3.connect(path)) as conn:
        rows = conn.execute("""
            SELECT username, unread_count, summary, last_timestamp,
                   last_msg_type, last_msg_sender, last_sender_display_name
            FROM SessionTable
            WHERE last_timestamp > 0
            ORDER BY last_timestamp DESC
            LIMIT ?
        """, (limit,)).fetchall()

    results = []
    for r in rows:
        username, unread, summary, ts, msg_type, sender, sender_name = r
        display = names.get(username, username)
        is_group = '@chatroom' in username

        if isinstance(summary, bytes):
            try:
                summary = _zstd_dctx.decompress(summary).decode('utf-8', errors='replace')
            except Exception:
                summary = '(压缩内容)'
        if isinstance(summary, str) and ':\n' in summary:
            summary = summary.split(':\n', 1)[1]

        sender_display = ''
        if is_group and sender:
            sender_display = names.get(sender, sender_name or sender)

        time_str = datetime.fromtimestamp(ts).strftime('%m-%d %H:%M')

        entry = f"[{time_str}] {display}"
        if is_group:
            entry += " [群]"
        if unread and unread > 0:
            entry += f" ({unread}条未读)"
        entry += f"\n  {format_msg_type(msg_type)}: "
        if sender_display:
            entry += f"{sender_display}: "
        entry += str(summary or "(无内容)")

        results.append(entry)

    return f"最近 {len(results)} 个会话:\n\n" + "\n\n".join(results)


@mcp.tool()
def get_chat_history(chat_name: str, limit: int = 50, offset: int = 0, start_time: str = "", end_time: str = "") -> str:
    """获取指定聊天的消息记录。

    Args:
        chat_name: 聊天对象的名字、备注名或wxid，自动模糊匹配
        limit: 返回的消息数量，默认50；支持较大的值，建议配合 offset 分页使用
        offset: 分页偏移量，默认0
        start_time: 起始时间，支持 YYYY-MM-DD / YYYY-MM-DD HH:MM / YYYY-MM-DD HH:MM:SS
        end_time: 结束时间，支持 YYYY-MM-DD / YYYY-MM-DD HH:MM / YYYY-MM-DD HH:MM:SS
    """
    try:
        _validate_pagination(limit, offset, limit_max=None)
        start_ts, end_ts = _parse_time_range(start_time, end_time)
    except ValueError as e:
        return f"错误: {e}"

    ctx = _resolve_chat_context(chat_name)
    if not ctx:
        return f"找不到聊天对象: {chat_name}\n提示: 可以用 get_contacts(query='{chat_name}') 搜索联系人"
    if not ctx['db_path']:
        return f"找不到 {ctx['display_name']} 的消息记录（可能在未解密的DB中或无消息）"

    names = get_contact_names()
    lines, failures = _collect_chat_history_lines(
        ctx,
        names,
        start_ts=start_ts,
        end_ts=end_ts,
        limit=limit,
        offset=offset,
    )

    if not lines:
        if failures:
            return "查询失败: " + "；".join(failures)
        return f"{ctx['display_name']} 无消息记录"

    header = f"{ctx['display_name']} 的消息记录（返回 {len(lines)} 条，offset={offset}, limit={limit}）"
    if ctx['is_group']:
        header += " [群聊]"
    if start_time or end_time:
        header += f"\n时间范围: {start_time or '最早'} ~ {end_time or '最新'}"
    if failures:
        header += "\n查询失败: " + "；".join(failures)
    return header + ":\n\n" + "\n".join(lines)


@mcp.tool()
def search_messages(
    keyword: str,
    chat_name: str | list[str] | None = None,
    start_time: str = "",
    end_time: str = "",
    limit: int = 20,
    offset: int = 0,
) -> str:
    """搜索消息内容，支持全库、单个聊天对象、多个聊天对象，以及时间范围和分页。

    Args:
        keyword: 搜索关键词
        chat_name: 聊天对象名称，可为空、单个字符串或字符串列表
        start_time: 起始时间，可为空
        end_time: 结束时间，可为空
        limit: 返回的结果数量，默认20，最大500
        offset: 分页偏移量，默认0
    """
    if not keyword or len(keyword) < 1:
        return "请提供搜索关键词"

    chat_names = _normalize_chat_names(chat_name)

    try:
        _validate_pagination(limit, offset)
        start_ts, end_ts = _parse_time_range(start_time, end_time)
    except ValueError as e:
        return f"错误: {e}"

    if len(chat_names) == 1:
        ctx = _resolve_chat_context(chat_names[0])
        if not ctx:
            return f"找不到聊天对象: {chat_names[0]}\n提示: 可以用 get_contacts(query='{chat_names[0]}') 搜索联系人"
        if not ctx['db_path']:
            return f"找不到 {ctx['display_name']} 的消息记录（可能在未解密的DB中或无消息）"
        return _search_single_chat(
            ctx,
            keyword,
            start_ts,
            end_ts,
            start_time,
            end_time,
            limit,
            offset,
        )

    if len(chat_names) > 1:
        return _search_multiple_chats(
            chat_names,
            keyword,
            start_ts,
            end_ts,
            start_time,
            end_time,
            limit,
            offset,
        )

    return _search_all_messages(
        keyword,
        start_ts,
        end_ts,
        start_time,
        end_time,
        limit,
        offset,
    )

@mcp.tool()
def get_contacts(query: str = "", limit: int = 50) -> str:
    """搜索或列出微信联系人。

    Args:
        query: 搜索关键词（匹配昵称、备注名、wxid），留空列出所有
        limit: 返回数量，默认50
    """
    contacts = get_contact_full()
    if not contacts:
        return "错误: 无法加载联系人数据"

    if query:
        q = query.lower()
        filtered = [
            c for c in contacts
            if q in c['nick_name'].lower()
            or q in c['remark'].lower()
            or q in c['username'].lower()
        ]
    else:
        filtered = contacts

    filtered = filtered[:limit]

    if not filtered:
        return f"未找到匹配 \"{query}\" 的联系人"

    lines = []
    for c in filtered:
        line = c['username']
        if c['remark']:
            line += f"  备注: {c['remark']}"
        if c['nick_name']:
            line += f"  昵称: {c['nick_name']}"
        lines.append(line)

    header = f"找到 {len(filtered)} 个联系人"
    if query:
        header += f"（搜索: {query}）"
    return header + ":\n\n" + "\n".join(lines)


@mcp.tool()
def get_new_messages() -> str:
    """获取自上次调用以来的新消息。首次调用返回最近的会话状态。"""
    global _last_check_state

    path = _cache.get(os.path.join("session", "session.db"))
    if not path:
        return "错误: 无法解密 session.db"

    names = get_contact_names()
    with closing(sqlite3.connect(path)) as conn:
        rows = conn.execute("""
            SELECT username, unread_count, summary, last_timestamp,
                   last_msg_type, last_msg_sender, last_sender_display_name
            FROM SessionTable
            WHERE last_timestamp > 0
            ORDER BY last_timestamp DESC
        """).fetchall()

    curr_state = {}
    for r in rows:
        username, unread, summary, ts, msg_type, sender, sender_name = r
        curr_state[username] = {
            'unread': unread, 'summary': summary, 'timestamp': ts,
            'msg_type': msg_type, 'sender': sender or '', 'sender_name': sender_name or '',
        }

    if not _last_check_state:
        _last_check_state = {u: s['timestamp'] for u, s in curr_state.items()}
        # 首次调用，返回有未读的会话
        unread_msgs = []
        for username, s in curr_state.items():
            if s['unread'] and s['unread'] > 0:
                display = names.get(username, username)
                is_group = '@chatroom' in username
                summary = s['summary']
                if isinstance(summary, bytes):
                    try:
                        summary = _zstd_dctx.decompress(summary).decode('utf-8', errors='replace')
                    except Exception:
                        summary = '(压缩内容)'
                if isinstance(summary, str) and ':\n' in summary:
                    summary = summary.split(':\n', 1)[1]
                time_str = datetime.fromtimestamp(s['timestamp']).strftime('%H:%M')
                tag = "[群]" if is_group else ""
                unread_msgs.append(f"[{time_str}] {display}{tag} ({s['unread']}条未读): {summary}")

        if unread_msgs:
            return f"当前 {len(unread_msgs)} 个未读会话:\n\n" + "\n".join(unread_msgs)
        return "当前无未读消息（已记录状态，下次调用将返回新消息）"

    # 对比上次状态
    new_msgs = []
    for username, s in curr_state.items():
        prev_ts = _last_check_state.get(username, 0)
        if s['timestamp'] > prev_ts:
            display = names.get(username, username)
            is_group = '@chatroom' in username
            summary = s['summary']
            if isinstance(summary, bytes):
                try:
                    summary = _zstd_dctx.decompress(summary).decode('utf-8', errors='replace')
                except Exception:
                    summary = '(压缩内容)'
            if isinstance(summary, str) and ':\n' in summary:
                summary = summary.split(':\n', 1)[1]

            sender_display = ''
            if is_group and s['sender']:
                sender_display = names.get(s['sender'], s['sender_name'] or s['sender'])

            time_str = datetime.fromtimestamp(s['timestamp']).strftime('%H:%M:%S')
            entry = f"[{time_str}] {display}"
            if is_group:
                entry += " [群]"
            entry += f": {format_msg_type(s['msg_type'])}"
            if sender_display:
                entry += f" ({sender_display})"
            entry += f" - {summary}"
            new_msgs.append((s['timestamp'], entry))

    _last_check_state = {u: s['timestamp'] for u, s in curr_state.items()}

    if not new_msgs:
        return "无新消息"

    new_msgs.sort(key=lambda x: x[0])
    entries = [m[1] for m in new_msgs]
    return f"{len(entries)} 条新消息:\n\n" + "\n".join(entries)


# ============ 图片解密 ============

_image_resolver = ImageResolver(WECHAT_BASE_DIR, DECODED_IMAGE_DIR, _cache)


@mcp.tool()
def decode_image(chat_name: str, local_id: int) -> str:
    """解密微信聊天中的一张图片。

    先用 get_chat_history 查看消息，图片消息会显示 local_id，
    然后用此工具解密对应图片。

    Args:
        chat_name: 聊天对象的名字、备注名或wxid
        local_id: 图片消息的 local_id（从 get_chat_history 获取）
    """
    username = resolve_username(chat_name)
    if not username:
        return f"找不到聊天对象: {chat_name}"

    result = _image_resolver.decode_image(username, local_id)
    if result['success']:
        return (
            f"解密成功!\n"
            f"  文件: {result['path']}\n"
            f"  格式: {result['format']}\n"
            f"  大小: {result['size']:,} bytes\n"
            f"  MD5: {result['md5']}"
        )
    else:
        error = result['error']
        if 'md5' in result:
            error += f"\n  MD5: {result['md5']}"
        return f"解密失败: {error}"


@mcp.tool()
def get_chat_images(chat_name: str, limit: int = 20) -> str:
    """列出某个聊天中的图片消息。

    返回图片的时间、local_id、MD5、文件大小等信息。
    可以配合 decode_image 工具解密指定图片。

    Args:
        chat_name: 聊天对象的名字、备注名或wxid
        limit: 返回数量，默认20
    """
    username = resolve_username(chat_name)
    if not username:
        return f"找不到聊天对象: {chat_name}"

    names = get_contact_names()
    display_name = names.get(username, username)

    db_path, table_name = _find_msg_table_for_user(username)
    if not db_path:
        return f"找不到 {display_name} 的消息记录"

    images = _image_resolver.list_chat_images(db_path, table_name, username, limit)
    if not images:
        return f"{display_name} 无图片消息"

    lines = []
    for img in images:
        time_str = datetime.fromtimestamp(img['create_time']).strftime('%Y-%m-%d %H:%M')
        line = f"[{time_str}] local_id={img['local_id']}"
        if img.get('md5'):
            line += f"  MD5={img['md5']}"
        if img.get('size'):
            size_kb = img['size'] / 1024
            line += f"  {size_kb:.0f}KB"
        if not img.get('md5'):
            line += "  (无资源信息)"
        lines.append(line)

    return f"{display_name} 的 {len(lines)} 张图片:\n\n" + "\n".join(lines)


if __name__ == "__main__":
    mcp.run()

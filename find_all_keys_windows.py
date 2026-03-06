"""
从微信进程内存中提取所有数据库的缓存raw key

WCDB为每个DB缓存: x'<64hex_enc_key><32hex_salt>'
salt嵌在hex字符串中，可以直接匹配DB文件的salt
"""
import ctypes
import ctypes.wintypes as wt
import struct, os, sys, hashlib, time, re, json
import hmac as hmac_mod
from Crypto.Cipher import AES

import functools
print = functools.partial(print, flush=True)

kernel32 = ctypes.windll.kernel32
MEM_COMMIT = 0x1000
READABLE = {0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80}
PAGE_SZ = 4096
KEY_SZ = 32
SALT_SZ = 16

from config import load_config
_cfg = load_config()
DB_DIR = _cfg["db_dir"]
OUT_FILE = _cfg["keys_file"]


class MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_uint64), ("AllocationBase", ctypes.c_uint64),
        ("AllocationProtect", wt.DWORD), ("_pad1", wt.DWORD),
        ("RegionSize", ctypes.c_uint64), ("State", wt.DWORD),
        ("Protect", wt.DWORD), ("Type", wt.DWORD), ("_pad2", wt.DWORD),
    ]


def get_pids():
    """返回所有 Weixin.exe 进程的 (pid, mem_kb) 列表，按内存降序"""
    import subprocess
    r = subprocess.run(["tasklist", "/FI", "IMAGENAME eq Weixin.exe", "/FO", "CSV", "/NH"],
                       capture_output=True, text=True)
    pids = []
    for line in r.stdout.strip().split('\n'):
        if not line.strip():
            continue
        p = line.strip('"').split('","')
        if len(p) >= 5:
            pid = int(p[1])
            mem = int(p[4].replace(',', '').replace(' K', '').strip() or '0')
            pids.append((pid, mem))
    if not pids:
        raise RuntimeError("Weixin.exe 未运行")
    pids.sort(key=lambda x: x[1], reverse=True)
    for pid, mem in pids:
        print(f"[+] Weixin.exe PID={pid} ({mem // 1024}MB)")
    return pids


def read_mem(h, addr, sz):
    buf = ctypes.create_string_buffer(sz)
    n = ctypes.c_size_t(0)
    if kernel32.ReadProcessMemory(h, ctypes.c_uint64(addr), buf, sz, ctypes.byref(n)):
        return buf.raw[:n.value]
    return None


def enum_regions(h):
    regs = []
    addr = 0
    mbi = MBI()
    while addr < 0x7FFFFFFFFFFF:
        if kernel32.VirtualQueryEx(h, ctypes.c_uint64(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
            break
        if mbi.State == MEM_COMMIT and mbi.Protect in READABLE and 0 < mbi.RegionSize < 500 * 1024 * 1024:
            regs.append((mbi.BaseAddress, mbi.RegionSize))
        nxt = mbi.BaseAddress + mbi.RegionSize
        if nxt <= addr:
            break
        addr = nxt
    return regs


def verify_key_for_db(enc_key, db_page1):
    """验证enc_key是否能解密这个DB的page 1"""
    salt = db_page1[:SALT_SZ]

    # HMAC验证 (最可靠)
    mac_salt = bytes(b ^ 0x3a for b in salt)
    mac_key = hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, 2, dklen=KEY_SZ)
    hmac_data = db_page1[SALT_SZ: PAGE_SZ - 80 + 16]
    stored_hmac = db_page1[PAGE_SZ - 64: PAGE_SZ]
    h = hmac_mod.new(mac_key, hmac_data, hashlib.sha512)
    h.update(struct.pack('<I', 1))
    return h.digest() == stored_hmac


def main():
    print("=" * 60)
    print("  提取所有微信数据库密钥")
    print("=" * 60)

    # 1. 收集所有DB文件及其salt
    db_files = []
    salt_to_dbs = {}

    for root, dirs, files in os.walk(DB_DIR):
        for f in files:
            if f.endswith('.db') and not f.endswith('-wal') and not f.endswith('-shm'):
                path = os.path.join(root, f)
                rel = os.path.relpath(path, DB_DIR)
                sz = os.path.getsize(path)
                if sz < PAGE_SZ:
                    continue
                with open(path, 'rb') as fh:
                    page1 = fh.read(PAGE_SZ)
                salt = page1[:SALT_SZ].hex()
                db_files.append((rel, path, sz, salt, page1))
                salt_to_dbs.setdefault(salt, []).append(rel)

    print(f"\n找到 {len(db_files)} 个数据库, {len(salt_to_dbs)} 个不同的salt")
    for salt_hex, dbs in sorted(salt_to_dbs.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"  salt {salt_hex}: {', '.join(dbs)}")

    # 2. 打开所有微信进程
    pids = get_pids()

    hex_re = re.compile(b"x'([0-9a-fA-F]{64,192})'")
    key_map = {}
    remaining_salts = set(salt_to_dbs.keys())
    all_hex_matches = 0
    t0 = time.time()

    for pid, mem in pids:
        h = kernel32.OpenProcess(0x0010 | 0x0400, False, pid)
        if not h:
            print(f"[WARN] 无法打开进程 PID={pid}，跳过")
            continue

        try:
            regions = enum_regions(h)
            total_bytes = sum(s for _, s in regions)
            total_mb = total_bytes / 1024 / 1024
            print(f"\n[*] 扫描 PID={pid} ({total_mb:.0f}MB, {len(regions)} 区域)")

            scanned_bytes = 0
            for reg_idx, (base, size) in enumerate(regions):
                data = read_mem(h, base, size)
                scanned_bytes += size
                if not data:
                    continue

                for m in hex_re.finditer(data):
                    hex_str = m.group(1).decode()
                    addr = base + m.start()
                    all_hex_matches += 1
                    hex_len = len(hex_str)

                    if hex_len == 96:
                        enc_key_hex = hex_str[:64]
                        salt_hex = hex_str[64:]

                        if salt_hex in remaining_salts:
                            enc_key = bytes.fromhex(enc_key_hex)
                            for rel, path, sz, s, page1 in db_files:
                                if s == salt_hex and verify_key_for_db(enc_key, page1):
                                    key_map[salt_hex] = enc_key_hex
                                    remaining_salts.discard(salt_hex)
                                    dbs = salt_to_dbs[salt_hex]
                                    print(f"\n  [FOUND] salt={salt_hex}")
                                    print(f"    enc_key={enc_key_hex}")
                                    print(f"    PID={pid} 地址: 0x{addr:016X}")
                                    print(f"    数据库: {', '.join(dbs)}")
                                    break

                    elif hex_len == 64:
                        if not remaining_salts:
                            continue
                        enc_key_hex = hex_str
                        enc_key = bytes.fromhex(enc_key_hex)
                        for rel, path, sz, salt_hex_db, page1 in db_files:
                            if salt_hex_db in remaining_salts and verify_key_for_db(enc_key, page1):
                                key_map[salt_hex_db] = enc_key_hex
                                remaining_salts.discard(salt_hex_db)
                                dbs = salt_to_dbs[salt_hex_db]
                                print(f"\n  [FOUND] salt={salt_hex_db}")
                                print(f"    enc_key={enc_key_hex}")
                                print(f"    PID={pid} 地址: 0x{addr:016X}")
                                print(f"    数据库: {', '.join(dbs)}")
                                break

                    elif hex_len > 96 and hex_len % 2 == 0:
                        enc_key_hex = hex_str[:64]
                        salt_hex = hex_str[-32:]

                        if salt_hex in remaining_salts:
                            enc_key = bytes.fromhex(enc_key_hex)
                            for rel, path, sz, s, page1 in db_files:
                                if s == salt_hex and verify_key_for_db(enc_key, page1):
                                    key_map[salt_hex] = enc_key_hex
                                    remaining_salts.discard(salt_hex)
                                    dbs = salt_to_dbs[salt_hex]
                                    print(f"\n  [FOUND] salt={salt_hex} (long hex {hex_len})")
                                    print(f"    enc_key={enc_key_hex}")
                                    print(f"    PID={pid} 地址: 0x{addr:016X}")
                                    print(f"    数据库: {', '.join(dbs)}")
                                    break

                if (reg_idx + 1) % 200 == 0:
                    elapsed = time.time() - t0
                    progress = scanned_bytes / total_bytes * 100 if total_bytes else 100
                    print(
                        f"  [{progress:.1f}%] {len(key_map)}/{len(salt_to_dbs)} salts matched, "
                        f"{all_hex_matches} hex patterns, {elapsed:.1f}s"
                    )
        finally:
            kernel32.CloseHandle(h)

        if not remaining_salts:
            print(f"\n[+] 所有密钥已找到，跳过剩余进程")
            break

    elapsed = time.time() - t0
    print(f"\n扫描完成: {elapsed:.1f}s, {len(pids)} 个进程, {all_hex_matches} hex模式")

    missing_salts = set(salt_to_dbs.keys()) - set(key_map.keys())
    if missing_salts and key_map:
        print(f"\n还有 {len(missing_salts)} 个salt未匹配，尝试交叉验证...")
        for salt_hex in list(missing_salts):
            for rel, path, sz, s, page1 in db_files:
                if s == salt_hex:
                    for known_salt, known_key_hex in key_map.items():
                        enc_key = bytes.fromhex(known_key_hex)
                        if verify_key_for_db(enc_key, page1):
                            key_map[salt_hex] = known_key_hex
                            print(f"  [CROSS] salt={salt_hex} 可用 key from salt={known_salt}")
                            missing_salts.discard(salt_hex)
                    break

    print(f"\n{'=' * 60}")
    print(f"结果: {len(key_map)}/{len(salt_to_dbs)} salts 找到密钥")

    result = {}
    for rel, path, sz, salt_hex, page1 in db_files:
        if salt_hex in key_map:
            result[rel] = {
                "enc_key": key_map[salt_hex],
                "salt": salt_hex,
                "size_mb": round(sz / 1024 / 1024, 1)
            }
            print(f"  OK: {rel} ({sz / 1024 / 1024:.1f}MB)")
        else:
            print(f"  MISSING: {rel} (salt={salt_hex})")

    if not result:
        print(f"\n[!] 未提取到任何密钥，保留已有的 {OUT_FILE}（如存在）")
        raise RuntimeError("未能从任何微信进程中提取到密钥")

    result["_db_dir"] = DB_DIR
    with open(OUT_FILE, 'w') as f:
        json.dump(result, f, indent=2)
    print(f"\n密钥保存到: {OUT_FILE}")

    missing = [rel for rel, path, sz, salt_hex, page1 in db_files if salt_hex not in key_map]
    if missing:
        print(f"\n未找到密钥的数据库:")
        for rel in missing:
            print(f"  {rel}")


if __name__ == '__main__':
    try:
        main()
    except RuntimeError as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)

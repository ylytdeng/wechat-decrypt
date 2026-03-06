"""
Linux 版微信数据库密钥提取

原理: 与 Windows/macOS 相同 — 扫描微信进程内存，查找
WCDB 缓存的 x'<64hex_enc_key><32hex_salt>' 模式，
通过匹配数据库 salt + HMAC 校验确认密钥。

读取方式: /proc/<pid>/maps + /proc/<pid>/mem
权限要求: root 或 CAP_SYS_PTRACE
"""
import functools
import hashlib
import hmac as hmac_mod
import json
import os
import re
import struct
import sys
import time

print = functools.partial(print, flush=True)

PAGE_SZ = 4096
KEY_SZ = 32
SALT_SZ = 16

from config import load_config
_cfg = load_config()
DB_DIR = _cfg["db_dir"]
OUT_FILE = _cfg["keys_file"]


def _safe_readlink(path):
    try:
        return os.path.realpath(os.readlink(path))
    except OSError:
        return ""


def get_pids():
    """返回所有疑似微信主进程的 (pid, rss_kb) 列表，按内存降序。"""
    pids = []
    for pid_str in os.listdir("/proc"):
        if not pid_str.isdigit():
            continue
        pid = int(pid_str)
        try:
            with open(f"/proc/{pid}/comm") as f:
                comm = f.read().strip()
            with open(f"/proc/{pid}/statm") as f:
                rss_pages = int(f.read().split()[1])
            rss_kb = rss_pages * 4
            exe_name = os.path.basename(_safe_readlink(f"/proc/{pid}/exe")) or comm
            haystack = " ".join((comm, exe_name)).lower()
            if "wechat" not in haystack and "weixin" not in haystack:
                continue
            pids.append((pid, rss_kb))
        except (PermissionError, FileNotFoundError, ProcessLookupError):
            continue

    if not pids:
        raise RuntimeError("未检测到 Linux 微信进程")

    pids.sort(key=lambda item: item[1], reverse=True)
    for pid, rss_kb in pids:
        exe_path = _safe_readlink(f"/proc/{pid}/exe")
        print(f"[+] WeChat PID={pid} ({rss_kb // 1024}MB) {exe_path}")
    return pids


def _get_readable_regions(pid):
    """解析 /proc/<pid>/maps，返回可读内存区域列表。"""
    regions = []
    with open(f"/proc/{pid}/maps") as f:
        for line in f:
            parts = line.split()
            if len(parts) < 2:
                continue
            if "r" not in parts[1]:
                continue
            start_s, end_s = parts[0].split("-")
            start = int(start_s, 16)
            size = int(end_s, 16) - start
            if 0 < size < 500 * 1024 * 1024:
                regions.append((start, size))
    return regions


def _collect_db_files():
    db_files = []
    salt_to_dbs = {}
    for root, dirs, files in os.walk(DB_DIR):
        for name in files:
            if not name.endswith(".db") or name.endswith("-wal") or name.endswith("-shm"):
                continue
            path = os.path.join(root, name)
            size = os.path.getsize(path)
            if size < PAGE_SZ:
                continue
            with open(path, "rb") as f:
                page1 = f.read(PAGE_SZ)
            rel = os.path.relpath(path, DB_DIR)
            salt = page1[:SALT_SZ].hex()
            db_files.append((rel, path, size, salt, page1))
            salt_to_dbs.setdefault(salt, []).append(rel)
    return db_files, salt_to_dbs


def _verify_enc_key(enc_key, db_page1):
    salt = db_page1[:SALT_SZ]
    mac_salt = bytes(b ^ 0x3A for b in salt)
    mac_key = hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, 2, dklen=KEY_SZ)
    hmac_data = db_page1[SALT_SZ: PAGE_SZ - 80 + 16]
    stored_hmac = db_page1[PAGE_SZ - 64: PAGE_SZ]
    hm = hmac_mod.new(mac_key, hmac_data, hashlib.sha512)
    hm.update(struct.pack("<I", 1))
    return hm.digest() == stored_hmac


def main():
    print("=" * 60)
    print("  提取 Linux 微信数据库密钥（内存扫描）")
    print("=" * 60)

    # 1. 收集 DB 文件和 salt
    db_files, salt_to_dbs = _collect_db_files()
    if not db_files:
        raise RuntimeError(f"在 {DB_DIR} 未找到可解密的 .db 文件")

    print(f"\n找到 {len(db_files)} 个数据库, {len(salt_to_dbs)} 个不同的 salt")
    for salt_hex, dbs in sorted(salt_to_dbs.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"  salt {salt_hex}: {', '.join(dbs)}")

    # 2. 找到微信进程
    pids = get_pids()

    hex_re = re.compile(rb"x'([0-9a-fA-F]{64,192})'")
    key_map = {}  # salt_hex -> enc_key_hex
    remaining_salts = set(salt_to_dbs.keys())
    all_hex_matches = 0
    t0 = time.time()

    for pid, rss_kb in pids:
        try:
            regions = _get_readable_regions(pid)
        except PermissionError:
            print(f"[WARN] 无法读取 /proc/{pid}/maps，权限不足，跳过")
            continue

        total_bytes = sum(s for _, s in regions)
        total_mb = total_bytes / 1024 / 1024
        print(f"\n[*] 扫描 PID={pid} ({total_mb:.0f}MB, {len(regions)} 区域)")

        scanned_bytes = 0
        try:
            mem = open(f"/proc/{pid}/mem", "rb")
        except PermissionError:
            print(f"[WARN] 无法打开 /proc/{pid}/mem，权限不足，跳过")
            continue

        try:
            for reg_idx, (base, size) in enumerate(regions):
                try:
                    mem.seek(base)
                    data = mem.read(size)
                except (OSError, ValueError):
                    continue
                scanned_bytes += len(data)

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
                                if s == salt_hex and _verify_enc_key(enc_key, page1):
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
                            if salt_hex_db in remaining_salts and _verify_enc_key(enc_key, page1):
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
                                if s == salt_hex and _verify_enc_key(enc_key, page1):
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
            mem.close()

        if not remaining_salts:
            print(f"\n[+] 所有密钥已找到，跳过剩余进程")
            break

    elapsed = time.time() - t0
    print(f"\n扫描完成: {elapsed:.1f}s, {len(pids)} 个进程, {all_hex_matches} hex 模式")

    # 交叉验证：用已找到的 key 尝试未匹配的 salt
    missing_salts = set(salt_to_dbs.keys()) - set(key_map.keys())
    if missing_salts and key_map:
        print(f"\n还有 {len(missing_salts)} 个 salt 未匹配，尝试交叉验证...")
        for salt_hex in list(missing_salts):
            for rel, path, sz, s, page1 in db_files:
                if s == salt_hex:
                    for known_salt, known_key_hex in key_map.items():
                        enc_key = bytes.fromhex(known_key_hex)
                        if _verify_enc_key(enc_key, page1):
                            key_map[salt_hex] = known_key_hex
                            print(f"  [CROSS] salt={salt_hex} 可用 key from salt={known_salt}")
                            missing_salts.discard(salt_hex)
                    break

    # 输出结果
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
    result["_platform"] = "linux"
    result["_key_source"] = "memory_scan"
    with open(OUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"\n密钥保存到: {OUT_FILE}")

    missing = [rel for rel, path, sz, salt_hex, page1 in db_files if salt_hex not in key_map]
    if missing:
        print(f"\n未找到密钥的数据库:")
        for rel in missing:
            print(f"  {rel}")


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as exc:
        print(f"\n[ERROR] {exc}")
        sys.exit(1)

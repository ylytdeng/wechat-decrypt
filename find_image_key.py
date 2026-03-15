"""从微信进程内存中提取图片 AES 密钥 (V2 .dat 格式)

V2 .dat 文件结构:
  [6B signature: 07 08 V2 08 07] [4B aes_size LE] [4B xor_size LE] [1B padding]
  [aes_size bytes AES-ECB encrypted] [raw_data unencrypted] [xor_size bytes XOR encrypted]

AES key: 16-byte ASCII string found in Weixin.exe process memory
XOR key: single byte, same as old format (derived from JPEG FF D9 ending)

Usage:
  1. 打开微信, 进入聊天/朋友圈, 点击查看 2-3 张图片
  2. 立即运行: python find_image_key.py
"""
import os
import sys
import re
import struct
import glob
import json
import time
import ctypes
from ctypes import wintypes
from Crypto.Cipher import AES
from Crypto.Util import Padding

# Windows API constants
PROCESS_ALL_ACCESS = 0x1F0FFF
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

kernel32 = ctypes.windll.kernel32

# 正则: 精确 32 字符 alphanum (前后是非 alphanum 或边界)
RE_KEY32 = re.compile(rb'(?<![a-zA-Z0-9])[a-zA-Z0-9]{32}(?![a-zA-Z0-9])')
# 正则: 精确 16 字符 alphanum
RE_KEY16 = re.compile(rb'(?<![a-zA-Z0-9])[a-zA-Z0-9]{16}(?![a-zA-Z0-9])')


def get_wechat_pids():
    import subprocess
    result = subprocess.run(
        ['tasklist.exe', '/FI', 'IMAGENAME eq Weixin.exe', '/FO', 'CSV', '/NH'],
        capture_output=True, text=True
    )
    pids = []
    for line in result.stdout.strip().split('\n'):
        if 'Weixin.exe' in line:
            parts = line.strip('"').split('","')
            if len(parts) >= 2:
                pids.append(int(parts[1]))
    return pids


def find_v2_ciphertext(attach_dir):
    """从多个 V2 .dat 文件中提取第一个 AES 密文块 (16 bytes)"""
    v2_magic = b'\x07\x08V2\x08\x07'

    # Search _t.dat (thumbnails, likely JPEG)
    pattern = os.path.join(attach_dir, "*", "*", "Img", "*_t.dat")
    dat_files = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)

    for f in dat_files[:100]:
        try:
            with open(f, 'rb') as fp:
                header = fp.read(31)
            if header[:6] == v2_magic and len(header) >= 31:
                return header[15:31], os.path.basename(f)
        except:
            continue
    return None, None


def find_xor_key(attach_dir):
    """从缩略图文件末尾推导 XOR key (JPEG 结尾 FF D9)"""
    v2_magic = b'\x07\x08V2\x08\x07'
    pattern = os.path.join(attach_dir, "*", "*", "Img", "*_t.dat")
    dat_files = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)

    tail_counts = {}
    for f in dat_files[:32]:
        try:
            sz = os.path.getsize(f)
            with open(f, 'rb') as fp:
                head = fp.read(6)
                fp.seek(sz - 2)
                tail = fp.read(2)
            if head == v2_magic and len(tail) == 2:
                key = (tail[0], tail[1])
                tail_counts[key] = tail_counts.get(key, 0) + 1
        except:
            continue

    if not tail_counts:
        return None

    most_common = max(tail_counts, key=tail_counts.get)
    x, y = most_common
    xor_key = x ^ 0xFF
    check = y ^ 0xD9

    if xor_key == check:
        return xor_key
    return xor_key  # return best guess anyway


def try_key(key_bytes, ciphertext):
    """Try decrypting ciphertext with key, return format name if successful"""
    try:
        cipher = AES.new(key_bytes, AES.MODE_ECB)
        dec = cipher.decrypt(ciphertext)
        if dec[:3] == b'\xFF\xD8\xFF':
            return 'JPEG'
        if dec[:4] == bytes([0x89, 0x50, 0x4E, 0x47]):
            return 'PNG'
        if dec[:4] == b'RIFF':
            return 'WEBP'
        if dec[:4] == b'wxgf':
            return 'WXGF'
        if dec[:3] == b'GIF':
            return 'GIF'
    except:
        pass
    return None


def is_rw_protect(protect):
    """Check if memory region is readable/writable (where string keys live)"""
    rw_flags = (PAGE_READWRITE | PAGE_WRITECOPY |
                PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
    return (protect & rw_flags) != 0


def scan_memory_for_aes_key(pid, ciphertext):
    """扫描微信进程内存寻找 AES key (regex 加速版)"""
    access = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
    h_process = kernel32.OpenProcess(access, False, pid)
    if not h_process:
        print(f"  无法打开进程 {pid} (尝试以管理员运行)", flush=True)
        return None

    try:
        # Enumerate memory regions
        address = 0
        mbi = MEMORY_BASIC_INFORMATION()
        rw_regions = []
        all_regions = []

        while address < 0x7FFFFFFFFFFF:
            result = kernel32.VirtualQueryEx(
                h_process, ctypes.c_void_p(address),
                ctypes.byref(mbi), ctypes.sizeof(mbi)
            )
            if result == 0:
                break
            if (mbi.State == MEM_COMMIT and
                mbi.Protect != PAGE_NOACCESS and
                (mbi.Protect & PAGE_GUARD) == 0 and
                mbi.RegionSize <= 50 * 1024 * 1024):
                region = (mbi.BaseAddress, mbi.RegionSize, mbi.Protect)
                all_regions.append(region)
                if is_rw_protect(mbi.Protect):
                    rw_regions.append(region)
            next_addr = address + mbi.RegionSize
            if next_addr <= address:
                break
            address = next_addr

        rw_mb = sum(r[1] for r in rw_regions) / 1024 / 1024
        all_mb = sum(r[1] for r in all_regions) / 1024 / 1024
        print(f"  RW 区域: {len(rw_regions)} ({rw_mb:.0f} MB), 总计: {len(all_regions)} ({all_mb:.0f} MB)", flush=True)

        # Phase 1: 只扫描 RW 区域 (key 字符串最可能在这里)
        print("  === Phase 1: 扫描 RW 内存 ===", flush=True)
        result = _scan_regions(h_process, rw_regions, ciphertext)
        if result:
            return result

        # Phase 2: 扫描所有可读区域
        print("  === Phase 2: 扫描所有内存 ===", flush=True)
        # 排除已扫描的 RW 区域
        rw_set = set((r[0], r[1]) for r in rw_regions)
        other_regions = [r for r in all_regions if (r[0], r[1]) not in rw_set]
        result = _scan_regions(h_process, other_regions, ciphertext)
        if result:
            return result

        return None

    finally:
        kernel32.CloseHandle(h_process)


def _scan_regions(h_process, regions, ciphertext):
    """扫描指定内存区域列表，返回找到的 key 或 None"""
    candidates_32 = 0
    candidates_16 = 0
    t0 = time.time()

    for idx, (base_addr, region_size, _protect) in enumerate(regions):
        if idx % 100 == 0:
            elapsed = time.time() - t0
            print(f"  扫描 {idx}/{len(regions)} ({elapsed:.1f}s)", end='\r', flush=True)

        buffer = ctypes.create_string_buffer(region_size)
        bytes_read = ctypes.c_size_t(0)
        ok = kernel32.ReadProcessMemory(
            h_process, ctypes.c_void_p(base_addr),
            buffer, region_size, ctypes.byref(bytes_read)
        )
        if not ok or bytes_read.value < 32:
            continue

        data = buffer.raw[:bytes_read.value]

        # 用正则找 32 字符 alphanum (C 级速度)
        for m in RE_KEY32.finditer(data):
            key_bytes = m.group()
            candidates_32 += 1

            # 前 16 字符作为 AES-128 key
            fmt = try_key(key_bytes[:16], ciphertext)
            if fmt:
                key_str = key_bytes.decode('ascii')
                print(f"\n*** 找到 AES key (32-char)! → {fmt} ***", flush=True)
                print(f"  完整: {key_str}", flush=True)
                print(f"  AES key: {key_str[:16]}", flush=True)
                return key_str[:16]

            # 也试完整 32 字节作 AES-256
            fmt = try_key(key_bytes, ciphertext)
            if fmt:
                key_str = key_bytes.decode('ascii')
                print(f"\n*** 找到 AES key (32-byte)! → {fmt} ***", flush=True)
                print(f"  完整: {key_str}", flush=True)
                return key_str

        # 也找独立的 16 字符 alphanum
        for m in RE_KEY16.finditer(data):
            key_bytes = m.group()
            candidates_16 += 1

            fmt = try_key(key_bytes, ciphertext)
            if fmt:
                key_str = key_bytes.decode('ascii')
                print(f"\n*** 找到 AES key (16-char)! → {fmt} ***", flush=True)
                print(f"  AES key: {key_str}", flush=True)
                return key_str

    elapsed = time.time() - t0
    print(f"\n  测试: {candidates_32} x 32-char + {candidates_16} x 16-char ({elapsed:.1f}s)", flush=True)
    return None


def verify_and_decrypt(attach_dir, aes_key_str, xor_key):
    """完整解密一个 V2 文件作为验证"""
    v2_magic = b'\x07\x08V2\x08\x07'
    key = aes_key_str.encode('ascii')[:16]

    pattern = os.path.join(attach_dir, "*", "*", "Img", "*_t.dat")
    dat_files = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)

    for f in dat_files[:10]:
        try:
            with open(f, 'rb') as fp:
                data = fp.read()
            if data[:6] != v2_magic:
                continue

            sig, aes_size, xor_size = struct.unpack_from('<6sLL', data)

            # AES 对齐: 向上取整到 16 的倍数 (PKCS7 填充)
            aligned_aes_size = aes_size
            aligned_aes_size -= ~(~aligned_aes_size % 16)

            offset = 15
            aes_data = data[offset:offset + aligned_aes_size]
            cipher = AES.new(key, AES.MODE_ECB)
            dec_aes = Padding.unpad(cipher.decrypt(aes_data), AES.block_size)
            offset += aligned_aes_size

            # Raw portion
            raw_data = data[offset:len(data) - xor_size]
            offset += len(raw_data)

            # XOR portion
            xor_data = data[offset:]
            dec_xor = bytes(b ^ xor_key for b in xor_data) if xor_key is not None else xor_data

            result = dec_aes + raw_data + dec_xor

            fmt = "unknown"
            ext = ".bin"
            if result[:3] == b'\xFF\xD8\xFF':
                fmt, ext = "JPEG", ".jpg"
            elif result[:4] == bytes([0x89, 0x50, 0x4E, 0x47]):
                fmt, ext = "PNG", ".png"
            elif result[:4] == b'RIFF':
                fmt, ext = "WEBP", ".webp"
            elif result[:4] == b'wxgf':
                fmt, ext = "WXGF", ".hevc"

            print(f"  {os.path.basename(f)} -> {fmt} ({len(result):,}B)", flush=True)

            if fmt != "unknown":
                out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "decoded_images")
                os.makedirs(out_dir, exist_ok=True)
                out_path = os.path.join(out_dir, os.path.splitext(os.path.basename(f))[0] + ext)
                with open(out_path, 'wb') as fp:
                    fp.write(result)
                print(f"  saved: {out_path}", flush=True)
                return True
        except Exception as e:
            continue
    return False


def main():
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
    with open(config_path, "r", encoding="utf-8") as f:
        config = json.load(f)

    db_dir = config['db_dir']
    base_dir = os.path.dirname(db_dir)
    attach_dir = os.path.join(base_dir, 'msg', 'attach')

    # 1. XOR key
    print("=== XOR Key ===", flush=True)
    xor_key = find_xor_key(attach_dir)
    if xor_key is not None:
        print(f"XOR key: 0x{xor_key:02x}", flush=True)

    # 2. V2 ciphertext
    print("\n=== V2 ciphertext ===", flush=True)
    ciphertext, ct_file = find_v2_ciphertext(attach_dir)
    if ciphertext is None:
        print("No V2 .dat files found")
        return
    print(f"File: {ct_file}", flush=True)
    print(f"Cipher: {ciphertext.hex()}", flush=True)

    # 3. Check if already have key in config
    if config.get('image_aes_key'):
        print(f"\nExisting image_aes_key: {config['image_aes_key']}", flush=True)
        fmt = try_key(config['image_aes_key'].encode('ascii')[:16], ciphertext)
        if fmt:
            print(f"Key valid! -> {fmt}", flush=True)
            print("\n=== Verify decrypt ===", flush=True)
            verify_and_decrypt(attach_dir, config['image_aes_key'], xor_key)
            return
        else:
            print("Saved key invalid, re-scanning...", flush=True)

    # 4. Scan memory
    print("\n=== Scanning WeChat process memory ===", flush=True)
    pids = get_wechat_pids()
    if not pids:
        print("WeChat not running!")
        return
    print(f"PIDs: {pids}", flush=True)
    print("Tip: View 2-3 images in WeChat first, then run this script immediately\n", flush=True)

    aes_key = None
    for pid in pids:
        print(f"Scanning PID {pid}...", flush=True)
        aes_key = scan_memory_for_aes_key(pid, ciphertext)
        if aes_key:
            break

    if aes_key:
        print(f"\n=== Result ===", flush=True)
        print(f"AES key: {aes_key}", flush=True)
        print(f"XOR key: 0x{xor_key:02x}" if xor_key is not None else "XOR key: unknown", flush=True)

        config['image_aes_key'] = aes_key
        if xor_key is not None:
            config['image_xor_key'] = xor_key
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        print(f"Saved to {config_path}", flush=True)

        print("\n=== Verify decrypt ===", flush=True)
        verify_and_decrypt(attach_dir, aes_key, xor_key)
    else:
        print("\nAES key not found!", flush=True)
        print("Steps:", flush=True)
        print("  1. Login WeChat and keep it running", flush=True)
        print("  2. Open Moments or a chat, view 2-3 images (tap to open full size)", flush=True)
        print("  3. Immediately re-run this script", flush=True)


if __name__ == '__main__':
    main()
